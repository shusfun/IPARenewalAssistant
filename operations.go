package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/danielpaulus/go-ios/ios/zipconduit"
)

func (s *Service) CheckEnvironment(ctx context.Context) EnvironmentStatus {
	return s.checkEnvironment(ctx).Status
}

func (s *Service) ListSigningIdentities(ctx context.Context) ([]SigningIdentityOption, error) {
	environment := s.checkEnvironment(ctx)
	selected := s.store.Snapshot().LastIdentityFingerprint
	options := make([]SigningIdentityOption, 0, len(environment.Identities))
	for index, identity := range environment.Identities {
		suffix := identity.TeamID
		if len(suffix) > 4 {
			suffix = suffix[len(suffix)-4:]
		}
		options = append(options, SigningIdentityOption{ID: identity.Fingerprint, Label: fmt.Sprintf("开发身份 %d · Team ••••%s", index+1, suffix), Selected: identity.Fingerprint == selected})
	}
	return options, nil
}

func (s *Service) SelectSigningIdentity(ctx context.Context, fingerprint string) error {
	environment := s.checkEnvironment(ctx)
	found := false
	for _, identity := range environment.Identities {
		if identity.Fingerprint == fingerprint {
			found = true
			break
		}
	}
	if !found {
		return &UserError{Code: "identity_not_found", Message: "所选开发身份已不可用"}
	}
	return s.store.Update(func(state *State) error {
		state.LastIdentityFingerprint = fingerprint
		return nil
	})
}

func (s *Service) ListManagedApps(ctx context.Context, deviceID string) ([]AppView, error) {
	if deviceID != "" {
		_ = s.store.Update(func(state *State) error { state.SelectedDeviceID = deviceID; return nil })
	}
	state := s.store.Snapshot()
	volumeReady := s.storageCheck() == nil
	if volumeReady && deviceID != "" {
		temp, err := os.MkdirTemp(s.paths.Cache, "scan-")
		if err == nil {
			defer os.RemoveAll(temp)
			for _, app := range state.Apps {
				if _, ok := app.Installs[deviceID]; !ok {
					continue
				}
				present, _, queryErr := s.queryInstalledApp(ctx, deviceID, app.EffectiveBundleID, temp)
				if queryErr == nil {
					_ = s.store.Update(func(next *State) error {
						current := next.Apps[app.ID]
						record := current.Installs[deviceID]
						record.Present = present
						record.LastConfirmed = s.now()
						current.Installs[deviceID] = record
						return nil
					})
				}
			}
			state = s.store.Snapshot()
		}
	}
	views := make([]AppView, 0, len(state.Apps))
	for _, app := range state.Apps {
		views = append(views, s.appView(app, deviceID, s.now()))
	}
	sort.Slice(views, func(i, j int) bool { return views[i].ImportedAt.After(views[j].ImportedAt) })
	return views, nil
}

func (s *Service) SignApp(appID string, args ...string) (JobHandle, error) {
	deviceID := s.store.Snapshot().SelectedDeviceID
	bundlePolicy := "preserve"
	certificatePolicy := "reuse"
	if len(args) == 1 {
		bundlePolicy = args[0]
	}
	if len(args) >= 2 {
		deviceID, bundlePolicy = args[0], args[1]
	}
	if len(args) >= 3 {
		certificatePolicy = args[2]
	}
	if deviceID == "" {
		return JobHandle{}, &UserError{Code: "device_required", Message: "请先选择一台可用的 iOS 设备"}
	}
	return s.startJob("sign", func(ctx context.Context, temp, jobID string) error {
		return s.signAppCore(ctx, temp, jobID, "sign", appID, deviceID, bundlePolicy, certificatePolicy)
	})
}

func (s *Service) InstallApp(appID, deviceID string) (JobHandle, error) {
	return s.startJob("install", func(ctx context.Context, temp, jobID string) error {
		return s.installAppCore(ctx, temp, jobID, "install", appID, deviceID)
	})
}

func (s *Service) RenewApp(appID, deviceID string, certificatePolicy ...string) (JobHandle, error) {
	policy := "reuse"
	if len(certificatePolicy) > 0 {
		policy = certificatePolicy[0]
	}
	return s.startJob("renew", func(ctx context.Context, temp, jobID string) error {
		state := s.store.Snapshot()
		app := state.Apps[appID]
		if app == nil {
			return &UserError{Code: "app_not_found", Message: "找不到这个托管 App"}
		}
		bundlePolicy := "existing"
		if app.EffectiveBundleID == app.OriginalBundleID {
			bundlePolicy = "preserve"
		}
		if err := s.signAppCore(ctx, temp, jobID, "renew", appID, deviceID, bundlePolicy, policy); err != nil {
			return err
		}
		return s.installAppCore(ctx, temp, jobID, "renew", appID, deviceID)
	})
}

func (s *Service) installAppCore(ctx context.Context, tempDir, jobID, kind, appID, deviceID string) error {
	if s.installOverride != nil {
		return s.installOverride(ctx, tempDir, jobID, kind, appID)
	}
	state := s.store.Snapshot()
	app := state.Apps[appID]
	if app == nil {
		return &UserError{Code: "app_not_found", Message: "找不到这个托管 App"}
	}
	if app.LatestSigned == nil {
		return &UserError{Code: "signed_ipa_missing", Message: "请先完成签名"}
	}
	s.audit(AuditEvent{Kind: kind, Stage: "start", Status: "started", AppID: appID, BundleID: app.EffectiveBundleID, DeviceID: deviceID, Message: "开始安装任务"})
	device, entry, err := s.findDeviceEntry(ctx, deviceID)
	if err != nil {
		s.audit(AuditEvent{Kind: kind, Stage: "connect", Status: "failed", AppID: appID, BundleID: app.EffectiveBundleID, DeviceID: deviceID, ErrorCode: "device_unavailable", Message: "设备不可用"})
		return err
	}
	if err := s.ensureDeviceReady(device); err != nil {
		return err
	}
	if _, err := os.Stat(app.LatestSigned.Path); err != nil {
		return &UserError{Code: "signed_ipa_missing", Message: "已签名 IPA 已不存在，请重新签名"}
	}
	expectedTeam := app.LatestSigned.Profile.TeamID
	profile, err := s.parseProfileFromIPA(ctx, app.LatestSigned.Path, tempDir)
	if err != nil {
		return err
	}
	if _, err := validateProfile(profile, expectedTeam, app.EffectiveBundleID, entry.Properties.SerialNumber, s.now()); err != nil {
		return err
	}
	present, _, installedTeam, lookupErr := s.lookupInstalledPinned(ctx, deviceID, app.EffectiveBundleID, tempDir, entry)
	if lookupErr != nil {
		return lookupErr
	}
	if present {
		if installedTeam != "" && installedTeam != expectedTeam {
			return &UserError{Code: "install_identity_conflict", Message: "设备上已有相同 Bundle ID 但签名身份不同", Recovery: "为避免覆盖或丢失数据，已停止安装，不会卸载原有应用。"}
		}
		if installedTeam == "" {
			record, ok := app.Installs[deviceID]
			if !ok || record.Profile.TeamID != expectedTeam {
				return &UserError{Code: "install_identity_unknown", Message: "无法确认设备上现有 App 的签名身份", Recovery: "为避免潜在数据丢失，已停止安装，不会卸载原有应用。"}
			}
		}
	}
	s.progress(jobID, kind, "prepare_install", "正在准备已签名 App", installPercent(kind, 20))
	s.progress(jobID, kind, "install", "正在安装到设备", installPercent(kind, 55))
	conn, connErr := zipconduit.New(entry)
	if connErr != nil {
		code, message := classifyInstallConnectError(connErr)
		s.audit(AuditEvent{Kind: kind, Stage: "connect", Status: "failed", AppID: appID, BundleID: app.EffectiveBundleID, DeviceID: deviceID, ErrorCode: code, Message: message})
		return &UserError{Code: code, Message: message, Recovery: "请解锁设备、确认开发者模式已开启，并保持当前 USB 或网络连接。不会改走另一条通道。"}
	}
	installErr := conn.SendFile(app.LatestSigned.Path)
	_ = conn.Close()
	if installErr != nil {
		code, message, status := classifyInstallTransferError(installErr)
		s.audit(AuditEvent{Kind: kind, Stage: "transfer", Status: status, AppID: appID, BundleID: app.EffectiveBundleID, DeviceID: deviceID, ErrorCode: code, Message: message})
		return &UserError{Code: code, Message: message, Recovery: "原有安装记录未改变。请重新连接同一通道后刷新回查，不要卸载或改走另一条连接重传。"}
	}
	s.progress(jobID, kind, "verify_install", "正在回查设备安装结果", installPercent(kind, 82))
	present, installedVersion, err := s.queryInstalledPinned(ctx, deviceID, app.EffectiveBundleID, tempDir, entry)
	if err != nil {
		s.audit(AuditEvent{Kind: kind, Stage: "verify", Status: "unknown", AppID: appID, BundleID: app.EffectiveBundleID, DeviceID: deviceID, ErrorCode: "device_query_failed", Message: "安装命令结束但设备回查失败，结果待确认"})
		return err
	}
	if !present {
		s.audit(AuditEvent{Kind: kind, Stage: "verify", Status: "unconfirmed", AppID: appID, BundleID: app.EffectiveBundleID, DeviceID: deviceID, ErrorCode: "install_not_confirmed", Message: "设备中未找到目标 App"})
		return &UserError{Code: "install_not_confirmed", Message: "安装命令已结束，但设备中没有找到目标 App", Recovery: "原有安装记录未改变，请重新连接设备后重试。"}
	}
	if installedVersion != "" && app.Version != "" && installedVersion != app.Version {
		s.audit(AuditEvent{Kind: kind, Stage: "verify", Status: "failed", AppID: appID, BundleID: app.EffectiveBundleID, DeviceID: deviceID, ErrorCode: "install_version_mismatch", Message: "设备版本与签名产物不一致"})
		return &UserError{Code: "install_version_mismatch", Message: "设备中的 App 版本与签名产物不一致，未更新安装记录"}
	}
	s.progress(jobID, kind, "launch", "正在启动应用以确认安装", installPercent(kind, 90))
	if err := s.launchInstalledPinned(ctx, deviceID, app.EffectiveBundleID, entry); err != nil {
		s.audit(AuditEvent{Kind: kind, Stage: "launch", Status: "failed", AppID: appID, BundleID: app.EffectiveBundleID, DeviceID: deviceID, ErrorCode: "launch_failed", Message: "安装后启动失败"})
		return err
	}
	now := s.now()
	artifact := *app.LatestSigned
	if err := s.store.Update(func(next *State) error {
		current := next.Apps[appID]
		if current == nil {
			return fmt.Errorf("App 已从状态中移除")
		}
		current.Installs[deviceID] = InstallRecord{DeviceID: deviceID, BundleID: current.EffectiveBundleID,
			Version: current.Version, Profile: artifact.Profile, InstalledAt: now, LastConfirmed: now, Present: true}
		return nil
	}); err != nil {
		s.audit(AuditEvent{Kind: kind, Stage: "commit", Status: "failed", AppID: appID, BundleID: app.EffectiveBundleID, DeviceID: deviceID, ErrorCode: "state_write_failed", Message: "安装记录写入失败"})
		return err
	}
	s.audit(AuditEvent{Kind: kind, Stage: "commit", Status: "success", AppID: appID, BundleID: app.EffectiveBundleID, DeviceID: deviceID, Message: "设备已确认安装"})
	s.progress(jobID, kind, "done", "设备已确认安装", installPercent(kind, 100))
	return nil
}

func classifyInstallConnectError(err error) (string, string) {
	if isInstallInterrupted(err) {
		return "device_unavailable", "安装服务连接中断，结果待确认"
	}
	return "install_service_unavailable", "无法连接设备安装服务"
}

func classifyInstallTransferError(err error) (string, string, string) {
	if isInstallInterrupted(err) {
		return "install_unconfirmed", "传输途中连接中断，安装结果待确认", "unknown"
	}
	return "install_failed", "设备安装失败，原有安装记录未改变", "failed"
}

func isInstallInterrupted(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) || errors.Is(err, net.ErrClosed) {
		return true
	}
	message := strings.ToLower(err.Error())
	for _, needle := range []string{"broken pipe", "connection reset", "connection refused", "not connected", "no device", "device not found", "eof"} {
		if strings.Contains(message, needle) {
			return true
		}
	}
	return false
}

func installPercent(kind string, normal int) int {
	if kind == "renew" {
		return 80 + normal/5
	}
	return normal
}

func (s *Service) RevealSignedIPA(appID string) error {
	app := s.store.Snapshot().Apps[appID]
	if app == nil || app.LatestSigned == nil {
		return &UserError{Code: "signed_ipa_missing", Message: "当前没有已签名 IPA"}
	}
	result, err := s.runner.Run(context.Background(), CommandSpec{Name: "open", Args: []string{"-R", app.LatestSigned.Path}, Timeout: 10 * time.Second})
	if err != nil {
		return commandError("finder_open_failed", "无法在 Finder 中显示文件", "", result, err)
	}
	return nil
}
