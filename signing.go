package main

import (
	"archive/zip"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"howett.net/plist"
)

// signAppCore delegates Apple ID provisioning and IPA signing to the bundled
// native helper. The helper talks to Apple's developer services directly and
// does not require an IDE project or a graphical IDE.
func (s *Service) signAppCore(ctx context.Context, tempDir, jobID, kind, appID, deviceID, bundlePolicy, certificatePolicy string) error {
	if s.signOverride != nil {
		return s.signOverride(ctx, tempDir, jobID, kind, appID, deviceID, bundlePolicy)
	}
	state := s.store.Snapshot()
	app := state.Apps[appID]
	if app == nil {
		return &UserError{Code: "app_not_found", Message: "找不到这个托管 App"}
	}
	if bundlePolicy == "replacement" && app.EffectiveBundleID == app.OriginalBundleID {
		return &UserError{Code: "bundle_replacement_unsupported", Message: "当前签名辅助组件暂不支持替代 Bundle ID", Recovery: "请先在 Apple 开发者账户中注册原 Bundle ID 后重试。"}
	}
	device, entry, err := s.findDeviceEntry(ctx, deviceID)
	if err != nil {
		return err
	}
	if err := s.ensureDeviceReady(device); err != nil {
		return err
	}
	status := s.GetAppleAccountStatus()
	if !status.SignedIn {
		return &UserError{Code: "apple_account_missing", Message: "请先登录 Apple ID", Recovery: "在顶部账户区域完成登录和验证码验证。"}
	}
	if status.NeedsTeam || strings.TrimSpace(status.TeamID) == "" {
		return &UserError{Code: "developer_team_required", Message: "请先选择开发团队", Recovery: "在账户设置中选择要用于签名的 Team。"}
	}
	if signerPath() == "" {
		return &UserError{Code: "signing_backend_missing", Message: "内置签名组件未安装"}
	}
	s.progress(jobID, kind, "prepare_sign", "正在检查输入和设备状态", signPercent(kind, 20))
	workDir := filepath.Join(tempDir, "work")
	if err := os.MkdirAll(workDir, 0o700); err != nil {
		return &UserError{Code: "cache_unavailable", Message: "无法创建签名工作目录"}
	}
	tmpOutput := filepath.Join(tempDir, "signed.ipa")
	s.progress(jobID, kind, "sign", "正在使用 Apple ID 生成描述文件并签名", signPercent(kind, 55))
	signArgs := []string{
		"sign", "--team-id", status.TeamID, "--udid", entry.Properties.SerialNumber,
		"--ipa", app.OriginalPath, "--output", tmpOutput,
	}
	if strings.EqualFold(strings.TrimSpace(certificatePolicy), "reissue") {
		signArgs = append(signArgs, "--reissue-certificate")
	}
	result, runErr := s.runner.Run(ctx, CommandSpec{
		Name: signerPath(),
		Args: signArgs,
		Env:     append(append([]string{}, os.Environ()...), "IPARENEWAL_WORK_DIR="+workDir),
		Timeout: 8 * time.Minute,
	})
	if runErr != nil {
		return appleSignError(result, runErr)
	}
	s.progress(jobID, kind, "verify", "正在解包并严格验签", signPercent(kind, 78))
	appPath, err := unpackIPA(tmpOutput, filepath.Join(tempDir, "verify"))
	if err != nil {
		return err
	}
	if err := s.verifySignedApp(ctx, appPath); err != nil {
		return err
	}
	profile, err := s.parseProfileFromIPA(ctx, tmpOutput, tempDir)
	if err != nil {
		return err
	}
	metadata, err := validateProfile(profile, status.TeamID, app.EffectiveBundleID, entry.Properties.SerialNumber, s.now())
	if err != nil {
		return err
	}
	originalApp, err := unpackIPA(app.OriginalPath, filepath.Join(tempDir, "original"))
	if err != nil {
		return err
	}
	originalEntitlements, err := s.readOriginalEntitlements(ctx, originalApp)
	if err != nil {
		return err
	}
	if _, err := buildEntitlements(originalEntitlements, profile.Entitlements); err != nil {
		return err
	}
	output := filepath.Join(s.paths.Library, "signed", fmt.Sprintf("%s-%d.ipa", app.ID, s.now().Unix()))
	if err := os.MkdirAll(filepath.Dir(output), 0o700); err != nil {
		return &UserError{Code: "storage_create_failed", Message: "无法保存签名产物"}
	}
	if err := copyFileAtomic(tmpOutput, output); err != nil {
		return &UserError{Code: "signed_ipa_publish_failed", Message: "签名校验已通过，但无法发布签名产物"}
	}
	artifact := &SignedArtifact{Path: output, Profile: metadata, IdentityFingerprint: "apple-id", SignedAt: s.now()}
	if err := s.store.Update(func(next *State) error {
		current := next.Apps[appID]
		if current == nil {
			return fmt.Errorf("App 已从状态中移除")
		}
		current.LatestSigned = artifact
		return nil
	}); err != nil {
		_ = os.Remove(output)
		return err
	}
	s.removeSupersededSignedIPAs(appID, output)
	s.progress(jobID, kind, "signed", "已生成并严格校验签名 IPA", signPercent(kind, 100))
	return nil
}

func (s *Service) removeSupersededSignedIPAs(appID, keepPath string) {
	dir := filepath.Clean(filepath.Join(s.paths.Library, "signed"))
	keepPath = filepath.Clean(keepPath)
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	prefix := appID + "-"
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		if !strings.HasPrefix(name, prefix) || !strings.HasSuffix(strings.ToLower(name), ".ipa") {
			continue
		}
		path := filepath.Join(dir, name)
		if path == keepPath {
			continue
		}
		_ = os.Remove(path)
	}
}

func unpackIPA(ipaPath, dest string) (string, error) {
	if err := os.MkdirAll(dest, 0o700); err != nil {
		return "", &UserError{Code: "cache_unavailable", Message: "无法创建解包目录"}
	}
	reader, err := zip.OpenReader(ipaPath)
	if err != nil {
		return "", &UserError{Code: "signed_ipa_invalid", Message: "无法读取 IPA"}
	}
	defer reader.Close()
	root := filepath.Clean(dest)
	var total int64
	for _, file := range reader.File {
		clean := filepath.ToSlash(filepath.Clean(file.Name))
		if strings.HasPrefix(clean, "../") || strings.HasPrefix(clean, "/") {
			return "", &UserError{Code: "unsafe_zip", Message: "IPA 包含不安全的文件路径"}
		}
		target := filepath.Join(root, filepath.FromSlash(clean))
		if target != root && !strings.HasPrefix(target, root+string(os.PathSeparator)) {
			return "", &UserError{Code: "unsafe_zip", Message: "IPA 包含不安全的文件路径"}
		}
		total += int64(file.UncompressedSize64)
		if total > maxExpandedIPA {
			return "", &UserError{Code: "ipa_too_large", Message: "IPA 解包后的体积超过 4 GB 限制"}
		}
		if file.FileInfo().IsDir() || strings.HasSuffix(clean, "/") {
			_ = os.MkdirAll(target, 0o700)
			continue
		}
		if err := os.MkdirAll(filepath.Dir(target), 0o700); err != nil {
			return "", err
		}
		if err := extractZipFile(file, target, 1<<30); err != nil {
			return "", &UserError{Code: "signed_ipa_invalid", Message: "无法解包签名产物"}
		}
	}
	payload := filepath.Join(root, "Payload")
	entries, err := os.ReadDir(payload)
	if err != nil {
		return "", &UserError{Code: "signed_ipa_invalid", Message: "签名产物中缺少 Payload"}
	}
	for _, entry := range entries {
		if entry.IsDir() && strings.HasSuffix(strings.ToLower(entry.Name()), ".app") {
			return filepath.Join(payload, entry.Name()), nil
		}
	}
	return "", &UserError{Code: "signed_ipa_invalid", Message: "签名产物中找不到 .app"}
}

func (s *Service) verifySignedApp(ctx context.Context, appPath string) error {
	if strings.HasSuffix(strings.ToLower(appPath), ".ipa") {
		return &UserError{Code: "signature_verify_failed", Message: "不能对 IPA 压缩包验签"}
	}
	result, err := s.runner.Run(ctx, CommandSpec{Name: "/usr/bin/codesign", Args: []string{"--verify", "--deep", "--strict", appPath}, Timeout: 2 * time.Minute})
	if err != nil {
		return commandError("signature_verify_failed", "签名产物严格验签失败", "签名未写入托管记录，请重新签名。", result, err)
	}
	var nested []string
	_ = filepath.Walk(appPath, func(path string, info os.FileInfo, walkErr error) error {
		if walkErr != nil || info == nil {
			return nil
		}
		lower := strings.ToLower(path)
		switch {
		case strings.HasSuffix(lower, ".appex"), strings.HasSuffix(lower, ".framework"):
			nested = append(nested, path)
			return filepath.SkipDir
		case strings.HasSuffix(lower, ".dylib"):
			nested = append(nested, path)
		}
		return nil
	})
	for _, path := range nested {
		nestedResult, nestedErr := s.runner.Run(ctx, CommandSpec{Name: "/usr/bin/codesign", Args: []string{"--verify", "--strict", path}, Timeout: time.Minute})
		if nestedErr != nil {
			return commandError("signature_verify_failed", "嵌套代码签名校验失败", "签名未写入托管记录，请重新签名。", nestedResult, nestedErr)
		}
	}
	return nil
}

func (s *Service) readOriginalEntitlements(ctx context.Context, appPath string) (map[string]any, error) {
	result, commandErr := s.runner.Run(ctx, CommandSpec{Name: "/usr/bin/codesign", Args: []string{"-d", "--entitlements", ":-", appPath}, Timeout: 20 * time.Second})
	for _, stream := range [][]byte{result.Stdout, result.Stderr} {
		text := string(stream)
		start := strings.Index(text, "<?xml")
		if start < 0 {
			continue
		}
		text = text[start:]
		if end := strings.Index(text, "</plist>"); end >= 0 {
			text = text[:end+len("</plist>")]
		}
		var entitlements map[string]any
		if _, err := plist.Unmarshal([]byte(text), &entitlements); err == nil {
			return entitlements, nil
		}
	}
	if commandErr == nil || originalEntitlementsAbsent(result) {
		return map[string]any{}, nil
	}
	return nil, commandError("entitlements_read_failed", "无法读取原 App 的签名权限", "为避免丢失能力，本次签名已停止。", result, commandErr)
}

func originalEntitlementsAbsent(result CommandResult) bool {
	text := strings.ToLower(string(append(append([]byte{}, result.Stderr...), result.Stdout...)))
	return strings.Contains(text, "no entitlements") ||
		strings.Contains(text, "code object is not signed at all") ||
		strings.Contains(text, "not signed at all")
}

func signPercent(kind string, normal int) int {
	if kind == "renew" {
		return normal * 80 / 100
	}
	return normal
}

func replacementBundleID(hash string) string {
	if len(hash) > 8 {
		hash = hash[:8]
	}
	return "com.shus.iparenew." + strings.ToLower(hash)
}

func (s *Service) parseProfileFromIPA(ctx context.Context, ipaPath, tempDir string) (mobileProvision, error) {
	r, err := zip.OpenReader(ipaPath)
	if err != nil {
		return mobileProvision{}, &UserError{Code: "signed_ipa_invalid", Message: "签名辅助组件返回的 IPA 无法读取"}
	}
	defer r.Close()
	for _, file := range r.File {
		if !strings.HasSuffix(file.Name, ".app/embedded.mobileprovision") {
			continue
		}
		reader, openErr := file.Open()
		if openErr != nil {
			return mobileProvision{}, openErr
		}
		profilePath := filepath.Join(tempDir, "embedded.mobileprovision")
		out, copyErr := os.Create(profilePath)
		if copyErr != nil {
			reader.Close()
			return mobileProvision{}, copyErr
		}
		_, copyErr = out.ReadFrom(reader)
		reader.Close()
		_ = out.Close()
		if copyErr != nil {
			return mobileProvision{}, copyErr
		}
		return s.parseProfile(ctx, profilePath)
	}
	return mobileProvision{}, &UserError{Code: "profile_missing", Message: "签名产物中缺少描述文件"}
}
