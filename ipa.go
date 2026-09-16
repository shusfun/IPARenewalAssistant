package main

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"debug/macho"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"howett.net/plist"
)

const maxExpandedIPA = int64(4 << 30)

type ipaInfo struct {
	Name          string
	Version       string
	BuildVersion  string
	BundleID      string
	MinimumOS     string
	Executable    string
	AppDirectory  string
	IconEntryName string
	Objects       []string
}

func (s *Service) ImportIPA(path string) (AppView, error) {
	if err := s.ensureExternalStorage(); err != nil {
		return AppView{}, err
	}
	if !strings.EqualFold(filepath.Ext(path), ".ipa") {
		return AppView{}, &UserError{Code: "not_ipa", Message: "请选择 .ipa 文件"}
	}
	hash, err := hashFile(path)
	if err != nil {
		return AppView{}, &UserError{Code: "ipa_read_failed", Message: "无法读取 IPA 文件"}
	}
	s.audit(AuditEvent{Kind: "import", Stage: "start", Status: "started", AppID: hash[:16], Message: "开始导入 IPA"})
	state := s.store.Snapshot()
	if existing := state.Apps[hash[:16]]; existing != nil && existing.SHA256 == hash {
		if existing.IconPath == "" {
			if info, inspectErr := inspectIPA(path); inspectErr == nil && info.IconEntryName != "" {
				iconPath := filepath.Join(s.paths.Library, "icons", hash+".png")
				if extractErr := extractZipEntry(path, info.IconEntryName, iconPath, 32<<20); extractErr == nil {
					s.normalizeIcon(iconPath)
					_ = s.store.Update(func(next *State) error {
						next.Apps[existing.ID].IconPath = iconPath
						return nil
					})
					existing = s.store.Snapshot().Apps[existing.ID]
				}
			}
		}
		s.audit(AuditEvent{Kind: "import", Stage: "commit", Status: "success", AppID: existing.ID, BundleID: existing.EffectiveBundleID, Message: "IPA 已在托管库中，复用已有记录"})
		return s.appView(existing, state.SelectedDeviceID, s.now()), nil
	}
	info, err := inspectIPA(path)
	if err != nil {
		return AppView{}, err
	}
	originalPath := filepath.Join(s.paths.Library, "originals", hash+".ipa")
	if _, err := os.Stat(originalPath); os.IsNotExist(err) {
		if err := copyFileAtomic(path, originalPath); err != nil {
			return AppView{}, &UserError{Code: "ipa_copy_failed", Message: "无法把原始 IPA 复制到托管库"}
		}
	}
	iconPath := ""
	if info.IconEntryName != "" {
		iconPath = filepath.Join(s.paths.Library, "icons", hash+".png")
		if err := extractZipEntry(path, info.IconEntryName, iconPath, 32<<20); err != nil {
			iconPath = ""
		} else {
			s.normalizeIcon(iconPath)
		}
	}
	managed := &ManagedApp{
		ID: hash[:16], SHA256: hash, OriginalPath: originalPath,
		OriginalBundleID: info.BundleID, EffectiveBundleID: info.BundleID,
		Name: info.Name, Version: info.Version, BuildVersion: info.BuildVersion,
		MinimumOS: info.MinimumOS, Executable: info.Executable,
		AppDirectory: info.AppDirectory, IconPath: iconPath, SigningObjects: info.Objects,
		ImportedAt: s.now(), Installs: make(map[string]InstallRecord),
	}
	if err := s.store.Update(func(state *State) error {
		state.Apps[managed.ID] = managed
		return nil
	}); err != nil {
		s.audit(AuditEvent{Kind: "import", Stage: "commit", Status: "failed", AppID: managed.ID, BundleID: managed.EffectiveBundleID, ErrorCode: "state_write_failed", Message: "导入状态写入失败"})
		return AppView{}, err
	}
	s.audit(AuditEvent{Kind: "import", Stage: "commit", Status: "success", AppID: managed.ID, BundleID: managed.EffectiveBundleID, Message: "IPA 已导入"})
	return s.appView(managed, s.store.Snapshot().SelectedDeviceID, s.now()), nil
}

func (s *Service) normalizeIcon(path string) {
	// CgBI 图标是 Apple 的私有 PNG 变体，系统预览和前端均可直接读取原始
	// 字节；不再调用外部图像工具，避免引入 IDE 运行时依赖。
	_ = path
}

func hashFile(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func inspectIPA(path string) (ipaInfo, error) {
	zr, err := zip.OpenReader(path)
	if err != nil {
		return ipaInfo{}, &UserError{Code: "invalid_zip", Message: "IPA 不是有效的 ZIP 文件或已经损坏"}
	}
	defer zr.Close()
	var total int64
	mainApps := map[string]bool{}
	for _, entry := range zr.File {
		clean := filepath.ToSlash(filepath.Clean(entry.Name))
		if strings.HasPrefix(clean, "../") || strings.HasPrefix(clean, "/") {
			return ipaInfo{}, &UserError{Code: "unsafe_zip", Message: "IPA 包含不安全的文件路径"}
		}
		total += int64(entry.UncompressedSize64)
		if total > maxExpandedIPA {
			return ipaInfo{}, &UserError{Code: "ipa_too_large", Message: "IPA 解包后的体积超过 4 GB 限制"}
		}
		parts := strings.Split(clean, "/")
		if len(parts) >= 2 && parts[0] == "Payload" && strings.HasSuffix(parts[1], ".app") {
			mainApps[parts[1]] = true
		}
		lower := strings.ToLower(clean)
		if strings.Contains(lower, "/plugins/") && strings.Contains(lower, ".appex/") {
			return ipaInfo{}, &UserError{Code: "extension_unsupported", Message: "此 IPA 包含 App Extension，第一版不会执行不完整签名"}
		}
		if strings.Contains(lower, "/watch/") || strings.Contains(lower, ".watchkitapp/") {
			return ipaInfo{}, &UserError{Code: "watch_unsupported", Message: "此 IPA 包含 Watch App，第一版暂不支持"}
		}
		if strings.Contains(lower, "/appclips/") {
			return ipaInfo{}, &UserError{Code: "appclip_unsupported", Message: "此 IPA 包含 App Clip，第一版暂不支持"}
		}
	}
	if len(mainApps) != 1 {
		return ipaInfo{}, &UserError{Code: "main_app_count", Message: "IPA 必须只包含一个主 App"}
	}
	var appName string
	for name := range mainApps {
		appName = name
	}
	appDir := "Payload/" + appName
	infoEntry := findZipEntry(zr.File, appDir+"/Info.plist")
	if infoEntry == nil {
		return ipaInfo{}, &UserError{Code: "info_missing", Message: "主 App 缺少 Info.plist"}
	}
	infoBytes, err := readZipEntry(infoEntry, 16<<20)
	if err != nil {
		return ipaInfo{}, &UserError{Code: "info_invalid", Message: "无法读取主 App 的 Info.plist"}
	}
	var values map[string]any
	if _, err := plist.Unmarshal(infoBytes, &values); err != nil {
		return ipaInfo{}, &UserError{Code: "info_invalid", Message: "主 App 的 Info.plist 已损坏"}
	}
	result := ipaInfo{
		Name:         plistString(values, "CFBundleDisplayName", "CFBundleName"),
		Version:      plistString(values, "CFBundleShortVersionString"),
		BuildVersion: plistString(values, "CFBundleVersion"),
		BundleID:     plistString(values, "CFBundleIdentifier"),
		MinimumOS:    plistString(values, "MinimumOSVersion"),
		Executable:   plistString(values, "CFBundleExecutable"),
		AppDirectory: appDir,
	}
	if result.Name == "" {
		result.Name = strings.TrimSuffix(appName, ".app")
	}
	if result.BundleID == "" || result.Executable == "" {
		return ipaInfo{}, &UserError{Code: "metadata_missing", Message: "IPA 缺少 Bundle ID 或主可执行文件信息"}
	}
	execEntry := findZipEntry(zr.File, appDir+"/"+result.Executable)
	if execEntry == nil {
		return ipaInfo{}, &UserError{Code: "executable_missing", Message: "IPA 中找不到主可执行文件"}
	}
	executable, err := readZipEntry(execEntry, 1<<30)
	if err != nil {
		return ipaInfo{}, &UserError{Code: "executable_invalid", Message: "无法读取主可执行文件"}
	}
	if err := validateMainMachO(executable); err != nil {
		return ipaInfo{}, err
	}
	if icon := chooseIcon(zr.File, appDir, values); icon != nil {
		result.IconEntryName = icon.Name
	}
	objectSet := map[string]bool{}
	for _, entry := range zr.File {
		clean := filepath.ToSlash(filepath.Clean(entry.Name))
		if !strings.HasPrefix(clean, appDir+"/") {
			continue
		}
		if idx := strings.Index(clean, ".framework/"); idx >= 0 {
			objectSet[clean[:idx+len(".framework")]] = true
		}
		if strings.HasSuffix(strings.ToLower(clean), ".dylib") {
			objectSet[clean] = true
		}
		reader, openErr := entry.Open()
		if openErr != nil {
			return ipaInfo{}, &UserError{Code: "invalid_zip", Message: "IPA 文件内容已损坏"}
		}
		if _, copyErr := io.Copy(io.Discard, reader); copyErr != nil {
			reader.Close()
			return ipaInfo{}, &UserError{Code: "invalid_zip", Message: "IPA 文件内容校验失败"}
		}
		reader.Close()
	}
	for object := range objectSet {
		result.Objects = append(result.Objects, object)
	}
	sort.Strings(result.Objects)
	return result, nil
}

func validateMainMachO(data []byte) error {
	reader := bytes.NewReader(data)
	if fat, err := macho.NewFatFile(reader); err == nil {
		defer fat.Close()
		for _, arch := range fat.Arches {
			if arch.Cpu == macho.CpuArm64 {
				return validateMachOSlice(arch.File)
			}
		}
		return &UserError{Code: "arm64_required", Message: "主程序不包含 arm64 架构，无法安装到当前 iOS 设备"}
	}
	file, err := macho.NewFile(reader)
	if err != nil {
		return &UserError{Code: "macho_invalid", Message: "主可执行文件不是有效的 Mach-O"}
	}
	defer file.Close()
	if file.Cpu != macho.CpuArm64 {
		return &UserError{Code: "arm64_required", Message: "主程序不是 arm64 架构"}
	}
	return validateMachOSlice(file)
}

func validateMachOSlice(file *macho.File) error {
	for _, load := range file.Loads {
		raw := load.Raw()
		if len(raw) < 20 {
			continue
		}
		cmd := file.ByteOrder.Uint32(raw[:4])
		if cmd == 0x21 || cmd == 0x2c {
			cryptID := file.ByteOrder.Uint32(raw[16:20])
			if cryptID != 0 {
				return &UserError{Code: "encrypted_macho", Message: "主程序仍受 App Store DRM 加密，无法重签", Recovery: "请使用开发者提供的未加密 IPA；本工具不会尝试绕过 DRM。"}
			}
		}
	}
	return nil
}

func plistString(values map[string]any, keys ...string) string {
	for _, key := range keys {
		if value, ok := values[key].(string); ok && value != "" {
			return value
		}
	}
	return ""
}

func findZipEntry(entries []*zip.File, name string) *zip.File {
	for _, entry := range entries {
		if filepath.ToSlash(filepath.Clean(entry.Name)) == name {
			return entry
		}
	}
	return nil
}

func readZipEntry(entry *zip.File, max int64) ([]byte, error) {
	reader, err := entry.Open()
	if err != nil {
		return nil, err
	}
	defer reader.Close()
	var out bytes.Buffer
	if err := copyLimited(&out, reader, max); err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}

func chooseIcon(entries []*zip.File, appDir string, values map[string]any) *zip.File {
	var names []string
	collectIconNames(values["CFBundleIconFiles"], &names)
	collectIconNames(values["CFBundleIcons"], &names)
	collectIconNames(values["CFBundleIcons~ipad"], &names)
	var candidates []*zip.File
	for _, entry := range entries {
		clean := filepath.ToSlash(filepath.Clean(entry.Name))
		if !strings.HasPrefix(clean, appDir+"/") || !strings.HasSuffix(strings.ToLower(clean), ".png") {
			continue
		}
		base := strings.TrimSuffix(filepath.Base(clean), filepath.Ext(clean))
		for _, name := range names {
			wanted := strings.TrimSuffix(filepath.Base(name), filepath.Ext(name))
			if strings.HasPrefix(base, wanted) {
				candidates = append(candidates, entry)
				break
			}
		}
		if len(names) == 0 && strings.HasPrefix(strings.ToLower(base), "icon") {
			candidates = append(candidates, entry)
		}
	}
	if len(candidates) == 0 {
		return nil
	}
	sort.Slice(candidates, func(i, j int) bool { return candidates[i].UncompressedSize64 > candidates[j].UncompressedSize64 })
	return candidates[0]
}

func collectIconNames(value any, names *[]string) {
	switch typed := value.(type) {
	case string:
		*names = append(*names, typed)
	case []any:
		for _, item := range typed {
			collectIconNames(item, names)
		}
	case []string:
		*names = append(*names, typed...)
	case map[string]any:
		for key, item := range typed {
			if key == "CFBundleIconFiles" || key == "CFBundlePrimaryIcon" {
				collectIconNames(item, names)
			}
		}
	case map[any]any:
		for key, item := range typed {
			if fmt.Sprint(key) == "CFBundleIconFiles" || fmt.Sprint(key) == "CFBundlePrimaryIcon" {
				collectIconNames(item, names)
			}
		}
	}
}

func copyFileAtomic(source, destination string) error {
	in, err := os.Open(source)
	if err != nil {
		return err
	}
	defer in.Close()
	tmp, err := os.CreateTemp(filepath.Dir(destination), ".ipa-*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if _, err := io.Copy(tmp, in); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, destination)
}

func extractZipFile(entry *zip.File, destination string, max int64) error {
	reader, err := entry.Open()
	if err != nil {
		return err
	}
	defer reader.Close()
	tmp, err := os.CreateTemp(filepath.Dir(destination), ".icon-*.tmp")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer os.Remove(name)
	if err := copyLimited(tmp, reader, max); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(name, destination)
}

func extractZipEntry(archivePath, entryName, destination string, max int64) error {
	archive, err := zip.OpenReader(archivePath)
	if err != nil {
		return err
	}
	defer archive.Close()
	entry := findZipEntry(archive.File, filepath.ToSlash(filepath.Clean(entryName)))
	if entry == nil {
		return fmt.Errorf("ZIP 条目不存在")
	}
	return extractZipFile(entry, destination, max)
}

func (s *Service) appView(app *ManagedApp, deviceID string, now time.Time) AppView {
	view := AppView{ID: app.ID, Name: app.Name, Version: app.Version, BuildVersion: app.BuildVersion,
		OriginalBundleID: app.OriginalBundleID, EffectiveBundleID: app.EffectiveBundleID,
		MinimumOS: app.MinimumOS, ImportedAt: app.ImportedAt, ValidityStatus: "unsigned"}
	if app.IconPath != "" {
		if b, err := os.ReadFile(app.IconPath); err == nil {
			view.IconDataURL = "data:image/png;base64," + base64.StdEncoding.EncodeToString(b)
		}
	}
	if app.LatestSigned != nil {
		view.Signed = true
		t := app.LatestSigned.SignedAt
		view.SignedAt = &t
	}
	if install, ok := app.Installs[deviceID]; ok && install.Present {
		view.Installed = true
		t := install.InstalledAt
		view.InstalledAt = &t
		exp := install.Profile.ExpirationTime
		view.ExpirationTime = &exp
		view.RemainingSeconds = int64(exp.Sub(now).Seconds())
		view.ValidityStatus = validityStatus(now, exp)
		view.CanRenew = view.RemainingSeconds <= int64((72 * time.Hour).Seconds())
	}
	return view
}

func validityStatus(now, expiration time.Time) string {
	remaining := expiration.Sub(now)
	if remaining <= 0 {
		return "expired"
	}
	if remaining <= 72*time.Hour {
		return "expiring"
	}
	return "valid"
}
