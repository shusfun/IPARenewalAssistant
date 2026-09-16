package main

import (
	"context"
	"fmt"
	"os"
	"reflect"
	"strings"
	"time"

	"howett.net/plist"
)

type mobileProvision struct {
	UUID               string         `plist:"UUID"`
	TeamIdentifier     []string       `plist:"TeamIdentifier"`
	ApplicationPrefix  []string       `plist:"ApplicationIdentifierPrefix"`
	CreationDate       time.Time      `plist:"CreationDate"`
	ExpirationDate     time.Time      `plist:"ExpirationDate"`
	ProvisionedDevices []string       `plist:"ProvisionedDevices"`
	Entitlements       map[string]any `plist:"Entitlements"`
}

func (s *Service) parseProfile(ctx context.Context, path string) (mobileProvision, error) {
	result, err := s.runner.Run(ctx, CommandSpec{Name: "security", Args: []string{"cms", "-D", "-i", path}, Timeout: 20 * time.Second})
	if err != nil {
		return mobileProvision{}, commandError("profile_decode_failed", "无法解析签名生成的描述文件", "请确认系统 security 工具可用并重试。", result, err)
	}
	var profile mobileProvision
	if _, err := plist.Unmarshal(result.Stdout, &profile); err != nil {
		return mobileProvision{}, &UserError{Code: "profile_invalid", Message: "自动签名生成的描述文件格式无效"}
	}
	return profile, nil
}

func validateProfile(profile mobileProvision, teamID, bundleID, deviceUDID string, now time.Time) (ProfileMetadata, error) {
	if len(profile.TeamIdentifier) != 1 || profile.TeamIdentifier[0] != teamID {
		return ProfileMetadata{}, &UserError{Code: "profile_team_mismatch", Message: "描述文件的开发团队与所选团队不匹配"}
	}
	applicationID, _ := profile.Entitlements["application-identifier"].(string)
	if applicationID != teamID+"."+bundleID {
		return ProfileMetadata{}, &UserError{Code: "profile_bundle_mismatch", Message: "描述文件与目标 Bundle ID 不匹配"}
	}
	foundDevice := false
	for _, value := range profile.ProvisionedDevices {
		if value == deviceUDID {
			foundDevice = true
			break
		}
	}
	if !foundDevice {
		return ProfileMetadata{}, &UserError{Code: "profile_device_mismatch", Message: "描述文件没有包含当前设备", Recovery: "请解锁设备并保持 USB 连接，让 Apple 开发者服务注册后重试。"}
	}
	if profile.CreationDate.After(now.Add(5*time.Minute)) || !profile.ExpirationDate.After(now) {
		return ProfileMetadata{}, &UserError{Code: "profile_time_invalid", Message: "描述文件的创建时间或到期时间无效"}
	}
	return ProfileMetadata{UUID: profile.UUID, TeamID: teamID, BundleID: bundleID, CreationTime: profile.CreationDate, ExpirationTime: profile.ExpirationDate}, nil
}

func buildEntitlements(original, allowed map[string]any) ([]byte, error) {
	result := make(map[string]any)
	core := []string{"application-identifier", "com.apple.developer.team-identifier", "get-task-allow", "keychain-access-groups"}
	for _, key := range core {
		if value, ok := allowed[key]; ok {
			result[key] = value
		}
	}
	for key, requested := range original {
		if key == "application-identifier" || key == "com.apple.developer.team-identifier" || key == "keychain-access-groups" {
			continue
		}
		permitted, ok := allowed[key]
		if !ok || !entitlementValueAllowed(requested, permitted) {
			label := key
			switch {
			case key == "aps-environment":
				label = "推送通知"
			case strings.Contains(key, "application-groups"):
				label = "App Groups"
			case strings.Contains(key, "icloud") || strings.Contains(key, "ubiquity"):
				label = "iCloud"
			}
			return nil, &UserError{Code: "capability_unsupported", Message: fmt.Sprintf("当前描述文件不允许原 App 使用的能力：%s", label), Recovery: "请使用不依赖该能力的开发版本，或在对应开发团队中配置能力后重试。"}
		}
		result[key] = requested
	}
	data, err := plist.Marshal(result, plist.XMLFormat)
	if err != nil {
		return nil, err
	}
	return data, nil
}

func entitlementValueAllowed(requested, allowed any) bool {
	if reflect.DeepEqual(requested, allowed) {
		return true
	}
	switch req := requested.(type) {
	case string:
		allow, ok := allowed.(string)
		return ok && strings.HasSuffix(allow, "*") && strings.HasPrefix(req, strings.TrimSuffix(allow, "*"))
	case []any:
		allow, ok := allowed.([]any)
		if !ok {
			return false
		}
		for _, item := range req {
			matched := false
			for _, candidate := range allow {
				if entitlementValueAllowed(item, candidate) {
					matched = true
					break
				}
			}
			if !matched {
				return false
			}
		}
		return true
	default:
		return false
	}
}

func writeEntitlements(path string, data []byte) error {
	return os.WriteFile(path, data, 0o600)
}
