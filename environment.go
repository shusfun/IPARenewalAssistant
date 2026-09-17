package main

import (
	"context"
	"crypto/sha1"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
)

type SigningIdentity struct {
	Fingerprint string
	Name        string
	TeamID      string
}

type Environment struct {
	Status     EnvironmentStatus
	Identities []SigningIdentity
}

var identityLinePattern = regexp.MustCompile(`(?m)^\s*\d+\)\s+([0-9A-Fa-f]{40})\s+"([^"]*Apple Development[^\"]*)"`)

func (s *Service) checkEnvironment(ctx context.Context) Environment {
	status := EnvironmentStatus{Issues: []string{}, PlatformSupported: runtime.GOOS == "darwin"}
	if !status.PlatformSupported {
		status.PlatformIssue = "当前版本仅支持 macOS"
		status.Issues = append(status.Issues, status.PlatformIssue)
	}
	if err := s.storageCheck(); err != nil {
		status.VolumeIssue = err.Error()
		status.Issues = append(status.Issues, err.Error())
	} else {
		status.VolumeAvailable = true
	}

	tools := []string{"security", "codesign", "ditto"}
	status.ToolsReady = true
	for _, tool := range tools {
		if _, err := os.Stat(filepath.Join("/usr/bin", tool)); err != nil {
			status.ToolsReady = false
			status.Issues = append(status.Issues, "缺少命令行工具: "+tool)
		}
	}
	status.SigningBackendReady = s.appleBackendReady()
	status.DeviceBackendReady = true
	status.AccountReady = s.storedAppleAccountReady()
	status.CanImport = status.PlatformSupported && status.VolumeAvailable
	status.CanSign = status.PlatformSupported && status.VolumeAvailable && status.SigningBackendReady && status.AccountReady && status.ToolsReady
	status.CanInstall = status.PlatformSupported && status.VolumeAvailable && status.DeviceBackendReady
	if !status.SigningBackendReady {
		status.Issues = append(status.Issues, "内置签名组件未就绪")
	}
	if !status.AccountReady {
		status.Issues = append(status.Issues, "尚未登录 Apple ID")
	}
	status.Ready = status.CanSign
	return Environment{Status: status}
}

func (s *Service) findSigningIdentities(ctx context.Context) ([]SigningIdentity, error) {
	result, err := s.runner.Run(ctx, CommandSpec{Name: "security", Args: []string{"find-identity", "-v", "-p", "codesigning"}})
	if err != nil {
		return nil, &UserError{Code: "identity_lookup_failed", Message: "无法读取代码签名身份", Recovery: "请确认 Apple 开发证书已安装且包含私钥。"}
	}
	matches := identityLinePattern.FindAllStringSubmatch(string(result.Stdout), -1)
	certificates, certErr := s.runner.Run(ctx, CommandSpec{Name: "security", Args: []string{"find-certificate", "-a", "-p"}})
	if certErr != nil {
		return nil, &UserError{Code: "certificate_lookup_failed", Message: "无法读取开发证书"}
	}
	certByFingerprint := make(map[string]*x509.Certificate)
	rest := certificates.Stdout
	for {
		block, remaining := pem.Decode(rest)
		if block == nil {
			break
		}
		rest = remaining
		certificate, parseErr := x509.ParseCertificate(block.Bytes)
		if parseErr != nil {
			continue
		}
		fingerprint := sha1.Sum(certificate.Raw)
		certByFingerprint[strings.ToUpper(hex.EncodeToString(fingerprint[:]))] = certificate
	}
	identities := make([]SigningIdentity, 0, len(matches))
	for _, match := range matches {
		fingerprint := strings.ToUpper(match[1])
		certificate := certByFingerprint[fingerprint]
		if certificate == nil || len(certificate.Subject.OrganizationalUnit) == 0 {
			continue
		}
		identities = append(identities, SigningIdentity{Fingerprint: fingerprint, Name: match[2], TeamID: certificate.Subject.OrganizationalUnit[0]})
	}
	sort.Slice(identities, func(i, j int) bool { return identities[i].Fingerprint < identities[j].Fingerprint })
	return identities, nil
}

func teamIDFromCertificate(data []byte) (string, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return "", fmt.Errorf("开发证书格式无效")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return "", err
	}
	if len(cert.Subject.OrganizationalUnit) == 0 || strings.TrimSpace(cert.Subject.OrganizationalUnit[0]) == "" {
		return "", fmt.Errorf("开发证书缺少 Team ID")
	}
	return cert.Subject.OrganizationalUnit[0], nil
}

func chooseIdentity(env Environment, preferred string) (SigningIdentity, error) {
	if len(env.Identities) == 0 {
		return SigningIdentity{}, &UserError{Code: "identity_missing", Message: "未找到可用的 Apple Development 身份", Recovery: "请在钥匙串中安装包含私钥的 Apple Development 证书。"}
	}
	if preferred != "" {
		for _, identity := range env.Identities {
			if identity.Fingerprint == preferred {
				return identity, nil
			}
		}
	}
	if len(env.Identities) == 1 {
		return env.Identities[0], nil
	}
	return SigningIdentity{}, &UserError{Code: "identity_selection_required", Message: "检测到多个开发签名身份，当前版本无法安全自动选择", Recovery: "请暂时移除不用的重复身份，或保留最近成功使用的身份后重试。"}
}
