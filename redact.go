package main

import (
	"path/filepath"
	"regexp"
	"strings"
)

var (
	emailPattern      = regexp.MustCompile(`(?i)[A-Z0-9._%+\-]+@[A-Z0-9.\-]+\.[A-Z]{2,}`)
	hexSecretPattern  = regexp.MustCompile(`(?i)\b[0-9a-f]{40,64}\b`)
	deviceUUIDPattern = regexp.MustCompile(`(?i)\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b`)
	appleUDIDPattern  = regexp.MustCompile(`(?i)\b[0-9a-f]{8}-[0-9a-f]{16}\b`)
	identifierField   = regexp.MustCompile(`(?i)(\b(?:id|udid|serialnumber)\s*[:=]\s*)[a-z0-9-]{8,}`)
	deviceNameField   = regexp.MustCompile(`(?i)(\bname\s*:\s*)[^,}\n]+`)
	certificateName   = regexp.MustCompile(`Apple Development:[^\n"]+`)
	tokenPattern      = regexp.MustCompile(`(?i)(token|password|authorization|cookie|verification(?:code)?|code)\s*[:=]\s*\S+`)
)

func redact(text string) string {
	text = emailPattern.ReplaceAllString(text, "<已隐藏账号>")
	text = deviceUUIDPattern.ReplaceAllString(text, "<已隐藏设备标识>")
	text = appleUDIDPattern.ReplaceAllString(text, "<已隐藏设备标识>")
	text = identifierField.ReplaceAllString(text, "$1<已隐藏设备标识>")
	text = deviceNameField.ReplaceAllString(text, "$1<已隐藏设备名称>")
	text = certificateName.ReplaceAllString(text, "Apple Development: <已隐藏证书>")
	text = hexSecretPattern.ReplaceAllString(text, "<已隐藏指纹>")
	text = tokenPattern.ReplaceAllString(text, "$1=<已隐藏>")
	if home, err := filepath.Abs(strings.TrimSpace(userHome())); err == nil && home != "." {
		text = strings.ReplaceAll(text, home, "~")
	}
	if len(text) > 4000 {
		text = text[len(text)-4000:]
	}
	return strings.TrimSpace(text)
}

func userHome() string {
	paths, err := defaultPaths()
	if err != nil {
		return ""
	}
	return filepath.Clean(filepath.Join(filepath.Dir(paths.StateFile), "..", "..", ".."))
}
