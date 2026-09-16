package main

import (
	"fmt"
	"os"
	"path/filepath"
)

const (
	appBundleID        = "com.shus.iparenewalassistant"
	expectedVolume     = "/Volumes/980Pro"
	expectedVolumeUUID = "26CAAB44-4990-4003-9F28-D4FB791D33D1"
	libraryRoot        = "/Volumes/980Pro/AppData/IPARenewalAssistant"
	cacheRoot          = "/Volumes/980Pro/Cache/IPARenewalAssistant"
	currentSchema      = 2
)

type Paths struct {
	StateFile string
	AuditFile string
	Library   string
	Cache     string
}

func defaultPaths() (Paths, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return Paths{}, fmt.Errorf("无法确定用户目录: %w", err)
	}
	return Paths{
		StateFile: filepath.Join(home, "Library", "Application Support", appBundleID, "state.json"),
		AuditFile: filepath.Join(home, "Library", "Application Support", appBundleID, "audit.jsonl"),
		Library:   libraryRoot,
		Cache:     cacheRoot,
	}, nil
}
