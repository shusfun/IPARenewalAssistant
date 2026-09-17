package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

const (
	appBundleID   = "com.shus.iparenewalassistant"
	currentSchema = 2
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
	support := filepath.Join(home, "Library", "Application Support", appBundleID)
	cache := filepath.Join(home, "Library", "Caches", appBundleID)
	library := strings.TrimSpace(os.Getenv("IPARENEWAL_LIBRARY"))
	if library == "" {
		library = support
	}
	cacheDir := strings.TrimSpace(os.Getenv("IPARENEWAL_CACHE"))
	if cacheDir == "" {
		cacheDir = cache
	}
	return Paths{
		StateFile: filepath.Join(support, "state.json"),
		AuditFile: filepath.Join(support, "audit.jsonl"),
		Library:   library,
		Cache:     cacheDir,
	}, nil
}

func checkStorage(paths Paths) error {
	for _, dir := range []string{paths.Library, paths.Cache} {
		if strings.TrimSpace(dir) == "" {
			return fmt.Errorf("应用目录未配置")
		}
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return fmt.Errorf("无法创建应用目录")
		}
		probe, err := os.CreateTemp(dir, ".iparenewal-write-check-*")
		if err != nil {
			return fmt.Errorf("应用目录当前不可写")
		}
		name := probe.Name()
		_ = probe.Close()
		_ = os.Remove(name)
	}
	return nil
}
