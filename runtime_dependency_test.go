package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The production Go layer must never regain the removed IDE/device CLI
// commands. Test adapters use injectable hooks instead of command-name tricks.
func TestProductionDoesNotReferenceRemovedCLIs(t *testing.T) {
	for _, name := range []string{"app.go", "apple_backend.go", "command.go", "devices.go", "environment.go", "ipa.go", "operations.go", "profile.go", "service.go", "signing.go", "store.go"} {
		path := filepath.Join(".", name)
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		text := strings.ToLower(string(data))
		for _, forbidden := range []string{"xcodebuild", "xcrun", "devicectl"} {
			if strings.Contains(text, forbidden) {
				t.Fatalf("%s references removed runtime command %q", name, forbidden)
			}
		}
	}
}

func TestProductionDoesNotBind980ProVolume(t *testing.T) {
	files := []string{
		"config.go",
		"environment.go",
		"service.go",
		filepath.Join("scripts", "dev.sh"),
		filepath.Join("frontend", "src", "App.tsx"),
	}
	for _, name := range files {
		data, err := os.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		text := string(data)
		if strings.Contains(text, "26CAAB44-4990-4003-9F28-D4FB791D33D1") || strings.Contains(text, "/Volumes/980Pro") {
			t.Fatalf("%s still binds the 980Pro volume", name)
		}
	}
}

func TestDefaultPathsUseUserLibrary(t *testing.T) {
	t.Setenv("IPARENEWAL_LIBRARY", "")
	t.Setenv("IPARENEWAL_CACHE", "")
	paths, err := defaultPaths()
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(paths.Library, "/Volumes/980Pro") || strings.Contains(paths.Cache, "/Volumes/980Pro") {
		t.Fatalf("paths still on 980Pro: %+v", paths)
	}
	if !strings.Contains(paths.Library, "Application Support") {
		t.Fatalf("library = %q", paths.Library)
	}
	if !strings.Contains(paths.Cache, "Caches") {
		t.Fatalf("cache = %q", paths.Cache)
	}
}

func TestDefaultPathsHonorLibraryAndCacheEnv(t *testing.T) {
	library := t.TempDir()
	cache := t.TempDir()
	t.Setenv("IPARENEWAL_LIBRARY", library)
	t.Setenv("IPARENEWAL_CACHE", cache)
	paths, err := defaultPaths()
	if err != nil {
		t.Fatal(err)
	}
	if paths.Library != library || paths.Cache != cache {
		t.Fatalf("paths = %+v", paths)
	}
}

func TestCheckStorageAcceptsWritableUserDirs(t *testing.T) {
	paths := Paths{Library: t.TempDir(), Cache: t.TempDir()}
	if err := checkStorage(paths); err != nil {
		t.Fatal(err)
	}
}

func TestBuildScriptsDoNotDefaultToIntelOpenSSL(t *testing.T) {
	files := []string{
		filepath.Join("native", "altsign-cli", "build.sh"),
		filepath.Join("scripts", "dev.sh"),
		filepath.Join("scripts", "build-signer.sh"),
		filepath.Join("scripts", "sign-altsign-cli.sh"),
		filepath.Join("scripts", "build-app.sh"),
		"codesign_keychain_test.go",
	}
	needle := "OPENSSL_PREFIX:-/usr/local/opt/openssl@3"
	for _, name := range files {
		data, err := os.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(data), needle) {
			t.Fatalf("%s still defaults OpenSSL to the Intel Homebrew path", name)
		}
	}
}
