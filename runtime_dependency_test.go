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
