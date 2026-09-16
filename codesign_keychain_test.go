package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestEphemeralLoginIdentityCanCodesign(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("codesign recipe is macOS-only")
	}
	if os.Getenv("CI") != "" {
		t.Skip("login keychain codesign waits for UI on GitHub-hosted runners")
	}
	var opensslCandidates []string
	if prefix := os.Getenv("OPENSSL_PREFIX"); prefix != "" {
		opensslCandidates = append(opensslCandidates, filepath.Join(prefix, "bin", "openssl"))
	}
	opensslCandidates = append(opensslCandidates,
		"/opt/homebrew/opt/openssl@3/bin/openssl",
		"/usr/local/opt/openssl@3/bin/openssl",
	)
	opensslBin := ""
	for _, candidate := range opensslCandidates {
		if _, err := os.Stat(candidate); err == nil {
			opensslBin = candidate
			break
		}
	}
	if opensslBin == "" {
		path, lookErr := exec.LookPath("openssl")
		if lookErr != nil {
			t.Skip("openssl is not available")
		}
		opensslBin = path
	}
	work := t.TempDir()
	hello := filepath.Join(work, "hello")
	src := filepath.Join(work, "hello.c")
	if err := os.WriteFile(src, []byte("int main(void) { return 0; }\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command("clang", "-o", hello, src).CombinedOutput(); err != nil {
		t.Fatalf("clang: %s\n%s", err, out)
	}
	cn := "IPARenewalAssistant Test " + time.Now().Format("150405.000")
	req := filepath.Join(work, "req.cnf")
	if err := os.WriteFile(req, []byte(`[req]
distinguished_name = req_distinguished_name
x509_extensions = v3_codesign
prompt = no
[req_distinguished_name]
CN = `+cn+`
[v3_codesign]
basicConstraints = CA:FALSE
keyUsage = digitalSignature
extendedKeyUsage = codeSigning
`), 0o600); err != nil {
		t.Fatal(err)
	}
	key := filepath.Join(work, "key.pem")
	cert := filepath.Join(work, "cert.pem")
	p12 := filepath.Join(work, "ident.p12")
	if out, err := exec.Command(opensslBin, "req", "-new", "-newkey", "rsa:2048", "-nodes", "-x509", "-days", "1",
		"-config", req, "-keyout", key, "-out", cert).CombinedOutput(); err != nil {
		t.Fatalf("openssl req: %s\n%s", err, out)
	}
	if out, err := exec.Command(opensslBin, "pkcs12", "-export", "-inkey", key, "-in", cert, "-out", p12,
		"-passout", "pass:altsign", "-name", cn, "-certpbe", "PBE-SHA1-3DES", "-keypbe", "PBE-SHA1-3DES", "-macalg", "SHA1").CombinedOutput(); err != nil {
		t.Fatalf("openssl pkcs12: %s\n%s", err, out)
	}
	login := filepath.Join(os.Getenv("HOME"), "Library", "Keychains", "login.keychain-db")
	if _, err := os.Stat(login); err != nil {
		login = filepath.Join(os.Getenv("HOME"), "Library", "Keychains", "login.keychain")
	}
	if out, err := exec.Command("/usr/bin/security", "import", p12, "-k", login, "-P", "altsign",
		"-T", "/usr/bin/codesign", "-T", "/usr/bin/security").CombinedOutput(); err != nil {
		t.Fatalf("security import: %s\n%s", err, out)
	}
	list, err := exec.Command("/usr/bin/security", "find-identity", "-p", "codesigning", login).CombinedOutput()
	if err != nil {
		t.Fatalf("find-identity: %s\n%s", err, list)
	}
	hash := ""
	for _, line := range strings.Split(string(list), "\n") {
		if strings.Contains(line, cn) {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				hash = fields[1]
			}
			break
		}
	}
	if len(hash) != 40 {
		t.Fatalf("missing identity hash for %s\n%s", cn, list)
	}
	t.Cleanup(func() {
		_ = exec.Command("/usr/bin/security", "delete-identity", "-Z", hash, login).Run()
	})
	if out, err := exec.Command("/usr/bin/codesign", "--force", "--sign", hash, hello).CombinedOutput(); err != nil {
		t.Fatalf("codesign: %s\n%s", err, out)
	}
	if out, err := exec.Command("/usr/bin/codesign", "--verify", hello).CombinedOutput(); err != nil {
		t.Fatalf("codesign verify: %s\n%s", err, out)
	}
	if out, err := exec.Command("/usr/bin/security", "delete-identity", "-Z", hash, login).CombinedOutput(); err != nil {
		t.Fatalf("delete-identity: %s\n%s", err, out)
	}
	hash = ""
}
