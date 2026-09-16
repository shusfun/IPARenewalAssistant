package main

import (
	"archive/zip"
	"bytes"
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"

	"howett.net/plist"
)

func machoArm64(cryptID uint32) []byte {
	buffer := new(bytes.Buffer)
	values := []uint32{0xfeedfacf, 0x0100000c, 0, 2, 1, 24, 0, 0, 0x2c, 24, 0, 0, cryptID, 0}
	for _, value := range values {
		_ = binary.Write(buffer, binary.LittleEndian, value)
	}
	return buffer.Bytes()
}

func writeTestIPA(t *testing.T, entries map[string][]byte) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "test.ipa")
	file, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	writer := zip.NewWriter(file)
	for name, data := range entries {
		entry, err := writer.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := entry.Write(data); err != nil {
			t.Fatal(err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	return path
}

func validIPAEntries(t *testing.T) map[string][]byte {
	t.Helper()
	info, err := plist.Marshal(map[string]any{
		"CFBundleDisplayName": "Test", "CFBundleIdentifier": "com.example.test",
		"CFBundleExecutable": "Test", "CFBundleShortVersionString": "1.0", "CFBundleVersion": "1",
	}, plist.XMLFormat)
	if err != nil {
		t.Fatal(err)
	}
	return map[string][]byte{"Payload/Test.app/Info.plist": info, "Payload/Test.app/Test": machoArm64(0)}
}

func TestInspectIPAValidatesMainApp(t *testing.T) {
	info, err := inspectIPA(writeTestIPA(t, validIPAEntries(t)))
	if err != nil {
		t.Fatal(err)
	}
	if info.BundleID != "com.example.test" || info.Executable != "Test" {
		t.Fatalf("unexpected info: %#v", info)
	}
}

func TestInspectIPARejectsEncryptedMachO(t *testing.T) {
	entries := validIPAEntries(t)
	entries["Payload/Test.app/Test"] = machoArm64(1)
	_, err := inspectIPA(writeTestIPA(t, entries))
	if err == nil || !stringsContains(err.Error(), "DRM") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestInspectIPARejectsExtensionsAndMultipleApps(t *testing.T) {
	entries := validIPAEntries(t)
	entries["Payload/Test.app/PlugIns/Share.appex/Info.plist"] = []byte("x")
	if _, err := inspectIPA(writeTestIPA(t, entries)); err == nil {
		t.Fatal("expected extension rejection")
	}
	entries = validIPAEntries(t)
	entries["Payload/Other.app/Info.plist"] = []byte("x")
	if _, err := inspectIPA(writeTestIPA(t, entries)); err == nil {
		t.Fatal("expected multiple app rejection")
	}
}

func TestInspectIPARejectsBrokenZip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "broken.ipa")
	if err := os.WriteFile(path, []byte("not a zip"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := inspectIPA(path); err == nil {
		t.Fatal("expected invalid zip error")
	}
}

func TestChooseIconReadsNestedIconDeclarations(t *testing.T) {
	entries := validIPAEntries(t)
	entries["Payload/Test.app/AppIcon60x60@2x.png"] = []byte("small")
	entries["Payload/Test.app/AppIcon60x60@3x.png"] = []byte("larger-icon")
	path := writeTestIPA(t, entries)
	archive, err := zip.OpenReader(path)
	if err != nil {
		t.Fatal(err)
	}
	defer archive.Close()
	chosen := chooseIcon(archive.File, "Payload/Test.app", map[string]any{
		"CFBundleIcons": map[string]any{"CFBundlePrimaryIcon": map[string]any{"CFBundleIconFiles": []string{"AppIcon60x60"}}},
	})
	if chosen == nil || chosen.Name != "Payload/Test.app/AppIcon60x60@3x.png" {
		t.Fatalf("unexpected icon: %#v", chosen)
	}
}

func stringsContains(value, part string) bool { return bytes.Contains([]byte(value), []byte(part)) }
