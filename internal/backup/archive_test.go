package backup

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCreateVerifyAndExtractEncryptedArchive(t *testing.T) {
	root := t.TempDir()
	if err := os.Mkdir(filepath.Join(root, "world"), 0700); err != nil {
		t.Fatal(err)
	}
	want := []byte("private player state and world data")
	file := filepath.Join(root, "world", "level.dat")
	if err := os.WriteFile(file, want, 0750); err != nil {
		t.Fatal(err)
	}
	key := []byte("test encryption key derived from auth secret")
	var encoded bytes.Buffer
	created, err := Create(&encoded, root, key)
	if err != nil {
		t.Fatal(err)
	}
	if created.Files != 1 || created.Directories != 1 || created.Bytes != int64(len(want)) {
		t.Fatalf("backup summary = %#v, want 1 file, 1 directory and %d bytes", created, len(want))
	}
	if bytes.Contains(encoded.Bytes(), want) {
		t.Fatal("backup archive contains the unencrypted server file")
	}
	verified, err := Verify(bytes.NewReader(encoded.Bytes()), key)
	if err != nil || verified != created {
		t.Fatalf("verification summary = %#v, err = %v", verified, err)
	}
	restored := filepath.Join(t.TempDir(), "restore")
	gotSummary, err := Extract(bytes.NewReader(encoded.Bytes()), restored, key)
	if err != nil || gotSummary != created {
		t.Fatalf("restore summary = %#v, err = %v", gotSummary, err)
	}
	got, err := os.ReadFile(filepath.Join(restored, "world", "level.dat"))
	if err != nil || !bytes.Equal(got, want) {
		t.Fatalf("restored file = %q, err = %v", got, err)
	}
}

func TestCreateRejectsSymbolicLinks(t *testing.T) {
	root := t.TempDir()
	secret := filepath.Join(t.TempDir(), "outside-secret")
	if err := os.WriteFile(secret, []byte("outside"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(secret, filepath.Join(root, "external")); err != nil {
		t.Skipf("symlinks are unavailable: %v", err)
	}
	var encoded bytes.Buffer
	_, err := Create(&encoded, root, []byte("backup-key"))
	if err == nil || !strings.Contains(err.Error(), "symbolic link") {
		t.Fatalf("expected a clear symbolic-link rejection, got %v", err)
	}
}

func TestVerifyRejectsTraversalPathAndCorruptTar(t *testing.T) {
	for _, tc := range []struct {
		name string
		path string
	}{
		{name: "parent traversal", path: "../escape.txt"},
		{name: "absolute path", path: "/tmp/escape.txt"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			encoded := encryptedTar(t, tc.path, []byte("never extract me"))
			if _, err := Verify(bytes.NewReader(encoded), []byte("backup-key")); err == nil || !strings.Contains(strings.ToLower(err.Error()), "unsafe path") {
				t.Fatalf("expected unsafe path rejection, got %v", err)
			}
		})
	}
}

func encryptedTar(t *testing.T, name string, body []byte) []byte {
	t.Helper()
	var encoded bytes.Buffer
	stream, err := NewStreamWriter(&encoded, []byte("backup-key"))
	if err != nil {
		t.Fatal(err)
	}
	compressed := gzip.NewWriter(stream)
	archive := tar.NewWriter(compressed)
	if err = archive.WriteHeader(&tar.Header{Name: name, Mode: 0600, Size: int64(len(body)), Typeflag: tar.TypeReg}); err != nil {
		t.Fatal(err)
	}
	if _, err = archive.Write(body); err != nil {
		t.Fatal(err)
	}
	if err = archive.Close(); err != nil {
		t.Fatal(err)
	}
	if err = compressed.Close(); err != nil {
		t.Fatal(err)
	}
	if err = stream.Close(); err != nil {
		t.Fatal(err)
	}
	return encoded.Bytes()
}
