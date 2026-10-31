package backup

import (
	"bytes"
	"io"
	"strings"
	"testing"
)

func encryptForTest(t *testing.T, plain, key []byte) []byte {
	t.Helper()
	var encoded bytes.Buffer
	w, err := NewStreamWriter(&encoded, key)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = w.Write(plain); err != nil {
		t.Fatal(err)
	}
	if err = w.Close(); err != nil {
		t.Fatal(err)
	}
	return encoded.Bytes()
}

func TestEncryptedStreamRoundTripsEmptyAndMultiChunkData(t *testing.T) {
	key := []byte("test-only-backup-key")
	for _, tc := range []struct {
		name string
		data []byte
	}{
		{name: "empty"},
		{name: "single chunk", data: bytes.Repeat([]byte("Yggdrasil backup data "), 900)},
		{name: "multiple chunks", data: bytes.Repeat([]byte("sensitive server file payload\n"), streamChunkSize*3/28)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			encoded := encryptForTest(t, tc.data, key)
			r, err := NewStreamReader(bytes.NewReader(encoded), key)
			if err != nil {
				t.Fatal(err)
			}
			got, err := io.ReadAll(r)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got, tc.data) {
				t.Fatalf("round trip changed %d bytes", len(tc.data))
			}
		})
	}
}

func TestEncryptedStreamRejectsWrongKeyTamperingTruncationAndTrailingData(t *testing.T) {
	key := []byte("original-backup-key")
	plain := bytes.Repeat([]byte("restore must verify before writing\n"), 3000)
	encoded := encryptForTest(t, plain, key)
	for _, tc := range []struct {
		name string
		data []byte
		key  []byte
	}{
		{name: "wrong key", data: encoded, key: []byte("another-backup-key")},
		{name: "changed ciphertext", data: mutate(encoded, 24), key: key},
		{name: "truncated final frame", data: encoded[:len(encoded)-5], key: key},
		{name: "trailing bytes", data: append(append([]byte(nil), encoded...), 1, 2), key: key},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r, err := NewStreamReader(bytes.NewReader(tc.data), tc.key)
			if err != nil {
				t.Fatal(err)
			}
			_, err = io.ReadAll(r)
			if err == nil || !strings.Contains(strings.ToLower(err.Error()), "backup") {
				t.Fatalf("expected a descriptive backup integrity error, got %v", err)
			}
		})
	}
}

func mutate(data []byte, at int) []byte {
	out := append([]byte(nil), data...)
	if at >= 0 && at < len(out) {
		out[at] ^= 0x80
	}
	return out
}
