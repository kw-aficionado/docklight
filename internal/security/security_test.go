package security

import (
	"strings"
	"testing"
	"time"
)

func TestArgon2idPasswordHash(t *testing.T) {
	hash, err := HashPassword("a strong test password")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(hash, "$argon2id$") {
		t.Fatalf("expected argon2id encoding, got %q", hash)
	}
	if !VerifyPassword(hash, "a strong test password") {
		t.Fatal("correct password did not verify")
	}
	if VerifyPassword(hash, "a different password") {
		t.Fatal("incorrect password verified")
	}
}

func TestAESGCMEncryptsAndDecrypts(t *testing.T) {
	key := []byte("test key")
	value, err := Encrypt(key, "super-secret-token")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(value, "super-secret-token") {
		t.Fatal("ciphertext contains the plaintext secret")
	}
	got, err := Decrypt(key, value)
	if err != nil {
		t.Fatal(err)
	}
	if got != "super-secret-token" {
		t.Fatalf("decrypted %q", got)
	}
	if _, err = Decrypt([]byte("wrong key"), value); err == nil {
		t.Fatal("expected wrong key to fail")
	}
}

func TestTOTPAuthenticatorVector(t *testing.T) {
	// RFC 6238 SHA-1 test secret and the six-digit value at t=59.
	secret := "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
	got, err := TOTP(secret, time.Unix(59, 0))
	if err != nil {
		t.Fatal(err)
	}
	if got != "287082" {
		t.Fatalf("expected RFC 6238 code 287082, got %s", got)
	}
	if _, ok := VerifyTOTP(secret, got, time.Unix(59, 0)); !ok {
		t.Fatal("valid authenticator code did not verify")
	}
}

func TestJWTSignatureAndExpiry(t *testing.T) {
	key := []byte("a session secret with enough entropy to test HS256")
	c := Claims{UserID: "user-1", Role: "user", Version: 2, Expires: time.Now().Add(time.Minute).Unix(), Issued: time.Now().Unix(), ID: "session"}
	token := SignJWT(key, c)
	got, err := ParseJWT(key, token)
	if err != nil {
		t.Fatal(err)
	}
	if got.UserID != "user-1" || got.Version != 2 {
		t.Fatalf("unexpected claims: %+v", got)
	}
	if _, err = ParseJWT([]byte("wrong"), token); err == nil {
		t.Fatal("wrong JWT key verified")
	}
	c.Expires = time.Now().Add(-time.Second).Unix()
	if _, err = ParseJWT(key, SignJWT(key, c)); err == nil {
		t.Fatal("expired JWT verified")
	}
}
