package security

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base32"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/argon2"
)

const argonMemory = 32 * 1024

func HashPassword(password string) (string, error) {
	if len(password) < 12 {
		return "", errors.New("password must contain at least 12 characters")
	}
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	hash := argon2.IDKey([]byte(password), salt, 2, argonMemory, 1, 32)
	return fmt.Sprintf("$argon2id$v=19$m=32768,t=2,p=1$%s$%s", base64.RawStdEncoding.EncodeToString(salt), base64.RawStdEncoding.EncodeToString(hash)), nil
}
func VerifyPassword(encoded, password string) bool {
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 || parts[1] != "argon2id" || parts[2] != "v=19" {
		return false
	}
	params := map[string]int{}
	for _, field := range strings.Split(parts[3], ",") {
		pair := strings.SplitN(field, "=", 2)
		if len(pair) != 2 {
			return false
		}
		value, err := strconv.Atoi(pair[1])
		if err != nil {
			return false
		}
		params[pair[0]] = value
	}
	memory, iterations, parallelism := params["m"], params["t"], params["p"]
	if memory < 8192 || memory > 262144 || iterations < 1 || iterations > 10 || parallelism < 1 || parallelism > 8 {
		return false
	}
	salt64, hash64 := parts[4], parts[5]
	salt, e1 := base64.RawStdEncoding.DecodeString(salt64)
	want, e2 := base64.RawStdEncoding.DecodeString(hash64)
	if e1 != nil || e2 != nil || len(salt) < 8 || len(want) < 16 {
		return false
	}
	got := argon2.IDKey([]byte(password), salt, uint32(iterations), uint32(memory), uint8(parallelism), uint32(len(want)))
	return hmac.Equal(got, want)
}

func Encrypt(key []byte, plaintext string) (string, error) {
	k := sha256.Sum256(key)
	block, err := aes.NewCipher(k[:])
	if err != nil {
		return "", err
	}
	g, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, g.NonceSize())
	if _, err = rand.Read(nonce); err != nil {
		return "", err
	}
	sealed := g.Seal(nonce, nonce, []byte(plaintext), nil)
	return "enc:" + base64.RawStdEncoding.EncodeToString(sealed), nil
}
func Decrypt(key []byte, value string) (string, error) {
	if !strings.HasPrefix(value, "enc:") {
		return "", errors.New("stored secret is not encrypted")
	}
	k := sha256.Sum256(key)
	block, err := aes.NewCipher(k[:])
	if err != nil {
		return "", err
	}
	g, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	b, err := base64.RawStdEncoding.DecodeString(strings.TrimPrefix(value, "enc:"))
	if err != nil || len(b) < g.NonceSize() {
		return "", errors.New("stored secret is invalid")
	}
	n := b[:g.NonceSize()]
	plain, err := g.Open(nil, n, b[g.NonceSize():], nil)
	if err != nil {
		return "", errors.New("stored secret cannot be decrypted")
	}
	return string(plain), nil
}

type Claims struct {
	UserID  string `json:"sub"`
	Role    string `json:"role"`
	Version int    `json:"ver"`
	Expires int64  `json:"exp"`
	Issued  int64  `json:"iat"`
	ID      string `json:"jti"`
}

func SignJWT(key []byte, c Claims) string {
	h := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS256","typ":"JWT"}`))
	p, _ := json.Marshal(c)
	payload := h + "." + base64.RawURLEncoding.EncodeToString(p)
	m := hmac.New(sha256.New, key)
	m.Write([]byte(payload))
	return payload + "." + base64.RawURLEncoding.EncodeToString(m.Sum(nil))
}
func ParseJWT(key []byte, token string) (Claims, error) {
	var c Claims
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return c, errors.New("invalid token")
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return c, errors.New("invalid token")
	}
	m := hmac.New(sha256.New, key)
	m.Write([]byte(parts[0] + "." + parts[1]))
	if !hmac.Equal(sig, m.Sum(nil)) {
		return c, errors.New("invalid token")
	}
	p, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil || json.Unmarshal(p, &c) != nil || c.UserID == "" || c.Expires < time.Now().Unix() {
		return c, errors.New("session expired")
	}
	return c, nil
}

func NewTOTPSecret() (string, error) {
	b := make([]byte, 20)
	if _, e := rand.Read(b); e != nil {
		return "", e
	}
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(b), nil
}
func TOTP(secret string, at time.Time) (string, error) {
	key, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(strings.ToUpper(strings.ReplaceAll(secret, " ", "")))
	if err != nil {
		return "", err
	}
	counter := uint64(at.Unix() / 30)
	var msg [8]byte
	for i := 7; i >= 0; i-- {
		msg[i] = byte(counter)
		counter >>= 8
	}
	mac := hmac.New(sha1.New, key)
	mac.Write(msg[:])
	h := mac.Sum(nil)
	off := h[len(h)-1] & 0x0f
	n := uint32(h[off]&0x7f)<<24 | uint32(h[off+1])<<16 | uint32(h[off+2])<<8 | uint32(h[off+3])
	return fmt.Sprintf("%06d", n%1000000), nil
}
func VerifyTOTP(secret, code string, at time.Time) (int64, bool) {
	if len(code) != 6 {
		return -1, false
	}
	for d := -1; d <= 1; d++ {
		t := at.Add(time.Duration(d) * 30 * time.Second)
		got, e := TOTP(secret, t)
		if e == nil && hmac.Equal([]byte(got), []byte(code)) {
			return t.Unix() / 30, true
		}
	}
	return -1, false
}
func TOTPURI(issuer, user, secret string) string {
	return "otpauth://totp/" + url.QueryEscape(issuer+":"+user) + "?secret=" + url.QueryEscape(secret) + "&issuer=" + url.QueryEscape(issuer) + "&algorithm=SHA1&digits=6&period=30"
}

func APIKeyHash(s string) string { h := sha256.Sum256([]byte(s)); return hex.EncodeToString(h[:]) }

func NewAPIToken() (string, error) {
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		return "", err
	}
	return "ygg_" + base64.RawURLEncoding.EncodeToString(secret), nil
}
