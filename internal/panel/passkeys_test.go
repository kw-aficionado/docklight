package panel

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-webauthn/webauthn/webauthn"
)

func passkeyRequest(h http.Handler, method, path, body, token string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, "http://panel.example"+path, strings.NewReader(body))
	r.Header.Set("X-Forwarded-Proto", "https")
	r.Header.Set("Origin", "https://panel.example")
	r.Header.Set("Content-Type", "application/json")
	if token != "" {
		r.Header.Set("Authorization", "Bearer "+token)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

func TestPasskeyOriginAndTLSRequirements(t *testing.T) {
	request := httptest.NewRequest(http.MethodPost, "http://panel.example/api", nil)
	if _, _, err := passkeyRequestOrigin(request); err == nil {
		t.Fatal("plain HTTP on a public hostname was accepted")
	}
	request = httptest.NewRequest(http.MethodPost, "http://localhost:8787/api", nil)
	origin, rpID, err := passkeyRequestOrigin(request)
	if err != nil || origin != "http://localhost:8787" || rpID != "localhost" {
		t.Fatalf("localhost origin=%q RP ID=%q err=%v", origin, rpID, err)
	}
	request = httptest.NewRequest(http.MethodPost, "http://panel.example:443/api", nil)
	request.Header.Set("X-Forwarded-Proto", "https, http")
	origin, rpID, err = passkeyRequestOrigin(request)
	if err != nil || origin != "https://panel.example" || rpID != "panel.example" {
		t.Fatalf("forwarded origin=%q RP ID=%q err=%v", origin, rpID, err)
	}
	request.Header.Set("X-Forwarded-Proto", "gopher")
	if _, _, err = passkeyRequestOrigin(request); err == nil {
		t.Fatal("invalid forwarded scheme was accepted")
	}
	if actual, err := canonicalWebOrigin("HTTPS://PANEL.EXAMPLE:443"); err != nil || actual != "https://panel.example" {
		t.Fatalf("origin canonicalization=%q err=%v", actual, err)
	}
	if _, err := canonicalWebOrigin("https://panel.example?"); err == nil {
		t.Fatal("origin with an empty query delimiter was accepted")
	}
	if requirePasskeyRequestOrigin(request, "https://panel.example") == nil {
		t.Fatal("malformed or missing Origin was accepted")
	}
}

func TestPasskeyLoginAndRegistrationBeginOptions(t *testing.T) {
	app, d, _ := testApp(t)
	admin := addRealmTestUser(t, app, "passkey-admin", "admin")
	handler := app.Router()

	login := passkeyRequest(handler, http.MethodPost, "/api/auth/passkey/login/begin", `{}`, "")
	if login.Code != http.StatusOK {
		t.Fatalf("begin passkey login: %d %s", login.Code, login.Body.String())
	}
	var loginResponse struct {
		SessionID string         `json:"session_id"`
		Options   map[string]any `json:"options"`
	}
	if err := json.Unmarshal(login.Body.Bytes(), &loginResponse); err != nil || len(loginResponse.SessionID) != 43 {
		t.Fatalf("invalid login ceremony response: err=%v response=%s", err, login.Body.String())
	}
	if loginResponse.Options["userVerification"] != "required" || loginResponse.Options["timeout"] != float64(300000) || loginResponse.Options["allowCredentials"] != nil {
		t.Fatalf("login options do not require UV with a five-minute discoverable ceremony: %#v", loginResponse.Options)
	}

	registration := passkeyRequest(handler, http.MethodPost, "/api/passkeys/register/begin", `{"name":"Laptop"}`, admin)
	if registration.Code != http.StatusOK {
		t.Fatalf("begin passkey registration: %d %s", registration.Code, registration.Body.String())
	}
	var registrationResponse struct {
		SessionID string         `json:"session_id"`
		Options   map[string]any `json:"options"`
	}
	if err := json.Unmarshal(registration.Body.Bytes(), &registrationResponse); err != nil || len(registrationResponse.SessionID) != 43 {
		t.Fatalf("invalid registration ceremony response: err=%v response=%s", err, registration.Body.String())
	}
	selection, ok := registrationResponse.Options["authenticatorSelection"].(map[string]any)
	if !ok || selection["userVerification"] != "required" || selection["residentKey"] != "required" || selection["requireResidentKey"] != true || registrationResponse.Options["timeout"] != float64(300000) {
		t.Fatalf("registration did not require user verification and discoverable credentials: %#v", registrationResponse.Options)
	}
	var encodedHandle string
	if err := d.QueryRow(`SELECT webauthn_user_handle FROM users WHERE id='passkey-admin'`).Scan(&encodedHandle); err != nil {
		t.Fatal(err)
	}
	handle, err := base64.RawURLEncoding.DecodeString(encodedHandle)
	if err != nil || len(handle) != 64 || strings.Contains(encodedHandle, "passkey-admin") {
		t.Fatalf("user handle is not a random opaque 64-byte value: size=%d err=%v", len(handle), err)
	}
}

func TestPasskeyCredentialStorageAndSelfService(t *testing.T) {
	app, d, _ := testApp(t)
	owner := addRealmTestUser(t, app, "passkey-owner", "user")
	other := addRealmTestUser(t, app, "passkey-other", "user")
	credential := &webauthn.Credential{ID: []byte("credential-id-for-tests"), PublicKey: []byte("public-key-material")}
	id, err := app.insertPasskey("passkey-owner", "Work laptop", credential)
	if err != nil {
		t.Fatal(err)
	}
	var encrypted string
	if err := d.QueryRow(`SELECT credential_enc FROM passkey_credentials WHERE id=?`, id).Scan(&encrypted); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(encrypted, string(credential.ID)) || strings.Contains(encrypted, string(credential.PublicKey)) {
		t.Fatal("credential record was stored without encryption")
	}

	handler := app.Router()
	listed := testRequest(handler, http.MethodGet, "/api/passkeys", "", owner)
	if listed.Code != http.StatusOK || !strings.Contains(listed.Body.String(), "Work laptop") || strings.Contains(listed.Body.String(), base64.RawURLEncoding.EncodeToString(credential.ID)) || strings.Contains(listed.Body.String(), string(credential.PublicKey)) {
		t.Fatalf("passkey list leaked credential state or omitted summary: %d %s", listed.Code, listed.Body.String())
	}
	rename := testRequest(handler, http.MethodPut, "/api/passkeys/"+id, `{"name":"Personal laptop"}`, owner)
	if rename.Code != http.StatusOK {
		t.Fatalf("rename passkey: %d %s", rename.Code, rename.Body.String())
	}
	otherDelete := testRequest(handler, http.MethodDelete, "/api/passkeys/"+id, `{}`, other)
	if otherDelete.Code != http.StatusNotFound {
		t.Fatalf("another account deleted this passkey: %d %s", otherDelete.Code, otherDelete.Body.String())
	}
	deleted := testRequest(handler, http.MethodDelete, "/api/passkeys/"+id, `{}`, owner)
	if deleted.Code != http.StatusOK {
		t.Fatalf("delete passkey: %d %s", deleted.Code, deleted.Body.String())
	}
	var remaining int
	if err := d.QueryRow(`SELECT count(*) FROM passkey_credentials WHERE user_id='passkey-owner'`).Scan(&remaining); err != nil || remaining != 0 {
		t.Fatalf("deleted passkey remains in storage: count=%d err=%v", remaining, err)
	}
}

func TestPasskeyCeremoniesAreSingleUseAndExpire(t *testing.T) {
	app, _, _ := testApp(t)
	valid := time.Now().Add(passkeyCeremonyTimeout)
	id, err := app.savePasskeyCeremony(passkeyCeremony{kind: "login", origin: "https://panel.example", rpID: "panel.example", session: webauthn.SessionData{Expires: valid}, expiresAt: valid})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := app.takePasskeyCeremony(id, "login"); !ok {
		t.Fatal("valid passkey ceremony could not be consumed")
	}
	if _, ok := app.takePasskeyCeremony(id, "login"); ok {
		t.Fatal("passkey ceremony was reusable")
	}
	expired := time.Now().Add(-time.Second)
	id, err = app.savePasskeyCeremony(passkeyCeremony{kind: "register", session: webauthn.SessionData{Expires: expired}, expiresAt: expired})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := app.takePasskeyCeremony(id, "register"); ok {
		t.Fatal("expired passkey ceremony was accepted")
	}
	future := time.Now().Add(time.Minute)
	for i := 0; i < maxPendingPasskeyCeremonies; i++ {
		app.passkeyCeremonies[fmt.Sprintf("pending-%d", i)] = passkeyCeremony{expiresAt: future}
	}
	if _, err := app.savePasskeyCeremony(passkeyCeremony{kind: "login", session: webauthn.SessionData{Expires: future}, expiresAt: future}); err == nil {
		t.Fatal("passkey ceremony storage exceeded its pending-state cap")
	}
}

func TestPasskeyLoginStepRateLimits(t *testing.T) {
	app, _, _ := testApp(t)
	request := httptest.NewRequest(http.MethodPost, "http://panel.example/api/auth/passkey/login/begin", nil)
	request.RemoteAddr = "192.0.2.5:1234"
	for attempt := 1; attempt <= 5; attempt++ {
		if !app.passkeyAttemptAllowed(request, "login-begin") {
			t.Fatalf("passkey login begin attempt %d was unexpectedly blocked", attempt)
		}
	}
	if app.passkeyAttemptAllowed(request, "login-begin") {
		t.Fatal("sixth passkey login begin attempt was not rate limited")
	}
	if !app.passkeyAttemptAllowed(request, "login-finish") {
		t.Fatal("separate passkey finish step shared the begin-step limit")
	}
	for i := 0; i < maxPasskeyRateLimitKeys; i++ {
		app.passkeyIPs[fmt.Sprintf("198.51.100.%d|login-begin", i)] = []time.Time{time.Now()}
	}
	request.RemoteAddr = "203.0.113.100:1234"
	if app.passkeyAttemptAllowed(request, "login-begin") {
		t.Fatal("rate-limit state exceeded its key cap")
	}
}

func TestPasskeyNamesCountUnicodeAndRejectControls(t *testing.T) {
	if !validPasskeyName(strings.Repeat("界", 80)) {
		t.Fatal("valid 80-character international passkey name was rejected")
	}
	if validPasskeyName(strings.Repeat("界", 81)) || validPasskeyName("line\nbreak") || validPasskeyName("   ") {
		t.Fatal("invalid or overlong passkey name was accepted")
	}
}
