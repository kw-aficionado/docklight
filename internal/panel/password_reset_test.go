package panel

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"example.com/yggdrasil-panel/internal/security"
)

func TestPasswordResetUsesOpaqueHashedSingleUseTokenAndRevokesSessions(t *testing.T) {
	app, d, _ := testApp(t)
	oldHash, err := security.HashPassword("original reset-test password")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = d.Exec(`INSERT INTO users(id,username,email,password_hash,role) VALUES('reset-user','reset-user','person@example.org',?,'user'),('reset-user-no-email','reset-user-no-email','',?,'user')`, oldHash, oldHash); err != nil {
		t.Fatal(err)
	}
	unknown := testRequest(app.Router(), http.MethodPost, "/api/auth/forgot", `{"identifier":"missing@example.org"}`, "")
	knownWithoutSMTP := testRequest(app.Router(), http.MethodPost, "/api/auth/forgot", `{"identifier":"person@example.org"}`, "")
	accountWithoutEmail := testRequest(app.Router(), http.MethodPost, "/api/auth/forgot", `{"identifier":"reset-user-no-email"}`, "")
	if unknown.Code != http.StatusOK || knownWithoutSMTP.Code != http.StatusOK || accountWithoutEmail.Code != http.StatusOK || unknown.Body.String() != knownWithoutSMTP.Body.String() || unknown.Body.String() != accountWithoutEmail.Body.String() || !strings.Contains(unknown.Body.String(), passwordResetResponse) {
		t.Fatalf("forgot responses differ or reveal setup: unknown=%d %s known=%d %s no-email=%d %s", unknown.Code, unknown.Body.String(), knownWithoutSMTP.Code, knownWithoutSMTP.Body.String(), accountWithoutEmail.Code, accountWithoutEmail.Body.String())
	}
	app.passwordResetWG.Wait()
	var pending int
	if err = d.QueryRow(`SELECT count(*) FROM password_reset_tokens`).Scan(&pending); err != nil || pending != 0 {
		t.Fatalf("request without SMTP created reset tokens: count=%d err=%v", pending, err)
	}

	configJSON, err := json.Marshal(notificationChannelConfig{SMTPHost: "smtp.example.org", SMTPPort: 587, From: "docklight@example.org", To: "alerts@example.org"})
	if err != nil {
		t.Fatal(err)
	}
	encrypted, err := security.Encrypt([]byte(app.cfg.Auth.SecretKey), string(configJSON))
	if err != nil {
		t.Fatal(err)
	}
	if _, err = d.Exec(`INSERT INTO notification_channels(id,type,config_enc,enabled,server_id) VALUES('reset-smtp','email',?,1,'')`, encrypted); err != nil {
		t.Fatal(err)
	}
	app.cfg.Server.PublicURL = "https://panel.example.org"
	type capturedMail struct {
		to, subject, body string
	}
	mailSent := make(chan capturedMail, 1)
	app.passwordResetSender = func(_ context.Context, config notificationChannelConfig, subject, body string) error {
		mailSent <- capturedMail{to: config.To, subject: subject, body: body}
		return nil
	}

	forgot := testRequest(app.Router(), http.MethodPost, "/api/auth/forgot", `{"identifier":"RESET-USER"}`, "")
	if forgot.Code != http.StatusOK || forgot.Body.String() != unknown.Body.String() {
		t.Fatalf("known-account forgot response = %d %s", forgot.Code, forgot.Body.String())
	}
	app.passwordResetWG.Wait()
	var mail capturedMail
	select {
	case mail = <-mailSent:
	case <-time.After(2 * time.Second):
		t.Fatal("reset email was not queued")
	}
	if mail.to != "person@example.org" || mail.subject != "[Docklight] Reset your password" || !strings.Contains(mail.body, "https://panel.example.org/?reset=") {
		t.Fatalf("reset mail recipient or content is wrong: %#v", mail)
	}
	if strings.Contains(forgot.Body.String(), "person@example.org") || strings.Contains(forgot.Body.String(), "reset=") {
		t.Fatalf("forgot response leaked account data or token: %s", forgot.Body.String())
	}
	marker := "https://panel.example.org/?reset="
	start := strings.Index(mail.body, marker)
	if start < 0 {
		t.Fatal("reset link missing from email")
	}
	linkText := strings.Fields(mail.body[start:])[0]
	link, err := url.Parse(linkText)
	if err != nil {
		t.Fatal(err)
	}
	resetToken := link.Query().Get("reset")
	if len(resetToken) != 43 {
		t.Fatalf("reset token length = %d, want 43", len(resetToken))
	}
	digest := sha256.Sum256([]byte(resetToken))
	hash := hex.EncodeToString(digest[:])
	var storedHash string
	var expires int64
	if err = d.QueryRow(`SELECT token_hash,expires_at FROM password_reset_tokens WHERE user_id='reset-user'`).Scan(&storedHash, &expires); err != nil {
		t.Fatal(err)
	}
	if storedHash != hash || strings.Contains(storedHash, resetToken) || expires < time.Now().Unix()+3500 || expires > time.Now().Unix()+3601 {
		t.Fatalf("reset token storage is not hash-only or expiry is wrong: hash=%q expires=%d", storedHash, expires)
	}

	oldSession, err := app.issue(User{ID: "reset-user", Username: "reset-user", Role: "user"})
	if err != nil {
		t.Fatal(err)
	}
	reset := testRequest(app.Router(), http.MethodPost, "/api/auth/reset", `{"token":"`+resetToken+`","password":"a completely new password"}`, "")
	if reset.Code != http.StatusOK || !strings.Contains(reset.Body.String(), `"ok":true`) {
		t.Fatalf("valid reset failed: %d %s", reset.Code, reset.Body.String())
	}
	var newHash string
	if err = d.QueryRow(`SELECT password_hash FROM users WHERE id='reset-user'`).Scan(&newHash); err != nil || !security.VerifyPassword(newHash, "a completely new password") {
		t.Fatalf("new password was not stored: err=%v", err)
	}
	if err = d.QueryRow(`SELECT count(*) FROM password_reset_tokens WHERE user_id='reset-user'`).Scan(&pending); err != nil || pending != 0 {
		t.Fatalf("reset tokens were not consumed: count=%d err=%v", pending, err)
	}
	oldSessionResponse := testRequest(app.Router(), http.MethodGet, "/api/me", "", oldSession)
	if oldSessionResponse.Code != http.StatusUnauthorized {
		t.Fatalf("old session survived reset: %d %s", oldSessionResponse.Code, oldSessionResponse.Body.String())
	}
	replay := testRequest(app.Router(), http.MethodPost, "/api/auth/reset", `{"token":"`+resetToken+`","password":"another completely new password"}`, "")
	if replay.Code != http.StatusBadRequest {
		t.Fatalf("used reset token was accepted: %d %s", replay.Code, replay.Body.String())
	}
	var auditCount int
	if err = d.QueryRow(`SELECT count(*) FROM audit_log WHERE action='user.password_reset' AND target_id='reset-user'`).Scan(&auditCount); err != nil || auditCount != 1 {
		t.Fatalf("password reset audit count=%d err=%v", auditCount, err)
	}
}

func TestUserEmailIsValidatedAndUnique(t *testing.T) {
	app, d, _ := testApp(t)
	adminToken := runeCatalogAdminToken(t, app, d)
	created := testRequest(app.Router(), http.MethodPost, "/api/users", `{"username":"mail-user","email":"Person@Example.org","password":"initial test password"}`, adminToken)
	if created.Code != http.StatusCreated || !strings.Contains(created.Body.String(), `"email":"person@example.org"`) {
		t.Fatalf("user email was not normalized: %d %s", created.Code, created.Body.String())
	}
	duplicate := testRequest(app.Router(), http.MethodPost, "/api/users", `{"username":"mail-user-two","email":"PERSON@example.org","password":"another initial password"}`, adminToken)
	if duplicate.Code != http.StatusConflict {
		t.Fatalf("duplicate account email was accepted: %d %s", duplicate.Code, duplicate.Body.String())
	}
	invalid := testRequest(app.Router(), http.MethodPost, "/api/users", `{"username":"bad-mail-user","email":"not-an-email","password":"another initial password"}`, adminToken)
	if invalid.Code != http.StatusBadRequest {
		t.Fatalf("invalid account email was accepted: %d %s", invalid.Code, invalid.Body.String())
	}
	list := testRequest(app.Router(), http.MethodGet, "/api/users", "", adminToken)
	if list.Code != http.StatusOK || !strings.Contains(list.Body.String(), `"email":"person@example.org"`) {
		t.Fatalf("admin user listing omitted email: %d %s", list.Code, list.Body.String())
	}
	var userID string
	if err := d.QueryRow(`SELECT id FROM users WHERE username='mail-user'`).Scan(&userID); err != nil {
		t.Fatal(err)
	}
	staleDigest := sha256.Sum256([]byte("pending-reset-token"))
	if _, err := d.Exec(`INSERT INTO password_reset_tokens(token_hash,user_id,expires_at) VALUES(?,?,?)`, hex.EncodeToString(staleDigest[:]), userID, time.Now().Add(time.Hour).Unix()); err != nil {
		t.Fatal(err)
	}
	updated := testRequest(app.Router(), http.MethodPut, "/api/users/"+userID, `{"email":"updated@example.org"}`, adminToken)
	if updated.Code != http.StatusOK || !strings.Contains(updated.Body.String(), `"email":"updated@example.org"`) {
		t.Fatalf("account email update failed: %d %s", updated.Code, updated.Body.String())
	}
	var outstanding int
	if err := d.QueryRow(`SELECT count(*) FROM password_reset_tokens WHERE user_id=?`, userID).Scan(&outstanding); err != nil || outstanding != 0 {
		t.Fatalf("email update left an old reset token: count=%d err=%v", outstanding, err)
	}
}

func TestExpiredPasswordResetTokenIsRejected(t *testing.T) {
	app, d, _ := testApp(t)
	passwordHash, err := security.HashPassword("original expired-reset password")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = d.Exec(`INSERT INTO users(id,username,password_hash,role) VALUES('expired-reset-user','expired-reset-user',?,'user')`, passwordHash); err != nil {
		t.Fatal(err)
	}
	token := strings.Repeat("x", 43)
	digest := sha256.Sum256([]byte(token))
	if _, err = d.Exec(`INSERT INTO password_reset_tokens(token_hash,user_id,expires_at) VALUES(?,?,?)`, hex.EncodeToString(digest[:]), "expired-reset-user", time.Now().Add(-time.Second).Unix()); err != nil {
		t.Fatal(err)
	}
	response := testRequest(app.Router(), http.MethodPost, "/api/auth/reset", `{"token":"`+token+`","password":"new expired-test password"}`, "")
	if response.Code != http.StatusBadRequest || !strings.Contains(response.Body.String(), "invalid or expired") {
		t.Fatalf("expired reset token was not rejected: %d %s", response.Code, response.Body.String())
	}
}

func TestPasswordResetOriginAndLinkResponseHeaders(t *testing.T) {
	request := httptest.NewRequest(http.MethodGet, "http://panel.example.org", nil)
	if got := passwordResetBaseURL("", request); got != "http://panel.example.org" {
		t.Fatalf("fallback reset origin = %q", got)
	}
	request.Header.Set("X-Forwarded-Proto", "https")
	if got := passwordResetBaseURL("", request); got != "https://panel.example.org" {
		t.Fatalf("forwarded HTTPS reset origin = %q", got)
	}
	request.Host = "panel.example.org/attacker-path"
	if got := passwordResetBaseURL("", request); got != "" {
		t.Fatalf("malformed request host was accepted as reset origin: %q", got)
	}
	if got := passwordResetBaseURL("https://docklight.example.org/", request); got != "https://docklight.example.org" {
		t.Fatalf("configured reset origin = %q", got)
	}

	app, _, _ := testApp(t)
	response := httptest.NewRecorder()
	app.Router().ServeHTTP(response, httptest.NewRequest(http.MethodGet, "http://panel.example.org/?reset=secret-token", nil))
	if response.Code != http.StatusOK || response.Header().Get("Cache-Control") != "no-store" || response.Header().Get("Referrer-Policy") != "no-referrer" {
		t.Fatalf("reset page headers status=%d cache=%q referrer=%q", response.Code, response.Header().Get("Cache-Control"), response.Header().Get("Referrer-Policy"))
	}
}

func TestPasswordResetRateLimitsByIPAndIdentifier(t *testing.T) {
	app, _, _ := testApp(t)
	now := time.Now()
	for attempt := 0; attempt < 3; attempt++ {
		if !app.allowPasswordResetRequest("192.0.2.4", "person@example.org", now) {
			t.Fatalf("identifier was blocked after %d attempts", attempt)
		}
	}
	if app.allowPasswordResetRequest("192.0.2.4", "person@example.org", now) {
		t.Fatal("identifier rate limit allowed a fourth request in one hour")
	}
	if !app.allowPasswordResetRequest("192.0.2.4", "another@example.org", now) {
		t.Fatal("identifier limit incorrectly blocked a different account")
	}
	for attempt := 0; attempt < 10; attempt++ {
		identifier := "account-" + strconv.Itoa(attempt) + "@example.org"
		if !app.allowPasswordResetRequest("192.0.2.5", identifier, now) {
			t.Fatalf("IP was blocked before attempt %d", attempt+1)
		}
	}
	if app.allowPasswordResetRequest("192.0.2.5", "last@example.org", now) {
		t.Fatal("IP rate limit allowed an eleventh request in one hour")
	}
	if !app.allowPasswordResetRequest("192.0.2.5", "after-window@example.org", now.Add(time.Hour+time.Second)) {
		t.Fatal("expired rate-limit entries were not cleared")
	}
}
