package panel

import (
	"bytes"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"example.com/yggdrasil-panel/internal/security"
	"github.com/go-chi/chi/v5"
	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
)

const passkeyCeremonyTimeout = 5 * time.Minute

const (
	maxPendingPasskeyCeremonies = 10000
	maxPasskeyRateLimitKeys     = 10000
)

var errPasskeyCapacity = errors.New("too many passkey ceremonies are pending")

type passkeyCeremony struct {
	kind      string
	userID    string
	name      string
	origin    string
	rpID      string
	session   webauthn.SessionData
	expiresAt time.Time
}

type webAuthnAccount struct {
	User
	handle      []byte
	credentials []webauthn.Credential
}

func (u *webAuthnAccount) WebAuthnID() []byte          { return u.handle }
func (u *webAuthnAccount) WebAuthnName() string        { return u.Username }
func (u *webAuthnAccount) WebAuthnDisplayName() string { return u.Username }
func (u *webAuthnAccount) WebAuthnCredentials() []webauthn.Credential {
	return u.credentials
}

type passkeySummary struct {
	ID         string `json:"id"`
	Name       string `json:"name"`
	CreatedAt  string `json:"created_at"`
	LastUsedAt string `json:"last_used_at,omitempty"`
}

func (a *App) passkeyWebAuthn(r *http.Request) (*webauthn.WebAuthn, string, string, error) {
	origin, rpID, err := passkeyRequestOrigin(r)
	if err != nil {
		return nil, "", "", err
	}
	timeout := webauthn.TimeoutConfig{Enforce: true, Timeout: passkeyCeremonyTimeout}
	wa, err := webauthn.New(&webauthn.Config{
		RPID:          rpID,
		RPDisplayName: "Docklight",
		RPOrigins:     []string{origin},
		Timeouts: webauthn.TimeoutsConfig{
			Login:        timeout,
			Registration: timeout,
		},
	})
	if err != nil {
		return nil, "", "", fmt.Errorf("invalid passkey relying party configuration: %w", err)
	}
	return wa, origin, rpID, nil
}

func passkeyRequestOrigin(r *http.Request) (string, string, error) {
	scheme := ""
	if r.TLS != nil {
		scheme = "https"
	} else if forwarded := strings.TrimSpace(strings.Split(r.Header.Get("X-Forwarded-Proto"), ",")[0]); forwarded != "" {
		scheme = strings.ToLower(forwarded)
	} else {
		scheme = "http"
	}
	if scheme != "https" && scheme != "http" {
		return "", "", errors.New("passkeys require a valid HTTP or HTTPS origin")
	}
	if r.Host == "" {
		return "", "", errors.New("passkeys need a valid panel hostname")
	}
	parsed, err := url.Parse("//" + r.Host)
	if err != nil || parsed.User != nil || parsed.Host == "" || parsed.Path != "" || parsed.RawQuery != "" || parsed.ForceQuery || strings.Contains(r.Host, "#") {
		return "", "", errors.New("passkeys need a valid panel hostname")
	}
	host := strings.TrimSuffix(strings.ToLower(parsed.Hostname()), ".")
	if host == "" {
		return "", "", errors.New("passkeys need a valid panel hostname")
	}
	if scheme != "https" && !isPasskeyLocalhost(host) {
		return "", "", errors.New("passkeys require HTTPS; localhost is allowed for local setup")
	}
	port := parsed.Port()
	if port != "" && ((scheme == "https" && port == "443") || (scheme == "http" && port == "80")) {
		port = ""
	}
	authority := host
	if strings.Contains(host, ":") {
		authority = "[" + host + "]"
	}
	if port != "" {
		authority = net.JoinHostPort(host, port)
	}
	return scheme + "://" + authority, host, nil
}

func isPasskeyLocalhost(host string) bool {
	return host == "localhost" || strings.HasSuffix(host, ".localhost")
}

func requirePasskeyRequestOrigin(r *http.Request, expected string) error {
	actual, err := canonicalWebOrigin(r.Header.Get("Origin"))
	if err != nil || actual != expected {
		return errors.New("passkey ceremony must be completed from the same panel origin")
	}
	return nil
}

func canonicalWebOrigin(value string) (string, error) {
	u, err := url.Parse(strings.TrimSpace(value))
	if err != nil || u.User != nil || u.Host == "" || u.Path != "" || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || strings.Contains(value, "#") {
		return "", errors.New("invalid origin")
	}
	scheme := strings.ToLower(u.Scheme)
	if scheme != "https" && scheme != "http" {
		return "", errors.New("invalid origin")
	}
	host := strings.TrimSuffix(strings.ToLower(u.Hostname()), ".")
	if host == "" {
		return "", errors.New("invalid origin")
	}
	port := u.Port()
	if port != "" && ((scheme == "https" && port == "443") || (scheme == "http" && port == "80")) {
		port = ""
	}
	authority := host
	if strings.Contains(host, ":") {
		authority = "[" + host + "]"
	}
	if port != "" {
		authority = net.JoinHostPort(host, port)
	}
	return scheme + "://" + authority, nil
}

func (a *App) passkeyAttemptAllowed(r *http.Request, step string) bool {
	key := clientIP(r) + "|" + step
	now := time.Now()
	a.passkeyMu.Lock()
	defer a.passkeyMu.Unlock()
	for ip, attempts := range a.passkeyIPs {
		attempts = recent(attempts, now.Add(-time.Minute))
		if len(attempts) == 0 {
			delete(a.passkeyIPs, ip)
		} else {
			a.passkeyIPs[ip] = attempts
		}
	}
	attempts := recent(a.passkeyIPs[key], now.Add(-time.Minute))
	if len(attempts) >= 5 {
		a.passkeyIPs[key] = attempts
		return false
	}
	if _, exists := a.passkeyIPs[key]; !exists && len(a.passkeyIPs) >= maxPasskeyRateLimitKeys {
		return false
	}
	a.passkeyIPs[key] = append(attempts, now)
	return true
}

func (a *App) savePasskeyCeremony(c passkeyCeremony) (string, error) {
	var random [32]byte
	if _, err := rand.Read(random[:]); err != nil {
		return "", err
	}
	id := base64.RawURLEncoding.EncodeToString(random[:])
	deadline := time.Now().Add(passkeyCeremonyTimeout)
	if c.expiresAt.IsZero() || c.expiresAt.After(deadline) {
		c.expiresAt = deadline
	}
	if c.session.Expires.IsZero() || c.session.Expires.After(c.expiresAt) {
		c.session.Expires = c.expiresAt
	}
	a.passkeyMu.Lock()
	defer a.passkeyMu.Unlock()
	for key, existing := range a.passkeyCeremonies {
		if !existing.expiresAt.After(time.Now()) {
			delete(a.passkeyCeremonies, key)
		}
	}
	if len(a.passkeyCeremonies) >= maxPendingPasskeyCeremonies {
		return "", errPasskeyCapacity
	}
	a.passkeyCeremonies[id] = c
	return id, nil
}

func (a *App) takePasskeyCeremony(id, kind string) (passkeyCeremony, bool) {
	a.passkeyMu.Lock()
	defer a.passkeyMu.Unlock()
	c, ok := a.passkeyCeremonies[id]
	delete(a.passkeyCeremonies, id)
	if !ok || c.kind != kind || !c.expiresAt.After(time.Now()) || !c.session.Expires.After(time.Now()) {
		return passkeyCeremony{}, false
	}
	return c, true
}

func (a *App) ensurePasskeyHandle(userID string) ([]byte, error) {
	for attempt := 0; attempt < 3; attempt++ {
		var encoded string
		if err := a.db.QueryRow(`SELECT webauthn_user_handle FROM users WHERE id=?`, userID).Scan(&encoded); err != nil {
			return nil, err
		}
		if encoded == "" {
			var random [64]byte
			if _, err := rand.Read(random[:]); err != nil {
				return nil, err
			}
			candidate := base64.RawURLEncoding.EncodeToString(random[:])
			if _, err := a.db.Exec(`UPDATE users SET webauthn_user_handle=? WHERE id=? AND webauthn_user_handle=''`, candidate, userID); err != nil {
				continue
			}
			continue
		}
		handle, err := base64.RawURLEncoding.DecodeString(encoded)
		if err != nil || len(handle) == 0 || len(handle) > 64 {
			return nil, errors.New("stored passkey user handle is invalid")
		}
		return handle, nil
	}
	return nil, errors.New("could not create a unique passkey user handle")
}

func (a *App) loadWebAuthnAccount(userID string) (*webAuthnAccount, error) {
	var account webAuthnAccount
	var disabled int
	var encoded string
	err := a.db.QueryRow(`SELECT id,username,role,disabled,token_version,totp_secret,totp_enabled,totp_last_counter,webauthn_user_handle FROM users WHERE id=?`, userID).
		Scan(&account.ID, &account.Username, &account.Role, &disabled, &account.TokenVersion, &account.TotpSecret, &account.TotpEnabled, &account.TotpLastCounter, &encoded)
	if err != nil {
		return nil, err
	}
	account.Disabled = disabled != 0
	if encoded == "" {
		account.handle, err = a.ensurePasskeyHandle(userID)
	} else {
		account.handle, err = base64.RawURLEncoding.DecodeString(encoded)
	}
	if err != nil || len(account.handle) == 0 || len(account.handle) > 64 {
		return nil, errors.New("stored passkey user handle is invalid")
	}
	account.credentials, err = a.loadPasskeyCredentials(userID)
	if err != nil {
		return nil, err
	}
	return &account, nil
}

func (a *App) loadWebAuthnAccountByHandle(handle []byte) (*webAuthnAccount, error) {
	encoded := base64.RawURLEncoding.EncodeToString(handle)
	var userID string
	if err := a.db.QueryRow(`SELECT id FROM users WHERE webauthn_user_handle=?`, encoded).Scan(&userID); err != nil {
		return nil, err
	}
	return a.loadWebAuthnAccount(userID)
}

func (a *App) loadPasskeyCredentials(userID string) ([]webauthn.Credential, error) {
	rows, err := a.db.Query(`SELECT credential_id,credential_enc FROM passkey_credentials WHERE user_id=? ORDER BY created_at,id`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	credentials := []webauthn.Credential{}
	for rows.Next() {
		var id []byte
		var encrypted string
		if err := rows.Scan(&id, &encrypted); err != nil {
			return nil, err
		}
		plaintext, err := security.Decrypt([]byte(a.cfg.Auth.SecretKey), encrypted)
		if err != nil {
			return nil, errors.New("stored passkey data could not be decrypted")
		}
		var credential webauthn.Credential
		if err := json.Unmarshal([]byte(plaintext), &credential); err != nil || !bytes.Equal(id, credential.ID) {
			return nil, errors.New("stored passkey data is invalid")
		}
		credentials = append(credentials, credential)
	}
	return credentials, rows.Err()
}

func (a *App) listPasskeys(w http.ResponseWriter, r *http.Request) {
	u := principal(r)
	if u.IsAPIToken {
		writeError(w, 403, "sign in with your account to manage passkeys")
		return
	}
	rows, err := a.db.Query(`SELECT id,name,created_at,last_used_at FROM passkey_credentials WHERE user_id=? ORDER BY created_at,id`, u.ID)
	if err != nil {
		writeError(w, 500, "could not load passkeys")
		return
	}
	defer rows.Close()
	items := []passkeySummary{}
	for rows.Next() {
		var item passkeySummary
		if err := rows.Scan(&item.ID, &item.Name, &item.CreatedAt, &item.LastUsedAt); err != nil {
			writeError(w, 500, "could not load passkeys")
			return
		}
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		writeError(w, 500, "could not load passkeys")
		return
	}
	writeJSON(w, 200, items)
}

func (a *App) passkeyRegistrationBegin(w http.ResponseWriter, r *http.Request) {
	u := principal(r)
	if u.IsAPIToken {
		writeError(w, 403, "sign in with your account to register a passkey")
		return
	}
	var in struct {
		Name string `json:"name"`
	}
	if decodeJSON(w, r, &in, 4096) != nil {
		return
	}
	in.Name = strings.TrimSpace(in.Name)
	if !validPasskeyName(in.Name) {
		writeError(w, 400, "passkey name must be between 1 and 80 characters")
		return
	}
	wa, origin, rpID, err := a.passkeyWebAuthn(r)
	if err != nil {
		writeError(w, 400, err.Error())
		return
	}
	account, err := a.loadWebAuthnAccount(u.ID)
	if err != nil || account.Disabled {
		writeError(w, 400, "could not load this account's passkey state")
		return
	}
	selection := protocol.AuthenticatorSelection{UserVerification: protocol.VerificationRequired}
	options, session, err := wa.BeginRegistration(account,
		webauthn.WithAuthenticatorSelection(selection),
		webauthn.WithResidentKeyRequirement(protocol.ResidentKeyRequirementRequired),
		webauthn.WithExclusions(passkeyExclusions(account.credentials)),
	)
	if err != nil {
		writeError(w, 400, "could not start passkey registration")
		return
	}
	sessionID, err := a.savePasskeyCeremony(passkeyCeremony{kind: "register", userID: u.ID, name: in.Name, origin: origin, rpID: rpID, session: *session, expiresAt: session.Expires})
	if err != nil {
		if errors.Is(err, errPasskeyCapacity) {
			writeError(w, 503, "too many passkey ceremonies are pending; retry shortly")
			return
		}
		writeError(w, 500, "could not store passkey registration state")
		return
	}
	writeJSON(w, 200, map[string]any{"session_id": sessionID, "options": options.Response})
}

func validPasskeyName(name string) bool {
	if !utf8.ValidString(name) || strings.TrimSpace(name) == "" || utf8.RuneCountInString(name) > 80 {
		return false
	}
	for _, r := range name {
		if unicode.IsControl(r) {
			return false
		}
	}
	return true
}

func passkeyExclusions(credentials []webauthn.Credential) []protocol.CredentialDescriptor {
	descriptors := make([]protocol.CredentialDescriptor, 0, len(credentials))
	for _, credential := range credentials {
		descriptors = append(descriptors, protocol.CredentialDescriptor{Type: protocol.PublicKeyCredentialType, CredentialID: credential.ID, Transport: credential.Transport})
	}
	return descriptors
}

func (a *App) passkeyRegistrationFinish(w http.ResponseWriter, r *http.Request) {
	u := principal(r)
	if u.IsAPIToken {
		writeError(w, 403, "sign in with your account to register a passkey")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	var in struct {
		SessionID  string          `json:"session_id"`
		Credential json.RawMessage `json:"credential"`
	}
	if decodeJSON(w, r, &in, 1<<20) != nil {
		return
	}
	ceremony, ok := a.takePasskeyCeremony(in.SessionID, "register")
	if !ok || ceremony.userID != u.ID {
		writeError(w, 400, "passkey registration expired; start again")
		return
	}
	if err := requirePasskeyRequestOrigin(r, ceremony.origin); err != nil {
		writeError(w, 403, err.Error())
		return
	}
	wa, origin, rpID, err := a.passkeyWebAuthn(r)
	if err != nil || origin != ceremony.origin || rpID != ceremony.rpID {
		writeError(w, 400, "passkey registration host changed; start again")
		return
	}
	account, err := a.loadWebAuthnAccount(u.ID)
	if err != nil || account.Disabled {
		writeError(w, 401, "account is unavailable")
		return
	}
	body, err := json.Marshal(in.Credential)
	if err != nil || len(in.Credential) == 0 {
		writeError(w, 400, "passkey response is invalid")
		return
	}
	credentialRequest := r.Clone(r.Context())
	credentialRequest.Body = io.NopCloser(bytes.NewReader(body))
	credentialRequest.ContentLength = int64(len(body))
	credentialRequest.Header = r.Header.Clone()
	credentialRequest.Header.Set("Content-Type", "application/json")
	credential, err := wa.FinishRegistration(account, ceremony.session, credentialRequest)
	if err != nil {
		writeError(w, 400, "passkey registration could not be verified")
		return
	}
	if len(credential.ID) == 0 || !credential.Flags.UserVerified {
		writeError(w, 400, "passkey must support user verification")
		return
	}
	passkeyID, err := a.insertPasskey(u.ID, ceremony.name, credential)
	if err != nil {
		writeError(w, 409, "this passkey is already registered or could not be saved")
		return
	}
	a.audit(u, "auth.passkey.create", "passkey", passkeyID, "")
	writeJSON(w, 200, map[string]bool{"ok": true})
}

func (a *App) insertPasskey(userID, name string, credential *webauthn.Credential) (string, error) {
	encoded, err := json.Marshal(credential)
	if err != nil {
		return "", err
	}
	encrypted, err := security.Encrypt([]byte(a.cfg.Auth.SecretKey), string(encoded))
	if err != nil {
		return "", err
	}
	id, err := newID()
	if err != nil {
		return "", err
	}
	_, err = a.db.Exec(`INSERT INTO passkey_credentials(id,user_id,credential_id,name,credential_enc) VALUES(?,?,?,?,?)`, id, userID, credential.ID, name, encrypted)
	return id, err
}

func (a *App) renamePasskey(w http.ResponseWriter, r *http.Request) {
	u := principal(r)
	if u.IsAPIToken {
		writeError(w, 403, "sign in with your account to manage passkeys")
		return
	}
	var in struct {
		Name string `json:"name"`
	}
	if decodeJSON(w, r, &in, 4096) != nil {
		return
	}
	in.Name = strings.TrimSpace(in.Name)
	if !validPasskeyName(in.Name) {
		writeError(w, 400, "passkey name must be between 1 and 80 characters")
		return
	}
	id := chi.URLParam(r, "id")
	result, err := a.db.Exec(`UPDATE passkey_credentials SET name=? WHERE id=? AND user_id=?`, in.Name, id, u.ID)
	if err != nil {
		writeError(w, 500, "could not rename passkey")
		return
	}
	changed, err := result.RowsAffected()
	if err != nil || changed != 1 {
		writeError(w, 404, "passkey not found")
		return
	}
	a.audit(u, "auth.passkey.rename", "passkey", id, "")
	writeJSON(w, 200, map[string]bool{"ok": true})
}

func (a *App) deletePasskey(w http.ResponseWriter, r *http.Request) {
	u := principal(r)
	if u.IsAPIToken {
		writeError(w, 403, "sign in with your account to manage passkeys")
		return
	}
	id := chi.URLParam(r, "id")
	result, err := a.db.Exec(`DELETE FROM passkey_credentials WHERE id=? AND user_id=?`, id, u.ID)
	if err != nil {
		writeError(w, 500, "could not delete passkey")
		return
	}
	changed, err := result.RowsAffected()
	if err != nil || changed != 1 {
		writeError(w, 404, "passkey not found")
		return
	}
	a.audit(u, "auth.passkey.delete", "passkey", id, "")
	writeJSON(w, 200, map[string]bool{"ok": true})
}

func (a *App) passkeyLoginBegin(w http.ResponseWriter, r *http.Request) {
	if !a.passkeyAttemptAllowed(r, "login-begin") {
		writeError(w, 429, "too many passkey sign-in attempts; wait a minute and try again")
		return
	}
	wa, origin, rpID, err := a.passkeyWebAuthn(r)
	if err != nil {
		writeError(w, 400, err.Error())
		return
	}
	options, session, err := wa.BeginDiscoverableLogin(webauthn.WithUserVerification(protocol.VerificationRequired))
	if err != nil {
		writeError(w, 400, "could not start passkey sign-in")
		return
	}
	sessionID, err := a.savePasskeyCeremony(passkeyCeremony{kind: "login", origin: origin, rpID: rpID, session: *session, expiresAt: session.Expires})
	if err != nil {
		if errors.Is(err, errPasskeyCapacity) {
			writeError(w, 503, "too many passkey ceremonies are pending; retry shortly")
			return
		}
		writeError(w, 500, "could not store passkey sign-in state")
		return
	}
	writeJSON(w, 200, map[string]any{"session_id": sessionID, "options": options.Response})
}

func (a *App) passkeyLoginFinish(w http.ResponseWriter, r *http.Request) {
	if !a.passkeyAttemptAllowed(r, "login-finish") {
		writeError(w, 429, "too many passkey sign-in attempts; wait a minute and try again")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	var in struct {
		SessionID  string          `json:"session_id"`
		Credential json.RawMessage `json:"credential"`
	}
	if decodeJSON(w, r, &in, 1<<20) != nil {
		return
	}
	ceremony, ok := a.takePasskeyCeremony(in.SessionID, "login")
	if !ok {
		writeError(w, 401, "invalid credentials")
		return
	}
	if err := requirePasskeyRequestOrigin(r, ceremony.origin); err != nil {
		writeError(w, 401, "invalid credentials")
		return
	}
	wa, origin, rpID, err := a.passkeyWebAuthn(r)
	if err != nil || origin != ceremony.origin || rpID != ceremony.rpID {
		writeError(w, 401, "invalid credentials")
		return
	}
	body, err := json.Marshal(in.Credential)
	if err != nil || len(in.Credential) == 0 {
		writeError(w, 401, "invalid credentials")
		return
	}
	credentialRequest := r.Clone(r.Context())
	credentialRequest.Body = io.NopCloser(bytes.NewReader(body))
	credentialRequest.ContentLength = int64(len(body))
	credentialRequest.Header = r.Header.Clone()
	credentialRequest.Header.Set("Content-Type", "application/json")
	var account *webAuthnAccount
	resultUser, credential, err := wa.FinishPasskeyLogin(func(_ []byte, userHandle []byte) (webauthn.User, error) {
		found, loadErr := a.loadWebAuthnAccountByHandle(userHandle)
		if loadErr != nil || found.Disabled || found.IsAPIToken {
			return nil, errors.New("account is unavailable")
		}
		if a.loginUserLocked(found.Username) {
			return nil, errors.New("account is temporarily locked")
		}
		account = found
		return found, nil
	}, ceremony.session, credentialRequest)
	if err != nil || account == nil || credential == nil || resultUser == nil {
		if account != nil {
			a.recordLoginFailure(clientIP(r), account.Username)
		}
		writeError(w, 401, "invalid credentials")
		return
	}
	if err := a.updateUsedPasskey(account.ID, credential); err != nil {
		writeError(w, 500, "could not update passkey use state")
		return
	}
	token, err := a.issue(account.User)
	if err != nil {
		writeError(w, 500, "could not create sign-in session")
		return
	}
	a.clearLoginFailures(clientIP(r), account.Username)
	a.audit(account.User, "auth.passkey.login", "user", account.ID, "")
	http.SetCookie(w, &http.Cookie{Name: "ygg_token", Value: token, Path: "/", HttpOnly: true, Secure: strings.HasPrefix(ceremony.origin, "https://"), SameSite: http.SameSiteStrictMode, Expires: time.Now().Add(time.Duration(a.cfg.Auth.SessionTTLHours) * time.Hour)})
	writeJSON(w, 200, map[string]any{"token": token, "user": account.User})
}

func (a *App) loginUserLocked(username string) bool {
	a.rateMu.Lock()
	defer a.rateMu.Unlock()
	key := strings.ToLower(username)
	a.loginUsers[key] = recent(a.loginUsers[key], time.Now().Add(-15*time.Minute))
	return len(a.loginUsers[key]) >= 10
}

func (a *App) updateUsedPasskey(userID string, credential *webauthn.Credential) error {
	encoded, err := json.Marshal(credential)
	if err != nil {
		return err
	}
	encrypted, err := security.Encrypt([]byte(a.cfg.Auth.SecretKey), string(encoded))
	if err != nil {
		return err
	}
	result, err := a.db.Exec(`UPDATE passkey_credentials SET credential_enc=?,last_used_at=CURRENT_TIMESTAMP WHERE user_id=? AND credential_id=?`, encrypted, userID, credential.ID)
	if err != nil {
		return err
	}
	changed, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if changed != 1 {
		return sql.ErrNoRows
	}
	return nil
}
