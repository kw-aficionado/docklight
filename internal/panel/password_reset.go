package panel

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"

	"example.com/yggdrasil-panel/internal/security"
)

const passwordResetResponse = "If an account matches that information, password reset instructions will be sent."

func (a *App) forgotPassword(w http.ResponseWriter, r *http.Request) {
	if origin := r.Header.Get("Origin"); origin != "" && !sameOrigin(r, origin) {
		writeError(w, http.StatusForbidden, "cross-origin request blocked")
		return
	}
	var in struct {
		Identifier string `json:"identifier"`
	}
	if decodeJSON(w, r, &in, 16*1024) != nil {
		return
	}
	identifier := strings.ToLower(strings.TrimSpace(in.Identifier))
	if identifier != "" && len(identifier) <= 254 && a.allowPasswordResetRequest(clientIP(r), identifier, time.Now()) {
		if base := passwordResetBaseURL(a.cfg.Server.PublicURL, r); base != "" {
			a.passwordResetWG.Add(1)
			go func() {
				defer a.passwordResetWG.Done()
				a.processPasswordResetRequest(identifier, base)
			}()
		}
	}
	writeJSON(w, http.StatusOK, map[string]string{"message": passwordResetResponse})
}

func (a *App) processPasswordResetRequest(identifier, base string) {
	var userID, email string
	err := a.db.QueryRow(`SELECT id,email FROM users WHERE disabled=0 AND (lower(username)=? OR lower(email)=?) ORDER BY CASE WHEN lower(username)=? THEN 0 ELSE 1 END LIMIT 1`, identifier, identifier, identifier).Scan(&userID, &email)
	if err != nil || email == "" {
		return
	}
	config, err := a.passwordResetSMTPConfig()
	if err != nil {
		return
	}
	token, err := a.issuePasswordReset(userID, time.Now())
	if err != nil {
		return
	}
	config.To = email
	link := base + "/?reset=" + url.QueryEscape(token)
	body := "A password reset was requested for your Docklight account.\n\n" +
		"Use this one-time link within one hour:\n" + link + "\n\n" +
		"If you did not request this, you can ignore this message."
	a.sendPasswordResetEmail(config, body)
}

func (a *App) allowPasswordResetRequest(ip, identifier string, now time.Time) bool {
	a.rateMu.Lock()
	defer a.rateMu.Unlock()
	if a.forgotAttempts == nil {
		a.forgotAttempts = make(map[string][]time.Time)
	}
	cutoff := now.Add(-time.Hour)
	if len(a.forgotAttempts) > 8192 {
		for key, attempts := range a.forgotAttempts {
			attempts = recent(attempts, cutoff)
			if len(attempts) == 0 {
				delete(a.forgotAttempts, key)
			} else {
				a.forgotAttempts[key] = attempts
			}
		}
	}
	ipKey := "ip:" + ip
	identifierKey := "identifier:" + identifier
	ipAttempts := recent(a.forgotAttempts[ipKey], cutoff)
	identifierAttempts := recent(a.forgotAttempts[identifierKey], cutoff)
	allowed := len(ipAttempts) < 10 && len(identifierAttempts) < 3
	if allowed {
		a.forgotAttempts[ipKey] = append(ipAttempts, now)
		if _, exists := a.forgotAttempts[identifierKey]; exists || len(a.forgotAttempts) < 8192 {
			a.forgotAttempts[identifierKey] = append(identifierAttempts, now)
		}
	}
	return allowed
}

func (a *App) passwordResetSMTPConfig() (notificationChannelConfig, error) {
	var encrypted string
	err := a.db.QueryRow(`SELECT config_enc FROM notification_channels WHERE type='email' AND enabled=1 AND server_id='' ORDER BY created_at,id LIMIT 1`).Scan(&encrypted)
	if errors.Is(err, sql.ErrNoRows) {
		return notificationChannelConfig{}, err
	}
	if err != nil {
		return notificationChannelConfig{}, err
	}
	plain, err := security.Decrypt([]byte(a.cfg.Auth.SecretKey), encrypted)
	if err != nil {
		return notificationChannelConfig{}, errors.New("saved SMTP channel cannot be decrypted")
	}
	var config notificationChannelConfig
	if err = json.Unmarshal([]byte(plain), &config); err != nil {
		return notificationChannelConfig{}, errors.New("saved SMTP channel configuration is invalid")
	}
	return config, nil
}

func (a *App) issuePasswordReset(userID string, now time.Time) (string, error) {
	var raw [32]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", err
	}
	token := base64.RawURLEncoding.EncodeToString(raw[:])
	digest := sha256.Sum256([]byte(token))
	tokenHash := hex.EncodeToString(digest[:])
	tx, err := a.db.Begin()
	if err != nil {
		return "", err
	}
	defer tx.Rollback()
	if _, err = tx.Exec(`DELETE FROM password_reset_tokens WHERE expires_at<=?`, now.Unix()); err != nil {
		return "", err
	}
	if _, err = tx.Exec(`DELETE FROM password_reset_tokens WHERE user_id=?`, userID); err != nil {
		return "", err
	}
	if _, err = tx.Exec(`INSERT INTO password_reset_tokens(token_hash,user_id,expires_at) VALUES(?,?,?)`, tokenHash, userID, now.Add(time.Hour).Unix()); err != nil {
		return "", err
	}
	if err = tx.Commit(); err != nil {
		return "", err
	}
	return token, nil
}

func passwordResetBaseURL(configured string, r *http.Request) string {
	if configured != "" {
		u, err := url.Parse(configured)
		if err != nil {
			return ""
		}
		u.Scheme = strings.ToLower(u.Scheme)
		return strings.TrimRight(u.String(), "/")
	}
	host := strings.TrimSpace(r.Host)
	if host == "" || strings.ContainsAny(host, "\r\n\t /\\@") {
		return ""
	}
	u, err := url.Parse(requestScheme(r) + "://" + host)
	if err != nil || u.Host == "" || u.Host != host || u.Hostname() == "" || u.User != nil || u.Path != "" || u.RawQuery != "" || u.Fragment != "" {
		return ""
	}
	return u.Scheme + "://" + u.Host
}

func (a *App) sendPasswordResetEmail(config notificationChannelConfig, body string) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	var err error
	if a.passwordResetSender != nil {
		err = a.passwordResetSender(ctx, config, "[Docklight] Reset your password", body)
	} else {
		err = sendSMTPEmail(ctx, config, "[Docklight] Reset your password", body)
	}
	if err != nil {
		log.Print("password reset email delivery failed")
	}
}

func (a *App) resetPassword(w http.ResponseWriter, r *http.Request) {
	if origin := r.Header.Get("Origin"); origin != "" && !sameOrigin(r, origin) {
		writeError(w, http.StatusForbidden, "cross-origin request blocked")
		return
	}
	var in struct {
		Token    string `json:"token"`
		Password string `json:"password"`
	}
	if decodeJSON(w, r, &in, 32*1024) != nil {
		return
	}
	in.Token = strings.TrimSpace(in.Token)
	if len(in.Token) < 40 || len(in.Token) > 128 {
		writeError(w, http.StatusBadRequest, "reset token is invalid or expired")
		return
	}
	digest := sha256.Sum256([]byte(in.Token))
	tokenHash := hex.EncodeToString(digest[:])
	tx, err := a.db.Begin()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not reset the password")
		return
	}
	defer tx.Rollback()
	var userID, username string
	err = tx.QueryRow(`SELECT u.id,u.username FROM password_reset_tokens t JOIN users u ON u.id=t.user_id WHERE t.token_hash=? AND t.expires_at>? AND u.disabled=0`, tokenHash, time.Now().Unix()).Scan(&userID, &username)
	if err != nil {
		writeError(w, http.StatusBadRequest, "reset token is invalid or expired")
		return
	}
	passwordHash, err := security.HashPassword(in.Password)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	res, err := tx.Exec(`UPDATE users SET password_hash=?,token_version=token_version+1 WHERE id=? AND disabled=0`, passwordHash, userID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not reset the password")
		return
	}
	if updated, rowsErr := res.RowsAffected(); rowsErr != nil || updated != 1 {
		writeError(w, http.StatusBadRequest, "reset token is invalid or expired")
		return
	}
	if _, err = tx.Exec(`DELETE FROM password_reset_tokens WHERE user_id=?`, userID); err != nil {
		writeError(w, http.StatusInternalServerError, "could not reset the password")
		return
	}
	if err = tx.Commit(); err != nil {
		writeError(w, http.StatusInternalServerError, "could not reset the password")
		return
	}
	a.clearLoginFailures("", username)
	a.audit(User{ID: userID, Username: username}, "user.password_reset", "user", userID, "")
	http.SetCookie(w, &http.Cookie{Name: "ygg_token", Value: "", Path: "/", HttpOnly: true, Secure: requestScheme(r) == "https", SameSite: http.SameSiteStrictMode, MaxAge: -1, Expires: time.Unix(1, 0)})
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}
