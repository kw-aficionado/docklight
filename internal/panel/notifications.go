package panel

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"example.com/yggdrasil-panel/internal/security"
)

const (
	notificationBackupSuccess = "backup.success"
	notificationBackupFailure = "backup.failure"
	notificationHostDiskLow   = "host.disk_low"
)

type notificationSettings struct {
	Enabled                 bool     `json:"enabled"`
	EndpointConfigured      bool     `json:"endpoint_configured"`
	SigningSecretConfigured bool     `json:"signing_secret_configured"`
	Events                  []string `json:"events"`
	UpdatedAt               string   `json:"updated_at"`
}

type storedNotificationSettings struct {
	Enabled       bool
	Endpoint      string
	SigningSecret string
	Events        []string
	UpdatedAt     string
}

type webhookPayload struct {
	Product  string         `json:"product"`
	Event    string         `json:"event"`
	Occurred string         `json:"occurred_at"`
	Server   *webhookServer `json:"server,omitempty"`
	Message  string         `json:"message,omitempty"`
}

type webhookServer struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

func (a *App) readNotificationSettings() (storedNotificationSettings, error) {
	var enabled int
	var eventsJSON string
	var out storedNotificationSettings
	err := a.db.QueryRow(`SELECT enabled,endpoint_enc,signing_secret_enc,events_json,updated_at FROM notification_settings WHERE id=1`).Scan(&enabled, &out.Endpoint, &out.SigningSecret, &eventsJSON, &out.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return storedNotificationSettings{Events: []string{}}, nil
	}
	if err != nil {
		return storedNotificationSettings{}, err
	}
	out.Enabled = enabled != 0
	if err = json.Unmarshal([]byte(eventsJSON), &out.Events); err != nil {
		return storedNotificationSettings{}, errors.New("stored notification event settings are invalid")
	}
	return out, nil
}

func (a *App) publicNotificationSettings(w http.ResponseWriter) {
	stored, err := a.readNotificationSettings()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not read notification settings")
		return
	}
	writeJSON(w, http.StatusOK, notificationSettings{
		Enabled: stored.Enabled, EndpointConfigured: stored.Endpoint != "",
		SigningSecretConfigured: stored.SigningSecret != "", Events: stored.Events, UpdatedAt: stored.UpdatedAt,
	})
}

func (a *App) getNotificationSettings(w http.ResponseWriter, _ *http.Request) {
	a.publicNotificationSettings(w)
}

func (a *App) updateNotificationSettings(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Enabled            *bool    `json:"enabled"`
		Endpoint           string   `json:"endpoint"`
		SigningSecret      string   `json:"signing_secret"`
		Events             []string `json:"events"`
		ClearEndpoint      bool     `json:"clear_endpoint"`
		ClearSigningSecret bool     `json:"clear_signing_secret"`
	}
	if decodeJSON(w, r, &in, 8192) != nil {
		return
	}
	current, err := a.readNotificationSettings()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not read notification settings")
		return
	}
	if in.ClearEndpoint {
		current.Endpoint = ""
	} else if strings.TrimSpace(in.Endpoint) != "" {
		endpoint := strings.TrimSpace(in.Endpoint)
		if len(endpoint) > 2048 {
			writeError(w, http.StatusBadRequest, "webhook endpoint must be 2048 characters or fewer")
			return
		}
		endpoint, err = normalizeWebhookEndpoint(endpoint)
		if err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		current.Endpoint, err = security.Encrypt([]byte(a.cfg.Auth.SecretKey), endpoint)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "could not encrypt webhook endpoint")
			return
		}
	}
	if in.ClearSigningSecret {
		current.SigningSecret = ""
	} else if in.SigningSecret != "" {
		if len(in.SigningSecret) > 512 {
			writeError(w, http.StatusBadRequest, "signing secret must be 512 characters or fewer")
			return
		}
		current.SigningSecret, err = security.Encrypt([]byte(a.cfg.Auth.SecretKey), in.SigningSecret)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "could not encrypt webhook signing secret")
			return
		}
	}
	if in.Events != nil {
		seen := make(map[string]bool, len(in.Events))
		current.Events = make([]string, 0, len(in.Events))
		for _, event := range in.Events {
			event = strings.TrimSpace(event)
			if event != notificationBackupSuccess && event != notificationBackupFailure && event != notificationHostDiskLow {
				writeError(w, http.StatusBadRequest, "event must be backup.success, backup.failure, or host.disk_low")
				return
			}
			if !seen[event] {
				seen[event] = true
				current.Events = append(current.Events, event)
			}
		}
	}
	if in.Enabled != nil {
		current.Enabled = *in.Enabled
	}
	if current.Enabled && current.Endpoint == "" {
		writeError(w, http.StatusBadRequest, "configure a webhook endpoint before enabling notifications")
		return
	}
	if current.Enabled && len(current.Events) == 0 {
		writeError(w, http.StatusBadRequest, "select at least one notification event before enabling notifications")
		return
	}
	eventsJSON, err := json.Marshal(current.Events)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not encode notification event settings")
		return
	}
	if _, err = a.db.Exec(`INSERT INTO notification_settings(id,enabled,endpoint_enc,signing_secret_enc,events_json,updated_at)
		VALUES(1,?,?,?,?,CURRENT_TIMESTAMP) ON CONFLICT(id) DO UPDATE SET enabled=excluded.enabled,endpoint_enc=excluded.endpoint_enc,signing_secret_enc=excluded.signing_secret_enc,events_json=excluded.events_json,updated_at=CURRENT_TIMESTAMP`, boolInt(current.Enabled), current.Endpoint, current.SigningSecret, string(eventsJSON)); err != nil {
		writeError(w, http.StatusInternalServerError, "could not save notification settings")
		return
	}
	eventDetail := strings.Join(current.Events, ",")
	a.audit(principal(r), "notification.settings.update", "notification", "webhook", fmt.Sprintf("enabled=%t events=%s", current.Enabled, eventDetail))
	a.publicNotificationSettings(w)
}

func (a *App) testNotification(w http.ResponseWriter, r *http.Request) {
	stored, err := a.readNotificationSettings()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not read notification settings")
		return
	}
	if stored.Endpoint == "" {
		writeError(w, http.StatusBadRequest, "configure a webhook endpoint before sending a test")
		return
	}
	payload := webhookPayload{Product: "Docklight", Event: "notification.test", Occurred: time.Now().UTC().Format(time.RFC3339Nano), Message: "Webhook delivery is configured."}
	if err = a.deliverWebhook(r.Context(), stored, payload); err != nil {
		writeError(w, http.StatusBadGateway, err.Error())
		return
	}
	a.audit(principal(r), "notification.webhook.test", "notification", "webhook", "")
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func normalizeWebhookEndpoint(value string) (string, error) {
	u, err := url.Parse(value)
	if err != nil || !u.IsAbs() || u.Hostname() == "" || u.User != nil || u.Fragment != "" {
		return "", errors.New("webhook endpoint must be an absolute HTTP(S) URL without user information or a fragment")
	}
	u.Scheme = strings.ToLower(u.Scheme)
	switch strings.ToLower(u.Scheme) {
	case "https":
	case "http":
		host := strings.TrimSuffix(strings.ToLower(u.Hostname()), ".")
		ip := net.ParseIP(host)
		if host != "localhost" && (ip == nil || !ip.IsLoopback()) {
			return "", errors.New("webhook endpoints must use HTTPS; plain HTTP is allowed only for localhost loopback testing")
		}
	default:
		return "", errors.New("webhook endpoint must use HTTPS")
	}
	return u.String(), nil
}

func (a *App) dispatchBackupNotification(event, serverID, serverName, message string) {
	a.dispatchWebhookNotification(event, &webhookServer{ID: serverID, Name: serverName}, message)
}

func (a *App) dispatchWebhookNotification(event string, server *webhookServer, message string) {
	stored, err := a.readNotificationSettings()
	if err != nil {
		log.Printf("could not read notification settings for %s", event)
		return
	}
	if !stored.Enabled || !containsString(stored.Events, event) {
		return
	}
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
		defer cancel()
		payload := webhookPayload{Product: "Docklight", Event: event, Occurred: time.Now().UTC().Format(time.RFC3339Nano), Server: server, Message: message}
		if err := a.deliverWebhook(ctx, stored, payload); err != nil {
			log.Printf("webhook notification %s failed: %v", event, err)
		}
	}()
}

func containsString(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

func (a *App) deliverWebhook(ctx context.Context, stored storedNotificationSettings, payload webhookPayload) error {
	endpoint, err := security.Decrypt([]byte(a.cfg.Auth.SecretKey), stored.Endpoint)
	if err != nil {
		return errors.New("stored webhook endpoint cannot be decrypted; check auth.secret_key")
	}
	endpoint, err = normalizeWebhookEndpoint(endpoint)
	if err != nil {
		return errors.New("stored webhook endpoint is invalid; update it in Notifications")
	}
	secret := ""
	if stored.SigningSecret != "" {
		secret, err = security.Decrypt([]byte(a.cfg.Auth.SecretKey), stored.SigningSecret)
		if err != nil {
			return errors.New("stored webhook signing secret cannot be decrypted; check auth.secret_key")
		}
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return errors.New("could not encode webhook notification")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(string(body)))
	if err != nil {
		return errors.New("could not prepare webhook request")
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "Docklight/1.0")
	if secret != "" {
		signature := hmac.New(sha256.New, []byte(secret))
		_, _ = signature.Write(body)
		req.Header.Set("X-Docklight-Signature", "sha256="+hex.EncodeToString(signature.Sum(nil)))
	}
	client := a.notificationClient
	if client == nil {
		client = &http.Client{Timeout: 5 * time.Second}
	} else {
		clientCopy := *client
		client = &clientCopy
	}
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	resp, err := client.Do(req)
	if err != nil {
		return errors.New("webhook delivery failed; check endpoint reachability and TLS settings")
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64*1024))
	_ = resp.Body.Close()
	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		return fmt.Errorf("webhook endpoint returned HTTP %d", resp.StatusCode)
	}
	return nil
}
