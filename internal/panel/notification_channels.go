package panel

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/mail"
	"net/smtp"
	"strconv"
	"strings"
	"time"

	"example.com/yggdrasil-panel/internal/security"
	"github.com/go-chi/chi/v5"
)

type notificationChannelSummary struct {
	ID         string `json:"id"`
	Type       string `json:"type"`
	ServerID   string `json:"server_id"`
	ServerName string `json:"server_name,omitempty"`
	Enabled    bool   `json:"enabled"`
	HasConfig  bool   `json:"has_config"`
}

type notificationChannelConfig struct {
	URL           string `json:"url,omitempty"`
	SigningSecret string `json:"signing_secret,omitempty"`
	BotToken      string `json:"bot_token,omitempty"`
	ChatID        string `json:"chat_id,omitempty"`
	SMTPHost      string `json:"smtp_host,omitempty"`
	SMTPPort      int    `json:"smtp_port,omitempty"`
	SMTPUsername  string `json:"smtp_username,omitempty"`
	SMTPPassword  string `json:"smtp_password,omitempty"`
	From          string `json:"from,omitempty"`
	To            string `json:"to,omitempty"`
}

type notificationChannelInput struct {
	Type     string          `json:"type"`
	ServerID string          `json:"server_id"`
	Enabled  *bool           `json:"enabled"`
	Config   json.RawMessage `json:"config"`
}

func (a *App) listNotificationChannelSummaries() ([]notificationChannelSummary, error) {
	rows, err := a.db.Query(`SELECT c.id,c.type,c.server_id,COALESCE(s.name,''),c.enabled,c.config_enc
		FROM notification_channels c LEFT JOIN servers s ON s.id=c.server_id ORDER BY c.created_at,c.id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]notificationChannelSummary, 0)
	for rows.Next() {
		var item notificationChannelSummary
		var enabled int
		var encrypted string
		if err = rows.Scan(&item.ID, &item.Type, &item.ServerID, &item.ServerName, &enabled, &encrypted); err != nil {
			return nil, err
		}
		item.Enabled = enabled != 0
		item.HasConfig = encrypted != ""
		out = append(out, item)
	}
	return out, rows.Err()
}

func decodeNotificationChannelInput(raw notificationChannelInput) (string, string, bool, notificationChannelConfig, error) {
	kind := strings.ToLower(strings.TrimSpace(raw.Type))
	if kind != "discord" && kind != "telegram" && kind != "webhook" && kind != "email" {
		return "", "", false, notificationChannelConfig{}, errors.New("channel type must be discord, telegram, webhook, or email")
	}
	if len(raw.Config) == 0 || len(raw.Config) > 24*1024 {
		return "", "", false, notificationChannelConfig{}, errors.New("channel configuration is required and must be at most 24 KiB")
	}
	var config notificationChannelConfig
	decoder := json.NewDecoder(bytes.NewReader(raw.Config))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&config); err != nil {
		return "", "", false, notificationChannelConfig{}, errors.New("channel configuration is invalid")
	}
	if err := decoder.Decode(new(any)); !errors.Is(err, io.EOF) {
		return "", "", false, notificationChannelConfig{}, errors.New("channel configuration must contain one JSON object")
	}
	switch kind {
	case "discord", "webhook":
		endpoint, err := normalizeWebhookEndpoint(strings.TrimSpace(config.URL))
		if err != nil {
			return "", "", false, notificationChannelConfig{}, err
		}
		config.URL = endpoint
		if len(config.SigningSecret) > 512 || strings.ContainsAny(config.SigningSecret, "\r\n\x00") {
			return "", "", false, notificationChannelConfig{}, errors.New("webhook signing secret must be 512 characters or fewer")
		}
		if kind == "discord" && config.SigningSecret != "" {
			return "", "", false, notificationChannelConfig{}, errors.New("Discord webhook channels do not use a signing secret")
		}
	case "telegram":
		config.BotToken = strings.TrimSpace(config.BotToken)
		config.ChatID = strings.TrimSpace(config.ChatID)
		if len(config.BotToken) > 256 || !strings.Contains(config.BotToken, ":") || strings.ContainsAny(config.BotToken, " \t\r\n\x00") {
			return "", "", false, notificationChannelConfig{}, errors.New("Telegram bot token is invalid")
		}
		if config.ChatID == "" || len(config.ChatID) > 256 || strings.ContainsAny(config.ChatID, "\r\n\x00") {
			return "", "", false, notificationChannelConfig{}, errors.New("Telegram chat ID is required and must be 256 characters or fewer")
		}
	case "email":
		host := strings.TrimSpace(config.SMTPHost)
		if host == "" || strings.ContainsAny(host, "/\\?#@\r\n\x00") {
			return "", "", false, notificationChannelConfig{}, errors.New("SMTP host must be a hostname or IP address")
		}
		if strings.HasPrefix(host, "[") && strings.HasSuffix(host, "]") {
			host = strings.TrimSuffix(strings.TrimPrefix(host, "["), "]")
		}
		if ip := net.ParseIP(host); ip != nil {
			host = ip.String()
		} else {
			host = strings.TrimSuffix(strings.ToLower(host), ".")
			if !validRegistryDNSName(host) {
				return "", "", false, notificationChannelConfig{}, errors.New("SMTP host is invalid")
			}
		}
		config.SMTPHost = host
		if config.SMTPPort == 0 {
			config.SMTPPort = 587
		}
		if config.SMTPPort < 1 || config.SMTPPort > 65535 {
			return "", "", false, notificationChannelConfig{}, errors.New("SMTP port must be between 1 and 65535")
		}
		if len(config.SMTPUsername) > 512 || strings.ContainsAny(config.SMTPUsername, "\r\n\x00") || len(config.SMTPPassword) > 4096 || strings.ContainsRune(config.SMTPPassword, '\x00') {
			return "", "", false, notificationChannelConfig{}, errors.New("SMTP credentials are invalid or too long")
		}
		if (config.SMTPUsername == "") != (config.SMTPPassword == "") {
			return "", "", false, notificationChannelConfig{}, errors.New("enter both an SMTP username and password, or leave both empty")
		}
		from, err := safeMailAddress(config.From)
		if err != nil {
			return "", "", false, notificationChannelConfig{}, errors.New("SMTP sender address is invalid")
		}
		to, err := safeMailAddress(config.To)
		if err != nil {
			return "", "", false, notificationChannelConfig{}, errors.New("SMTP recipient address is invalid")
		}
		config.From, config.To = from, to
	}
	serverID := strings.TrimSpace(raw.ServerID)
	if len(serverID) > 100 || strings.ContainsAny(serverID, "\r\n\x00") {
		return "", "", false, notificationChannelConfig{}, errors.New("notification server scope is invalid")
	}
	enabled := true
	if raw.Enabled != nil {
		enabled = *raw.Enabled
	}
	return kind, serverID, enabled, config, nil
}

func safeMailAddress(value string) (string, error) {
	value = strings.TrimSpace(value)
	parsed, err := mail.ParseAddress(value)
	if err != nil || parsed.Address != value || strings.ContainsAny(value, "\r\n\x00") {
		return "", errors.New("invalid email address")
	}
	return parsed.Address, nil
}

func (a *App) createNotificationChannel(w http.ResponseWriter, r *http.Request) {
	var raw notificationChannelInput
	if decodeJSON(w, r, &raw, 32*1024) != nil {
		return
	}
	kind, serverID, enabled, config, err := decodeNotificationChannelInput(raw)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if serverID != "" {
		var found int
		if err = a.db.QueryRow(`SELECT count(*) FROM servers WHERE id=?`, serverID).Scan(&found); err != nil {
			writeError(w, http.StatusInternalServerError, "could not validate notification server scope")
			return
		}
		if found != 1 {
			writeError(w, http.StatusBadRequest, "notification server scope does not exist")
			return
		}
	}
	encoded, err := json.Marshal(config)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not encode notification channel configuration")
		return
	}
	encrypted, err := security.Encrypt([]byte(a.cfg.Auth.SecretKey), string(encoded))
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not encrypt notification channel configuration")
		return
	}
	id, err := newID()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not create notification channel id")
		return
	}
	if _, err = a.db.Exec(`INSERT INTO notification_channels(id,type,config_enc,enabled,server_id) VALUES(?,?,?,?,?)`, id, kind, encrypted, boolInt(enabled), serverID); err != nil {
		writeError(w, http.StatusInternalServerError, "could not save notification channel")
		return
	}
	a.audit(principal(r), "notification.channel.create", "notification", id, kind)
	a.writeNotificationChannel(w, id, http.StatusCreated)
}

func (a *App) updateNotificationChannel(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	var exists int
	if err := a.db.QueryRow(`SELECT count(*) FROM notification_channels WHERE id=?`, id).Scan(&exists); err != nil {
		writeError(w, http.StatusInternalServerError, "could not read notification channel")
		return
	} else if exists == 0 {
		writeError(w, http.StatusNotFound, "notification channel not found")
		return
	}
	var raw notificationChannelInput
	if decodeJSON(w, r, &raw, 32*1024) != nil {
		return
	}
	kind, serverID, enabled, config, err := decodeNotificationChannelInput(raw)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if serverID != "" {
		var found int
		if err = a.db.QueryRow(`SELECT count(*) FROM servers WHERE id=?`, serverID).Scan(&found); err != nil || found != 1 {
			writeError(w, http.StatusBadRequest, "notification server scope does not exist")
			return
		}
	}
	if raw.Enabled == nil {
		var current int
		if err = a.db.QueryRow(`SELECT enabled FROM notification_channels WHERE id=?`, id).Scan(&current); err != nil {
			writeError(w, http.StatusInternalServerError, "could not read notification channel")
			return
		}
		enabled = current != 0
	}
	encoded, err := json.Marshal(config)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not encode notification channel configuration")
		return
	}
	encrypted, err := security.Encrypt([]byte(a.cfg.Auth.SecretKey), string(encoded))
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not encrypt notification channel configuration")
		return
	}
	if _, err = a.db.Exec(`UPDATE notification_channels SET type=?,config_enc=?,enabled=?,server_id=?,updated_at=CURRENT_TIMESTAMP WHERE id=?`, kind, encrypted, boolInt(enabled), serverID, id); err != nil {
		writeError(w, http.StatusInternalServerError, "could not update notification channel")
		return
	}
	a.audit(principal(r), "notification.channel.update", "notification", id, kind)
	a.writeNotificationChannel(w, id, http.StatusOK)
}

func (a *App) writeNotificationChannel(w http.ResponseWriter, id string, status int) {
	channels, err := a.listNotificationChannelSummaries()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not read notification channel")
		return
	}
	for _, item := range channels {
		if item.ID == id {
			writeJSON(w, status, item)
			return
		}
	}
	writeError(w, http.StatusNotFound, "notification channel not found")
}

func (a *App) deleteNotificationChannel(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	var kind string
	err := a.db.QueryRow(`SELECT type FROM notification_channels WHERE id=?`, id).Scan(&kind)
	if errors.Is(err, sql.ErrNoRows) {
		writeError(w, http.StatusNotFound, "notification channel not found")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not read notification channel")
		return
	}
	if _, err = a.db.Exec(`DELETE FROM notification_channels WHERE id=?`, id); err != nil {
		writeError(w, http.StatusInternalServerError, "could not delete notification channel")
		return
	}
	a.audit(principal(r), "notification.channel.delete", "notification", id, kind)
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (a *App) readNotificationChannel(id string) (string, string, bool, notificationChannelConfig, error) {
	var kind, serverID, encrypted string
	var enabled int
	err := a.db.QueryRow(`SELECT type,server_id,enabled,config_enc FROM notification_channels WHERE id=?`, id).Scan(&kind, &serverID, &enabled, &encrypted)
	if err != nil {
		return "", "", false, notificationChannelConfig{}, err
	}
	plain, err := security.Decrypt([]byte(a.cfg.Auth.SecretKey), encrypted)
	if err != nil {
		return "", "", false, notificationChannelConfig{}, errors.New("saved notification channel cannot be decrypted; check auth.secret_key")
	}
	var config notificationChannelConfig
	if err = json.Unmarshal([]byte(plain), &config); err != nil {
		return "", "", false, notificationChannelConfig{}, errors.New("saved notification channel configuration is invalid")
	}
	return kind, serverID, enabled != 0, config, nil
}

func (a *App) testNotificationChannel(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	kind, _, enabled, config, err := a.readNotificationChannel(id)
	if errors.Is(err, sql.ErrNoRows) {
		writeError(w, http.StatusNotFound, "notification channel not found")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if !enabled {
		writeError(w, http.StatusBadRequest, "enable the channel before sending a test")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()
	err = a.sendNotificationChannel(ctx, kind, config, "[Docklight] Test notification — channels are working.")
	if err != nil {
		writeError(w, http.StatusBadGateway, err.Error())
		return
	}
	a.audit(principal(r), "notification.channel.test", "notification", id, kind)
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (a *App) dispatchNotificationChannels(payload webhookPayload) {
	serverID := ""
	if payload.Server != nil {
		serverID = payload.Server.ID
	}
	rows, err := a.db.Query(`SELECT id,type,config_enc FROM notification_channels WHERE enabled=1 AND (server_id='' OR server_id=?)`, serverID)
	if err != nil {
		log.Printf("could not read notification channels for event %s", payload.Event)
		return
	}
	type delivery struct {
		id, kind string
		config   notificationChannelConfig
	}
	items := make([]delivery, 0)
	for rows.Next() {
		var item delivery
		var encrypted string
		if err = rows.Scan(&item.id, &item.kind, &encrypted); err != nil {
			continue
		}
		plain, decryptErr := security.Decrypt([]byte(a.cfg.Auth.SecretKey), encrypted)
		if decryptErr != nil || json.Unmarshal([]byte(plain), &item.config) != nil {
			log.Printf("notification channel %s could not be read; check auth.secret_key", item.id)
			continue
		}
		items = append(items, item)
	}
	if err = rows.Err(); err != nil {
		log.Printf("could not read notification channels for event %s", payload.Event)
	}
	_ = rows.Close()
	message := notificationChannelMessage(payload)
	for _, item := range items {
		item := item
		timeout := 10 * time.Second
		if item.kind == "email" {
			timeout = 20 * time.Second
		}
		go func() {
			ctx, cancel := context.WithTimeout(context.Background(), timeout)
			defer cancel()
			if err := a.sendNotificationChannel(ctx, item.kind, item.config, message); err != nil {
				log.Printf("notification channel %s (%s) delivery failed: %v", item.id, item.kind, err)
			}
		}()
	}
}

func notificationChannelMessage(payload webhookPayload) string {
	message := strings.TrimSpace(payload.Message)
	if message == "" {
		message = payload.Event
	}
	if payload.Schedule != nil {
		message = fmt.Sprintf("%s (%s)", message, payload.Schedule.Action)
	}
	if payload.Server != nil && payload.Server.Name != "" {
		message = payload.Server.Name + ": " + message
	}
	return "[Docklight] " + message
}

func (a *App) sendNotificationChannel(ctx context.Context, kind string, config notificationChannelConfig, message string) error {
	switch kind {
	case "discord":
		endpoint, err := normalizeWebhookEndpoint(config.URL)
		if err != nil {
			return errors.New("stored Discord webhook URL is invalid; update it in Notifications")
		}
		return a.postChannelJSON(ctx, endpoint, map[string]any{
			"content":          truncateNotificationText(message, 2000),
			"allowed_mentions": map[string][]string{"parse": {}},
		}, "")
	case "webhook":
		endpoint, err := normalizeWebhookEndpoint(config.URL)
		if err != nil {
			return errors.New("stored webhook URL is invalid; update it in Notifications")
		}
		return a.postChannelJSON(ctx, endpoint, map[string]string{"text": message}, config.SigningSecret)
	case "telegram":
		endpoint := "https://api.telegram.org/bot" + config.BotToken + "/sendMessage"
		body, _ := json.Marshal(map[string]string{"chat_id": config.ChatID, "text": truncateNotificationText(message, 4096)})
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
		if err != nil {
			return errors.New("could not prepare Telegram notification")
		}
		req.Header.Set("Content-Type", "application/json")
		resp, err := a.notificationHTTPClient().Do(req)
		if err != nil {
			return errors.New("Telegram delivery failed; check the bot token, chat ID, and network")
		}
		defer resp.Body.Close()
		responseBody, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
		if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
			return fmt.Errorf("Telegram returned HTTP %d; check the bot token and chat permissions", resp.StatusCode)
		}
		var result struct {
			OK bool `json:"ok"`
		}
		if json.Unmarshal(responseBody, &result) != nil || !result.OK {
			return errors.New("Telegram did not accept the notification; check the bot token and chat ID")
		}
		return nil
	case "email":
		return sendSMTPNotification(ctx, config, message)
	default:
		return errors.New("notification channel type is unsupported")
	}
}

func truncateNotificationText(value string, limit int) string {
	runes := []rune(value)
	if len(runes) <= limit {
		return value
	}
	if limit < 2 {
		return string(runes[:limit])
	}
	return string(runes[:limit-1]) + "…"
}

func (a *App) notificationHTTPClient() *http.Client {
	var client http.Client
	if a.notificationClient != nil {
		client = *a.notificationClient
	}
	if client.Timeout <= 0 {
		client.Timeout = 10 * time.Second
	}
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return &client
}

func (a *App) postChannelJSON(ctx context.Context, endpoint string, payload any, signingSecret string) error {
	body, err := json.Marshal(payload)
	if err != nil {
		return errors.New("could not encode notification")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return errors.New("could not prepare notification request")
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "Docklight/1.0")
	if signingSecret != "" {
		signature := hmac.New(sha256.New, []byte(signingSecret))
		_, _ = signature.Write(body)
		req.Header.Set("X-Docklight-Signature", "sha256="+hex.EncodeToString(signature.Sum(nil)))
	}
	resp, err := a.notificationHTTPClient().Do(req)
	if err != nil {
		return errors.New("notification delivery failed; check the endpoint and network")
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64*1024))
	_ = resp.Body.Close()
	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		return fmt.Errorf("notification endpoint returned HTTP %d", resp.StatusCode)
	}
	return nil
}

func sendSMTPNotification(ctx context.Context, config notificationChannelConfig, message string) error {
	dialer := &net.Dialer{Timeout: 5 * time.Second}
	return sendSMTPNotificationWithDial(ctx, config, message, dialer.DialContext)
}

func sendSMTPNotificationWithDial(ctx context.Context, config notificationChannelConfig, message string, dial func(context.Context, string, string) (net.Conn, error)) error {
	address := net.JoinHostPort(config.SMTPHost, strconv.Itoa(config.SMTPPort))
	conn, err := dial(ctx, "tcp", address)
	if err != nil {
		return errors.New("SMTP connection failed; check the host, port, and network")
	}
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	} else {
		_ = conn.SetDeadline(time.Now().Add(20 * time.Second))
	}
	secure := false
	if config.SMTPPort == 465 {
		tlsConn := tls.Client(conn, &tls.Config{ServerName: config.SMTPHost, MinVersion: tls.VersionTLS12})
		if err = tlsConn.HandshakeContext(ctx); err != nil {
			_ = conn.Close()
			return errors.New("SMTP TLS handshake failed; check the host certificate and port")
		}
		conn = tlsConn
		secure = true
	}
	client, err := smtp.NewClient(conn, config.SMTPHost)
	if err != nil {
		_ = conn.Close()
		return errors.New("SMTP server did not complete its greeting")
	}
	defer client.Close()
	if !secure {
		if supported, _ := client.Extension("STARTTLS"); supported {
			if err = client.StartTLS(&tls.Config{ServerName: config.SMTPHost, MinVersion: tls.VersionTLS12}); err != nil {
				return errors.New("SMTP STARTTLS failed; check the server certificate")
			}
			secure = true
		}
	}
	if !secure && config.SMTPUsername != "" {
		return errors.New("SMTP authentication requires TLS; enable STARTTLS or use port 465")
	}
	if !secure && !isLoopbackSMTPHost(config.SMTPHost) {
		return errors.New("SMTP server must support TLS; use STARTTLS or port 465")
	}
	if config.SMTPUsername != "" {
		if err = client.Auth(smtp.PlainAuth("", config.SMTPUsername, config.SMTPPassword, config.SMTPHost)); err != nil {
			return errors.New("SMTP rejected the configured credentials")
		}
	}
	from, _ := safeMailAddress(config.From)
	to, _ := safeMailAddress(config.To)
	if err = client.Mail(from); err != nil {
		return errors.New("SMTP rejected the sender address")
	}
	if err = client.Rcpt(to); err != nil {
		return errors.New("SMTP rejected the recipient address")
	}
	writer, err := client.Data()
	if err != nil {
		return errors.New("SMTP refused the message")
	}
	contents := "From: " + from + "\r\nTo: " + to + "\r\nSubject: [Docklight] Notification\r\nMIME-Version: 1.0\r\nContent-Type: text/plain; charset=UTF-8\r\nContent-Transfer-Encoding: 8bit\r\n\r\n" + message
	if _, err = io.WriteString(writer, contents); err != nil {
		_ = writer.Close()
		return errors.New("could not write the SMTP message")
	}
	if err = writer.Close(); err != nil {
		return errors.New("SMTP did not accept the message")
	}
	if err = client.Quit(); err != nil {
		return errors.New("SMTP connection did not close cleanly")
	}
	return nil
}

func isLoopbackSMTPHost(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
