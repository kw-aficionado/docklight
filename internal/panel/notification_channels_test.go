package panel

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"example.com/yggdrasil-panel/internal/security"
)

type notificationChannelRoundTripper func(*http.Request) (*http.Response, error)

func (fn notificationChannelRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	return fn(req)
}

func notificationChannelResponse(req *http.Request, status int, body string) *http.Response {
	return &http.Response{StatusCode: status, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(body)), Request: req}
}

func TestNotificationChannelsEncryptConfigAndKeepItOutOfResponses(t *testing.T) {
	app, d, _ := testApp(t)
	token := runeCatalogAdminToken(t, app, d)
	secretURL := "https://discord.example/api/webhooks/123/private-webhook-token"
	request, err := json.Marshal(map[string]any{"type": "discord", "config": map[string]string{"url": secretURL}})
	if err != nil {
		t.Fatal(err)
	}
	created := testRequest(app.Router(), http.MethodPost, "/api/notifications", string(request), token)
	if created.Code != http.StatusCreated || strings.Contains(created.Body.String(), secretURL) || strings.Contains(created.Body.String(), "private-webhook-token") {
		t.Fatalf("create channel status=%d body=%s", created.Code, created.Body.String())
	}
	var summary notificationChannelSummary
	if err = json.Unmarshal(created.Body.Bytes(), &summary); err != nil || summary.ID == "" || summary.Type != "discord" || !summary.HasConfig {
		t.Fatalf("channel summary=%s err=%v", created.Body.String(), err)
	}
	var encrypted string
	if err = d.QueryRow(`SELECT config_enc FROM notification_channels WHERE id=?`, summary.ID).Scan(&encrypted); err != nil {
		t.Fatal(err)
	}
	if encrypted == "" || strings.Contains(encrypted, secretURL) {
		t.Fatalf("channel config was not encrypted: %q", encrypted)
	}
	plain, err := security.Decrypt([]byte(app.cfg.Auth.SecretKey), encrypted)
	if err != nil || !strings.Contains(plain, secretURL) {
		t.Fatalf("decrypted config=%q err=%v", plain, err)
	}
	listed := testRequest(app.Router(), http.MethodGet, "/api/notifications", "", token)
	if listed.Code != http.StatusOK || strings.Contains(listed.Body.String(), secretURL) || strings.Contains(listed.Body.String(), "private-webhook-token") || !strings.Contains(listed.Body.String(), `"has_config":true`) {
		t.Fatalf("channel list leaked config or omitted mask: %d %s", listed.Code, listed.Body.String())
	}
	var tested bool
	app.notificationClient = &http.Client{Transport: notificationChannelRoundTripper(func(req *http.Request) (*http.Response, error) {
		if req.URL.String() != secretURL || req.Method != http.MethodPost {
			t.Fatalf("unexpected Discord endpoint: %s", req.URL.String())
		}
		var body struct {
			Content         string `json:"content"`
			AllowedMentions struct {
				Parse []string `json:"parse"`
			} `json:"allowed_mentions"`
		}
		if err := json.NewDecoder(req.Body).Decode(&body); err != nil || !strings.Contains(body.Content, "Docklight") || len(body.AllowedMentions.Parse) != 0 {
			t.Fatalf("Discord body=%v err=%v", body, err)
		}
		tested = true
		return notificationChannelResponse(req, http.StatusNoContent, ""), nil
	})}
	testResponse := testRequest(app.Router(), http.MethodPost, "/api/notifications/"+summary.ID+"/test", `{}`, token)
	if testResponse.Code != http.StatusOK || strings.Contains(testResponse.Body.String(), "private-webhook-token") || !tested {
		t.Fatalf("test channel response=%d %s tested=%t", testResponse.Code, testResponse.Body.String(), tested)
	}
	removed := testRequest(app.Router(), http.MethodDelete, "/api/notifications/"+summary.ID, "", token)
	if removed.Code != http.StatusOK {
		t.Fatalf("delete channel: %d %s", removed.Code, removed.Body.String())
	}
	var auditCount int
	if err = d.QueryRow(`SELECT count(*) FROM audit_log WHERE action='notification.channel.delete' AND target_id=?`, summary.ID).Scan(&auditCount); err != nil || auditCount != 1 {
		t.Fatalf("channel delete audit count=%d err=%v", auditCount, err)
	}
}

func TestTelegramTestUsesBotAPIAndDoesNotReturnToken(t *testing.T) {
	app, d, _ := testApp(t)
	token := runeCatalogAdminToken(t, app, d)
	botToken := "123456:telegram-private-token"
	request, err := json.Marshal(map[string]any{"type": "telegram", "config": map[string]string{"bot_token": botToken, "chat_id": "@docklight_alerts"}})
	if err != nil {
		t.Fatal(err)
	}
	created := testRequest(app.Router(), http.MethodPost, "/api/notifications", string(request), token)
	if created.Code != http.StatusCreated || strings.Contains(created.Body.String(), botToken) {
		t.Fatalf("create Telegram channel status=%d body=%s", created.Code, created.Body.String())
	}
	var summary notificationChannelSummary
	if err = json.Unmarshal(created.Body.Bytes(), &summary); err != nil {
		t.Fatal(err)
	}
	var called bool
	app.notificationClient = &http.Client{Transport: notificationChannelRoundTripper(func(req *http.Request) (*http.Response, error) {
		if req.URL.Scheme != "https" || req.URL.Host != "api.telegram.org" || req.URL.Path != "/bot"+botToken+"/sendMessage" {
			t.Fatalf("unexpected Telegram API request: %s", req.URL.String())
		}
		var body map[string]string
		if err := json.NewDecoder(req.Body).Decode(&body); err != nil || body["chat_id"] != "@docklight_alerts" {
			t.Fatalf("Telegram body=%v err=%v", body, err)
		}
		called = true
		return notificationChannelResponse(req, http.StatusOK, `{"ok":true,"result":{"message_id":1}}`), nil
	})}
	response := testRequest(app.Router(), http.MethodPost, "/api/notifications/"+summary.ID+"/test", `{}`, token)
	if response.Code != http.StatusOK || strings.Contains(response.Body.String(), botToken) || !called {
		t.Fatalf("Telegram test response=%d %s called=%t", response.Code, response.Body.String(), called)
	}
}

func TestNotificationChannelServerScopeRoutesOnlyMatchingServer(t *testing.T) {
	app, d, _ := testApp(t)
	for _, channel := range []struct{ id, serverID string }{{"global", ""}, {"server-one", "server-1"}, {"server-two", "server-2"}} {
		config, err := json.Marshal(notificationChannelConfig{URL: "https://hooks.example/" + channel.id})
		if err != nil {
			t.Fatal(err)
		}
		encrypted, err := security.Encrypt([]byte(app.cfg.Auth.SecretKey), string(config))
		if err != nil {
			t.Fatal(err)
		}
		if _, err = d.Exec(`INSERT INTO notification_channels(id,type,config_enc,enabled,server_id) VALUES(?,'discord',?,1,?)`, channel.id, encrypted, channel.serverID); err != nil {
			t.Fatal(err)
		}
	}
	requests := make(chan string, 3)
	app.notificationClient = &http.Client{Transport: notificationChannelRoundTripper(func(req *http.Request) (*http.Response, error) {
		requests <- strings.TrimPrefix(req.URL.Path, "/")
		return notificationChannelResponse(req, http.StatusNoContent, ""), nil
	})}
	app.dispatchNotificationChannels(webhookPayload{Event: notificationServerCrash, Server: &webhookServer{ID: "server-1", Name: "Harbor"}, Message: "Container exited."})
	got := map[string]bool{}
	for i := 0; i < 2; i++ {
		select {
		case path := <-requests:
			got[path] = true
		case <-time.After(2 * time.Second):
			t.Fatalf("timed out waiting for scoped notification sends: %v", got)
		}
	}
	if !got["global"] || !got["server-one"] || got["server-two"] {
		t.Fatalf("wrong notification scope deliveries: %v", got)
	}
	select {
	case path := <-requests:
		t.Fatalf("received an extra out-of-scope delivery: %s", path)
	case <-time.After(50 * time.Millisecond):
	}
}

func TestEmailChannelValidationDefaultsPortAndSMTPUsesTLSBoundary(t *testing.T) {
	raw := json.RawMessage(`{"smtp_host":"mail.example.com","from":"docklight@example.com","to":"ops@example.com","smtp_username":"mailer","smtp_password":"smtp-private-password"}`)
	kind, scope, enabled, config, err := decodeNotificationChannelInput(notificationChannelInput{Type: "email", Config: raw})
	if err != nil || kind != "email" || scope != "" || !enabled || config.SMTPPort != 587 || config.From != "docklight@example.com" {
		t.Fatalf("email config kind=%q scope=%q enabled=%t config=%#v err=%v", kind, scope, enabled, config, err)
	}
	if _, _, _, _, err = decodeNotificationChannelInput(notificationChannelInput{Type: "email", Config: json.RawMessage(`{"smtp_host":"mail.example.com","from":"bad\r\nBcc:x@example.com","to":"ops@example.com"}`)}); err == nil {
		t.Fatal("SMTP header injection address was accepted")
	}
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	serverDone := make(chan string, 1)
	go func() {
		reader := bufio.NewReader(server)
		var data strings.Builder
		_, _ = io.WriteString(server, "220 localhost ESMTP\r\n")
		for {
			line, readErr := reader.ReadString('\n')
			if readErr != nil {
				serverDone <- readErr.Error()
				return
			}
			command := strings.TrimSpace(line)
			switch {
			case strings.HasPrefix(command, "EHLO ") || strings.HasPrefix(command, "HELO "):
				_, _ = io.WriteString(server, "250 localhost\r\n")
			case strings.HasPrefix(command, "MAIL FROM:") || strings.HasPrefix(command, "RCPT TO:"):
				_, _ = io.WriteString(server, "250 OK\r\n")
			case command == "DATA":
				_, _ = io.WriteString(server, "354 End data with <CR><LF>.<CR><LF>\r\n")
				for {
					dataLine, dataErr := reader.ReadString('\n')
					if dataErr != nil {
						serverDone <- dataErr.Error()
						return
					}
					if dataLine == ".\r\n" {
						break
					}
					data.WriteString(dataLine)
				}
				_, _ = io.WriteString(server, "250 queued\r\n")
			case command == "QUIT":
				_, _ = io.WriteString(server, "221 bye\r\n")
				serverDone <- data.String()
				return
			default:
				_, _ = io.WriteString(server, "250 OK\r\n")
			}
		}
	}()
	config.SMTPHost = "localhost"
	config.SMTPPort = 2525
	config.SMTPUsername, config.SMTPPassword = "", ""
	err = sendSMTPNotificationWithDial(context.Background(), config, "Docklight test body", func(context.Context, string, string) (net.Conn, error) { return client, nil })
	if err != nil {
		t.Fatal(err)
	}
	select {
	case body := <-serverDone:
		if !strings.Contains(body, "Subject: [Docklight] Notification") || !strings.Contains(body, "Docklight test body") || strings.Contains(body, "smtp-private-password") {
			t.Fatalf("unexpected SMTP message: %q", body)
		}
	case <-time.After(time.Second):
		t.Fatal("SMTP test server did not receive the complete message")
	}
}
