package panel

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"example.com/yggdrasil-panel/internal/security"
)

type notificationRoundTripper func(*http.Request) (*http.Response, error)

func (f notificationRoundTripper) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestNotificationSettingsAreAdminOnlyEncryptedAndSigned(t *testing.T) {
	a, d, _ := testApp(t)
	if _, err := d.Exec(`INSERT INTO users(id,username,password_hash,role) VALUES('notify-admin','notify-admin','unused-hash','admin'),('notify-user','notify-user','unused-hash','user')`); err != nil {
		t.Fatal(err)
	}
	adminToken, err := a.issue(User{ID: "notify-admin", Username: "notify-admin", Role: "admin"})
	if err != nil {
		t.Fatal(err)
	}
	userToken, err := a.issue(User{ID: "notify-user", Username: "notify-user", Role: "user"})
	if err != nil {
		t.Fatal(err)
	}
	h := a.Router()
	denied := testRequest(h, http.MethodGet, "/api/notifications", "", userToken)
	if denied.Code != http.StatusForbidden {
		t.Fatalf("non-admin read notification settings: %d %s", denied.Code, denied.Body.String())
	}
	invalidHTTP := testRequest(h, http.MethodPut, "/api/notifications", `{"enabled":true,"endpoint":"http://example.com/hook","events":["backup.failure"]}`, adminToken)
	if invalidHTTP.Code != http.StatusBadRequest {
		t.Fatalf("remote HTTP endpoint accepted: %d %s", invalidHTTP.Code, invalidHTTP.Body.String())
	}
	invalidEvent := testRequest(h, http.MethodPut, "/api/notifications", `{"enabled":true,"endpoint":"https://hooks.example.com/docklight","events":["host.disk_recovered"]}`, adminToken)
	if invalidEvent.Code != http.StatusBadRequest {
		t.Fatalf("unsupported notification event accepted: %d %s", invalidEvent.Code, invalidEvent.Body.String())
	}
	endpoint := "http://127.0.0.1:18765/hook?private=url-token"
	secret := "signing-secret-do-not-store-plaintext"
	updated := testRequest(h, http.MethodPut, "/api/notifications", `{"enabled":true,"endpoint":"`+endpoint+`","signing_secret":"`+secret+`","events":["backup.success","backup.failure","host.disk_low"]}`, adminToken)
	if updated.Code != http.StatusOK || !strings.Contains(updated.Body.String(), `"endpoint_configured":true`) || !strings.Contains(updated.Body.String(), `"signing_secret_configured":true`) || !strings.Contains(updated.Body.String(), `"host.disk_low"`) {
		t.Fatalf("save notification settings: %d %s", updated.Code, updated.Body.String())
	}
	if strings.Contains(updated.Body.String(), secret) || strings.Contains(updated.Body.String(), "private=url-token") || strings.Contains(updated.Body.String(), `"endpoint"`) {
		t.Fatalf("notification response exposed endpoint or signing secret: %s", updated.Body.String())
	}
	var endpointCiphertext, secretCiphertext string
	if err = d.QueryRow(`SELECT endpoint_enc,signing_secret_enc FROM notification_settings WHERE id=1`).Scan(&endpointCiphertext, &secretCiphertext); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(endpointCiphertext, endpoint) || strings.Contains(secretCiphertext, secret) {
		t.Fatal("notification credentials were stored in plaintext")
	}
	if got, decryptErr := security.Decrypt([]byte(a.cfg.Auth.SecretKey), endpointCiphertext); decryptErr != nil || got != endpoint {
		t.Fatalf("encrypted endpoint did not round trip: value=%q err=%v", got, decryptErr)
	}
	if got, decryptErr := security.Decrypt([]byte(a.cfg.Auth.SecretKey), secretCiphertext); decryptErr != nil || got != secret {
		t.Fatalf("encrypted signing secret did not round trip: value=%q err=%v", got, decryptErr)
	}

	requests := make(chan webhookPayload, 2)
	a.notificationClient = &http.Client{Transport: notificationRoundTripper(func(r *http.Request) (*http.Response, error) {
		if r.URL.String() != endpoint {
			t.Errorf("webhook endpoint=%q, want configured endpoint", r.URL.String())
		}
		body, readErr := io.ReadAll(r.Body)
		if readErr != nil {
			t.Errorf("read webhook body: %v", readErr)
		}
		mac := hmac.New(sha256.New, []byte(secret))
		_, _ = mac.Write(body)
		wantSignature := "sha256=" + hex.EncodeToString(mac.Sum(nil))
		if got := r.Header.Get("X-Docklight-Signature"); got != wantSignature {
			t.Errorf("signature=%q, want %q", got, wantSignature)
		}
		var payload webhookPayload
		if err := json.Unmarshal(body, &payload); err != nil {
			t.Errorf("decode webhook body: %v", err)
		}
		requests <- payload
		return &http.Response{StatusCode: http.StatusNoContent, Header: make(http.Header), Body: io.NopCloser(strings.NewReader("")), Request: r}, nil
	})}
	testSent := testRequest(h, http.MethodPost, "/api/notifications/test", `{}`, adminToken)
	if testSent.Code != http.StatusOK {
		t.Fatalf("send webhook test: %d %s", testSent.Code, testSent.Body.String())
	}
	select {
	case payload := <-requests:
		if payload.Event != "notification.test" || payload.Product != "Docklight" || payload.Occurred == "" {
			t.Fatalf("unexpected test notification: %#v", payload)
		}
	case <-time.After(time.Second):
		t.Fatal("test webhook was not delivered")
	}
	a.dispatchBackupNotification(notificationBackupSuccess, "srv-1", "Factorio", "A scheduled backup completed.")
	select {
	case payload := <-requests:
		if payload.Event != notificationBackupSuccess || payload.Server == nil || payload.Server.ID != "srv-1" || payload.Server.Name != "Factorio" {
			t.Fatalf("unexpected backup notification: %#v", payload)
		}
	case <-time.After(time.Second):
		t.Fatal("enabled backup event was not delivered")
	}

	updatedForUser := testRequest(h, http.MethodPut, "/api/notifications", `{"enabled":false}`, userToken)
	if updatedForUser.Code != http.StatusForbidden {
		t.Fatalf("non-admin updated notification settings: %d %s", updatedForUser.Code, updatedForUser.Body.String())
	}
}

func TestNotificationSettingsCannotEnableWithoutEndpointOrEvents(t *testing.T) {
	a, d, _ := testApp(t)
	if _, err := d.Exec(`INSERT INTO users(id,username,password_hash,role) VALUES('notify-admin','notify-admin','unused-hash','admin')`); err != nil {
		t.Fatal(err)
	}
	token, err := a.issue(User{ID: "notify-admin", Username: "notify-admin", Role: "admin"})
	if err != nil {
		t.Fatal(err)
	}
	h := a.Router()
	noEndpoint := testRequest(h, http.MethodPut, "/api/notifications", `{"enabled":true,"events":["backup.failure"]}`, token)
	if noEndpoint.Code != http.StatusBadRequest {
		t.Fatalf("enabled notifications accepted without endpoint: %d %s", noEndpoint.Code, noEndpoint.Body.String())
	}
	noEvents := testRequest(h, http.MethodPut, "/api/notifications", `{"enabled":true,"endpoint":"https://hooks.example.com/docklight","events":[]}`, token)
	if noEvents.Code != http.StatusBadRequest {
		t.Fatalf("enabled notifications accepted without events: %d %s", noEvents.Code, noEvents.Body.String())
	}
	var rows int
	if err = d.QueryRow(`SELECT count(*) FROM notification_settings`).Scan(&rows); err != nil || rows != 0 {
		t.Fatalf("invalid update changed settings rows: rows=%d err=%v", rows, err)
	}
}

func TestWebhookDeliveryDoesNotFollowRedirectsOrLeakURL(t *testing.T) {
	a, _, _ := testApp(t)
	endpoint := "http://localhost/secret-path?token=hidden"
	encrypted, err := security.Encrypt([]byte(a.cfg.Auth.SecretKey), endpoint)
	if err != nil {
		t.Fatal(err)
	}
	a.notificationClient = &http.Client{Transport: notificationRoundTripper(func(r *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusTemporaryRedirect, Header: http.Header{"Location": []string{"https://other.example/"}}, Body: io.NopCloser(strings.NewReader("")), Request: r}, nil
	})}
	err = a.deliverWebhook(context.Background(), storedNotificationSettings{Endpoint: encrypted}, webhookPayload{Product: "Docklight", Event: "notification.test"})
	if err == nil || !strings.Contains(err.Error(), "HTTP 307") || strings.Contains(err.Error(), "hidden") || strings.Contains(err.Error(), "secret-path") {
		t.Fatalf("redirect handling error=%v", err)
	}
}
