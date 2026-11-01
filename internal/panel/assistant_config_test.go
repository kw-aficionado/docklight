package panel

import (
	"database/sql"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"example.com/yggdrasil-panel/internal/security"
)

type assistantTestRoundTripper func(*http.Request) (*http.Response, error)

func (f assistantTestRoundTripper) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func assistantTestHTTPResponse(r *http.Request, status int, header http.Header, body string) (*http.Response, error) {
	if header == nil {
		header = make(http.Header)
	}
	return &http.Response{StatusCode: status, Header: header, Body: io.NopCloser(strings.NewReader(body)), Request: r}, nil
}

func assistantTestSessions(t *testing.T, a *App, d *sql.DB) (string, string) {
	t.Helper()
	_, err := d.Exec(`INSERT INTO users(id,username,password_hash,role) VALUES('assistant-admin','assistant-admin','unused-hash','admin'),('assistant-user','assistant-user','unused-hash','user')`)
	if err != nil {
		t.Fatal(err)
	}
	adminToken, err := a.issue(User{ID: "assistant-admin", Username: "assistant-admin", Role: "admin"})
	if err != nil {
		t.Fatal(err)
	}
	userToken, err := a.issue(User{ID: "assistant-user", Username: "assistant-user", Role: "user"})
	if err != nil {
		t.Fatal(err)
	}
	return adminToken, userToken
}

func TestAssistantConfigAdminOnlyEncryptedAndMasked(t *testing.T) {
	a, d, _ := testApp(t)
	adminToken, userToken := assistantTestSessions(t, a, d)
	h := a.Router()

	initial := testRequest(h, http.MethodGet, "/api/ai/config", "", userToken)
	if initial.Code != http.StatusForbidden {
		t.Fatalf("non-admin read Assistant config: %d %s", initial.Code, initial.Body.String())
	}
	deniedSave := testRequest(h, http.MethodPut, "/api/ai/config", `{"provider":"openai","model":"test","api_key":"secret"}`, userToken)
	if deniedSave.Code != http.StatusForbidden {
		t.Fatalf("non-admin updated Assistant config: %d %s", deniedSave.Code, deniedSave.Body.String())
	}
	deniedTest := testRequest(h, http.MethodPost, "/api/ai/config/test", `{}`, userToken)
	if deniedTest.Code != http.StatusForbidden {
		t.Fatalf("non-admin tested Assistant config: %d %s", deniedTest.Code, deniedTest.Body.String())
	}
	emptyConfig := testRequest(h, http.MethodGet, "/api/ai/config", "", adminToken)
	if emptyConfig.Code != http.StatusOK || !strings.Contains(emptyConfig.Body.String(), `"enabled":false`) || !strings.Contains(emptyConfig.Body.String(), `"api_key_configured":false`) {
		t.Fatalf("Assistant should start disabled and unconfigured: %d %s", emptyConfig.Code, emptyConfig.Body.String())
	}

	const secret = "provider-key-must-not-leak"
	saved := testRequest(h, http.MethodPut, "/api/ai/config", `{"provider":"openai","model":"test-model","base_url":"http://127.0.0.1:11434/v1","api_key":"`+secret+`"}`, adminToken)
	if saved.Code != http.StatusOK {
		t.Fatalf("save Assistant config: %d %s", saved.Code, saved.Body.String())
	}
	if !strings.Contains(saved.Body.String(), `"api_key_configured":true`) || !strings.Contains(saved.Body.String(), assistantKeyMask) || strings.Contains(saved.Body.String(), secret) || strings.Contains(saved.Body.String(), `"api_key":`) || !strings.Contains(saved.Body.String(), `"enabled":false`) {
		t.Fatalf("Assistant config response leaked a key or reported wrong state: %s", saved.Body.String())
	}
	loaded := testRequest(h, http.MethodGet, "/api/ai/config", "", adminToken)
	if loaded.Code != http.StatusOK || !strings.Contains(loaded.Body.String(), assistantKeyMask) || strings.Contains(loaded.Body.String(), secret) {
		t.Fatalf("Assistant config GET exposed its saved key: %d %s", loaded.Code, loaded.Body.String())
	}
	var encryptedKey string
	if err := d.QueryRow(`SELECT api_key_enc FROM assistant_config WHERE id=1`).Scan(&encryptedKey); err != nil {
		t.Fatal(err)
	}
	if encryptedKey == "" || strings.Contains(encryptedKey, secret) {
		t.Fatal("provider key was not encrypted at rest")
	}
	if got, err := security.Decrypt([]byte(a.cfg.Auth.SecretKey), encryptedKey); err != nil || got != secret {
		t.Fatalf("provider key did not decrypt: got %q err=%v", got, err)
	}

	preserved := testRequest(h, http.MethodPut, "/api/ai/config", `{"provider":"openai","model":"test-model","base_url":"http://127.0.0.1:11434/v1","api_key":"`+assistantKeyMask+`"}`, adminToken)
	if preserved.Code != http.StatusOK {
		t.Fatalf("save with the returned key mask: %d %s", preserved.Code, preserved.Body.String())
	}
	var preservedCiphertext string
	if err := d.QueryRow(`SELECT api_key_enc FROM assistant_config WHERE id=1`).Scan(&preservedCiphertext); err != nil || preservedCiphertext != encryptedKey {
		t.Fatalf("the returned key mask should keep existing ciphertext: equal=%v err=%v", preservedCiphertext == encryptedKey, err)
	}

	for _, endpoint := range []string{"http://provider.example/v1", "https://user:pass@example.com/v1", "https://example.com/v1?token=secret", "https://example.com/v1#fragment"} {
		body, _ := json.Marshal(map[string]string{"provider": "custom", "model": "test-model", "base_url": endpoint})
		invalid := testRequest(h, http.MethodPut, "/api/ai/config", string(body), adminToken)
		if invalid.Code != http.StatusBadRequest {
			t.Errorf("unsafe endpoint %q accepted: %d %s", endpoint, invalid.Code, invalid.Body.String())
		}
	}

	cleared := testRequest(h, http.MethodPut, "/api/ai/config", `{"provider":"openai","model":"test-model","base_url":"http://127.0.0.1:11434/v1","clear_api_key":true}`, adminToken)
	if cleared.Code != http.StatusOK || !strings.Contains(cleared.Body.String(), `"api_key_configured":false`) {
		t.Fatalf("clear provider key: %d %s", cleared.Code, cleared.Body.String())
	}
	if err := d.QueryRow(`SELECT api_key_enc FROM assistant_config WHERE id=1`).Scan(&encryptedKey); err != nil || encryptedKey != "" {
		t.Fatalf("provider key was not cleared: value=%q err=%v", encryptedKey, err)
	}
}

func TestAssistantConnectionUsesProviderRequestsAndIsNotAudited(t *testing.T) {
	tests := []struct {
		name, provider, basePath, baseSuffix, response string
		needsKey                                       bool
	}{
		{name: "Anthropic Messages", provider: "anthropic", basePath: "/v1/messages", response: `{"content":[{"type":"text","text":"connected"}]}`, needsKey: true},
		{name: "Anthropic proxy with version path", provider: "anthropic", basePath: "/v1/messages", baseSuffix: "/v1", response: `{"content":[{"type":"text","text":"connected"}]}`, needsKey: true},
		{name: "OpenAI compatible", provider: "openrouter", basePath: "/v1/chat/completions", baseSuffix: "/v1", response: `{"choices":[{"message":{"content":"connected"}}]}`, needsKey: true},
		{name: "Ollama without key", provider: "ollama", basePath: "/v1/chat/completions", baseSuffix: "/v1", response: `{"choices":[{"message":{"content":"connected"}}]}`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a, d, _ := testApp(t)
			adminToken, _ := assistantTestSessions(t, a, d)
			const secret = "connection-test-secret"
			providerURL, _ := url.Parse("http://127.0.0.1:11434")
			a.assistantHTTPClient = &http.Client{Transport: assistantTestRoundTripper(func(r *http.Request) (*http.Response, error) {
				if r.URL.Path != tt.basePath {
					t.Errorf("provider path=%q, want %q", r.URL.Path, tt.basePath)
				}
				if r.Method != http.MethodPost || r.Header.Get("Content-Type") != "application/json" {
					t.Errorf("unexpected provider request: method=%q content-type=%q", r.Method, r.Header.Get("Content-Type"))
				}
				if tt.provider == "anthropic" {
					if r.Header.Get("x-api-key") != secret || r.Header.Get("anthropic-version") != "2023-06-01" {
						t.Errorf("Anthropic auth/version headers are wrong: x-api-key=%q version=%q", r.Header.Get("x-api-key"), r.Header.Get("anthropic-version"))
					}
				} else if tt.needsKey && r.Header.Get("Authorization") != "Bearer "+secret {
					t.Errorf("OpenAI-compatible bearer header is wrong: %q", r.Header.Get("Authorization"))
				} else if !tt.needsKey && r.Header.Get("Authorization") != "" {
					t.Errorf("unexpected auth header for local provider: %q", r.Header.Get("Authorization"))
				}
				var body struct {
					Model    string `json:"model"`
					MaxToken int    `json:"max_tokens"`
					Messages []struct {
						Role    string `json:"role"`
						Content string `json:"content"`
					} `json:"messages"`
				}
				if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
					t.Errorf("decode provider request: %v", err)
				}
				if body.Model != "test-model" || body.MaxToken != 32 || len(body.Messages) != 1 || body.Messages[0].Role != "user" || body.Messages[0].Content != assistantConnectionPrompt {
					t.Errorf("unexpected connection test request body: %#v", body)
				}
				header := make(http.Header)
				header.Set("Content-Type", "application/json")
				return assistantTestHTTPResponse(r, http.StatusOK, header, tt.response)
			})}

			baseURL := providerURL.String()
			baseURL += tt.baseSuffix
			input := map[string]string{"provider": tt.provider, "model": "test-model", "base_url": baseURL}
			if tt.needsKey {
				input["api_key"] = secret
			}
			body, _ := json.Marshal(input)
			h := a.Router()
			saved := testRequest(h, http.MethodPut, "/api/ai/config", string(body), adminToken)
			if saved.Code != http.StatusOK {
				t.Fatalf("save provider config: %d %s", saved.Code, saved.Body.String())
			}
			var auditBefore int
			if err := d.QueryRow(`SELECT count(*) FROM audit_log`).Scan(&auditBefore); err != nil {
				t.Fatal(err)
			}
			result := testRequest(h, http.MethodPost, "/api/ai/config/test", `{}`, adminToken)
			if result.Code != http.StatusOK || result.Body.String() != "{\"ok\":true}\n" {
				t.Fatalf("test provider connection: %d %s", result.Code, result.Body.String())
			}
			var auditAfter int
			if err := d.QueryRow(`SELECT count(*) FROM audit_log`).Scan(&auditAfter); err != nil || auditAfter != auditBefore {
				t.Fatalf("connection test should not be audited: before=%d after=%d err=%v", auditBefore, auditAfter, err)
			}
			if strings.Contains(result.Body.String(), secret) || strings.Contains(result.Body.String(), "connected") {
				t.Fatalf("connection test exposed the key or provider response: %s", result.Body.String())
			}
		})
	}
}

func TestAssistantConnectionDoesNotFollowRedirectsOrReturnProviderBody(t *testing.T) {
	a, d, _ := testApp(t)
	adminToken, _ := assistantTestSessions(t, a, d)
	const secret = "provider-secret-not-in-errors"
	redirectHit := false
	providerURL, _ := url.Parse("http://127.0.0.1:11434")
	targetURL := "https://example.net/stolen?key=" + secret
	providerCalls := 0
	a.assistantHTTPClient = &http.Client{Transport: assistantTestRoundTripper(func(r *http.Request) (*http.Response, error) {
		providerCalls++
		if providerCalls > 1 {
			redirectHit = true
		}
		header := make(http.Header)
		header.Set("Location", targetURL)
		return assistantTestHTTPResponse(r, http.StatusFound, header, "provider error includes "+secret)
	}), CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }}
	body, _ := json.Marshal(map[string]string{"provider": "openai", "model": "test-model", "base_url": providerURL.String() + "/v1", "api_key": secret})
	h := a.Router()
	if saved := testRequest(h, http.MethodPut, "/api/ai/config", string(body), adminToken); saved.Code != http.StatusOK {
		t.Fatalf("save provider config: %d %s", saved.Code, saved.Body.String())
	}
	response := testRequest(h, http.MethodPost, "/api/ai/config/test", `{}`, adminToken)
	if response.Code != http.StatusBadGateway || !strings.Contains(response.Body.String(), "HTTP 302") || strings.Contains(response.Body.String(), secret) || strings.Contains(response.Body.String(), "provider error") {
		t.Fatalf("unexpected redirect/error response: %d %s", response.Code, response.Body.String())
	}
	if redirectHit || providerCalls != 1 {
		t.Fatal("assistant provider test followed a redirect")
	}
}

func TestAssistantConnectionBoundsTimeoutAndResponseSize(t *testing.T) {
	t.Run("timeout", func(t *testing.T) {
		a, d, _ := testApp(t)
		adminToken, _ := assistantTestSessions(t, a, d)
		const secret = "timeout-secret-must-not-leak"
		a.assistantHTTPClient = &http.Client{Timeout: 5 * time.Millisecond, Transport: assistantTestRoundTripper(func(r *http.Request) (*http.Response, error) {
			<-r.Context().Done()
			return nil, r.Context().Err()
		})}
		body, _ := json.Marshal(map[string]string{"provider": "openai", "model": "test-model", "base_url": "https://provider.example/v1", "api_key": secret})
		h := a.Router()
		if saved := testRequest(h, http.MethodPut, "/api/ai/config", string(body), adminToken); saved.Code != http.StatusOK {
			t.Fatalf("save provider config: %d %s", saved.Code, saved.Body.String())
		}
		response := testRequest(h, http.MethodPost, "/api/ai/config/test", `{}`, adminToken)
		if response.Code != http.StatusBadGateway || strings.Contains(response.Body.String(), secret) || !strings.Contains(response.Body.String(), "could not reach") {
			t.Fatalf("timeout error exposed provider data: %d %s", response.Code, response.Body.String())
		}
	})

	t.Run("oversized response", func(t *testing.T) {
		a, d, _ := testApp(t)
		adminToken, _ := assistantTestSessions(t, a, d)
		const secret = "large-response-secret"
		a.assistantHTTPClient = &http.Client{Transport: assistantTestRoundTripper(func(r *http.Request) (*http.Response, error) {
			return assistantTestHTTPResponse(r, http.StatusOK, nil, strings.Repeat("x", assistantMaxResponseBytes+1))
		})}
		body, _ := json.Marshal(map[string]string{"provider": "openai", "model": "test-model", "base_url": "https://provider.example/v1", "api_key": secret})
		h := a.Router()
		if saved := testRequest(h, http.MethodPut, "/api/ai/config", string(body), adminToken); saved.Code != http.StatusOK {
			t.Fatalf("save provider config: %d %s", saved.Code, saved.Body.String())
		}
		response := testRequest(h, http.MethodPost, "/api/ai/config/test", `{}`, adminToken)
		if response.Code != http.StatusBadGateway || strings.Contains(response.Body.String(), secret) || strings.Contains(response.Body.String(), strings.Repeat("x", 32)) {
			t.Fatalf("oversized provider response escaped: %d %s", response.Code, response.Body.String())
		}
	})
}
