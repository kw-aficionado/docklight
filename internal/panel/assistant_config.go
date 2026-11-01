package panel

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
	"unicode/utf8"

	"example.com/yggdrasil-panel/internal/security"
)

const (
	assistantKeyMask          = "••••••••"
	assistantMaxResponseBytes = 1 << 20
	assistantConnectionPrompt = "Reply with the word connected."
)

type assistantConfig struct {
	Enabled           bool     `json:"enabled"`
	DigestEnabled     bool     `json:"digest_enabled"`
	DigestHour        int      `json:"digest_hour"`
	DigestLastDay     string   `json:"digest_last_day"`
	ActionsEnabled    bool     `json:"actions_enabled"`
	ChatDataLevel     int      `json:"chat_data_level"`
	ProactiveLevel    int      `json:"proactive_level"`
	ProactiveTriggers []string `json:"proactive_triggers"`
	Provider          string   `json:"provider"`
	Model             string   `json:"model"`
	BaseURL           string   `json:"base_url"`
	APIKeyConfigured  bool     `json:"api_key_configured"`
	APIKeyMasked      string   `json:"api_key_masked"`
}

type assistantConfigInput struct {
	Provider    string `json:"provider"`
	Model       string `json:"model"`
	BaseURL     string `json:"base_url"`
	APIKey      string `json:"api_key"`
	ClearAPIKey bool   `json:"clear_api_key"`
}

func assistantDefaultBaseURL(provider string) string {
	switch provider {
	case "anthropic":
		return "https://api.anthropic.com"
	case "openai":
		return "https://api.openai.com/v1"
	case "openrouter":
		return "https://openrouter.ai/api/v1"
	case "deepseek":
		return "https://api.deepseek.com/v1"
	case "mistral":
		return "https://api.mistral.ai/v1"
	case "ollama":
		return "http://127.0.0.1:11434/v1"
	default:
		return ""
	}
}

func validAssistantProvider(provider string) bool {
	switch provider {
	case "anthropic", "openai", "openrouter", "deepseek", "mistral", "ollama", "custom":
		return true
	default:
		return false
	}
}

func validateAssistantModel(model string) (string, error) {
	model = strings.TrimSpace(model)
	if model == "" || utf8.RuneCountInString(model) > 128 {
		return "", errors.New("enter a model name up to 128 characters")
	}
	for _, char := range model {
		if char < 0x20 || char == 0x7f {
			return "", errors.New("model name contains an invalid character")
		}
	}
	return model, nil
}

func validateAssistantBaseURL(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" || len(raw) > 512 {
		return "", errors.New("enter a provider URL up to 512 characters")
	}
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.Opaque != "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return "", errors.New("provider URL must be an HTTP or HTTPS URL without credentials, query, or fragment")
	}
	if u.Port() != "" {
		// url.Parse rejects malformed ports; this guard keeps invalid numeric ports out too.
		port, portErr := net.LookupPort("tcp", u.Port())
		if portErr != nil || port < 1 || port > 65535 {
			return "", errors.New("provider URL has an invalid port")
		}
	}
	if u.Scheme == "http" && !assistantPrivateHTTPHost(u.Hostname()) {
		return "", errors.New("plain HTTP is allowed only for loopback or private-network providers")
	}
	u.Path = strings.TrimRight(u.Path, "/")
	u.RawPath = ""
	return strings.TrimRight(u.String(), "/"), nil
}

func assistantPrivateHTTPHost(host string) bool {
	host = strings.ToLower(strings.TrimSuffix(strings.Trim(host, "[]"), "."))
	if ip := net.ParseIP(host); ip != nil {
		return ip.IsLoopback() || ip.IsPrivate()
	}
	if host == "localhost" || strings.HasSuffix(host, ".localhost") || strings.HasSuffix(host, ".local") || strings.HasSuffix(host, ".lan") || strings.HasSuffix(host, ".home") || strings.HasSuffix(host, ".internal") {
		return host != "metadata.google.internal"
	}
	// Single-label names are commonly used by local containers, such as
	// http://ollama:11434. Public service names should use HTTPS.
	return !strings.Contains(host, ".") && host != ""
}

func (a *App) getAssistantConfig(w http.ResponseWriter, r *http.Request) {
	var enabled, digestEnabled, digestHour, actionsEnabled, chatDataLevel, proactiveLevel int
	var provider, model, baseURL, encryptedKey, digestLastDay, proactiveTriggers string
	err := a.db.QueryRow(`SELECT enabled,digest_enabled,digest_hour,digest_last_day,actions_enabled,chat_data_level,proactive_level,proactive_triggers,provider,model,base_url,api_key_enc FROM assistant_config WHERE id=1`).Scan(&enabled, &digestEnabled, &digestHour, &digestLastDay, &actionsEnabled, &chatDataLevel, &proactiveLevel, &proactiveTriggers, &provider, &model, &baseURL, &encryptedKey)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not read Assistant settings")
		return
	}
	writeJSON(w, http.StatusOK, assistantConfig{
		Enabled:           enabled != 0,
		DigestEnabled:     digestEnabled != 0,
		DigestHour:        digestHour,
		DigestLastDay:     digestLastDay,
		ActionsEnabled:    actionsEnabled != 0,
		ChatDataLevel:     chatDataLevel,
		ProactiveLevel:    proactiveLevel,
		ProactiveTriggers: assistantProactiveTriggerList(proactiveTriggers),
		Provider:          provider,
		Model:             model,
		BaseURL:           baseURL,
		APIKeyConfigured:  encryptedKey != "",
		APIKeyMasked:      assistantMaskKey(encryptedKey),
	})
}

type assistantChatScopeInput struct {
	DataLevel *int `json:"data_level"`
}

func (a *App) updateAssistantChatScope(w http.ResponseWriter, r *http.Request) {
	var input assistantChatScopeInput
	if decodeJSON(w, r, &input, 1024) != nil {
		return
	}
	if input.DataLevel == nil || *input.DataLevel < 0 || *input.DataLevel > 2 {
		writeError(w, http.StatusBadRequest, "data_level must be 0, 1, or 2")
		return
	}
	if _, err := a.db.Exec(`UPDATE assistant_config SET chat_data_level=?,updated_at=CURRENT_TIMESTAMP WHERE id=1`, *input.DataLevel); err != nil {
		writeError(w, http.StatusInternalServerError, "could not save Advisory data scope")
		return
	}
	a.audit(principal(r), "ai.config", "assistant", "1", fmt.Sprintf("chat_data_level=%d", *input.DataLevel))
	writeJSON(w, http.StatusOK, map[string]int{"chat_data_level": *input.DataLevel})
}

type assistantDigestSettingsInput struct {
	Enabled *bool `json:"enabled"`
	Hour    *int  `json:"hour"`
}

func (a *App) updateAssistantDigestSettings(w http.ResponseWriter, r *http.Request) {
	var input assistantDigestSettingsInput
	if decodeJSON(w, r, &input, 1024) != nil {
		return
	}
	if input.Enabled == nil || input.Hour == nil || *input.Hour < 0 || *input.Hour > 23 {
		writeError(w, http.StatusBadRequest, "daily digest requires an enabled flag and an hour from 0 to 23")
		return
	}
	if *input.Enabled {
		var enabled int
		if err := a.db.QueryRow(`SELECT enabled FROM assistant_config WHERE id=1`).Scan(&enabled); err != nil {
			writeError(w, http.StatusInternalServerError, "could not read Advisory settings")
			return
		}
		if enabled == 0 {
			writeError(w, http.StatusConflict, "enable Advisory before scheduling a daily digest")
			return
		}
	}
	if _, err := a.db.Exec(`UPDATE assistant_config SET digest_enabled=?,digest_hour=?,updated_at=CURRENT_TIMESTAMP WHERE id=1`, boolInt(*input.Enabled), *input.Hour); err != nil {
		writeError(w, http.StatusInternalServerError, "could not save daily digest settings")
		return
	}
	state := "disabled"
	if *input.Enabled {
		state = fmt.Sprintf("enabled at %02d:00", *input.Hour)
	}
	a.audit(principal(r), "ai.config", "assistant", "1", "daily_digest="+state)
	writeJSON(w, http.StatusOK, map[string]any{"digest_enabled": *input.Enabled, "digest_hour": *input.Hour})
}

func assistantMaskKey(encryptedKey string) string {
	if encryptedKey == "" {
		return ""
	}
	return assistantKeyMask
}

func (a *App) updateAssistantConfig(w http.ResponseWriter, r *http.Request) {
	var input assistantConfigInput
	if err := decodeJSON(w, r, &input, 16*1024); err != nil {
		return
	}
	input.Provider = strings.TrimSpace(input.Provider)
	if !validAssistantProvider(input.Provider) {
		writeError(w, http.StatusBadRequest, "choose a supported provider")
		return
	}
	model, err := validateAssistantModel(input.Model)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	baseURL := strings.TrimSpace(input.BaseURL)
	if baseURL == "" {
		baseURL = assistantDefaultBaseURL(input.Provider)
	}
	if baseURL == "" {
		writeError(w, http.StatusBadRequest, "a provider URL is required for the custom provider")
		return
	}
	baseURL, err = validateAssistantBaseURL(baseURL)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if len(input.APIKey) > 4096 || strings.ContainsAny(input.APIKey, "\r\n") {
		writeError(w, http.StatusBadRequest, "API key is invalid or too long")
		return
	}
	input.APIKey = strings.TrimSpace(input.APIKey)
	var encryptedKey string
	if err = a.db.QueryRow(`SELECT api_key_enc FROM assistant_config WHERE id=1`).Scan(&encryptedKey); err != nil {
		writeError(w, http.StatusInternalServerError, "could not read Assistant settings")
		return
	}
	if input.ClearAPIKey {
		encryptedKey = ""
	} else if input.APIKey != "" && input.APIKey != assistantKeyMask {
		encryptedKey, err = security.Encrypt([]byte(a.cfg.Auth.SecretKey), input.APIKey)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "could not encrypt provider key")
			return
		}
	}
	_, err = a.db.Exec(`UPDATE assistant_config SET provider=?,model=?,base_url=?,api_key_enc=?,updated_at=CURRENT_TIMESTAMP WHERE id=1`, input.Provider, model, baseURL, encryptedKey)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not save Assistant settings")
		return
	}
	a.audit(principal(r), "ai.config", "assistant", "1", input.Provider)
	var enabled int
	if err = a.db.QueryRow(`SELECT enabled FROM assistant_config WHERE id=1`).Scan(&enabled); err != nil {
		writeError(w, http.StatusInternalServerError, "settings were saved, but their status could not be read")
		return
	}
	writeJSON(w, http.StatusOK, assistantConfig{
		Enabled:          enabled != 0,
		Provider:         input.Provider,
		Model:            model,
		BaseURL:          baseURL,
		APIKeyConfigured: encryptedKey != "",
		APIKeyMasked:     assistantMaskKey(encryptedKey),
	})
}

func (a *App) testAssistantConnection(w http.ResponseWriter, r *http.Request) {
	var provider, model, baseURL, encryptedKey string
	if err := a.db.QueryRow(`SELECT provider,model,base_url,api_key_enc FROM assistant_config WHERE id=1`).Scan(&provider, &model, &baseURL, &encryptedKey); err != nil {
		writeError(w, http.StatusInternalServerError, "could not read Assistant settings")
		return
	}
	if !validAssistantProvider(provider) || model == "" || baseURL == "" {
		writeError(w, http.StatusBadRequest, "save a provider, model, and URL before testing")
		return
	}
	apiKey := ""
	if encryptedKey != "" {
		var err error
		apiKey, err = security.Decrypt([]byte(a.cfg.Auth.SecretKey), encryptedKey)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "could not read the saved provider key")
			return
		}
	}
	if apiKey == "" && provider != "ollama" && provider != "custom" {
		writeError(w, http.StatusBadRequest, "save an API key before testing this provider")
		return
	}
	if err := a.requestAssistantConnection(r, provider, model, baseURL, apiKey); err != nil {
		message := "could not reach the configured provider or read its response"
		var statusErr assistantProviderStatusError
		if errors.As(err, &statusErr) {
			message = fmt.Sprintf("provider returned HTTP %d", statusErr.status)
		}
		writeError(w, http.StatusBadGateway, message)
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

type assistantProviderStatusError struct{ status int }

func (e assistantProviderStatusError) Error() string {
	return fmt.Sprintf("provider returned HTTP %d", e.status)
}

func (a *App) requestAssistantConnection(r *http.Request, provider, model, baseURL, apiKey string) error {
	path := "/chat/completions"
	if provider == "anthropic" {
		path = "/v1/messages"
		if strings.HasSuffix(strings.TrimRight(baseURL, "/"), "/v1") {
			path = "/messages"
		}
	}
	endpoint := strings.TrimRight(baseURL, "/") + path
	requestBody := map[string]any{
		"model": model, "max_tokens": 32,
		"messages": []map[string]string{{"role": "user", "content": assistantConnectionPrompt}},
	}
	encoded, err := json.Marshal(requestBody)
	if err != nil {
		return err
	}
	request, err := http.NewRequestWithContext(r.Context(), http.MethodPost, endpoint, bytes.NewReader(encoded))
	if err != nil {
		return err
	}
	request.Header.Set("Content-Type", "application/json")
	if provider == "anthropic" {
		request.Header.Set("x-api-key", apiKey)
		request.Header.Set("anthropic-version", "2023-06-01")
	} else if apiKey != "" {
		request.Header.Set("Authorization", "Bearer "+apiKey)
	}
	client := a.assistantHTTPClient
	if client == nil {
		client = &http.Client{
			Timeout: 12 * time.Second,
			CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
				return http.ErrUseLastResponse
			},
		}
	}
	response, err := client.Do(request)
	if err != nil {
		return errors.New("provider request failed")
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return assistantProviderStatusError{status: response.StatusCode}
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, assistantMaxResponseBytes+1))
	if err != nil || len(body) > assistantMaxResponseBytes {
		return errors.New("provider response was unreadable or too large")
	}
	if provider == "anthropic" {
		var result struct {
			Content []struct {
				Type string `json:"type"`
				Text string `json:"text"`
			} `json:"content"`
		}
		if err = json.Unmarshal(body, &result); err != nil {
			return errors.New("provider response was invalid")
		}
		for _, item := range result.Content {
			if item.Type == "text" && strings.TrimSpace(item.Text) != "" {
				return nil
			}
		}
		return errors.New("provider response contained no text")
	}
	var result struct {
		Choices []struct {
			Message struct {
				Content string `json:"content"`
			} `json:"message"`
		} `json:"choices"`
	}
	if err = json.Unmarshal(body, &result); err != nil || len(result.Choices) == 0 || strings.TrimSpace(result.Choices[0].Message.Content) == "" {
		return errors.New("provider response was invalid or empty")
	}
	return nil
}
