package panel

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestAssistantAdvisoryNeedsAdministratorConfigurationAndExplicitEnable(t *testing.T) {
	a, d, _ := testApp(t)
	adminToken, userToken := assistantTestSessions(t, a, d)
	h := a.Router()

	if result := testRequest(h, http.MethodPost, "/api/ai/health-digest", `{}`, userToken); result.Code != http.StatusForbidden {
		t.Fatalf("non-admin generated a health digest: %d %s", result.Code, result.Body.String())
	}
	if result := testRequest(h, http.MethodPut, "/api/ai/enabled", `{"enabled":true}`, userToken); result.Code != http.StatusForbidden {
		t.Fatalf("non-admin enabled Advisory: %d %s", result.Code, result.Body.String())
	}
	if result := testRequest(h, http.MethodPost, "/api/ai/health-digest", `{}`, adminToken); result.Code != http.StatusConflict {
		t.Fatalf("disabled Advisory generated a digest: %d %s", result.Code, result.Body.String())
	}
	if result := testRequest(h, http.MethodPut, "/api/ai/enabled", `{"enabled":true}`, adminToken); result.Code != http.StatusConflict {
		t.Fatalf("unconfigured Assistant was enabled: %d %s", result.Code, result.Body.String())
	}
	if result := testRequest(h, http.MethodPut, "/api/ai/config", `{"provider":"openai","model":"model","base_url":"https://api.openai.com/v1"}`, adminToken); result.Code != http.StatusOK {
		t.Fatalf("save hosted provider without key for setup: %d %s", result.Code, result.Body.String())
	}
	if result := testRequest(h, http.MethodPut, "/api/ai/enabled", `{"enabled":true}`, adminToken); result.Code != http.StatusConflict {
		t.Fatalf("hosted provider without a key was enabled: %d %s", result.Code, result.Body.String())
	}
	if result := testRequest(h, http.MethodPut, "/api/ai/config", `{"provider":"ollama","model":"local-model"}`, adminToken); result.Code != http.StatusOK {
		t.Fatalf("save local Ollama provider: %d %s", result.Code, result.Body.String())
	}
	if result := testRequest(h, http.MethodPut, "/api/ai/enabled", `{"enabled":true}`, adminToken); result.Code != http.StatusOK || !strings.Contains(result.Body.String(), `"enabled":true`) {
		t.Fatalf("enable configured Advisory: %d %s", result.Code, result.Body.String())
	}
	if result := testRequest(h, http.MethodPut, "/api/ai/enabled", `{}`, adminToken); result.Code != http.StatusBadRequest {
		t.Fatalf("missing enabled flag accepted: %d %s", result.Code, result.Body.String())
	}
	if result := testRequest(h, http.MethodPut, "/api/ai/enabled", `{"enabled":false}`, adminToken); result.Code != http.StatusOK {
		t.Fatalf("disable Advisory: %d %s", result.Code, result.Body.String())
	}
	var enabled int
	if err := d.QueryRow(`SELECT enabled FROM assistant_config WHERE id=1`).Scan(&enabled); err != nil || enabled != 0 {
		t.Fatalf("Advisory disable did not persist: enabled=%d err=%v", enabled, err)
	}
}

func TestAssistantHealthDigestSendsOnlyBoundedOperationalSnapshot(t *testing.T) {
	a, d, _ := testApp(t)
	adminToken, _ := assistantTestSessions(t, a, d)
	if result := testRequest(a.Router(), http.MethodPut, "/api/ai/config", `{"provider":"ollama","model":"local-model"}`, adminToken); result.Code != http.StatusOK {
		t.Fatalf("save local provider: %d %s", result.Code, result.Body.String())
	}
	if result := testRequest(a.Router(), http.MethodPut, "/api/ai/enabled", `{"enabled":true}`, adminToken); result.Code != http.StatusOK {
		t.Fatalf("enable Advisory: %d %s", result.Code, result.Body.String())
	}
	dataDir := t.TempDir()
	if _, err := d.Exec(`INSERT INTO servers(id,name,gameskill_id,status,installed,env_json,ports_json,data_dir,container_id) VALUES('digest-running','Arena 01','minecraft-java','running',1,'{"API_SECRET":"do-not-send-this"}','{}',?,'container-digest'),('digest-stopped','Stopped App','uptime-kuma','stopped',1,'{}','{}',?,'')`, dataDir, dataDir); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	if _, err := d.Exec(`INSERT INTO server_metrics(server_id,sampled_at,cpu_percent,memory_mb,players) VALUES('digest-running',?,25,512,3)`, now.Add(-time.Hour).Unix()); err != nil {
		t.Fatal(err)
	}
	if _, err := d.Exec(`INSERT INTO host_metrics(sampled_at,cpu_percent,memory_used_mb,memory_total_mb,disk_used_mb,disk_total_mb) VALUES(?,18,1024,8192,5000,20000)`, now.Add(-5*time.Minute).Unix()); err != nil {
		t.Fatal(err)
	}
	if _, err := d.Exec(`INSERT INTO backup_schedules(id,server_id,name,action,cron) VALUES('digest-backup-schedule','digest-running','Nightly backup','backup','0 3 * * *'),('digest-restart-schedule','digest-running','Restart schedule','restart','0 4 * * *')`); err != nil {
		t.Fatal(err)
	}
	failureAt := scheduleTimestamp(now.Add(-2 * time.Hour))
	if _, err := d.Exec(`INSERT INTO backup_schedule_runs(id,schedule_id,server_id,started_at,finished_at,status,detail) VALUES('digest-failed-backup','digest-backup-schedule','digest-running',?,?,'error','provider secret must not be forwarded'),('digest-failed-restart','digest-restart-schedule','digest-running',?,?,'error','raw error details stay local')`, failureAt, failureAt, failureAt, failureAt); err != nil {
		t.Fatal(err)
	}
	var sentPrompt string
	a.assistantHTTPClient = &http.Client{Transport: assistantTestRoundTripper(func(r *http.Request) (*http.Response, error) {
		if r.URL.Path != "/v1/chat/completions" || r.Method != http.MethodPost {
			t.Errorf("unexpected Advisory provider target: %s %s", r.Method, r.URL)
		}
		if r.Header.Get("Authorization") != "" {
			t.Errorf("local provider received an unexpected authorization header")
		}
		var body struct {
			Model     string `json:"model"`
			MaxTokens int    `json:"max_tokens"`
			Messages  []struct {
				Role    string `json:"role"`
				Content string `json:"content"`
			} `json:"messages"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Errorf("decode Advisory request: %v", err)
		}
		if body.Model != "local-model" || body.MaxTokens != 600 || len(body.Messages) != 2 || body.Messages[0].Role != "system" || body.Messages[1].Role != "user" {
			t.Errorf("unexpected health digest request envelope: %#v", body)
		}
		sentPrompt = body.Messages[1].Content
		if len(sentPrompt) > assistantMaxPromptBytes {
			t.Errorf("health snapshot prompt was too large: %d", len(sentPrompt))
		}
		return assistantTestHTTPResponse(r, http.StatusOK, http.Header{"Content-Type": []string{"application/json"}}, `{"choices":[{"message":{"content":"State\nTwo servers; one scheduled failure."}}]}`)
	})}
	response := testRequest(a.Router(), http.MethodPost, "/api/ai/health-digest", `{}`, adminToken)
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), "Two servers") {
		t.Fatalf("generate health digest: %d %s", response.Code, response.Body.String())
	}
	for _, expected := range []string{`"name":"Arena 01"`, `"status":"running"`, `"name":"Stopped App"`, `"failed_backup_runs_24h":1`, `"schedule_failures_24h":2`, `"disk_total_mb":20000`, `"average_cpu_percent":25`} {
		if !strings.Contains(sentPrompt, expected) {
			t.Errorf("provider snapshot does not include %s: %s", expected, sentPrompt)
		}
	}
	for _, secret := range []string{"do-not-send-this", "provider secret must not be forwarded", "raw error details stay local", "rcon.password_var"} {
		if strings.Contains(sentPrompt, secret) {
			t.Errorf("provider snapshot contains disallowed data %q", secret)
		}
	}
	var auditCount int
	if err := d.QueryRow(`SELECT COUNT(*) FROM audit_log WHERE action='ai.health_digest'`).Scan(&auditCount); err != nil || auditCount != 1 {
		t.Fatalf("successful digest was not audited once: count=%d err=%v", auditCount, err)
	}
	var storedAudit string
	if err := d.QueryRow(`SELECT detail FROM audit_log WHERE action='ai.health_digest'`).Scan(&storedAudit); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(storedAudit, "Two servers") || strings.Contains(storedAudit, "do-not-send-this") || strings.Contains(storedAudit, sentPrompt) {
		t.Fatalf("audit retained prompt, response, or secret: %s", storedAudit)
	}
}

func TestAssistantHealthSnapshotEmptyHostAndNoServers(t *testing.T) {
	a, _, _ := testApp(t)
	snapshot, err := a.assistantHealthData()
	if err != nil {
		t.Fatalf("empty panel snapshot: %v", err)
	}
	if snapshot.TotalServerCount != 0 || snapshot.RunningCount != 0 || snapshot.DownCount != 0 || snapshot.Host.CPUPercent != -1 || snapshot.Host.DiskTotalMB != -1 {
		t.Fatalf("empty panel snapshot did not preserve unknowns: %#v", snapshot)
	}
}

func TestAssistantCompletionUsesContextDeadline(t *testing.T) {
	a, _, _ := testApp(t)
	a.assistantHTTPClient = &http.Client{Transport: assistantTestRoundTripper(func(r *http.Request) (*http.Response, error) {
		deadline, ok := r.Context().Deadline()
		if !ok || time.Until(deadline) > assistantCompletionTimeout || time.Until(deadline) < assistantCompletionTimeout-time.Second {
			t.Errorf("Assistant completion request has no bounded deadline: %v %v", deadline, ok)
		}
		return assistantTestHTTPResponse(r, http.StatusOK, nil, `{"choices":[{"message":{"content":"summary"}}]}`)
	})}
	request, _ := http.NewRequestWithContext(context.Background(), http.MethodPost, "http://panel.local", nil)
	if _, err := a.requestAssistantCompletion(request, "ollama", "model", "http://127.0.0.1:11434/v1", "", "system", "snapshot", 10); err != nil {
		t.Fatalf("bounded completion request: %v", err)
	}
}

func TestAssistantCompletionUsesAnthropicMessagesAndRedactsProviderErrors(t *testing.T) {
	a, _, _ := testApp(t)
	a.assistantHTTPClient = &http.Client{Transport: assistantTestRoundTripper(func(r *http.Request) (*http.Response, error) {
		if r.URL.Path != "/v1/messages" || r.Header.Get("x-api-key") != "local-test-key" || r.Header.Get("anthropic-version") != "2023-06-01" {
			t.Errorf("Anthropic completion headers or path are wrong: %s %#v", r.URL, r.Header)
		}
		var body struct {
			Model     string `json:"model"`
			MaxTokens int    `json:"max_tokens"`
			System    string `json:"system"`
			Messages  []struct {
				Role    string `json:"role"`
				Content string `json:"content"`
			} `json:"messages"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Errorf("decode Anthropic completion: %v", err)
		}
		if body.Model != "claude-local" || body.MaxTokens != 12 || body.System != "Only summarize facts" || len(body.Messages) != 1 || body.Messages[0].Role != "user" || body.Messages[0].Content != "snapshot" {
			t.Errorf("unexpected Anthropic completion body: %#v", body)
		}
		return assistantTestHTTPResponse(r, http.StatusOK, nil, `{"content":[{"type":"text","text":"  First. "},{"type":"text","text":"Second."}]}`)
	})}
	request, _ := http.NewRequest(http.MethodPost, "http://panel.local", nil)
	answer, err := a.requestAssistantCompletion(request, "anthropic", "claude-local", "https://api.anthropic.com", "local-test-key", "Only summarize facts", "snapshot", 12)
	if err != nil || answer != "First.\nSecond." {
		t.Fatalf("Anthropic completion result=%q err=%v", answer, err)
	}

	a.assistantHTTPClient = &http.Client{Transport: assistantTestRoundTripper(func(r *http.Request) (*http.Response, error) {
		return assistantTestHTTPResponse(r, http.StatusForbidden, nil, "provider-secret-error-body")
	})}
	_, err = a.requestAssistantCompletion(request, "openai", "model", "https://api.example.com/v1", "key", "system", "snapshot", 12)
	if err == nil || !strings.Contains(err.Error(), "403") || strings.Contains(err.Error(), "provider-secret-error-body") {
		t.Fatalf("provider failure was not safely summarized: %v", err)
	}
}
