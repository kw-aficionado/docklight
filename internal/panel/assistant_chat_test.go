package panel

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestAssistantServerChatScopesContextToVisibleServerAndDataLevel(t *testing.T) {
	a, d, _ := testApp(t)
	adminToken, userToken := assistantTestSessions(t, a, d)
	h := a.Router()
	if result := testRequest(h, http.MethodPut, "/api/ai/config", `{"provider":"ollama","model":"local-model"}`, adminToken); result.Code != http.StatusOK {
		t.Fatalf("save local provider: %d %s", result.Code, result.Body.String())
	}
	if result := testRequest(h, http.MethodPut, "/api/ai/enabled", `{"enabled":true}`, adminToken); result.Code != http.StatusOK {
		t.Fatalf("enable Advisory: %d %s", result.Code, result.Body.String())
	}
	if result := testRequest(h, http.MethodPut, "/api/ai/chat-scope", `{"data_level":1}`, userToken); result.Code != http.StatusForbidden {
		t.Fatalf("non-admin changed chat scope: %d %s", result.Code, result.Body.String())
	}
	if result := testRequest(h, http.MethodPut, "/api/ai/chat-scope", `{"data_level":1}`, adminToken); result.Code != http.StatusOK {
		t.Fatalf("admin set chat scope: %d %s", result.Code, result.Body.String())
	}

	dataDir := t.TempDir()
	if _, err := d.Exec(`INSERT INTO servers(id,name,gameskill_id,status,installed,env_json,ports_json,data_dir,container_id) VALUES('chat-visible','Visible Arena','minecraft-java','running',1,'{"RCON_PASSWORD":"private-config-secret"}','{}',?,'container-visible'),('chat-hidden','PRIVATE-OUTSIDE-9e2','minecraft-java','stopped',1,'{}','{}',?,'')`, dataDir, dataDir); err != nil {
		t.Fatal(err)
	}
	if _, err := d.Exec(`INSERT INTO permissions(user_id,scope_type,scope_id,perms) VALUES('assistant-user','server','chat-visible','server.view')`); err != nil {
		t.Fatal(err)
	}
	cutoff := time.Now().Add(-time.Hour).Unix()
	if _, err := d.Exec(`INSERT INTO server_metrics(server_id,sampled_at,cpu_percent,memory_mb,players) VALUES('chat-visible',?,23.5,512,2),('chat-hidden',?,99.9,9999,99)`, cutoff, cutoff); err != nil {
		t.Fatal(err)
	}
	var sentPrompts []string
	a.assistantHTTPClient = &http.Client{Transport: assistantTestRoundTripper(func(r *http.Request) (*http.Response, error) {
		var body struct {
			Messages []struct {
				Role    string `json:"role"`
				Content string `json:"content"`
			} `json:"messages"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			return nil, err
		}
		if len(body.Messages) != 2 || body.Messages[0].Role != "system" || body.Messages[1].Role != "user" {
			return nil, fmt.Errorf("unexpected provider messages: %#v", body.Messages)
		}
		sentPrompts = append(sentPrompts, body.Messages[1].Content)
		return assistantTestHTTPResponse(r, http.StatusOK, nil, `{"choices":[{"message":{"content":"Check the server's backup schedule."}}]}`)
	})}

	question := "How should I check the backup setup?"
	requestBody := `{"question":"` + question + `"}`
	chat := testRequest(h, http.MethodPost, "/api/servers/chat-visible/assistant/chat", requestBody, userToken)
	if chat.Code != http.StatusOK || !strings.Contains(chat.Body.String(), "backup schedule") || !strings.Contains(chat.Body.String(), `"docs_used":`) {
		t.Fatalf("server chat did not answer with docs metadata: %d %s", chat.Code, chat.Body.String())
	}
	if len(sentPrompts) != 1 || !strings.Contains(sentPrompts[0], "Visible Arena") || !strings.Contains(sentPrompts[0], `"average_cpu_percent":23.5`) {
		t.Fatalf("chat omitted selected-server context or metrics: %q", sentPrompts)
	}
	if strings.Contains(sentPrompts[0], "PRIVATE-OUTSIDE-9e2") || strings.Contains(sentPrompts[0], `"average_cpu_percent":99.9`) || strings.Contains(sentPrompts[0], "private-config-secret") {
		t.Fatalf("server chat leaked hidden-server or configuration data: %s", sentPrompts[0])
	}

	denied := testRequest(h, http.MethodPost, "/api/servers/chat-hidden/assistant/chat", requestBody, userToken)
	if denied.Code != http.StatusForbidden || len(sentPrompts) != 1 {
		t.Fatalf("chat used a server without server.view: %d %s provider_calls=%d", denied.Code, denied.Body.String(), len(sentPrompts))
	}
	logDenied := testRequest(h, http.MethodPost, "/api/servers/chat-visible/assistant/chat", `{"question":"explain this failure","log_query":"connection refused"}`, userToken)
	if logDenied.Code != http.StatusConflict || len(sentPrompts) != 1 {
		t.Fatalf("log search bypassed the configured data level: %d %s provider_calls=%d", logDenied.Code, logDenied.Body.String(), len(sentPrompts))
	}

	if result := testRequest(h, http.MethodPut, "/api/ai/chat-scope", `{"data_level":0}`, adminToken); result.Code != http.StatusOK {
		t.Fatalf("admin lowered chat scope: %d %s", result.Code, result.Body.String())
	}
	limited := testRequest(h, http.MethodPost, "/api/servers/chat-visible/assistant/chat", requestBody, userToken)
	if limited.Code != http.StatusOK || len(sentPrompts) != 2 {
		t.Fatalf("snapshot-only chat failed: %d %s calls=%d", limited.Code, limited.Body.String(), len(sentPrompts))
	}
	if strings.Contains(sentPrompts[1], `"metrics_24h"`) || strings.Contains(sentPrompts[1], "PRIVATE-OUTSIDE-9e2") {
		t.Fatalf("snapshot-only chat included extra or hidden panel data: %s", sentPrompts[1])
	}
	var auditDetail string
	if err := d.QueryRow(`SELECT detail FROM audit_log WHERE action='ai.server_chat' ORDER BY id DESC LIMIT 1`).Scan(&auditDetail); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(auditDetail, question) || strings.Contains(auditDetail, "private-config-secret") {
		t.Fatalf("chat audit stored prompt or secret: %s", auditDetail)
	}
}

func TestHostedAssistantLogSharingRequiresCurrentHostConsentOnEveryEndpoint(t *testing.T) {
	a, d, _ := testApp(t)
	adminToken, userToken := assistantTestSessions(t, a, d)
	if result := testRequest(a.Router(), http.MethodPut, "/api/ai/config", `{"provider":"openai","model":"test-model","base_url":"https://api.openai.com/v1","api_key":"test-provider-key"}`, adminToken); result.Code != http.StatusOK {
		t.Fatalf("save hosted provider: %d %s", result.Code, result.Body.String())
	}
	if result := testRequest(a.Router(), http.MethodPut, "/api/ai/enabled", `{"enabled":true}`, adminToken); result.Code != http.StatusOK {
		t.Fatalf("enable hosted Advisory: %d %s", result.Code, result.Body.String())
	}
	if result := testRequest(a.Router(), http.MethodPut, "/api/ai/chat-scope", `{"data_level":2}`, adminToken); result.Code != http.StatusOK {
		t.Fatalf("enable searched chat logs: %d %s", result.Code, result.Body.String())
	}
	if _, err := d.Exec(`INSERT INTO servers(id,name,gameskill_id,status,installed,env_json,ports_json,data_dir,container_id) VALUES('cloud-log-server','Cloud Log Server','minecraft-java','running',1,'{}','{}',?,'container-cloud-log')`, t.TempDir()); err != nil {
		t.Fatal(err)
	}
	if _, err := d.Exec(`INSERT INTO permissions(user_id,scope_type,scope_id,perms) VALUES('assistant-user','server','cloud-log-server','server.view')`); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, method, path, body, token string
	}{
		{name: "searched chat", method: http.MethodPost, path: "/api/servers/cloud-log-server/assistant/chat", body: `{"question":"explain this","log_query":"connection refused"}`, token: userToken},
		{name: "log explanation", method: http.MethodPost, path: "/api/servers/cloud-log-server/explain", body: `{}`, token: userToken},
		{name: "watcher suggestions", method: http.MethodPost, path: "/api/servers/cloud-log-server/watchers/suggest", body: `{}`, token: adminToken},
	} {
		t.Run(tc.name, func(t *testing.T) {
			result := testRequest(a.Router(), tc.method, tc.path, tc.body, tc.token)
			if result.Code != http.StatusConflict || !strings.Contains(result.Body.String(), "confirm") {
				t.Fatalf("hosted log-sharing endpoint bypassed consent: %d %s", result.Code, result.Body.String())
			}
		})
	}
	staleHost := testRequest(a.Router(), http.MethodPost, "/api/servers/cloud-log-server/assistant/chat", `{"question":"explain this","log_query":"connection refused","confirm_external_logs":true,"confirm_external_host":"old-provider.example"}`, userToken)
	if staleHost.Code != http.StatusConflict || !strings.Contains(staleHost.Body.String(), "configured provider host") {
		t.Fatalf("consent for a different provider host was accepted: %d %s", staleHost.Code, staleHost.Body.String())
	}
}

func TestAssistantSearchLogLinesFiltersAndBoundsMatches(t *testing.T) {
	var input strings.Builder
	for index := 0; index < 30; index++ {
		if index%2 == 0 {
			fmt.Fprintf(&input, "INFO no match %02d\n", index)
		} else {
			fmt.Fprintf(&input, "ERROR connection refused %02d %s\n", index, strings.Repeat("x", 600))
		}
	}
	result := assistantSearchLogLines(input.String(), "connection refused")
	if result.ReviewedLines != 30 || result.IncludedLines == 0 || result.IncludedLines > assistantChatLogLineLimit || assistantChatTextBytes(result.MatchingLines) > assistantChatLogByteLimit {
		t.Fatalf("log search exceeded its line/byte bounds: %#v bytes=%d", result, assistantChatTextBytes(result.MatchingLines))
	}
	for _, line := range result.MatchingLines {
		if !strings.Contains(line, "ERROR connection refused") || strings.Contains(line, "INFO no match") {
			t.Fatalf("log search included a non-matching line: %q", line)
		}
	}
}
