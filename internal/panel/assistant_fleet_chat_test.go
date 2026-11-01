package panel

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestAssistantFleetCurrentUserRefreshesRoleAndRejectsRevokedSession(t *testing.T) {
	a, d, _ := testApp(t)
	_, token := assistantTestSessions(t, a, d)
	request := httptest.NewRequest(http.MethodGet, "/api/ai/chat/ws", nil)
	request.AddCookie(&http.Cookie{Name: "ygg_token", Value: token})
	stale := User{ID: "assistant-user", Username: "assistant-user", Role: "user"}
	if _, err := d.Exec("UPDATE users SET role='admin' WHERE id='assistant-user'"); err != nil {
		t.Fatal(err)
	}
	current, err := a.assistantFleetCurrentUser(t.Context(), request, stale)
	if err != nil || current.Role != "admin" {
		t.Fatalf("refresh role from current account: user=%#v err=%v", current, err)
	}
	if _, err = d.Exec("UPDATE users SET role='user',token_version=token_version+1 WHERE id='assistant-user'"); err != nil {
		t.Fatal(err)
	}
	if _, err = a.assistantFleetCurrentUser(t.Context(), request, stale); err == nil {
		t.Fatal("accepted a WebSocket session after its token version changed")
	}
}

func TestFleetAssistantUsesOnlyServersWithCallerViewAccess(t *testing.T) {
	a, d, _ := testApp(t)
	adminToken, _ := assistantTestSessions(t, a, d)
	if result := testRequest(a.Router(), http.MethodPut, "/api/ai/config", `{"provider":"ollama","model":"local-model"}`, adminToken); result.Code != http.StatusOK {
		t.Fatalf("save local provider: %d %s", result.Code, result.Body.String())
	}
	if result := testRequest(a.Router(), http.MethodPut, "/api/ai/enabled", `{"enabled":true}`, adminToken); result.Code != http.StatusOK {
		t.Fatalf("enable Advisory: %d %s", result.Code, result.Body.String())
	}
	if result := testRequest(a.Router(), http.MethodPut, "/api/ai/chat-scope", `{"data_level":1}`, adminToken); result.Code != http.StatusOK {
		t.Fatalf("set chat data level: %d %s", result.Code, result.Body.String())
	}
	if _, err := d.Exec(`INSERT INTO servers(id,name,gameskill_id,status,installed,env_json,ports_json,data_dir) VALUES
		('fleet-visible','Visible Arena','minecraft-java','running',1,'{}','{}',?),
		('fleet-hidden','PRIVATE-FLEET-5c8','minecraft-java','stopped',1,'{}','{}',?)`, t.TempDir(), t.TempDir()); err != nil {
		t.Fatal(err)
	}
	if _, err := d.Exec(`INSERT INTO permissions(user_id,scope_type,scope_id,perms) VALUES('assistant-user','server','fleet-visible','server.view')`); err != nil {
		t.Fatal(err)
	}
	if _, err := d.Exec(`INSERT INTO server_metrics(server_id,sampled_at,cpu_percent,memory_mb,players) VALUES('fleet-visible',strftime('%s','now'),21.5,512,3),('fleet-hidden',strftime('%s','now'),98.5,8192,90)`); err != nil {
		t.Fatal(err)
	}
	var prompt string
	a.assistantHTTPClient = &http.Client{Transport: assistantTestRoundTripper(func(r *http.Request) (*http.Response, error) {
		var request struct {
			Messages []struct {
				Role    string `json:"role"`
				Content string `json:"content"`
			} `json:"messages"`
		}
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			return nil, err
		}
		if len(request.Messages) != 2 || request.Messages[0].Role != "system" || request.Messages[1].Role != "user" {
			t.Fatalf("unexpected provider messages: %#v", request.Messages)
		}
		prompt = request.Messages[1].Content
		return assistantTestHTTPResponse(r, http.StatusOK, nil, `{"choices":[{"message":{"content":"The visible server is running."}}]}`)
	})}
	result, err := a.assistantFleetChatAnswer(t.Context(), User{ID: "assistant-user", Username: "assistant-user", Role: "user"}, assistantFleetChatInput{Question: "Summarize my server"})
	if err != nil {
		t.Fatalf("answer fleet chat: %v", err)
	}
	if result.VisibleServerCount != 1 || result.IncludedServerCount != 1 || result.DataLevel != 1 || result.Text != "The visible server is running." {
		t.Fatalf("fleet result does not report the caller's scoped context: %#v", result)
	}
	if !strings.Contains(prompt, "Visible Arena") || !strings.Contains(prompt, `"average_cpu_percent":21.5`) {
		t.Fatalf("fleet context omitted the caller's server or panel metrics: %s", prompt)
	}
	if strings.Contains(prompt, "PRIVATE-FLEET-5c8") || strings.Contains(prompt, `"average_cpu_percent":98.5`) || strings.Contains(prompt, `"visible_server_count":2`) {
		t.Fatalf("fleet context exposed hidden-server data: %s", prompt)
	}
	if result := testRequest(a.Router(), http.MethodPut, "/api/ai/chat-scope", `{"data_level":2}`, adminToken); result.Code != http.StatusOK {
		t.Fatalf("enable log-search scope: %d %s", result.Code, result.Body.String())
	}
	_, err = a.assistantFleetChatAnswer(t.Context(), User{ID: "assistant-user", Username: "assistant-user", Role: "user"}, assistantFleetChatInput{Question: "Search logs", LogServerID: "fleet-hidden", LogQuery: "failed"})
	var fleetErr *assistantFleetChatError
	if !errors.As(err, &fleetErr) || fleetErr.status != http.StatusForbidden {
		t.Fatalf("fleet chat allowed logs from an invisible server: %v", err)
	}
}
