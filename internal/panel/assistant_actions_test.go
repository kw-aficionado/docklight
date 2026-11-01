package panel

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestAssistantActionGrantsAreBoundAndOneUse(t *testing.T) {
	a, _, _ := testApp(t)
	server := assistantActionServer{ID: "proposal-server", Status: "running", Installed: true}
	proposalID, err := a.issueAssistantActionGrant("operator-a", server, "restart")
	if err != nil || proposalID == "" {
		t.Fatalf("issue action proposal grant: id=%q err=%v", proposalID, err)
	}
	if _, ok := a.consumeAssistantActionGrant(proposalID, "operator-b", server.ID, "restart"); ok {
		t.Fatal("operator B consumed operator A's proposal")
	}
	if _, ok := a.consumeAssistantActionGrant(proposalID, "operator-a", "other-server", "restart"); ok {
		t.Fatal("proposal was accepted for a different server")
	}
	if _, ok := a.consumeAssistantActionGrant(proposalID, "operator-a", server.ID, "stop"); ok {
		t.Fatal("proposal was accepted for a different action")
	}
	grant, ok := a.consumeAssistantActionGrant(proposalID, "operator-a", server.ID, "restart")
	if !ok || grant.Status != "running" || !grant.Installed {
		t.Fatalf("valid proposal grant could not be consumed: %#v ok=%v", grant, ok)
	}
	if _, ok = a.consumeAssistantActionGrant(proposalID, "operator-a", server.ID, "restart"); ok {
		t.Fatal("proposal grant was reusable")
	}

	expiredID := "expired-proposal"
	a.assistantPlanMu.Lock()
	if a.assistantPlans == nil {
		a.assistantPlans = make(map[string]assistantActionGrant)
	}
	a.assistantPlans[expiredID] = assistantActionGrant{UserID: "operator-a", ServerID: server.ID, Action: "restart", ExpiresAt: time.Now().Add(-time.Second)}
	a.assistantPlanMu.Unlock()
	if _, ok = a.consumeAssistantActionGrant(expiredID, "operator-a", server.ID, "restart"); ok {
		t.Fatal("expired proposal grant was accepted")
	}
}

func TestAssistantActionAPIRejectsExecutionWithoutPlanConfirmation(t *testing.T) {
	a, d, _ := testApp(t)
	adminToken, userToken := assistantTestSessions(t, a, d)
	if result := testRequest(a.Router(), http.MethodPut, "/api/ai/config", `{"provider":"ollama","model":"local-model"}`, adminToken); result.Code != http.StatusOK {
		t.Fatalf("save local provider: %d %s", result.Code, result.Body.String())
	}
	if result := testRequest(a.Router(), http.MethodPut, "/api/ai/enabled", `{"enabled":true}`, adminToken); result.Code != http.StatusOK {
		t.Fatalf("enable Advisory: %d %s", result.Code, result.Body.String())
	}
	if result := testRequest(a.Router(), http.MethodPut, "/api/ai/actions-enabled", `{"enabled":true}`, adminToken); result.Code != http.StatusOK {
		t.Fatalf("enable Actions: %d %s", result.Code, result.Body.String())
	}
	dataDir := t.TempDir()
	if _, err := d.Exec(`INSERT INTO servers(id,name,gameskill_id,status,installed,env_json,ports_json,data_dir,container_id) VALUES('proposal-direct','Proposal Direct','minecraft-java','running',1,'{}','{}',?,'container-direct')`, dataDir); err != nil {
		t.Fatal(err)
	}
	if _, err := d.Exec(`INSERT INTO permissions(user_id,scope_type,scope_id,perms) VALUES('assistant-user','server','proposal-direct','server.control')`); err != nil {
		t.Fatal(err)
	}
	result := testRequest(a.Router(), http.MethodPost, "/api/ai/plan/execute", `{"actions":[{"server_id":"proposal-direct","action":"stop"}]}`, userToken)
	if result.Code != http.StatusOK || !strings.Contains(result.Body.String(), "a current plan confirmation is required") || strings.Contains(result.Body.String(), `"status":"executed"`) {
		t.Fatalf("action API allowed direct execution without a plan grant: %d %s", result.Code, result.Body.String())
	}
}

func TestAssistantActionPlanIssuesOperatorBoundConfirmation(t *testing.T) {
	a, d, _ := testApp(t)
	adminToken, userToken := assistantTestSessions(t, a, d)
	if result := testRequest(a.Router(), http.MethodPut, "/api/ai/config", `{"provider":"ollama","model":"local-model"}`, adminToken); result.Code != http.StatusOK {
		t.Fatalf("save local provider: %d %s", result.Code, result.Body.String())
	}
	if result := testRequest(a.Router(), http.MethodPut, "/api/ai/enabled", `{"enabled":true}`, adminToken); result.Code != http.StatusOK {
		t.Fatalf("enable Advisory: %d %s", result.Code, result.Body.String())
	}
	if result := testRequest(a.Router(), http.MethodPut, "/api/ai/actions-enabled", `{"enabled":true}`, adminToken); result.Code != http.StatusOK {
		t.Fatalf("enable Actions: %d %s", result.Code, result.Body.String())
	}
	dataDir := t.TempDir()
	if _, err := d.Exec(`INSERT INTO servers(id,name,gameskill_id,status,installed,env_json,ports_json,data_dir) VALUES('planned-server','Planned Server','minecraft-java','running',1,'{}','{}',?)`, dataDir); err != nil {
		t.Fatal(err)
	}
	if _, err := d.Exec(`INSERT INTO permissions(user_id,scope_type,scope_id,perms) VALUES('assistant-user','server','planned-server','server.control')`); err != nil {
		t.Fatal(err)
	}
	a.assistantHTTPClient = &http.Client{Transport: assistantTestRoundTripper(func(r *http.Request) (*http.Response, error) {
		return assistantTestHTTPResponse(r, http.StatusOK, nil, `{"choices":[{"message":{"content":"{\"actions\":[{\"server_id\":\"planned-server\",\"action\":\"stop\",\"reason\":\"Operator requested a stop.\"}]}"}}]}`)
	})}
	result := testRequest(a.Router(), http.MethodPost, "/api/ai/plan", `{"request":"Stop this server","server_id":"planned-server"}`, userToken)
	if result.Code != http.StatusOK {
		t.Fatalf("prepare plan: %d %s", result.Code, result.Body.String())
	}
	var response struct {
		Actions []assistantActionProposalResult `json:"actions"`
	}
	if err := json.Unmarshal(result.Body.Bytes(), &response); err != nil {
		t.Fatalf("decode plan: %v", err)
	}
	if len(response.Actions) != 1 || !response.Actions[0].Accepted || response.Actions[0].ProposalID == "" {
		t.Fatalf("accepted plan has no confirmation token: %#v", response.Actions)
	}
	if _, ok := a.consumeAssistantActionGrant(response.Actions[0].ProposalID, "assistant-user", "planned-server", "stop"); !ok {
		t.Fatal("returned proposal ID was not bound to its operator, server, and action")
	}
}
