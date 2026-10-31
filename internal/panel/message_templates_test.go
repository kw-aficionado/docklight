package panel

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

func TestMessageTemplatesAreSeededAndAdminManaged(t *testing.T) {
	a, d, _ := testApp(t)
	if _, err := d.Exec(`INSERT INTO users(id,username,password_hash,role) VALUES('template-admin','template-admin','unused-hash','admin'),('template-user','template-user','unused-hash','user')`); err != nil {
		t.Fatal(err)
	}
	adminToken, err := a.issue(User{ID: "template-admin", Role: "admin"})
	if err != nil {
		t.Fatal(err)
	}
	userToken, err := a.issue(User{ID: "template-user", Role: "user"})
	if err != nil {
		t.Fatal(err)
	}
	h := a.Router()
	adminList := testRequest(h, http.MethodGet, "/api/message-templates", "", adminToken)
	if adminList.Code != http.StatusOK || strings.Count(adminList.Body.String(), `"builtin":true`) != 5 || !strings.Contains(adminList.Body.String(), "builtin-maintenance-notice") {
		t.Fatalf("expected five seeded templates, got %d %s", strings.Count(adminList.Body.String(), `"builtin":true`), adminList.Body.String())
	}
	userList := testRequest(h, http.MethodGet, "/api/message-templates", "", userToken)
	if userList.Code != http.StatusOK || strings.Contains(userList.Body.String(), `"body"`) || !strings.Contains(userList.Body.String(), `"parameters":["server_name","minutes"]`) {
		t.Fatalf("non-admin template list should expose choices and parameters without command bodies: %d %s", userList.Code, userList.Body.String())
	}
	denied := testRequest(h, http.MethodPost, "/api/message-templates", `{"name":"Custom notice","body":"say {{server_name}} in {{minutes}} minutes"}`, userToken)
	if denied.Code != http.StatusForbidden {
		t.Fatalf("non-admin created a message template: %d %s", denied.Code, denied.Body.String())
	}
	invalid := testRequest(h, http.MethodPost, "/api/message-templates", `{"name":"Invalid","body":"say {{server_name}} {{operator}}"}`, adminToken)
	if invalid.Code != http.StatusBadRequest || !strings.Contains(invalid.Body.String(), "unsupported message placeholder") {
		t.Fatalf("unsupported placeholder was accepted: %d %s", invalid.Code, invalid.Body.String())
	}
	builtinUpdate := testRequest(h, http.MethodPut, "/api/message-templates/builtin-maintenance-notice", `{"name":"Changed","body":"say {{server_name}}"}`, adminToken)
	if builtinUpdate.Code != http.StatusConflict {
		t.Fatalf("built-in template was editable: %d %s", builtinUpdate.Code, builtinUpdate.Body.String())
	}
	builtinDelete := testRequest(h, http.MethodDelete, "/api/message-templates/builtin-maintenance-notice", "{}", adminToken)
	if builtinDelete.Code != http.StatusConflict {
		t.Fatalf("built-in template was deletable: %d %s", builtinDelete.Code, builtinDelete.Body.String())
	}
	created := testRequest(h, http.MethodPost, "/api/message-templates", `{"name":"Custom notice","body":"say {{server_name}} in {{minutes}} minutes"}`, adminToken)
	if created.Code != http.StatusCreated {
		t.Fatalf("create custom template: %d %s", created.Code, created.Body.String())
	}
	var item messageTemplate
	if err = json.Unmarshal(created.Body.Bytes(), &item); err != nil {
		t.Fatal(err)
	}
	if item.ID == "" || item.BuiltIn || item.Name != "Custom notice" || item.Body != "say {{server_name}} in {{minutes}} minutes" || len(item.Parameters) != 2 || item.Parameters[1] != "minutes" {
		t.Fatalf("custom template metadata mismatch: %#v", item)
	}
	updated := testRequest(h, http.MethodPut, "/api/message-templates/"+item.ID, `{"name":"Custom countdown","body":"say {{server_name}} in {{seconds}} seconds"}`, adminToken)
	if updated.Code != http.StatusOK || !strings.Contains(updated.Body.String(), `"name":"Custom countdown"`) || !strings.Contains(updated.Body.String(), `"parameters":["server_name","seconds"]`) {
		t.Fatalf("update custom template: %d %s", updated.Code, updated.Body.String())
	}
	deleted := testRequest(h, http.MethodDelete, "/api/message-templates/"+item.ID, "{}", adminToken)
	if deleted.Code != http.StatusOK {
		t.Fatalf("delete custom template: %d %s", deleted.Code, deleted.Body.String())
	}
}
