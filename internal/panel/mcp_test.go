package panel

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"

	"example.com/yggdrasil-panel/internal/security"
)

const (
	mcpTestIssuer   = "https://panel.example.test"
	mcpTestRedirect = "https://client.example.test/callback"
	mcpTestVerifier = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~"
)

func TestMCPDiscoveryAndDynamicClientRegistration(t *testing.T) {
	a, d, _ := testApp(t)
	a.cfg.Server.PublicURL = mcpTestIssuer
	h := a.Router()
	if _, err := a.mcpIssuer(httptest.NewRequest(http.MethodGet, "http://localhost/", nil)); err != nil {
		t.Fatalf("loopback development issuer was rejected: %v", err)
	}
	a.cfg.Server.PublicURL = "ftp://localhost"
	if _, err := a.mcpIssuer(httptest.NewRequest(http.MethodGet, "http://localhost/", nil)); err == nil {
		t.Fatal("non-HTTP issuer scheme was accepted for a loopback host")
	}
	a.cfg.Server.PublicURL = mcpTestIssuer

	for _, path := range []string{"/.well-known/oauth-authorization-server", "/.well-known/oauth-protected-resource", "/.well-known/oauth-protected-resource/api/mcp"} {
		w := httpsRequest(h, http.MethodGet, path, "", "")
		if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "https://panel.example.test") {
			t.Fatalf("metadata %s: status=%d body=%s", path, w.Code, w.Body.String())
		}
	}
	plainHTTP := httptest.NewRequest(http.MethodPost, "http://panel.example.test/oauth/register", strings.NewReader(`{"client_name":"insecure","redirect_uris":["https://client.example.test/callback"]}`))
	plainHTTP.Header.Set("Content-Type", "application/json")
	plainHTTPResponse := httptest.NewRecorder()
	h.ServeHTTP(plainHTTPResponse, plainHTTP)
	if plainHTTPResponse.Code != http.StatusBadRequest || !strings.Contains(plainHTTPResponse.Body.String(), "HTTPS transport") {
		t.Fatalf("MCP client registration accepted plain HTTP: %d %s", plainHTTPResponse.Code, plainHTTPResponse.Body.String())
	}
	var clientsBefore int
	if err := d.QueryRow("SELECT COUNT(*) FROM mcp_clients").Scan(&clientsBefore); err != nil {
		t.Fatal(err)
	}
	for _, redirect := range []string{"http://client.example.test/callback", "javascript:alert(1)", "data:text/html,hello"} {
		body, _ := json.Marshal(mcpRegisterInput{ClientName: "Bad callback", RedirectURIs: []string{redirect}})
		w := httpsRequest(h, http.MethodPost, "/oauth/register", string(body), "")
		if w.Code != http.StatusBadRequest {
			t.Errorf("accepted unsafe redirect %q: status=%d body=%s", redirect, w.Code, w.Body.String())
		}
	}
	valid, err := json.Marshal(mcpRegisterInput{ClientName: "Desktop connector", RedirectURIs: []string{mcpTestRedirect}, ResponseTypes: []string{"code"}, GrantTypes: []string{"authorization_code", "refresh_token"}, TokenEndpointAuthMethod: "none"})
	if err != nil {
		t.Fatal(err)
	}
	w := httpsRequest(h, http.MethodPost, "/oauth/register", string(valid), "")
	var registered map[string]any
	if w.Code != http.StatusCreated || json.Unmarshal(w.Body.Bytes(), &registered) != nil || registered["client_id"] == "" || registered["token_endpoint_auth_method"] != "none" || registered["client_secret"] != nil {
		t.Fatalf("register public client: status=%d body=%s", w.Code, w.Body.String())
	}
	var clientsAfter int
	if err = d.QueryRow("SELECT COUNT(*) FROM mcp_clients").Scan(&clientsAfter); err != nil || clientsAfter != clientsBefore+1 {
		t.Fatalf("bad redirect registration changed client count: before=%d after=%d err=%v", clientsBefore, clientsAfter, err)
	}
}

func TestMCPReachabilityFlagMarksPrivateAndReservedAddresses(t *testing.T) {
	for _, tc := range []struct {
		issuer string
		public bool
	}{
		{"https://docklight.app", true},
		{"https://panel.example.test", false},
		{"https://panel.local", false},
		{"https://192.168.1.20", false},
		{"https://100.64.10.2", false},
		{"https://192.0.2.10", false},
		{"http://docklight.app", false},
	} {
		public, _ := mcpPublicURL(tc.issuer)
		if public != tc.public {
			t.Errorf("mcpPublicURL(%q)=%t, want %t", tc.issuer, public, tc.public)
		}
	}
}

func TestMCPOAuthPKCERefreshToolsAndRevocation(t *testing.T) {
	a, d, _ := testApp(t)
	a.cfg.Server.PublicURL = mcpTestIssuer
	_, userSession := assistantTestSessions(t, a, d)
	insertRuntimeServer(t, a, "mcp-visible")
	if _, err := d.Exec(`UPDATE servers SET name='Visible test server' WHERE id='mcp-visible'`); err != nil {
		t.Fatal(err)
	}
	insertRuntimeServer(t, a, "mcp-duplicate")
	if _, err := d.Exec(`UPDATE servers SET name='Visible test server' WHERE id='mcp-duplicate'`); err != nil {
		t.Fatal(err)
	}
	insertRuntimeServer(t, a, "mcp-hidden")
	if _, err := d.Exec(`UPDATE servers SET name='Hidden test server' WHERE id='mcp-hidden'`); err != nil {
		t.Fatal(err)
	}
	insertRuntimeServer(t, a, "mcp-control-only")
	if _, err := d.Exec(`UPDATE servers SET name='Control-only test server',installed=0 WHERE id='mcp-control-only'`); err != nil {
		t.Fatal(err)
	}
	if _, err := d.Exec(`INSERT INTO permissions(user_id,scope_type,scope_id,perms) VALUES('assistant-user','server','mcp-visible','server.view')`); err != nil {
		t.Fatal(err)
	}
	if _, err := d.Exec(`INSERT INTO permissions(user_id,scope_type,scope_id,perms) VALUES('assistant-user','server','mcp-duplicate','server.view')`); err != nil {
		t.Fatal(err)
	}
	if _, err := d.Exec(`INSERT INTO permissions(user_id,scope_type,scope_id,perms) VALUES('assistant-user','server','mcp-control-only','server.control')`); err != nil {
		t.Fatal(err)
	}
	h := a.Router()
	clientID := registerMCPTestClient(t, h)
	access, refresh, firstCode := authorizeMCPTestClient(t, h, clientID, userSession)
	if firstCode == "" || !strings.HasPrefix(access.AccessToken, "ygg_mcp_") || !strings.HasPrefix(refresh, "ygg_mcp_") || access.Resource != mcpTestIssuer+"/api/mcp" || access.Scope != mcpScope {
		t.Fatalf("bad token response: %+v refresh=%q", access, refresh)
	}
	var accessHashCount, refreshHashCount, plaintextCount int
	if err := d.QueryRow("SELECT COUNT(*) FROM mcp_access_tokens WHERE token_hash=?", security.APIKeyHash(access.AccessToken)).Scan(&accessHashCount); err != nil {
		t.Fatal(err)
	}
	if err := d.QueryRow("SELECT COUNT(*) FROM mcp_refresh_tokens WHERE token_hash=?", security.APIKeyHash(refresh)).Scan(&refreshHashCount); err != nil {
		t.Fatal(err)
	}
	if err := d.QueryRow("SELECT (SELECT COUNT(*) FROM mcp_access_tokens WHERE token_hash=?)+(SELECT COUNT(*) FROM mcp_refresh_tokens WHERE token_hash=?)", access.AccessToken, refresh).Scan(&plaintextCount); err != nil {
		t.Fatal(err)
	}
	if accessHashCount != 1 || refreshHashCount != 1 || plaintextCount != 0 {
		t.Fatalf("MCP credentials should be stored only as hashes: access=%d refresh=%d plaintext=%d", accessHashCount, refreshHashCount, plaintextCount)
	}
	info := httpsRequest(h, http.MethodGet, "/api/mcp/info", "", userSession)
	if info.Code != http.StatusOK || !strings.Contains(info.Body.String(), mcpTestIssuer+"/api/mcp") || !strings.Contains(info.Body.String(), `"tool_count":7`) || !strings.Contains(info.Body.String(), `"public_reachable":false`) {
		t.Fatalf("MCP connection information: %d %s", info.Code, info.Body.String())
	}

	missing := httpsRequest(h, http.MethodPost, "/api/mcp", `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`, "")
	if missing.Code != http.StatusUnauthorized || !strings.Contains(missing.Header().Get("WWW-Authenticate"), "oauth-protected-resource") {
		t.Fatalf("unauthenticated MCP discovery: status=%d headers=%v body=%s", missing.Code, missing.Header(), missing.Body.String())
	}
	plainConnector := httptest.NewRequest(http.MethodPost, "http://panel.example.test/api/mcp", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`))
	plainConnector.Header.Set("Content-Type", "application/json")
	plainConnector.Header.Set("Authorization", "Bearer "+access.AccessToken)
	plainConnectorResponse := httptest.NewRecorder()
	h.ServeHTTP(plainConnectorResponse, plainConnector)
	if plainConnectorResponse.Code != http.StatusBadRequest {
		t.Fatalf("MCP bearer token was accepted over plain HTTP: %d %s", plainConnectorResponse.Code, plainConnectorResponse.Body.String())
	}
	webSession := httpsRequest(h, http.MethodPost, "/api/mcp", `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`, userSession)
	if webSession.Code != http.StatusUnauthorized {
		t.Fatalf("ordinary browser session bypassed MCP consent: %d %s", webSession.Code, webSession.Body.String())
	}
	listed := httpsRequest(h, http.MethodPost, "/api/mcp", `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`, access.AccessToken)
	var listResponse struct {
		Result struct {
			Tools []map[string]any `json:"tools"`
		} `json:"result"`
	}
	if listed.Code != http.StatusOK || json.Unmarshal(listed.Body.Bytes(), &listResponse) != nil || len(listResponse.Result.Tools) != 7 {
		t.Fatalf("MCP tools/list: status=%d body=%s", listed.Code, listed.Body.String())
	}
	for _, method := range []string{http.MethodGet, http.MethodDelete} {
		methodResponse := httpsRequest(h, method, "/api/mcp", "", access.AccessToken)
		if methodResponse.Code != http.StatusMethodNotAllowed || methodResponse.Header().Get("Allow") != http.MethodPost {
			t.Errorf("MCP %s should be rejected: status=%d allow=%q", method, methodResponse.Code, methodResponse.Header().Get("Allow"))
		}
	}
	for _, tool := range listResponse.Result.Tools {
		if name, _ := tool["name"].(string); name == "delete_server" || name == "server_files" || name == "update_server_settings" {
			t.Fatalf("MCP exposed a forbidden tool %q", name)
		}
	}
	visible := callMCPTestTool(t, h, access.AccessToken, "list_servers", `{}`)
	if !strings.Contains(visible, "mcp-visible") || strings.Contains(visible, "mcp-hidden") {
		t.Fatalf("MCP did not enforce per-user server visibility: %s", visible)
	}
	ambiguous := callMCPTestTool(t, h, access.AccessToken, "get_server", `{"server":"Visible test server"}`)
	if !strings.Contains(ambiguous, `"isError":true`) || !strings.Contains(ambiguous, "ambiguous") {
		t.Fatalf("MCP silently chose a server for an ambiguous name: %s", ambiguous)
	}
	byID := callMCPTestTool(t, h, access.AccessToken, "get_server", `{"server":"mcp-visible"}`)
	if !strings.Contains(byID, "mcp-visible") || strings.Contains(byID, `"isError":true`) {
		t.Fatalf("MCP server ID did not disambiguate: %s", byID)
	}
	denied := callMCPTestTool(t, h, access.AccessToken, "get_server", `{"server":"mcp-hidden"}`)
	if !strings.Contains(denied, `"isError":true`) || !strings.Contains(denied, "server.view permission") {
		t.Fatalf("MCP allowed access to a hidden server: %s", denied)
	}
	controlDenied := callMCPTestTool(t, h, access.AccessToken, "start_server", `{"server":"mcp-visible"}`)
	if !strings.Contains(controlDenied, `"isError":true`) || !strings.Contains(controlDenied, "server.control permission") {
		t.Fatalf("MCP performed a control action without permission: %s", controlDenied)
	}
	controlOnly := callMCPTestTool(t, h, access.AccessToken, "start_server", `{"server":"Control-only test server"}`)
	if !strings.Contains(controlOnly, `"isError":true`) || !strings.Contains(controlOnly, "install this server before starting it") {
		t.Fatalf("MCP failed to honor server.control without requiring server.view: %s", controlOnly)
	}
	apiToken := "ygg_test-mcp-api-token"
	if _, err := d.Exec(`INSERT INTO api_tokens(id,user_id,name,token_hash,scope) VALUES('mcp-api-token','assistant-user','MCP API test',?,'server.view')`, security.APIKeyHash(apiToken)); err != nil {
		t.Fatal(err)
	}
	apiVisible := callMCPTestTool(t, h, apiToken, "list_servers", `{}`)
	if !strings.Contains(apiVisible, "mcp-visible") || strings.Contains(apiVisible, "mcp-hidden") {
		t.Fatalf("scoped API token did not work with MCP: %s", apiVisible)
	}
	wrongPath := httpsRequest(h, http.MethodGet, "/api/mcp/info", "", access.AccessToken)
	if wrongPath.Code != http.StatusUnauthorized {
		t.Fatalf("connector access token was accepted outside /api/mcp: %d %s", wrongPath.Code, wrongPath.Body.String())
	}

	rotated := exchangeMCPRefresh(t, h, clientID, refresh)
	if rotated.AccessToken == access.AccessToken || rotated.RefreshToken == refresh {
		t.Fatal("refresh did not rotate both MCP tokens")
	}
	replay := postMCPToken(t, h, url.Values{"grant_type": {"refresh_token"}, "client_id": {clientID}, "refresh_token": {refresh}, "resource": {mcpTestIssuer + "/api/mcp"}})
	if replay.Code != http.StatusBadRequest || !strings.Contains(replay.Body.String(), "reuse detected") {
		t.Fatalf("refresh replay was not rejected and revoked: %d %s", replay.Code, replay.Body.String())
	}
	revoked := httpsRequest(h, http.MethodPost, "/api/mcp", `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`, rotated.AccessToken)
	if revoked.Code != http.StatusUnauthorized {
		t.Fatalf("refresh replay did not revoke the connection: %d %s", revoked.Code, revoked.Body.String())
	}

	secondAccess, _, _ := authorizeMCPTestClient(t, h, clientID, userSession)
	connections := httpsRequest(h, http.MethodGet, "/api/mcp/connections", "", userSession)
	var connectionResponse struct {
		Connections []struct {
			ID string `json:"id"`
		} `json:"connections"`
	}
	if connections.Code != http.StatusOK || json.Unmarshal(connections.Body.Bytes(), &connectionResponse) != nil || len(connectionResponse.Connections) != 1 {
		t.Fatalf("connection management list: %d %s", connections.Code, connections.Body.String())
	}
	revokePath := "/api/mcp/connections/" + connectionResponse.Connections[0].ID
	revokedByUser := httpsRequest(h, http.MethodDelete, revokePath, "", userSession)
	if revokedByUser.Code != http.StatusOK {
		t.Fatalf("revoke own MCP connection: %d %s", revokedByUser.Code, revokedByUser.Body.String())
	}
	afterRevoke := httpsRequest(h, http.MethodPost, "/api/mcp", `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`, secondAccess.AccessToken)
	if afterRevoke.Code != http.StatusUnauthorized {
		t.Fatalf("revocation did not invalidate the access token: %d %s", afterRevoke.Code, afterRevoke.Body.String())
	}
}

type mcpTestTokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	Scope        string `json:"scope"`
	Resource     string `json:"resource"`
}

func registerMCPTestClient(t *testing.T, h http.Handler) string {
	t.Helper()
	body, _ := json.Marshal(mcpRegisterInput{ClientName: "Test connector", RedirectURIs: []string{mcpTestRedirect}})
	w := httpsRequest(h, http.MethodPost, "/oauth/register", string(body), "")
	var result struct {
		ClientID string `json:"client_id"`
	}
	if w.Code != http.StatusCreated || json.Unmarshal(w.Body.Bytes(), &result) != nil || result.ClientID == "" {
		t.Fatalf("register MCP client: %d %s", w.Code, w.Body.String())
	}
	return result.ClientID
}

func authorizeMCPTestClient(t *testing.T, h http.Handler, clientID, session string) (mcpTestTokenResponse, string, string) {
	t.Helper()
	const verifier = mcpTestVerifier
	digest := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(digest[:])
	query := url.Values{
		"response_type": {"code"}, "client_id": {clientID}, "redirect_uri": {mcpTestRedirect},
		"scope": {mcpScope}, "state": {"test-state"}, "code_challenge": {challenge},
		"code_challenge_method": {"S256"}, "resource": {mcpTestIssuer + "/api/mcp"},
	}
	page := httpsRequest(h, http.MethodGet, "/oauth/authorize?"+query.Encode(), "", "")
	nonceMatch := regexp.MustCompile(`name="nonce" value="([^"]+)"`).FindStringSubmatch(page.Body.String())
	if page.Code != http.StatusOK || len(nonceMatch) != 2 {
		t.Fatalf("MCP consent page: %d %s", page.Code, page.Body.String())
	}
	form := url.Values{"nonce": {nonceMatch[1]}, "decision": {"allow"}}
	forged := httptest.NewRequest(http.MethodPost, mcpTestIssuer+"/oauth/authorize", strings.NewReader(form.Encode()))
	forged.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	forged.AddCookie(&http.Cookie{Name: "ygg_token", Value: session})
	forgedRecorder := httptest.NewRecorder()
	h.ServeHTTP(forgedRecorder, forged)
	if forgedRecorder.Code != http.StatusForbidden {
		t.Fatalf("MCP approval without a same-origin browser request was accepted: %d %s", forgedRecorder.Code, forgedRecorder.Body.String())
	}
	crossOrigin := httptest.NewRequest(http.MethodPost, mcpTestIssuer+"/oauth/authorize", strings.NewReader(form.Encode()))
	crossOrigin.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	crossOrigin.Header.Set("Origin", "https://attacker.example")
	crossOrigin.AddCookie(&http.Cookie{Name: "ygg_token", Value: session})
	crossOriginRecorder := httptest.NewRecorder()
	h.ServeHTTP(crossOriginRecorder, crossOrigin)
	if crossOriginRecorder.Code != http.StatusForbidden {
		t.Fatalf("cross-origin MCP approval was accepted: %d %s", crossOriginRecorder.Code, crossOriginRecorder.Body.String())
	}
	req := httptest.NewRequest(http.MethodPost, mcpTestIssuer+"/oauth/authorize", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(&http.Cookie{Name: "ygg_token", Value: session})
	req.Header.Set("Origin", mcpTestIssuer)
	consentRecorder := httptest.NewRecorder()
	h.ServeHTTP(consentRecorder, req)
	if consentRecorder.Code != http.StatusSeeOther {
		t.Fatalf("approve MCP consent: %d %s", consentRecorder.Code, consentRecorder.Body.String())
	}
	callback, err := url.Parse(consentRecorder.Header().Get("Location"))
	if err != nil || callback.Query().Get("state") != "test-state" || callback.Query().Get("iss") != mcpTestIssuer {
		t.Fatalf("bad MCP authorization redirect: %q err=%v", consentRecorder.Header().Get("Location"), err)
	}
	code := callback.Query().Get("code")
	tokenForm := url.Values{
		"grant_type": {"authorization_code"}, "client_id": {clientID}, "code": {code},
		"redirect_uri": {mcpTestRedirect}, "code_verifier": {verifier}, "resource": {mcpTestIssuer + "/api/mcp"},
	}
	wrongVerifier := url.Values{}
	for key, values := range tokenForm {
		wrongVerifier[key] = append([]string(nil), values...)
	}
	wrongVerifier.Set("code_verifier", "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~x")
	wrongExchange := postMCPToken(t, h, wrongVerifier)
	if wrongExchange.Code != http.StatusBadRequest {
		t.Fatalf("authorization code was redeemed with the wrong PKCE verifier: %d %s", wrongExchange.Code, wrongExchange.Body.String())
	}
	exchanged := postMCPToken(t, h, tokenForm)
	var tokens mcpTestTokenResponse
	if exchanged.Code != http.StatusOK || json.Unmarshal(exchanged.Body.Bytes(), &tokens) != nil || tokens.AccessToken == "" {
		t.Fatalf("exchange MCP authorization code: %d %s", exchanged.Code, exchanged.Body.String())
	}
	replay := postMCPToken(t, h, tokenForm)
	if replay.Code != http.StatusBadRequest {
		t.Fatalf("authorization code replay was accepted: %d %s", replay.Code, replay.Body.String())
	}
	return tokens, tokens.RefreshToken, code
}

func exchangeMCPRefresh(t *testing.T, h http.Handler, clientID, refresh string) mcpTestTokenResponse {
	t.Helper()
	w := postMCPToken(t, h, url.Values{"grant_type": {"refresh_token"}, "client_id": {clientID}, "refresh_token": {refresh}, "resource": {mcpTestIssuer + "/api/mcp"}})
	var tokens mcpTestTokenResponse
	if w.Code != http.StatusOK || json.Unmarshal(w.Body.Bytes(), &tokens) != nil || tokens.AccessToken == "" {
		t.Fatalf("rotate MCP refresh token: %d %s", w.Code, w.Body.String())
	}
	return tokens
}

func postMCPToken(t *testing.T, h http.Handler, values url.Values) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, mcpTestIssuer+"/oauth/token", strings.NewReader(values.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	return w
}

func callMCPTestTool(t *testing.T, h http.Handler, token, name, arguments string) string {
	t.Helper()
	body := `{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"` + name + `","arguments":` + arguments + `}}`
	w := httpsRequest(h, http.MethodPost, "/api/mcp", body, token)
	if w.Code != http.StatusOK {
		t.Fatalf("call MCP tool %s: %d %s", name, w.Code, w.Body.String())
	}
	return w.Body.String()
}

func httpsRequest(h http.Handler, method, path, body, bearer string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, mcpTestIssuer+path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	return w
}
