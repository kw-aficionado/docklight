package panel

import (
	"context"
	"database/sql"
	"errors"
	"net"
	"net/http"
	"strings"
	"testing"

	"example.com/yggdrasil-panel/internal/rune"
	"example.com/yggdrasil-panel/internal/security"
	"example.com/yggdrasil-panel/internal/upnp"
)

type fakeUPnPGateway struct {
	localIP         net.IP
	wanIP           net.IP
	mappings        map[string]upnp.Mapping
	adds            int
	deletes         int
	getCalls        int
	getErrAfter     int
	getErr          error
	addErr          error
	applyOnAddError bool
	deleteErr       error
}

func (g *fakeUPnPGateway) LocalIP() net.IP { return append(net.IP(nil), g.localIP...) }
func (g *fakeUPnPGateway) ExternalIP(context.Context) (net.IP, error) {
	return append(net.IP(nil), g.wanIP...), nil
}
func (g *fakeUPnPGateway) GetMapping(_ context.Context, protocol string, port uint16) (upnp.Mapping, bool, error) {
	g.getCalls++
	if g.getErr != nil || g.getErrAfter > 0 && g.getCalls >= g.getErrAfter {
		if g.getErr == nil {
			return upnp.Mapping{}, false, errors.New("router mapping lookup timed out")
		}
		return upnp.Mapping{}, false, g.getErr
	}
	mapping, ok := g.mappings[mappingKey(protocol, port)]
	return mapping, ok, nil
}
func (g *fakeUPnPGateway) AddMapping(_ context.Context, mapping upnp.Mapping) error {
	g.adds++
	if g.addErr != nil {
		if g.applyOnAddError {
			g.mappings[mappingKey(mapping.Protocol, mapping.ExternalPort)] = mapping
		}
		return g.addErr
	}
	key := mappingKey(mapping.Protocol, mapping.ExternalPort)
	if _, exists := g.mappings[key]; exists {
		return errors.New("mapping conflict")
	}
	g.mappings[key] = mapping
	return nil
}
func (g *fakeUPnPGateway) DeleteMapping(_ context.Context, protocol string, port uint16) error {
	g.deletes++
	if g.deleteErr != nil {
		return g.deleteErr
	}
	delete(g.mappings, mappingKey(protocol, port))
	return nil
}

func TestDesiredServerMappingsExpandProtocolsAndSkipControlPorts(t *testing.T) {
	server := Server{ID: "server-123", Ports: map[string]int{"game": 25565, "rcon": 25575, "admin-api": 8081}}
	game := rune.Rune{Ports: []rune.Port{
		{Name: "game", Protocol: "tcp+udp"},
		{Name: "rcon", Protocol: "tcp"},
		{Name: "admin-api", Protocol: "tcp"},
	}}
	mappings := desiredServerMappings(server, game, "192.168.1.40")
	if len(mappings) != 2 {
		t.Fatalf("wanted only the TCP and UDP game mappings, got %#v", mappings)
	}
	if mappings[0].Protocol != "TCP" || mappings[1].Protocol != "UDP" {
		t.Fatalf("protocol expansion is incorrect: %#v", mappings)
	}
	for _, mapping := range mappings {
		if mapping.ExternalPort != 25565 || mapping.InternalPort != 25565 || mapping.InternalClient != "192.168.1.40" || !strings.HasPrefix(mapping.Description, "Docklight:") {
			t.Fatalf("mapping has an unexpected target or description: %#v", mapping)
		}
	}
}

func TestOpenServerUPnPMappingsCreatesOnlyOwnedDeclaredPortsAndIsIdempotent(t *testing.T) {
	app, d, _ := testApp(t)
	if _, err := d.Exec(`UPDATE upnp_settings SET enabled=1 WHERE id=1`); err != nil {
		t.Fatal(err)
	}
	seedUPnPServer(t, d, "map-server", `{"game":25565,"rcon":25575}`)
	server, err := app.getServer("map-server")
	if err != nil {
		t.Fatal(err)
	}
	gateway := &fakeUPnPGateway{localIP: net.ParseIP("192.168.1.40"), wanIP: net.ParseIP("203.0.113.9"), mappings: map[string]upnp.Mapping{}}
	app.upnpDiscover = func(context.Context) (upnp.Gateway, error) { return gateway, nil }
	if err = app.openServerUPnPMappings(context.Background(), server); err != nil {
		t.Fatal(err)
	}
	if len(gateway.mappings) != 1 || gateway.adds != 1 {
		t.Fatalf("expected only the game port to be forwarded: mappings=%#v adds=%d", gateway.mappings, gateway.adds)
	}
	tracked, err := app.listServerUPnPMappings(server.ID)
	if err != nil || len(tracked) != 1 || tracked[0].PortName != "game" || tracked[0].Protocol != "TCP" {
		t.Fatalf("recorded mapping does not match the game port: %#v err=%v", tracked, err)
	}
	created := gateway.mappings["TCP:25565"]
	if !created.Enabled || created.LeaseDuration != 0 || created.InternalClient != "192.168.1.40" {
		t.Fatalf("mapping does not use the permanent LAN target: %#v", created)
	}
	if err = app.openServerUPnPMappings(context.Background(), server); err != nil {
		t.Fatal(err)
	}
	if gateway.adds != 1 || gateway.deletes != 0 {
		t.Fatalf("identical start repeated router changes: adds=%d deletes=%d", gateway.adds, gateway.deletes)
	}
}

func TestUPnPAddTimeoutRetainsOwnershipRecordUntilRouterCanBeChecked(t *testing.T) {
	app, d, _ := testApp(t)
	if _, err := d.Exec(`UPDATE upnp_settings SET enabled=1 WHERE id=1`); err != nil {
		t.Fatal(err)
	}
	seedUPnPServer(t, d, "uncertain-server", `{"game":25565,"rcon":25575}`)
	server, err := app.getServer("uncertain-server")
	if err != nil {
		t.Fatal(err)
	}
	gateway := &fakeUPnPGateway{
		localIP: net.ParseIP("192.168.1.40"), wanIP: net.ParseIP("203.0.113.9"),
		mappings: map[string]upnp.Mapping{}, addErr: errors.New("router response timed out"),
		applyOnAddError: true, getErrAfter: 2,
	}
	app.upnpDiscover = func(context.Context) (upnp.Gateway, error) { return gateway, nil }
	if err = app.openServerUPnPMappings(context.Background(), server); err == nil {
		t.Fatal("expected an uncertain add result")
	}
	tracked, err := app.listServerUPnPMappings(server.ID)
	if err != nil || len(tracked) != 1 {
		t.Fatalf("uncertain router outcome was not retained for safe cleanup: %#v err=%v", tracked, err)
	}
	gateway.getErrAfter = 0
	if err = app.removeServerUPnPMappings(context.Background(), server.ID, gateway); err != nil {
		t.Fatal(err)
	}
	if gateway.deletes != 1 || len(gateway.mappings) != 0 {
		t.Fatalf("verified owned mapping was not cleaned up: deletes=%d mappings=%#v", gateway.deletes, gateway.mappings)
	}
}

func TestUPnPConflictDoesNotReplaceAnExistingRouterRule(t *testing.T) {
	app, d, _ := testApp(t)
	if _, err := d.Exec(`UPDATE upnp_settings SET enabled=1 WHERE id=1`); err != nil {
		t.Fatal(err)
	}
	seedUPnPServer(t, d, "conflict-server", `{"game":25565,"rcon":25575}`)
	server, err := app.getServer("conflict-server")
	if err != nil {
		t.Fatal(err)
	}
	foreign := upnp.Mapping{ExternalPort: 25565, Protocol: "TCP", InternalPort: 25565, InternalClient: "192.168.1.22", Enabled: true, Description: "another application"}
	gateway := &fakeUPnPGateway{localIP: net.ParseIP("192.168.1.40"), wanIP: net.ParseIP("203.0.113.9"), mappings: map[string]upnp.Mapping{"TCP:25565": foreign}}
	app.upnpDiscover = func(context.Context) (upnp.Gateway, error) { return gateway, nil }
	err = app.openServerUPnPMappings(context.Background(), server)
	if err == nil || !strings.Contains(err.Error(), "does not own") {
		t.Fatalf("expected a foreign mapping conflict, got %v", err)
	}
	if gateway.adds != 0 || gateway.deletes != 0 || gateway.mappings["TCP:25565"].Description != "another application" {
		t.Fatalf("foreign router rule was changed: %#v", gateway)
	}
	tracked, listErr := app.listServerUPnPMappings(server.ID)
	if listErr != nil || len(tracked) != 0 {
		t.Fatalf("foreign mapping was incorrectly recorded as Docklight-owned: %#v err=%v", tracked, listErr)
	}
}

func TestUPnPCleanupDeletesOnlyMappingsThatStillMatchOwnershipRecord(t *testing.T) {
	app, d, _ := testApp(t)
	seedUPnPServer(t, d, "cleanup-server", `{"game":25565}`)
	server, err := app.getServer("cleanup-server")
	if err != nil {
		t.Fatal(err)
	}
	game, err := app.loadRune(server.GameskillID)
	if err != nil {
		t.Fatal(err)
	}
	record := desiredServerMappings(server, game, "192.168.1.40")[0]
	if err = app.saveUPnPRecord(record); err != nil {
		t.Fatal(err)
	}
	gateway := &fakeUPnPGateway{localIP: net.ParseIP("192.168.1.40"), wanIP: net.ParseIP("203.0.113.9"), mappings: map[string]upnp.Mapping{
		"TCP:25565": {ExternalPort: 25565, Protocol: "TCP", InternalPort: 25565, InternalClient: "192.168.1.40", Enabled: true, Description: "router admin changed this mapping"},
	}}
	if err = app.removeServerUPnPMappings(context.Background(), server.ID, gateway); err != nil {
		t.Fatal(err)
	}
	if gateway.deletes != 0 || gateway.mappings["TCP:25565"].Description != "router admin changed this mapping" {
		t.Fatalf("changed router mapping was deleted: %#v", gateway)
	}
	tracked, err := app.listServerUPnPMappings(server.ID)
	if err != nil || len(tracked) != 0 {
		t.Fatalf("stale ownership record was retained: %#v err=%v", tracked, err)
	}
	if err = app.saveUPnPRecord(record); err != nil {
		t.Fatal(err)
	}
	gateway.mappings["TCP:25565"] = upnp.Mapping{ExternalPort: record.ExternalPort, Protocol: record.Protocol, InternalPort: record.InternalPort, InternalClient: record.InternalClient, Enabled: true, Description: record.Description}
	if err = app.removeServerUPnPMappings(context.Background(), server.ID, gateway); err != nil {
		t.Fatal(err)
	}
	if gateway.deletes != 1 {
		t.Fatalf("owned router mapping was not deleted: deletes=%d", gateway.deletes)
	}
}

func TestGlobalUPnPSettingIsAdminOnlyAndDisabledByDefault(t *testing.T) {
	app, d, _ := testApp(t)
	adminToken := runeCatalogAdminToken(t, app, d)
	userHash, err := security.HashPassword("upnp-user-password")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = d.Exec(`INSERT INTO users(id,username,password_hash,role) VALUES('upnp-user','upnp-user',?,'user')`, userHash); err != nil {
		t.Fatal(err)
	}
	userToken, err := app.issue(User{ID: "upnp-user", Username: "upnp-user", Role: "user"})
	if err != nil {
		t.Fatal(err)
	}
	userRead := testRequest(app.Router(), http.MethodGet, "/api/settings/upnp", "", userToken)
	if userRead.Code != http.StatusForbidden {
		t.Fatalf("non-admin read returned %d: %s", userRead.Code, userRead.Body.String())
	}
	initial := testRequest(app.Router(), http.MethodGet, "/api/settings/upnp", "", adminToken)
	if initial.Code != http.StatusOK || !strings.Contains(initial.Body.String(), `"enabled":false`) {
		t.Fatalf("UPnP did not start disabled: %d %s", initial.Code, initial.Body.String())
	}
	userUpdate := testRequest(app.Router(), http.MethodPut, "/api/settings/upnp", `{"enabled":true}`, userToken)
	if userUpdate.Code != http.StatusForbidden {
		t.Fatalf("non-admin update returned %d: %s", userUpdate.Code, userUpdate.Body.String())
	}
	adminUpdate := testRequest(app.Router(), http.MethodPut, "/api/settings/upnp", `{"enabled":true}`, adminToken)
	if adminUpdate.Code != http.StatusOK || !strings.Contains(adminUpdate.Body.String(), `"enabled":true`) {
		t.Fatalf("admin update returned %d: %s", adminUpdate.Code, adminUpdate.Body.String())
	}
	var enabled int
	if err = d.QueryRow(`SELECT enabled FROM upnp_settings WHERE id=1`).Scan(&enabled); err != nil || enabled != 1 {
		t.Fatalf("admin setting was not saved: enabled=%d err=%v", enabled, err)
	}
}

func TestUPnPStatusReportsRouterAndOwnedMappingCounts(t *testing.T) {
	app, d, _ := testApp(t)
	adminToken := runeCatalogAdminToken(t, app, d)
	if _, err := d.Exec(`UPDATE upnp_settings SET enabled=1 WHERE id=1`); err != nil {
		t.Fatal(err)
	}
	seedUPnPServer(t, d, "status-server", `{"game":25565}`)
	server, err := app.getServer("status-server")
	if err != nil {
		t.Fatal(err)
	}
	game, err := app.loadRune(server.GameskillID)
	if err != nil {
		t.Fatal(err)
	}
	if err = app.saveUPnPRecord(desiredServerMappings(server, game, "192.168.1.40")[0]); err != nil {
		t.Fatal(err)
	}
	app.upnpDiscover = func(context.Context) (upnp.Gateway, error) {
		return &fakeUPnPGateway{localIP: net.ParseIP("192.168.1.40"), wanIP: net.ParseIP("203.0.113.9"), mappings: map[string]upnp.Mapping{}}, nil
	}
	response := testRequest(app.Router(), http.MethodGet, "/api/upnp/status", "", adminToken)
	for _, expected := range []string{`"enabled":true`, `"available":true`, `"lan_ip":"192.168.1.40"`, `"wan_ip":"203.0.113.9"`, `"owned_mappings":1`, `"pending_cleanup":0`} {
		if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), expected) {
			t.Fatalf("UPnP status missing %s: %d %s", expected, response.Code, response.Body.String())
		}
	}
}

func TestServerUPnPPreferenceRequiresServerControlAndDefaultsOn(t *testing.T) {
	app, d, _ := testApp(t)
	adminToken := runeCatalogAdminToken(t, app, d)
	userHash, err := security.HashPassword("upnp-preference-user-password")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = d.Exec(`INSERT INTO users(id,username,password_hash,role) VALUES('upnp-pref-user','upnp-pref-user',?,'user')`, userHash); err != nil {
		t.Fatal(err)
	}
	userToken, err := app.issue(User{ID: "upnp-pref-user", Username: "upnp-pref-user", Role: "user"})
	if err != nil {
		t.Fatal(err)
	}
	seedUPnPServer(t, d, "preference-server", `{"game":25565}`)
	initial := testRequest(app.Router(), http.MethodGet, "/api/servers/preference-server/upnp", "", adminToken)
	if initial.Code != http.StatusOK || !strings.Contains(initial.Body.String(), `"auto_forward":true`) || !strings.Contains(initial.Body.String(), `"global_enabled":false`) {
		t.Fatalf("server forwarding defaults are wrong: %d %s", initial.Code, initial.Body.String())
	}
	denied := testRequest(app.Router(), http.MethodPut, "/api/servers/preference-server/upnp", `{"auto_forward":false}`, userToken)
	if denied.Code != http.StatusForbidden {
		t.Fatalf("user without server.control changed forwarding: %d %s", denied.Code, denied.Body.String())
	}
	saved := testRequest(app.Router(), http.MethodPut, "/api/servers/preference-server/upnp", `{"auto_forward":false}`, adminToken)
	if saved.Code != http.StatusOK || !strings.Contains(saved.Body.String(), `"auto_forward":false`) {
		t.Fatalf("server preference was not saved: %d %s", saved.Code, saved.Body.String())
	}
	var enabled int
	if err = d.QueryRow(`SELECT auto_forward FROM servers WHERE id='preference-server'`).Scan(&enabled); err != nil || enabled != 0 {
		t.Fatalf("server preference was not persisted: enabled=%d err=%v", enabled, err)
	}
}

func seedUPnPServer(t *testing.T, d *sql.DB, id, ports string) {
	t.Helper()
	if _, err := d.Exec(`INSERT INTO servers(id,name,gameskill_id,status,installed,env_json,ports_json,data_dir,auto_forward)
		VALUES(?,?,'minecraft-java','running',1,'{}',?,'/tmp/docklight-upnp-test',1)`, id, id, ports); err != nil {
		t.Fatal(err)
	}
}
