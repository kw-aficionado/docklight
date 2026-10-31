package panel

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"example.com/yggdrasil-panel/internal/rune"
)

func TestHostMountValidationResolvesSourcesAndProtectsTargets(t *testing.T) {
	a, _, _ := testApp(t)
	gs, err := a.loadRune("cloudflared")
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	source := filepath.Join(root, "library")
	if err = os.Mkdir(source, 0700); err != nil {
		t.Fatal(err)
	}
	alias := filepath.Join(root, "library-alias")
	if err = os.Symlink(source, alias); err != nil {
		t.Fatal(err)
	}
	mounts, err := a.validateHostMounts(gs, []HostMount{{Source: alias, Target: "/mnt/library"}})
	if err != nil {
		t.Fatalf("valid symlinked source was rejected: %v", err)
	}
	resolved, _ := filepath.EvalSymlinks(source)
	if len(mounts) != 1 || mounts[0].Source != resolved || mounts[0].Write {
		t.Fatalf("source was not canonicalized or read-only by default: %#v", mounts)
	}

	blockedTargets := []string{"/", "/data", "/data/media", "/etc", "/proc/config", "/usr/share", "/var/lib/app", "/tmp/cache"}
	for _, target := range blockedTargets {
		if _, err = a.validateHostMounts(gs, []HostMount{{Source: source, Target: target}}); err == nil {
			t.Errorf("protected target %q was accepted", target)
		}
	}
	for _, sourcePath := range []string{"/", "/etc", a.dataRoot, a.backupRoot} {
		if _, err = a.validateHostMounts(gs, []HostMount{{Source: sourcePath, Target: "/mnt/private"}}); err == nil {
			t.Errorf("protected source %q was accepted", sourcePath)
		}
	}
	blockedAlias := filepath.Join(root, "etc-alias")
	if err = os.Symlink("/etc", blockedAlias); err != nil {
		t.Fatal(err)
	}
	if _, err = a.validateHostMounts(gs, []HostMount{{Source: blockedAlias, Target: "/mnt/private"}}); err == nil {
		t.Fatal("symlink to a protected source was accepted")
	}
	if _, err = a.validateHostMounts(gs, []HostMount{{Source: source, Target: "/mnt/library"}, {Source: source, Target: "/mnt/library/cache"}}); err == nil {
		t.Fatal("overlapping mount targets were accepted")
	}
	stackRune := gs
	stackRune.Stack = &rune.Stack{Services: []rune.Service{{Name: "database", Image: "mariadb:11", DataPath: "/var/lib/mysql"}}}
	stackMounts, err := a.validateHostMounts(stackRune, []HostMount{{Source: source, Target: "/mnt/shared"}, {Source: source, Target: "/mnt/shared", Service: "database", Write: true}})
	if err != nil || len(stackMounts) != 2 {
		t.Fatalf("separate containers could not use the same mount target: mounts=%#v err=%v", stackMounts, err)
	}
	if _, err = a.validateHostMounts(stackRune, []HostMount{{Source: source, Target: "/var/lib/mysql/config", Service: "database"}}); err == nil {
		t.Fatal("sidecar mount shadowed its persistent data path")
	}
	if _, err = a.validateHostMounts(stackRune, []HostMount{{Source: source, Target: "/mnt/shared", Service: "missing"}}); err == nil {
		t.Fatal("mount to an unknown stack service was accepted")
	}
}

func TestHostMountRuntimeBindsAreReadOnlyUnlessWriteIsEnabled(t *testing.T) {
	a, _, _ := testApp(t)
	gs, err := a.loadRune("cloudflared")
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	sourceRO := filepath.Join(root, "read-only")
	sourceRW := filepath.Join(root, "read-write")
	for _, dir := range []string{sourceRO, sourceRW} {
		if err = os.Mkdir(dir, 0700); err != nil {
			t.Fatal(err)
		}
	}
	canonicalRO, err := filepath.EvalSymlinks(sourceRO)
	if err != nil {
		t.Fatal(err)
	}
	canonicalRW, err := filepath.EvalSymlinks(sourceRW)
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := a.containerConfig(Server{
		ID: "host-mount-runtime", DataDir: filepath.Join(root, "server-data"),
		HostMounts: []HostMount{{Source: sourceRO, Target: "/mnt/ro"}, {Source: sourceRW, Target: "/mnt/rw", Write: true}},
	}, gs, map[string]string{})
	if err != nil {
		t.Fatal(err)
	}
	has := func(expected string) bool {
		for _, bind := range cfg.HostConfig.Binds {
			if bind == expected {
				return true
			}
		}
		return false
	}
	if !has(canonicalRO+":/mnt/ro:ro") || !has(canonicalRW+":/mnt/rw") {
		t.Fatalf("runtime binds did not preserve read-only defaults and explicit write: %#v", cfg.HostConfig.Binds)
	}
}

func TestHostMountRoutesAreAdminOnlyAndDoNotLeakThroughServerViews(t *testing.T) {
	a, d, _ := testApp(t)
	adminToken := runeCatalogAdminToken(t, a, d)
	if _, err := d.Exec(`INSERT INTO users(id,username,password_hash,role) VALUES('mount-viewer','mount-viewer','unused-hash','user')`); err != nil {
		t.Fatal(err)
	}
	viewer, err := a.issue(User{ID: "mount-viewer", Username: "mount-viewer", Role: "user"})
	if err != nil {
		t.Fatal(err)
	}
	serverData := filepath.Join(a.dataRoot, "host-mount-server")
	if err = os.MkdirAll(serverData, 0700); err != nil {
		t.Fatal(err)
	}
	if _, err = d.Exec(`INSERT INTO servers(id,name,gameskill_id,status,installed,env_json,ports_json,data_dir) VALUES('host-mount-server','Mount server','cloudflared','stopped',1,'{}','{}',?)`, serverData); err != nil {
		t.Fatal(err)
	}
	if _, err = d.Exec(`INSERT INTO permissions(user_id,scope_type,scope_id,perms) VALUES('mount-viewer','server','host-mount-server','server.view')`); err != nil {
		t.Fatal(err)
	}
	source := t.TempDir()
	canonicalSource, err := filepath.EvalSymlinks(source)
	if err != nil {
		t.Fatal(err)
	}
	body, err := json.Marshal(hostMountsInput{Mounts: []HostMount{{Source: source, Target: "/mnt/library"}}})
	if err != nil {
		t.Fatal(err)
	}
	h := a.Router()
	saved := testRequest(h, http.MethodPut, "/api/servers/host-mount-server/host-mounts", string(body), adminToken)
	if saved.Code != http.StatusOK || !strings.Contains(saved.Body.String(), canonicalSource) {
		t.Fatalf("admin could not save mount: %d %s", saved.Code, saved.Body.String())
	}
	for _, tc := range []struct{ method, path, body string }{
		{http.MethodGet, "/api/servers/host-mount-server/host-mounts", ""},
		{http.MethodPut, "/api/servers/host-mount-server/host-mounts", `{"mounts":[]}`},
		{http.MethodGet, "/api/host/mounts", ""},
		{http.MethodGet, "/api/host/browse?path=%2F", ""},
	} {
		denied := testRequest(h, tc.method, tc.path, tc.body, viewer)
		if denied.Code != http.StatusForbidden {
			t.Errorf("non-admin %s %s: status=%d body=%s", tc.method, tc.path, denied.Code, denied.Body.String())
		}
	}
	view := testRequest(h, http.MethodGet, "/api/servers/host-mount-server", "", viewer)
	if view.Code != http.StatusOK || strings.Contains(view.Body.String(), canonicalSource) || strings.Contains(view.Body.String(), "host_mounts") {
		t.Fatalf("ordinary server view leaked host paths: %d %s", view.Code, view.Body.String())
	}
	list := testRequest(h, http.MethodGet, "/api/servers", "", viewer)
	if list.Code != http.StatusOK || strings.Contains(list.Body.String(), canonicalSource) {
		t.Fatalf("ordinary server list leaked host paths: %d %s", list.Code, list.Body.String())
	}
	loaded := testRequest(h, http.MethodGet, "/api/servers/host-mount-server/host-mounts", "", adminToken)
	if loaded.Code != http.StatusOK || !strings.Contains(loaded.Body.String(), `"applies_on":"next_start"`) || !strings.Contains(loaded.Body.String(), canonicalSource) {
		t.Fatalf("admin mount retrieval failed: %d %s", loaded.Code, loaded.Body.String())
	}
	roots := testRequest(h, http.MethodGet, "/api/host/mounts", "", adminToken)
	if roots.Code != http.StatusOK || !strings.Contains(roots.Body.String(), `"mounts":`) {
		t.Fatalf("admin host mount roots were unavailable: %d %s", roots.Code, roots.Body.String())
	}
	browse := testRequest(h, http.MethodGet, "/api/host/browse?path=%2F", "", adminToken)
	if browse.Code != http.StatusOK || !strings.Contains(browse.Body.String(), `"can_mount":false`) {
		t.Fatalf("admin host root browse did not safely report browse-only root: %d %s", browse.Code, browse.Body.String())
	}
}

func TestHostMountBrowserSkipsProtectedDirectories(t *testing.T) {
	a, _, _ := testApp(t)
	root := t.TempDir()
	allowed := filepath.Join(root, "allowed")
	if err := os.Mkdir(allowed, 0700); err != nil {
		t.Fatal(err)
	}
	alias := filepath.Join(root, "protected")
	if err := os.Symlink("/etc", alias); err != nil {
		t.Fatal(err)
	}
	if _, err := a.canonicalHostMountSource(allowed); err != nil {
		t.Fatalf("allowed folder was not mountable: %v", err)
	}
	if _, err := a.canonicalHostMountSource(alias); err == nil {
		t.Fatal("browser-visible symlink escaped into a protected path")
	}
	parent := filepath.Dir(a.dataRoot)
	if _, err := a.resolveHostBrowsePath(parent); err != nil {
		t.Fatalf("folder browser could not traverse a parent of Docklight storage: %v", err)
	}
	if _, err := a.resolveHostBrowsePath(a.dataRoot); err == nil {
		t.Fatal("host folder browser exposed Docklight's own server data directory")
	}
	if _, err := a.resolveHostBrowsePath("/etc"); err == nil {
		t.Fatal("host folder browser exposed a protected system directory")
	}
}
