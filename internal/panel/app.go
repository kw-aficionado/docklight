package panel

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"example.com/yggdrasil-panel"
	"example.com/yggdrasil-panel/internal/config"
	"example.com/yggdrasil-panel/internal/docker"
	"example.com/yggdrasil-panel/internal/rune"
	"example.com/yggdrasil-panel/internal/security"
	"example.com/yggdrasil-panel/internal/upnp"
	"github.com/go-chi/chi/v5"
)

type App struct {
	cfg                   config.Config
	configPath            string
	db                    *sql.DB
	engine                *docker.Engine
	dataRoot              string
	updateDir             string
	backupRoot            string
	backupStoreFactory    func(backupTargetConfig) (backupObjectStore, error)
	booted                time.Time
	dataMu                sync.Mutex
	scheduleMu            sync.Mutex
	scheduleRestart       func(context.Context, string, bool, int) (string, error)
	scheduleControl       func(context.Context, string, string) (string, string, error)
	scheduleUpdate        func(context.Context, string) (string, error)
	scheduleReady         func(context.Context, string, time.Duration) error
	schedulePlayers       func(context.Context, string) (int, error)
	scheduleWait          func(context.Context, time.Duration) error
	scheduleCommand       func(context.Context, Server, string) error
	notificationClient    *http.Client
	runeCatalogHTTPClient *http.Client
	runeCatalogMu         sync.Mutex
	runeCatalogCache      map[string]runeCatalogCacheEntry
	runtimeMu             sync.Mutex
	runtimePending        map[string]pendingRuntimeIncident
	runtimeInspect        func(context.Context, string) (docker.Inspect, error)
	runtimePing           func(context.Context) error
	diskAlertMu           sync.Mutex
	diskProbe             func(string) (diskUsage, error)
	watchdogMu            sync.Mutex
	watchdogStates        map[string]*watchdogRuntimeState
	watchdogQuery         func(context.Context, Server, rune.Rune) error
	watchdogHeal          func(context.Context, Server) error
	watchdogStart         func(context.Context, Server) error
	watchdogWait          func(context.Context, time.Duration) error
	statusMu              sync.Mutex
	statusCache           []byte
	statusCacheUntil      time.Time
	version               string
	releaseRepo           string
	releaseMu             sync.Mutex
	releaseCache          releaseCacheEntry
	updateRequestMu       sync.Mutex
	beaconSendMu          sync.Mutex
	beaconMu              sync.Mutex
	beaconCountCache      *beaconCountResponse
	beaconCountCacheUntil time.Time
	networkMu             sync.Mutex
	blockingMu            sync.Mutex
	upnpMu                sync.Mutex
	unifiMu               sync.Mutex
	npmMu                 sync.Mutex
	cfMu                  sync.Mutex
	networkDetected       string
	networkDetectedAt     time.Time
	networkAttemptAt      time.Time
	networkHTTPClient     *http.Client
	upnpDiscover          func(context.Context) (upnp.Gateway, error)
	unifiHTTPClient       *http.Client
	hostLocalIP           func(context.Context, string) (net.IP, error)
	npmHTTPClient         *http.Client
	cfHTTPClient          *http.Client
	cfAPIBaseURL          string
	reachabilityMu        sync.Mutex
	reachabilityCache     map[string]reachabilityCacheEntry
	reachabilityProbe     func(context.Context, string, int, rune.Rune) error
	domainProbeMu         sync.Mutex
	domainProbeCache      map[string]domainProbeCacheEntry
	rateMu                sync.Mutex
	loginIPs              map[string][]time.Time
	loginUsers            map[string][]time.Time
	forgotAttempts        map[string][]time.Time
	passkeyMu             sync.Mutex
	passkeyCeremonies     map[string]passkeyCeremony
	passkeyIPs            map[string][]time.Time
	passwordResetSender   func(context.Context, notificationChannelConfig, string, string) error
	passwordResetWG       sync.WaitGroup
	jobsMu                sync.RWMutex
	jobs                  map[string]*installJob
}

type User struct {
	ID              string          `json:"id"`
	Username        string          `json:"username"`
	Email           string          `json:"-"`
	Role            string          `json:"role"`
	Disabled        bool            `json:"disabled"`
	TokenVersion    int             `json:"-"`
	TotpSecret      string          `json:"-"`
	TotpEnabled     bool            `json:"totp_enabled"`
	TotpLastCounter int64           `json:"-"`
	IsAPIToken      bool            `json:"-"`
	APIScopes       map[string]bool `json:"-"`
}
type principalKey struct{}

func New(c config.Config, configPath string, d *sql.DB) *App {
	root := filepath.Dir(c.Database.Path)
	_ = os.MkdirAll(filepath.Join(root, "servers"), 0700)
	backupRoot := c.Backups.Path
	if backupRoot == "" {
		backupRoot = filepath.Join(root, "backups")
	} else if !filepath.IsAbs(backupRoot) {
		backupRoot = filepath.Join(root, backupRoot)
	}
	if absolute, err := filepath.Abs(backupRoot); err == nil {
		backupRoot = absolute
	}
	if resolved, err := resolvedPath(backupRoot); err == nil {
		backupRoot = resolved
	}
	return &App{cfg: c, configPath: configPath, db: d, engine: docker.New(c.Docker.Socket, c.Docker.APIVersion), dataRoot: filepath.Join(root, "servers"), updateDir: root, backupRoot: backupRoot, booted: time.Now(), version: "dev", loginIPs: map[string][]time.Time{}, loginUsers: map[string][]time.Time{}, forgotAttempts: map[string][]time.Time{}, passkeyCeremonies: map[string]passkeyCeremony{}, passkeyIPs: map[string][]time.Time{}, jobs: map[string]*installJob{}, runtimePending: map[string]pendingRuntimeIncident{}, watchdogStates: map[string]*watchdogRuntimeState{}, reachabilityCache: map[string]reachabilityCacheEntry{}}
}

func (a *App) SetBuildVersion(version string) {
	version = strings.TrimSpace(version)
	if version != "" {
		a.version = version
	}
}

func EnsureAdmin(d *sql.DB, username, password string) (string, error) {
	var count int
	if err := d.QueryRow(`SELECT count(*) FROM users WHERE role='admin' AND disabled=0`).Scan(&count); err != nil {
		return "", err
	}
	if count > 0 {
		return "", nil
	}
	if username == "" {
		username = "admin"
	}
	generated := ""
	if password == "" {
		var err error
		generated, err = config.Password()
		if err != nil {
			return "", err
		}
		password = generated
	}
	hash, err := security.HashPassword(password)
	if err != nil {
		return "", err
	}
	id, err := newID()
	if err != nil {
		return "", err
	}
	_, err = d.Exec(`INSERT INTO users(id,username,password_hash,role) VALUES(?,?,?,'admin')`, id, username, hash)
	return generated, err
}
func UpsertBuiltins(d *sql.DB) error {
	files, err := yggdrasil.BuiltinRunes.ReadDir("builtin-runes")
	if err != nil {
		return err
	}
	for _, f := range files {
		b, e := yggdrasil.BuiltinRunes.ReadFile("builtin-runes/" + f.Name())
		if e != nil {
			return e
		}
		r, e := rune.Parse(string(b))
		if e != nil {
			return fmt.Errorf("built-in %s: %w", f.Name(), e)
		}
		_, e = d.Exec(`INSERT INTO gameskills(id,name,category,version,yaml_blob,builtin) VALUES(?,?,?,?,?,1) ON CONFLICT(id) DO UPDATE SET name=excluded.name,category=excluded.category,version=excluded.version,yaml_blob=excluded.yaml_blob,builtin=1`, r.ID, r.Name, r.Category, r.Version, string(b))
		if e != nil {
			return e
		}
	}
	return nil
}

func (a *App) Router() http.Handler {
	r := chi.NewRouter()
	r.Use(a.headers)
	r.Get("/", a.static("web/index.html", "text/html; charset=utf-8"))
	r.Get("/app.js", a.static("web/app.js", "text/javascript; charset=utf-8"))
	r.Get("/ui-utils.mjs", a.static("web/ui-utils.mjs", "text/javascript; charset=utf-8"))
	r.Get("/style.css", a.static("web/style.css", "text/css; charset=utf-8"))
	r.Get("/config-editor.css", a.static("web/config-editor.css", "text/css; charset=utf-8"))
	r.Get("/status", a.publicStatusPage)
	r.Get("/status.js", a.publicStatusScript)
	r.Get("/manifest.webmanifest", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 200, map[string]any{"name": "Docklight", "short_name": "Docklight", "start_url": "/", "display": "standalone", "background_color": "#0d1417", "theme_color": "#0d1417", "icons": []map[string]string{{"src": "/brand.svg", "sizes": "any", "type": "image/svg+xml", "purpose": "any maskable"}}})
	})
	r.Get("/brand.svg", a.static("web/brand.svg", "image/svg+xml"))
	r.Route("/api", func(api chi.Router) {
		api.Get("/status", a.publicStatusJSON)
		api.Post("/beacon", a.receiveBeacon)
		api.Get("/beacon/count", a.publicBeaconCount)
		api.Get("/health", func(w http.ResponseWriter, r *http.Request) {
			writeJSON(w, 200, map[string]string{"status": "ok", "version": a.version})
		})
		api.Get("/version", a.getVersionInfo)
		api.Post("/login", a.login)
		api.Post("/auth/login", a.login)
		api.Post("/auth/forgot", a.forgotPassword)
		api.Post("/auth/reset", a.resetPassword)
		api.Post("/auth/passkey/login/begin", a.passkeyLoginBegin)
		api.Post("/auth/passkey/login/finish", a.passkeyLoginFinish)
		api.Post("/logout", a.auth(a.logout))
		api.Post("/password", a.auth(a.changePassword))
		api.Get("/me", a.auth(a.me))
		api.Get("/auth/me", a.auth(a.me))
		api.Get("/2fa/status", a.auth(a.totpStatus))
		api.Post("/2fa/setup", a.auth(a.totpSetup))
		api.Post("/2fa/enable", a.auth(a.totpEnable))
		api.Post("/2fa/disable", a.auth(a.totpDisable))
		api.Get("/tokens", a.auth(a.listAPITokens))
		api.Post("/tokens", a.auth(a.createAPIToken))
		api.Delete("/tokens/{id}", a.auth(a.deleteAPIToken))
		api.Get("/passkeys", a.auth(a.listPasskeys))
		api.Post("/passkeys/register/begin", a.auth(a.passkeyRegistrationBegin))
		api.Post("/passkeys/register/finish", a.auth(a.passkeyRegistrationFinish))
		api.Put("/passkeys/{id}", a.auth(a.renamePasskey))
		api.Delete("/passkeys/{id}", a.auth(a.deletePasskey))
		api.Group(func(priv chi.Router) {
			priv.Use(func(next http.Handler) http.Handler {
				return a.auth(func(w http.ResponseWriter, r *http.Request) { next.ServeHTTP(w, r) })
			})
			priv.Get("/gameskills", a.listRunes)
			priv.Get("/gameskills/{id}", a.getRune)
			priv.Get("/gameskills/github", a.admin(a.browseGitHubCatalog))
			priv.Get("/gameskills/updates", a.admin(a.checkRuneUpdates))
			priv.Get("/realms", a.listRealms)
			priv.Post("/realms", a.admin(a.createRealm))
			priv.Post("/realms/reorder", a.admin(a.reorderRealms))
			priv.Put("/realms/{id}/collapsed", a.updateRealmCollapsed)
			priv.Put("/realms/{id}", a.admin(a.updateRealm))
			priv.Delete("/realms/{id}", a.admin(a.deleteRealm))
			priv.Post("/gameskills", a.uploadRune)
			priv.Post("/gameskills/import-compose", a.importCompose)
			priv.Post("/gameskills/import-egg", a.importEgg)
			priv.Post("/gameskills/import-xml", a.importXML)
			priv.Post("/gameskills/install-from-github", a.admin(a.installGitHubRune))
			priv.Delete("/gameskills/{id}", a.deleteRune)
			priv.Get("/rune-repos", a.admin(a.listRuneRepos))
			priv.Post("/rune-repos", a.admin(a.createRuneRepo))
			priv.Get("/rune-repos/{id}/browse", a.admin(a.browseSavedRuneRepo))
			priv.Post("/rune-repos/{id}/install", a.admin(a.installSavedRuneRepo))
			priv.Put("/rune-repos/{id}", a.admin(a.updateRuneRepo))
			priv.Delete("/rune-repos/{id}", a.admin(a.deleteRuneRepo))
			priv.Get("/settings/github", a.admin(a.getGitHubCatalogSettings))
			priv.Put("/settings/github", a.admin(a.updateGitHubCatalogSettings))
			priv.Get("/registry-logins", a.admin(a.listRegistryLogins))
			priv.Post("/registry-logins", a.admin(a.saveRegistryLogin))
			priv.Delete("/registry-logins/{id}", a.admin(a.deleteRegistryLogin))
			priv.Post("/registry-logins/{id}/test", a.admin(a.testRegistryLogin))
			priv.Get("/message-templates", a.listMessageTemplates)
			priv.Post("/message-templates", a.admin(a.createMessageTemplate))
			priv.Put("/message-templates/{id}", a.admin(a.updateMessageTemplate))
			priv.Delete("/message-templates/{id}", a.admin(a.deleteMessageTemplate))
			priv.Get("/schedules", a.admin(a.listScopedSchedules))
			priv.Post("/schedules", a.admin(a.createScopedSchedule))
			priv.Put("/schedules/{scheduleID}", a.admin(a.updateScopedSchedule))
			priv.Delete("/schedules/{scheduleID}", a.admin(a.deleteScopedSchedule))
			priv.Get("/schedules/{scheduleID}/runs", a.admin(a.listScopedScheduleRuns))
			priv.Post("/schedules/{scheduleID}/run-now", a.admin(a.runScheduleNow))
			priv.Get("/servers", a.listServers)
			priv.Post("/servers", a.createServer)
			priv.Put("/servers/{id}/realm", a.admin(a.moveServerRealm))
			priv.Get("/servers/{id}", a.getServerHandler)
			priv.Put("/servers/{id}", a.updateServer)
			priv.Get("/servers/{id}/host-mounts", a.admin(a.getServerHostMounts))
			priv.Put("/servers/{id}/host-mounts", a.admin(a.updateServerHostMounts))
			priv.Delete("/servers/{id}", a.deleteServer)
			priv.Get("/servers/{id}/backups", a.listBackups)
			priv.Post("/servers/{id}/backups", a.createBackup)
			priv.Post("/servers/{id}/backups/prune", a.pruneBackups)
			priv.Post("/servers/{id}/backups/{backupID}/verify", a.verifyBackup)
			priv.Post("/servers/{id}/backups/{backupID}/restore", a.restoreBackup)
			priv.Delete("/servers/{id}/backups/{backupID}", a.deleteBackup)
			priv.Get("/servers/{id}/schedules", a.listBackupSchedules)
			priv.Get("/servers/{id}/schedule-options", a.scheduleOptions)
			priv.Post("/servers/{id}/schedules", a.createBackupSchedule)
			priv.Put("/servers/{id}/schedules/{scheduleID}", a.updateBackupSchedule)
			priv.Delete("/servers/{id}/schedules/{scheduleID}", a.deleteBackupSchedule)
			priv.Get("/servers/{id}/schedules/{scheduleID}/runs", a.listBackupScheduleRuns)
			priv.Get("/servers/{id}/crashes", a.listServerCrashes)
			priv.Put("/servers/{id}/watchdog", a.updateWatchdogSettings)
			priv.Get("/servers/{id}/upnp", a.getServerUPnPSettingsHandler)
			priv.Put("/servers/{id}/upnp", a.updateServerUPnPSettings)
			priv.Get("/notifications", a.admin(a.getNotificationSettings))
			priv.Put("/notifications", a.admin(a.updateNotificationSettings))
			priv.Post("/notifications/test", a.admin(a.testNotification))
			priv.Post("/notifications", a.admin(a.createNotificationChannel))
			priv.Put("/notifications/{id}", a.admin(a.updateNotificationChannel))
			priv.Delete("/notifications/{id}", a.admin(a.deleteNotificationChannel))
			priv.Post("/notifications/{id}/test", a.admin(a.testNotificationChannel))
			priv.Get("/settings/status-page", a.admin(a.getStatusPageSettings))
			priv.Put("/settings/status-page", a.admin(a.updateStatusPageSettings))
			priv.Get("/settings/beacon", a.admin(a.getBeaconSettings))
			priv.Put("/settings/beacon", a.admin(a.updateBeaconSettings))
			priv.Post("/settings/beacon/notice", a.admin(a.ackBeaconNotice))
			priv.Post("/settings/beacon/test", a.admin(a.testBeacon))
			priv.Get("/beacon/stats", a.admin(a.beaconStats))
			priv.Get("/system/update-status", a.admin(a.getPanelUpdateStatus))
			priv.Post("/system/update", a.admin(a.requestPanelUpdateHandler))
			priv.Post("/system/check-update", a.admin(a.checkPanelUpdateNow))
			priv.Get("/system/auto-update", a.admin(a.getAutoUpdateSettings))
			priv.Put("/system/auto-update", a.admin(a.updateAutoUpdateSettings))
			priv.Get("/settings/network", a.getNetworkSettings)
			priv.Put("/settings/network", a.admin(a.updateNetworkSettings))
			priv.Get("/settings/upnp", a.admin(a.getUPnPSettings))
			priv.Put("/settings/upnp", a.admin(a.updateUPnPSettings))
			priv.Get("/upnp/status", a.admin(a.getUPnPStatus))
			priv.Get("/settings/unifi", a.admin(a.getUniFiSettings))
			priv.Put("/settings/unifi", a.admin(a.updateUniFiSettings))
			priv.Post("/unifi/test", a.admin(a.testUniFiConnection))
			priv.Get("/unifi/rules", a.admin(a.listUniFiRules))
			priv.Get("/unifi/strays", a.admin(a.listUniFiStrayRules))
			priv.Post("/unifi/strays/delete", a.admin(a.deleteUniFiStrayRules))
			priv.Get("/settings/npm", a.admin(a.getNPMSettings))
			priv.Put("/settings/npm", a.admin(a.updateNPMSettings))
			priv.Post("/npm/test", a.admin(a.testNPMConnection))
			priv.Get("/settings/cloudflare", a.admin(a.getCloudflareSettings))
			priv.Put("/settings/cloudflare", a.admin(a.updateCloudflareSettings))
			priv.Get("/settings/blocking", a.admin(a.getBlockingSettings))
			priv.Put("/settings/blocking", a.admin(a.updateBlockingSettings))
			priv.Get("/blocks", a.admin(a.listBlockedIPs))
			priv.Post("/blocks", a.admin(a.createBlockedIP))
			priv.Delete("/blocks/{id}", a.admin(a.deleteBlockedIP))
			priv.Post("/cloudflare/test", a.admin(a.testCloudflareConnection))
			priv.Get("/domains/cloudflare", a.admin(a.listCloudflareDomains))
			priv.Get("/servers/{id}/npm", a.getServerNPMSettings)
			priv.Put("/servers/{id}/npm", a.updateServerNPMSettings)
			priv.Get("/servers/{id}/cloudflare", a.getServerCloudflareSettings)
			priv.Put("/servers/{id}/cloudflare", a.updateServerCloudflareSettings)
			priv.Get("/servers/{id}/routes", a.listServerRoutes)
			priv.Post("/servers/{id}/routes", a.admin(a.createServerRoute))
			priv.Delete("/servers/{id}/routes/{routeID}", a.admin(a.deleteServerRoute))
			priv.Get("/domains", a.listDomains)
			priv.Get("/backups/target/status", a.backupTargetStatus)
			priv.Get("/backups/target", a.admin(a.getBackupTarget))
			priv.Put("/backups/target", a.admin(a.updateBackupTarget))
			priv.Post("/backups/target/test", a.admin(a.testBackupTarget))
			priv.Get("/system/disk", a.admin(a.getDiskStatus))
			priv.Get("/host/mounts", a.admin(a.listHostMountDirectories))
			priv.Get("/host/browse", a.admin(a.browseHostMountDirectories))
			priv.Post("/servers/{id}/install", a.installServer)
			priv.Get("/servers/{id}/install/status", a.installStatus)
			priv.Post("/servers/{id}/start", a.startServer)
			priv.Post("/servers/{id}/stop", a.stopServer)
			priv.Post("/servers/{id}/restart", a.restartServer)
			priv.Get("/servers/{id}/stats", a.serverStats)
			priv.Get("/servers/{id}/query", a.serverQuery)
			priv.Get("/servers/{id}/reachability", a.serverReachability)
			priv.Post("/servers/{id}/rcon", a.serverRCON)
			priv.Get("/servers/{id}/logs", a.logsWS)
			priv.Get("/servers/{id}/stack-services/{service}/logs", a.stackServiceLogsWS)
			priv.Post("/servers/{id}/stack-services/{service}/exec", a.execStackService)
			priv.Get("/servers/{id}/console", a.consoleWS)
			priv.Get("/servers/{id}/install/log", a.installWS)
			priv.Get("/servers/{id}/files", a.fileList)
			priv.Get("/servers/{id}/files/content", a.fileRead)
			priv.Put("/servers/{id}/files/content", a.fileWrite)
			priv.Delete("/servers/{id}/files/content", a.fileDelete)
			priv.Post("/servers/{id}/files/mkdir", a.fileMkdir)
			priv.Post("/servers/{id}/files/upload", a.fileUpload)
			priv.Get("/servers/{id}/files/download", a.fileDownload)
			priv.Get("/audit", a.auditList)
			priv.Get("/users", a.admin(a.listUsers))
			priv.Post("/users", a.admin(a.createUser))
			priv.Put("/users/{id}", a.admin(a.updateUser))
			priv.Delete("/users/{id}", a.admin(a.deleteUser))
			priv.Put("/users/{id}/permissions", a.admin(a.setPermissions))
			priv.Get("/users/{id}/permissions", a.admin(a.getPermissions))
			priv.Get("/permissions/catalog", func(w http.ResponseWriter, r *http.Request) { writeJSON(w, 200, permissionCatalog) })
		})
		api.NotFound(func(w http.ResponseWriter, r *http.Request) { writeError(w, 404, "API route not found") })
	})
	r.NotFound(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/api/") {
			writeError(w, 404, "API route not found")
			return
		}
		http.ServeFileFS(w, r, yggdrasil.WebFS, "web/index.html")
	})
	return r
}

func (a *App) headers(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self' ws: wss:; object-src 'none'; base-uri 'self'; frame-ancestors 'none'")
		if r.URL.Path == "/robots.txt" || r.URL.Path == "/app.js" || r.URL.Path == "/style.css" || r.URL.Path == "/config-editor.css" {
			w.Header().Set("Cache-Control", "public, max-age=60")
		}
		if strings.HasPrefix(r.URL.Path, "/api/") {
			w.Header().Set("Cache-Control", "no-store")
		}
		if r.URL.Path == "/" && r.URL.Query().Has("reset") {
			w.Header().Set("Cache-Control", "no-store")
		}
		next.ServeHTTP(w, r)
	})
}
func (a *App) static(file, contentType string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		b, err := yggdrasil.WebFS.ReadFile(file)
		if err != nil {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", contentType)
		cacheControl := "no-cache"
		if r.URL.Path == "/" && r.URL.Query().Has("reset") {
			cacheControl = "no-store"
		}
		w.Header().Set("Cache-Control", cacheControl)
		w.WriteHeader(200)
		_, _ = w.Write(b)
	}
}

func (a *App) login(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Username string `json:"username"`
		Password string `json:"password"`
		TOTP     string `json:"totp"`
	}
	if decodeJSON(w, r, &in, 64*1024) != nil {
		return
	}
	ip := clientIP(r)
	now := time.Now()
	a.rateMu.Lock()
	a.loginIPs[ip] = recent(a.loginIPs[ip], now.Add(-time.Minute))
	a.loginUsers[strings.ToLower(in.Username)] = recent(a.loginUsers[strings.ToLower(in.Username)], now.Add(-15*time.Minute))
	if len(a.loginIPs[ip]) >= 5 || len(a.loginUsers[strings.ToLower(in.Username)]) >= 10 {
		a.rateMu.Unlock()
		writeError(w, 429, "too many sign-in attempts; wait a few minutes and try again")
		return
	}
	a.rateMu.Unlock()
	var u User
	var hash string
	var disabled int
	err := a.db.QueryRow(`SELECT id,username,role,disabled,token_version,totp_secret,totp_enabled,totp_last_counter,password_hash FROM users WHERE username=?`, in.Username).Scan(&u.ID, &u.Username, &u.Role, &disabled, &u.TokenVersion, &u.TotpSecret, &u.TotpEnabled, &u.TotpLastCounter, &hash)
	if err != nil || disabled != 0 || !security.VerifyPassword(hash, in.Password) {
		a.recordLoginFailure(ip, in.Username)
		writeError(w, 401, "invalid username or password")
		return
	}
	u.Disabled = false
	if u.TotpEnabled {
		secret, decryptErr := security.Decrypt([]byte(a.cfg.Auth.SecretKey), u.TotpSecret)
		counter, ok := security.VerifyTOTP(secret, in.TOTP, now)
		if decryptErr != nil || !ok {
			a.recordLoginFailure(ip, in.Username)
			writeError(w, 401, "a valid six-digit authenticator code is required")
			return
		}
		if counter <= u.TotpLastCounter {
			a.recordLoginFailure(ip, in.Username)
			writeError(w, 401, "this authenticator code was already used; wait for the next code")
			return
		}
		res, updateErr := a.db.Exec(`UPDATE users SET totp_last_counter=? WHERE id=? AND totp_last_counter<?`, counter, u.ID, counter)
		updated, rowsErr := int64(0), updateErr
		if updateErr == nil {
			updated, rowsErr = res.RowsAffected()
		}
		if rowsErr != nil || updated != 1 {
			a.recordLoginFailure(ip, in.Username)
			writeError(w, 401, "this authenticator code was already used; wait for the next code")
			return
		}
	}
	token, err := a.issue(u)
	if err != nil {
		writeError(w, 500, "could not create sign-in session")
		return
	}
	a.clearLoginFailures(ip, in.Username)
	http.SetCookie(w, &http.Cookie{Name: "ygg_token", Value: token, Path: "/", HttpOnly: true, Secure: requestScheme(r) == "https", SameSite: http.SameSiteStrictMode, Expires: time.Now().Add(time.Duration(a.cfg.Auth.SessionTTLHours) * time.Hour)})
	writeJSON(w, 200, map[string]any{"token": token, "user": u})
}
func (a *App) recordLoginFailure(ip, user string) {
	a.rateMu.Lock()
	defer a.rateMu.Unlock()
	now := time.Now()
	a.loginIPs[ip] = append(recent(a.loginIPs[ip], now.Add(-time.Minute)), now)
	k := strings.ToLower(user)
	a.loginUsers[k] = append(recent(a.loginUsers[k], now.Add(-15*time.Minute)), now)
}
func (a *App) clearLoginFailures(ip, user string) {
	a.rateMu.Lock()
	delete(a.loginUsers, strings.ToLower(user))
	a.rateMu.Unlock()
}
func recent(a []time.Time, after time.Time) []time.Time {
	n := a[:0]
	for _, t := range a {
		if t.After(after) {
			n = append(n, t)
		}
	}
	return n
}
func (a *App) issue(u User) (string, error) {
	id, err := newID()
	if err != nil {
		return "", err
	}
	now := time.Now()
	return security.SignJWT([]byte(a.cfg.Auth.SecretKey), security.Claims{UserID: u.ID, Role: u.Role, Version: u.TokenVersion, Expires: now.Add(time.Duration(a.cfg.Auth.SessionTTLHours) * time.Hour).Unix(), Issued: now.Unix(), ID: id}), nil
}
func (a *App) auth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if mutating(r.Method) {
			if origin := r.Header.Get("Origin"); origin != "" {
				if !sameOrigin(r, origin) {
					writeError(w, 403, "cross-origin request blocked")
					return
				}
			}
		}
		authorization := strings.TrimSpace(r.Header.Get("Authorization"))
		token := strings.TrimSpace(strings.TrimPrefix(authorization, "Bearer "))
		if token == "" {
			if c, e := r.Cookie("ygg_token"); e == nil {
				token = c.Value
			}
		}
		var u User
		var disabled int
		if strings.HasPrefix(token, "ygg_") && strings.HasPrefix(authorization, "Bearer ") {
			var rawScopes string
			err := a.db.QueryRow(`SELECT u.id,u.username,u.role,u.disabled,u.token_version,u.totp_secret,u.totp_enabled,u.totp_last_counter,t.scope FROM api_tokens t JOIN users u ON u.id=t.user_id WHERE t.token_hash=?`, security.APIKeyHash(token)).Scan(&u.ID, &u.Username, &u.Role, &disabled, &u.TokenVersion, &u.TotpSecret, &u.TotpEnabled, &u.TotpLastCounter, &rawScopes)
			if err != nil || disabled != 0 {
				writeError(w, 401, "unauthorized")
				return
			}
			u.IsAPIToken = true
			u.APIScopes = map[string]bool{}
			for _, scope := range strings.Split(rawScopes, ",") {
				if scope = strings.TrimSpace(scope); scope != "" {
					u.APIScopes[scope] = true
				}
			}
			_, _ = a.db.Exec(`UPDATE api_tokens SET last_used_at=CURRENT_TIMESTAMP WHERE token_hash=?`, security.APIKeyHash(token))
		} else {
			claims, err := security.ParseJWT([]byte(a.cfg.Auth.SecretKey), token)
			if err != nil {
				writeError(w, 401, "unauthorized")
				return
			}
			err = a.db.QueryRow(`SELECT id,username,role,disabled,token_version,totp_secret,totp_enabled,totp_last_counter FROM users WHERE id=?`, claims.UserID).Scan(&u.ID, &u.Username, &u.Role, &disabled, &u.TokenVersion, &u.TotpSecret, &u.TotpEnabled, &u.TotpLastCounter)
			if err != nil || disabled != 0 || u.TokenVersion != claims.Version {
				writeError(w, 401, "session expired")
				return
			}
		}
		u.Disabled = false
		next(w, r.WithContext(context.WithValue(r.Context(), principalKey{}, u)))
	}
}

func sameOrigin(r *http.Request, origin string) bool {
	actual, err := canonicalWebOrigin(origin)
	if err != nil {
		return false
	}
	expected, err := canonicalWebOrigin(requestScheme(r) + "://" + r.Host)
	return err == nil && actual == expected
}

func requestScheme(r *http.Request) string {
	if r.TLS != nil {
		return "https"
	}
	forwarded := strings.TrimSpace(strings.Split(r.Header.Get("X-Forwarded-Proto"), ",")[0])
	if strings.EqualFold(forwarded, "https") {
		return "https"
	}
	return "http"
}

func (a *App) admin(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		u := principal(r)
		if u.Role != "admin" || u.IsAPIToken && !u.APIScopes["admin"] {
			writeError(w, 403, "admin required")
			return
		}
		a.recordRecentAdminIP(r)
		next(w, r)
	}
}
func principal(r *http.Request) User { u, _ := r.Context().Value(principalKey{}).(User); return u }
func (a *App) me(w http.ResponseWriter, r *http.Request) {
	u := principal(r)
	writeJSON(w, 200, map[string]any{"id": u.ID, "username": u.Username, "role": u.Role, "totp_enabled": u.TotpEnabled, "server_count": a.visibleServerCount(u)})
}
func (a *App) logout(w http.ResponseWriter, r *http.Request) {
	u := principal(r)
	if u.IsAPIToken {
		writeError(w, 400, "API tokens are revoked from account settings")
		return
	}
	_, _ = a.db.Exec(`UPDATE users SET token_version=token_version+1 WHERE id=?`, u.ID)
	http.SetCookie(w, &http.Cookie{Name: "ygg_token", Value: "", Path: "/", HttpOnly: true, SameSite: http.SameSiteStrictMode, MaxAge: -1, Expires: time.Unix(1, 0)})
	writeJSON(w, 200, map[string]bool{"ok": true})
}

func (a *App) totpStatus(w http.ResponseWriter, r *http.Request) {
	u := principal(r)
	if u.IsAPIToken {
		writeError(w, 403, "sign in with your account to manage two-factor authentication")
		return
	}
	writeJSON(w, 200, map[string]bool{"enabled": u.TotpEnabled})
}
func (a *App) totpSetup(w http.ResponseWriter, r *http.Request) {
	u := principal(r)
	if u.IsAPIToken {
		writeError(w, 403, "sign in with your account to manage two-factor authentication")
		return
	}
	if u.TotpEnabled {
		writeError(w, 409, "two-factor authentication is already enabled")
		return
	}
	secret, err := security.NewTOTPSecret()
	if err != nil {
		writeError(w, 500, "could not generate an authenticator secret")
		return
	}
	encrypted, err := security.Encrypt([]byte(a.cfg.Auth.SecretKey), secret)
	if err != nil {
		writeError(w, 500, "could not store the authenticator secret")
		return
	}
	_, _ = a.db.Exec(`UPDATE users SET totp_secret=? WHERE id=?`, encrypted, u.ID)
	writeJSON(w, 200, map[string]string{"secret": secret, "otpauth_url": security.TOTPURI("Docklight", u.Username, secret)})
}
func (a *App) totpEnable(w http.ResponseWriter, r *http.Request) {
	if principal(r).IsAPIToken {
		writeError(w, 403, "sign in with your account to manage two-factor authentication")
		return
	}
	var in struct {
		Code string `json:"code"`
	}
	if decodeJSON(w, r, &in, 4096) != nil {
		return
	}
	u := principal(r)
	secret, err := security.Decrypt([]byte(a.cfg.Auth.SecretKey), u.TotpSecret)
	if err != nil || u.TotpSecret == "" {
		writeError(w, 409, "start two-factor setup first")
		return
	}
	counter, ok := security.VerifyTOTP(secret, in.Code, time.Now())
	if !ok {
		writeError(w, 400, "authenticator code is invalid")
		return
	}
	_, err = a.db.Exec(`UPDATE users SET totp_enabled=1,totp_last_counter=? WHERE id=?`, counter, u.ID)
	if err != nil {
		writeError(w, 500, "could not enable two-factor authentication")
		return
	}
	a.audit(u, "auth.totp.enable", "user", u.ID, "")
	writeJSON(w, 200, map[string]bool{"enabled": true})
}
func (a *App) totpDisable(w http.ResponseWriter, r *http.Request) {
	if principal(r).IsAPIToken {
		writeError(w, 403, "sign in with your account to manage two-factor authentication")
		return
	}
	var in struct {
		Code     string `json:"code"`
		Password string `json:"password"`
	}
	if decodeJSON(w, r, &in, 4096) != nil {
		return
	}
	u := principal(r)
	var hash string
	if err := a.db.QueryRow(`SELECT password_hash FROM users WHERE id=?`, u.ID).Scan(&hash); err != nil || !security.VerifyPassword(hash, in.Password) {
		writeError(w, 401, "password confirmation failed")
		return
	}
	secret, err := security.Decrypt([]byte(a.cfg.Auth.SecretKey), u.TotpSecret)
	if err != nil {
		writeError(w, 400, "enter a valid authenticator code")
		return
	}
	counter, ok := security.VerifyTOTP(secret, in.Code, time.Now())
	if !ok || counter <= u.TotpLastCounter {
		writeError(w, 400, "enter the current unused authenticator code")
		return
	}
	_, _ = a.db.Exec(`UPDATE users SET totp_secret='',totp_enabled=0,totp_last_counter=-1,token_version=token_version+1 WHERE id=?`, u.ID)
	a.audit(u, "auth.totp.disable", "user", u.ID, "")
	writeJSON(w, 200, map[string]bool{"enabled": false})
}

func (a *App) listRunes(w http.ResponseWriter, r *http.Request) {
	rows, err := a.db.Query(`SELECT id,name,category,version,yaml_blob,builtin,source_host,source_repo FROM gameskills ORDER BY category,name`)
	if err != nil {
		writeError(w, 500, "could not list templates")
		return
	}
	type row struct {
		id, name, category, yaml, sourceHost, sourceRepo string
		version, builtin                                 int
	}
	all := []row{}
	for rows.Next() {
		var x row
		if rows.Scan(&x.id, &x.name, &x.category, &x.version, &x.yaml, &x.builtin, &x.sourceHost, &x.sourceRepo) == nil {
			all = append(all, x)
		}
	}
	_ = rows.Close()
	out := []map[string]any{}
	u := principal(r)
	for _, x := range all {
		if !a.allowedRune(u, "server.create", x.id) {
			continue
		}
		rr, _ := rune.Parse(x.yaml)
		rr = publicRune(rr)
		item := map[string]any{"id": x.id, "name": x.name, "category": x.category, "version": x.version, "builtin": x.builtin != 0, "can_create_default": a.allowedRuneScope(u, "server.create", x.id), "description": rr.Description, "author": rr.Author, "icon": rr.Icon, "variables": rr.Variables, "ports": rr.Ports, "query": rr.Query, "config_files": rr.ConfigFiles}
		if u.Role == "admin" {
			item["source_host"], item["source_repo"] = x.sourceHost, x.sourceRepo
		}
		out = append(out, item)
	}
	writeJSON(w, 200, out)
}
func (a *App) getRune(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	var raw string
	if e := a.db.QueryRow(`SELECT yaml_blob FROM gameskills WHERE id=?`, id).Scan(&raw); e != nil {
		writeError(w, 404, "template not found")
		return
	}
	u := principal(r)
	if !a.allowedRune(u, "server.create", id) {
		writeError(w, 403, "insufficient permissions")
		return
	}
	gs, e := rune.Parse(raw)
	if e != nil {
		writeError(w, 500, "stored template is invalid; review or re-import it")
		return
	}
	writeJSON(w, 200, publicRune(gs))
}
func (a *App) uploadRune(w http.ResponseWriter, r *http.Request) {
	if !a.requireAdmin(w, r) {
		return
	}
	b, e := io.ReadAll(http.MaxBytesReader(w, r.Body, 512*1024))
	if e != nil {
		writeError(w, 400, "template exceeds the 512 KiB upload limit")
		return
	}
	gs, e := rune.Parse(string(b))
	if e != nil {
		writeError(w, 400, e.Error())
		return
	}
	var builtin int
	_ = a.db.QueryRow(`SELECT builtin FROM gameskills WHERE id=?`, gs.ID).Scan(&builtin)
	if builtin != 0 {
		writeError(w, 409, "built-in templates cannot be overwritten")
		return
	}
	_, e = a.db.Exec(`INSERT INTO gameskills(id,name,category,version,yaml_blob,builtin) VALUES(?,?,?,?,?,0) ON CONFLICT(id) DO UPDATE SET name=excluded.name,category=excluded.category,version=excluded.version,yaml_blob=excluded.yaml_blob,source_host='',source_repo='',source_path='',source_ref=''`, gs.ID, gs.Name, gs.Category, gs.Version, string(b))
	if e != nil {
		writeError(w, 500, "could not save template")
		return
	}
	a.audit(principal(r), "template.save", "gameskill", gs.ID, "")
	writeJSON(w, 201, map[string]any{"id": gs.ID, "name": gs.Name})
}
func (a *App) deleteRune(w http.ResponseWriter, r *http.Request) {
	if !a.requireAdmin(w, r) {
		return
	}
	id := chi.URLParam(r, "id")
	var used, builtin int
	if e := a.db.QueryRow(`SELECT count(*) FROM servers WHERE gameskill_id=?`, id).Scan(&used); e != nil {
		writeError(w, 500, "could not check template usage")
		return
	}
	if used > 0 {
		writeError(w, 409, "this template is used by one or more servers; delete those servers first")
		return
	}
	_ = a.db.QueryRow(`SELECT builtin FROM gameskills WHERE id=?`, id).Scan(&builtin)
	if builtin != 0 {
		writeError(w, 409, "built-in templates cannot be deleted in this release")
		return
	}
	if _, e := a.db.Exec(`DELETE FROM gameskills WHERE id=?`, id); e != nil {
		writeError(w, 500, "could not delete template")
		return
	}
	a.audit(principal(r), "template.delete", "gameskill", id, "")
	writeJSON(w, 200, map[string]bool{"ok": true})
}

func (a *App) requireAdmin(w http.ResponseWriter, r *http.Request) bool {
	u := principal(r)
	if u.Role != "admin" || u.IsAPIToken && !u.APIScopes["admin"] {
		writeError(w, 403, "admin required")
		return false
	}
	return true
}
func (a *App) audit(u User, action, typ, id, detail string) {
	_, err := a.db.Exec(`INSERT INTO audit_log(user_id,username,action,target_type,target_id,detail) VALUES(?,?,?,?,?,?)`, u.ID, u.Username, action, typ, id, detail)
	if err != nil {
		log.Printf("audit write failed for action %s", action)
	}
}
func (a *App) auditList(w http.ResponseWriter, r *http.Request) {
	u := principal(r)
	if u.Role != "admin" || u.IsAPIToken && !u.APIScopes["admin"] {
		writeError(w, 403, "admin required")
		return
	}
	rows, e := a.db.Query(`SELECT at,username,action,target_type,target_id,detail FROM audit_log ORDER BY id DESC LIMIT 200`)
	if e != nil {
		writeError(w, 500, "could not read audit history")
		return
	}
	defer rows.Close()
	out := []map[string]string{}
	for rows.Next() {
		var at, user, action, t, id, detail string
		if rows.Scan(&at, &user, &action, &t, &id, &detail) == nil {
			out = append(out, map[string]string{"at": at, "username": user, "action": action, "target_type": t, "target_id": id, "detail": detail})
		}
	}
	writeJSON(w, 200, out)
}

var permissionCatalog = []string{"server.view", "server.control", "server.console", "server.files", "server.backup", "server.schedule", "server.create", "server.delete"}

func (a *App) visibleServerCount(u User) int {
	if u.Role == "admin" && (!u.IsAPIToken || u.APIScopes["server.view"]) {
		var n int
		_ = a.db.QueryRow(`SELECT count(*) FROM servers`).Scan(&n)
		return n
	}
	rows, e := a.db.Query(`SELECT id,gameskill_id,realm_id FROM servers`)
	if e != nil {
		return 0
	}
	type row struct{ id, runeID, realmID string }
	all := []row{}
	for rows.Next() {
		var x row
		if rows.Scan(&x.id, &x.runeID, &x.realmID) == nil {
			all = append(all, x)
		}
	}
	_ = rows.Close()
	n := 0
	for _, x := range all {
		if a.allowedServer(u, "server.view", x.id, x.runeID, x.realmID) {
			n++
		}
	}
	return n
}
func (a *App) allowedRune(u User, perm, runeID string) bool {
	if a.allowedRuneScope(u, perm, runeID) {
		return true
	}
	if u.IsAPIToken && !u.APIScopes[perm] {
		return false
	}
	if u.Role == "admin" {
		return true
	}
	if perm != "server.create" {
		return false
	}
	rows, err := a.db.Query(`SELECT id FROM realms`)
	if err != nil {
		return false
	}
	ids := []string{}
	for rows.Next() {
		var id string
		if rows.Scan(&id) == nil {
			ids = append(ids, id)
		}
	}
	_ = rows.Close()
	for _, id := range ids {
		if a.allowedRealmCreate(u, id) {
			return true
		}
	}
	return false
}
func (a *App) allowedRuneScope(u User, perm, runeID string) bool {
	if u.IsAPIToken && !u.APIScopes[perm] {
		return false
	}
	if u.Role == "admin" {
		return true
	}
	return a.grant(u.ID, perm, "global", "") || a.grant(u.ID, perm, "gameskill", runeID)
}
func (a *App) allowedRealmCreate(u User, realmID string) bool {
	if u.IsAPIToken && !u.APIScopes["server.create"] {
		return false
	}
	if u.Role == "admin" {
		return true
	}
	return a.grant(u.ID, "server.create", "global", "") || a.grant(u.ID, "server.create", "realm", realmID)
}
func (a *App) allowedServer(u User, perm, serverID, runeID string, realmIDs ...string) bool {
	if u.IsAPIToken && !u.APIScopes[perm] {
		return false
	}
	if u.Role == "admin" {
		return true
	}
	realmID := ""
	if len(realmIDs) != 0 {
		realmID = realmIDs[0]
	}
	return a.grant(u.ID, perm, "global", "") ||
		(realmID != "" && a.grant(u.ID, perm, "realm", realmID)) ||
		a.grant(u.ID, perm, "gameskill", runeID) ||
		a.grant(u.ID, perm, "server", serverID)
}
func (a *App) grant(uid, perm, scope, id string) bool {
	var raw string
	e := a.db.QueryRow(`SELECT perms FROM permissions WHERE user_id=? AND scope_type=? AND scope_id=?`, uid, scope, id).Scan(&raw)
	if e != nil {
		return false
	}
	for _, p := range strings.Split(raw, ",") {
		if strings.TrimSpace(p) == perm {
			return true
		}
	}
	return false
}
func (a *App) getServer(id string) (Server, error) {
	var s Server
	var env, ports, hostMounts string
	var installed int
	var watchdogEnabled, watchdogQuarantined, autoForward int
	err := a.db.QueryRow(`SELECT id,name,gameskill_id,realm_id,status,installed,env_json,ports_json,data_dir,container_id,cpu_limit,memory_limit_mb,created_at,error_message,watchdog_enabled,watchdog_quarantined,host_mounts,auto_forward FROM servers WHERE id=?`, id).Scan(&s.ID, &s.Name, &s.GameskillID, &s.RealmID, &s.Status, &installed, &env, &ports, &s.DataDir, &s.ContainerID, &s.CPULimit, &s.MemoryLimitMB, &s.CreatedAt, &s.ErrorMessage, &watchdogEnabled, &watchdogQuarantined, &hostMounts, &autoForward)
	if err != nil {
		return s, err
	}
	s.Installed = installed != 0
	s.WatchdogEnabled = watchdogEnabled != 0
	s.WatchdogQuarantined = watchdogQuarantined != 0
	s.AutoForward = autoForward != 0
	if json.Unmarshal([]byte(env), &s.Env) != nil {
		s.Env = map[string]string{}
	}
	if json.Unmarshal([]byte(ports), &s.Ports) != nil {
		s.Ports = map[string]int{}
	}
	if err := json.Unmarshal([]byte(hostMounts), &s.HostMounts); err != nil {
		return Server{}, fmt.Errorf("stored host mounts are invalid")
	}
	if s.HostMounts == nil {
		s.HostMounts = []HostMount{}
	}
	return s, nil
}

func decodeJSON(w http.ResponseWriter, r *http.Request, dst any, max int64) error {
	r.Body = http.MaxBytesReader(w, r.Body, max)
	defer r.Body.Close()
	dec := json.NewDecoder(r.Body)
	if err := dec.Decode(dst); err != nil {
		writeError(w, 400, "invalid JSON request")
		return err
	}
	return nil
}
func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}
func writeError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, map[string]string{"error": message})
}
func mutating(m string) bool {
	return m == http.MethodPost || m == http.MethodPut || m == http.MethodPatch || m == http.MethodDelete
}
func newID() (string, error) {
	var b [16]byte
	if _, e := rand.Read(b[:]); e != nil {
		return "", e
	}
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	s := hex.EncodeToString(b[:])
	return s[:8] + "-" + s[8:12] + "-" + s[12:16] + "-" + s[16:20] + "-" + s[20:], nil
}
func clientIP(r *http.Request) string {
	host, _, e := net.SplitHostPort(r.RemoteAddr)
	if e == nil {
		return host
	}
	return r.RemoteAddr
}
