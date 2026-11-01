package db

import (
	"database/sql"
	"path/filepath"
	"testing"

	_ "modernc.org/sqlite"
)

func TestOpenMigratesExistingSchemaAndRecordsVersions(t *testing.T) {
	path := filepath.Join(t.TempDir(), "panel.db")
	legacy, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = legacy.Exec(schema); err != nil {
		t.Fatal(err)
	}
	if _, err = legacy.Exec(`INSERT INTO gameskills(id,name,category,yaml_blob) VALUES('legacy-game','Legacy Game','Games','')`); err != nil {
		t.Fatal(err)
	}
	if _, err = legacy.Exec(`CREATE TABLE server_backups (
		id TEXT PRIMARY KEY,
		server_id TEXT NOT NULL,
		size_bytes INTEGER NOT NULL,
		sha256 TEXT NOT NULL,
		files INTEGER NOT NULL,
		directories INTEGER NOT NULL,
		data_bytes INTEGER NOT NULL,
		created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
	)`); err != nil {
		t.Fatal(err)
	}
	if _, err = legacy.Exec(`INSERT INTO server_backups(id,server_id,size_bytes,sha256,files,directories,data_bytes) VALUES('legacy-backup','legacy-server',10,'hash',1,0,8)`); err != nil {
		t.Fatal(err)
	}
	if _, err = legacy.Exec(`CREATE TABLE backup_schedules (
		id TEXT PRIMARY KEY,
		server_id TEXT NOT NULL,
		name TEXT NOT NULL,
		cron TEXT NOT NULL,
		enabled INTEGER NOT NULL DEFAULT 1,
		next_run TEXT NOT NULL DEFAULT '',
		last_run TEXT NOT NULL DEFAULT '',
		last_status TEXT NOT NULL DEFAULT '',
		last_error TEXT NOT NULL DEFAULT '',
		created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
	)`); err != nil {
		t.Fatal(err)
	}
	if _, err = legacy.Exec(`INSERT INTO backup_schedules(id,server_id,name,cron) VALUES('legacy-schedule','legacy-server','Legacy backup','0 3 * * *')`); err != nil {
		t.Fatal(err)
	}
	if _, err = legacy.Exec(`INSERT INTO servers(id,name,gameskill_id,status,data_dir) VALUES('legacy-public-server','Legacy server','minecraft-java','running','/legacy/server')`); err != nil {
		t.Fatal(err)
	}
	if _, err = legacy.Exec(`INSERT INTO servers(id,name,gameskill_id,status,data_dir) VALUES('legacy-public-server-two','Legacy server two','legacy-game','stopped','/legacy/server-two')`); err != nil {
		t.Fatal(err)
	}
	if _, err = legacy.Exec(`INSERT INTO servers(id,name,gameskill_id,status,data_dir) VALUES('legacy-public-server-three','Legacy server three','legacy-game','stopped','/legacy/server-three')`); err != nil {
		t.Fatal(err)
	}
	if err = legacy.Close(); err != nil {
		t.Fatal(err)
	}

	d, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	var count int
	if err = d.QueryRow(`SELECT count(*) FROM schema_migrations`).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 49 {
		t.Fatalf("expected 49 migrations, got %d", count)
	}
	var logBaselineTable int
	if err = d.QueryRow(`SELECT count(*) FROM sqlite_master WHERE type='table' AND name='assistant_log_volume_baselines'`).Scan(&logBaselineTable); err != nil || logBaselineTable != 1 {
		t.Fatalf("version 49 log-volume baseline table missing: count=%d err=%v", logBaselineTable, err)
	}
	var watcherTable, watcherConsentColumn int
	if err = d.QueryRow(`SELECT count(*) FROM sqlite_master WHERE type='table' AND name='log_watchers'`).Scan(&watcherTable); err != nil {
		t.Fatal(err)
	}
	if err = d.QueryRow(`SELECT count(*) FROM pragma_table_info('log_watchers') WHERE name='advisory_host'`).Scan(&watcherConsentColumn); err != nil {
		t.Fatal(err)
	}
	if watcherTable != 1 || watcherConsentColumn != 1 {
		t.Fatalf("log watcher schema missing table or provider consent binding: table=%d consent=%d", watcherTable, watcherConsentColumn)
	}
	var proactiveTable int
	if err = d.QueryRow("SELECT count(*) FROM sqlite_master WHERE type='table' AND name='assistant_proactive_events'").Scan(&proactiveTable); err != nil || proactiveTable != 1 {
		t.Fatalf("proactive Advisory event table missing: count=%d err=%v", proactiveTable, err)
	}
	var mcpTables int
	if err = d.QueryRow("SELECT count(*) FROM sqlite_master WHERE type='table' AND name IN ('mcp_clients','mcp_authorization_requests','mcp_authorization_codes','mcp_connections','mcp_access_tokens','mcp_refresh_tokens')").Scan(&mcpTables); err != nil || mcpTables != 6 {
		t.Fatalf("MCP OAuth schema incomplete: tables=%d err=%v", mcpTables, err)
	}
	var assistantEnabled int
	var assistantProvider, assistantModel, assistantURL, assistantKey string
	if err = d.QueryRow(`SELECT enabled,provider,model,base_url,api_key_enc FROM assistant_config WHERE id=1`).Scan(&assistantEnabled, &assistantProvider, &assistantModel, &assistantURL, &assistantKey); err != nil {
		t.Fatalf("read default Assistant provider config: %v", err)
	}
	if assistantEnabled != 0 || assistantProvider != "" || assistantModel != "" || assistantURL != "" || assistantKey != "" {
		t.Fatalf("Assistant must start disabled and unconfigured: enabled=%d provider=%q model=%q url=%q key=%q", assistantEnabled, assistantProvider, assistantModel, assistantURL, assistantKey)
	}
	var digestEnabled, digestHour, actionsEnabled, proactiveLevel, chatDataLevel int
	var digestLastDay, proactiveTriggers string
	if err = d.QueryRow(`SELECT digest_enabled,digest_hour,digest_last_day,actions_enabled,proactive_level,proactive_triggers,chat_data_level FROM assistant_config WHERE id=1`).Scan(&digestEnabled, &digestHour, &digestLastDay, &actionsEnabled, &proactiveLevel, &proactiveTriggers, &chatDataLevel); err != nil {
		t.Fatalf("read future Assistant tier defaults: %v", err)
	}
	if digestEnabled != 0 || digestHour != 8 || digestLastDay != "" || actionsEnabled != 0 || proactiveLevel != 0 || proactiveTriggers != "crash,slowstart,resource,host" || chatDataLevel != 1 {
		t.Fatalf("Assistant defaults should remain safe and predictable: digest=%d/%d/%q actions=%d proactive=%d/%q data=%d", digestEnabled, digestHour, digestLastDay, actionsEnabled, proactiveLevel, proactiveTriggers, chatDataLevel)
	}
	var hostMountColumn int
	if err = d.QueryRow(`SELECT count(*) FROM pragma_table_info('servers') WHERE name='host_mounts'`).Scan(&hostMountColumn); err != nil || hostMountColumn != 1 {
		t.Fatalf("host mount migration is missing servers.host_mounts: count=%d err=%v", hostMountColumn, err)
	}
	var autoForward int
	if err = d.QueryRow(`SELECT auto_forward FROM servers WHERE id='legacy-public-server'`).Scan(&autoForward); err != nil || autoForward != 1 {
		t.Fatalf("UPnP per-server default should be enabled for migrated servers: value=%d err=%v", autoForward, err)
	}
	for _, column := range []string{"protocol", "port"} {
		var found int
		if err = d.QueryRow(`SELECT count(*) FROM pragma_table_info('backup_target_settings') WHERE name=?`, column).Scan(&found); err != nil || found != 1 {
			t.Fatalf("backup target migration is missing %q: count=%d err=%v", column, found, err)
		}
	}
	for _, column := range []string{"source_host", "source_repo", "source_path", "source_ref"} {
		var found int
		if err = d.QueryRow(`SELECT count(*) FROM pragma_table_info('gameskills') WHERE name=?`, column).Scan(&found); err != nil || found != 1 {
			t.Fatalf("catalog source migration is missing %q: count=%d err=%v", column, found, err)
		}
	}
	var modImportsColumn int
	if err = d.QueryRow(`SELECT count(*) FROM pragma_table_info('dayz_economy_settings') WHERE name='mod_imports_json'`).Scan(&modImportsColumn); err != nil || modImportsColumn != 1 {
		t.Fatalf("DayZ mod import migration is missing dayz_economy_settings.mod_imports_json: count=%d err=%v", modImportsColumn, err)
	}
	for _, table := range []string{"rune_repos", "github_catalog_settings", "registry_logins", "notification_channels", "password_reset_tokens", "passkey_credentials", "network_settings", "upnp_settings", "server_upnp_mappings", "server_upnp_state", "unifi_settings", "server_unifi_mappings", "server_unifi_state", "npm_settings", "server_npm_state", "cloudflare_settings", "server_cf_state", "blocking_settings", "blocked_ips", "admin_ip_history", "server_routes", "beacon_settings", "beacon_pings", "panel_update_settings", "bans", "violation_rules", "ban_server_state", "server_metrics", "host_metrics"} {
		var found int
		if err = d.QueryRow(`SELECT count(*) FROM sqlite_master WHERE type='table' AND name=?`, table).Scan(&found); err != nil || found != 1 {
			t.Fatalf("schema migration is missing table %q: count=%d err=%v", table, found, err)
		}
	}
	var autoForwardColumn int
	if err = d.QueryRow(`SELECT count(*) FROM pragma_table_info('servers') WHERE name='auto_forward'`).Scan(&autoForwardColumn); err != nil || autoForwardColumn != 1 {
		t.Fatalf("UPnP migration is missing servers.auto_forward: count=%d err=%v", autoForwardColumn, err)
	}
	var enabled int
	if err = d.QueryRow(`SELECT enabled FROM upnp_settings WHERE id=1`).Scan(&enabled); err != nil || enabled != 0 {
		t.Fatalf("UPnP must be disabled by default: enabled=%d err=%v", enabled, err)
	}
	if err = d.QueryRow(`SELECT enabled FROM unifi_settings WHERE id=1`).Scan(&enabled); err != nil || enabled != 0 {
		t.Fatalf("UniFi forwarding must be disabled by default: enabled=%d err=%v", enabled, err)
	}
	if err = d.QueryRow(`SELECT enabled FROM npm_settings WHERE id=1`).Scan(&enabled); err != nil || enabled != 0 {
		t.Fatalf("Nginx Proxy Manager integration must be disabled by default: enabled=%d err=%v", enabled, err)
	}
	var npmSubdomainColumn int
	if err = d.QueryRow(`SELECT count(*) FROM pragma_table_info('servers') WHERE name='npm_subdomain'`).Scan(&npmSubdomainColumn); err != nil || npmSubdomainColumn != 1 {
		t.Fatalf("Nginx Proxy Manager migration is missing servers.npm_subdomain: count=%d err=%v", npmSubdomainColumn, err)
	}
	var cleanupPendingColumn int
	if err = d.QueryRow(`SELECT count(*) FROM pragma_table_info('server_npm_state') WHERE name='cleanup_pending'`).Scan(&cleanupPendingColumn); err != nil || cleanupPendingColumn != 1 {
		t.Fatalf("Nginx Proxy Manager migration is missing cleanup_pending state: count=%d err=%v", cleanupPendingColumn, err)
	}
	var cfHostnameColumn int
	if err = d.QueryRow(`SELECT count(*) FROM pragma_table_info('servers') WHERE name='cf_hostname'`).Scan(&cfHostnameColumn); err != nil || cfHostnameColumn != 1 {
		t.Fatalf("Cloudflare migration is missing servers.cf_hostname: count=%d err=%v", cfHostnameColumn, err)
	}
	for _, column := range []string{"email", "webauthn_user_handle"} {
		var found int
		if err = d.QueryRow(`SELECT count(*) FROM pragma_table_info('users') WHERE name=?`, column).Scan(&found); err != nil || found != 1 {
			t.Fatalf("password reset migration is missing users.%q: count=%d err=%v", column, found, err)
		}
	}
	var sidecarTable string
	if err = d.QueryRow(`SELECT name FROM sqlite_master WHERE type='table' AND name='server_sidecars'`).Scan(&sidecarTable); err != nil || sidecarTable != "server_sidecars" {
		t.Fatalf("server sidecars table missing: name=%q err=%v", sidecarTable, err)
	}
	var notificationTable string
	if err = d.QueryRow(`SELECT name FROM sqlite_master WHERE type='table' AND name='notification_settings'`).Scan(&notificationTable); err != nil || notificationTable != "notification_settings" {
		t.Fatalf("notification settings table missing: name=%q err=%v", notificationTable, err)
	}
	var crashTable string
	if err = d.QueryRow(`SELECT name FROM sqlite_master WHERE type='table' AND name='server_crashes'`).Scan(&crashTable); err != nil || crashTable != "server_crashes" {
		t.Fatalf("server crash table missing: name=%q err=%v", crashTable, err)
	}
	var alertTable string
	if err = d.QueryRow(`SELECT name FROM sqlite_master WHERE type='table' AND name='system_alert_state'`).Scan(&alertTable); err != nil || alertTable != "system_alert_state" {
		t.Fatalf("system alert state table missing: name=%q err=%v", alertTable, err)
	}
	var publicColumn int
	if err = d.QueryRow(`SELECT count(*) FROM pragma_table_info('servers') WHERE name='status_public'`).Scan(&publicColumn); err != nil || publicColumn != 1 {
		t.Fatalf("version 18 did not add the per-server status-page opt-in: count=%d err=%v", publicColumn, err)
	}
	var legacyPublic int
	if err = d.QueryRow(`SELECT status_public FROM servers WHERE id='legacy-public-server'`).Scan(&legacyPublic); err != nil || legacyPublic != 0 {
		t.Fatalf("legacy server status-page opt-in defaulted to %d, err=%v", legacyPublic, err)
	}
	var legacyRealmName string
	if err = d.QueryRow(`SELECT r.name FROM servers s JOIN realms r ON r.id=s.realm_id WHERE s.id='legacy-public-server'`).Scan(&legacyRealmName); err != nil || legacyRealmName != "Default" {
		t.Fatalf("legacy server without a template realm name=%q err=%v, want Default", legacyRealmName, err)
	}
	var firstRealmID, secondRealmID, thirdRealmID string
	if err = d.QueryRow(`SELECT realm_id FROM servers WHERE id='legacy-public-server'`).Scan(&firstRealmID); err != nil {
		t.Fatal(err)
	}
	if err = d.QueryRow(`SELECT realm_id FROM servers WHERE id='legacy-public-server-two'`).Scan(&secondRealmID); err != nil || firstRealmID == secondRealmID {
		t.Fatalf("servers from different categories shared realm %q: second=%q err=%v", firstRealmID, secondRealmID, err)
	}
	if err = d.QueryRow(`SELECT realm_id FROM servers WHERE id='legacy-public-server-three'`).Scan(&thirdRealmID); err != nil || secondRealmID != thirdRealmID {
		t.Fatalf("servers from the same template category got realms %q and %q: err=%v", secondRealmID, thirdRealmID, err)
	}
	var legacyGameRealm string
	if err = d.QueryRow(`SELECT name FROM realms WHERE id=?`, secondRealmID).Scan(&legacyGameRealm); err != nil || legacyGameRealm != "Games" {
		t.Fatalf("legacy template category realm name=%q err=%v, want Games", legacyGameRealm, err)
	}
	var statusPageEnabled int
	var statusPageTitle string
	if err = d.QueryRow(`SELECT enabled,title FROM status_page_settings WHERE id=1`).Scan(&statusPageEnabled, &statusPageTitle); err != nil || statusPageEnabled != 0 || statusPageTitle != "Server Status" {
		t.Fatalf("status-page settings default enabled=%d title=%q err=%v", statusPageEnabled, statusPageTitle, err)
	}
	var querySampleTable int
	if err = d.QueryRow(`SELECT count(*) FROM sqlite_master WHERE type='table' AND name='server_query_samples'`).Scan(&querySampleTable); err != nil || querySampleTable != 1 {
		t.Fatalf("version 18 query sample table missing: count=%d err=%v", querySampleTable, err)
	}
	var watchdogColumns int
	if err = d.QueryRow(`SELECT count(*) FROM pragma_table_info('servers') WHERE name IN ('watchdog_enabled','watchdog_quarantined','watchdog_last_attempt')`).Scan(&watchdogColumns); err != nil || watchdogColumns != 3 {
		t.Fatalf("watchdog columns missing: count=%d err=%v", watchdogColumns, err)
	}
	var watchdogHealsTable int
	if err = d.QueryRow(`SELECT count(*) FROM sqlite_master WHERE type='table' AND name='server_watchdog_heals'`).Scan(&watchdogHealsTable); err != nil || watchdogHealsTable != 1 {
		t.Fatalf("watchdog heal history table missing: count=%d err=%v", watchdogHealsTable, err)
	}
	rows, err := d.Query(`PRAGMA table_info(servers)`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	found := false
	for rows.Next() {
		var cid, notnull, pk int
		var name, typ string
		var defaultValue any
		if err = rows.Scan(&cid, &name, &typ, &notnull, &defaultValue, &pk); err != nil {
			t.Fatal(err)
		}
		if name == "error_message" {
			found = true
		}
	}
	if !found {
		t.Fatal("version 2 did not add servers.error_message")
	}
	var backupsTable int
	if err = d.QueryRow(`SELECT count(*) FROM sqlite_master WHERE type='table' AND name='server_backups'`).Scan(&backupsTable); err != nil {
		t.Fatal(err)
	}
	if backupsTable != 1 {
		t.Fatalf("version 3 did not create server_backups, found %d tables", backupsTable)
	}
	var schedulesTable, runsTable int
	if err = d.QueryRow(`SELECT count(*) FROM sqlite_master WHERE type='table' AND name='backup_schedules'`).Scan(&schedulesTable); err != nil {
		t.Fatal(err)
	}
	if err = d.QueryRow(`SELECT count(*) FROM sqlite_master WHERE type='table' AND name='backup_schedule_runs'`).Scan(&runsTable); err != nil {
		t.Fatal(err)
	}
	if schedulesTable != 1 || runsTable != 1 {
		t.Fatalf("version 4 did not create schedule tables: schedules=%d runs=%d", schedulesTable, runsTable)
	}
	var scheduleColumns int
	if err = d.QueryRow(`SELECT count(*) FROM pragma_table_info('backup_schedules') WHERE name IN ('action','warn_players','warning_seconds','skip_if_players_online','command_enc','message_payload_enc','destination')`).Scan(&scheduleColumns); err != nil || scheduleColumns != 7 {
		t.Fatalf("version 10/11/12/13/17 schedule columns missing: count=%d err=%v", scheduleColumns, err)
	}
	var action, destination string
	var warnPlayers, warningSeconds, skipIfPlayersOnline int
	var commandEnc, messagePayloadEnc string
	if err = d.QueryRow(`SELECT action,warn_players,warning_seconds,skip_if_players_online,command_enc,message_payload_enc,destination FROM backup_schedules WHERE id='legacy-schedule'`).Scan(&action, &warnPlayers, &warningSeconds, &skipIfPlayersOnline, &commandEnc, &messagePayloadEnc, &destination); err != nil {
		t.Fatal(err)
	}
	if action != "backup" || warnPlayers != 0 || warningSeconds != 60 || skipIfPlayersOnline != 0 || commandEnc != "" || messagePayloadEnc != "" || destination != "local" {
		t.Fatalf("legacy backup schedule migrated as action=%q warn=%d seconds=%d skip=%d command_enc=%q message_payload_enc=%q destination=%q", action, warnPlayers, warningSeconds, skipIfPlayersOnline, commandEnc, messagePayloadEnc, destination)
	}
	var scopeType, scopeID string
	var runNow int
	if err = d.QueryRow(`SELECT scope_type,scope_id,run_now FROM backup_schedules WHERE id='legacy-schedule'`).Scan(&scopeType, &scopeID, &runNow); err != nil {
		t.Fatal(err)
	}
	if scopeType != "server" || scopeID != "legacy-server" || runNow != 0 {
		t.Fatalf("legacy schedule scope migrated incorrectly: type=%q id=%q run_now=%d", scopeType, scopeID, runNow)
	}
	var templates int
	if err = d.QueryRow(`SELECT count(*) FROM message_templates WHERE builtin=1`).Scan(&templates); err != nil || templates != 5 {
		t.Fatalf("version 13 should seed five built-in message templates, count=%d err=%v", templates, err)
	}
	var backupTargetTable int
	if err = d.QueryRow(`SELECT count(*) FROM sqlite_master WHERE type='table' AND name='backup_target_settings'`).Scan(&backupTargetTable); err != nil || backupTargetTable != 1 {
		t.Fatalf("version 14 did not create encrypted backup target settings: count=%d err=%v", backupTargetTable, err)
	}
	var backupStorageColumns int
	if err = d.QueryRow(`SELECT count(*) FROM pragma_table_info('server_backups') WHERE name IN ('storage','storage_key')`).Scan(&backupStorageColumns); err != nil || backupStorageColumns != 2 {
		t.Fatalf("version 14 did not add backup storage metadata: count=%d err=%v", backupStorageColumns, err)
	}
	var storage, storageKey string
	if err = d.QueryRow(`SELECT storage,storage_key FROM server_backups WHERE id='legacy-backup'`).Scan(&storage, &storageKey); err != nil {
		t.Fatal(err)
	}
	if storage != "local" || storageKey != "" {
		t.Fatalf("legacy backup location migrated as storage=%q key=%q", storage, storageKey)
	}
}
