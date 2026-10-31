package db

import (
	"database/sql"
	"fmt"
	_ "modernc.org/sqlite"
	"os"
	"path/filepath"
)

func Open(path string) (*sql.DB, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return nil, err
	}
	d, err := sql.Open("sqlite", path+"?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)&_pragma=foreign_keys(ON)")
	if err != nil {
		return nil, err
	}
	d.SetMaxOpenConns(1)
	if err = d.Ping(); err != nil {
		d.Close()
		return nil, err
	}
	if err = migrate(d); err != nil {
		d.Close()
		return nil, fmt.Errorf("migrate database: %w", err)
	}
	return d, nil
}

func migrate(d *sql.DB) error {
	if _, err := d.Exec(`CREATE TABLE IF NOT EXISTS schema_migrations (version INTEGER PRIMARY KEY, applied_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP)`); err != nil {
		return err
	}
	var version int
	if err := d.QueryRow(`SELECT COALESCE(MAX(version),0) FROM schema_migrations`).Scan(&version); err != nil {
		return err
	}
	if version < 1 {
		tx, err := d.Begin()
		if err != nil {
			return err
		}
		if _, err = tx.Exec(schema); err != nil {
			_ = tx.Rollback()
			return err
		}
		if _, err = tx.Exec(`INSERT INTO schema_migrations(version) VALUES(1)`); err != nil {
			_ = tx.Rollback()
			return err
		}
		if err = tx.Commit(); err != nil {
			return err
		}
		version = 1
	}
	if version < 2 {
		tx, err := d.Begin()
		if err != nil {
			return err
		}
		if !hasColumn(tx, "servers", "error_message") {
			if _, err = tx.Exec(`ALTER TABLE servers ADD COLUMN error_message TEXT NOT NULL DEFAULT ''`); err != nil {
				_ = tx.Rollback()
				return err
			}
		}
		if _, err = tx.Exec(`CREATE INDEX IF NOT EXISTS idx_api_tokens_user ON api_tokens(user_id)`); err != nil {
			_ = tx.Rollback()
			return err
		}
		if _, err = tx.Exec(`INSERT INTO schema_migrations(version) VALUES(2)`); err != nil {
			_ = tx.Rollback()
			return err
		}
		if err = tx.Commit(); err != nil {
			return err
		}
	}
	if version < 3 {
		tx, err := d.Begin()
		if err != nil {
			return err
		}
		if _, err = tx.Exec(`CREATE TABLE IF NOT EXISTS server_backups (
			id TEXT PRIMARY KEY,
			server_id TEXT NOT NULL,
			size_bytes INTEGER NOT NULL,
			sha256 TEXT NOT NULL,
			files INTEGER NOT NULL,
			directories INTEGER NOT NULL,
			data_bytes INTEGER NOT NULL,
			created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
		)`); err != nil {
			_ = tx.Rollback()
			return err
		}
		if _, err = tx.Exec(`CREATE INDEX IF NOT EXISTS idx_server_backups_recent ON server_backups(server_id, created_at DESC, id DESC)`); err != nil {
			_ = tx.Rollback()
			return err
		}
		if _, err = tx.Exec(`INSERT INTO schema_migrations(version) VALUES(3)`); err != nil {
			_ = tx.Rollback()
			return err
		}
		if err = tx.Commit(); err != nil {
			return err
		}
	}
	if version < 4 {
		tx, err := d.Begin()
		if err != nil {
			return err
		}
		if _, err = tx.Exec(`CREATE TABLE IF NOT EXISTS backup_schedules (
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
			_ = tx.Rollback()
			return err
		}
		if _, err = tx.Exec(`CREATE INDEX IF NOT EXISTS idx_backup_schedules_due ON backup_schedules(enabled, next_run)`); err != nil {
			_ = tx.Rollback()
			return err
		}
		if _, err = tx.Exec(`CREATE TABLE IF NOT EXISTS backup_schedule_runs (
			id TEXT PRIMARY KEY,
			schedule_id TEXT NOT NULL,
			server_id TEXT NOT NULL,
			started_at TEXT NOT NULL,
			finished_at TEXT NOT NULL DEFAULT '',
			status TEXT NOT NULL,
			detail TEXT NOT NULL DEFAULT ''
		)`); err != nil {
			_ = tx.Rollback()
			return err
		}
		if _, err = tx.Exec(`CREATE INDEX IF NOT EXISTS idx_backup_schedule_runs_recent ON backup_schedule_runs(schedule_id, started_at DESC)`); err != nil {
			_ = tx.Rollback()
			return err
		}
		if _, err = tx.Exec(`INSERT INTO schema_migrations(version) VALUES(4)`); err != nil {
			_ = tx.Rollback()
			return err
		}
		if err = tx.Commit(); err != nil {
			return err
		}
	}
	if version < 5 {
		tx, err := d.Begin()
		if err != nil {
			return err
		}
		if _, err = tx.Exec(`CREATE TABLE IF NOT EXISTS notification_settings (
			id INTEGER PRIMARY KEY CHECK(id=1),
			enabled INTEGER NOT NULL DEFAULT 0,
			endpoint_enc TEXT NOT NULL DEFAULT '',
			signing_secret_enc TEXT NOT NULL DEFAULT '',
			events_json TEXT NOT NULL DEFAULT '[]',
			updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
		)`); err != nil {
			_ = tx.Rollback()
			return err
		}
		if _, err = tx.Exec(`INSERT INTO schema_migrations(version) VALUES(5)`); err != nil {
			_ = tx.Rollback()
			return err
		}
		if err = tx.Commit(); err != nil {
			return err
		}
	}
	if version < 6 {
		tx, err := d.Begin()
		if err != nil {
			return err
		}
		if _, err = tx.Exec(`CREATE TABLE IF NOT EXISTS server_crashes (
			id TEXT PRIMARY KEY,
			server_id TEXT NOT NULL,
			container_id TEXT NOT NULL DEFAULT '',
			reason TEXT NOT NULL,
			exit_code INTEGER NOT NULL DEFAULT -1,
			message TEXT NOT NULL,
			detected_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
		)`); err != nil {
			_ = tx.Rollback()
			return err
		}
		if _, err = tx.Exec(`CREATE INDEX IF NOT EXISTS idx_server_crashes_recent ON server_crashes(server_id, detected_at DESC, id DESC)`); err != nil {
			_ = tx.Rollback()
			return err
		}
		if _, err = tx.Exec(`INSERT INTO schema_migrations(version) VALUES(6)`); err != nil {
			_ = tx.Rollback()
			return err
		}
		if err = tx.Commit(); err != nil {
			return err
		}
	}
	if version < 7 {
		tx, err := d.Begin()
		if err != nil {
			return err
		}
		if _, err = tx.Exec(`CREATE TABLE IF NOT EXISTS system_alert_state (
			name TEXT PRIMARY KEY,
			active INTEGER NOT NULL DEFAULT 0,
			updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
		)`); err != nil {
			_ = tx.Rollback()
			return err
		}
		if _, err = tx.Exec(`INSERT INTO schema_migrations(version) VALUES(7)`); err != nil {
			_ = tx.Rollback()
			return err
		}
		if err = tx.Commit(); err != nil {
			return err
		}
	}
	if version < 8 {
		tx, err := d.Begin()
		if err != nil {
			return err
		}
		if !hasColumn(tx, "servers", "watchdog_enabled") {
			if _, err = tx.Exec(`ALTER TABLE servers ADD COLUMN watchdog_enabled INTEGER NOT NULL DEFAULT 0`); err != nil {
				_ = tx.Rollback()
				return err
			}
		}
		if !hasColumn(tx, "servers", "watchdog_quarantined") {
			if _, err = tx.Exec(`ALTER TABLE servers ADD COLUMN watchdog_quarantined INTEGER NOT NULL DEFAULT 0`); err != nil {
				_ = tx.Rollback()
				return err
			}
		}
		if _, err = tx.Exec(`INSERT INTO schema_migrations(version) VALUES(8)`); err != nil {
			_ = tx.Rollback()
			return err
		}
		if err = tx.Commit(); err != nil {
			return err
		}
	}
	if version < 9 {
		tx, err := d.Begin()
		if err != nil {
			return err
		}
		if !hasColumn(tx, "servers", "watchdog_last_attempt") {
			if _, err = tx.Exec(`ALTER TABLE servers ADD COLUMN watchdog_last_attempt INTEGER NOT NULL DEFAULT 0`); err != nil {
				_ = tx.Rollback()
				return err
			}
		}
		if _, err = tx.Exec(`CREATE TABLE IF NOT EXISTS server_watchdog_heals (
			server_id TEXT NOT NULL REFERENCES servers(id) ON DELETE CASCADE,
			healed_at INTEGER NOT NULL
		)`); err != nil {
			_ = tx.Rollback()
			return err
		}
		if _, err = tx.Exec(`CREATE INDEX IF NOT EXISTS idx_server_watchdog_heals_recent ON server_watchdog_heals(server_id, healed_at)`); err != nil {
			_ = tx.Rollback()
			return err
		}
		if _, err = tx.Exec(`INSERT INTO schema_migrations(version) VALUES(9)`); err != nil {
			_ = tx.Rollback()
			return err
		}
		if err = tx.Commit(); err != nil {
			return err
		}
	}
	if version < 10 {
		tx, err := d.Begin()
		if err != nil {
			return err
		}
		for _, column := range []struct {
			name string
			ddl  string
		}{
			{"action", `ALTER TABLE backup_schedules ADD COLUMN action TEXT NOT NULL DEFAULT 'backup'`},
			{"warn_players", `ALTER TABLE backup_schedules ADD COLUMN warn_players INTEGER NOT NULL DEFAULT 0`},
			{"warning_seconds", `ALTER TABLE backup_schedules ADD COLUMN warning_seconds INTEGER NOT NULL DEFAULT 60`},
		} {
			if !hasColumn(tx, "backup_schedules", column.name) {
				if _, err = tx.Exec(column.ddl); err != nil {
					_ = tx.Rollback()
					return err
				}
			}
		}
		if _, err = tx.Exec(`INSERT INTO schema_migrations(version) VALUES(10)`); err != nil {
			_ = tx.Rollback()
			return err
		}
		if err = tx.Commit(); err != nil {
			return err
		}
	}
	if version < 11 {
		tx, err := d.Begin()
		if err != nil {
			return err
		}
		if !hasColumn(tx, "backup_schedules", "skip_if_players_online") {
			if _, err = tx.Exec(`ALTER TABLE backup_schedules ADD COLUMN skip_if_players_online INTEGER NOT NULL DEFAULT 0`); err != nil {
				_ = tx.Rollback()
				return err
			}
		}
		if _, err = tx.Exec(`INSERT INTO schema_migrations(version) VALUES(11)`); err != nil {
			_ = tx.Rollback()
			return err
		}
		if err = tx.Commit(); err != nil {
			return err
		}
	}
	if version < 12 {
		tx, err := d.Begin()
		if err != nil {
			return err
		}
		if !hasColumn(tx, "backup_schedules", "command_enc") {
			if _, err = tx.Exec(`ALTER TABLE backup_schedules ADD COLUMN command_enc TEXT NOT NULL DEFAULT ''`); err != nil {
				_ = tx.Rollback()
				return err
			}
		}
		if _, err = tx.Exec(`INSERT INTO schema_migrations(version) VALUES(12)`); err != nil {
			_ = tx.Rollback()
			return err
		}
		if err = tx.Commit(); err != nil {
			return err
		}
	}
	if version < 13 {
		tx, err := d.Begin()
		if err != nil {
			return err
		}
		if _, err = tx.Exec(`CREATE TABLE IF NOT EXISTS message_templates (
			id TEXT PRIMARY KEY,
			name TEXT NOT NULL,
			body TEXT NOT NULL,
			builtin INTEGER NOT NULL DEFAULT 0,
			created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
			updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
		)`); err != nil {
			_ = tx.Rollback()
			return err
		}
		if !hasColumn(tx, "backup_schedules", "message_payload_enc") {
			if _, err = tx.Exec(`ALTER TABLE backup_schedules ADD COLUMN message_payload_enc TEXT NOT NULL DEFAULT ''`); err != nil {
				_ = tx.Rollback()
				return err
			}
		}
		for _, item := range []struct{ id, name, body string }{
			{"builtin-restart-warning", "Restart warning", "say {{server_name}} will restart in {{minutes}} minutes."},
			{"builtin-restart-countdown", "Restart countdown", "say {{server_name}} is restarting in {{seconds}} seconds."},
			{"builtin-backup-warning", "Backup warning", "say {{server_name}} backup starts in {{minutes}} minutes."},
			{"builtin-maintenance-notice", "Maintenance notice", "say {{server_name}} maintenance starts in {{minutes}} minutes."},
			{"builtin-update-warning", "Update warning", "say {{server_name}} update starts in {{minutes}} minutes."},
		} {
			if _, err = tx.Exec(`INSERT INTO message_templates(id,name,body,builtin) VALUES(?,?,?,1) ON CONFLICT(id) DO NOTHING`, item.id, item.name, item.body); err != nil {
				_ = tx.Rollback()
				return err
			}
		}
		if _, err = tx.Exec(`INSERT INTO schema_migrations(version) VALUES(13)`); err != nil {
			_ = tx.Rollback()
			return err
		}
		if err = tx.Commit(); err != nil {
			return err
		}
	}
	if version < 14 {
		tx, err := d.Begin()
		if err != nil {
			return err
		}
		if _, err = tx.Exec(`CREATE TABLE IF NOT EXISTS backup_target_settings (
			id INTEGER PRIMARY KEY CHECK(id=1),
			enabled INTEGER NOT NULL DEFAULT 0,
			endpoint_enc TEXT NOT NULL DEFAULT '',
			bucket TEXT NOT NULL DEFAULT '',
			region TEXT NOT NULL DEFAULT '',
			access_key_enc TEXT NOT NULL DEFAULT '',
			secret_key_enc TEXT NOT NULL DEFAULT '',
			prefix TEXT NOT NULL DEFAULT '',
			updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
		)`); err != nil {
			_ = tx.Rollback()
			return err
		}
		for _, column := range []struct {
			name string
			ddl  string
		}{
			{"storage", `ALTER TABLE server_backups ADD COLUMN storage TEXT NOT NULL DEFAULT 'local'`},
			{"storage_key", `ALTER TABLE server_backups ADD COLUMN storage_key TEXT NOT NULL DEFAULT ''`},
		} {
			if !hasColumn(tx, "server_backups", column.name) {
				if _, err = tx.Exec(column.ddl); err != nil {
					_ = tx.Rollback()
					return err
				}
			}
		}
		if _, err = tx.Exec(`INSERT INTO schema_migrations(version) VALUES(14)`); err != nil {
			_ = tx.Rollback()
			return err
		}
		if err = tx.Commit(); err != nil {
			return err
		}
	}
	if version < 15 {
		tx, err := d.Begin()
		if err != nil {
			return err
		}
		if _, err = tx.Exec(`CREATE TABLE IF NOT EXISTS server_sidecars (
			server_id TEXT NOT NULL REFERENCES servers(id) ON DELETE CASCADE,
			service_name TEXT NOT NULL,
			container_id TEXT NOT NULL DEFAULT '',
			status TEXT NOT NULL DEFAULT 'stopped',
			updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
			PRIMARY KEY(server_id, service_name)
		)`); err != nil {
			_ = tx.Rollback()
			return err
		}
		if _, err = tx.Exec(`CREATE INDEX IF NOT EXISTS idx_server_sidecars_server ON server_sidecars(server_id)`); err != nil {
			_ = tx.Rollback()
			return err
		}
		if _, err = tx.Exec(`INSERT INTO schema_migrations(version) VALUES(15)`); err != nil {
			_ = tx.Rollback()
			return err
		}
		if err = tx.Commit(); err != nil {
			return err
		}
	}
	if version < 16 {
		tx, err := d.Begin()
		if err != nil {
			return err
		}
		if !hasColumn(tx, "server_sidecars", "last_error") {
			if _, err = tx.Exec(`ALTER TABLE server_sidecars ADD COLUMN last_error TEXT NOT NULL DEFAULT ''`); err != nil {
				_ = tx.Rollback()
				return err
			}
		}
		if _, err = tx.Exec(`INSERT INTO schema_migrations(version) VALUES(16)`); err != nil {
			_ = tx.Rollback()
			return err
		}
		if err = tx.Commit(); err != nil {
			return err
		}
	}
	if version < 17 {
		tx, err := d.Begin()
		if err != nil {
			return err
		}
		if !hasColumn(tx, "backup_schedules", "destination") {
			if _, err = tx.Exec(`ALTER TABLE backup_schedules ADD COLUMN destination TEXT NOT NULL DEFAULT 'local'`); err != nil {
				_ = tx.Rollback()
				return err
			}
		}
		if _, err = tx.Exec(`INSERT INTO schema_migrations(version) VALUES(17)`); err != nil {
			_ = tx.Rollback()
			return err
		}
		if err = tx.Commit(); err != nil {
			return err
		}
	}
	if version < 18 {
		tx, err := d.Begin()
		if err != nil {
			return err
		}
		if !hasColumn(tx, "servers", "status_public") {
			if _, err = tx.Exec(`ALTER TABLE servers ADD COLUMN status_public INTEGER NOT NULL DEFAULT 0`); err != nil {
				_ = tx.Rollback()
				return err
			}
		}
		if _, err = tx.Exec(`CREATE TABLE IF NOT EXISTS status_page_settings (
			id INTEGER PRIMARY KEY CHECK(id=1),
			enabled INTEGER NOT NULL DEFAULT 0,
			title TEXT NOT NULL DEFAULT 'Server Status',
			updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
		)`); err != nil {
			_ = tx.Rollback()
			return err
		}
		if _, err = tx.Exec(`INSERT OR IGNORE INTO status_page_settings(id,enabled,title) VALUES(1,0,'Server Status')`); err != nil {
			_ = tx.Rollback()
			return err
		}
		if _, err = tx.Exec(`CREATE TABLE IF NOT EXISTS server_query_samples (
			server_id TEXT PRIMARY KEY REFERENCES servers(id) ON DELETE CASCADE,
			online INTEGER NOT NULL,
			max_players INTEGER NOT NULL,
			sampled_at INTEGER NOT NULL
		)`); err != nil {
			_ = tx.Rollback()
			return err
		}
		if _, err = tx.Exec(`INSERT INTO schema_migrations(version) VALUES(18)`); err != nil {
			_ = tx.Rollback()
			return err
		}
		if err = tx.Commit(); err != nil {
			return err
		}
	}
	if version < 19 {
		tx, err := d.Begin()
		if err != nil {
			return err
		}
		if !hasColumn(tx, "servers", "realm_id") {
			if _, err = tx.Exec(`ALTER TABLE servers ADD COLUMN realm_id TEXT NOT NULL DEFAULT ''`); err != nil {
				_ = tx.Rollback()
				return err
			}
		}
		if _, err = tx.Exec(`CREATE TABLE IF NOT EXISTS realms (
			id TEXT PRIMARY KEY,
			name TEXT NOT NULL COLLATE NOCASE UNIQUE,
			description TEXT NOT NULL DEFAULT '',
			sort_order INTEGER NOT NULL DEFAULT 0,
			created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
		)`); err != nil {
			_ = tx.Rollback()
			return err
		}
		if _, err = tx.Exec(`CREATE TABLE IF NOT EXISTS realm_user_state (
			user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
			realm_id TEXT NOT NULL REFERENCES realms(id) ON DELETE CASCADE,
			collapsed INTEGER NOT NULL DEFAULT 0,
			PRIMARY KEY(user_id, realm_id)
		)`); err != nil {
			_ = tx.Rollback()
			return err
		}
		if _, err = tx.Exec(`CREATE INDEX IF NOT EXISTS idx_servers_realm ON servers(realm_id)`); err != nil {
			_ = tx.Rollback()
			return err
		}
		rows, err := tx.Query(`SELECT s.id,COALESCE(NULLIF(TRIM(g.category),''),'Default') FROM servers s LEFT JOIN gameskills g ON g.id=s.gameskill_id ORDER BY s.id`)
		if err != nil {
			_ = tx.Rollback()
			return err
		}
		type legacyServerRealm struct{ serverID, name string }
		legacy := []legacyServerRealm{}
		for rows.Next() {
			var x legacyServerRealm
			if err = rows.Scan(&x.serverID, &x.name); err != nil {
				_ = rows.Close()
				_ = tx.Rollback()
				return err
			}
			legacy = append(legacy, x)
		}
		if err = rows.Err(); err != nil {
			_ = rows.Close()
			_ = tx.Rollback()
			return err
		}
		_ = rows.Close()
		for _, x := range legacy {
			if _, err = tx.Exec(`INSERT OR IGNORE INTO realms(id,name,sort_order) VALUES(lower(hex(randomblob(16))),?,(SELECT COALESCE(MAX(sort_order)+1,0) FROM realms))`, x.name); err != nil {
				_ = tx.Rollback()
				return err
			}
			if _, err = tx.Exec(`UPDATE servers SET realm_id=(SELECT id FROM realms WHERE name=? COLLATE NOCASE LIMIT 1) WHERE id=?`, x.name, x.serverID); err != nil {
				_ = tx.Rollback()
				return err
			}
		}
		if _, err = tx.Exec(`INSERT INTO schema_migrations(version) VALUES(19)`); err != nil {
			_ = tx.Rollback()
			return err
		}
		if err = tx.Commit(); err != nil {
			return err
		}
	}
	if version < 20 {
		tx, err := d.Begin()
		if err != nil {
			return err
		}
		for _, column := range []struct {
			name string
			ddl  string
		}{
			{"protocol", `ALTER TABLE backup_target_settings ADD COLUMN protocol TEXT NOT NULL DEFAULT 's3'`},
			{"port", `ALTER TABLE backup_target_settings ADD COLUMN port INTEGER NOT NULL DEFAULT 0`},
		} {
			if !hasColumn(tx, "backup_target_settings", column.name) {
				if _, err = tx.Exec(column.ddl); err != nil {
					_ = tx.Rollback()
					return err
				}
			}
		}
		if _, err = tx.Exec(`INSERT INTO schema_migrations(version) VALUES(20)`); err != nil {
			_ = tx.Rollback()
			return err
		}
		if err = tx.Commit(); err != nil {
			return err
		}
	}
	if version < 21 {
		tx, err := d.Begin()
		if err != nil {
			return err
		}
		for _, column := range []struct {
			name string
			ddl  string
		}{
			{"source_host", `ALTER TABLE gameskills ADD COLUMN source_host TEXT NOT NULL DEFAULT ''`},
			{"source_repo", `ALTER TABLE gameskills ADD COLUMN source_repo TEXT NOT NULL DEFAULT ''`},
			{"source_path", `ALTER TABLE gameskills ADD COLUMN source_path TEXT NOT NULL DEFAULT ''`},
			{"source_ref", `ALTER TABLE gameskills ADD COLUMN source_ref TEXT NOT NULL DEFAULT ''`},
		} {
			if !hasColumn(tx, "gameskills", column.name) {
				if _, err = tx.Exec(column.ddl); err != nil {
					_ = tx.Rollback()
					return err
				}
			}
		}
		if _, err = tx.Exec(`CREATE TABLE IF NOT EXISTS rune_repos (
			id TEXT PRIMARY KEY,
			name TEXT NOT NULL,
			host TEXT NOT NULL DEFAULT '',
			repo TEXT NOT NULL,
			path TEXT NOT NULL DEFAULT '',
			ref TEXT NOT NULL DEFAULT 'main',
			token_enc TEXT NOT NULL DEFAULT '',
			created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
			updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
		)`); err != nil {
			_ = tx.Rollback()
			return err
		}
		if _, err = tx.Exec(`CREATE INDEX IF NOT EXISTS idx_rune_repos_source ON rune_repos(host,repo,path,ref)`); err != nil {
			_ = tx.Rollback()
			return err
		}
		if _, err = tx.Exec(`CREATE TABLE IF NOT EXISTS github_catalog_settings (
			id INTEGER PRIMARY KEY CHECK(id=1),
			token_enc TEXT NOT NULL DEFAULT '',
			updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
		)`); err != nil {
			_ = tx.Rollback()
			return err
		}
		if _, err = tx.Exec(`INSERT INTO schema_migrations(version) VALUES(21)`); err != nil {
			_ = tx.Rollback()
			return err
		}
		if err = tx.Commit(); err != nil {
			return err
		}
	}
	if version < 22 {
		tx, err := d.Begin()
		if err != nil {
			return err
		}
		if _, err = tx.Exec(`CREATE TABLE IF NOT EXISTS registry_logins (
			id TEXT PRIMARY KEY,
			registry TEXT NOT NULL UNIQUE,
			username TEXT NOT NULL,
			secret_enc TEXT NOT NULL,
			created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
			updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
		)`); err != nil {
			_ = tx.Rollback()
			return err
		}
		if _, err = tx.Exec(`INSERT INTO schema_migrations(version) VALUES(22)`); err != nil {
			_ = tx.Rollback()
			return err
		}
		if err = tx.Commit(); err != nil {
			return err
		}
	}
	if version < 23 {
		tx, err := d.Begin()
		if err != nil {
			return err
		}
		if _, err = tx.Exec(`CREATE TABLE IF NOT EXISTS notification_channels (
			id TEXT PRIMARY KEY,
			type TEXT NOT NULL,
			config_enc TEXT NOT NULL,
			enabled INTEGER NOT NULL DEFAULT 1,
			server_id TEXT NOT NULL DEFAULT '',
			created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
			updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
		)`); err != nil {
			_ = tx.Rollback()
			return err
		}
		if _, err = tx.Exec(`CREATE INDEX IF NOT EXISTS idx_notification_channels_scope ON notification_channels(enabled,server_id)`); err != nil {
			_ = tx.Rollback()
			return err
		}
		if _, err = tx.Exec(`INSERT INTO schema_migrations(version) VALUES(23)`); err != nil {
			_ = tx.Rollback()
			return err
		}
		if err = tx.Commit(); err != nil {
			return err
		}
	}
	return nil
}

func hasColumn(tx *sql.Tx, table, name string) bool {
	rows, err := tx.Query(`PRAGMA table_info(` + table + `)`)
	if err != nil {
		return false
	}
	defer rows.Close()
	for rows.Next() {
		var cid, notnull, pk int
		var col, typ string
		var dflt any
		if rows.Scan(&cid, &col, &typ, &notnull, &dflt, &pk) == nil && col == name {
			return true
		}
	}
	return false
}

const schema = `
CREATE TABLE IF NOT EXISTS users (
 id TEXT PRIMARY KEY, username TEXT NOT NULL UNIQUE, password_hash TEXT NOT NULL,
 role TEXT NOT NULL DEFAULT 'user', disabled INTEGER NOT NULL DEFAULT 0,
 created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP, totp_secret TEXT NOT NULL DEFAULT '',
 totp_enabled INTEGER NOT NULL DEFAULT 0, totp_last_counter INTEGER NOT NULL DEFAULT -1,
 token_version INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS permissions (
 id INTEGER PRIMARY KEY AUTOINCREMENT, user_id TEXT NOT NULL, scope_type TEXT NOT NULL,
 scope_id TEXT NOT NULL DEFAULT '', perms TEXT NOT NULL,
 UNIQUE(user_id,scope_type,scope_id)
);
CREATE TABLE IF NOT EXISTS api_tokens (
 id TEXT PRIMARY KEY, user_id TEXT NOT NULL, name TEXT NOT NULL, token_hash TEXT NOT NULL UNIQUE,
 scope TEXT NOT NULL DEFAULT '', created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
 last_used_at TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS gameskills (
 id TEXT PRIMARY KEY, name TEXT NOT NULL, category TEXT NOT NULL DEFAULT 'Default',
 version INTEGER NOT NULL DEFAULT 1, yaml_blob TEXT NOT NULL, builtin INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS servers (
 id TEXT PRIMARY KEY, name TEXT NOT NULL, gameskill_id TEXT NOT NULL, status TEXT NOT NULL,
 installed INTEGER NOT NULL DEFAULT 0, env_json TEXT NOT NULL DEFAULT '{}', ports_json TEXT NOT NULL DEFAULT '{}',
 data_dir TEXT NOT NULL, container_id TEXT NOT NULL DEFAULT '', cpu_limit REAL NOT NULL DEFAULT 0,
 memory_limit_mb INTEGER NOT NULL DEFAULT 0, created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
 updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS port_allocations (port INTEGER PRIMARY KEY, server_id TEXT NOT NULL, name TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS audit_log (
 id INTEGER PRIMARY KEY AUTOINCREMENT, at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
 user_id TEXT NOT NULL DEFAULT '', username TEXT NOT NULL DEFAULT '', action TEXT NOT NULL,
 target_type TEXT NOT NULL DEFAULT '', target_id TEXT NOT NULL DEFAULT '', detail TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_audit_at ON audit_log(at DESC);
CREATE INDEX IF NOT EXISTS idx_permissions_user ON permissions(user_id);
CREATE INDEX IF NOT EXISTS idx_servers_rune ON servers(gameskill_id);
`
