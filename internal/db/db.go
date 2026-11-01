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
	if version < 24 {
		tx, err := d.Begin()
		if err != nil {
			return err
		}
		if !hasColumn(tx, "users", "email") {
			if _, err = tx.Exec(`ALTER TABLE users ADD COLUMN email TEXT NOT NULL DEFAULT ''`); err != nil {
				_ = tx.Rollback()
				return err
			}
		}
		if _, err = tx.Exec(`CREATE UNIQUE INDEX IF NOT EXISTS idx_users_email_unique ON users(lower(email)) WHERE email<>''`); err != nil {
			_ = tx.Rollback()
			return err
		}
		if _, err = tx.Exec(`CREATE TABLE IF NOT EXISTS password_reset_tokens (
			token_hash TEXT PRIMARY KEY,
			user_id TEXT NOT NULL,
			expires_at INTEGER NOT NULL,
			created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
		)`); err != nil {
			_ = tx.Rollback()
			return err
		}
		if _, err = tx.Exec(`CREATE INDEX IF NOT EXISTS idx_password_reset_tokens_user ON password_reset_tokens(user_id)`); err != nil {
			_ = tx.Rollback()
			return err
		}
		if _, err = tx.Exec(`INSERT INTO schema_migrations(version) VALUES(24)`); err != nil {
			_ = tx.Rollback()
			return err
		}
		if err = tx.Commit(); err != nil {
			return err
		}
	}
	if version < 25 {
		tx, err := d.Begin()
		if err != nil {
			return err
		}
		if !hasColumn(tx, "users", "webauthn_user_handle") {
			if _, err = tx.Exec(`ALTER TABLE users ADD COLUMN webauthn_user_handle TEXT NOT NULL DEFAULT ''`); err != nil {
				_ = tx.Rollback()
				return err
			}
		}
		if _, err = tx.Exec(`CREATE UNIQUE INDEX IF NOT EXISTS idx_users_webauthn_handle ON users(webauthn_user_handle) WHERE webauthn_user_handle<>''`); err != nil {
			_ = tx.Rollback()
			return err
		}
		if _, err = tx.Exec(`CREATE TABLE IF NOT EXISTS passkey_credentials (
			id TEXT PRIMARY KEY,
			user_id TEXT NOT NULL,
			credential_id BLOB NOT NULL UNIQUE,
			name TEXT NOT NULL,
			credential_enc TEXT NOT NULL,
			created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
			last_used_at TEXT NOT NULL DEFAULT ''
		)`); err != nil {
			_ = tx.Rollback()
			return err
		}
		if _, err = tx.Exec(`CREATE INDEX IF NOT EXISTS idx_passkey_credentials_user ON passkey_credentials(user_id,created_at)`); err != nil {
			_ = tx.Rollback()
			return err
		}
		if _, err = tx.Exec(`INSERT INTO schema_migrations(version) VALUES(25)`); err != nil {
			_ = tx.Rollback()
			return err
		}
		if err = tx.Commit(); err != nil {
			return err
		}
	}
	if version < 26 {
		tx, err := d.Begin()
		if err != nil {
			return err
		}
		for _, column := range []struct{ name, ddl string }{
			{"scope_type", `ALTER TABLE backup_schedules ADD COLUMN scope_type TEXT NOT NULL DEFAULT 'server'`},
			{"scope_id", `ALTER TABLE backup_schedules ADD COLUMN scope_id TEXT NOT NULL DEFAULT ''`},
			{"run_now", `ALTER TABLE backup_schedules ADD COLUMN run_now INTEGER NOT NULL DEFAULT 0`},
		} {
			if !hasColumn(tx, "backup_schedules", column.name) {
				if _, err = tx.Exec(column.ddl); err != nil {
					_ = tx.Rollback()
					return err
				}
			}
		}
		if _, err = tx.Exec(`UPDATE backup_schedules SET scope_id=server_id WHERE scope_type='server' AND scope_id=''`); err != nil {
			_ = tx.Rollback()
			return err
		}
		if _, err = tx.Exec(`CREATE INDEX IF NOT EXISTS idx_backup_schedules_scope ON backup_schedules(scope_type,scope_id,created_at DESC)`); err != nil {
			_ = tx.Rollback()
			return err
		}
		if _, err = tx.Exec(`INSERT INTO schema_migrations(version) VALUES(26)`); err != nil {
			_ = tx.Rollback()
			return err
		}
		if err = tx.Commit(); err != nil {
			return err
		}
	}
	if version < 27 {
		tx, err := d.Begin()
		if err != nil {
			return err
		}
		if !hasColumn(tx, "servers", "host_mounts") {
			if _, err = tx.Exec(`ALTER TABLE servers ADD COLUMN host_mounts TEXT NOT NULL DEFAULT '[]'`); err != nil {
				_ = tx.Rollback()
				return err
			}
		}
		if _, err = tx.Exec(`INSERT INTO schema_migrations(version) VALUES(27)`); err != nil {
			_ = tx.Rollback()
			return err
		}
		if err = tx.Commit(); err != nil {
			return err
		}
	}
	if version < 28 {
		tx, err := d.Begin()
		if err != nil {
			return err
		}
		if _, err = tx.Exec(`CREATE TABLE IF NOT EXISTS network_settings (
			id INTEGER PRIMARY KEY CHECK(id=1),
			public_hostname TEXT NOT NULL DEFAULT '',
			updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
		)`); err != nil {
			_ = tx.Rollback()
			return err
		}
		if _, err = tx.Exec(`INSERT OR IGNORE INTO network_settings(id,public_hostname) VALUES(1,'')`); err != nil {
			_ = tx.Rollback()
			return err
		}
		if _, err = tx.Exec(`INSERT INTO schema_migrations(version) VALUES(28)`); err != nil {
			_ = tx.Rollback()
			return err
		}
		if err = tx.Commit(); err != nil {
			return err
		}
	}
	if version < 29 {
		tx, err := d.Begin()
		if err != nil {
			return err
		}
		if !hasColumn(tx, "servers", "auto_forward") {
			if _, err = tx.Exec(`ALTER TABLE servers ADD COLUMN auto_forward INTEGER NOT NULL DEFAULT 1`); err != nil {
				_ = tx.Rollback()
				return err
			}
		}
		if _, err = tx.Exec(`CREATE TABLE IF NOT EXISTS upnp_settings (
			id INTEGER PRIMARY KEY CHECK(id=1),
			enabled INTEGER NOT NULL DEFAULT 0,
			updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
		)`); err != nil {
			_ = tx.Rollback()
			return err
		}
		if _, err = tx.Exec(`INSERT OR IGNORE INTO upnp_settings(id,enabled) VALUES(1,0)`); err != nil {
			_ = tx.Rollback()
			return err
		}
		if _, err = tx.Exec(`CREATE TABLE IF NOT EXISTS server_upnp_mappings (
			server_id TEXT NOT NULL,
			port_name TEXT NOT NULL,
			external_port INTEGER NOT NULL,
			protocol TEXT NOT NULL,
			internal_port INTEGER NOT NULL,
			internal_client TEXT NOT NULL,
			description TEXT NOT NULL,
			created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
			PRIMARY KEY(server_id,external_port,protocol)
		)`); err != nil {
			_ = tx.Rollback()
			return err
		}
		if _, err = tx.Exec(`CREATE TABLE IF NOT EXISTS server_upnp_state (
			server_id TEXT PRIMARY KEY,
			last_error TEXT NOT NULL DEFAULT '',
			updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
		)`); err != nil {
			_ = tx.Rollback()
			return err
		}
		if _, err = tx.Exec(`INSERT INTO schema_migrations(version) VALUES(29)`); err != nil {
			_ = tx.Rollback()
			return err
		}
		if err = tx.Commit(); err != nil {
			return err
		}
	}
	if version < 30 {
		tx, err := d.Begin()
		if err != nil {
			return err
		}
		if _, err = tx.Exec(`CREATE TABLE IF NOT EXISTS unifi_settings (
			id INTEGER PRIMARY KEY CHECK(id=1),
			enabled INTEGER NOT NULL DEFAULT 0,
			controller_url TEXT NOT NULL DEFAULT '',
			username_enc TEXT NOT NULL DEFAULT '',
			password_enc TEXT NOT NULL DEFAULT '',
			site TEXT NOT NULL DEFAULT 'default',
			updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
		)`); err != nil {
			_ = tx.Rollback()
			return err
		}
		if _, err = tx.Exec(`INSERT OR IGNORE INTO unifi_settings(id,enabled) VALUES(1,0)`); err != nil {
			_ = tx.Rollback()
			return err
		}
		if _, err = tx.Exec(`CREATE TABLE IF NOT EXISTS server_unifi_mappings (
			server_id TEXT NOT NULL,
			rule_id TEXT NOT NULL,
			controller_url TEXT NOT NULL,
			rule_name TEXT NOT NULL,
			protocol TEXT NOT NULL,
			external_port INTEGER NOT NULL,
			internal_port INTEGER NOT NULL,
			internal_client TEXT NOT NULL,
			created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
			PRIMARY KEY(server_id,rule_id)
		)`); err != nil {
			_ = tx.Rollback()
			return err
		}
		if _, err = tx.Exec(`CREATE TABLE IF NOT EXISTS server_unifi_state (
			server_id TEXT PRIMARY KEY,
			last_error TEXT NOT NULL DEFAULT '',
			updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
		)`); err != nil {
			_ = tx.Rollback()
			return err
		}
		if _, err = tx.Exec(`INSERT INTO schema_migrations(version) VALUES(30)`); err != nil {
			_ = tx.Rollback()
			return err
		}
		if err = tx.Commit(); err != nil {
			return err
		}
	}
	if version < 31 {
		tx, err := d.Begin()
		if err != nil {
			return err
		}
		if !hasColumn(tx, "servers", "npm_subdomain") {
			if _, err = tx.Exec(`ALTER TABLE servers ADD COLUMN npm_subdomain TEXT NOT NULL DEFAULT ''`); err != nil {
				_ = tx.Rollback()
				return err
			}
		}
		if _, err = tx.Exec(`CREATE TABLE IF NOT EXISTS npm_settings (
			id INTEGER PRIMARY KEY CHECK(id=1),
			enabled INTEGER NOT NULL DEFAULT 0,
			url TEXT NOT NULL DEFAULT '',
			email TEXT NOT NULL DEFAULT '',
			password_enc TEXT NOT NULL DEFAULT '',
			base_domain TEXT NOT NULL DEFAULT '',
			internal_host TEXT NOT NULL DEFAULT '',
			le_email TEXT NOT NULL DEFAULT '',
			updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
		)`); err != nil {
			_ = tx.Rollback()
			return err
		}
		if _, err = tx.Exec(`INSERT OR IGNORE INTO npm_settings(id,enabled) VALUES(1,0)`); err != nil {
			_ = tx.Rollback()
			return err
		}
		if _, err = tx.Exec(`CREATE TABLE IF NOT EXISTS server_npm_state (
			server_id TEXT PRIMARY KEY REFERENCES servers(id) ON DELETE CASCADE,
			host_id TEXT NOT NULL DEFAULT '',
			hostname TEXT NOT NULL DEFAULT '',
			last_error TEXT NOT NULL DEFAULT '',
			cleanup_pending INTEGER NOT NULL DEFAULT 0,
			updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
		)`); err != nil {
			_ = tx.Rollback()
			return err
		}
		if _, err = tx.Exec(`INSERT INTO schema_migrations(version) VALUES(31)`); err != nil {
			_ = tx.Rollback()
			return err
		}
		if err = tx.Commit(); err != nil {
			return err
		}
	}
	if version < 32 {
		tx, err := d.Begin()
		if err != nil {
			return err
		}
		if !hasColumn(tx, "servers", "cf_hostname") {
			if _, err = tx.Exec(`ALTER TABLE servers ADD COLUMN cf_hostname TEXT NOT NULL DEFAULT ''`); err != nil {
				_ = tx.Rollback()
				return err
			}
		}
		if _, err = tx.Exec(`CREATE TABLE IF NOT EXISTS cloudflare_settings (
			id INTEGER PRIMARY KEY CHECK(id=1),
			enabled INTEGER NOT NULL DEFAULT 0,
			api_token_enc TEXT NOT NULL DEFAULT '',
			account_id TEXT NOT NULL DEFAULT '',
			tunnel_id TEXT NOT NULL DEFAULT '',
			base_domain TEXT NOT NULL DEFAULT '',
			zone_id TEXT NOT NULL DEFAULT '',
			internal_host TEXT NOT NULL DEFAULT '',
			updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
		)`); err != nil {
			_ = tx.Rollback()
			return err
		}
		if _, err = tx.Exec(`INSERT OR IGNORE INTO cloudflare_settings(id,enabled) VALUES(1,0)`); err != nil {
			_ = tx.Rollback()
			return err
		}
		if _, err = tx.Exec(`CREATE TABLE IF NOT EXISTS server_cf_state (
			server_id TEXT PRIMARY KEY REFERENCES servers(id) ON DELETE CASCADE,
			hostname TEXT NOT NULL DEFAULT '',
			service TEXT NOT NULL DEFAULT '',
			dns_record_id TEXT NOT NULL DEFAULT '',
			last_error TEXT NOT NULL DEFAULT '',
			cleanup_pending INTEGER NOT NULL DEFAULT 0,
			updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
		)`); err != nil {
			_ = tx.Rollback()
			return err
		}
		if _, err = tx.Exec(`INSERT INTO schema_migrations(version) VALUES(32)`); err != nil {
			_ = tx.Rollback()
			return err
		}
		if err = tx.Commit(); err != nil {
			return err
		}
	}
	if version < 33 {
		tx, err := d.Begin()
		if err != nil {
			return err
		}
		if _, err = tx.Exec(`CREATE TABLE IF NOT EXISTS blocking_settings (
			id INTEGER PRIMARY KEY CHECK(id=1),
			enabled INTEGER NOT NULL DEFAULT 0,
			mode TEXT NOT NULL DEFAULT 'off',
			nft_enabled INTEGER NOT NULL DEFAULT 0,
			allowlist TEXT NOT NULL DEFAULT '[]',
			updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
		)`); err != nil {
			_ = tx.Rollback()
			return err
		}
		if _, err = tx.Exec(`INSERT OR IGNORE INTO blocking_settings(id,enabled,mode,nft_enabled) VALUES(1,0,'off',0)`); err != nil {
			_ = tx.Rollback()
			return err
		}
		if _, err = tx.Exec(`CREATE TABLE IF NOT EXISTS blocked_ips (
			id TEXT PRIMARY KEY,
			ip TEXT NOT NULL,
			backend TEXT NOT NULL CHECK(backend IN ('cloudflare','nftables')),
			scope TEXT NOT NULL DEFAULT '',
			cf_rule_id TEXT NOT NULL DEFAULT '',
			server_id TEXT NOT NULL DEFAULT '',
			reason TEXT NOT NULL DEFAULT '',
			source TEXT NOT NULL DEFAULT 'manual' CHECK(source IN ('manual','kvasir')),
			created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
			expires_at TEXT NOT NULL DEFAULT '',
			last_error TEXT NOT NULL DEFAULT '',
			UNIQUE(ip,backend,scope)
		)`); err != nil {
			_ = tx.Rollback()
			return err
		}
		if _, err = tx.Exec(`CREATE INDEX IF NOT EXISTS idx_blocked_ips_expiry ON blocked_ips(expires_at) WHERE expires_at<>''`); err != nil {
			_ = tx.Rollback()
			return err
		}
		if _, err = tx.Exec(`CREATE TABLE IF NOT EXISTS admin_ip_history (
			ip TEXT PRIMARY KEY,
			last_seen TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
		)`); err != nil {
			_ = tx.Rollback()
			return err
		}
		if _, err = tx.Exec(`INSERT INTO schema_migrations(version) VALUES(33)`); err != nil {
			_ = tx.Rollback()
			return err
		}
		if err = tx.Commit(); err != nil {
			return err
		}
	}
	if version < 34 {
		tx, err := d.Begin()
		if err != nil {
			return err
		}
		if !hasColumn(tx, "blocking_settings", "allowlist") {
			if _, err = tx.Exec(`ALTER TABLE blocking_settings ADD COLUMN allowlist TEXT NOT NULL DEFAULT '[]'`); err != nil {
				_ = tx.Rollback()
				return err
			}
		}
		if _, err = tx.Exec(`INSERT INTO schema_migrations(version) VALUES(34)`); err != nil {
			_ = tx.Rollback()
			return err
		}
		if err = tx.Commit(); err != nil {
			return err
		}
	}
	if version < 35 {
		tx, err := d.Begin()
		if err != nil {
			return err
		}
		if _, err = tx.Exec(`CREATE TABLE IF NOT EXISTS server_routes (
			id TEXT PRIMARY KEY,
			server_id TEXT NOT NULL REFERENCES servers(id) ON DELETE CASCADE,
			hostname TEXT NOT NULL,
			port_name TEXT NOT NULL DEFAULT '',
			cf_service TEXT NOT NULL DEFAULT '',
			cf_dns_record_id TEXT NOT NULL DEFAULT '',
			cf_last_error TEXT NOT NULL DEFAULT '',
			cf_cleanup_pending INTEGER NOT NULL DEFAULT 0,
			npm_host_id TEXT NOT NULL DEFAULT '',
			npm_last_error TEXT NOT NULL DEFAULT '',
			npm_cleanup_pending INTEGER NOT NULL DEFAULT 0,
			delete_pending INTEGER NOT NULL DEFAULT 0,
			created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
			updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
		)`); err != nil {
			_ = tx.Rollback()
			return err
		}
		if _, err = tx.Exec(`CREATE INDEX IF NOT EXISTS idx_server_routes_server ON server_routes(server_id,created_at,id)`); err != nil {
			_ = tx.Rollback()
			return err
		}
		if _, err = tx.Exec(`INSERT INTO schema_migrations(version) VALUES(35)`); err != nil {
			_ = tx.Rollback()
			return err
		}
		if err = tx.Commit(); err != nil {
			return err
		}
	}
	if version < 36 {
		tx, err := d.Begin()
		if err != nil {
			return err
		}
		if _, err = tx.Exec(`CREATE TABLE IF NOT EXISTS beacon_settings (
			id INTEGER PRIMARY KEY CHECK(id=1),
			enabled INTEGER NOT NULL DEFAULT 1,
			instance_id TEXT NOT NULL DEFAULT '',
			last_day TEXT NOT NULL DEFAULT '',
			last_version TEXT NOT NULL DEFAULT '',
			last_success_at TEXT NOT NULL DEFAULT '',
			last_error TEXT NOT NULL DEFAULT '',
			last_error_at TEXT NOT NULL DEFAULT '',
			notice_ack INTEGER NOT NULL DEFAULT 0,
			receiver_enabled INTEGER NOT NULL DEFAULT 0,
			url TEXT NOT NULL DEFAULT 'https://beacon.docklight.app/api/beacon',
			public_count_enabled INTEGER NOT NULL DEFAULT 0,
			public_count_min INTEGER NOT NULL DEFAULT 25,
			updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
		)`); err != nil {
			_ = tx.Rollback()
			return err
		}
		if _, err = tx.Exec(`INSERT OR IGNORE INTO beacon_settings(id) VALUES(1)`); err != nil {
			_ = tx.Rollback()
			return err
		}
		if _, err = tx.Exec(`CREATE TABLE IF NOT EXISTS beacon_pings (
			instance_id TEXT PRIMARY KEY,
			version TEXT NOT NULL,
			first_seen TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
			last_seen TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
			ping_count INTEGER NOT NULL DEFAULT 1
		)`); err != nil {
			_ = tx.Rollback()
			return err
		}
		if _, err = tx.Exec(`CREATE INDEX IF NOT EXISTS idx_beacon_pings_last_seen ON beacon_pings(last_seen)`); err != nil {
			_ = tx.Rollback()
			return err
		}
		if _, err = tx.Exec(`INSERT INTO schema_migrations(version) VALUES(36)`); err != nil {
			_ = tx.Rollback()
			return err
		}
		if err = tx.Commit(); err != nil {
			return err
		}
	}
	if version < 37 {
		tx, err := d.Begin()
		if err != nil {
			return err
		}
		if _, err = tx.Exec(`CREATE TABLE IF NOT EXISTS panel_update_settings (
			id INTEGER PRIMARY KEY CHECK(id=1),
			auto_enabled INTEGER NOT NULL DEFAULT 0,
			auto_hour INTEGER NOT NULL DEFAULT 4,
			last_auto_day TEXT NOT NULL DEFAULT '',
			updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
		)`); err != nil {
			_ = tx.Rollback()
			return err
		}
		if _, err = tx.Exec(`INSERT OR IGNORE INTO panel_update_settings(id) VALUES(1)`); err != nil {
			_ = tx.Rollback()
			return err
		}
		if _, err = tx.Exec(`INSERT INTO schema_migrations(version) VALUES(37)`); err != nil {
			_ = tx.Rollback()
			return err
		}
		if err = tx.Commit(); err != nil {
			return err
		}
	}
	if version < 38 {
		tx, err := d.Begin()
		if err != nil {
			return err
		}
		if _, err = tx.Exec(`CREATE TABLE IF NOT EXISTS bans (
			id TEXT PRIMARY KEY,
			player_name TEXT NOT NULL,
			player_id TEXT NOT NULL DEFAULT '',
			server_id TEXT NOT NULL DEFAULT '',
			reason TEXT NOT NULL,
			banned_by TEXT NOT NULL,
			expires_at TEXT NOT NULL DEFAULT '',
			active INTEGER NOT NULL DEFAULT 1,
			created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
			revoked_at TEXT NOT NULL DEFAULT ''
		)`); err != nil {
			_ = tx.Rollback()
			return err
		}
		if _, err = tx.Exec(`CREATE INDEX IF NOT EXISTS idx_bans_active_player ON bans(active,server_id,player_name COLLATE NOCASE)`); err != nil {
			_ = tx.Rollback()
			return err
		}
		if _, err = tx.Exec(`CREATE INDEX IF NOT EXISTS idx_bans_expiry ON bans(expires_at) WHERE active=1 AND expires_at<>''`); err != nil {
			_ = tx.Rollback()
			return err
		}
		if _, err = tx.Exec(`CREATE TABLE IF NOT EXISTS violation_rules (
			id TEXT PRIMARY KEY,
			name TEXT NOT NULL,
			pattern TEXT NOT NULL,
			threshold INTEGER NOT NULL CHECK(threshold BETWEEN 1 AND 100),
			window_minutes INTEGER NOT NULL CHECK(window_minutes BETWEEN 1 AND 1440),
			action TEXT NOT NULL CHECK(action IN ('ban','kick')),
			scope_global INTEGER NOT NULL DEFAULT 0,
			enabled INTEGER NOT NULL DEFAULT 1,
			created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
			updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
		)`); err != nil {
			_ = tx.Rollback()
			return err
		}
		if _, err = tx.Exec(`CREATE TABLE IF NOT EXISTS ban_server_state (
			ban_id TEXT NOT NULL REFERENCES bans(id) ON DELETE CASCADE,
			server_id TEXT NOT NULL REFERENCES servers(id) ON DELETE CASCADE,
			desired_active INTEGER NOT NULL DEFAULT 1,
			state TEXT NOT NULL DEFAULT 'pending' CHECK(state IN ('pending','applied','removed','error')),
			last_error TEXT NOT NULL DEFAULT '',
			updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
			PRIMARY KEY(ban_id,server_id)
		)`); err != nil {
			_ = tx.Rollback()
			return err
		}
		if _, err = tx.Exec(`CREATE INDEX IF NOT EXISTS idx_ban_server_state_due ON ban_server_state(server_id,state,updated_at)`); err != nil {
			_ = tx.Rollback()
			return err
		}
		if _, err = tx.Exec(`INSERT INTO schema_migrations(version) VALUES(38)`); err != nil {
			_ = tx.Rollback()
			return err
		}
		if err = tx.Commit(); err != nil {
			return err
		}
	}
	if version < 39 {
		tx, err := d.Begin()
		if err != nil {
			return err
		}
		if _, err = tx.Exec(`CREATE TABLE IF NOT EXISTS dayz_economy_settings (
			server_id TEXT PRIMARY KEY REFERENCES servers(id) ON DELETE CASCADE,
			min_lifetime_hours INTEGER NOT NULL DEFAULT 0 CHECK(min_lifetime_hours BETWEEN 0 AND 8760),
			globals_json TEXT NOT NULL DEFAULT '{}',
			registered_files_json TEXT NOT NULL DEFAULT '[]',
			updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
		)`); err != nil {
			_ = tx.Rollback()
			return err
		}
		if _, err = tx.Exec(`INSERT INTO schema_migrations(version) VALUES(39)`); err != nil {
			_ = tx.Rollback()
			return err
		}
		if err = tx.Commit(); err != nil {
			return err
		}
	}
	if version < 40 {
		tx, err := d.Begin()
		if err != nil {
			return err
		}
		if _, err = tx.Exec(`CREATE TABLE IF NOT EXISTS dayz_steam_settings (
			id INTEGER PRIMARY KEY CHECK(id=1),
			api_key_enc TEXT NOT NULL DEFAULT '',
			updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
		)`); err != nil {
			_ = tx.Rollback()
			return err
		}
		if _, err = tx.Exec(`INSERT INTO schema_migrations(version) VALUES(40)`); err != nil {
			_ = tx.Rollback()
			return err
		}
		if err = tx.Commit(); err != nil {
			return err
		}
	}
	if version < 41 {
		tx, err := d.Begin()
		if err != nil {
			return err
		}
		if !hasColumn(tx, "dayz_economy_settings", "mod_imports_json") {
			if _, err = tx.Exec(`ALTER TABLE dayz_economy_settings ADD COLUMN mod_imports_json TEXT NOT NULL DEFAULT '[]'`); err != nil {
				_ = tx.Rollback()
				return err
			}
		}
		if _, err = tx.Exec(`INSERT INTO schema_migrations(version) VALUES(41)`); err != nil {
			_ = tx.Rollback()
			return err
		}
		if err = tx.Commit(); err != nil {
			return err
		}
	}
	if version < 42 {
		tx, err := d.Begin()
		if err != nil {
			return err
		}
		if _, err = tx.Exec(`CREATE TABLE IF NOT EXISTS assistant_config (
			id INTEGER PRIMARY KEY CHECK(id=1),
			enabled INTEGER NOT NULL DEFAULT 0,
			provider TEXT NOT NULL DEFAULT '',
			model TEXT NOT NULL DEFAULT '',
			base_url TEXT NOT NULL DEFAULT '',
			api_key_enc TEXT NOT NULL DEFAULT '',
			updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
		)`); err != nil {
			_ = tx.Rollback()
			return err
		}
		if _, err = tx.Exec(`INSERT OR IGNORE INTO assistant_config(id) VALUES(1)`); err != nil {
			_ = tx.Rollback()
			return err
		}
		if _, err = tx.Exec(`INSERT INTO schema_migrations(version) VALUES(42)`); err != nil {
			_ = tx.Rollback()
			return err
		}
		if err = tx.Commit(); err != nil {
			return err
		}
	}
	if version < 43 {
		tx, err := d.Begin()
		if err != nil {
			return err
		}
		if _, err = tx.Exec(`CREATE TABLE IF NOT EXISTS server_metrics (
			server_id TEXT NOT NULL REFERENCES servers(id) ON DELETE CASCADE,
			sampled_at INTEGER NOT NULL,
			cpu_percent REAL NOT NULL DEFAULT -1,
			memory_mb REAL NOT NULL DEFAULT -1,
			players INTEGER NOT NULL DEFAULT -1,
			PRIMARY KEY(server_id,sampled_at)
		)`); err != nil {
			_ = tx.Rollback()
			return err
		}
		if _, err = tx.Exec(`CREATE INDEX IF NOT EXISTS idx_server_metrics_sampled_at ON server_metrics(sampled_at)`); err != nil {
			_ = tx.Rollback()
			return err
		}
		if _, err = tx.Exec(`CREATE TABLE IF NOT EXISTS host_metrics (
			sampled_at INTEGER PRIMARY KEY,
			cpu_percent REAL NOT NULL DEFAULT -1,
			memory_used_mb REAL NOT NULL DEFAULT -1,
			memory_total_mb REAL NOT NULL DEFAULT -1,
			disk_used_mb REAL NOT NULL DEFAULT -1,
			disk_total_mb REAL NOT NULL DEFAULT -1
		)`); err != nil {
			_ = tx.Rollback()
			return err
		}
		if _, err = tx.Exec(`INSERT INTO schema_migrations(version) VALUES(43)`); err != nil {
			_ = tx.Rollback()
			return err
		}
		if err = tx.Commit(); err != nil {
			return err
		}
	}
	if version < 44 {
		tx, err := d.Begin()
		if err != nil {
			return err
		}
		columns := []struct{ name, definition string }{
			{"digest_enabled", `ALTER TABLE assistant_config ADD COLUMN digest_enabled INTEGER NOT NULL DEFAULT 0`},
			{"digest_hour", `ALTER TABLE assistant_config ADD COLUMN digest_hour INTEGER NOT NULL DEFAULT 8`},
			{"digest_last_day", `ALTER TABLE assistant_config ADD COLUMN digest_last_day TEXT NOT NULL DEFAULT ''`},
			{"actions_enabled", `ALTER TABLE assistant_config ADD COLUMN actions_enabled INTEGER NOT NULL DEFAULT 0`},
			{"proactive_level", `ALTER TABLE assistant_config ADD COLUMN proactive_level INTEGER NOT NULL DEFAULT 0`},
			{"proactive_triggers", `ALTER TABLE assistant_config ADD COLUMN proactive_triggers TEXT NOT NULL DEFAULT 'crash,slowstart,resource,host'`},
			{"chat_data_level", `ALTER TABLE assistant_config ADD COLUMN chat_data_level INTEGER NOT NULL DEFAULT 1`},
		}
		for _, column := range columns {
			if !hasColumn(tx, "assistant_config", column.name) {
				if _, err = tx.Exec(column.definition); err != nil {
					_ = tx.Rollback()
					return err
				}
			}
		}
		if _, err = tx.Exec(`INSERT INTO schema_migrations(version) VALUES(44)`); err != nil {
			_ = tx.Rollback()
			return err
		}
		if err = tx.Commit(); err != nil {
			return err
		}
	}
	if version < 45 {
		tx, err := d.Begin()
		if err != nil {
			return err
		}
		if _, err = tx.Exec(`CREATE TABLE IF NOT EXISTS log_watchers (
			id TEXT PRIMARY KEY,
			server_id TEXT NOT NULL DEFAULT '',
			name TEXT NOT NULL,
			pattern TEXT NOT NULL,
			threshold INTEGER NOT NULL DEFAULT 1,
			window_secs INTEGER NOT NULL DEFAULT 60,
			action TEXT NOT NULL DEFAULT 'notify',
			enabled INTEGER NOT NULL DEFAULT 1,
			last_fired TEXT NOT NULL DEFAULT '',
			source TEXT NOT NULL DEFAULT 'user',
			source_key TEXT NOT NULL DEFAULT '',
			created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
			updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
			CHECK(threshold BETWEEN 1 AND 1000),
			CHECK(window_secs BETWEEN 1 AND 3600),
			CHECK(action IN ('notify','advisory')),
			CHECK(source IN ('user','rune'))
		)`); err != nil {
			_ = tx.Rollback()
			return err
		}
		if _, err = tx.Exec(`CREATE INDEX IF NOT EXISTS idx_log_watchers_scope_enabled ON log_watchers(enabled,server_id)`); err != nil {
			_ = tx.Rollback()
			return err
		}
		if _, err = tx.Exec(`CREATE UNIQUE INDEX IF NOT EXISTS idx_log_watchers_rune_seed ON log_watchers(server_id,source_key) WHERE source='rune' AND source_key<>''`); err != nil {
			_ = tx.Rollback()
			return err
		}
		if _, err = tx.Exec(`INSERT INTO schema_migrations(version) VALUES(45)`); err != nil {
			_ = tx.Rollback()
			return err
		}
		if err = tx.Commit(); err != nil {
			return err
		}
	}
	if version < 46 {
		tx, err := d.Begin()
		if err != nil {
			return err
		}
		if !hasColumn(tx, "log_watchers", "advisory_host") {
			if _, err = tx.Exec(`ALTER TABLE log_watchers ADD COLUMN advisory_host TEXT NOT NULL DEFAULT ''`); err != nil {
				_ = tx.Rollback()
				return err
			}
		}
		if _, err = tx.Exec(`INSERT INTO schema_migrations(version) VALUES(46)`); err != nil {
			_ = tx.Rollback()
			return err
		}
		if err = tx.Commit(); err != nil {
			return err
		}
	}
	if version < 47 {
		tx, err := d.Begin()
		if err != nil {
			return err
		}
		if _, err = tx.Exec("CREATE TABLE IF NOT EXISTS assistant_proactive_events (" +
			"id TEXT PRIMARY KEY, source_key TEXT NOT NULL UNIQUE, server_id TEXT NOT NULL DEFAULT '', " +
			"event_type TEXT NOT NULL, summary TEXT NOT NULL, details_json TEXT NOT NULL DEFAULT '{}', " +
			"explanation TEXT NOT NULL DEFAULT '', suggested_action TEXT NOT NULL DEFAULT 'none', " +
			"suggestion_reason TEXT NOT NULL DEFAULT '', level INTEGER NOT NULL, applied INTEGER NOT NULL DEFAULT 0, " +
			"apply_status TEXT NOT NULL DEFAULT 'not_requested', status TEXT NOT NULL DEFAULT 'pending', " +
			"dismissed INTEGER NOT NULL DEFAULT 0, created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP, " +
			"updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP, " +
			"CHECK(event_type IN ('crash','slowstart','resource','host','anomalies')), CHECK(level BETWEEN 1 AND 3), " +
			"CHECK(applied IN (0,1)), CHECK(dismissed IN (0,1)), " +
			"CHECK(status IN ('pending','processing','explained','failed','applied')), " +
			"CHECK(apply_status IN ('not_requested','proposal','applied','failed','rate_limited','not_allowed'))" +
			")"); err != nil {
			_ = tx.Rollback()
			return err
		}
		if _, err = tx.Exec("CREATE INDEX IF NOT EXISTS idx_assistant_proactive_server_recent ON assistant_proactive_events(server_id,created_at DESC)"); err != nil {
			_ = tx.Rollback()
			return err
		}
		if _, err = tx.Exec("CREATE INDEX IF NOT EXISTS idx_assistant_proactive_pending ON assistant_proactive_events(status,created_at)"); err != nil {
			_ = tx.Rollback()
			return err
		}
		if _, err = tx.Exec("INSERT INTO schema_migrations(version) VALUES(47)"); err != nil {
			_ = tx.Rollback()
			return err
		}
		if err = tx.Commit(); err != nil {
			return err
		}
	}
	if version < 48 {
		tx, err := d.Begin()
		if err != nil {
			return err
		}
		statements := []string{
			`CREATE TABLE IF NOT EXISTS mcp_clients (
				client_id TEXT PRIMARY KEY,
				name TEXT NOT NULL,
				redirect_uris_json TEXT NOT NULL,
				created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
			)`,
			`CREATE TABLE IF NOT EXISTS mcp_authorization_requests (
				nonce_hash TEXT PRIMARY KEY,
				client_id TEXT NOT NULL,
				redirect_uri TEXT NOT NULL,
				code_challenge TEXT NOT NULL,
				state TEXT NOT NULL DEFAULT '',
				scope TEXT NOT NULL,
				resource TEXT NOT NULL,
				expires_at INTEGER NOT NULL,
				consumed INTEGER NOT NULL DEFAULT 0 CHECK(consumed IN (0,1))
			)`,
			`CREATE TABLE IF NOT EXISTS mcp_authorization_codes (
				code_hash TEXT PRIMARY KEY,
				client_id TEXT NOT NULL,
				user_id TEXT NOT NULL,
				user_token_version INTEGER NOT NULL,
				redirect_uri TEXT NOT NULL,
				code_challenge TEXT NOT NULL,
				scope TEXT NOT NULL,
				resource TEXT NOT NULL,
				expires_at INTEGER NOT NULL,
				consumed INTEGER NOT NULL DEFAULT 0 CHECK(consumed IN (0,1)),
				created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
			)`,
			`CREATE TABLE IF NOT EXISTS mcp_connections (
				id TEXT PRIMARY KEY,
				client_id TEXT NOT NULL,
				user_id TEXT NOT NULL,
				user_token_version INTEGER NOT NULL,
				scope TEXT NOT NULL,
				resource TEXT NOT NULL,
				created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
				last_used_at TEXT NOT NULL DEFAULT '',
				revoked_at INTEGER NOT NULL DEFAULT 0
			)`,
			`CREATE TABLE IF NOT EXISTS mcp_access_tokens (
				token_hash TEXT PRIMARY KEY,
				connection_id TEXT NOT NULL,
				user_id TEXT NOT NULL,
				expires_at INTEGER NOT NULL,
				created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
			)`,
			`CREATE TABLE IF NOT EXISTS mcp_refresh_tokens (
				token_hash TEXT PRIMARY KEY,
				connection_id TEXT NOT NULL,
				user_id TEXT NOT NULL,
				expires_at INTEGER NOT NULL,
				consumed_at INTEGER NOT NULL DEFAULT 0,
				created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
			)`,
			`CREATE INDEX IF NOT EXISTS idx_mcp_codes_expiry ON mcp_authorization_codes(expires_at,consumed)`,
			`CREATE INDEX IF NOT EXISTS idx_mcp_requests_expiry ON mcp_authorization_requests(expires_at,consumed)`,
			`CREATE INDEX IF NOT EXISTS idx_mcp_connections_user ON mcp_connections(user_id,revoked_at,created_at DESC)`,
			`CREATE INDEX IF NOT EXISTS idx_mcp_access_connection ON mcp_access_tokens(connection_id,expires_at)`,
			`CREATE INDEX IF NOT EXISTS idx_mcp_access_expiry ON mcp_access_tokens(expires_at)`,
			`CREATE INDEX IF NOT EXISTS idx_mcp_refresh_connection ON mcp_refresh_tokens(connection_id,expires_at)`,
			`CREATE INDEX IF NOT EXISTS idx_mcp_refresh_expiry ON mcp_refresh_tokens(expires_at,consumed_at)`,
		}
		for _, statement := range statements {
			if _, err = tx.Exec(statement); err != nil {
				_ = tx.Rollback()
				return err
			}
		}
		if _, err = tx.Exec(`INSERT INTO schema_migrations(version) VALUES(48)`); err != nil {
			_ = tx.Rollback()
			return err
		}
		if err = tx.Commit(); err != nil {
			return err
		}
	}
	if version < 49 {
		tx, err := d.Begin()
		if err != nil {
			return err
		}
		if _, err = tx.Exec(`CREATE TABLE IF NOT EXISTS assistant_log_volume_baselines (
			server_id TEXT PRIMARY KEY, sample_count INTEGER NOT NULL DEFAULT 0,
			mean_bytes REAL NOT NULL DEFAULT 0, variance_bytes REAL NOT NULL DEFAULT 0,
			last_sample_at INTEGER NOT NULL DEFAULT 0, updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
		)`); err != nil {
			_ = tx.Rollback()
			return err
		}
		if _, err = tx.Exec(`INSERT INTO schema_migrations(version) VALUES(49)`); err != nil {
			_ = tx.Rollback()
			return err
		}
		if err = tx.Commit(); err != nil {
			return err
		}
	}
	if version < 50 {
		tx, err := d.Begin()
		if err != nil {
			return err
		}
		if _, err = tx.Exec(`CREATE TABLE IF NOT EXISTS steam_account (
			id INTEGER PRIMARY KEY CHECK(id=1),
			username TEXT NOT NULL DEFAULT '',
			authorized INTEGER NOT NULL DEFAULT 0 CHECK(authorized IN (0,1)),
			authorized_at TEXT NOT NULL DEFAULT ''
		)`); err != nil {
			_ = tx.Rollback()
			return err
		}
		if _, err = tx.Exec(`INSERT OR IGNORE INTO steam_account(id) VALUES(1)`); err != nil {
			_ = tx.Rollback()
			return err
		}
		if _, err = tx.Exec(`INSERT INTO schema_migrations(version) VALUES(50)`); err != nil {
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
