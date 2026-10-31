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
