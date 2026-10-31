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
	if count != 3 {
		t.Fatalf("expected 3 migrations, got %d", count)
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
}
