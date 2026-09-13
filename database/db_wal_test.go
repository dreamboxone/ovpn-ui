package database

import (
	"os"
	"path/filepath"
	"testing"
)

// The whole point of the DSN change: a freshly opened DB must be in WAL.
func TestInitDBEnablesWAL(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "vpn-ui.db")
	if err := InitDB(p); err != nil {
		t.Fatal(err)
	}
	var mode string
	if err := db.Raw("PRAGMA journal_mode;").Scan(&mode).Error; err != nil {
		t.Fatal(err)
	}
	if mode != "wal" {
		t.Fatalf("journal_mode = %q, want wal (readers stall behind every writer without it)", mode)
	}
	var busy int
	if err := db.Raw("PRAGMA busy_timeout;").Scan(&busy).Error; err != nil {
		t.Fatal(err)
	}
	if busy != 10000 {
		t.Fatalf("busy_timeout = %d, want 10000", busy)
	}
	// TRUNCATE checkpoint must leave a zero-length WAL, which is what makes the
	// panel's DB-download a complete snapshot of the .db file alone.
	if err := db.Exec("CREATE TABLE t(x); INSERT INTO t VALUES (1);").Error; err != nil {
		t.Fatal(err)
	}
	if err := Checkpoint(); err != nil {
		t.Fatal(err)
	}
	if fi, err := os.Stat(p + "-wal"); err == nil && fi.Size() != 0 {
		t.Fatalf("WAL still %d bytes after TRUNCATE checkpoint; a DB export would miss recent writes", fi.Size())
	}
}

func TestRemoveSidecars(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "vpn-ui.db")
	for _, s := range []string{"", "-wal", "-shm"} {
		if err := os.WriteFile(p+s, []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	RemoveSidecars(p)
	for _, s := range []string{"-wal", "-shm"} {
		if _, err := os.Stat(p + s); !os.IsNotExist(err) {
			t.Fatalf("%s survived; an imported DB would inherit a foreign WAL", p+s)
		}
	}
	if _, err := os.Stat(p); err != nil {
		t.Fatal("the database itself must not be removed")
	}
	RemoveSidecars(p) // idempotent
}
