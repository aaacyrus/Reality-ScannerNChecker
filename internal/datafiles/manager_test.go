package datafiles

import (
	"path/filepath"
	"testing"
	"time"
)

func TestPrepareDoesNotRequireAnEmbeddedDatabase(t *testing.T) {
	manager := &Manager{cacheDir: filepath.Join(t.TempDir(), "missing-cache"), now: time.Now}
	if err := manager.Prepare(); err != nil {
		t.Fatal(err)
	}
	if manager.ActiveDir() != "" {
		t.Fatalf("active directory = %q, want empty", manager.ActiveDir())
	}
	if !manager.NeedsUpdate() {
		t.Fatal("missing database should need an update")
	}
}
