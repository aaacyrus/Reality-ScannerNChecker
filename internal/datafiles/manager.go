// Package datafiles manages the optional country database used to exclude CN endpoints.
package datafiles

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/oschwald/geoip2-golang"
)

const updateInterval = 7 * 24 * time.Hour

type Manager struct {
	cacheDir string
	active   string
	client   *http.Client
	now      func() time.Time
}

var countryDatabaseURL = "https://github.com/Loyalsoldier/geoip/releases/latest/download/Country.mmdb"

func New() (*Manager, error) {
	base, err := os.UserCacheDir()
	if err != nil {
		return nil, err
	}
	return &Manager{cacheDir: filepath.Join(base, "reality-scanner-checker", "data"), client: &http.Client{Timeout: 45 * time.Second}, now: time.Now}, nil
}

// Prepare uses a validated local database when one exists. No third-party
// source or embedded snapshot is shipped with this project.
func (m *Manager) Prepare() error {
	if validateDirectory(m.cacheDir) == nil {
		m.active = m.cacheDir
	}
	return nil
}

func (m *Manager) ActiveDir() string { return m.active }

func (m *Manager) NeedsUpdate() bool {
	info, err := os.Stat(filepath.Join(m.cacheDir, "Country.mmdb"))
	return err != nil || m.now().Sub(info.ModTime()) >= updateInterval
}

func (m *Manager) Update(ctx context.Context, progress func(done, total int, name string)) error {
	if err := os.MkdirAll(m.cacheDir, 0o700); err != nil {
		return err
	}
	staging, err := os.CreateTemp(m.cacheDir, ".Country.mmdb-*")
	if err != nil {
		return err
	}
	temporary := staging.Name()
	defer os.Remove(temporary)
	if err := m.download(ctx, countryDatabaseURL, staging); err != nil {
		staging.Close()
		return err
	}
	if err := staging.Close(); err != nil {
		return err
	}
	if err := validateCountryDatabase(temporary); err != nil {
		return fmt.Errorf("downloaded country database is invalid: %w", err)
	}
	if progress != nil {
		progress(1, 1, "Country.mmdb")
	}
	if err := os.Rename(temporary, filepath.Join(m.cacheDir, "Country.mmdb")); err != nil {
		return err
	}
	m.active = m.cacheDir
	return nil
}

func (m *Manager) Close() error { return nil }

func (m *Manager) download(ctx context.Context, sourceURL string, destination *os.File) error {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, sourceURL, nil)
	if err != nil {
		return err
	}
	response, err := m.client.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected HTTP status %d", response.StatusCode)
	}
	_, err = io.Copy(destination, io.LimitReader(response.Body, 64<<20))
	return err
}

func validateDirectory(dir string) error {
	return validateCountryDatabase(filepath.Join(dir, "Country.mmdb"))
}

func validateCountryDatabase(path string) error {
	info, err := os.Stat(path)
	if err != nil {
		return err
	}
	if info.Size() == 0 {
		return fmt.Errorf("Country.mmdb is empty")
	}
	reader, err := geoip2.Open(path)
	if err != nil {
		return err
	}
	return reader.Close()
}
