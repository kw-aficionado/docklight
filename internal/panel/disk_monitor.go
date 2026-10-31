package panel

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log"
	"net/http"
	"path/filepath"
	"time"

	"golang.org/x/sys/unix"
)

const (
	diskMonitorInterval = 5 * time.Minute
	diskLowThreshold    = 10.0
	diskRearmThreshold  = 15.0
	diskAlertName       = "panel_storage_low"
)

type diskUsage struct {
	Path           string  `json:"path"`
	TotalBytes     uint64  `json:"total_bytes"`
	AvailableBytes uint64  `json:"available_bytes"`
	FreePercent    float64 `json:"free_percent"`
}

type diskStatus struct {
	diskUsage
	AlertActive bool   `json:"alert_active"`
	MeasuredAt  string `json:"measured_at"`
}

func probeDiskUsage(path string) (diskUsage, error) {
	var stat unix.Statfs_t
	if err := unix.Statfs(path, &stat); err != nil {
		return diskUsage{}, fmt.Errorf("could not read filesystem usage for %s", path)
	}
	if stat.Bsize <= 0 {
		return diskUsage{}, errors.New("filesystem reported an invalid block size")
	}
	blockSize := uint64(stat.Bsize)
	total := uint64(stat.Blocks) * blockSize
	available := uint64(stat.Bavail) * blockSize
	if total == 0 {
		return diskUsage{}, errors.New("filesystem reported zero total capacity")
	}
	if available > total {
		available = total
	}
	return diskUsage{Path: path, TotalBytes: total, AvailableBytes: available, FreePercent: float64(available) * 100 / float64(total)}, nil
}

func (a *App) panelStoragePath() string {
	return filepath.Dir(a.dataRoot)
}

// StartDiskMonitor checks the filesystem holding Docklight's panel data and
// emits one webhook when free space falls below 10 percent. It rearms at 15.
func (a *App) StartDiskMonitor(ctx context.Context) {
	ticker := time.NewTicker(diskMonitorInterval)
	go func() {
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				a.checkDiskSpace()
			}
		}
	}()
}

func (a *App) checkDiskSpace() {
	path := a.panelStoragePath()
	probe := a.diskProbe
	if probe == nil {
		probe = probeDiskUsage
	}
	usage, err := probe(path)
	if err != nil {
		log.Printf("disk monitor: %v", err)
		return
	}
	alert, err := a.updateDiskAlertState(usage.FreePercent)
	if err != nil {
		log.Printf("disk monitor: could not update alert state")
		return
	}
	if alert {
		message := fmt.Sprintf("Docklight storage on %s has only %.1f%% available (%s free of %s). Inspect server data at %s and local backups at %s; these are the panel's known storage locations.", usage.Path, usage.FreePercent, formatDiskBytes(usage.AvailableBytes), formatDiskBytes(usage.TotalBytes), a.dataRoot, a.backupRoot)
		a.dispatchWebhookNotification(notificationHostDiskLow, nil, message)
	}
}

func (a *App) updateDiskAlertState(freePercent float64) (bool, error) {
	a.diskAlertMu.Lock()
	defer a.diskAlertMu.Unlock()
	var active int
	err := a.db.QueryRow(`SELECT active FROM system_alert_state WHERE name=?`, diskAlertName).Scan(&active)
	if errors.Is(err, sql.ErrNoRows) {
		active = 0
	} else if err != nil {
		return false, err
	}
	if active == 0 && freePercent < diskLowThreshold {
		if _, err = a.db.Exec(`INSERT INTO system_alert_state(name,active,updated_at) VALUES(?,1,CURRENT_TIMESTAMP) ON CONFLICT(name) DO UPDATE SET active=1,updated_at=CURRENT_TIMESTAMP`, diskAlertName); err != nil {
			return false, err
		}
		return true, nil
	}
	if active != 0 && freePercent >= diskRearmThreshold {
		if _, err = a.db.Exec(`UPDATE system_alert_state SET active=0,updated_at=CURRENT_TIMESTAMP WHERE name=?`, diskAlertName); err != nil {
			return false, err
		}
	}
	return false, nil
}

func (a *App) getDiskStatus(w http.ResponseWriter, _ *http.Request) {
	path := a.panelStoragePath()
	probe := a.diskProbe
	if probe == nil {
		probe = probeDiskUsage
	}
	usage, err := probe(path)
	if err != nil {
		writeError(w, 503, "could not read panel storage capacity; check that the configured data path exists and is accessible")
		return
	}
	a.diskAlertMu.Lock()
	var active int
	err = a.db.QueryRow(`SELECT active FROM system_alert_state WHERE name=?`, diskAlertName).Scan(&active)
	if errors.Is(err, sql.ErrNoRows) {
		err = nil
	}
	a.diskAlertMu.Unlock()
	if err != nil {
		writeError(w, 500, "could not read disk alert state")
		return
	}
	writeJSON(w, 200, diskStatus{diskUsage: usage, AlertActive: active != 0 || usage.FreePercent < diskLowThreshold, MeasuredAt: time.Now().UTC().Format(time.RFC3339Nano)})
}

func formatDiskBytes(value uint64) string {
	const gib = uint64(1 << 30)
	if value >= gib {
		return fmt.Sprintf("%.1f GiB", float64(value)/float64(gib))
	}
	const mib = uint64(1 << 20)
	return fmt.Sprintf("%.1f MiB", float64(value)/float64(mib))
}
