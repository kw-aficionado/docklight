package panel

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"example.com/yggdrasil-panel/internal/security"
)

func TestDiskMonitorAlertsOnceAndRearmsAtFifteenPercent(t *testing.T) {
	a, d, _ := testApp(t)
	endpoint, err := security.Encrypt([]byte(a.cfg.Auth.SecretKey), "http://127.0.0.1:18765/disk")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = d.Exec(`INSERT INTO notification_settings(id,enabled,endpoint_enc,events_json) VALUES(1,1,?,'["host.disk_low"]')`, endpoint); err != nil {
		t.Fatal(err)
	}
	requests := make(chan webhookPayload, 4)
	a.notificationClient = &http.Client{Transport: notificationRoundTripper(func(r *http.Request) (*http.Response, error) {
		body, readErr := io.ReadAll(r.Body)
		if readErr != nil {
			t.Errorf("read webhook body: %v", readErr)
		}
		var payload webhookPayload
		if err := json.Unmarshal(body, &payload); err != nil {
			t.Errorf("decode webhook body: %v", err)
		}
		requests <- payload
		return &http.Response{StatusCode: http.StatusNoContent, Header: make(http.Header), Body: io.NopCloser(strings.NewReader("")), Request: r}, nil
	})}
	total := uint64(100 << 30)
	setFree := func(percent float64) {
		a.diskProbe = func(path string) (diskUsage, error) {
			return diskUsage{Path: path, TotalBytes: total, AvailableBytes: uint64(float64(total) * percent / 100), FreePercent: percent}, nil
		}
		a.checkDiskSpace()
	}
	receive := func() webhookPayload {
		t.Helper()
		select {
		case payload := <-requests:
			return payload
		case <-time.After(time.Second):
			t.Fatal("low-disk webhook was not delivered")
			return webhookPayload{}
		}
	}
	assertNoEvent := func() {
		t.Helper()
		select {
		case payload := <-requests:
			t.Fatalf("unexpected repeated low-disk webhook: %#v", payload)
		case <-time.After(40 * time.Millisecond):
		}
	}

	setFree(10.0)
	assertNoEvent()
	setFree(9.9)
	first := receive()
	if first.Event != notificationHostDiskLow || first.Product != "Docklight" || !strings.Contains(first.Message, "9.9%") || !strings.Contains(first.Message, a.dataRoot) || !strings.Contains(first.Message, a.backupRoot) {
		t.Fatalf("unexpected low-disk event: %#v", first)
	}
	setFree(9.0)
	assertNoEvent()
	setFree(14.9)
	assertNoEvent()
	setFree(15.0)
	assertNoEvent()
	var active int
	if err = d.QueryRow(`SELECT active FROM system_alert_state WHERE name=?`, diskAlertName).Scan(&active); err != nil || active != 0 {
		t.Fatalf("alert was not rearmed at 15 percent: active=%d err=%v", active, err)
	}
	setFree(10.0)
	assertNoEvent()
	setFree(9.9)
	second := receive()
	if second.Event != notificationHostDiskLow || !strings.Contains(second.Message, "9.9%") {
		t.Fatalf("unexpected second low-disk event: %#v", second)
	}
	assertNoEvent()
	if err = d.QueryRow(`SELECT active FROM system_alert_state WHERE name=?`, diskAlertName).Scan(&active); err != nil || active != 1 {
		t.Fatalf("re-triggered alert was not persisted: active=%d err=%v", active, err)
	}
}

func TestDiskMonitorProbeFailureLeavesAlertStateUntouched(t *testing.T) {
	a, d, _ := testApp(t)
	a.diskProbe = func(string) (diskUsage, error) { return diskUsage{}, errors.New("statfs unavailable") }
	a.checkDiskSpace()
	var rows int
	if err := d.QueryRow(`SELECT count(*) FROM system_alert_state`).Scan(&rows); err != nil || rows != 0 {
		t.Fatalf("failed disk probe changed alert state: rows=%d err=%v", rows, err)
	}
}

func TestDiskStatusIsAdminOnlyAndUsesCurrentProbe(t *testing.T) {
	a, d, _ := testApp(t)
	if _, err := d.Exec(`INSERT INTO users(id,username,password_hash,role) VALUES('disk-admin','disk-admin','unused-hash','admin'),('disk-user','disk-user','unused-hash','user')`); err != nil {
		t.Fatal(err)
	}
	adminToken, err := a.issue(User{ID: "disk-admin", Username: "disk-admin", Role: "admin"})
	if err != nil {
		t.Fatal(err)
	}
	userToken, err := a.issue(User{ID: "disk-user", Username: "disk-user", Role: "user"})
	if err != nil {
		t.Fatal(err)
	}
	a.diskProbe = func(path string) (diskUsage, error) {
		return diskUsage{Path: path, TotalBytes: 1000, AvailableBytes: 420, FreePercent: 42}, nil
	}
	h := a.Router()
	denied := testRequest(h, http.MethodGet, "/api/system/disk", "", userToken)
	if denied.Code != http.StatusForbidden {
		t.Fatalf("non-admin read host storage state: %d %s", denied.Code, denied.Body.String())
	}
	response := testRequest(h, http.MethodGet, "/api/system/disk", "", adminToken)
	var status diskStatus
	if response.Code != http.StatusOK || json.Unmarshal(response.Body.Bytes(), &status) != nil || status.TotalBytes != 1000 || status.AvailableBytes != 420 || status.FreePercent != 42 || status.AlertActive {
		t.Fatalf("disk status response=%d body=%s decoded=%#v", response.Code, response.Body.String(), status)
	}
}

func TestDiskProbeReadsFilesystemCapacity(t *testing.T) {
	usage, err := probeDiskUsage(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if usage.TotalBytes == 0 || usage.AvailableBytes > usage.TotalBytes || usage.FreePercent < 0 || usage.FreePercent > 100 {
		t.Fatalf("invalid filesystem capacity: %#v", usage)
	}
	if diskMonitorInterval != 5*time.Minute || diskLowThreshold != 10 || diskRearmThreshold != 15 {
		t.Fatalf("unexpected low-disk policy: interval=%s trigger=%.1f rearm=%.1f", diskMonitorInterval, diskLowThreshold, diskRearmThreshold)
	}
}
