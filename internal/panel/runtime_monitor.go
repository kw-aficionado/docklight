package panel

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"example.com/yggdrasil-panel/internal/docker"
	"github.com/go-chi/chi/v5"
)

const (
	runtimeMonitorInterval        = 15 * time.Second
	runtimeStartupGrace           = 60 * time.Second
	runtimeMissingConfirmInterval = 15 * time.Second
	runtimeInspectTimeout         = 2 * time.Second
)

type serverCrash struct {
	ID         string `json:"id"`
	ServerID   string `json:"server_id"`
	Reason     string `json:"reason"`
	ExitCode   int    `json:"exit_code"`
	Message    string `json:"message"`
	DetectedAt string `json:"detected_at"`
}

type pendingRuntimeIncident struct {
	FirstSeen time.Time
	Reason    string
	ExitCode  int
}

// StartRuntimeMonitor records known exits for servers Docklight believed were running.
// Docker failures are treated as unknown and never trigger a state change.
func (a *App) StartRuntimeMonitor(ctx context.Context) {
	ticker := time.NewTicker(runtimeMonitorInterval)
	go func() {
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case now := <-ticker.C:
				if err := a.scanRunningServers(ctx, now); err != nil && !errors.Is(err, context.Canceled) {
					log.Printf("runtime monitor: %v", err)
				}
			}
		}
	}()
}

func (a *App) scanRunningServers(ctx context.Context, now time.Time) error {
	if now.Sub(a.booted) < runtimeStartupGrace {
		return nil
	}
	pingCtx, cancel := context.WithTimeout(ctx, runtimeInspectTimeout)
	err := a.pingRuntimeDocker(pingCtx)
	cancel()
	if err != nil {
		// Docker may be starting or unreachable. Keep the last known state.
		return nil
	}
	rows, err := a.db.Query(`SELECT id FROM servers WHERE status='running' AND container_id<>'' ORDER BY id`)
	if err != nil {
		return fmt.Errorf("could not list running servers")
	}
	ids := make([]string, 0)
	for rows.Next() {
		var id string
		if err = rows.Scan(&id); err != nil {
			_ = rows.Close()
			return fmt.Errorf("could not read running server IDs")
		}
		ids = append(ids, id)
	}
	if err = rows.Err(); err != nil {
		_ = rows.Close()
		return fmt.Errorf("could not read running server IDs")
	}
	if err = rows.Close(); err != nil {
		return fmt.Errorf("could not finish reading running server IDs")
	}
	for _, id := range ids {
		if err = ctx.Err(); err != nil {
			return err
		}
		if err = a.monitorServerRuntime(ctx, id, now); err != nil {
			return err
		}
	}
	return nil
}

func (a *App) pingRuntimeDocker(ctx context.Context) error {
	if a.runtimePing != nil {
		return a.runtimePing(ctx)
	}
	return a.engine.Ping(ctx)
}

func (a *App) inspectRuntimeContainer(ctx context.Context, id string) (docker.Inspect, error) {
	if a.runtimeInspect != nil {
		return a.runtimeInspect(ctx, id)
	}
	return a.engine.Inspect(ctx, id)
}

func (a *App) monitorServerRuntime(ctx context.Context, id string, now time.Time) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	a.dataMu.Lock()
	defer a.dataMu.Unlock()
	s, err := a.getServer(id)
	if errors.Is(err, sql.ErrNoRows) {
		a.clearRuntimePending(id)
		return nil
	}
	if err != nil {
		return fmt.Errorf("could not read server runtime state")
	}
	if s.Status != "running" || s.ContainerID == "" {
		a.clearRuntimePending(id)
		return nil
	}
	inspectCtx, cancel := context.WithTimeout(ctx, runtimeInspectTimeout)
	state, inspectErr := a.inspectRuntimeContainer(inspectCtx, s.ContainerID)
	cancel()
	if inspectErr != nil {
		if !isMissingContainerError(inspectErr) {
			a.clearRuntimePending(id)
			return nil
		}
		if !a.confirmRuntimeIncident(id, "container_missing", -1, now) {
			return nil
		}
		return a.recordServerCrash(s, "container_missing", -1, "Docker confirmed on repeated checks that this container is missing; server data was kept.")
	}
	if state.State.Running {
		a.clearRuntimePending(id)
		return nil
	}
	if !a.confirmRuntimeIncident(id, "container_exited", state.State.ExitCode, now) {
		return nil
	}
	message := fmt.Sprintf("Container exited unexpectedly with code %d; review its logs before restarting.", state.State.ExitCode)
	return a.recordServerCrash(s, "container_exited", state.State.ExitCode, message)
}

func isMissingContainerError(err error) bool {
	message := strings.ToLower(err.Error())
	return strings.Contains(message, "no such container") || strings.Contains(message, "no longer has this server container")
}

func (a *App) confirmRuntimeIncident(id, reason string, exitCode int, now time.Time) bool {
	a.runtimeMu.Lock()
	defer a.runtimeMu.Unlock()
	previous, ok := a.runtimePending[id]
	if !ok || previous.Reason != reason || previous.ExitCode != exitCode {
		a.runtimePending[id] = pendingRuntimeIncident{FirstSeen: now, Reason: reason, ExitCode: exitCode}
		return false
	}
	return now.Sub(previous.FirstSeen) >= runtimeMissingConfirmInterval
}

func (a *App) clearRuntimePending(id string) {
	a.runtimeMu.Lock()
	delete(a.runtimePending, id)
	a.runtimeMu.Unlock()
}

func (a *App) recordServerCrash(s Server, reason string, exitCode int, message string) error {
	id, err := newID()
	if err != nil {
		return fmt.Errorf("could not create server incident ID")
	}
	tx, err := a.db.Begin()
	if err != nil {
		return fmt.Errorf("could not record server incident")
	}
	result, err := tx.Exec(`UPDATE servers SET status='error',error_message=?,updated_at=CURRENT_TIMESTAMP WHERE id=? AND status IN ('running','starting') AND container_id=?`, message, s.ID, s.ContainerID)
	if err != nil {
		_ = tx.Rollback()
		return fmt.Errorf("could not update server state after container exit")
	}
	changed, err := result.RowsAffected()
	if err != nil {
		_ = tx.Rollback()
		return fmt.Errorf("could not confirm server state after container exit")
	}
	if changed == 0 {
		_ = tx.Rollback()
		return nil
	}
	detectedAt := time.Now().UTC().Format(time.RFC3339Nano)
	if _, err = tx.Exec(`INSERT INTO server_crashes(id,server_id,container_id,reason,exit_code,message,detected_at) VALUES(?,?,?,?,?,?,?)`, id, s.ID, s.ContainerID, reason, exitCode, message, detectedAt); err != nil {
		_ = tx.Rollback()
		return fmt.Errorf("could not save server crash history")
	}
	if err = tx.Commit(); err != nil {
		return fmt.Errorf("could not commit server crash history")
	}
	a.clearRuntimePending(s.ID)
	detail := fmt.Sprintf("reason=%s exit_code=%d", reason, exitCode)
	a.audit(User{Username: "runtime monitor"}, "server.container_crash", "server", s.ID, detail)
	if _, err = a.db.Exec(`DELETE FROM server_crashes WHERE server_id=? AND id NOT IN (SELECT id FROM server_crashes WHERE server_id=? ORDER BY detected_at DESC,id DESC LIMIT 100)`, s.ID, s.ID); err != nil {
		log.Printf("could not prune crash history for server %s", s.ID)
	}
	return nil
}

func (a *App) listServerCrashes(w http.ResponseWriter, r *http.Request) {
	s, err := a.getServer(chi.URLParam(r, "id"))
	if err != nil {
		writeError(w, http.StatusNotFound, "server not found")
		return
	}
	if !a.allowedServer(principal(r), "server.view", s.ID, s.GameskillID) {
		writeError(w, http.StatusForbidden, "server.view permission is required")
		return
	}
	rows, err := a.db.Query(`SELECT id,server_id,reason,exit_code,message,detected_at FROM server_crashes WHERE server_id=? ORDER BY detected_at DESC,id DESC LIMIT 50`, s.ID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not list server crash history")
		return
	}
	defer rows.Close()
	out := []serverCrash{}
	for rows.Next() {
		var item serverCrash
		if err = rows.Scan(&item.ID, &item.ServerID, &item.Reason, &item.ExitCode, &item.Message, &item.DetectedAt); err != nil {
			writeError(w, http.StatusInternalServerError, "could not read server crash history")
			return
		}
		out = append(out, item)
	}
	if err = rows.Err(); err != nil {
		writeError(w, http.StatusInternalServerError, "could not read server crash history")
		return
	}
	writeJSON(w, http.StatusOK, out)
}
