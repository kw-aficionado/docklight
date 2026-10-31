package panel

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"time"

	"example.com/yggdrasil-panel/internal/rune"
	"github.com/go-chi/chi/v5"
)

const (
	watchdogInterval          = 20 * time.Second
	watchdogQueryTimeout      = 3 * time.Second
	watchdogFailureLimit      = 3
	watchdogCooldown          = 4 * time.Minute
	watchdogHealWindow        = 30 * time.Minute
	watchdogQuarantineAtHeals = 5
)

type watchdogRuntimeState struct {
	Failures    int
	LastAttempt time.Time
	Heals       []time.Time
}

// StartWatchdogMonitor checks opted-in query-capable servers every 20 seconds.
func (a *App) StartWatchdogMonitor(ctx context.Context) {
	ticker := time.NewTicker(watchdogInterval)
	go func() {
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case now := <-ticker.C:
				if err := a.scanWatchdogs(ctx, now); err != nil && !errors.Is(err, context.Canceled) {
					log.Printf("watchdog monitor: %v", err)
				}
			}
		}
	}()
}

func (a *App) scanWatchdogs(ctx context.Context, now time.Time) error {
	if now.Sub(a.booted) < runtimeStartupGrace {
		return nil
	}
	pingCtx, cancel := context.WithTimeout(ctx, runtimeInspectTimeout)
	err := a.pingRuntimeDocker(pingCtx)
	cancel()
	if err != nil {
		return nil
	}
	rows, err := a.db.Query(`SELECT id FROM servers WHERE status='running' AND watchdog_enabled=1 AND watchdog_quarantined=0 AND container_id<>'' ORDER BY id`)
	if err != nil {
		return errors.New("could not list watchdog-enabled servers")
	}
	ids := make([]string, 0)
	for rows.Next() {
		var id string
		if err = rows.Scan(&id); err != nil {
			_ = rows.Close()
			return errors.New("could not read watchdog-enabled server IDs")
		}
		ids = append(ids, id)
	}
	if err = rows.Err(); err != nil {
		_ = rows.Close()
		return errors.New("could not read watchdog-enabled server IDs")
	}
	if err = rows.Close(); err != nil {
		return errors.New("could not finish reading watchdog-enabled server IDs")
	}
	for _, id := range ids {
		if err = ctx.Err(); err != nil {
			return err
		}
		a.monitorWatchdogServer(ctx, id, now)
	}
	return nil
}

func (a *App) monitorWatchdogServer(ctx context.Context, id string, now time.Time) {
	s, err := a.getServer(id)
	if err != nil || s.Status != "running" || !s.WatchdogEnabled || s.WatchdogQuarantined || s.ContainerID == "" {
		return
	}
	gs, err := a.loadRune(s.GameskillID)
	if err != nil || gs.Query == nil {
		return
	}
	probe := a.watchdogQuery
	if probe == nil {
		probe = probeWatchdogServer
	}
	probeCtx, cancel := context.WithTimeout(ctx, watchdogQueryTimeout)
	probeErr := probe(probeCtx, s, gs)
	cancel()
	if probeErr == nil {
		a.watchdogMu.Lock()
		if state := a.watchdogStates[id]; state != nil {
			state.Failures = 0
		}
		a.watchdogMu.Unlock()
		return
	}
	// Re-read after the network probe so a manual stop or opt-out wins.
	s, err = a.getServer(id)
	if err != nil || s.Status != "running" || !s.WatchdogEnabled || s.WatchdogQuarantined || s.ContainerID == "" {
		return
	}
	a.watchdogMu.Lock()
	state := a.watchdogStates[id]
	if state == nil {
		state = a.loadWatchdogRuntimeState(id, now)
		a.watchdogStates[id] = state
	}
	state.Failures++
	if state.Failures < watchdogFailureLimit || !state.LastAttempt.IsZero() && now.Sub(state.LastAttempt) < watchdogCooldown {
		a.watchdogMu.Unlock()
		return
	}
	state.Heals = recentWatchdogHeals(state.Heals, now)
	if len(state.Heals) >= watchdogQuarantineAtHeals {
		a.watchdogMu.Unlock()
		a.quarantineWatchdog(id, s)
		return
	}
	state.Failures = 0
	state.LastAttempt = now
	if _, persistErr := a.db.Exec(`UPDATE servers SET watchdog_last_attempt=? WHERE id=?`, now.Unix(), id); persistErr != nil {
		log.Printf("watchdog could not persist cooldown for server %s: %v", id, persistErr)
	}
	a.watchdogMu.Unlock()

	a.dispatchWebhookNotification(notificationWatchdog, &webhookServer{ID: s.ID, Name: s.Name}, "Three consecutive player-query checks failed. Docklight is attempting an automatic restart.")
	heal := a.watchdogHeal
	if heal == nil {
		heal = func(ctx context.Context, server Server) error {
			return a.watchdogHealServer(ctx, server, now)
		}
	}
	healErr := heal(ctx, s)
	if healErr != nil {
		log.Printf("watchdog could not restart server %s: %v", s.ID, healErr)
		a.audit(User{Username: "watchdog"}, "server.watchdog.failure", "server", s.ID, "automatic restart failed after three query failures")
		a.dispatchWebhookNotification(notificationWatchdog, &webhookServer{ID: s.ID, Name: s.Name}, "The automatic restart failed after three consecutive player-query checks. Check Docker and the server Console.")
		return
	}
	a.watchdogMu.Lock()
	if current := a.watchdogStates[id]; current == state {
		current.Heals = append(current.Heals, now)
		if _, persistErr := a.db.Exec(`INSERT INTO server_watchdog_heals(server_id,healed_at) VALUES(?,?)`, id, now.Unix()); persistErr != nil {
			log.Printf("watchdog could not persist heal history for server %s: %v", id, persistErr)
		} else if _, pruneErr := a.db.Exec(`DELETE FROM server_watchdog_heals WHERE server_id=? AND healed_at<=?`, id, now.Unix()-int64(watchdogHealWindow/time.Second)); pruneErr != nil {
			log.Printf("watchdog could not prune heal history for server %s: %v", id, pruneErr)
		}
	}
	a.watchdogMu.Unlock()
	a.audit(User{Username: "watchdog"}, "server.watchdog.heal", "server", s.ID, "automatic restart after three query failures")
	a.dispatchWebhookNotification(notificationWatchdog, &webhookServer{ID: s.ID, Name: s.Name}, "Docklight restarted the server after three consecutive player-query failures.")

	// Five successful automatic heals in a rolling 30-minute window pause
	// further automation until an operator manually starts or stops the server.
	a.watchdogMu.Lock()
	current := a.watchdogStates[id]
	quarantine := current == state && len(recentWatchdogHeals(current.Heals, now)) >= watchdogQuarantineAtHeals
	a.watchdogMu.Unlock()
	if quarantine {
		a.quarantineWatchdog(id, s)
	}
}

func probeWatchdogServer(ctx context.Context, s Server, gs rune.Rune) error {
	port, err := queryPort(s, gs)
	if err != nil {
		return err
	}
	_, err = queryAtPort(ctx, gs, port)
	return err
}

func recentWatchdogHeals(heals []time.Time, now time.Time) []time.Time {
	active := heals[:0]
	for _, at := range heals {
		if now.Sub(at) < watchdogHealWindow {
			active = append(active, at)
		}
	}
	return active
}

func (a *App) loadWatchdogRuntimeState(id string, now time.Time) *watchdogRuntimeState {
	state := &watchdogRuntimeState{}
	var lastAttempt int64
	if err := a.db.QueryRow(`SELECT watchdog_last_attempt FROM servers WHERE id=?`, id).Scan(&lastAttempt); err == nil && lastAttempt > 0 {
		state.LastAttempt = time.Unix(lastAttempt, 0)
	} else if err != nil {
		log.Printf("watchdog could not load cooldown for server %s: %v", id, err)
	}
	rows, err := a.db.Query(`SELECT healed_at FROM server_watchdog_heals WHERE server_id=? AND healed_at>? ORDER BY healed_at`, id, now.Unix()-int64(watchdogHealWindow/time.Second))
	if err != nil {
		log.Printf("watchdog could not load heal history for server %s: %v", id, err)
		return state
	}
	defer rows.Close()
	for rows.Next() {
		var at int64
		if err = rows.Scan(&at); err != nil {
			log.Printf("watchdog could not read heal history for server %s: %v", id, err)
			state.Heals = nil
			return state
		}
		state.Heals = append(state.Heals, time.Unix(at, 0))
	}
	if err = rows.Err(); err != nil {
		log.Printf("watchdog could not finish reading heal history for server %s: %v", id, err)
		state.Heals = nil
		return state
	}
	state.Heals = recentWatchdogHeals(state.Heals, now)
	return state
}

func (a *App) quarantineWatchdog(id string, s Server) {
	result, err := a.db.Exec(`UPDATE servers SET watchdog_quarantined=1,updated_at=CURRENT_TIMESTAMP WHERE id=? AND watchdog_enabled=1 AND status IN ('running','starting') AND watchdog_quarantined=0`, id)
	if err != nil {
		log.Printf("watchdog could not quarantine server %s", id)
		return
	}
	changed, err := result.RowsAffected()
	if err != nil || changed == 0 {
		return
	}
	a.audit(User{Username: "watchdog"}, "server.watchdog.quarantine", "server", id, fmt.Sprintf("%d automatic heals in the last 30 minutes", watchdogQuarantineAtHeals))
	a.dispatchWebhookNotification(notificationWatchdog, &webhookServer{ID: s.ID, Name: s.Name}, "Docklight paused automatic recovery after five heals in 30 minutes. Manually start or stop this server after investigating the cause.")
	a.watchdogMu.Lock()
	if state := a.watchdogStates[id]; state != nil {
		state.Failures = 0
	}
	a.watchdogMu.Unlock()
}

func (a *App) watchdogHealServer(ctx context.Context, stale Server, reservedAt time.Time) error {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	var lastErr error
	for attempt := 1; attempt <= 3; attempt++ {
		if attempt > 1 {
			if err := a.waitWatchdogRetry(ctx, 15*time.Second); err != nil {
				return err
			}
		}
		a.dataMu.Lock()
		s, err := a.getServer(stale.ID)
		if err != nil {
			a.dataMu.Unlock()
			return err
		}
		var currentAttempt int64
		if err = a.db.QueryRow(`SELECT watchdog_last_attempt FROM servers WHERE id=?`, stale.ID).Scan(&currentAttempt); err != nil {
			a.dataMu.Unlock()
			return err
		}
		if currentAttempt != reservedAt.Unix() {
			a.dataMu.Unlock()
			return errors.New("automatic recovery was cancelled by a manual server action")
		}
		if attempt == 1 && s.Status != "running" {
			a.dataMu.Unlock()
			return errors.New("server was manually stopped before automatic recovery began")
		}
		if !s.WatchdogEnabled || s.WatchdogQuarantined {
			a.dataMu.Unlock()
			return errors.New("watchdog was disabled before the automatic restart began")
		}
		if a.watchdogStart != nil {
			lastErr = a.watchdogStart(ctx, s)
		} else if s.ContainerID != "" {
			lastErr = a.recreateAndStart(ctx, s)
		} else {
			lastErr = a.startWithContext(s, ctx)
		}
		a.dataMu.Unlock()
		if lastErr == nil {
			return nil
		}
	}
	return fmt.Errorf("automatic restart failed after three attempts: %w", lastErr)
}

func (a *App) waitWatchdogRetry(ctx context.Context, delay time.Duration) error {
	if a.watchdogWait != nil {
		return a.watchdogWait(ctx, delay)
	}
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func (a *App) resetWatchdog(id string) {
	a.watchdogMu.Lock()
	delete(a.watchdogStates, id)
	a.watchdogMu.Unlock()
	if _, err := a.db.Exec(`UPDATE servers SET watchdog_quarantined=0,watchdog_last_attempt=0 WHERE id=?`, id); err != nil {
		log.Printf("watchdog could not clear server state for %s: %v", id, err)
	}
	if _, err := a.db.Exec(`DELETE FROM server_watchdog_heals WHERE server_id=?`, id); err != nil {
		log.Printf("watchdog could not clear heal history for %s: %v", id, err)
	}
}

func (a *App) updateWatchdogSettings(w http.ResponseWriter, r *http.Request) {
	s, err := a.getServer(chi.URLParam(r, "id"))
	if err != nil {
		writeError(w, http.StatusNotFound, "server not found")
		return
	}
	u := principal(r)
	if !a.allowedServer(u, "server.control", s.ID, s.GameskillID, s.RealmID) {
		writeError(w, http.StatusForbidden, "server.control permission is required")
		return
	}
	var in struct {
		Enabled *bool `json:"enabled"`
	}
	if decodeJSON(w, r, &in, 4096) != nil {
		return
	}
	if in.Enabled == nil {
		writeError(w, http.StatusBadRequest, "enabled must be true or false")
		return
	}
	gs, err := a.loadRune(s.GameskillID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "server template is invalid")
		return
	}
	if *in.Enabled && gs.Query == nil {
		writeError(w, http.StatusConflict, "automatic recovery requires a template with a player query protocol")
		return
	}
	a.dataMu.Lock()
	defer a.dataMu.Unlock()
	s, err = a.getServer(s.ID)
	if err != nil {
		writeError(w, http.StatusNotFound, "server not found")
		return
	}
	if _, err = a.db.Exec(`UPDATE servers SET watchdog_enabled=?,watchdog_quarantined=CASE WHEN ?=0 OR watchdog_enabled=0 THEN 0 ELSE watchdog_quarantined END,updated_at=CURRENT_TIMESTAMP WHERE id=?`, boolInt(*in.Enabled), boolInt(*in.Enabled), s.ID); err != nil {
		writeError(w, http.StatusInternalServerError, "could not update automatic recovery settings")
		return
	}
	if !*in.Enabled || !s.WatchdogEnabled {
		a.resetWatchdog(s.ID)
	}
	a.audit(u, "server.watchdog.settings", "server", s.ID, fmt.Sprintf("enabled=%t", *in.Enabled))
	s, err = a.getServer(s.ID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "settings were saved but the server could not be reloaded")
		return
	}
	writeJSON(w, http.StatusOK, a.decorateServer(u, maskServer(s, a.db)))
}
