package panel

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log"
	"net/http"
	"regexp"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"example.com/yggdrasil-panel/internal/docker"
	"github.com/go-chi/chi/v5"
)

const (
	violationScanInterval = 15 * time.Second
	violationRetryDelay   = 5 * time.Minute
	violationMaxLogLine   = 64 * 1024
	violationMaxHitKeys   = 50000
)

var (
	violationPlayerPattern = regexp.MustCompile(`^[\pL\pN_.@ -]{1,64}$`)
	violationPlayerID      = regexp.MustCompile(`^[A-Za-z0-9_.:-]{1,128}$`)
	errBanAlreadyActive    = errors.New("an active ban already exists for this player and scope")
)

type banRecord struct {
	ID          string `json:"id"`
	PlayerName  string `json:"player_name"`
	PlayerID    string `json:"player_id,omitempty"`
	ServerID    string `json:"server_id"`
	ServerName  string `json:"server_name"`
	Reason      string `json:"reason"`
	BannedBy    string `json:"banned_by"`
	ExpiresAt   string `json:"expires_at,omitempty"`
	Active      bool   `json:"active"`
	CreatedAt   string `json:"created_at"`
	RevokedAt   string `json:"revoked_at,omitempty"`
	SyncApplied int    `json:"sync_applied"`
	SyncPending int    `json:"sync_pending"`
	SyncErrors  int    `json:"sync_errors"`
	SyncError   string `json:"sync_error,omitempty"`
}

type banInput struct {
	PlayerName string `json:"player_name"`
	PlayerID   string `json:"player_id"`
	ServerID   string `json:"server_id"`
	Reason     string `json:"reason"`
	ExpiresAt  string `json:"expires_at"`
}

type violationRule struct {
	ID            string         `json:"id"`
	Name          string         `json:"name"`
	Pattern       string         `json:"pattern"`
	Threshold     int            `json:"threshold"`
	WindowMinutes int            `json:"window_minutes"`
	Action        string         `json:"action"`
	ScopeGlobal   bool           `json:"scope_global"`
	Enabled       bool           `json:"enabled"`
	CreatedAt     string         `json:"created_at,omitempty"`
	UpdatedAt     string         `json:"updated_at,omitempty"`
	compiled      *regexp.Regexp `json:"-"`
}

type violationRuleInput struct {
	Name          string `json:"name"`
	Pattern       string `json:"pattern"`
	Threshold     int    `json:"threshold"`
	WindowMinutes int    `json:"window_minutes"`
	Action        string `json:"action"`
	ScopeGlobal   bool   `json:"scope_global"`
	Enabled       *bool  `json:"enabled"`
}

type violationLogWatch struct {
	containerID string
	cancel      context.CancelFunc
}

type violationAction struct {
	rule   violationRule
	server Server
	player string
}

// StartViolationMonitor watches only new log output from running containers and
// retries saved ban operations after server starts or temporary command errors.
func (a *App) StartViolationMonitor(ctx context.Context) {
	go a.runViolationActions(ctx)
	go func() {
		a.scanViolationServers(ctx)
		ticker := time.NewTicker(violationScanInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				a.stopViolationWatches()
				return
			case <-ticker.C:
				a.scanViolationServers(ctx)
			}
		}
	}()
}

func (a *App) scanViolationServers(ctx context.Context) {
	if err := a.expireBans(ctx, time.Now().UTC()); err != nil {
		log.Printf("could not expire player bans: %v", err)
	}
	rows, err := a.db.QueryContext(ctx, `SELECT id FROM servers WHERE installed=1 AND status='running' AND container_id<>'' ORDER BY id`)
	if err != nil {
		log.Printf("could not list running servers for moderation: %v", err)
		return
	}
	ids := make([]string, 0)
	for rows.Next() {
		var id string
		if rows.Scan(&id) == nil {
			ids = append(ids, id)
		}
	}
	rowsErr := rows.Err()
	_ = rows.Close()
	if rowsErr != nil {
		log.Printf("could not finish listing running servers for moderation: %v", rowsErr)
		return
	}
	active := make(map[string]Server, len(ids))
	for _, id := range ids {
		server, getErr := a.getServer(id)
		if getErr != nil || server.Status != "running" || server.ContainerID == "" {
			continue
		}
		active[id] = server
	}
	a.syncViolationWatches(ctx, active)
	for _, server := range active {
		if err := a.reconcileServerBanStates(ctx, server); err != nil && !errors.Is(err, context.Canceled) {
			log.Printf("could not reconcile player bans for server %s: %v", server.ID, err)
		}
	}
	a.pruneViolationHits(time.Now())
}

func (a *App) syncViolationWatches(parent context.Context, active map[string]Server) {
	a.violationMu.Lock()
	if a.violationWatches == nil {
		a.violationWatches = map[string]violationLogWatch{}
	}
	for id, watch := range a.violationWatches {
		server, ok := active[id]
		if !ok || server.ContainerID != watch.containerID {
			watch.cancel()
			delete(a.violationWatches, id)
		}
	}
	for id, server := range active {
		if _, ok := a.violationWatches[id]; ok {
			continue
		}
		watchCtx, cancel := context.WithCancel(parent)
		a.violationWatches[id] = violationLogWatch{containerID: server.ContainerID, cancel: cancel}
		go a.watchViolationLogs(watchCtx, server)
	}
	a.violationMu.Unlock()
}

func (a *App) stopViolationWatches() {
	a.violationMu.Lock()
	defer a.violationMu.Unlock()
	for id, watch := range a.violationWatches {
		watch.cancel()
		delete(a.violationWatches, id)
	}
}

func (a *App) watchViolationLogs(ctx context.Context, server Server) {
	for ctx.Err() == nil {
		// tail=0 keeps old log history from triggering new moderation actions.
		body, err := a.engine.Logs(ctx, server.ContainerID, "0", true)
		if err == nil {
			writer := &violationLogWriter{ctx: ctx, app: a, server: server}
			err = docker.CopyLogs(writer, body)
			_ = body.Close()
			if writer.carry != "" && !writer.discardLine {
				writer.process(writer.carry)
			}
		}
		if ctx.Err() != nil {
			return
		}
		if err != nil {
			log.Printf("moderation log stream ended for server %s: %v", server.ID, err)
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(2 * time.Second):
		}
	}
}

type violationLogWriter struct {
	ctx         context.Context
	app         *App
	server      Server
	carry       string
	discardLine bool
}

func (w *violationLogWriter) Write(p []byte) (int, error) {
	inputLen := len(p)
	if w.discardLine {
		newline := strings.IndexByte(string(p), '\n')
		if newline < 0 {
			return len(p), nil
		}
		p = p[newline+1:]
		w.discardLine = false
		w.carry = ""
	}
	combined := w.carry + string(p)
	parts := strings.Split(combined, "\n")
	for _, line := range parts[:len(parts)-1] {
		line = strings.TrimSuffix(line, "\r")
		if len(line) <= violationMaxLogLine && strings.TrimSpace(line) != "" {
			w.process(line)
		}
	}
	w.carry = parts[len(parts)-1]
	if len(w.carry) > violationMaxLogLine {
		w.carry = ""
		w.discardLine = true
	}
	return inputLen, nil
}

func (w *violationLogWriter) process(line string) {
	rules, err := w.app.violationRuleSnapshot(w.ctx)
	if err != nil {
		return
	}
	now := time.Now()
	for _, rule := range rules {
		if !rule.Enabled || rule.compiled == nil {
			continue
		}
		match := rule.compiled.FindStringSubmatch(line)
		if len(match) < 2 {
			continue
		}
		player := cleanModerationText(match[1], 64)
		if !validModerationPlayer(player) {
			continue
		}
		key := rule.ID + "\x00" + w.server.ID + "\x00" + strings.ToLower(player)
		window := time.Duration(rule.WindowMinutes) * time.Minute
		w.app.violationMu.Lock()
		if w.app.violationHits == nil {
			w.app.violationHits = map[string][]time.Time{}
		}
		hits := w.app.violationHits[key]
		if len(hits) == 0 && len(w.app.violationHits) >= violationMaxHitKeys {
			shouldLog := now.Sub(w.app.violationDroppedAt) >= time.Minute
			if shouldLog {
				w.app.violationDroppedAt = now
			}
			w.app.violationMu.Unlock()
			if shouldLog {
				log.Printf("moderation hit tracker reached its %d-player limit; additional log matches are not counted", violationMaxHitKeys)
			}
			continue
		}
		kept := hits[:0]
		for _, hit := range hits {
			if now.Sub(hit) <= window {
				kept = append(kept, hit)
			}
		}
		kept = append(kept, now)
		fired := len(kept) >= rule.Threshold
		queueFull := false
		if fired {
			action := violationAction{rule: rule, server: w.server, player: player}
			select {
			case w.app.violationActions <- action:
				delete(w.app.violationHits, key)
			default:
				if len(kept) > rule.Threshold {
					kept = kept[len(kept)-rule.Threshold:]
				}
				w.app.violationHits[key] = kept
				queueFull = true
			}
		} else {
			w.app.violationHits[key] = kept
		}
		shouldLogDrop := false
		if queueFull && now.Sub(w.app.violationDroppedAt) >= time.Minute {
			w.app.violationDroppedAt = now
			shouldLogDrop = true
		}
		w.app.violationMu.Unlock()
		if shouldLogDrop {
			log.Printf("moderation action queue is full; matched actions will retry on later log output")
		}
	}
}

func (a *App) runViolationActions(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case action := <-a.violationActions:
			a.executeViolationAction(ctx, action)
		}
	}
}

func (a *App) executeViolationAction(parent context.Context, action violationAction) {
	ctx, cancel := context.WithTimeout(parent, 12*time.Second)
	defer cancel()
	reason := "auto: " + action.rule.Name
	server := &webhookServer{ID: action.server.ID, Name: action.server.Name}
	if action.rule.Action == "kick" {
		if _, err := a.sendCommand(ctx, action.server, "kick "+action.player); err != nil {
			log.Printf("automatic kick failed for player %q on server %s: %v", action.player, action.server.ID, err)
			return
		}
		detail := fmt.Sprintf("auto-kicked %s after %d matching log lines in %d minutes (rule %s)", action.player, action.rule.Threshold, action.rule.WindowMinutes, action.rule.Name)
		a.audit(User{Username: "system"}, "violation.kick", "server", action.server.ID, detail)
		a.dispatchWebhookNotification(notificationAutoModeration, server, "👢 Auto-kicked "+action.player+" on rule "+action.rule.Name+".")
		return
	}
	_, err := a.createBanRecord(ctx, banInput{PlayerName: action.player, ServerID: func() string {
		if action.rule.ScopeGlobal {
			return ""
		}
		return action.server.ID
	}(), Reason: reason}, "Docklight automation")
	if errors.Is(err, errBanAlreadyActive) {
		return
	}
	if err != nil {
		log.Printf("automatic ban failed for player %q on server %s: %v", action.player, action.server.ID, err)
		return
	}
	detail := fmt.Sprintf("queued auto-ban for %s after %d matching log lines in %d minutes (rule %s)", action.player, action.rule.Threshold, action.rule.WindowMinutes, action.rule.Name)
	a.audit(User{Username: "system"}, "violation.ban.queued", "ban", action.player, detail)
}

func (a *App) violationRuleSnapshot(ctx context.Context) ([]violationRule, error) {
	a.violationMu.Lock()
	if time.Since(a.violationRulesAt) < violationScanInterval {
		out := append([]violationRule(nil), a.violationRules...)
		a.violationMu.Unlock()
		return out, nil
	}
	a.violationMu.Unlock()
	rows, err := a.db.QueryContext(ctx, `SELECT id,name,pattern,threshold,window_minutes,action,scope_global,enabled,created_at,updated_at FROM violation_rules ORDER BY id`)
	if err != nil {
		return nil, err
	}
	var rules []violationRule
	for rows.Next() {
		var item violationRule
		var scope, enabled int
		if err = rows.Scan(&item.ID, &item.Name, &item.Pattern, &item.Threshold, &item.WindowMinutes, &item.Action, &scope, &enabled, &item.CreatedAt, &item.UpdatedAt); err != nil {
			_ = rows.Close()
			return nil, err
		}
		item.ScopeGlobal, item.Enabled = scope != 0, enabled != 0
		item.compiled, err = regexp.Compile(item.Pattern)
		if err != nil {
			_ = rows.Close()
			return nil, fmt.Errorf("stored violation rule %s has an invalid pattern", item.ID)
		}
		rules = append(rules, item)
	}
	if err = rows.Err(); err != nil {
		_ = rows.Close()
		return nil, err
	}
	_ = rows.Close()
	a.violationMu.Lock()
	a.violationRules = rules
	a.violationRulesAt = time.Now()
	out := append([]violationRule(nil), rules...)
	a.violationMu.Unlock()
	return out, nil
}

func (a *App) invalidateViolationRules() {
	a.violationMu.Lock()
	a.violationRulesAt = time.Time{}
	a.violationMu.Unlock()
}

func (a *App) clearViolationHits(ruleID string) {
	a.violationMu.Lock()
	defer a.violationMu.Unlock()
	prefix := ruleID + "\x00"
	for key := range a.violationHits {
		if strings.HasPrefix(key, prefix) {
			delete(a.violationHits, key)
		}
	}
}

func (a *App) pruneViolationHits(now time.Time) {
	a.violationMu.Lock()
	defer a.violationMu.Unlock()
	for key, hits := range a.violationHits {
		kept := hits[:0]
		for _, hit := range hits {
			if now.Sub(hit) <= 24*time.Hour {
				kept = append(kept, hit)
			}
		}
		if len(kept) == 0 {
			delete(a.violationHits, key)
		} else {
			a.violationHits[key] = kept
		}
	}
}

func validModerationPlayer(value string) bool {
	return violationPlayerPattern.MatchString(value)
}

func cleanModerationText(value string, max int) string {
	value = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return ' '
		}
		return r
	}, value)
	value = strings.Join(strings.Fields(value), " ")
	if len(value) > max {
		value = value[:max]
		for !utf8.ValidString(value) {
			value = value[:len(value)-1]
		}
	}
	return strings.TrimSpace(value)
}

func (a *App) createBan(w http.ResponseWriter, r *http.Request) {
	var in banInput
	if decodeJSON(w, r, &in, 4096) != nil {
		return
	}
	id, err := a.createBanRecord(r.Context(), in, principal(r).Username)
	if errors.Is(err, errBanAlreadyActive) {
		writeError(w, http.StatusConflict, err.Error())
		return
	}
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	a.audit(principal(r), "ban.create", "ban", id, fmt.Sprintf("player=%s server=%s", cleanModerationText(in.PlayerName, 64), in.ServerID))
	writeJSON(w, http.StatusCreated, map[string]string{"id": id, "state": "pending"})
}

func (a *App) createBanRecord(ctx context.Context, in banInput, bannedBy string) (string, error) {
	if len(strings.TrimSpace(in.PlayerName)) > 64 || len(strings.TrimSpace(in.PlayerID)) > 128 || len(strings.TrimSpace(in.Reason)) > 256 {
		return "", errors.New("player name, ID, or reason exceeds its length limit")
	}
	in.PlayerName = cleanModerationText(in.PlayerName, 64)
	in.PlayerID = cleanModerationText(in.PlayerID, 128)
	in.Reason = cleanModerationText(in.Reason, 256)
	in.ServerID = strings.TrimSpace(in.ServerID)
	if !validModerationPlayer(in.PlayerName) {
		return "", errors.New("player name must be 1–64 letters, numbers, spaces, dots, underscores, hyphens or @ signs")
	}
	if in.PlayerID != "" && !violationPlayerID.MatchString(in.PlayerID) {
		return "", errors.New("player ID contains unsupported characters")
	}
	if in.Reason == "" {
		return "", errors.New("enter a reason for the ban")
	}
	if len(in.Reason) > 256 {
		return "", errors.New("ban reason must be 256 characters or fewer")
	}
	if bannedBy == "" {
		bannedBy = "system"
	}
	expiresAt := ""
	if strings.TrimSpace(in.ExpiresAt) != "" {
		parsed, err := time.Parse(time.RFC3339, strings.TrimSpace(in.ExpiresAt))
		if err != nil || !parsed.After(time.Now()) {
			return "", errors.New("expiry must be a future RFC3339 timestamp")
		}
		expiresAt = parsed.UTC().Format(time.RFC3339)
	}
	if in.ServerID != "" {
		if _, err := a.getServer(in.ServerID); err != nil {
			return "", errors.New("selected server does not exist")
		}
	}
	id, err := newID()
	if err != nil {
		return "", errors.New("could not create ban ID")
	}
	tx, err := a.db.BeginTx(ctx, nil)
	if err != nil {
		return "", errors.New("could not start the ban transaction")
	}
	defer tx.Rollback()
	var exists int
	if err = tx.QueryRowContext(ctx, `SELECT count(*) FROM bans WHERE active=1 AND player_name=? COLLATE NOCASE AND (server_id=? OR server_id='' OR ?='')`, in.PlayerName, in.ServerID, in.ServerID).Scan(&exists); err != nil {
		return "", errors.New("could not check existing bans")
	}
	if exists > 0 {
		return "", errBanAlreadyActive
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO bans(id,player_name,player_id,server_id,reason,banned_by,expires_at,active) VALUES(?,?,?,?,?,?,?,1)`, id, in.PlayerName, in.PlayerID, in.ServerID, in.Reason, bannedBy, expiresAt); err != nil {
		return "", errors.New("could not save the ban")
	}
	var servers *sql.Rows
	if in.ServerID == "" {
		servers, err = tx.QueryContext(ctx, `SELECT id FROM servers`)
	} else {
		servers, err = tx.QueryContext(ctx, `SELECT id FROM servers WHERE id=?`, in.ServerID)
	}
	if err != nil {
		return "", errors.New("could not list ban targets")
	}
	var serverIDs []string
	for servers.Next() {
		var serverID string
		if err = servers.Scan(&serverID); err != nil {
			_ = servers.Close()
			return "", errors.New("could not read ban targets")
		}
		serverIDs = append(serverIDs, serverID)
	}
	if err = servers.Err(); err != nil {
		_ = servers.Close()
		return "", errors.New("could not finish reading ban targets")
	}
	_ = servers.Close()
	for _, serverID := range serverIDs {
		if _, err = tx.ExecContext(ctx, `INSERT INTO ban_server_state(ban_id,server_id,desired_active,state,last_error,updated_at) VALUES(?,?,1,'pending','',CURRENT_TIMESTAMP)`, id, serverID); err != nil {
			return "", errors.New("could not queue ban delivery")
		}
	}
	if err = tx.Commit(); err != nil {
		return "", errors.New("could not save the ban and delivery state")
	}
	return id, nil
}

func (a *App) listBans(w http.ResponseWriter, r *http.Request) {
	rows, err := a.db.QueryContext(r.Context(), `SELECT b.id,b.player_name,b.player_id,b.server_id,COALESCE(s.name,''),b.reason,b.banned_by,b.expires_at,b.active,b.created_at,b.revoked_at,
		(SELECT count(*) FROM ban_server_state x WHERE x.ban_id=b.id AND x.state='applied'),
		(SELECT count(*) FROM ban_server_state x WHERE x.ban_id=b.id AND x.state='pending'),
		(SELECT count(*) FROM ban_server_state x WHERE x.ban_id=b.id AND x.state='error'),
		COALESCE((SELECT last_error FROM ban_server_state x WHERE x.ban_id=b.id AND x.state='error' ORDER BY x.updated_at DESC LIMIT 1),'')
		FROM bans b LEFT JOIN servers s ON s.id=b.server_id ORDER BY b.active DESC,b.created_at DESC LIMIT 500`)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not read the ban list")
		return
	}
	defer rows.Close()
	out := make([]banRecord, 0)
	for rows.Next() {
		var item banRecord
		var active int
		if err = rows.Scan(&item.ID, &item.PlayerName, &item.PlayerID, &item.ServerID, &item.ServerName, &item.Reason, &item.BannedBy, &item.ExpiresAt, &active, &item.CreatedAt, &item.RevokedAt, &item.SyncApplied, &item.SyncPending, &item.SyncErrors, &item.SyncError); err != nil {
			writeError(w, http.StatusInternalServerError, "could not read the ban list")
			return
		}
		item.Active = active != 0
		if item.ServerID == "" {
			item.ServerName = "All servers"
		}
		out = append(out, item)
	}
	if err = rows.Err(); err != nil {
		writeError(w, http.StatusInternalServerError, "could not read the ban list")
		return
	}
	writeJSON(w, http.StatusOK, out)
}

func (a *App) revokeBan(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	a.banSyncMu.Lock()
	tx, err := a.db.BeginTx(r.Context(), nil)
	var result sql.Result
	if err == nil {
		result, err = tx.ExecContext(r.Context(), `UPDATE bans SET active=0,revoked_at=CURRENT_TIMESTAMP WHERE id=? AND active=1`, id)
	}
	var changed int64
	if err == nil {
		changed, err = result.RowsAffected()
	}
	if err == nil && changed > 0 {
		_, err = tx.ExecContext(r.Context(), `UPDATE ban_server_state SET desired_active=0,state=CASE WHEN state='applied' THEN 'pending' ELSE 'removed' END,last_error='',updated_at=CURRENT_TIMESTAMP WHERE ban_id=?`, id)
	}
	if err == nil {
		err = tx.Commit()
	} else if tx != nil {
		_ = tx.Rollback()
	}
	a.banSyncMu.Unlock()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not revoke the ban")
		return
	}
	if changed == 0 {
		var exists int
		if a.db.QueryRowContext(r.Context(), `SELECT count(*) FROM bans WHERE id=?`, id).Scan(&exists) != nil || exists == 0 {
			writeError(w, http.StatusNotFound, "ban not found")
		} else {
			writeError(w, http.StatusConflict, "ban has already been revoked")
		}
		return
	}
	a.audit(principal(r), "ban.revoke", "ban", id, "remote unban queued where previously applied")
	writeJSON(w, http.StatusAccepted, map[string]string{"id": id, "state": "unban_pending"})
}

func (a *App) expireBans(ctx context.Context, now time.Time) error {
	a.banSyncMu.Lock()
	defer a.banSyncMu.Unlock()
	tx, err := a.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(ctx, `UPDATE bans SET active=0,revoked_at=? WHERE active=1 AND expires_at<>'' AND expires_at<=?`, now.Format(time.RFC3339), now.Format(time.RFC3339)); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, `UPDATE ban_server_state SET desired_active=0,state=CASE WHEN state='applied' THEN 'pending' ELSE 'removed' END,last_error='',updated_at=CURRENT_TIMESTAMP WHERE ban_id IN (SELECT id FROM bans WHERE active=0 AND revoked_at=?)`, now.Format(time.RFC3339)); err != nil {
		return err
	}
	return tx.Commit()
}

func (a *App) reconcileServerBanStates(ctx context.Context, server Server) error {
	a.banSyncMu.Lock()
	defer a.banSyncMu.Unlock()
	if _, err := a.db.ExecContext(ctx, `INSERT OR IGNORE INTO ban_server_state(ban_id,server_id,desired_active,state) SELECT id,?,1,'pending' FROM bans WHERE active=1 AND (server_id='' OR server_id=?)`, server.ID, server.ID); err != nil {
		return err
	}
	rows, err := a.db.QueryContext(ctx, `SELECT bs.ban_id,bs.state,b.player_name,b.player_id,b.reason,b.banned_by,b.active,bs.desired_active
		FROM ban_server_state bs JOIN bans b ON b.id=bs.ban_id
		WHERE bs.server_id=? AND bs.state IN ('pending','error') AND (bs.state='pending' OR bs.updated_at<=?)
		ORDER BY b.created_at,bs.ban_id`, server.ID, time.Now().Add(-violationRetryDelay).UTC().Format("2006-01-02 15:04:05"))
	if err != nil {
		return err
	}
	type pendingBan struct {
		id, state, name, playerID, reason, bannedBy string
		active, desired                             int
	}
	var pending []pendingBan
	for rows.Next() {
		var item pendingBan
		if err = rows.Scan(&item.id, &item.state, &item.name, &item.playerID, &item.reason, &item.bannedBy, &item.active, &item.desired); err != nil {
			_ = rows.Close()
			return err
		}
		pending = append(pending, item)
	}
	if err = rows.Err(); err != nil {
		_ = rows.Close()
		return err
	}
	_ = rows.Close()
	for _, item := range pending {
		wanted := item.active != 0 && item.desired != 0
		gs, loadErr := a.loadRune(server.GameskillID)
		if loadErr != nil {
			err = fmt.Errorf("could not load the server template")
		} else if gs.Bans == nil {
			err = fmt.Errorf("template does not define ban and unban commands")
		} else {
			command := gs.Bans.UnbanCommand
			if wanted {
				command = gs.Bans.BanCommand
			}
			command = renderModerationCommand(command, item.name, item.playerID, item.reason)
			actionCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
			_, err = a.sendCommand(actionCtx, server, command)
			cancel()
		}
		if err != nil {
			_, saveErr := a.db.ExecContext(ctx, `UPDATE ban_server_state SET state='error',last_error=?,updated_at=CURRENT_TIMESTAMP WHERE ban_id=? AND server_id=?`, cleanModerationText(err.Error(), 400), item.id, server.ID)
			if saveErr != nil {
				return saveErr
			}
			continue
		}
		state := "removed"
		if wanted {
			state = "applied"
		}
		if _, err = a.db.ExecContext(ctx, `UPDATE ban_server_state SET state=?,last_error='',updated_at=CURRENT_TIMESTAMP WHERE ban_id=? AND server_id=?`, state, item.id, server.ID); err != nil {
			return err
		}
		if wanted && item.bannedBy == "Docklight automation" {
			ruleName := strings.TrimPrefix(item.reason, "auto: ")
			detail := fmt.Sprintf("auto-banned %s after violation rule %s was matched", item.name, ruleName)
			a.audit(User{Username: "system"}, "violation.ban.applied", "ban", item.id, detail)
			a.dispatchWebhookNotification(notificationAutoModeration, &webhookServer{ID: server.ID, Name: server.Name}, "🔨 Auto-banned "+item.name+" on rule "+ruleName+".")
		}
	}
	return nil
}

func renderModerationCommand(command, player, playerID, reason string) string {
	command = strings.ReplaceAll(command, "{{player}}", cleanModerationText(player, 64))
	command = strings.ReplaceAll(command, "{{player_id}}", cleanModerationText(playerID, 128))
	command = strings.ReplaceAll(command, "{{reason}}", cleanModerationText(reason, 256))
	return strings.TrimSpace(command)
}

func (a *App) listViolationRules(w http.ResponseWriter, r *http.Request) {
	rows, err := a.db.QueryContext(r.Context(), `SELECT id,name,pattern,threshold,window_minutes,action,scope_global,enabled,created_at,updated_at FROM violation_rules ORDER BY name COLLATE NOCASE,id`)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not read violation rules")
		return
	}
	defer rows.Close()
	out := make([]violationRule, 0)
	for rows.Next() {
		var item violationRule
		var global, enabled int
		if err = rows.Scan(&item.ID, &item.Name, &item.Pattern, &item.Threshold, &item.WindowMinutes, &item.Action, &global, &enabled, &item.CreatedAt, &item.UpdatedAt); err != nil {
			writeError(w, http.StatusInternalServerError, "could not read violation rules")
			return
		}
		item.ScopeGlobal, item.Enabled = global != 0, enabled != 0
		out = append(out, item)
	}
	if err = rows.Err(); err != nil {
		writeError(w, http.StatusInternalServerError, "could not read violation rules")
		return
	}
	writeJSON(w, http.StatusOK, out)
}

func normalizeViolationRule(in violationRuleInput) (violationRule, error) {
	if len(strings.TrimSpace(in.Name)) > 80 {
		return violationRule{}, errors.New("rule name must be 1–80 characters")
	}
	item := violationRule{Name: cleanModerationText(in.Name, 80), Pattern: strings.TrimSpace(in.Pattern), Threshold: in.Threshold, WindowMinutes: in.WindowMinutes, Action: strings.ToLower(strings.TrimSpace(in.Action)), ScopeGlobal: in.ScopeGlobal, Enabled: true}
	if in.Enabled != nil {
		item.Enabled = *in.Enabled
	}
	if item.Name == "" || len(item.Name) > 80 {
		return violationRule{}, errors.New("rule name must be 1–80 characters")
	}
	if len(item.Pattern) == 0 || len(item.Pattern) > 512 {
		return violationRule{}, errors.New("regular expression must be 1–512 characters")
	}
	compiled, err := regexp.Compile(item.Pattern)
	if err != nil {
		return violationRule{}, fmt.Errorf("invalid regular expression: %w", err)
	}
	item.compiled = compiled
	if item.compiled.NumSubexp() < 1 {
		return violationRule{}, errors.New("regular expression needs a capture group for the player name")
	}
	if item.Threshold < 1 || item.Threshold > 100 || item.WindowMinutes < 1 || item.WindowMinutes > 1440 {
		return violationRule{}, errors.New("threshold must be 1–100 and window_minutes must be 1–1440")
	}
	if item.Action != "kick" && item.Action != "ban" {
		return violationRule{}, errors.New("action must be kick or ban")
	}
	return item, nil
}

func (a *App) createViolationRule(w http.ResponseWriter, r *http.Request) {
	var in violationRuleInput
	if decodeJSON(w, r, &in, 8192) != nil {
		return
	}
	item, err := normalizeViolationRule(in)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	item.ID, err = newID()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not create violation rule")
		return
	}
	if _, err = a.db.ExecContext(r.Context(), `INSERT INTO violation_rules(id,name,pattern,threshold,window_minutes,action,scope_global,enabled) VALUES(?,?,?,?,?,?,?,?)`, item.ID, item.Name, item.Pattern, item.Threshold, item.WindowMinutes, item.Action, boolInt(item.ScopeGlobal), boolInt(item.Enabled)); err != nil {
		writeError(w, http.StatusInternalServerError, "could not save violation rule")
		return
	}
	a.invalidateViolationRules()
	a.audit(principal(r), "violation.rule.create", "violation_rule", item.ID, "action="+item.Action)
	writeJSON(w, http.StatusCreated, item)
}

func (a *App) updateViolationRule(w http.ResponseWriter, r *http.Request) {
	var in violationRuleInput
	if decodeJSON(w, r, &in, 8192) != nil {
		return
	}
	item, err := normalizeViolationRule(in)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	item.ID = chi.URLParam(r, "id")
	result, err := a.db.ExecContext(r.Context(), `UPDATE violation_rules SET name=?,pattern=?,threshold=?,window_minutes=?,action=?,scope_global=?,enabled=?,updated_at=CURRENT_TIMESTAMP WHERE id=?`, item.Name, item.Pattern, item.Threshold, item.WindowMinutes, item.Action, boolInt(item.ScopeGlobal), boolInt(item.Enabled), item.ID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not update violation rule")
		return
	}
	changed, _ := result.RowsAffected()
	if changed == 0 {
		writeError(w, http.StatusNotFound, "violation rule not found")
		return
	}
	a.invalidateViolationRules()
	a.clearViolationHits(item.ID)
	a.audit(principal(r), "violation.rule.update", "violation_rule", item.ID, "action="+item.Action+" enabled="+fmt.Sprint(item.Enabled))
	writeJSON(w, http.StatusOK, item)
}

func (a *App) deleteViolationRule(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	result, err := a.db.ExecContext(r.Context(), `DELETE FROM violation_rules WHERE id=?`, id)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not delete violation rule")
		return
	}
	changed, _ := result.RowsAffected()
	if changed == 0 {
		writeError(w, http.StatusNotFound, "violation rule not found")
		return
	}
	a.invalidateViolationRules()
	a.clearViolationHits(id)
	a.audit(principal(r), "violation.rule.delete", "violation_rule", id, "")
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}
