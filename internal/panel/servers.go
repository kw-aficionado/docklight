package panel

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"example.com/yggdrasil-panel/internal/docker"
	"example.com/yggdrasil-panel/internal/rune"
	"example.com/yggdrasil-panel/internal/security"
	"github.com/go-chi/chi/v5"
)

type Server struct {
	ID                  string               `json:"id"`
	Name                string               `json:"name"`
	GameskillID         string               `json:"gameskill_id"`
	Status              string               `json:"status"`
	Installed           bool                 `json:"installed"`
	Env                 map[string]string    `json:"env"`
	Ports               map[string]int       `json:"ports"`
	DataDir             string               `json:"-"`
	FilesRoot           string               `json:"-"`
	ContainerID         string               `json:"-"`
	CPULimit            float64              `json:"cpu_limit"`
	MemoryLimitMB       int                  `json:"memory_limit_mb"`
	WatchdogEnabled     bool                 `json:"watchdog_enabled"`
	WatchdogQuarantined bool                 `json:"watchdog_quarantined"`
	ErrorMessage        string               `json:"error_message,omitempty"`
	Permissions         []string             `json:"permissions,omitempty"`
	StackServices       []StackServiceStatus `json:"stack_services,omitempty"`
	CreatedAt           string               `json:"created_at"`
}

type StackServiceStatus struct {
	Name         string `json:"name"`
	Status       string `json:"status"`
	ErrorMessage string `json:"error_message,omitempty"`
}
type createServerInput struct {
	Name          string            `json:"name"`
	GameskillID   string            `json:"gameskill_id"`
	Env           map[string]string `json:"env"`
	CPULimit      float64           `json:"cpu_limit"`
	MemoryLimitMB int               `json:"memory_limit_mb"`
}
type installJob struct {
	mu        sync.Mutex
	lines     []string
	done      bool
	err       string
	container string
	updated   time.Time
}

func (a *App) listServers(w http.ResponseWriter, r *http.Request) {
	u := principal(r)
	rows, e := a.db.Query(`SELECT id,name,gameskill_id,status,installed,env_json,ports_json,data_dir,container_id,cpu_limit,memory_limit_mb,created_at,error_message,watchdog_enabled,watchdog_quarantined FROM servers ORDER BY created_at DESC`)
	if e != nil {
		writeError(w, 500, "could not list servers")
		return
	}
	out := []Server{}
	for rows.Next() {
		var s Server
		var in, ports string
		var installed, watchdogEnabled, watchdogQuarantined int
		if rows.Scan(&s.ID, &s.Name, &s.GameskillID, &s.Status, &installed, &in, &ports, &s.DataDir, &s.ContainerID, &s.CPULimit, &s.MemoryLimitMB, &s.CreatedAt, &s.ErrorMessage, &watchdogEnabled, &watchdogQuarantined) != nil {
			continue
		}
		s.Installed = installed != 0
		s.WatchdogEnabled = watchdogEnabled != 0
		s.WatchdogQuarantined = watchdogQuarantined != 0
		_ = json.Unmarshal([]byte(in), &s.Env)
		_ = json.Unmarshal([]byte(ports), &s.Ports)
		out = append(out, s)
	}
	_ = rows.Close()
	visible := out[:0]
	for _, s := range out {
		if !a.allowedServer(u, "server.view", s.ID, s.GameskillID) {
			continue
		}
		visible = append(visible, a.decorateServer(u, maskServer(s, a.db)))
	}
	writeJSON(w, 200, visible)
}
func (a *App) getServerHandler(w http.ResponseWriter, r *http.Request) {
	s, e := a.getServer(chi.URLParam(r, "id"))
	if e != nil {
		writeError(w, 404, "server not found")
		return
	}
	u := principal(r)
	if !a.allowedServer(u, "server.view", s.ID, s.GameskillID) {
		writeError(w, 403, "insufficient permissions")
		return
	}
	writeJSON(w, 200, a.decorateServer(u, maskServer(s, a.db)))
}
func (a *App) createServer(w http.ResponseWriter, r *http.Request) {
	var in createServerInput
	if decodeJSON(w, r, &in, 1<<20) != nil {
		return
	}
	in.Name = strings.TrimSpace(in.Name)
	if in.Name == "" || len(in.Name) > 80 {
		writeError(w, 400, "server name must contain 1 to 80 characters")
		return
	}
	u := principal(r)
	if !a.allowedRune(u, "server.create", in.GameskillID) {
		writeError(w, 403, "server.create permission is required for this template")
		return
	}
	gs, err := a.loadRune(in.GameskillID)
	if err != nil {
		writeError(w, 404, "template not found")
		return
	}
	env := gs.DefaultEnv()
	for k, v := range in.Env {
		env[k] = v
	}
	if err = gs.ValidateEnv(env); err != nil {
		writeError(w, 400, err.Error())
		return
	}
	filtered := map[string]string{}
	secret := map[string]bool{}
	for _, v := range gs.Variables {
		if raw, ok := env[v.Key]; ok {
			filtered[v.Key] = raw
			secret[v.Key] = secretVariables(gs)[v.Key]
		}
	}
	encoded := map[string]string{}
	for k, v := range filtered {
		if secret[k] {
			ciphertext, e := security.Encrypt([]byte(a.cfg.Auth.SecretKey), v)
			if e != nil {
				writeError(w, 500, "could not protect a secret setting")
				return
			}
			encoded[k] = ciphertext
		} else {
			encoded[k] = v
		}
	}
	id, err := newID()
	if err != nil {
		writeError(w, 500, "could not create server ID")
		return
	}
	dataDir := filepath.Join(a.dataRoot, id)
	if err = os.MkdirAll(dataDir, 0700); err != nil {
		writeError(w, 500, "could not create the server data directory; check panel storage permissions")
		return
	}
	ports, err := a.allocatePorts(id, gs.Ports)
	if err != nil {
		_ = os.RemoveAll(dataDir)
		writeError(w, 503, err.Error())
		return
	}
	envJSON, _ := json.Marshal(encoded)
	portsJSON, _ := json.Marshal(ports)
	if in.CPULimit < 0 || in.CPULimit > 64 || in.MemoryLimitMB < 0 || in.MemoryLimitMB > 1024*1024 {
		a.releasePorts(id)
		_ = os.RemoveAll(dataDir)
		writeError(w, 400, "CPU limit must be 0–64 cores and memory must be 0–1048576 MB")
		return
	}
	_, err = a.db.Exec(`INSERT INTO servers(id,name,gameskill_id,status,installed,env_json,ports_json,data_dir,cpu_limit,memory_limit_mb) VALUES(?,?,?,'stopped',0,?,?,?,?,?)`, id, in.Name, gs.ID, string(envJSON), string(portsJSON), dataDir, in.CPULimit, in.MemoryLimitMB)
	if err != nil {
		a.releasePorts(id)
		_ = os.RemoveAll(dataDir)
		writeError(w, 500, "could not save the server; choose another name or check panel storage")
		return
	}
	a.audit(u, "server.create", "server", id, "template="+gs.ID)
	s, _ := a.getServer(id)
	writeJSON(w, 201, a.decorateServer(u, maskServer(s, a.db)))
}
func (a *App) updateServer(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	s, e := a.getServer(id)
	if e != nil {
		writeError(w, 404, "server not found")
		return
	}
	u := principal(r)
	if !a.allowedServer(u, "server.control", s.ID, s.GameskillID) {
		writeError(w, 403, "server.control permission is required")
		return
	}
	a.dataMu.Lock()
	defer a.dataMu.Unlock()
	s, e = a.getServer(id)
	if e != nil {
		writeError(w, 404, "server not found")
		return
	}
	var in struct {
		Name          *string           `json:"name"`
		Env           map[string]string `json:"env"`
		CPULimit      *float64          `json:"cpu_limit"`
		MemoryLimitMB *int              `json:"memory_limit_mb"`
	}
	if decodeJSON(w, r, &in, 1<<20) != nil {
		return
	}
	gs, e := a.loadRune(s.GameskillID)
	if e != nil {
		writeError(w, 500, "server template is invalid")
		return
	}
	env, err := a.runtimeEnv(s, gs)
	if err != nil {
		writeError(w, 500, "stored server settings could not be decrypted")
		return
	}
	for k, v := range in.Env {
		if v == "********" || v == "" && isSecretVariable(gs, k) {
			continue
		}
		env[k] = v
	}
	if err = gs.ValidateEnv(env); err != nil {
		writeError(w, 400, err.Error())
		return
	}
	cipherMap := map[string]string{}
	secret := secretVariables(gs)
	for _, v := range gs.Variables {
		if val, ok := env[v.Key]; ok {
			if secret[v.Key] {
				enc, ee := security.Encrypt([]byte(a.cfg.Auth.SecretKey), val)
				if ee != nil {
					writeError(w, 500, "could not protect a secret setting")
					return
				}
				cipherMap[v.Key] = enc
			} else {
				cipherMap[v.Key] = val
			}
		}
	}
	if in.Name != nil {
		n := strings.TrimSpace(*in.Name)
		if n == "" || len(n) > 80 {
			writeError(w, 400, "server name must contain 1 to 80 characters")
			return
		}
		s.Name = n
	}
	if in.CPULimit != nil {
		s.CPULimit = *in.CPULimit
	}
	if in.MemoryLimitMB != nil {
		s.MemoryLimitMB = *in.MemoryLimitMB
	}
	if s.CPULimit < 0 || s.CPULimit > 64 || s.MemoryLimitMB < 0 || s.MemoryLimitMB > 1024*1024 {
		writeError(w, 400, "CPU limit must be 0–64 cores and memory must be 0–1048576 MB")
		return
	}
	b, _ := json.Marshal(cipherMap)
	_, err = a.db.Exec(`UPDATE servers SET name=?,env_json=?,cpu_limit=?,memory_limit_mb=?,updated_at=CURRENT_TIMESTAMP WHERE id=?`, s.Name, string(b), s.CPULimit, s.MemoryLimitMB, id)
	if err != nil {
		writeError(w, 500, "could not update server settings")
		return
	}
	if s.Status == "running" {
		if err = a.recreateAndStart(r.Context(), s); err != nil {
			writeError(w, 502, err.Error())
			return
		}
	}
	a.audit(u, "server.settings", "server", id, "")
	s, _ = a.getServer(id)
	writeJSON(w, 200, a.decorateServer(u, maskServer(s, a.db)))
}
func (a *App) deleteServer(w http.ResponseWriter, r *http.Request) {
	s, e := a.getServer(chi.URLParam(r, "id"))
	if e != nil {
		writeError(w, 404, "server not found")
		return
	}
	u := principal(r)
	if !a.allowedServer(u, "server.delete", s.ID, s.GameskillID) {
		writeError(w, 403, "server.delete permission is required")
		return
	}
	a.dataMu.Lock()
	defer a.dataMu.Unlock()
	s, e = a.getServer(s.ID)
	if e != nil {
		writeError(w, 404, "server not found")
		return
	}
	if s.ContainerID != "" {
		ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
		defer cancel()
		ins, err := a.engine.Inspect(ctx, s.ContainerID)
		if err == nil {
			if ins.State.Running {
				_ = a.engine.Stop(ctx, s.ContainerID, 15)
			}
			if e := a.engine.Remove(ctx, s.ContainerID); e != nil {
				writeError(w, 503, e.Error())
				return
			}
		} else if !strings.Contains(strings.ToLower(err.Error()), "no longer has this server container") {
			writeError(w, 503, err.Error())
			return
		}
	}
	stackCtx, stackCancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer stackCancel()
	var serverRune *rune.Rune
	if loadedRune, loadErr := a.loadRune(s.GameskillID); loadErr == nil {
		serverRune = &loadedRune
	}
	if err := a.removeStackResources(stackCtx, s, serverRune); err != nil {
		writeError(w, 503, "app stack cleanup failed: "+err.Error())
		return
	}
	if err := a.removeServerBackups(s.ID); err != nil {
		writeError(w, 500, err.Error())
		return
	}
	if err := a.removeServerBackupSchedules(s.ID); err != nil {
		writeError(w, 500, "backups were removed but their schedules could not be deleted")
		return
	}
	if _, err := a.db.Exec(`DELETE FROM server_crashes WHERE server_id=?`, s.ID); err != nil {
		writeError(w, 500, "server backups were removed but crash history could not be deleted")
		return
	}
	if err := os.RemoveAll(s.DataDir); err != nil {
		writeError(w, 500, "Docker removed the container but panel data cleanup failed; fix storage permissions and retry cleanup")
		return
	}
	a.clearRuntimePending(s.ID)
	a.resetWatchdog(s.ID)
	a.releasePorts(s.ID)
	_, _ = a.db.Exec(`DELETE FROM permissions WHERE scope_type='server' AND scope_id=?`, s.ID)
	_, _ = a.db.Exec(`DELETE FROM servers WHERE id=?`, s.ID)
	a.audit(u, "server.delete", "server", s.ID, "data_removed=true")
	writeJSON(w, 200, map[string]bool{"ok": true})
}

func (a *App) installServer(w http.ResponseWriter, r *http.Request) {
	s, e := a.getServer(chi.URLParam(r, "id"))
	if e != nil {
		writeError(w, 404, "server not found")
		return
	}
	u := principal(r)
	if !a.allowedServer(u, "server.control", s.ID, s.GameskillID) {
		writeError(w, 403, "server.control permission is required")
		return
	}
	a.dataMu.Lock()
	defer a.dataMu.Unlock()
	s, e = a.getServer(s.ID)
	if e != nil {
		writeError(w, 404, "server not found")
		return
	}
	if s.Status == "installing" {
		writeError(w, 409, "server installation is already running")
		return
	}
	if s.Installed {
		writeError(w, 409, "server is already installed; use reinstall only after it is supported")
		return
	}
	gs, e := a.loadRune(s.GameskillID)
	if e != nil {
		writeError(w, 500, "server template is invalid")
		return
	}
	if gs.Install == nil {
		_, _ = a.db.Exec(`UPDATE servers SET installed=1,status='stopped' WHERE id=?`, s.ID)
		s.Installed = true
		if e = a.start(s); e != nil {
			writeError(w, 502, e.Error())
			return
		}
		writeJSON(w, 200, map[string]any{"installed": true, "status": "starting"})
		return
	}
	j := &installJob{lines: []string{}, updated: time.Now()}
	a.jobsMu.Lock()
	a.jobs[s.ID] = j
	a.jobsMu.Unlock()
	_, _ = a.db.Exec(`UPDATE servers SET status='installing',error_message='' WHERE id=?`, s.ID)
	go a.runInstall(s, gs, j)
	a.audit(u, "server.install", "server", s.ID, "")
	writeJSON(w, 202, map[string]any{"status": "installing", "log_url": "/api/servers/" + s.ID + "/install/log"})
}
func (a *App) installStatus(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	s, e := a.getServer(id)
	if e != nil {
		writeError(w, 404, "server not found")
		return
	}
	u := principal(r)
	if !a.allowedServer(u, "server.view", s.ID, s.GameskillID) {
		writeError(w, 403, "insufficient permissions")
		return
	}
	a.jobsMu.RLock()
	j := a.jobs[id]
	a.jobsMu.RUnlock()
	if j == nil {
		writeJSON(w, 200, map[string]any{"status": s.Status, "installed": s.Installed})
		return
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	writeJSON(w, 200, map[string]any{"status": s.Status, "installed": s.Installed, "done": j.done, "error": j.err, "lines": j.lines})
}
func (a *App) runInstall(s Server, gs rune.Rune, j *installJob) {
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Minute)
	defer cancel()
	secrets := []string{}
	finish := func(err error) {
		j.mu.Lock()
		j.done = true
		if err != nil {
			message := redactSecrets(err.Error(), secrets)
			j.err = message
			j.lines = append(j.lines, "ERROR: "+message)
			_, _ = a.db.Exec(`UPDATE servers SET status='error',error_message=? WHERE id=?`, message, s.ID)
		} else {
			_, _ = a.db.Exec(`UPDATE servers SET installed=1,status='stopped',error_message='' WHERE id=?`, s.ID)
		}
		j.updated = time.Now()
		j.mu.Unlock()
	}
	image := gs.Install.Image
	if image == "" {
		image = gs.Docker.Image
	}
	env, err := a.runtimeEnv(s, gs)
	if err != nil {
		finish(err)
		return
	}
	image = rune.ApplyTemplate(image, env)
	script := rune.ApplyTemplate(gs.Install.Script, env)
	secrets = runeSecretValues(gs, env)
	if err = a.engine.Pull(ctx, image); err != nil {
		finish(err)
		return
	}
	appDataDir := serverAppDataDir(s, gs)
	if err = os.MkdirAll(appDataDir, 0770); err != nil {
		finish(fmt.Errorf("create app data directory: %w", err))
		return
	}
	cfg := docker.CreateConfig{Image: image, Cmd: []string{"/bin/sh", "-c", script}, WorkingDir: "/data", User: "0:0", Tty: false, OpenStdin: true, AttachStdin: true, AttachStdout: true, AttachStderr: true, HostConfig: docker.HostConfig{Binds: []string{appDataDir + ":/data"}}}
	cid, err := a.engine.Create(ctx, "ygg-install-"+shortID(s.ID), cfg)
	if err != nil {
		finish(err)
		return
	}
	j.mu.Lock()
	j.container = cid
	j.mu.Unlock()
	if err = a.engine.Start(ctx, cid); err != nil {
		_ = a.engine.Remove(context.Background(), cid)
		finish(err)
		return
	}
	logCtx, logCancel := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() {
		defer close(done)
		body, e := a.engine.Logs(logCtx, cid, "all", true)
		if e != nil {
			a.addJobLine(j, e.Error())
			return
		}
		defer body.Close()
		_ = docker.CopyLogs(&logLineWriter{job: j, secrets: secrets}, body)
	}()
	code, waitErr := a.engine.Wait(ctx, cid)
	logCancel()
	<-done
	_ = a.engine.Remove(context.Background(), cid)
	if waitErr != nil {
		finish(waitErr)
		return
	}
	if code != 0 {
		finish(fmt.Errorf("installer exited with status %d; review the installation log and correct the template settings", code))
		return
	}
	if err = a.fixOwnership(ctx, appDataDir); err != nil {
		finish(err)
		return
	}
	a.dataMu.Lock()
	finish(nil)
	s.Installed = true
	if e := a.start(s); e != nil {
		j.mu.Lock()
		j.err = redactSecrets("installation succeeded but server start failed: "+e.Error(), secrets)
		j.lines = append(j.lines, "ERROR: "+j.err)
		j.mu.Unlock()
		_, _ = a.db.Exec(`UPDATE servers SET status='error',error_message=? WHERE id=?`, j.err, s.ID)
	}
	a.dataMu.Unlock()
}

type logLineWriter struct {
	job     *installJob
	carry   string
	secrets []string
}

func (w *logLineWriter) Write(p []byte) (int, error) {
	combined := w.carry + string(p)
	parts := strings.Split(combined, "\n")
	w.carry = parts[len(parts)-1]
	for _, line := range parts[:len(parts)-1] {
		if strings.TrimSpace(line) != "" {
			line = redactSecrets(line, w.secrets)
			w.job.mu.Lock()
			w.job.lines = append(w.job.lines, line)
			if len(w.job.lines) > 1000 {
				w.job.lines = w.job.lines[len(w.job.lines)-1000:]
			}
			w.job.updated = time.Now()
			w.job.mu.Unlock()
		}
	}
	return len(p), nil
}
func (a *App) addJobLine(j *installJob, line string) {
	j.mu.Lock()
	j.lines = append(j.lines, line)
	j.updated = time.Now()
	j.mu.Unlock()
}
func (a *App) fixOwnership(ctx context.Context, data string) error {
	if e := a.engine.Pull(ctx, "busybox:1.36"); e != nil {
		return fmt.Errorf("could not prepare the data ownership helper: %w", e)
	}
	uid, gid := os.Getuid(), os.Getgid()
	cmd := fmt.Sprintf("chown -R %d:%d /data", uid, gid)
	cfg := docker.CreateConfig{Image: "busybox:1.36", Cmd: []string{"/bin/sh", "-c", cmd}, User: "0:0", HostConfig: docker.HostConfig{Binds: []string{data + ":/data"}}}
	id, e := a.engine.Create(ctx, "ygg-chown-"+strconv.FormatInt(time.Now().UnixNano(), 10), cfg)
	if e != nil {
		return e
	}
	defer a.engine.Remove(context.Background(), id)
	if e = a.engine.Start(ctx, id); e != nil {
		return e
	}
	code, e := a.engine.Wait(ctx, id)
	if e != nil {
		return e
	}
	if code != 0 {
		return errors.New("could not set panel ownership on installed files; check the host filesystem and container permissions")
	}
	return nil
}

func (a *App) startServer(w http.ResponseWriter, r *http.Request) {
	s, e := a.getServer(chi.URLParam(r, "id"))
	if e != nil {
		writeError(w, 404, "server not found")
		return
	}
	u := principal(r)
	if !a.allowedServer(u, "server.control", s.ID, s.GameskillID) {
		writeError(w, 403, "server.control permission is required")
		return
	}
	a.dataMu.Lock()
	defer a.dataMu.Unlock()
	s, e = a.getServer(s.ID)
	if e != nil {
		writeError(w, 404, "server not found")
		return
	}
	if !s.Installed {
		writeError(w, 409, "install this server before starting it")
		return
	}
	if e = a.start(s); e != nil {
		writeError(w, 502, e.Error())
		return
	}
	a.resetWatchdog(s.ID)
	a.audit(u, "server.start", "server", s.ID, "")
	writeJSON(w, 202, map[string]string{"status": "starting"})
}
func (a *App) stopServer(w http.ResponseWriter, r *http.Request) {
	s, e := a.getServer(chi.URLParam(r, "id"))
	if e != nil {
		writeError(w, 404, "server not found")
		return
	}
	u := principal(r)
	if !a.allowedServer(u, "server.control", s.ID, s.GameskillID) {
		writeError(w, 403, "server.control permission is required")
		return
	}
	a.dataMu.Lock()
	defer a.dataMu.Unlock()
	s, e = a.getServer(s.ID)
	if e != nil {
		writeError(w, 404, "server not found")
		return
	}
	if e = a.stop(s); e != nil {
		writeError(w, 502, e.Error())
		return
	}
	a.resetWatchdog(s.ID)
	a.audit(u, "server.stop", "server", s.ID, "")
	writeJSON(w, 200, map[string]string{"status": "stopped"})
}
func (a *App) restartServer(w http.ResponseWriter, r *http.Request) {
	s, e := a.getServer(chi.URLParam(r, "id"))
	if e != nil {
		writeError(w, 404, "server not found")
		return
	}
	u := principal(r)
	if !a.allowedServer(u, "server.control", s.ID, s.GameskillID) {
		writeError(w, 403, "server.control permission is required")
		return
	}
	a.dataMu.Lock()
	defer a.dataMu.Unlock()
	s, e = a.getServer(s.ID)
	if e != nil {
		writeError(w, 404, "server not found")
		return
	}
	if !s.Installed {
		writeError(w, 409, "install this server before restarting it")
		return
	}
	if e = a.recreateAndStart(r.Context(), s); e != nil {
		writeError(w, 502, e.Error())
		return
	}
	a.resetWatchdog(s.ID)
	a.audit(u, "server.restart", "server", s.ID, "")
	writeJSON(w, 202, map[string]string{"status": "starting"})
}
func (a *App) start(s Server) error {
	return a.startWithContext(s, context.Background())
}

func (a *App) startWithContext(s Server, parent context.Context) error {
	if !s.Installed {
		return errors.New("install this server before starting it")
	}
	gs, err := a.loadRune(s.GameskillID)
	if err != nil {
		return fmt.Errorf("load server template %q: %w", s.GameskillID, err)
	}
	ctx, cancel := context.WithTimeout(parent, 15*time.Minute)
	defer cancel()
	env, err := a.runtimeEnv(s, gs)
	if err != nil {
		return err
	}
	image := rune.ApplyTemplate(gs.Docker.Image, env)
	if err = a.engine.Pull(ctx, image); err != nil {
		return err
	}
	cleanupStartedStack := func(cause error) error {
		if gs.Stack == nil {
			return cause
		}
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cleanupCancel()
		if cleanupErr := a.cleanupStackSidecars(cleanupCtx, s, &gs, true); cleanupErr != nil {
			return errors.Join(cause, fmt.Errorf("app stack rollback failed: %w", cleanupErr))
		}
		return cause
	}
	if s.ContainerID != "" {
		ins, e := a.engine.Inspect(ctx, s.ContainerID)
		if e == nil {
			if ins.State.Running {
				return errors.New("server is already running")
			}
			if removeErr := a.engine.Remove(ctx, s.ContainerID); removeErr != nil && !docker.IsNotFound(removeErr) {
				return fmt.Errorf("remove previous server container: %w", removeErr)
			}
		} else if !docker.IsNotFound(e) && !strings.Contains(strings.ToLower(e.Error()), "no longer has this server container") {
			return e
		}
	}
	stackNetwork := ""
	if gs.Stack != nil {
		stackNetwork, err = a.ensureStackNetwork(ctx, s.ID)
		if err != nil {
			return fmt.Errorf("prepare private app stack network: %w", err)
		}
		if err = a.createStackSidecars(ctx, s, gs, env, stackNetwork, stackResourceLimits(s, gs)); err != nil {
			return cleanupStartedStack(err)
		}
	}
	limits := stackResourceLimits(s, gs)
	cfg, err := a.containerConfigWithStack(s, gs, env, stackNetwork, limits[0])
	if err != nil {
		return cleanupStartedStack(err)
	}
	cid, err := a.engine.Create(ctx, docker.SafeContainerName(s.ID), cfg)
	if err != nil {
		return cleanupStartedStack(err)
	}
	if err = a.engine.Start(ctx, cid); err != nil {
		removeErr := a.engine.Remove(context.Background(), cid)
		if removeErr != nil && !docker.IsNotFound(removeErr) {
			err = errors.Join(err, fmt.Errorf("remove failed server container: %w", removeErr))
		}
		return cleanupStartedStack(err)
	}
	_, err = a.db.Exec(`UPDATE servers SET container_id=?,status='starting',error_message='',updated_at=CURRENT_TIMESTAMP WHERE id=?`, cid, s.ID)
	if err != nil {
		removeErr := a.engine.Remove(context.Background(), cid)
		if removeErr != nil && !docker.IsNotFound(removeErr) {
			err = errors.Join(err, fmt.Errorf("remove unrecorded server container: %w", removeErr))
		}
		return cleanupStartedStack(fmt.Errorf("server started but panel could not record its ID: %w", err))
	}
	a.clearRuntimePending(s.ID)
	s.ContainerID = cid
	s.Status = "starting"
	go a.watchReady(s, gs)
	return nil
}
func (a *App) recreateAndStart(ctx context.Context, s Server) error {
	if err := a.stop(s); err != nil && !docker.IsNotFound(err) && !strings.Contains(strings.ToLower(err.Error()), "no longer has this server container") {
		return err
	}
	if s.ContainerID != "" {
		c, cancel := context.WithTimeout(ctx, 20*time.Second)
		removeErr := a.engine.Remove(c, s.ContainerID)
		cancel()
		if removeErr != nil && !docker.IsNotFound(removeErr) {
			return fmt.Errorf("remove previous server container: %w", removeErr)
		}
	}
	if _, err := a.db.Exec(`UPDATE servers SET container_id='',status='stopped' WHERE id=?`, s.ID); err != nil {
		return fmt.Errorf("record stopped server before restart: %w", err)
	}
	a.clearRuntimePending(s.ID)
	s.ContainerID = ""
	return a.startWithContext(s, ctx)
}
func (a *App) stop(s Server) error {
	gs, loadErr := a.loadRune(s.GameskillID)
	if loadErr != nil && s.ContainerID != "" {
		return loadErr
	}
	timeout := 30
	if loadErr == nil && gs.Startup.StopTimeout != 0 {
		timeout = gs.Startup.StopTimeout
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeout+15)*time.Second)
	defer cancel()
	if s.ContainerID != "" {
		if loadErr == nil && gs.Startup.SaveCommand != "" {
			_ = a.engine.SendInput(ctx, s.ContainerID, gs.Startup.SaveCommand)
			time.Sleep(2 * time.Second)
		}
		if loadErr == nil && gs.Startup.Stop != "" {
			_ = a.engine.SendInput(ctx, s.ContainerID, gs.Startup.Stop)
			time.Sleep(2 * time.Second)
		}
		err := a.engine.Stop(ctx, s.ContainerID, timeout)
		if err != nil && !docker.IsNotFound(err) && !docker.IsNotModified(err) && !strings.Contains(strings.ToLower(err.Error()), "no longer has this server container") {
			return err
		}
	}
	var stack *rune.Rune
	if loadErr == nil {
		stack = &gs
	}
	if err := a.cleanupStackSidecars(ctx, s, stack, false); err != nil {
		_, _ = a.db.Exec(`UPDATE servers SET status='error',error_message=?,updated_at=CURRENT_TIMESTAMP WHERE id=?`, err.Error(), s.ID)
		return err
	}
	if _, err := a.db.Exec(`UPDATE servers SET status='stopped',error_message='',updated_at=CURRENT_TIMESTAMP WHERE id=?`, s.ID); err != nil {
		return fmt.Errorf("record stopped stack state: %w", err)
	}
	a.clearRuntimePending(s.ID)
	return nil
}
func (a *App) watchReady(s Server, gs rune.Rune) {
	start := time.Now()
	var re *regexp.Regexp
	if gs.Startup.DoneRegex != "" {
		re, _ = regexp.Compile(gs.Startup.DoneRegex)
	}
	for {
		time.Sleep(2 * time.Second)
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		ins, err := a.engine.Inspect(ctx, s.ContainerID)
		cancel()
		if err != nil {
			if strings.Contains(strings.ToLower(err.Error()), "no such container") {
				_, _ = a.db.Exec(`UPDATE servers SET status='stopped',error_message='container is no longer present in Docker' WHERE id=?`, s.ID)
			} else {
				message := "Docker Engine could not be reached while checking startup; check docker.service and the configured socket"
				_, _ = a.db.Exec(`UPDATE servers SET status='error',error_message=? WHERE id=?`, message, s.ID)
				a.audit(User{Username: "system"}, "server.readiness_error", "server", s.ID, message)
			}
			return
		}
		if !ins.State.Running {
			message := fmt.Sprintf("Container exited before readiness with code %d; review its logs and template startup settings.", ins.State.ExitCode)
			if err = a.recordServerCrash(s, "container_exited", ins.State.ExitCode, message); err != nil {
				log.Printf("could not record startup exit for server %s", s.ID)
				_, _ = a.db.Exec(`UPDATE servers SET status='error',error_message=? WHERE id=? AND status='starting'`, message, s.ID)
			}
			return
		}
		logReady := re == nil
		if re != nil {
			ctx, cancel = context.WithTimeout(context.Background(), 5*time.Second)
			logs, e := a.engine.Logs(ctx, s.ContainerID, "2000", false)
			if e == nil {
				var b strings.Builder
				_ = docker.CopyLogs(&b, logs)
				logs.Close()
				logReady = re.MatchString(b.String())
			}
			cancel()
		}
		web := false
		hasWeb := false
		for _, p := range gs.Ports {
			if strings.EqualFold(p.Name, "web") && p.Protocol != "udp" {
				hasWeb = true
				hp := s.Ports[p.Name]
				conn, e := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(hp)), 500*time.Millisecond)
				if e == nil {
					web = true
					conn.Close()
				}
				break
			}
		}
		ready := logReady
		if hasWeb {
			ready = web && (re == nil || logReady)
		}
		if ready {
			_, _ = a.db.Exec(`UPDATE servers SET status='running',error_message='' WHERE id=?`, s.ID)
			return
		}
		if time.Since(start) > 10*time.Minute {
			message := "startup did not reach readiness after 10 minutes; check the console, template readiness pattern, and published web port"
			_, _ = a.db.Exec(`UPDATE servers SET status='error',error_message=? WHERE id=?`, message, s.ID)
			a.audit(User{Username: "system"}, "server.readiness_timeout", "server", s.ID, message)
			return
		}
	}
}

func (a *App) serverStats(w http.ResponseWriter, r *http.Request) {
	s, e := a.getServer(chi.URLParam(r, "id"))
	if e != nil {
		writeError(w, 404, "server not found")
		return
	}
	u := principal(r)
	if !a.allowedServer(u, "server.view", s.ID, s.GameskillID) {
		writeError(w, 403, "insufficient permissions")
		return
	}
	if s.ContainerID == "" || s.Status != "running" {
		writeJSON(w, 200, map[string]any{"running": false, "cpu_percent": 0, "memory_mb": 0})
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	cpu, mem, e := a.engine.Stats(ctx, s.ContainerID)
	if e != nil {
		writeError(w, 502, e.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"running": true, "cpu_percent": cpu, "memory_mb": float64(mem) / 1024 / 1024, "cpu_limit": s.CPULimit, "memory_limit_mb": s.MemoryLimitMB})
}

func (a *App) loadRune(id string) (rune.Rune, error) {
	var raw string
	if err := a.db.QueryRow(`SELECT yaml_blob FROM gameskills WHERE id=?`, id).Scan(&raw); err != nil {
		return rune.Rune{}, err
	}
	return rune.Parse(raw)
}
func (a *App) runtimeEnv(s Server, gs rune.Rune) (map[string]string, error) {
	env := gs.DefaultEnv()
	for k, v := range s.Env {
		if isSecretVariable(gs, k) {
			plain, e := security.Decrypt([]byte(a.cfg.Auth.SecretKey), v)
			if e != nil {
				return nil, fmt.Errorf("setting %s cannot be decrypted; verify auth.secret_key in the config", k)
			}
			env[k] = plain
		} else {
			env[k] = v
		}
	}
	env["SERVER_NAME"] = s.Name
	env["HOME"] = "/data"
	env["PUID"] = strconv.Itoa(os.Getuid())
	env["PGID"] = strconv.Itoa(os.Getgid())
	env["UID"] = strconv.Itoa(os.Getuid())
	env["GID"] = strconv.Itoa(os.Getgid())
	for _, p := range gs.Ports {
		if n, ok := s.Ports[p.Name]; ok {
			env[strings.ToUpper(p.Name)+"_PORT"] = strconv.Itoa(n)
		}
	}
	host := a.publicHost()
	port := 0
	if n, ok := s.Ports["web"]; ok {
		port = n
	}
	if port == 0 {
		for _, p := range gs.Ports {
			if p.Protocol != "udp" {
				port = s.Ports[p.Name]
				break
			}
		}
	}
	if port > 0 {
		env["PUBLIC_URL"] = "http://" + net.JoinHostPort(host, strconv.Itoa(port))
	} else {
		env["PUBLIC_URL"] = "http://" + host
	}
	for k, v := range env {
		if strings.Contains(v, "{{PUBLIC_URL}}") && k != "PUBLIC_URL" {
			env[k] = strings.ReplaceAll(v, "{{PUBLIC_URL}}", env["PUBLIC_URL"])
		}
	}
	return env, nil
}

func (a *App) publicHost() string {
	configured := strings.TrimSpace(a.cfg.Server.Host)
	if configured != "" && configured != "0.0.0.0" && configured != "::" {
		return strings.Trim(configured, "[]")
	}
	addresses, err := net.InterfaceAddrs()
	if err == nil {
		for _, address := range addresses {
			ip, _, err := net.ParseCIDR(address.String())
			if err != nil || ip.IsLoopback() || ip.IsUnspecified() {
				continue
			}
			if v4 := ip.To4(); v4 != nil {
				return v4.String()
			}
		}
		for _, address := range addresses {
			ip, _, err := net.ParseCIDR(address.String())
			if err == nil && !ip.IsLoopback() && !ip.IsUnspecified() {
				return ip.String()
			}
		}
	}
	return "localhost"
}

func (a *App) containerConfig(s Server, gs rune.Rune, env map[string]string) (docker.CreateConfig, error) {
	limits := stackResourceLimits(s, gs)
	return a.containerConfigWithStack(s, gs, env, "", limits[0])
}

func (a *App) containerConfigWithStack(s Server, gs rune.Rune, env map[string]string, network string, limits stackResourceLimit) (docker.CreateConfig, error) {
	image := rune.ApplyTemplate(gs.Docker.Image, env)
	containerPath := gs.Docker.DataPath
	if containerPath == "" {
		containerPath = "/data"
	}
	appDataDir := serverAppDataDir(s, gs)
	if err := os.MkdirAll(appDataDir, 0770); err != nil {
		return docker.CreateConfig{}, fmt.Errorf("create app data directory: %w", err)
	}
	binds := []string{appDataDir + ":" + containerPath}
	for _, v := range gs.Docker.ExtraVolumes {
		target := filepath.Join(appDataDir, "_"+strings.ReplaceAll(strings.Trim(v, "/"), "/", "_"))
		if err := os.MkdirAll(target, 0770); err != nil {
			return docker.CreateConfig{}, fmt.Errorf("create data volume for %s: %w", v, err)
		}
		binds = append(binds, target+":"+v)
	}
	hostCfg := docker.HostConfig{Binds: binds, PortBindings: map[string][]docker.PortBinding{}, RestartPolicy: map[string]any{"Name": "on-failure", "MaximumRetryCount": 3}}
	for _, capability := range gs.Docker.Capabilities {
		capability = strings.TrimPrefix(strings.ToUpper(strings.TrimSpace(capability)), "CAP_")
		hostCfg.CapAdd = append(hostCfg.CapAdd, capability)
	}
	for _, device := range gs.Docker.Devices {
		parts := strings.Split(device, ":")
		target, permissions := parts[0], "rwm"
		if len(parts) > 1 && parts[1] != "" {
			target = parts[1]
		}
		if len(parts) == 3 {
			permissions = parts[2]
		}
		hostCfg.Devices = append(hostCfg.Devices, docker.DeviceMapping{PathOnHost: parts[0], PathInContainer: target, CgroupPermissions: permissions})
	}
	if len(gs.Docker.Sysctls) > 0 {
		hostCfg.Sysctls = make(map[string]string, len(gs.Docker.Sysctls))
		for key, value := range gs.Docker.Sysctls {
			hostCfg.Sysctls[key] = rune.ApplyTemplate(value, env)
		}
	}
	hostCfg.NanoCPUs = limits.cpuNano
	hostCfg.Memory = limits.memoryBytes
	exposed := map[string]struct{}{}
	for _, p := range gs.Ports {
		host := s.Ports[p.Name]
		if host == 0 {
			continue
		}
		protos := []string{p.Protocol}
		if p.Protocol == "tcp+udp" {
			protos = []string{"tcp", "udp"}
		}
		for _, protocol := range protos {
			key := fmt.Sprintf("%d/%s", p.Default, protocol)
			exposed[key] = struct{}{}
			ip := "0.0.0.0"
			if strings.EqualFold(p.Name, "rcon") {
				ip = "127.0.0.1"
			}
			hostCfg.PortBindings[key] = append(hostCfg.PortBindings[key], docker.PortBinding{HostIP: ip, HostPort: strconv.Itoa(host)})
		}
	}
	containerEnv := map[string]string{"HOME": "/data"}
	for k, v := range gs.Docker.Env {
		containerEnv[k] = rune.ApplyTemplate(v, env)
	}
	for k, v := range env {
		if gs.Stack == nil || isPanelRuntimeVariable(k) {
			containerEnv[k] = v
		}
	}
	for name, port := range s.Ports {
		containerEnv["PORT_"+name] = strconv.Itoa(port)
	}
	envList := make([]string, 0, len(containerEnv))
	for k, v := range containerEnv {
		envList = append(envList, k+"="+v)
	}
	sort.Strings(envList)
	cmd := []string{}
	for _, c := range gs.Startup.Exec {
		cmd = append(cmd, rune.ApplyTemplate(c, env))
	}
	if len(cmd) == 0 && strings.TrimSpace(gs.Startup.Command) != "" {
		cmd = []string{"/bin/sh", "-c", rune.ApplyTemplate(gs.Startup.Command, env)}
	}
	user := gs.Docker.User
	if user == "" && !gs.Docker.KeepEntrypoint {
		user = fmt.Sprintf("%d:%d", os.Getuid(), os.Getgid())
	}
	if !gs.Docker.KeepEntrypoint {
		passwd, err := a.passwdShim(user)
		if err != nil {
			return docker.CreateConfig{}, err
		}
		binds = append(binds, passwd+":/etc/passwd:ro")
		hostCfg.Binds = binds
	}
	working := ""
	if gs.Docker.DataPath == "" {
		working = "/data"
	}
	labels := map[string]string{docklightServerLabel: s.ID, docklightRoleLabel: "server"}
	config := docker.CreateConfig{Image: image, Cmd: cmd, Env: envList, WorkingDir: working, User: user, Tty: false, OpenStdin: true, AttachStdin: true, AttachStdout: true, AttachStderr: true, ExposedPorts: exposed, Labels: labels, HostConfig: hostCfg}
	if network != "" {
		config.NetworkingConfig = &docker.NetworkingConfig{EndpointsConfig: map[string]docker.EndpointSettings{network: {}}}
	}
	return config, nil
}

func isPanelRuntimeVariable(name string) bool {
	key := strings.ToUpper(name)
	switch key {
	case "SERVER_NAME", "PUBLIC_URL", "HOME", "PUID", "PGID", "UID", "GID":
		return true
	default:
		return strings.HasPrefix(key, "PORT_") || strings.HasSuffix(key, "_PORT")
	}
}

func (a *App) allocatePorts(serverID string, definitions []rune.Port) (map[string]int, error) {
	tx, e := a.db.Begin()
	if e != nil {
		return nil, fmt.Errorf("reserve host ports: %w", e)
	}
	defer tx.Rollback()
	out := map[string]int{}
	used := map[int]bool{}
	for _, p := range definitions {
		allocated := 0
		for candidate := a.cfg.Ports.RangeMin; candidate < a.cfg.Ports.RangeMax; candidate++ {
			if used[candidate] {
				continue
			}
			var exists int
			if tx.QueryRow(`SELECT count(*) FROM port_allocations WHERE port=?`, candidate).Scan(&exists) != nil || exists != 0 {
				continue
			}
			available, checkErr := portAvailable(candidate, p.Protocol)
			if checkErr != nil {
				return nil, checkErr
			}
			if available {
				allocated = candidate
			}
			if allocated > 0 {
				break
			}
		}
		if allocated == 0 {
			return nil, fmt.Errorf("no free host ports remain in range %d–%d; widen ports.range_min/range_max or free a port", a.cfg.Ports.RangeMin, a.cfg.Ports.RangeMax)
		}
		if _, e = tx.Exec(`INSERT INTO port_allocations(port,server_id,name) VALUES(?,?,?)`, allocated, serverID, p.Name); e != nil {
			return nil, fmt.Errorf("reserve host port %d: %w", allocated, e)
		}
		out[p.Name] = allocated
		used[allocated] = true
	}
	if e = tx.Commit(); e != nil {
		return nil, e
	}
	return out, nil
}

func portAvailable(port int, protocol string) (bool, error) {
	check := func(network string) (bool, error) {
		address := net.JoinHostPort("0.0.0.0", strconv.Itoa(port))
		var err error
		if network == "udp4" {
			var conn *net.UDPConn
			conn, err = net.ListenUDP(network, &net.UDPAddr{IP: net.IPv4zero, Port: port})
			if err == nil {
				_ = conn.Close()
			}
		} else {
			var listener net.Listener
			listener, err = net.Listen(network, address)
			if err == nil {
				_ = listener.Close()
			}
		}
		if err == nil {
			return true, nil
		}
		if errors.Is(err, syscall.EADDRINUSE) {
			return false, nil
		}
		return false, fmt.Errorf("cannot check whether host port %d is free: %w; allow the panel to bind ports in its configured range", port, err)
	}
	if protocol == "udp" {
		return check("udp4")
	}
	tcpFree, err := check("tcp4")
	if err != nil || !tcpFree || protocol == "tcp" {
		return tcpFree, err
	}
	udpFree, err := check("udp4")
	if err != nil {
		return false, err
	}
	return tcpFree && udpFree, nil
}

func (a *App) releasePorts(id string) {
	_, _ = a.db.Exec(`DELETE FROM port_allocations WHERE server_id=?`, id)
}
func (a *App) requirePerm(w http.ResponseWriter, u User, s Server, p string) bool {
	if !a.allowedServer(u, p, s.ID, s.GameskillID) {
		writeError(w, 403, p+" permission is required for this server")
		return false
	}
	return true
}

func maskServer(s Server, d *sql.DB) Server {
	var raw string
	if d.QueryRow(`SELECT yaml_blob FROM gameskills WHERE id=?`, s.GameskillID).Scan(&raw) == nil {
		if gs, e := rune.Parse(raw); e == nil {
			sec := secretVariables(gs)
			for k := range s.Env {
				if sec[k] {
					s.Env[k] = "********"
				}
			}
		}
	}
	return s
}

func (a *App) decorateServer(u User, s Server) Server {
	s.Permissions = []string{}
	for _, permission := range []string{"server.view", "server.control", "server.console", "server.files", "server.backup", "server.schedule", "server.delete"} {
		if a.allowedServer(u, permission, s.ID, s.GameskillID) {
			s.Permissions = append(s.Permissions, permission)
		}
	}
	if gs, err := a.loadRune(s.GameskillID); err == nil && gs.Stack != nil {
		type serviceState struct{ status, message string }
		states := map[string]serviceState{}
		rows, queryErr := a.db.Query(`SELECT service_name,status,last_error FROM server_sidecars WHERE server_id=?`, s.ID)
		if queryErr == nil {
			for rows.Next() {
				var name, status, message string
				if rows.Scan(&name, &status, &message) == nil {
					states[name] = serviceState{status: status, message: message}
				}
			}
			_ = rows.Close()
		}
		s.StackServices = make([]StackServiceStatus, 0, len(gs.Stack.Services))
		for _, service := range gs.Stack.Services {
			state := states[service.Name]
			if state.status == "" {
				state.status = "stopped"
			}
			s.StackServices = append(s.StackServices, StackServiceStatus{Name: service.Name, Status: state.status, ErrorMessage: state.message})
		}
	}
	return s
}

func secretVariables(gs rune.Rune) map[string]bool {
	m := map[string]bool{}
	for _, v := range gs.Variables {
		if v.Secret || secretFieldName(v.Key) {
			m[v.Key] = true
		}
	}
	if gs.RCON != nil && gs.RCON.PasswordVar != "" {
		m[gs.RCON.PasswordVar] = true
	}
	return m
}
func secretFieldName(key string) bool {
	name := strings.ToLower(strings.NewReplacer("_", "", "-", "", ".", "").Replace(key))
	for _, suffix := range []string{"password", "passwd", "pass", "secret", "token", "credential", "apikey", "privatekey", "accesskey"} {
		if strings.HasSuffix(name, suffix) {
			return true
		}
	}
	return strings.Contains(name, "clientsecret") || strings.Contains(name, "signingkey")
}
func publicRune(gs rune.Rune) rune.Rune {
	gs.Variables = append([]rune.Variable(nil), gs.Variables...)
	secret := secretVariables(gs)
	for i := range gs.Variables {
		if secret[gs.Variables[i].Key] {
			gs.Variables[i].Default = nil
			gs.Variables[i].Secret = true
		}
	}
	return gs
}
func runeSecretValues(gs rune.Rune, env map[string]string) []string {
	secret := secretVariables(gs)
	values := []string{}
	for k, value := range env {
		if secret[k] && value != "" {
			values = append(values, value)
		}
	}
	return values
}
func redactSecrets(s string, secrets []string) string {
	for _, value := range secrets {
		if value != "" {
			s = strings.ReplaceAll(s, value, "[redacted]")
		}
	}
	return s
}
func isSecretVariable(gs rune.Rune, key string) bool { return secretVariables(gs)[key] }
func shortID(s string) string {
	if len(s) > 8 {
		return s[:8]
	}
	return s
}

func (a *App) passwdShim(user string) (string, error) {
	uid, gid := os.Getuid(), os.Getgid()
	if user != "" {
		parts := strings.Split(user, ":")
		if len(parts) > 0 {
			if n, err := strconv.Atoi(parts[0]); err == nil {
				uid = n
			}
		}
		if len(parts) > 1 {
			if n, err := strconv.Atoi(parts[1]); err == nil {
				gid = n
			}
		}
	}
	content := fmt.Sprintf("root:x:0:0:root:/root:/bin/sh\nygg:x:%d:%d:Docklight:/data:/bin/sh\nnobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin\n", uid, gid)
	file := filepath.Join(a.dataRoot, ".ygg-passwd")
	if err := os.WriteFile(file, []byte(content), 0444); err != nil {
		return "", fmt.Errorf("create the runtime passwd shim: %w", err)
	}
	return file, nil
}

var _ = sql.ErrNoRows
