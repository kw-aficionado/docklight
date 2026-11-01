package panel

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"sort"
	"strings"
	"time"

	"example.com/yggdrasil-panel/internal/docker"
	"example.com/yggdrasil-panel/internal/rune"
	"github.com/go-chi/chi/v5"
)

var errScheduledAppUpdateSkipped = errors.New("skipped because the server is stopped")

func (a *App) updateServerApp(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	u := principal(r)
	if u.Role != "admin" {
		writeError(w, http.StatusForbidden, "only administrators can update an app")
		return
	}
	s, err := a.getServer(id)
	if err != nil {
		writeError(w, http.StatusNotFound, "server not found")
		return
	}
	if !a.allowedServer(u, "server.control", s.ID, s.GameskillID, s.RealmID) {
		writeError(w, http.StatusForbidden, "server.control permission is required")
		return
	}
	if s.Status == "installing" || s.Status == "updating" || s.Status == "starting" {
		writeError(w, http.StatusConflict, "wait for the current server operation to finish")
		return
	}

	a.dataMu.Lock()
	locked := true
	defer func() {
		if locked {
			a.dataMu.Unlock()
		}
	}()
	s, err = a.getServer(id)
	if err != nil {
		writeError(w, http.StatusNotFound, "server not found")
		return
	}
	if s.Status == "installing" || s.Status == "updating" || s.Status == "starting" {
		writeError(w, http.StatusConflict, "wait for the current server operation to finish")
		return
	}
	if !s.Installed {
		writeError(w, http.StatusConflict, "install this app before updating it")
		return
	}
	gs, err := a.loadRune(s.GameskillID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "server template is invalid")
		return
	}
	if gs.Update == nil {
		writeError(w, http.StatusConflict, "this template does not define an app update")
		return
	}
	job := &installJob{lines: []string{"App update started; existing app data will be retained."}, updated: time.Now()}
	a.jobsMu.Lock()
	a.jobs[s.ID] = job
	a.jobsMu.Unlock()
	if _, err = a.db.Exec(`UPDATE servers SET status='updating',error_message='',updated_at=CURRENT_TIMESTAMP WHERE id=?`, s.ID); err != nil {
		a.jobsMu.Lock()
		delete(a.jobs, s.ID)
		a.jobsMu.Unlock()
		writeError(w, http.StatusInternalServerError, "could not record app update state")
		return
	}
	a.audit(u, "server.app_update.start", "server", s.ID, "")
	locked = false
	go func() {
		defer a.dataMu.Unlock()
		_ = a.runAppUpdate(context.Background(), s, gs, u, job)
	}()
	writeJSON(w, http.StatusAccepted, map[string]any{"status": "updating", "log_url": "/api/servers/" + s.ID + "/install/log"})
}

func (a *App) runAppUpdate(parent context.Context, s Server, gs rune.Rune, actor User, job *installJob) error {
	ctx, cancel := context.WithTimeout(parent, 45*time.Minute)
	defer cancel()
	var updateErr error
	serverWasRunning := s.Status == "running"
	secrets := runeSecretValues(gs, s.Env)
	preparedNetwork := ""

	if err := a.stopMainForAppUpdate(ctx, s, gs); err != nil {
		updateErr = fmt.Errorf("stop app before update: %w", err)
	} else {
		appDataDir := serverAppDataDir(s, gs)
		if err = os.MkdirAll(appDataDir, 0770); err != nil {
			updateErr = fmt.Errorf("prepare app data directory: %w", err)
		} else {
			env, envErr := a.runtimeEnv(s, gs)
			if envErr != nil {
				updateErr = envErr
			} else {
				secrets = runeSecretValues(gs, env)
				network := ""
				if gs.Stack != nil {
					network, err = a.ensureStackNetwork(ctx, s.ID)
					if err != nil {
						updateErr = fmt.Errorf("prepare private app stack network: %w", err)
					} else {
						running, checkErr := a.stackServicesRunning(ctx, s, gs, env)
						if checkErr != nil {
							updateErr = checkErr
						} else if !running {
							if err = a.createStackSidecars(ctx, s, gs, env, network, stackResourceLimits(s, gs)); err != nil {
								updateErr = fmt.Errorf("start private app services before update: %w", err)
							} else {
								preparedNetwork = network
							}
						} else {
							preparedNetwork = network
						}
					}
				}
				if updateErr == nil {
					image := gs.Update.Image
					if strings.TrimSpace(image) == "" {
						image = gs.Docker.Image
					}
					image = rune.ApplyTemplate(image, env)
					script := rune.ApplyTemplate(gs.Update.Script, env)
					if err = a.pullImage(ctx, image); err != nil {
						updateErr = fmt.Errorf("pull app update image: %w", err)
					} else if err = a.runAppUpdateScript(ctx, s, gs, env, network, image, script, job, secrets); err != nil {
						updateErr = err
					}
				}
			}
		}
	}

	if updateErr != nil {
		a.addJobLine(job, "App update step failed: "+redactSecrets(updateErr.Error(), secrets))
	}
	a.addJobLine(job, "Starting a fresh app container.")
	restartCtx, restartCancel := context.WithTimeout(context.Background(), 15*time.Minute)
	defer restartCancel()
	var startErr error
	if preparedNetwork != "" {
		startErr = a.startWithContextOnNetwork(s, restartCtx, preparedNetwork)
	} else {
		startErr = a.startWithContext(s, restartCtx)
	}
	if startErr != nil {
		startErr = fmt.Errorf("start app after update: %w", startErr)
		if updateErr != nil {
			updateErr = errors.Join(updateErr, startErr)
		} else {
			updateErr = startErr
		}
		message := redactSecrets(updateErr.Error(), secrets)
		_, _ = a.db.Exec(`UPDATE servers SET status='error',error_message=?,updated_at=CURRENT_TIMESTAMP WHERE id=?`, message, s.ID)
		a.addJobLine(job, "ERROR: "+message)
	} else if !serverWasRunning {
		a.addJobLine(job, "App container start initiated after the update.")
	} else {
		a.addJobLine(job, "App container recreation initiated after the update.")
	}

	job.mu.Lock()
	job.done = true
	job.err = redactSecrets(errorString(updateErr), secrets)
	job.updated = time.Now()
	job.mu.Unlock()
	status := "success"
	if updateErr != nil {
		status = "error"
	}
	a.audit(actor, "server.app_update.finish", "server", s.ID, "status="+status)
	if updateErr != nil {
		return errors.New(redactSecrets(updateErr.Error(), secrets))
	}
	return nil
}

func (a *App) stopMainForAppUpdate(ctx context.Context, s Server, gs rune.Rune) error {
	if s.ContainerID == "" {
		return nil
	}
	ins, err := a.engine.Inspect(ctx, s.ContainerID)
	if docker.IsNotFound(err) {
		return nil
	}
	if err != nil {
		return err
	}
	if !ins.State.Running {
		return nil
	}
	if gs.Startup.SaveCommand != "" {
		_ = a.engine.SendInput(ctx, s.ContainerID, gs.Startup.SaveCommand)
		if err = waitContext(ctx, 2*time.Second); err != nil {
			return err
		}
	}
	if gs.Startup.Stop != "" {
		_ = a.engine.SendInput(ctx, s.ContainerID, gs.Startup.Stop)
		if err = waitContext(ctx, 2*time.Second); err != nil {
			return err
		}
	}
	timeout := gs.Startup.StopTimeout
	if timeout == 0 {
		timeout = 30
	}
	if err = a.engine.Stop(ctx, s.ContainerID, timeout); err != nil && !docker.IsNotFound(err) && !docker.IsNotModified(err) {
		return err
	}
	return nil
}

func waitContext(ctx context.Context, duration time.Duration) error {
	timer := time.NewTimer(duration)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func (a *App) stackServicesRunning(ctx context.Context, s Server, gs rune.Rune, env map[string]string) (bool, error) {
	if gs.Stack == nil {
		return true, nil
	}
	for _, service := range gs.Stack.Services {
		enabled, err := rune.ServiceEnabled(service.Enabled, env)
		if err != nil {
			return false, fmt.Errorf("app stack service %q: %w", service.Name, err)
		}
		if !enabled {
			continue
		}
		var id string
		if err = a.db.QueryRowContext(ctx, `SELECT container_id FROM server_sidecars WHERE server_id=? AND service_name=?`, s.ID, service.Name).Scan(&id); err != nil {
			return false, nil
		}
		ins, err := a.engine.Inspect(ctx, id)
		if err != nil || !ins.State.Running {
			return false, nil
		}
	}
	return true, nil
}

func (a *App) runAppUpdateScript(ctx context.Context, s Server, gs rune.Rune, env map[string]string, network, image, script string, job *installJob, secrets []string) error {
	appDataDir := serverAppDataDir(s, gs)
	cfg := docker.CreateConfig{
		Image: image, Entrypoint: []string{"/bin/sh", "-c"}, Cmd: []string{script}, Env: runtimeEnvList(env),
		WorkingDir: "/data", User: "0:0", Tty: false, OpenStdin: true, AttachStdin: true, AttachStdout: true, AttachStderr: true,
		Labels:     map[string]string{docklightServerLabel: s.ID, docklightRoleLabel: "app-update"},
		HostConfig: docker.HostConfig{Binds: []string{appDataDir + ":/data"}},
	}
	if network != "" {
		cfg.NetworkingConfig = &docker.NetworkingConfig{EndpointsConfig: map[string]docker.EndpointSettings{network: {}}}
	}
	id, err := a.engine.Create(ctx, "docklight-update-"+shortID(s.ID), cfg)
	if err != nil {
		return fmt.Errorf("create app update container: %w", err)
	}
	job.mu.Lock()
	job.container = id
	job.mu.Unlock()
	if err = a.engine.Start(ctx, id); err != nil {
		_ = a.engine.Remove(context.Background(), id)
		return fmt.Errorf("start app update container: %w", err)
	}
	logCtx, logCancel := context.WithCancel(ctx)
	logDone := make(chan struct{})
	go func() {
		defer close(logDone)
		body, logErr := a.engine.Logs(logCtx, id, "all", true)
		if logErr != nil {
			a.addJobLine(job, logErr.Error())
			return
		}
		defer body.Close()
		_ = docker.CopyLogs(&logLineWriter{job: job, secrets: secrets}, body)
	}()
	code, waitErr := a.engine.Wait(ctx, id)
	logCancel()
	<-logDone
	removeErr := a.engine.Remove(context.Background(), id)
	var scriptErr error
	if removeErr != nil && !docker.IsNotFound(removeErr) {
		scriptErr = fmt.Errorf("remove app update container: %w", removeErr)
	}
	if waitErr != nil {
		scriptErr = errors.Join(scriptErr, fmt.Errorf("wait for app update container: %w", waitErr))
	} else if code != 0 {
		scriptErr = errors.Join(scriptErr, fmt.Errorf("app update script exited with status %d", code))
	}
	if err = a.fixAppUpdateOwnership(ctx, appDataDir, gs.Update.AppWritable); err != nil {
		scriptErr = errors.Join(scriptErr, fmt.Errorf("restore app data ownership: %w", err))
	}
	return scriptErr
}

func runtimeEnvList(env map[string]string) []string {
	keys := make([]string, 0, len(env))
	for key := range env {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	values := make([]string, 0, len(keys))
	for _, key := range keys {
		values = append(values, key+"="+env[key])
	}
	return values
}

func (a *App) fixAppUpdateOwnership(ctx context.Context, data string, writable []string) error {
	if err := a.pullImage(ctx, "busybox:1.36"); err != nil {
		return fmt.Errorf("could not prepare the data ownership helper: %w", err)
	}
	parts := []string{"set -eu", fmt.Sprintf("chown -R %d /data", os.Getuid())}
	for _, relative := range writable {
		if relative == "." {
			continue
		}
		segments := strings.Split(relative, "/")
		prefix := "/data"
		for _, segment := range segments {
			prefix += "/" + segment
			parts = append(parts, "[ ! -L "+shellQuote(prefix)+" ] || exit 41")
		}
		target := "/data/" + relative
		quoted := shellQuote(target)
		parts = append(parts, "if [ -e "+quoted+" ]; then chmod -R g+w -- "+quoted+"; fi")
	}
	command := strings.Join(parts, "\n")
	cfg := docker.CreateConfig{Image: "busybox:1.36", Cmd: []string{"/bin/sh", "-c", command}, User: "0:0", HostConfig: docker.HostConfig{Binds: []string{data + ":/data"}}}
	id, err := a.engine.Create(ctx, "docklight-owner-"+fmt.Sprint(time.Now().UnixNano()), cfg)
	if err != nil {
		return err
	}
	defer a.engine.Remove(context.Background(), id)
	if err = a.engine.Start(ctx, id); err != nil {
		return err
	}
	code, err := a.engine.Wait(ctx, id)
	if err != nil {
		return err
	}
	if code != 0 {
		return errors.New("app ownership helper failed; check app_writable paths for symlinks or filesystem errors")
	}
	return nil
}

func shellQuote(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "'\\''") + "'"
}

func errorString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}
