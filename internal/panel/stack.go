package panel

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"example.com/yggdrasil-panel/internal/docker"
	"example.com/yggdrasil-panel/internal/rune"
)

const (
	docklightServerLabel  = "docklight.server_id"
	docklightRoleLabel    = "docklight.role"
	docklightServiceLabel = "docklight.service"
	stackHealthTimeout    = 2 * time.Minute
	stackHealthInterval   = 2 * time.Second
)

type stackResourceLimit struct {
	cpuNano     int64
	memoryBytes int64
}

func serverAppDataDir(s Server, gs rune.Rune) string {
	if gs.Stack != nil {
		return filepath.Join(s.DataDir, "_app")
	}
	return s.DataDir
}

func (a *App) serverFilesRoot(s Server) (string, error) {
	gs, err := a.loadRune(s.GameskillID)
	if err != nil {
		return "", fmt.Errorf("load server template for file access: %w", err)
	}
	root := serverAppDataDir(s, gs)
	if gs.Stack != nil {
		if info, statErr := os.Lstat(s.DataDir); statErr != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return "", errors.New("server data directory is unavailable")
		}
		if err = os.MkdirAll(root, 0700); err != nil {
			return "", fmt.Errorf("create app data directory: %w", err)
		}
		rootInfo, statErr := os.Lstat(root)
		if statErr != nil || !rootInfo.IsDir() || rootInfo.Mode()&os.ModeSymlink != 0 {
			return "", errors.New("app data directory is unavailable")
		}
	}
	return root, nil
}

func stackResourceLimits(s Server, gs rune.Rune) []stackResourceLimit {
	count := 1
	if gs.Stack != nil {
		count += len(gs.Stack.Services)
	}
	weights := make([]int, count)
	weights[0] = 3
	for i := 1; i < count; i++ {
		weights[i] = gs.Stack.Services[i-1].ResourceWeight
		if weights[i] == 0 {
			weights[i] = 1
		}
	}
	limits := make([]stackResourceLimit, count)
	cpu := int64(s.CPULimit * 1e9)
	memory := int64(s.MemoryLimitMB) * 1024 * 1024
	for i, amount := range splitResource(cpu, weights) {
		limits[i].cpuNano = amount
	}
	for i, amount := range splitResource(memory, weights) {
		limits[i].memoryBytes = amount
	}
	return limits
}

func splitResource(total int64, weights []int) []int64 {
	out := make([]int64, len(weights))
	if total <= 0 || len(weights) == 0 {
		return out
	}
	weightTotal := int64(0)
	for _, weight := range weights {
		weightTotal += int64(weight)
	}
	used := int64(0)
	for i, weight := range weights {
		out[i] = total * int64(weight) / weightTotal
		used += out[i]
	}
	out[0] += total - used
	return out
}

func stackNamePart(serverID string) string {
	sum := sha256.Sum256([]byte(serverID))
	return hex.EncodeToString(sum[:8])
}

func stackNetworkName(serverID string) string {
	return "docklight-stack-" + stackNamePart(serverID)
}

func stackContainerName(serverID, service string) string {
	return "docklight-" + stackNamePart(serverID) + "-" + service
}

func (a *App) ensureStackNetwork(ctx context.Context, serverID string) (string, error) {
	name := stackNetworkName(serverID)
	info, err := a.engine.InspectNetwork(ctx, name)
	if err == nil {
		if info.Labels[docklightServerLabel] != serverID {
			return "", fmt.Errorf("Docker network %q exists without Docklight ownership labels", name)
		}
		return name, nil
	}
	if !docker.IsNotFound(err) {
		return "", err
	}
	_, err = a.engine.CreateNetwork(ctx, name, docker.NetworkCreateConfig{
		Driver: "bridge",
		Labels: map[string]string{docklightServerLabel: serverID, "docklight.managed": "true"},
	})
	if err == nil {
		return name, nil
	}
	// If another start created the deterministic network first, reuse it only
	// after confirming the server ownership label.
	info, inspectErr := a.engine.InspectNetwork(ctx, name)
	if inspectErr == nil && info.Labels[docklightServerLabel] == serverID {
		return name, nil
	}
	return "", err
}

func (a *App) stackContainers(ctx context.Context, s Server) ([]docker.ContainerSummary, error) {
	containers, err := a.engine.ListContainers(ctx, true, map[string]string{
		docklightServerLabel: s.ID,
		docklightRoleLabel:   "sidecar",
	})
	if err != nil {
		return nil, err
	}
	seen := make(map[string]bool, len(containers))
	for _, container := range containers {
		seen[container.ID] = true
	}
	rows, err := a.db.Query(`SELECT service_name,container_id FROM server_sidecars WHERE server_id=?`, s.ID)
	if err != nil {
		return nil, fmt.Errorf("load saved sidecar IDs: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var name, id string
		if err = rows.Scan(&name, &id); err != nil {
			return nil, err
		}
		if id != "" && !seen[id] {
			containers = append(containers, docker.ContainerSummary{ID: id, Labels: map[string]string{docklightServiceLabel: name}})
			seen[id] = true
		}
	}
	if err = rows.Err(); err != nil {
		return nil, err
	}
	return containers, nil
}

func (a *App) setSidecarState(serverID, name, containerID, status string) error {
	_, err := a.db.Exec(`INSERT INTO server_sidecars(server_id,service_name,container_id,status,last_error,updated_at)
		VALUES(?,?,?,?, '',CURRENT_TIMESTAMP)
		ON CONFLICT(server_id,service_name) DO UPDATE SET container_id=excluded.container_id,status=excluded.status,last_error='',updated_at=CURRENT_TIMESTAMP`, serverID, name, containerID, status)
	if err != nil {
		return fmt.Errorf("record sidecar %q state: %w", name, err)
	}
	return nil
}

func (a *App) setSidecarFailure(serverID, name, containerID, message string) error {
	_, err := a.db.Exec(`INSERT INTO server_sidecars(server_id,service_name,container_id,status,last_error,updated_at)
		VALUES(?,?,?,'error',?,CURRENT_TIMESTAMP)
		ON CONFLICT(server_id,service_name) DO UPDATE SET container_id=excluded.container_id,status='error',last_error=excluded.last_error,updated_at=CURRENT_TIMESTAMP`, serverID, name, containerID, message)
	if err != nil {
		return fmt.Errorf("record app stack service %q failure: %w", name, err)
	}
	return nil
}

func (a *App) deleteSidecarState(serverID, name, containerID string) {
	if name != "" {
		_, _ = a.db.Exec(`DELETE FROM server_sidecars WHERE server_id=? AND (service_name=? OR container_id=?)`, serverID, name, containerID)
		return
	}
	_, _ = a.db.Exec(`DELETE FROM server_sidecars WHERE server_id=? AND container_id=?`, serverID, containerID)
}

func (a *App) orderSidecars(containers []docker.ContainerSummary, gs *rune.Rune) {
	order := map[string]int{}
	if gs != nil && gs.Stack != nil {
		for i, service := range gs.Stack.Services {
			order[service.Name] = i
		}
	}
	sort.SliceStable(containers, func(i, j int) bool {
		left, ok := order[containers[i].Labels[docklightServiceLabel]]
		if !ok {
			left = len(order)
		}
		right, ok := order[containers[j].Labels[docklightServiceLabel]]
		if !ok {
			right = len(order)
		}
		if left == right {
			return containers[i].ID < containers[j].ID
		}
		return left > right
	})
}

func (a *App) cleanupStackSidecars(ctx context.Context, s Server, gs *rune.Rune, remove bool) error {
	if gs == nil || gs.Stack == nil {
		var count int
		if err := a.db.QueryRow(`SELECT count(*) FROM server_sidecars WHERE server_id=?`, s.ID).Scan(&count); err != nil {
			return fmt.Errorf("check saved app stack state: %w", err)
		}
		if count == 0 {
			return nil
		}
	}
	containers, err := a.stackContainers(ctx, s)
	if err != nil {
		return fmt.Errorf("list app stack sidecars: %w", err)
	}
	a.orderSidecars(containers, gs)
	for _, container := range containers {
		if container.ID == "" {
			continue
		}
		service := container.Labels[docklightServiceLabel]
		ins, inspectErr := a.engine.Inspect(ctx, container.ID)
		if docker.IsNotFound(inspectErr) {
			a.deleteSidecarState(s.ID, service, container.ID)
			continue
		}
		if inspectErr != nil {
			return fmt.Errorf("inspect app stack sidecar %q: %w", service, inspectErr)
		}
		if ins.State.Running {
			if stopErr := a.engine.Stop(ctx, container.ID, 15); stopErr != nil && !docker.IsNotFound(stopErr) && !docker.IsNotModified(stopErr) {
				return fmt.Errorf("stop app stack sidecar %q: %w", service, stopErr)
			}
		}
		if remove {
			if removeErr := a.engine.Remove(ctx, container.ID); removeErr != nil && !docker.IsNotFound(removeErr) {
				return fmt.Errorf("remove app stack sidecar %q: %w", service, removeErr)
			}
			a.deleteSidecarState(s.ID, service, container.ID)
		} else if service != "" {
			if err = a.setSidecarState(s.ID, service, container.ID, "stopped"); err != nil {
				return err
			}
		} else {
			_, err = a.db.Exec(`UPDATE server_sidecars SET status='stopped',updated_at=CURRENT_TIMESTAMP WHERE server_id=? AND container_id=?`, s.ID, container.ID)
			if err != nil {
				return fmt.Errorf("record stopped sidecar state: %w", err)
			}
		}
	}
	return nil
}

func (a *App) removeStackResources(ctx context.Context, s Server, gs *rune.Rune) error {
	if gs == nil || gs.Stack == nil {
		var count int
		if err := a.db.QueryRow(`SELECT count(*) FROM server_sidecars WHERE server_id=?`, s.ID).Scan(&count); err != nil {
			return fmt.Errorf("check saved app stack state: %w", err)
		}
		if count == 0 {
			return nil
		}
	}
	if err := a.cleanupStackSidecars(ctx, s, gs, true); err != nil {
		return err
	}
	name := stackNetworkName(s.ID)
	info, err := a.engine.InspectNetwork(ctx, name)
	if docker.IsNotFound(err) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("inspect app stack network: %w", err)
	}
	if info.Labels[docklightServerLabel] != s.ID {
		return fmt.Errorf("refusing to remove Docker network %q without matching Docklight ownership labels", name)
	}
	if err = a.engine.RemoveNetwork(ctx, info.ID); err != nil && !docker.IsNotFound(err) {
		return fmt.Errorf("remove app stack network: %w", err)
	}
	return nil
}

func (a *App) monitorStackSidecars(ctx context.Context, s Server) error {
	rows, err := a.db.Query(`SELECT service_name,container_id,status,last_error FROM server_sidecars WHERE server_id=? ORDER BY service_name`, s.ID)
	if err != nil {
		return fmt.Errorf("list app stack service state: %w", err)
	}
	type savedService struct {
		name, id, status, lastError string
	}
	var services []savedService
	for rows.Next() {
		var item savedService
		if err = rows.Scan(&item.name, &item.id, &item.status, &item.lastError); err != nil {
			_ = rows.Close()
			return fmt.Errorf("read app stack service state: %w", err)
		}
		services = append(services, item)
	}
	if err = rows.Err(); err != nil {
		_ = rows.Close()
		return fmt.Errorf("read app stack service state: %w", err)
	}
	if err = rows.Close(); err != nil {
		return fmt.Errorf("finish app stack service state: %w", err)
	}
	for _, item := range services {
		if err = ctx.Err(); err != nil {
			return err
		}
		if item.id == "" {
			continue
		}
		inspectCtx, cancel := context.WithTimeout(ctx, runtimeInspectTimeout)
		ins, inspectErr := a.engine.Inspect(inspectCtx, item.id)
		cancel()
		if inspectErr != nil {
			if docker.IsNotFound(inspectErr) {
				message := "Docker no longer has this stack service container."
				if item.status != "error" || item.lastError != message {
					if err = a.setSidecarFailure(s.ID, item.name, item.id, message); err != nil {
						return err
					}
				}
			}
			// A Docker transport error is unknown state; keep the last saved status.
			continue
		}
		if ins.State.Running {
			if item.status != "running" || item.lastError != "" {
				if err = a.setSidecarState(s.ID, item.name, item.id, "running"); err != nil {
					return err
				}
			}
			continue
		}
		message := fmt.Sprintf("Container exited with code %d.", ins.State.ExitCode)
		if item.status != "error" || item.lastError != message {
			if err = a.setSidecarFailure(s.ID, item.name, item.id, message); err != nil {
				return err
			}
		}
	}
	return nil
}

func (a *App) createStackSidecars(ctx context.Context, s Server, gs rune.Rune, env map[string]string, network string, limits []stackResourceLimit) error {
	if gs.Stack == nil {
		return nil
	}
	if err := a.cleanupStackSidecars(ctx, s, &gs, true); err != nil {
		return err
	}
	for i, service := range gs.Stack.Services {
		enabled, err := rune.ServiceEnabled(service.Enabled, env)
		if err != nil {
			return fmt.Errorf("app stack service %q: %w", service.Name, err)
		}
		if !enabled {
			continue
		}
		image := rune.ApplyTemplate(service.Image, env)
		if image == "" {
			return fmt.Errorf("app stack service %q resolved to an empty image", service.Name)
		}
		if err := a.pullImage(ctx, image); err != nil {
			return fmt.Errorf("pull app stack service %q: %w", service.Name, err)
		}
		serviceEnv := make([]string, 0, len(service.Environment))
		for key, value := range service.Environment {
			serviceEnv = append(serviceEnv, key+"="+rune.ApplyTemplate(value, env))
		}
		sort.Strings(serviceEnv)
		host := docker.HostConfig{
			RestartPolicy: map[string]any{"Name": "on-failure", "MaximumRetryCount": 3},
			NanoCPUs:      limits[i+1].cpuNano,
			Memory:        limits[i+1].memoryBytes,
		}
		if service.DataPath != "" {
			dataDir := filepath.Join(s.DataDir, "_stack", service.Name)
			if err := os.MkdirAll(dataDir, 0770); err != nil {
				return fmt.Errorf("create data directory for app stack service %q: %w", service.Name, err)
			}
			host.Binds = []string{dataDir + ":" + service.DataPath}
		}
		labels := map[string]string{docklightServerLabel: s.ID, docklightRoleLabel: "sidecar", docklightServiceLabel: service.Name}
		config := docker.CreateConfig{
			Image: image, Cmd: applyStackCommand(service.Command, env), Env: serviceEnv, User: service.User,
			Labels: labels, HostConfig: host,
			NetworkingConfig: &docker.NetworkingConfig{EndpointsConfig: map[string]docker.EndpointSettings{network: {Aliases: []string{service.Name}}}},
		}
		name := stackContainerName(s.ID, service.Name)
		containerID, err := a.engine.Create(ctx, name, config)
		if err != nil {
			return fmt.Errorf("create app stack service %q: %w", service.Name, err)
		}
		if err = a.setSidecarState(s.ID, service.Name, containerID, "created"); err != nil {
			removeErr := a.engine.Remove(context.Background(), containerID)
			if removeErr != nil && !docker.IsNotFound(removeErr) {
				return errors.Join(err, fmt.Errorf("remove unrecorded sidecar %q: %w", service.Name, removeErr))
			}
			return err
		}
		if err = a.engine.Start(ctx, containerID); err != nil {
			removeErr := a.engine.Remove(context.Background(), containerID)
			a.deleteSidecarState(s.ID, service.Name, containerID)
			if removeErr != nil && !docker.IsNotFound(removeErr) {
				return errors.Join(fmt.Errorf("start app stack service %q: %w", service.Name, err), fmt.Errorf("remove failed sidecar %q: %w", service.Name, removeErr))
			}
			return fmt.Errorf("start app stack service %q: %w", service.Name, err)
		}
		if err = a.setSidecarState(s.ID, service.Name, containerID, "running"); err != nil {
			return err
		}
	}
	return a.waitStackSidecarHealth(ctx, s, gs, stackHealthTimeout, stackHealthInterval)
}

func (a *App) waitStackSidecarHealth(ctx context.Context, s Server, gs rune.Rune, timeout, interval time.Duration) error {
	if gs.Stack == nil {
		return nil
	}
	deadline := time.Now().Add(timeout)
	for {
		pending := false
		for _, service := range gs.Stack.Services {
			var containerID string
			err := a.db.QueryRowContext(ctx, `SELECT container_id FROM server_sidecars WHERE server_id=? AND service_name=?`, s.ID, service.Name).Scan(&containerID)
			if errors.Is(err, sql.ErrNoRows) {
				continue
			}
			if err != nil {
				return fmt.Errorf("read app stack service %q before health check: %w", service.Name, err)
			}
			inspectCtx, cancel := context.WithTimeout(ctx, runtimeInspectTimeout)
			ins, inspectErr := a.engine.Inspect(inspectCtx, containerID)
			cancel()
			if docker.IsNotFound(inspectErr) {
				return fmt.Errorf("app stack service %q disappeared before its health check completed", service.Name)
			}
			if inspectErr != nil {
				return fmt.Errorf("inspect app stack service %q health: %w", service.Name, inspectErr)
			}
			check := ins.Config.Healthcheck.Test
			if len(check) == 0 || strings.EqualFold(check[0], "NONE") {
				continue
			}
			if ins.State.Health != nil && ins.State.Health.Status == "healthy" {
				continue
			}
			if ins.State.Health != nil && ins.State.Health.Status == "unhealthy" {
				return fmt.Errorf("app stack service %q failed its Docker health check; review its Logs and image settings", service.Name)
			}
			pending = true
		}
		if !pending {
			return nil
		}
		remaining := time.Until(deadline)
		if remaining <= 0 {
			return fmt.Errorf("app stack sidecar health checks did not become healthy within %s; review service logs and Docker image settings", timeout)
		}
		wait := interval
		if wait <= 0 || wait > remaining {
			wait = remaining
		}
		timer := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}
}

func applyStackCommand(command []string, env map[string]string) []string {
	if len(command) == 0 {
		return nil
	}
	out := make([]string, len(command))
	for i, arg := range command {
		out[i] = rune.ApplyTemplate(arg, env)
	}
	return out
}
