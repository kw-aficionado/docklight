package panel

import (
	"bufio"
	"context"
	"database/sql"
	"errors"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/go-chi/chi/v5"
)

const (
	metricsSampleInterval = 5 * time.Minute
	metricsRetention      = 7 * 24 * time.Hour
	metricsPruneInterval  = time.Hour
	metricsWorkerCount    = 8
)

type serverMetricPoint struct {
	SampledAt  int64   `json:"sampled_at"`
	CPUPercent float64 `json:"cpu_percent"`
	MemoryMB   float64 `json:"memory_mb"`
	Players    int     `json:"players"`
}

type hostMetricPoint struct {
	SampledAt     int64   `json:"sampled_at"`
	CPUPercent    float64 `json:"cpu_percent"`
	MemoryUsedMB  float64 `json:"memory_used_mb"`
	MemoryTotalMB float64 `json:"memory_total_mb"`
	DiskUsedMB    float64 `json:"disk_used_mb"`
	DiskTotalMB   float64 `json:"disk_total_mb"`
}

type serverMetricSeries struct {
	ServerID string              `json:"server_id"`
	Hours    int                 `json:"hours"`
	Points   []serverMetricPoint `json:"points"`
}

type hostMetricSeries struct {
	Hours  int               `json:"hours"`
	Points []hostMetricPoint `json:"points"`
}

type fleetMetricSummary struct {
	ID                string   `json:"id"`
	Name              string   `json:"name"`
	Status            string   `json:"status"`
	Samples           int      `json:"samples"`
	AverageCPUPercent *float64 `json:"average_cpu_percent"`
	PeakCPUPercent    *float64 `json:"peak_cpu_percent"`
	AverageMemoryMB   *float64 `json:"average_memory_mb"`
	PeakMemoryMB      *float64 `json:"peak_memory_mb"`
	AveragePlayers    *float64 `json:"average_players"`
	PeakPlayers       *float64 `json:"peak_players"`
}

// StartMetricsSampler records five-minute server and host snapshots, retaining
// the seven-day window used by server history and Assistant lookups.
func (a *App) StartMetricsSampler(ctx context.Context) {
	ticker := time.NewTicker(metricsSampleInterval)
	go func() {
		defer ticker.Stop()
		if err := a.sampleMetrics(ctx, time.Now().UTC()); err != nil && !errors.Is(err, context.Canceled) {
			log.Printf("metrics sampler: %v", err)
		}
		for {
			select {
			case <-ctx.Done():
				return
			case now := <-ticker.C:
				if err := a.sampleMetrics(ctx, now.UTC()); err != nil && !errors.Is(err, context.Canceled) {
					log.Printf("metrics sampler: %v", err)
				}
			}
		}
	}()
}

func (a *App) sampleMetrics(ctx context.Context, now time.Time) error {
	now = now.UTC().Truncate(time.Second)
	host := hostMetricPoint{SampledAt: now.Unix(), CPUPercent: -1, MemoryUsedMB: -1, MemoryTotalMB: -1, DiskUsedMB: -1, DiskTotalMB: -1}
	if a.metricsHostProbe != nil {
		host = a.metricsHostProbe(now)
		host.SampledAt = now.Unix()
	} else {
		host = a.probeHostMetrics(now)
	}
	if _, err := a.db.Exec(`INSERT INTO host_metrics(sampled_at,cpu_percent,memory_used_mb,memory_total_mb,disk_used_mb,disk_total_mb) VALUES(?,?,?,?,?,?) ON CONFLICT(sampled_at) DO UPDATE SET cpu_percent=excluded.cpu_percent,memory_used_mb=excluded.memory_used_mb,memory_total_mb=excluded.memory_total_mb,disk_used_mb=excluded.disk_used_mb,disk_total_mb=excluded.disk_total_mb`, host.SampledAt, host.CPUPercent, host.MemoryUsedMB, host.MemoryTotalMB, host.DiskUsedMB, host.DiskTotalMB); err != nil {
		return errors.New("could not save host metrics")
	}
	rows, err := a.db.Query(`SELECT id FROM servers WHERE status='running' AND container_id<>'' ORDER BY id`)
	if err != nil {
		return errors.New("could not list running servers for metrics")
	}
	ids := make([]string, 0)
	for rows.Next() {
		var id string
		if err = rows.Scan(&id); err != nil {
			_ = rows.Close()
			return errors.New("could not read running server IDs for metrics")
		}
		ids = append(ids, id)
	}
	if err = rows.Err(); err != nil {
		_ = rows.Close()
		return errors.New("could not read running server IDs for metrics")
	}
	if err = rows.Close(); err != nil {
		return errors.New("could not finish reading running server IDs for metrics")
	}
	if len(ids) > 0 {
		workerCount := min(metricsWorkerCount, len(ids))
		jobs := make(chan string)
		var workers sync.WaitGroup
		var failures atomicCounter
		for i := 0; i < workerCount; i++ {
			workers.Add(1)
			go func() {
				defer workers.Done()
				for id := range jobs {
					if err := a.sampleServerMetric(ctx, id, now); err != nil {
						failures.Add()
					}
				}
			}()
		}
		for _, id := range ids {
			select {
			case jobs <- id:
			case <-ctx.Done():
				close(jobs)
				workers.Wait()
				return ctx.Err()
			}
		}
		close(jobs)
		workers.Wait()
		if failures.Load() > 0 {
			return errors.New("one or more server metric samples could not be saved")
		}
	}
	if a.metricsPruneDue(now) {
		cutoff := now.Add(-metricsRetention).Unix()
		if _, err = a.db.Exec(`DELETE FROM server_metrics WHERE sampled_at<?`, cutoff); err != nil {
			return errors.New("could not prune server metrics")
		}
		if _, err = a.db.Exec(`DELETE FROM host_metrics WHERE sampled_at<?`, cutoff); err != nil {
			return errors.New("could not prune host metrics")
		}
		a.metricsMarkPruned(now)
	}
	return nil
}

type atomicCounter struct {
	mu sync.Mutex
	n  int
}

func (c *atomicCounter) Add()      { c.mu.Lock(); c.n++; c.mu.Unlock() }
func (c *atomicCounter) Load() int { c.mu.Lock(); defer c.mu.Unlock(); return c.n }

func (a *App) metricsPruneDue(now time.Time) bool {
	a.metricsMu.Lock()
	defer a.metricsMu.Unlock()
	return a.metricsPruneAt.IsZero() || now.Sub(a.metricsPruneAt) >= metricsPruneInterval
}

func (a *App) metricsMarkPruned(now time.Time) {
	a.metricsMu.Lock()
	defer a.metricsMu.Unlock()
	a.metricsPruneAt = now
}

func (a *App) sampleServerMetric(ctx context.Context, id string, now time.Time) error {
	s, err := a.getServer(id)
	if err != nil {
		return nil // A server may have been removed after the ID snapshot.
	}
	cpuPercent, memoryMB, players := -1.0, -1.0, -1
	if s.Status == "running" && s.ContainerID != "" {
		statsCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
		stats := a.metricsStats
		if stats == nil {
			stats = func(ctx context.Context, server Server) (float64, uint64, error) {
				return a.engine.Stats(ctx, server.ContainerID)
			}
		}
		cpu, memory, statsErr := stats(statsCtx, s)
		cancel()
		if statsErr == nil {
			cpuPercent = clampMetricCPU(cpu)
			memoryMB = float64(memory) / 1024 / 1024
		}
		playerCtx, playerCancel := context.WithTimeout(ctx, 4*time.Second)
		queryPlayers := a.metricsPlayers
		if queryPlayers == nil {
			queryPlayers = a.scheduledMetricPlayers
		}
		count, playerErr := queryPlayers(playerCtx, s)
		playerCancel()
		if playerErr == nil && count >= 0 {
			players = count
		}
	}
	_, err = a.db.Exec(`INSERT INTO server_metrics(server_id,sampled_at,cpu_percent,memory_mb,players) VALUES(?,?,?,?,?) ON CONFLICT(server_id,sampled_at) DO UPDATE SET cpu_percent=excluded.cpu_percent,memory_mb=excluded.memory_mb,players=excluded.players`, s.ID, now.Unix(), cpuPercent, memoryMB, players)
	if err != nil {
		return errors.New("could not save a server metric sample")
	}
	return nil
}

func (a *App) scheduledMetricPlayers(ctx context.Context, s Server) (int, error) {
	if s.Status != "running" {
		return 0, errors.New("server is not running")
	}
	gs, err := a.loadRune(s.GameskillID)
	if err != nil || gs.Query == nil {
		return 0, errors.New("server has no supported player query")
	}
	port, err := queryPort(s, gs)
	if err != nil {
		return 0, err
	}
	result, err := queryAtPort(ctx, gs, port)
	if err != nil {
		return 0, err
	}
	if result.Online < 0 {
		return 0, errors.New("player query returned an invalid count")
	}
	return result.Online, nil
}

func clampMetricCPU(cpu float64) float64 {
	if cpu < 0 {
		return 0
	}
	if cpu > 100 {
		return 100
	}
	return cpu
}

func (a *App) probeHostMetrics(now time.Time) hostMetricPoint {
	point := hostMetricPoint{SampledAt: now.Unix(), CPUPercent: -1, MemoryUsedMB: -1, MemoryTotalMB: -1, DiskUsedMB: -1, DiskTotalMB: -1}
	busy, total, err := readHostCPUCounters()
	if err == nil {
		a.metricsMu.Lock()
		if a.metricsCPUTotal > 0 && total > a.metricsCPUTotal && busy >= a.metricsCPUBusy {
			deltaTotal := total - a.metricsCPUTotal
			deltaBusy := busy - a.metricsCPUBusy
			if deltaTotal > 0 {
				point.CPUPercent = clampMetricCPU(float64(deltaBusy) * 100 / float64(deltaTotal))
			}
		}
		a.metricsCPUBusy, a.metricsCPUTotal = busy, total
		a.metricsMu.Unlock()
	}
	if used, capacity, memErr := readHostMemory(); memErr == nil {
		point.MemoryUsedMB, point.MemoryTotalMB = used, capacity
	}
	if usage, diskErr := probeDiskUsage(a.panelStoragePath()); diskErr == nil {
		point.DiskTotalMB = float64(usage.TotalBytes) / 1024 / 1024
		point.DiskUsedMB = float64(usage.TotalBytes-usage.AvailableBytes) / 1024 / 1024
	}
	return point
}

func readHostCPUCounters() (busy, total uint64, err error) {
	file, err := os.Open("/proc/stat")
	if err != nil {
		return 0, 0, err
	}
	defer file.Close()
	line, err := bufio.NewReader(file).ReadString('\n')
	if err != nil {
		return 0, 0, err
	}
	fields := strings.Fields(line)
	if len(fields) < 6 || fields[0] != "cpu" {
		return 0, 0, errors.New("host CPU counters are unavailable")
	}
	values := make([]uint64, 0, len(fields)-1)
	for _, field := range fields[1:min(len(fields), 9)] {
		value, parseErr := strconv.ParseUint(field, 10, 64)
		if parseErr != nil {
			return 0, 0, errors.New("host CPU counters are invalid")
		}
		values = append(values, value)
		total += value
	}
	idle := values[3]
	if len(values) > 4 {
		idle += values[4]
	}
	if idle > total {
		return 0, 0, errors.New("host CPU counters are invalid")
	}
	return total - idle, total, nil
}

func readHostMemory() (usedMB, totalMB float64, err error) {
	file, err := os.Open("/proc/meminfo")
	if err != nil {
		return -1, -1, err
	}
	defer file.Close()
	values := map[string]uint64{}
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 2 {
			continue
		}
		name := strings.TrimSuffix(fields[0], ":")
		if name != "MemTotal" && name != "MemAvailable" {
			continue
		}
		value, parseErr := strconv.ParseUint(fields[1], 10, 64)
		if parseErr != nil {
			return -1, -1, errors.New("host memory counters are invalid")
		}
		values[name] = value * 1024 // /proc/meminfo values are KiB.
	}
	if err = scanner.Err(); err != nil {
		return -1, -1, err
	}
	capacity, okTotal := values["MemTotal"]
	available, okAvailable := values["MemAvailable"]
	if !okTotal || !okAvailable || available > capacity {
		return -1, -1, errors.New("host memory counters are incomplete")
	}
	return float64(capacity-available) / 1024 / 1024, float64(capacity) / 1024 / 1024, nil
}

func metricsHours(r *http.Request) (int, error) {
	raw := strings.TrimSpace(r.URL.Query().Get("hours"))
	if raw == "" {
		return 24, nil
	}
	hours, err := strconv.Atoi(raw)
	if err != nil || hours < 1 || hours > 168 {
		return 0, errors.New("hours must be from 1 to 168")
	}
	return hours, nil
}

func (a *App) serverMetrics(w http.ResponseWriter, r *http.Request) {
	s, err := a.getServer(chi.URLParam(r, "id"))
	if err != nil {
		writeError(w, http.StatusNotFound, "server not found")
		return
	}
	if !a.allowedServer(principal(r), "server.view", s.ID, s.GameskillID, s.RealmID) {
		writeError(w, http.StatusForbidden, "server.view permission is required")
		return
	}
	hours, err := metricsHours(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	points := make([]serverMetricPoint, 0)
	cutoff := time.Now().Add(-time.Duration(hours) * time.Hour).Unix()
	rows, err := a.db.Query(`SELECT sampled_at,cpu_percent,memory_mb,players FROM server_metrics WHERE server_id=? AND sampled_at>=? ORDER BY sampled_at`, s.ID, cutoff)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not read server metrics")
		return
	}
	defer rows.Close()
	for rows.Next() {
		var point serverMetricPoint
		if err = rows.Scan(&point.SampledAt, &point.CPUPercent, &point.MemoryMB, &point.Players); err != nil {
			writeError(w, http.StatusInternalServerError, "could not read server metrics")
			return
		}
		points = append(points, point)
	}
	if err = rows.Err(); err != nil {
		writeError(w, http.StatusInternalServerError, "could not read server metrics")
		return
	}
	writeJSON(w, http.StatusOK, serverMetricSeries{ServerID: s.ID, Hours: hours, Points: points})
}

func (a *App) hostMetrics(w http.ResponseWriter, r *http.Request) {
	hours, err := metricsHours(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	points := make([]hostMetricPoint, 0)
	cutoff := time.Now().Add(-time.Duration(hours) * time.Hour).Unix()
	rows, err := a.db.Query(`SELECT sampled_at,cpu_percent,memory_used_mb,memory_total_mb,disk_used_mb,disk_total_mb FROM host_metrics WHERE sampled_at>=? ORDER BY sampled_at`, cutoff)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not read host metrics")
		return
	}
	defer rows.Close()
	for rows.Next() {
		var point hostMetricPoint
		if err = rows.Scan(&point.SampledAt, &point.CPUPercent, &point.MemoryUsedMB, &point.MemoryTotalMB, &point.DiskUsedMB, &point.DiskTotalMB); err != nil {
			writeError(w, http.StatusInternalServerError, "could not read host metrics")
			return
		}
		points = append(points, point)
	}
	if err = rows.Err(); err != nil {
		writeError(w, http.StatusInternalServerError, "could not read host metrics")
		return
	}
	writeJSON(w, http.StatusOK, hostMetricSeries{Hours: hours, Points: points})
}

func (a *App) fleetMetrics(w http.ResponseWriter, r *http.Request) {
	hours, err := metricsHours(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	items, err := a.fleetMetricSummaries(hours)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not read fleet metrics")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"hours": hours, "servers": items})
}

func (a *App) fleetMetricSummaries(hours int) ([]fleetMetricSummary, error) {
	cutoff := time.Now().Add(-time.Duration(hours) * time.Hour).Unix()
	rows, err := a.db.Query(`SELECT s.id,s.name,s.status,COUNT(m.sampled_at),AVG(CASE WHEN m.cpu_percent>=0 THEN m.cpu_percent END),MAX(CASE WHEN m.cpu_percent>=0 THEN m.cpu_percent END),AVG(CASE WHEN m.memory_mb>=0 THEN m.memory_mb END),MAX(CASE WHEN m.memory_mb>=0 THEN m.memory_mb END),AVG(CASE WHEN m.players>=0 THEN m.players END),MAX(CASE WHEN m.players>=0 THEN m.players END) FROM servers s LEFT JOIN server_metrics m ON m.server_id=s.id AND m.sampled_at>=? GROUP BY s.id,s.name,s.status ORDER BY s.name COLLATE NOCASE,s.id`, cutoff)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := make([]fleetMetricSummary, 0)
	for rows.Next() {
		var item fleetMetricSummary
		var avgCPU, peakCPU, avgMemory, peakMemory, avgPlayers, peakPlayers sql.NullFloat64
		if err = rows.Scan(&item.ID, &item.Name, &item.Status, &item.Samples, &avgCPU, &peakCPU, &avgMemory, &peakMemory, &avgPlayers, &peakPlayers); err != nil {
			return nil, err
		}
		item.AverageCPUPercent = nullableFloat(avgCPU)
		item.PeakCPUPercent = nullableFloat(peakCPU)
		item.AverageMemoryMB = nullableFloat(avgMemory)
		item.PeakMemoryMB = nullableFloat(peakMemory)
		item.AveragePlayers = nullableFloat(avgPlayers)
		item.PeakPlayers = nullableFloat(peakPlayers)
		items = append(items, item)
	}
	if err = rows.Err(); err != nil {
		return nil, err
	}
	return items, nil
}

func nullableFloat(value sql.NullFloat64) *float64 {
	if !value.Valid {
		return nil
	}
	return &value.Float64
}
