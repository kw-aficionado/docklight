package panel

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"

	"example.com/yggdrasil-panel/internal/rune"
	"github.com/go-chi/chi/v5"
)

const (
	maxServerHostMounts  = 32
	maxHostBrowseEntries = 500
)

// HostMount is an administrator-managed bind mount for the primary server
// container. It is deliberately omitted from ordinary server API responses.
type HostMount struct {
	Source  string `json:"source"`
	Target  string `json:"target"`
	Service string `json:"service,omitempty"`
	Write   bool   `json:"write"`
}

type hostMountsInput struct {
	Mounts []HostMount `json:"mounts"`
}

type hostMountDirectory struct {
	Name string `json:"name"`
	Path string `json:"path"`
}

var deniedHostMountRoots = []string{
	"/etc", "/usr", "/root", "/boot", "/proc", "/sys", "/dev", "/run",
	"/var/run", "/var/lib/docker", "/var/lib/yggdrasil",
}

var deniedContainerMountRoots = []string{
	"/bin", "/boot", "/dev", "/etc", "/lib", "/lib64", "/proc", "/root",
	"/run", "/sbin", "/sys", "/tmp", "/usr", "/var",
}

func (a *App) getServerHostMounts(w http.ResponseWriter, r *http.Request) {
	s, err := a.getServer(chi.URLParam(r, "id"))
	if err != nil {
		writeError(w, http.StatusNotFound, "server not found")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"mounts": s.HostMounts, "applies_on": "next_start"})
}

func (a *App) updateServerHostMounts(w http.ResponseWriter, r *http.Request) {
	var input hostMountsInput
	if decodeJSON(w, r, &input, 64<<10) != nil {
		return
	}
	a.dataMu.Lock()
	defer a.dataMu.Unlock()
	s, err := a.getServer(chi.URLParam(r, "id"))
	if err != nil {
		writeError(w, http.StatusNotFound, "server not found")
		return
	}
	gs, err := a.loadRune(s.GameskillID)
	if err != nil {
		writeError(w, http.StatusConflict, "server template is unavailable")
		return
	}
	mounts, err := a.validateHostMounts(gs, input.Mounts)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	encoded, err := json.Marshal(mounts)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not encode host mounts")
		return
	}
	result, err := a.db.Exec(`UPDATE servers SET host_mounts=?,updated_at=CURRENT_TIMESTAMP WHERE id=?`, string(encoded), s.ID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not save host mounts")
		return
	}
	if updated, rowsErr := result.RowsAffected(); rowsErr == nil && updated == 0 {
		writeError(w, http.StatusNotFound, "server not found")
		return
	}
	a.audit(principal(r), "server.host_mounts.update", "server", s.ID, fmt.Sprintf("count=%d", len(mounts)))
	writeJSON(w, http.StatusOK, map[string]any{"mounts": mounts, "applies_on": "next_start"})
}

func (a *App) listHostMountDirectories(w http.ResponseWriter, r *http.Request) {
	seen := map[string]struct{}{}
	directories := make([]hostMountDirectory, 0)
	add := func(candidate string) {
		resolved, err := a.canonicalHostMountSource(candidate)
		if err != nil {
			return
		}
		if _, ok := seen[resolved]; ok {
			return
		}
		seen[resolved] = struct{}{}
		directories = append(directories, hostMountDirectory{Name: filepath.Base(resolved), Path: resolved})
	}

	// mountinfo is useful when the panel can see host-mounted disks or network
	// shares. Conventional roots keep the picker useful on other Unix hosts.
	if file, err := os.Open("/proc/self/mountinfo"); err == nil {
		scanner := bufio.NewScanner(file)
		scanner.Buffer(make([]byte, 4096), 1<<20)
		for scanner.Scan() {
			fields := strings.Fields(scanner.Text())
			if len(fields) > 4 {
				add(unescapeMountInfo(fields[4]))
			}
		}
		_ = file.Close()
	}
	for _, candidate := range []string{"/mnt", "/media", "/srv", "/home", "/opt", "/workspace", "/Users"} {
		add(candidate)
	}
	sort.Slice(directories, func(i, j int) bool { return directories[i].Path < directories[j].Path })
	writeJSON(w, http.StatusOK, map[string]any{"mounts": directories})
}

func (a *App) browseHostMountDirectories(w http.ResponseWriter, r *http.Request) {
	requested := strings.TrimSpace(r.URL.Query().Get("path"))
	if requested == "" {
		requested = string(filepath.Separator)
	}
	current, err := a.resolveHostBrowsePath(requested)
	if err != nil {
		writeError(w, http.StatusBadRequest, "choose an existing host directory")
		return
	}
	directory, err := os.Open(current)
	if err != nil {
		writeError(w, http.StatusForbidden, "host directory cannot be browsed")
		return
	}
	entries, err := directory.ReadDir(maxHostBrowseEntries + 1)
	_ = directory.Close()
	if err != nil {
		writeError(w, http.StatusForbidden, "host directory cannot be browsed")
		return
	}
	truncated := len(entries) > maxHostBrowseEntries
	if truncated {
		entries = entries[:maxHostBrowseEntries]
	}
	directories := make([]hostMountDirectory, 0, len(entries))
	for _, entry := range entries {
		candidate := filepath.Join(current, entry.Name())
		resolved, err := a.resolveHostBrowsePath(candidate)
		if err != nil {
			continue
		}
		info, err := os.Stat(resolved)
		if err != nil || !info.IsDir() {
			continue
		}
		directories = append(directories, hostMountDirectory{Name: entry.Name(), Path: resolved})
	}
	sort.Slice(directories, func(i, j int) bool {
		return strings.ToLower(directories[i].Name) < strings.ToLower(directories[j].Name)
	})
	_, mountErr := a.canonicalHostMountSource(current)
	writeJSON(w, http.StatusOK, map[string]any{"path": current, "parent": filepath.Dir(current), "can_mount": mountErr == nil, "truncated": truncated, "entries": directories})
}

func (a *App) validateHostMounts(gs rune.Rune, mounts []HostMount) ([]HostMount, error) {
	if len(mounts) > maxServerHostMounts {
		return nil, fmt.Errorf("a server can have at most %d host mounts", maxServerHostMounts)
	}
	validated := make([]HostMount, 0, len(mounts))
	for _, mount := range mounts {
		source, err := a.canonicalHostMountSource(strings.TrimSpace(mount.Source))
		if err != nil {
			return nil, fmt.Errorf("host mount source must be an existing directory outside protected panel paths")
		}
		service := strings.TrimSpace(mount.Service)
		if service != "" && !stackHasService(gs.Stack, service) {
			return nil, fmt.Errorf("host mount names an unknown stack service")
		}
		target, err := validateHostMountTarget(strings.TrimSpace(mount.Target), gs, service)
		if err != nil {
			return nil, err
		}
		for _, existing := range validated {
			if existing.Service == service && containerPathsOverlap(existing.Target, target) {
				return nil, fmt.Errorf("host mount targets must not overlap")
			}
		}
		validated = append(validated, HostMount{Source: source, Target: target, Service: service, Write: mount.Write})
	}
	return validated, nil
}

func (a *App) canonicalHostMountSource(source string) (string, error) {
	if source == "" || len(source) > 4096 || !filepath.IsAbs(source) || strings.ContainsAny(source, ":\x00\r\n") {
		return "", fmt.Errorf("invalid host mount source")
	}
	resolved, err := filepath.EvalSymlinks(filepath.Clean(source))
	if err != nil {
		return "", err
	}
	resolved, err = filepath.Abs(resolved)
	if err != nil {
		return "", err
	}
	info, err := os.Stat(resolved)
	if err != nil || !info.IsDir() {
		return "", fmt.Errorf("host mount source must be a directory")
	}
	if resolved == string(filepath.Separator) {
		// The root cannot be a source, but can be used to start folder browsing.
		return "", fmt.Errorf("host mount source is protected")
	}
	for _, root := range deniedHostMountRoots {
		protected, _ := filepath.Abs(root)
		if canonical, resolveErr := filepath.EvalSymlinks(protected); resolveErr == nil {
			protected = canonical
		}
		if hostPathOverlaps(resolved, protected) {
			return "", fmt.Errorf("host mount source is protected")
		}
	}
	for _, root := range []string{a.dataRoot, a.backupRoot} {
		if root != "" && hostPathsOverlapResolved(resolved, root) {
			return "", fmt.Errorf("host mount source overlaps Docklight storage")
		}
	}
	return filepath.Clean(resolved), nil
}

func validateHostMountTarget(target string, gs rune.Rune, serviceName string) (string, error) {
	if target == "" || len(target) > 1024 || !path.IsAbs(target) || strings.ContainsAny(target, ":\\\x00\r\n") || path.Clean(target) != target {
		return "", fmt.Errorf("host mount target must be a clean absolute container path")
	}
	for _, protected := range deniedContainerMountRoots {
		if containerPathsOverlap(target, protected) {
			return "", fmt.Errorf("host mount target overlaps a protected system path")
		}
	}
	if containerPathsOverlap(target, "/data") {
		return "", fmt.Errorf("host mount target must not shadow /data")
	}
	var dataPath string
	var extraVolumes []string
	if serviceName == "" {
		dataPath, extraVolumes = gs.Docker.DataPath, gs.Docker.ExtraVolumes
	} else {
		for _, service := range gs.Stack.Services {
			if service.Name == serviceName {
				dataPath, extraVolumes = service.DataPath, service.ExtraVolumes
				break
			}
		}
	}
	if dataPath == "" && serviceName == "" {
		dataPath = "/data"
	}
	if dataPath != "" && containerPathsOverlap(target, dataPath) {
		return "", fmt.Errorf("host mount target must not replace or shadow the service data path")
	}
	for _, extra := range extraVolumes {
		if containerPathsOverlap(target, extra) {
			return "", fmt.Errorf("host mount target overlaps a template data volume")
		}
	}
	return target, nil
}

func stackHasService(stack *rune.Stack, name string) bool {
	if stack == nil || name == "" {
		return false
	}
	for _, service := range stack.Services {
		if service.Name == name {
			return true
		}
	}
	return false
}

func (a *App) resolveHostBrowsePath(value string) (string, error) {
	if value == "" || len(value) > 4096 || !filepath.IsAbs(value) || strings.ContainsAny(value, ":\x00\r\n") {
		return "", fmt.Errorf("invalid path")
	}
	resolved, err := filepath.EvalSymlinks(filepath.Clean(value))
	if err != nil {
		return "", err
	}
	info, err := os.Stat(resolved)
	if err != nil || !info.IsDir() {
		return "", fmt.Errorf("not a directory")
	}
	resolved, err = filepath.Abs(resolved)
	if err != nil {
		return "", err
	}
	for _, root := range deniedHostMountRoots {
		protected, _ := filepath.Abs(root)
		if canonical, resolveErr := filepath.EvalSymlinks(protected); resolveErr == nil {
			protected = canonical
		}
		if hostPathContains(protected, resolved) {
			return "", fmt.Errorf("protected path")
		}
	}
	for _, root := range []string{a.dataRoot, a.backupRoot} {
		if root == "" {
			continue
		}
		resolvedRoot, rootErr := resolvedPath(root)
		if rootErr != nil || hostPathContains(resolvedRoot, resolved) {
			// Parents such as /tmp may be browsed, but Docklight's own storage
			// directory and everything beneath it stay out of the picker.
			return "", fmt.Errorf("protected path")
		}
	}
	return filepath.Clean(resolved), nil
}

func hostPathOverlaps(first, second string) bool {
	first = filepath.Clean(first)
	second = filepath.Clean(second)
	return hostPathContains(first, second) || hostPathContains(second, first)
}

func hostPathContains(root, target string) bool {
	rel, err := filepath.Rel(root, target)
	return err == nil && (rel == "." || rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) && !filepath.IsAbs(rel))
}

func hostPathsOverlapResolved(first, second string) bool {
	resolved, err := resolvedPath(second)
	if err != nil {
		return true
	}
	return hostPathOverlaps(first, resolved)
}

func containerPathsOverlap(first, second string) bool {
	first, second = path.Clean(first), path.Clean(second)
	return containerPathContains(first, second) || containerPathContains(second, first)
}

func containerPathContains(root, target string) bool {
	if root == target {
		return true
	}
	if root == "/" {
		return path.IsAbs(target)
	}
	return strings.HasPrefix(target, strings.TrimSuffix(root, "/")+"/")
}

func unescapeMountInfo(value string) string {
	replacer := strings.NewReplacer(`\040`, " ", `\011`, "\t", `\012`, "\n", `\134`, `\`)
	return replacer.Replace(value)
}
