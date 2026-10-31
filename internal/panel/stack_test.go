package panel

import (
	"bufio"
	"bytes"
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"example.com/yggdrasil-panel/internal/backup"
	"example.com/yggdrasil-panel/internal/docker"
	"example.com/yggdrasil-panel/internal/rune"
	"example.com/yggdrasil-panel/internal/security"
	"github.com/go-chi/chi/v5"
)

type fakeStackContainer struct {
	name        string
	state       string
	config      docker.CreateConfig
	healthcheck bool
	healthState string
}

type stackRoundTripFunc func(*http.Request) (*http.Response, error)

func (fn stackRoundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) { return fn(req) }

type pipeHijackResponseWriter struct {
	clientReady chan net.Conn
}

func (w *pipeHijackResponseWriter) Header() http.Header            { return make(http.Header) }
func (w *pipeHijackResponseWriter) WriteHeader(int)                {}
func (w *pipeHijackResponseWriter) Write(data []byte) (int, error) { return len(data), nil }
func (w *pipeHijackResponseWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	server, client := net.Pipe()
	w.clientReady <- client
	return server, bufio.NewReadWriter(bufio.NewReader(server), bufio.NewWriter(server)), nil
}

func readWebSocketFrame(reader *bufio.Reader) (byte, string, error) {
	header := make([]byte, 2)
	if _, err := io.ReadFull(reader, header); err != nil {
		return 0, "", err
	}
	length := uint64(header[1] & 0x7f)
	if length == 126 {
		var extended [2]byte
		if _, err := io.ReadFull(reader, extended[:]); err != nil {
			return 0, "", err
		}
		length = uint64(binary.BigEndian.Uint16(extended[:]))
	} else if length == 127 {
		var extended [8]byte
		if _, err := io.ReadFull(reader, extended[:]); err != nil {
			return 0, "", err
		}
		length = binary.BigEndian.Uint64(extended[:])
	}
	if length > 1<<20 {
		return 0, "", fmt.Errorf("frame payload exceeded test limit: %d", length)
	}
	payload := make([]byte, length)
	if _, err := io.ReadFull(reader, payload); err != nil {
		return 0, "", err
	}
	return header[0] & 0x0f, string(payload), nil
}

type fakeStackDocker struct {
	mu             sync.Mutex
	networkName    string
	networkID      string
	serverID       string
	failStart      string
	containers     map[string]fakeStackContainer
	byName         map[string]string
	configs        map[string]docker.CreateConfig
	operations     []string
	nextID         int
	logsOutput     string
	healthInspects int
	execCommand    []string
	execOutput     string
	execExitCode   int
	execCount      int
}

func newFakeStackDocker(serverID, failStart string) *fakeStackDocker {
	return &fakeStackDocker{serverID: serverID, failStart: failStart, containers: map[string]fakeStackContainer{}, byName: map[string]string{}, configs: map[string]docker.CreateConfig{}}
}

func (f *fakeStackDocker) roundTrip(req *http.Request) (*http.Response, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	path := req.URL.Path
	query := req.URL.Query()
	var body []byte
	if req.Body != nil {
		body, _ = io.ReadAll(req.Body)
	}
	respond := func(status int, text string) (*http.Response, error) {
		return &http.Response{StatusCode: status, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(text)), Request: req}, nil
	}
	if req.Method == http.MethodPost && path == "/v1.45/images/create" {
		f.operations = append(f.operations, "pull:"+query.Get("fromImage"))
		return respond(http.StatusOK, "")
	}
	if req.Method == http.MethodPost && path == "/v1.45/networks/create" {
		var config docker.NetworkCreateConfig
		if err := json.Unmarshal(body, &config); err != nil {
			return respond(http.StatusBadRequest, `{"message":"bad network config"}`)
		}
		f.networkName = query.Get("name")
		f.networkID = "network-stack"
		f.operations = append(f.operations, "network:create")
		return respond(http.StatusCreated, `{"Id":"network-stack"}`)
	}
	if req.Method == http.MethodGet && strings.HasPrefix(path, "/v1.45/networks/") {
		if f.networkID == "" || strings.TrimPrefix(path, "/v1.45/networks/") != f.networkID && strings.TrimPrefix(path, "/v1.45/networks/") != f.networkName {
			return respond(http.StatusNotFound, `{"message":"No such network"}`)
		}
		labels := map[string]string{docklightServerLabel: f.serverID, "docklight.managed": "true"}
		result, _ := json.Marshal(map[string]any{"Id": f.networkID, "Name": f.networkName, "Labels": labels})
		return respond(http.StatusOK, string(result))
	}
	if req.Method == http.MethodGet && path == "/v1.45/containers/json" {
		var output []map[string]any
		for id, container := range f.containers {
			labels := container.config.Labels
			if labels[docklightServerLabel] != queryLabel(query.Get("filters"), docklightServerLabel) || labels[docklightRoleLabel] != "sidecar" {
				continue
			}
			output = append(output, map[string]any{"Id": id, "State": container.state, "Names": []string{"/" + container.name}, "Labels": labels})
		}
		result, _ := json.Marshal(output)
		return respond(http.StatusOK, string(result))
	}
	if req.Method == http.MethodPost && path == "/v1.45/containers/create" {
		var config docker.CreateConfig
		if err := json.Unmarshal(body, &config); err != nil {
			return respond(http.StatusBadRequest, `{"message":"bad container config"}`)
		}
		f.nextID++
		id, name := fmt.Sprintf("container-%d", f.nextID), query.Get("name")
		container := fakeStackContainer{name: name, state: "created", config: config}
		if strings.HasPrefix(config.Image, "healthcheck:") {
			container.healthcheck = true
			container.healthState = strings.TrimPrefix(config.Image, "healthcheck:")
		}
		f.containers[id] = container
		f.byName[name], f.configs[name] = id, config
		f.operations = append(f.operations, "container:create:"+name)
		return respond(http.StatusCreated, `{"Id":"`+id+`"}`)
	}
	if req.Method == http.MethodPost && strings.HasPrefix(path, "/v1.45/containers/") {
		parts := strings.Split(strings.TrimPrefix(path, "/v1.45/containers/"), "/")
		if len(parts) == 2 && parts[1] == "exec" {
			container, ok := f.containers[parts[0]]
			if !ok {
				return respond(http.StatusNotFound, `{"message":"No such container"}`)
			}
			if container.state != "running" {
				return respond(http.StatusConflict, `{"message":"Container is not running"}`)
			}
			var config struct {
				Cmd []string `json:"Cmd"`
			}
			if err := json.Unmarshal(body, &config); err != nil || len(config.Cmd) == 0 {
				return respond(http.StatusBadRequest, `{"message":"bad exec config"}`)
			}
			f.execCommand = append([]string(nil), config.Cmd...)
			f.execCount++
			f.operations = append(f.operations, "exec:create:"+container.name)
			return respond(http.StatusCreated, `{"Id":"exec-1"}`)
		}
		if len(parts) == 2 && parts[1] == "start" {
			container, ok := f.containers[parts[0]]
			if !ok {
				return respond(http.StatusNotFound, `{"message":"No such container"}`)
			}
			if container.name == f.failStart {
				return respond(http.StatusInternalServerError, `{"message":"planned start failure"}`)
			}
			container.state = "running"
			f.containers[parts[0]] = container
			f.operations = append(f.operations, "container:start:"+container.name)
			return respond(http.StatusNoContent, "")
		}
		if len(parts) == 2 && parts[1] == "stop" {
			container, ok := f.containers[parts[0]]
			if !ok {
				return respond(http.StatusNotFound, `{"message":"No such container"}`)
			}
			container.state = "exited"
			f.containers[parts[0]] = container
			f.operations = append(f.operations, "container:stop:"+container.name)
			return respond(http.StatusNoContent, "")
		}
	}
	if req.Method == http.MethodPost && path == "/v1.45/exec/exec-1/start" {
		frame := make([]byte, 8+len(f.execOutput))
		frame[0] = 1
		binary.BigEndian.PutUint32(frame[4:8], uint32(len(f.execOutput)))
		copy(frame[8:], f.execOutput)
		f.operations = append(f.operations, "exec:start")
		return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: io.NopCloser(bytes.NewReader(frame)), Request: req}, nil
	}
	if req.Method == http.MethodGet && path == "/v1.45/exec/exec-1/json" {
		f.operations = append(f.operations, "exec:inspect")
		return respond(http.StatusOK, fmt.Sprintf(`{"Running":false,"ExitCode":%d}`, f.execExitCode))
	}
	if req.Method == http.MethodGet && strings.HasPrefix(path, "/v1.45/containers/") && strings.HasSuffix(path, "/json") {
		id := strings.TrimSuffix(strings.TrimPrefix(path, "/v1.45/containers/"), "/json")
		container, ok := f.containers[id]
		if !ok {
			return respond(http.StatusNotFound, `{"message":"No such container"}`)
		}
		configView := map[string]any{"Image": container.config.Image, "Labels": container.config.Labels}
		stateView := map[string]any{"Status": container.state, "Running": container.state == "running", "ExitCode": 0}
		if container.healthcheck {
			configView["Healthcheck"] = map[string]any{"Test": []string{"CMD", "health-check"}}
			stateView["Health"] = map[string]string{"Status": container.healthState}
			f.healthInspects++
		}
		result, _ := json.Marshal(map[string]any{"Id": id, "Name": "/" + container.name, "Config": configView, "State": stateView})
		return respond(http.StatusOK, string(result))
	}
	if req.Method == http.MethodGet && strings.HasPrefix(path, "/v1.45/containers/") && strings.HasSuffix(path, "/logs") {
		id := strings.TrimSuffix(strings.TrimPrefix(path, "/v1.45/containers/"), "/logs")
		if _, ok := f.containers[id]; !ok {
			return respond(http.StatusNotFound, `{"message":"No such container"}`)
		}
		payload := []byte(f.logsOutput)
		frame := make([]byte, 8+len(payload))
		frame[0] = 1
		binary.BigEndian.PutUint32(frame[4:8], uint32(len(payload)))
		copy(frame[8:], payload)
		return respond(http.StatusOK, string(frame))
	}
	if req.Method == http.MethodDelete && strings.HasPrefix(path, "/v1.45/containers/") {
		id := strings.TrimSuffix(strings.TrimPrefix(path, "/v1.45/containers/"), "")
		container, ok := f.containers[id]
		if !ok {
			return respond(http.StatusNotFound, `{"message":"No such container"}`)
		}
		delete(f.containers, id)
		delete(f.byName, container.name)
		f.operations = append(f.operations, "container:remove:"+container.name)
		return respond(http.StatusNoContent, "")
	}
	if req.Method == http.MethodDelete && strings.HasPrefix(path, "/v1.45/networks/") {
		f.operations = append(f.operations, "network:remove")
		f.networkName, f.networkID = "", ""
		return respond(http.StatusNoContent, "")
	}
	return respond(http.StatusInternalServerError, `{"message":"unexpected fake Docker request: `+req.Method+" "+path+`"}`)
}

func queryLabel(filters, key string) string {
	var values map[string][]string
	if json.Unmarshal([]byte(filters), &values) != nil {
		return ""
	}
	for _, item := range values["label"] {
		name, value, ok := strings.Cut(item, "=")
		if ok && name == key {
			return value
		}
	}
	return ""
}

func insertWordPressStackServer(t *testing.T, a *App, d *sql.DB, configPath string) Server {
	t.Helper()
	var raw string
	if err := d.QueryRow(`SELECT yaml_blob FROM gameskills WHERE id='wordpress-mariadb'`).Scan(&raw); err != nil {
		t.Fatal(err)
	}
	raw = strings.Replace(raw, "    done_regex: \"resuming normal operations\"\n", "", 1)
	raw = strings.Replace(raw, "  ports:\n    - name: web\n      default: 80\n      protocol: tcp\n", "", 1)
	if _, err := d.Exec(`UPDATE gameskills SET yaml_blob=? WHERE id='wordpress-mariadb'`, raw); err != nil {
		t.Fatal(err)
	}
	dataDir := filepath.Join(filepath.Dir(configPath), "servers", "stack-server")
	if err := os.MkdirAll(dataDir, 0700); err != nil {
		t.Fatal(err)
	}
	password, err := security.Encrypt([]byte(a.cfg.Auth.SecretKey), "unique-db-password-234567890")
	if err != nil {
		t.Fatal(err)
	}
	rootPassword, err := security.Encrypt([]byte(a.cfg.Auth.SecretKey), "unique-root-password-987654321")
	if err != nil {
		t.Fatal(err)
	}
	env, _ := json.Marshal(map[string]string{"DB_PASSWORD": password, "DB_ROOT_PASSWORD": rootPassword})
	if _, err = d.Exec(`INSERT INTO servers(id,name,gameskill_id,status,installed,env_json,ports_json,data_dir,container_id,cpu_limit,memory_limit_mb)
		VALUES('stack-server','Private stack','wordpress-mariadb','stopped',1,?, '{"web":31080}',?,'',4,800)`, string(env), dataDir); err != nil {
		t.Fatal(err)
	}
	return Server{ID: "stack-server", Name: "Private stack", GameskillID: "wordpress-mariadb", Status: "stopped", Installed: true, Env: map[string]string{"DB_PASSWORD": password, "DB_ROOT_PASSWORD": rootPassword}, Ports: map[string]int{"web": 31080}, DataDir: dataDir, CPULimit: 4, MemoryLimitMB: 800}
}

func TestWordPressStackStartsStopsAndKeepsSidecarInPrivateNetwork(t *testing.T) {
	a, d, config := testApp(t)
	fake := newFakeStackDocker("stack-server", "")
	a.engine = docker.NewWithHTTPClient("fake-docker", "1.45", &http.Client{Transport: stackRoundTripFunc(fake.roundTrip)})
	var rawRune string
	if err := d.QueryRow(`SELECT yaml_blob FROM gameskills WHERE id='wordpress-mariadb'`).Scan(&rawRune); err != nil {
		t.Fatal(err)
	}
	needle := "        data_path: /var/lib/mysql\n"
	if !strings.Contains(rawRune, needle) {
		t.Fatal("built-in MariaDB data path fixture was not found")
	}
	rawRune = strings.Replace(rawRune, needle, needle+"        extra_volumes:\n          - /var/lib/mysql-files\n", 1)
	if _, err := d.Exec(`UPDATE gameskills SET yaml_blob=? WHERE id='wordpress-mariadb'`, rawRune); err != nil {
		t.Fatal(err)
	}
	originalRune, err := a.loadRune("wordpress-mariadb")
	if err != nil {
		t.Fatal(err)
	}
	mainEnv := map[string]string{"DB_NAME": "wordpress", "DB_USER": "wordpress", "DB_PASSWORD": "unique-db-password-234567890", "DB_ROOT_PASSWORD": "unique-root-password-987654321", "PUBLIC_URL": "http://127.0.0.1:31080", "HOME": "/data", "SERVER_NAME": "Private stack"}
	mainPreview, err := a.containerConfigWithStack(Server{ID: "stack-server", Name: "Private stack", DataDir: t.TempDir(), Ports: map[string]int{"web": 31080}}, originalRune, mainEnv, "preview-network", stackResourceLimit{})
	if err != nil {
		t.Fatal(err)
	}
	if len(mainPreview.HostConfig.PortBindings["80/tcp"]) != 1 || mainPreview.HostConfig.PortBindings["80/tcp"][0].HostPort != "31080" || strings.Contains(strings.Join(mainPreview.Env, "\n"), "unique-root-password-987654321") {
		t.Fatalf("main application port or secret isolation is wrong: ports=%#v env=%#v", mainPreview.HostConfig.PortBindings, mainPreview.Env)
	}
	s := insertWordPressStackServer(t, a, d, config.Database.Path)
	privateData := filepath.Join(s.DataDir, "_stack", "database")
	if err := os.MkdirAll(privateData, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(privateData, "credentials.dat"), []byte("database-private"), 0600); err != nil {
		t.Fatal(err)
	}
	filesRoot, err := a.serverFilesRoot(s)
	if err != nil || filesRoot != filepath.Join(s.DataDir, "_app") {
		t.Fatalf("app file root did not isolate stack data: root=%q err=%v", filesRoot, err)
	}
	if _, err := safePath(filesRoot, "../_stack/database/credentials.dat", true); err == nil {
		t.Fatal("server file root can traverse into sidecar data")
	}
	if err := a.startWithContext(s, context.Background()); err != nil {
		t.Fatalf("start app stack: %v", err)
	}
	deadline := time.Now().Add(4 * time.Second)
	for time.Now().Before(deadline) {
		current, err := a.getServer(s.ID)
		if err == nil && current.Status == "running" {
			s = current
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if s.Status != "running" {
		current, _ := a.getServer(s.ID)
		t.Fatalf("main app did not reach running state: %s %s", current.Status, current.ErrorMessage)
	}
	var serviceID, serviceStatus string
	if err := d.QueryRow(`SELECT container_id,status FROM server_sidecars WHERE server_id='stack-server' AND service_name='database'`).Scan(&serviceID, &serviceStatus); err != nil || serviceID == "" || serviceStatus != "running" {
		t.Fatalf("database sidecar state was not persisted: id=%q status=%q err=%v", serviceID, serviceStatus, err)
	}
	mainName := docker.SafeContainerName(s.ID)
	fake.mu.Lock()
	mainConfig, mainOK := fake.configs[mainName]
	sidecarConfig, sidecarOK := fake.configs[stackContainerName(s.ID, "database")]
	operations := append([]string(nil), fake.operations...)
	networkName := fake.networkName
	fake.mu.Unlock()
	if !mainOK || !sidecarOK {
		t.Fatal("main app and MariaDB containers were not both created")
	}
	if len(mainConfig.HostConfig.Binds) == 0 || mainConfig.HostConfig.Binds[0] != filepath.Join(s.DataDir, "_app")+":/var/www/html" {
		t.Fatalf("main application can see the server-wide backup root: %#v", mainConfig.HostConfig.Binds)
	}
	if strings.Contains(strings.Join(operations, "|"), "container:start:"+mainName) && strings.Index(strings.Join(operations, "|"), "container:start:"+stackContainerName(s.ID, "database")) > strings.Index(strings.Join(operations, "|"), "container:start:"+mainName) {
		t.Fatalf("main app started before its sidecar: %v", operations)
	}
	mainAttached := false
	if mainConfig.NetworkingConfig != nil {
		_, mainAttached = mainConfig.NetworkingConfig.EndpointsConfig[networkName]
	}
	if !mainAttached {
		t.Fatal("main application was not attached to its dedicated network")
	}
	endpoint, ok := sidecarConfig.NetworkingConfig.EndpointsConfig[networkName]
	if !ok || len(endpoint.Aliases) != 1 || endpoint.Aliases[0] != "database" {
		t.Fatalf("MariaDB did not receive its private DNS alias: %#v", sidecarConfig.NetworkingConfig)
	}
	if len(sidecarConfig.HostConfig.PortBindings) != 0 {
		t.Fatalf("sidecar unexpectedly published host ports: %#v", sidecarConfig.HostConfig.PortBindings)
	}
	if len(sidecarConfig.HostConfig.Binds) != 2 || !strings.Contains(sidecarConfig.HostConfig.Binds[0], filepath.Join("_stack", "database")+":/var/lib/mysql") || !strings.Contains(sidecarConfig.HostConfig.Binds[1], filepath.Join("_stack", "database", "_extra", "var", "lib", "mysql-files")+":/var/lib/mysql-files") {
		t.Fatalf("MariaDB data is not mounted under the server backup root: %#v", sidecarConfig.HostConfig.Binds)
	}
	if !strings.Contains(strings.Join(sidecarConfig.Env, "\n"), "MARIADB_PASSWORD=unique-db-password-234567890") || !strings.Contains(strings.Join(sidecarConfig.Env, "\n"), "MARIADB_ROOT_PASSWORD=unique-root-password-987654321") {
		t.Fatalf("sidecar env did not interpolate its database credentials: %#v", sidecarConfig.Env)
	}
	if strings.Contains(strings.Join(mainConfig.Env, "\n"), "unique-root-password-987654321") {
		t.Fatal("database root credential leaked to the main application container")
	}
	if mainConfig.HostConfig.NanoCPUs+sidecarConfig.HostConfig.NanoCPUs != 4_000_000_000 || mainConfig.HostConfig.Memory+sidecarConfig.HostConfig.Memory != 800*1024*1024 {
		t.Fatalf("stack resource limits were multiplied instead of shared: main=%+v sidecar=%+v", mainConfig.HostConfig, sidecarConfig.HostConfig)
	}
	if len(operations) < 2 || !strings.HasPrefix(operations[0], "pull:wordpress:") || !strings.Contains(strings.Join(operations, "|"), "container:start:"+stackContainerName(s.ID, "database")) {
		t.Fatalf("unexpected stack startup order: %v", operations)
	}
	fake.mu.Lock()
	container := fake.containers[serviceID]
	container.state = "exited"
	fake.containers[serviceID] = container
	fake.mu.Unlock()
	if err := a.monitorStackSidecars(context.Background(), s); err != nil {
		t.Fatalf("monitor exited sidecar: %v", err)
	}
	decorated := a.decorateServer(User{Role: "admin"}, s)
	if len(decorated.StackServices) != 1 || decorated.StackServices[0].Status != "error" || decorated.StackServices[0].ErrorMessage != "Container exited with code 0." {
		t.Fatalf("confirmed sidecar exit was not exposed to the server overview: %#v", decorated.StackServices)
	}
	fake.mu.Lock()
	container = fake.containers[serviceID]
	container.state = "running"
	fake.containers[serviceID] = container
	fake.mu.Unlock()
	if err := a.monitorStackSidecars(context.Background(), s); err != nil {
		t.Fatalf("monitor recovered sidecar: %v", err)
	}
	decorated = a.decorateServer(User{Role: "admin"}, s)
	if decorated.StackServices[0].Status != "running" || decorated.StackServices[0].ErrorMessage != "" {
		t.Fatalf("recovered sidecar status was not cleared: %#v", decorated.StackServices[0])
	}
	if err := a.stop(s); err != nil {
		t.Fatalf("stop app stack: %v", err)
	}
	if err := d.QueryRow(`SELECT status FROM server_sidecars WHERE server_id='stack-server' AND service_name='database'`).Scan(&serviceStatus); err != nil || serviceStatus != "stopped" {
		t.Fatalf("stop did not persist sidecar state: status=%q err=%v", serviceStatus, err)
	}
	if err := a.engine.Remove(context.Background(), s.ContainerID); err != nil {
		t.Fatalf("remove stopped main container for server cleanup: %v", err)
	}
	if err := a.removeStackResources(context.Background(), s, nil); err != nil {
		t.Fatalf("remove app stack resources: %v", err)
	}
	var remainingSidecars int
	if err := d.QueryRow(`SELECT count(*) FROM server_sidecars WHERE server_id='stack-server'`).Scan(&remainingSidecars); err != nil || remainingSidecars != 0 {
		t.Fatalf("stack deletion left sidecar metadata: count=%d err=%v", remainingSidecars, err)
	}
	fake.mu.Lock()
	remainingContainers, remainingNetwork := len(fake.containers), fake.networkID
	fake.mu.Unlock()
	if remainingContainers != 0 || remainingNetwork != "" {
		t.Fatalf("stack deletion left Docker resources: containers=%d network=%q", remainingContainers, remainingNetwork)
	}
}

func TestWordPressStackRollsBackSidecarsWhenMainAppFails(t *testing.T) {
	a, d, config := testApp(t)
	mainName := docker.SafeContainerName("stack-server")
	fake := newFakeStackDocker("stack-server", mainName)
	a.engine = docker.NewWithHTTPClient("fake-docker", "1.45", &http.Client{Transport: stackRoundTripFunc(fake.roundTrip)})
	s := insertWordPressStackServer(t, a, d, config.Database.Path)
	if err := a.startWithContext(s, context.Background()); err == nil || !strings.Contains(err.Error(), "planned start failure") {
		t.Fatalf("expected planned main app failure, got %v", err)
	}
	var sidecars, liveContainers int
	if err := d.QueryRow(`SELECT count(*) FROM server_sidecars WHERE server_id='stack-server'`).Scan(&sidecars); err != nil {
		t.Fatal(err)
	}
	fake.mu.Lock()
	liveContainers = len(fake.containers)
	fake.mu.Unlock()
	if sidecars != 0 || liveContainers != 0 {
		t.Fatalf("failed startup left sidecars or containers behind: db rows=%d live containers=%d", sidecars, liveContainers)
	}
}

func TestAppStackSupportsStatelessAndDisabledServices(t *testing.T) {
	a, d, config := testApp(t)
	fake := newFakeStackDocker("stack-server", "")
	a.engine = docker.NewWithHTTPClient("fake-docker", "1.45", &http.Client{Transport: stackRoundTripFunc(fake.roundTrip)})
	s := insertWordPressStackServer(t, a, d, config.Database.Path)
	gs, err := a.loadRune("wordpress-mariadb")
	if err != nil {
		t.Fatal(err)
	}
	gs.Stack.Services = []rune.Service{
		{Name: "optional-worker", Image: "busybox:1.36", Enabled: "{{NEW_SERVICE}}", DataPath: "/var/lib/worker"},
		{Name: "stateless", Image: "busybox:1.36", Command: []string{"sleep", "3600"}},
	}
	limits := stackResourceLimits(s, gs)
	if err = a.createStackSidecars(context.Background(), s, gs, map[string]string{}, "private-network", limits); err != nil {
		t.Fatalf("create stack sidecars: %v", err)
	}
	fake.mu.Lock()
	configs := make(map[string]docker.CreateConfig, len(fake.configs))
	for name, cfg := range fake.configs {
		configs[name] = cfg
	}
	fake.mu.Unlock()
	if len(configs) != 1 {
		t.Fatalf("unresolved optional service should stay disabled; created %d containers", len(configs))
	}
	stateless, ok := configs[stackContainerName(s.ID, "stateless")]
	if !ok || len(stateless.HostConfig.Binds) != 0 {
		t.Fatalf("stateless sidecar should not receive a persistent bind: found=%t config=%+v", ok, stateless.HostConfig)
	}
	var serviceCount int
	if err = d.QueryRow(`SELECT count(*) FROM server_sidecars WHERE server_id=?`, s.ID).Scan(&serviceCount); err != nil || serviceCount != 1 {
		t.Fatalf("disabled service was recorded as created: count=%d err=%v", serviceCount, err)
	}
	if _, err = os.Stat(filepath.Join(s.DataDir, "_stack", "stateless")); !os.IsNotExist(err) {
		t.Fatalf("stateless service unexpectedly created a data directory: err=%v", err)
	}
}

func TestStackExtraVolumeRejectsSymlinkEscape(t *testing.T) {
	a, _, _ := testApp(t)
	fake := newFakeStackDocker("symlink-stack", "")
	a.engine = docker.NewWithHTTPClient("fake-docker", "1.45", &http.Client{Transport: stackRoundTripFunc(fake.roundTrip)})
	dataRoot := t.TempDir()
	serviceRoot := filepath.Join(dataRoot, "_stack", "database")
	if err := os.MkdirAll(serviceRoot, 0700); err != nil {
		t.Fatal(err)
	}
	outside := t.TempDir()
	if err := os.Symlink(outside, filepath.Join(serviceRoot, "_extra")); err != nil {
		t.Fatal(err)
	}
	s := Server{ID: "symlink-stack", Name: "Database stack", DataDir: dataRoot}
	gs := rune.Rune{
		ID: "symlink-stack", Name: "Database stack", Docker: rune.Docker{Image: "example/app:1", KeepEntrypoint: true},
		Stack: &rune.Stack{Services: []rune.Service{{Name: "database", Image: "mariadb:11", DataPath: "/var/lib/mysql", ExtraVolumes: []string{"/var/lib/mysql-files"}}}},
	}
	err := a.createStackSidecars(context.Background(), s, gs, map[string]string{}, "private-network", stackResourceLimits(s, gs))
	if err == nil || !strings.Contains(err.Error(), "unsafe") {
		t.Fatalf("sidecar extra-volume symlink escape was not rejected: %v", err)
	}
	entries, err := os.ReadDir(outside)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("extra volume created files outside the sidecar directory: %v", entries)
	}
}

func TestAppStackWaitsForDeclaredDockerHealthChecks(t *testing.T) {
	a, d, config := testApp(t)
	fake := newFakeStackDocker("stack-server", "")
	a.engine = docker.NewWithHTTPClient("fake-docker", "1.45", &http.Client{Transport: stackRoundTripFunc(fake.roundTrip)})
	s := insertWordPressStackServer(t, a, d, config.Database.Path)
	gs, err := a.loadRune(s.GameskillID)
	if err != nil {
		t.Fatal(err)
	}
	gs.Stack.Services = []rune.Service{
		{Name: "ready", Image: "healthcheck:healthy"},
		{Name: "worker", Image: "busybox:1.36"},
	}
	if _, err = a.engine.CreateNetwork(context.Background(), "health-check-network", docker.NetworkCreateConfig{Driver: "bridge"}); err != nil {
		t.Fatal(err)
	}
	if err = a.createStackSidecars(context.Background(), s, gs, map[string]string{}, "health-check-network", stackResourceLimits(s, gs)); err != nil {
		t.Fatalf("healthy service should allow the stack to continue: %v", err)
	}
	fake.mu.Lock()
	initialHealthInspects := fake.healthInspects
	containerID := fake.byName[stackContainerName(s.ID, "ready")]
	container := fake.containers[containerID]
	container.healthState = "starting"
	fake.containers[containerID] = container
	fake.mu.Unlock()
	go func() {
		time.Sleep(20 * time.Millisecond)
		fake.mu.Lock()
		container := fake.containers[containerID]
		container.healthState = "healthy"
		fake.containers[containerID] = container
		fake.mu.Unlock()
	}()
	if err = a.waitStackSidecarHealth(context.Background(), s, gs, time.Second, time.Millisecond); err != nil {
		t.Fatalf("starting health check did not wait for recovery: %v", err)
	}
	fake.mu.Lock()
	healthInspects := fake.healthInspects
	container = fake.containers[containerID]
	container.healthState = "unhealthy"
	fake.containers[containerID] = container
	fake.mu.Unlock()
	if initialHealthInspects != 1 || healthInspects < initialHealthInspects+2 {
		t.Fatalf("health-check polling did not skip unmonitored workers or wait while starting: initial=%d after=%d", initialHealthInspects, healthInspects)
	}
	if err = a.waitStackSidecarHealth(context.Background(), s, gs, time.Second, time.Millisecond); err == nil || !strings.Contains(err.Error(), "failed its Docker health check") {
		t.Fatalf("unhealthy sidecar did not stop stack startup: %v", err)
	}
	fake.mu.Lock()
	container = fake.containers[containerID]
	container.healthState = "starting"
	fake.containers[containerID] = container
	fake.mu.Unlock()
	if err = a.waitStackSidecarHealth(context.Background(), s, gs, 10*time.Millisecond, time.Millisecond); err == nil || !strings.Contains(err.Error(), "did not become healthy") {
		t.Fatalf("stalled sidecar health check did not respect the bounded wait: %v", err)
	}
}

func TestUnhealthyStackSidecarRollsBackBeforeMainAppStart(t *testing.T) {
	a, d, config := testApp(t)
	fake := newFakeStackDocker("stack-server", "")
	a.engine = docker.NewWithHTTPClient("fake-docker", "1.45", &http.Client{Transport: stackRoundTripFunc(fake.roundTrip)})
	s := insertWordPressStackServer(t, a, d, config.Database.Path)
	var raw string
	if err := d.QueryRow(`SELECT yaml_blob FROM gameskills WHERE id='wordpress-mariadb'`).Scan(&raw); err != nil {
		t.Fatal(err)
	}
	raw = strings.Replace(raw, "image: mariadb:11", "image: healthcheck:unhealthy", 1)
	if _, err := d.Exec(`UPDATE gameskills SET yaml_blob=? WHERE id='wordpress-mariadb'`, raw); err != nil {
		t.Fatal(err)
	}
	err := a.startWithContext(s, context.Background())
	if err == nil || !strings.Contains(err.Error(), "failed its Docker health check") {
		t.Fatalf("unhealthy sidecar should block stack startup, got %v", err)
	}
	var sidecarRows int
	if err = d.QueryRow(`SELECT count(*) FROM server_sidecars WHERE server_id=?`, s.ID).Scan(&sidecarRows); err != nil {
		t.Fatal(err)
	}
	fake.mu.Lock()
	containerCount := len(fake.containers)
	mainCreated := fake.byName[docker.SafeContainerName(s.ID)] != ""
	fake.mu.Unlock()
	if sidecarRows != 0 || containerCount != 0 || mainCreated {
		t.Fatalf("health failure did not roll back before main app start: rows=%d containers=%d main=%t", sidecarRows, containerCount, mainCreated)
	}
}

func TestStackServiceLogTargetChecksOwnershipAndRedactsSecrets(t *testing.T) {
	a, d, config := testApp(t)
	fake := newFakeStackDocker("stack-server", "")
	a.engine = docker.NewWithHTTPClient("fake-docker", "1.45", &http.Client{Transport: stackRoundTripFunc(fake.roundTrip)})
	s := insertWordPressStackServer(t, a, d, config.Database.Path)
	gs, err := a.loadRune(s.GameskillID)
	if err != nil {
		t.Fatal(err)
	}
	network := "stack-log-test"
	if _, err = a.engine.CreateNetwork(context.Background(), network, docker.NetworkCreateConfig{Driver: "bridge", Labels: map[string]string{docklightServerLabel: s.ID}}); err != nil {
		t.Fatal(err)
	}
	env, err := a.runtimeEnv(s, gs)
	if err != nil {
		t.Fatal(err)
	}
	if err = a.createStackSidecars(context.Background(), s, gs, env, network, stackResourceLimits(s, gs)); err != nil {
		t.Fatal(err)
	}
	id, secrets, err := a.stackServiceLogTarget(context.Background(), s, "database")
	if err != nil || id == "" {
		t.Fatalf("validated sidecar log target: id=%q err=%v", id, err)
	}
	if !containsString(secrets, "unique-db-password-234567890") || !containsString(secrets, "unique-root-password-987654321") {
		t.Fatalf("sidecar log redaction did not load both database secrets: %#v", secrets)
	}
	var output []string
	writer := &wsLineWriter{secrets: secrets, send: func(line string) error { output = append(output, line); return nil }}
	if _, err = writer.Write([]byte("MariaDB started with unique-root-password-987654321\n")); err != nil {
		t.Fatal(err)
	}
	if len(output) != 1 || output[0] != "MariaDB started with [redacted]" {
		t.Fatalf("sidecar log writer returned unredacted text: %#v", output)
	}
	fake.mu.Lock()
	containerID := fake.byName[stackContainerName(s.ID, "database")]
	container := fake.containers[containerID]
	container.config.Labels[docklightServerLabel] = "another-server"
	fake.containers[containerID] = container
	fake.mu.Unlock()
	if _, _, err = a.stackServiceLogTarget(context.Background(), s, "database"); err == nil || !strings.Contains(err.Error(), "ownership could not be verified") {
		t.Fatalf("sidecar logs were allowed for an unowned container: %v", err)
	}
}

func TestStackServiceCommandsRequirePermissionAndRunSafely(t *testing.T) {
	a, d, config := testApp(t)
	fake := newFakeStackDocker("stack-server", "")
	a.engine = docker.NewWithHTTPClient("fake-docker", "1.45", &http.Client{Transport: stackRoundTripFunc(fake.roundTrip)})
	s := insertWordPressStackServer(t, a, d, config.Database.Path)
	gs, err := a.loadRune(s.GameskillID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = a.engine.CreateNetwork(context.Background(), "stack-exec-network", docker.NetworkCreateConfig{Driver: "bridge", Labels: map[string]string{docklightServerLabel: s.ID}}); err != nil {
		t.Fatal(err)
	}
	env, err := a.runtimeEnv(s, gs)
	if err != nil {
		t.Fatal(err)
	}
	if err = a.createStackSidecars(context.Background(), s, gs, env, "stack-exec-network", stackResourceLimits(s, gs)); err != nil {
		t.Fatal(err)
	}
	fake.mu.Lock()
	fake.execOutput = "connected with unique-db-password-234567890\n"
	fake.execExitCode = 0
	fake.mu.Unlock()

	requestFor := func(user User) *httptest.ResponseRecorder {
		request := httptest.NewRequest(http.MethodPost, "/api/servers/stack-server/stack-services/database/exec", strings.NewReader(`{"command":"printf safe"}`))
		route := chi.NewRouteContext()
		route.URLParams.Add("id", s.ID)
		route.URLParams.Add("service", "database")
		ctx := context.WithValue(request.Context(), chi.RouteCtxKey, route)
		ctx = context.WithValue(ctx, principalKey{}, user)
		request = request.WithContext(ctx)
		response := httptest.NewRecorder()
		a.execStackService(response, request)
		return response
	}
	limited := requestFor(User{ID: "limited", Username: "limited", Role: "user"})
	if limited.Code != http.StatusForbidden || !strings.Contains(limited.Body.String(), "server.console permission is required") {
		t.Fatalf("sidecar command access did not require server.console: status=%d body=%s", limited.Code, limited.Body.String())
	}

	response := requestFor(User{ID: "admin", Username: "admin", Role: "admin"})
	if response.Code != http.StatusOK {
		t.Fatalf("sidecar command failed: %d %s", response.Code, response.Body.String())
	}
	var result struct {
		Service  string `json:"service"`
		Output   string `json:"output"`
		ExitCode int    `json:"exit_code"`
		Success  bool   `json:"success"`
	}
	if err = json.Unmarshal(response.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if result.Service != "database" || result.Output != "connected with [redacted]\n" || !result.Success || result.ExitCode != 0 {
		t.Fatalf("sidecar command response leaked or lost result fields: %+v", result)
	}
	fake.mu.Lock()
	command := append([]string(nil), fake.execCommand...)
	execCount := fake.execCount
	containerID := fake.byName[stackContainerName(s.ID, "database")]
	container := fake.containers[containerID]
	container.state = "exited"
	fake.containers[containerID] = container
	fake.mu.Unlock()
	if strings.Join(command, "|") != "/bin/sh|-c|printf safe" || execCount != 1 {
		t.Fatalf("sidecar command config=%v exec count=%d", command, execCount)
	}
	var auditDetail string
	if err = d.QueryRow(`SELECT detail FROM audit_log WHERE action='server.stack.command' AND target_id=?`, s.ID).Scan(&auditDetail); err != nil {
		t.Fatal(err)
	}
	if auditDetail != "service=database exit_code=0" || strings.Contains(auditDetail, "printf safe") || strings.Contains(auditDetail, "unique-db-password") {
		t.Fatalf("command audit detail contains user input or secret: %q", auditDetail)
	}
	stopped := requestFor(User{ID: "admin", Username: "admin", Role: "admin"})
	if stopped.Code != http.StatusConflict {
		t.Fatalf("commands were accepted by a stopped private service: %d %s", stopped.Code, stopped.Body.String())
	}
	fake.mu.Lock()
	defer fake.mu.Unlock()
	if fake.execCount != 1 {
		t.Fatalf("stopped private service created another exec: %d", fake.execCount)
	}
}

func TestStackServiceLogsRequireServerView(t *testing.T) {
	a, d, config := testApp(t)
	_ = insertWordPressStackServer(t, a, d, config.Database.Path)
	request := httptest.NewRequest(http.MethodGet, "/api/servers/stack-server/stack-services/database/logs", nil)
	route := chi.NewRouteContext()
	route.URLParams.Add("id", "stack-server")
	route.URLParams.Add("service", "database")
	ctx := context.WithValue(request.Context(), chi.RouteCtxKey, route)
	ctx = context.WithValue(ctx, principalKey{}, User{ID: "limited-user", Username: "limited", Role: "user"})
	request = request.WithContext(ctx)
	response := httptest.NewRecorder()
	a.stackServiceLogsWS(response, request)
	if response.Code != http.StatusForbidden || !strings.Contains(response.Body.String(), "server.view permission is required") {
		t.Fatalf("private service logs were not protected by server.view: status=%d body=%s", response.Code, response.Body.String())
	}
}

func TestStackServiceLogsWebSocketStreamsRedactedOutput(t *testing.T) {
	a, d, config := testApp(t)
	fake := newFakeStackDocker("stack-server", "")
	a.engine = docker.NewWithHTTPClient("fake-docker", "1.45", &http.Client{Transport: stackRoundTripFunc(fake.roundTrip)})
	s := insertWordPressStackServer(t, a, d, config.Database.Path)
	gs, err := a.loadRune(s.GameskillID)
	if err != nil {
		t.Fatal(err)
	}
	network := "stack-logs-network"
	if _, err = a.engine.CreateNetwork(context.Background(), network, docker.NetworkCreateConfig{Driver: "bridge", Labels: map[string]string{docklightServerLabel: s.ID}}); err != nil {
		t.Fatal(err)
	}
	env, err := a.runtimeEnv(s, gs)
	if err != nil {
		t.Fatal(err)
	}
	if err = a.createStackSidecars(context.Background(), s, gs, env, network, stackResourceLimits(s, gs)); err != nil {
		t.Fatal(err)
	}
	fake.mu.Lock()
	fake.logsOutput = "MariaDB started with unique-root-password-987654321\n"
	fake.mu.Unlock()
	request := httptest.NewRequest(http.MethodGet, "/api/servers/stack-server/stack-services/database/logs", nil)
	route := chi.NewRouteContext()
	route.URLParams.Add("id", s.ID)
	route.URLParams.Add("service", "database")
	ctx := context.WithValue(request.Context(), chi.RouteCtxKey, route)
	ctx = context.WithValue(ctx, principalKey{}, User{ID: "admin", Username: "admin", Role: "admin"})
	request = request.WithContext(ctx)
	request.Header.Set("Connection", "Upgrade")
	request.Header.Set("Upgrade", "websocket")
	request.Header.Set("Sec-WebSocket-Key", base64.StdEncoding.EncodeToString([]byte("sixteen-byte-key")))
	writer := &pipeHijackResponseWriter{clientReady: make(chan net.Conn, 1)}
	done := make(chan struct{})
	go func() {
		a.stackServiceLogsWS(writer, request)
		close(done)
	}()
	var client net.Conn
	select {
	case client = <-writer.clientReady:
	case <-time.After(2 * time.Second):
		t.Fatal("WebSocket handler did not create a client connection")
	}
	defer client.Close()
	_ = client.SetReadDeadline(time.Now().Add(3 * time.Second))
	reader := bufio.NewReader(client)
	for {
		line, readErr := reader.ReadString('\n')
		if readErr != nil {
			t.Fatalf("read WebSocket handshake: %v", readErr)
		}
		if line == "\r\n" {
			break
		}
	}
	opcode, output, err := readWebSocketFrame(reader)
	if err != nil || opcode != 1 || output != "MariaDB started with [redacted]" {
		t.Fatalf("private service log was not streamed safely: opcode=%d output=%q err=%v", opcode, output, err)
	}
	closeOpcode, _, closeErr := readWebSocketFrame(reader)
	if closeErr != nil || closeOpcode != 8 {
		t.Fatalf("private service log stream did not close cleanly: opcode=%d err=%v", closeOpcode, closeErr)
	}
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("private service log WebSocket did not finish after Docker log stream ended")
	}
}

func TestWordPressStackBackupContainsAppAndSidecarData(t *testing.T) {
	root := t.TempDir()
	appDir := filepath.Join(root, "_app")
	dbDir := filepath.Join(root, "_stack", "database")
	if err := os.MkdirAll(appDir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(dbDir, 0700); err != nil {
		t.Fatal(err)
	}
	appData := []byte("wordpress configuration")
	databaseData := []byte("mariadb table data")
	if err := os.WriteFile(filepath.Join(appDir, "wp-config.php"), appData, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dbDir, "ibdata1"), databaseData, 0600); err != nil {
		t.Fatal(err)
	}
	key := []byte("docklight-backup-test-key")
	var archive bytes.Buffer
	summary, err := backup.Create(&archive, root, key)
	if err != nil {
		t.Fatalf("create stack backup: %v", err)
	}
	if summary.Files != 2 || summary.Bytes != int64(len(appData)+len(databaseData)) {
		t.Fatalf("backup did not include both stack data files: %+v", summary)
	}
	restored := filepath.Join(t.TempDir(), "restored")
	restoredSummary, err := backup.Extract(bytes.NewReader(archive.Bytes()), restored, key)
	if err != nil {
		t.Fatalf("restore stack backup: %v", err)
	}
	for name, want := range map[string][]byte{
		filepath.Join("_app", "wp-config.php"):         appData,
		filepath.Join("_stack", "database", "ibdata1"): databaseData,
	} {
		got, readErr := os.ReadFile(filepath.Join(restored, name))
		if readErr != nil || !bytes.Equal(got, want) {
			t.Fatalf("restored stack file %q mismatch: got=%q err=%v", name, got, readErr)
		}
	}
	if restoredSummary.Files != 2 || restoredSummary.Bytes != summary.Bytes {
		t.Fatalf("restore summary does not show both stack files: %+v", restoredSummary)
	}
}
