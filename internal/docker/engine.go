package docker

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"path"
	"sort"
	"strconv"
	"strings"
	"time"
)

type Engine struct {
	socket string
	api    string
	client *http.Client
}

func New(socket, api string) *Engine {
	socket = strings.TrimPrefix(socket, "unix://")
	if api == "" {
		api = "v1.45"
	}
	if !strings.HasPrefix(api, "v") {
		api = "v" + api
	}
	tr := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, "unix", socket)
	}, DisableKeepAlives: false}
	return &Engine{socket: socket, api: api, client: &http.Client{Transport: tr}}
}

// NewWithHTTPClient builds an Engine around a caller-provided client. It is
// primarily useful for deterministic Docker Engine API tests.
func NewWithHTTPClient(socket, api string, client *http.Client) *Engine {
	e := New(socket, api)
	if client != nil {
		e.client = client
	}
	return e
}
func (e *Engine) endpoint(p string) string {
	return "http://docker/" + e.api + "/" + strings.TrimLeft(p, "/")
}

type apiError struct {
	Message string `json:"message"`
	Cause   string `json:"cause"`
}

type APIError struct {
	StatusCode int
	Message    string
}

func (e *APIError) Error() string { return "Docker Engine: " + actionable(e.Message) }

func IsNotFound(err error) bool {
	var apiErr *APIError
	return errors.As(err, &apiErr) && apiErr.StatusCode == http.StatusNotFound
}

func IsNotModified(err error) bool {
	var apiErr *APIError
	return errors.As(err, &apiErr) && apiErr.StatusCode == http.StatusNotModified
}

func (e *Engine) do(ctx context.Context, method, p string, body any) (*http.Response, error) {
	return e.doWithHeaders(ctx, method, p, body, nil)
}

func (e *Engine) doWithHeaders(ctx context.Context, method, p string, body any, headers http.Header) (*http.Response, error) {
	var r io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}
		r = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, e.endpoint(p), r)
	if err != nil {
		return nil, err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	for name, values := range headers {
		for _, value := range values {
			req.Header.Add(name, value)
		}
	}
	resp, err := e.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("Docker Engine is not reachable at %s: %w", e.socket, err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		defer resp.Body.Close()
		var d apiError
		_ = json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&d)
		msg := d.Message
		if msg == "" {
			msg = http.StatusText(resp.StatusCode)
		}
		return nil, &APIError{StatusCode: resp.StatusCode, Message: msg}
	}
	return resp, nil
}
func actionable(s string) string {
	l := strings.ToLower(s)
	switch {
	case strings.Contains(l, "unauthorized") || strings.Contains(l, "authentication required") || strings.Contains(l, "pull access denied") || strings.Contains(l, "requested access to the resource is denied"):
		return "Login required for this private image; check the saved registry login and repository access."
	case strings.Contains(l, "no such image") || strings.Contains(l, "manifest unknown"):
		return "Docker could not pull this image; check the image name, tag and registry access."
	case strings.Contains(l, "port is already allocated") || strings.Contains(l, "address already in use"):
		return "Docker could not bind the port because another process is using it; choose another host port."
	case strings.Contains(l, "permission denied"):
		return "Docker denied access; check that the panel service account can access the Docker socket and server data directory."
	case strings.Contains(l, "no such container"):
		return "Docker no longer has this server container; refresh the server state and try again."
	default:
		return s
	}
}
func (e *Engine) Ping(ctx context.Context) error {
	r, err := e.do(ctx, http.MethodGet, "/_ping", nil)
	if err == nil {
		r.Body.Close()
	}
	return err
}

func (e *Engine) Pull(ctx context.Context, image string) error {
	return e.pull(ctx, image, nil, "")
}

// RegistryAuthConfig is sent only with a single pull request. The Engine does
// not persist these credentials in its daemon or host credential store.
type RegistryAuthConfig struct {
	Username      string `json:"username,omitempty"`
	Password      string `json:"password,omitempty"`
	ServerAddress string `json:"serveraddress,omitempty"`
}

func (e *Engine) PullWithAuth(ctx context.Context, image string, auth RegistryAuthConfig) error {
	return e.pull(ctx, image, &auth, "")
}

func (e *Engine) PullPlatform(ctx context.Context, image, platform string) error {
	return e.pull(ctx, image, nil, platform)
}

func (e *Engine) pull(ctx context.Context, image string, auth *RegistryAuthConfig, platform string) error {
	q := url.Values{"fromImage": {image}}
	if platform != "" {
		q.Set("platform", platform)
	}
	headers := make(http.Header)
	if auth != nil {
		payload, err := json.Marshal(auth)
		if err != nil {
			return fmt.Errorf("encode registry authentication: %w", err)
		}
		headers.Set("X-Registry-Auth", base64.URLEncoding.EncodeToString(payload))
	}
	r, err := e.doWithHeaders(ctx, http.MethodPost, "/images/create?"+q.Encode(), nil, headers)
	if err != nil {
		return fmt.Errorf("pull image %q: %w", image, err)
	}
	defer r.Body.Close()
	sc := bufio.NewScanner(r.Body)
	sc.Buffer(make([]byte, 4096), 2*1024*1024)
	for sc.Scan() {
		var msg struct {
			Error  string `json:"error"`
			Detail struct {
				Message string `json:"message"`
			} `json:"errorDetail"`
		}
		if json.Unmarshal(sc.Bytes(), &msg) == nil {
			if msg.Error != "" {
				return fmt.Errorf("pull image %q: %s", image, actionable(msg.Error))
			}
			if msg.Detail.Message != "" && strings.Contains(strings.ToLower(msg.Detail.Message), "error") {
				return fmt.Errorf("pull image %q: %s", image, actionable(msg.Detail.Message))
			}
		}
	}
	if err := sc.Err(); err != nil {
		return fmt.Errorf("pull image %q: %w", image, err)
	}
	return nil
}

// TestRegistryAuth asks Docker to verify the credentials without storing them.
func (e *Engine) TestRegistryAuth(ctx context.Context, auth RegistryAuthConfig) error {
	r, err := e.do(ctx, http.MethodPost, "/auth", auth)
	if err != nil {
		return err
	}
	defer r.Body.Close()
	_, err = io.Copy(io.Discard, io.LimitReader(r.Body, 1<<20))
	return err
}

type PortBinding struct {
	HostIP   string `json:"HostIp"`
	HostPort string `json:"HostPort"`
}
type HostConfig struct {
	Binds         []string                 `json:"Binds,omitempty"`
	PortBindings  map[string][]PortBinding `json:"PortBindings,omitempty"`
	RestartPolicy map[string]any           `json:"RestartPolicy,omitempty"`
	NanoCPUs      int64                    `json:"NanoCpus,omitempty"`
	Memory        int64                    `json:"Memory,omitempty"`
	Init          *bool                    `json:"Init,omitempty"`
	CapAdd        []string                 `json:"CapAdd,omitempty"`
	Devices       []DeviceMapping          `json:"Devices,omitempty"`
	Sysctls       map[string]string        `json:"Sysctls,omitempty"`
}
type DeviceMapping struct {
	PathOnHost        string `json:"PathOnHost"`
	PathInContainer   string `json:"PathInContainer"`
	CgroupPermissions string `json:"CgroupPermissions"`
}
type CreateConfig struct {
	Image            string              `json:"Image"`
	Entrypoint       []string            `json:"Entrypoint,omitempty"`
	Cmd              []string            `json:"Cmd,omitempty"`
	Env              []string            `json:"Env,omitempty"`
	WorkingDir       string              `json:"WorkingDir,omitempty"`
	User             string              `json:"User,omitempty"`
	Tty              bool                `json:"Tty"`
	OpenStdin        bool                `json:"OpenStdin,omitempty"`
	AttachStdin      bool                `json:"AttachStdin,omitempty"`
	AttachStdout     bool                `json:"AttachStdout,omitempty"`
	AttachStderr     bool                `json:"AttachStderr,omitempty"`
	ExposedPorts     map[string]struct{} `json:"ExposedPorts,omitempty"`
	Labels           map[string]string   `json:"Labels,omitempty"`
	HostConfig       HostConfig          `json:"HostConfig"`
	NetworkingConfig *NetworkingConfig   `json:"NetworkingConfig,omitempty"`
}

// Attach opens a Docker container's bidirectional stdin/stdout stream. Docker
// requires an HTTP upgrade for attach; the returned body owns that connection.
func (e *Engine) Attach(ctx context.Context, id string) (io.ReadWriteCloser, error) {
	return e.attach(ctx, id, true, true, true)
}

// AttachOutput opens a Docker stream that carries stdout only. It is useful
// when stdout contains binary data and stderr must not be mixed into it.
func (e *Engine) AttachOutput(ctx context.Context, id string) (io.ReadWriteCloser, error) {
	return e.attach(ctx, id, false, true, false)
}

func (e *Engine) attach(ctx context.Context, id string, stdin, stdout, stderr bool) (io.ReadWriteCloser, error) {
	if id == "" {
		return nil, errors.New("Docker attach needs a container ID")
	}
	q := url.Values{"stream": {"1"}, "stdin": {strconv.FormatBool(stdin)}, "stdout": {strconv.FormatBool(stdout)}, "stderr": {strconv.FormatBool(stderr)}}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, e.endpoint("/containers/"+url.PathEscape(id)+"/attach?"+q.Encode()), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("Upgrade", "tcp")
	resp, err := e.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("attach to Docker container: %w", err)
	}
	if resp.StatusCode != http.StatusSwitchingProtocols {
		defer resp.Body.Close()
		var detail apiError
		_ = json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&detail)
		if detail.Message == "" {
			detail.Message = http.StatusText(resp.StatusCode)
		}
		return nil, &APIError{StatusCode: resp.StatusCode, Message: detail.Message}
	}
	stream, ok := resp.Body.(io.ReadWriteCloser)
	if !ok {
		_ = resp.Body.Close()
		return nil, errors.New("Docker attach did not provide a bidirectional stream")
	}
	return stream, nil
}

type NetworkingConfig struct {
	EndpointsConfig map[string]EndpointSettings `json:"EndpointsConfig"`
}
type EndpointSettings struct {
	Aliases []string `json:"Aliases,omitempty"`
}
type Created struct {
	ID string `json:"Id"`
}

type NetworkCreateConfig struct {
	Driver     string            `json:"Driver,omitempty"`
	Internal   bool              `json:"Internal,omitempty"`
	Attachable bool              `json:"Attachable,omitempty"`
	Labels     map[string]string `json:"Labels,omitempty"`
}
type NetworkInfo struct {
	ID     string            `json:"Id"`
	Name   string            `json:"Name"`
	Labels map[string]string `json:"Labels"`
}
type ContainerSummary struct {
	ID     string            `json:"Id"`
	State  string            `json:"State"`
	Labels map[string]string `json:"Labels"`
}

func (e *Engine) CreateNetwork(ctx context.Context, name string, cfg NetworkCreateConfig) (string, error) {
	q := url.Values{"name": {name}}
	r, err := e.do(ctx, http.MethodPost, "/networks/create?"+q.Encode(), cfg)
	if err != nil {
		return "", err
	}
	defer r.Body.Close()
	var out struct {
		ID string `json:"Id"`
	}
	if err = json.NewDecoder(r.Body).Decode(&out); err != nil {
		return "", err
	}
	if out.ID == "" {
		return "", errors.New("Docker returned an empty network ID")
	}
	return out.ID, nil
}

func (e *Engine) InspectNetwork(ctx context.Context, idOrName string) (NetworkInfo, error) {
	var out NetworkInfo
	r, err := e.do(ctx, http.MethodGet, "/networks/"+url.PathEscape(idOrName), nil)
	if err != nil {
		return out, err
	}
	defer r.Body.Close()
	err = json.NewDecoder(r.Body).Decode(&out)
	return out, err
}

func (e *Engine) RemoveNetwork(ctx context.Context, idOrName string) error {
	r, err := e.do(ctx, http.MethodDelete, "/networks/"+url.PathEscape(idOrName), nil)
	if err == nil {
		r.Body.Close()
	}
	return err
}

func (e *Engine) ListContainers(ctx context.Context, all bool, labels map[string]string) ([]ContainerSummary, error) {
	filters := map[string][]string{}
	keys := make([]string, 0, len(labels))
	for key := range labels {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		filters["label"] = append(filters["label"], key+"="+labels[key])
	}
	encoded, err := json.Marshal(filters)
	if err != nil {
		return nil, err
	}
	q := url.Values{"all": {strconv.FormatBool(all)}, "filters": {string(encoded)}}
	r, err := e.do(ctx, http.MethodGet, "/containers/json?"+q.Encode(), nil)
	if err != nil {
		return nil, err
	}
	defer r.Body.Close()
	var out []ContainerSummary
	err = json.NewDecoder(r.Body).Decode(&out)
	return out, err
}

func (e *Engine) Create(ctx context.Context, name string, c CreateConfig) (string, error) {
	return e.CreateWithPlatform(ctx, name, c, "")
}

func (e *Engine) CreateWithPlatform(ctx context.Context, name string, c CreateConfig, platform string) (string, error) {
	q := url.Values{"name": {name}}
	if platform != "" {
		q.Set("platform", platform)
	}
	r, err := e.do(ctx, http.MethodPost, "/containers/create?"+q.Encode(), c)
	if err != nil {
		return "", err
	}
	defer r.Body.Close()
	var out Created
	if err = json.NewDecoder(r.Body).Decode(&out); err != nil {
		return "", err
	}
	if out.ID == "" {
		return "", errors.New("Docker returned an empty container ID")
	}
	return out.ID, nil
}
func (e *Engine) Start(ctx context.Context, id string) error {
	r, err := e.do(ctx, http.MethodPost, "/containers/"+url.PathEscape(id)+"/start", nil)
	if err == nil {
		r.Body.Close()
	}
	return err
}
func (e *Engine) Stop(ctx context.Context, id string, seconds int) error {
	if seconds < 0 {
		seconds = 0
	}
	r, err := e.do(ctx, http.MethodPost, fmt.Sprintf("/containers/%s/stop?t=%d", url.PathEscape(id), seconds), nil)
	if err == nil {
		r.Body.Close()
	}
	return err
}
func (e *Engine) Remove(ctx context.Context, id string) error {
	r, err := e.do(ctx, http.MethodDelete, "/containers/"+url.PathEscape(id)+"?force=true&v=true", nil)
	if err == nil {
		r.Body.Close()
	}
	return err
}

type Inspect struct {
	ID     string `json:"Id"`
	Name   string `json:"Name"`
	Config struct {
		Image       string            `json:"Image"`
		Labels      map[string]string `json:"Labels"`
		Healthcheck struct {
			Test []string `json:"Test"`
		} `json:"Healthcheck"`
	} `json:"Config"`
	State struct {
		Status   string `json:"Status"`
		Running  bool   `json:"Running"`
		ExitCode int    `json:"ExitCode"`
		Health   *struct {
			Status string `json:"Status"`
		} `json:"Health"`
	} `json:"State"`
}

func (e *Engine) Inspect(ctx context.Context, id string) (Inspect, error) {
	var out Inspect
	r, err := e.do(ctx, http.MethodGet, "/containers/"+url.PathEscape(id)+"/json", nil)
	if err != nil {
		return out, err
	}
	defer r.Body.Close()
	err = json.NewDecoder(r.Body).Decode(&out)
	return out, err
}
func (e *Engine) Wait(ctx context.Context, id string) (int, error) {
	r, err := e.do(ctx, http.MethodPost, "/containers/"+url.PathEscape(id)+"/wait?condition=not-running", nil)
	if err != nil {
		return -1, err
	}
	defer r.Body.Close()
	var out struct {
		StatusCode int `json:"StatusCode"`
		Error      *struct {
			Message string `json:"Message"`
		} `json:"Error"`
	}
	if err = json.NewDecoder(r.Body).Decode(&out); err != nil {
		return -1, err
	}
	if out.Error != nil {
		return out.StatusCode, errors.New(out.Error.Message)
	}
	return out.StatusCode, nil
}
func (e *Engine) Logs(ctx context.Context, id, tail string, follow bool) (io.ReadCloser, error) {
	q := url.Values{"stdout": {"1"}, "stderr": {"1"}, "tail": {tail}, "timestamps": {"1"}}
	if follow {
		q.Set("follow", "1")
	}
	r, err := e.do(ctx, http.MethodGet, "/containers/"+url.PathEscape(id)+"/logs?"+q.Encode(), nil)
	if err != nil {
		return nil, err
	}
	return r.Body, nil
}

// LogsSince reads container output emitted at or after the supplied time.
// Docker supplies timestamped, multiplexed stdout and stderr frames.
func (e *Engine) LogsSince(ctx context.Context, id string, since time.Time) (io.ReadCloser, error) {
	q := url.Values{"stdout": {"1"}, "stderr": {"1"}, "since": {strconv.FormatInt(since.Unix(), 10)}, "timestamps": {"1"}}
	r, err := e.do(ctx, http.MethodGet, "/containers/"+url.PathEscape(id)+"/logs?"+q.Encode(), nil)
	if err != nil {
		return nil, err
	}
	return r.Body, nil
}

// CopyLogs removes Docker's 8-byte multiplex headers and writes readable log lines.
func CopyLogs(dst io.Writer, src io.Reader) error {
	br := bufio.NewReader(src)
	for {
		hdr := make([]byte, 8)
		if _, err := io.ReadFull(br, hdr); err != nil {
			if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
				return nil
			}
			return err
		}
		n := int64(hdr[4])<<24 | int64(hdr[5])<<16 | int64(hdr[6])<<8 | int64(hdr[7])
		if n < 0 || n > 16*1024*1024 {
			return errors.New("Docker sent an invalid log frame")
		}
		if _, err := io.CopyN(dst, br, n); err != nil {
			return err
		}
	}
}

// CopyStream strips Docker's multiplex headers and copies only the requested
// stream (1 is stdout, 2 is stderr), discarding any other frames.
func CopyStream(dst io.Writer, src io.Reader, stream byte) error {
	if stream != 1 && stream != 2 {
		return errors.New("Docker stream must be stdout (1) or stderr (2)")
	}
	br := bufio.NewReader(src)
	for {
		hdr := make([]byte, 8)
		if _, err := io.ReadFull(br, hdr); err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return err
		}
		if hdr[1] != 0 || hdr[2] != 0 || hdr[3] != 0 {
			return errors.New("Docker sent an invalid stream frame")
		}
		n := int64(hdr[4])<<24 | int64(hdr[5])<<16 | int64(hdr[6])<<8 | int64(hdr[7])
		if n < 0 || n > 16*1024*1024 {
			return errors.New("Docker sent an invalid stream frame")
		}
		if hdr[0] == stream {
			if _, err := io.CopyN(dst, br, n); err != nil {
				return err
			}
		} else {
			if _, err := io.CopyN(io.Discard, br, n); err != nil {
				return err
			}
		}
	}
}
func (e *Engine) SendInput(ctx context.Context, id, line string) error {
	conn, err := (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, "unix", e.socket)
	if err != nil {
		return fmt.Errorf("Docker attach: %w", err)
	}
	defer conn.Close()
	path := fmt.Sprintf("/%s/containers/%s/attach?stream=1&stdin=1&stdout=0&stderr=0", e.api, url.PathEscape(id))
	req := fmt.Sprintf("POST %s HTTP/1.1\r\nHost: docker\r\nConnection: Upgrade\r\nUpgrade: tcp\r\nContent-Length: 0\r\n\r\n", path)
	if _, err = io.WriteString(conn, req); err != nil {
		return err
	}
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	br := bufio.NewReader(conn)
	status, err := br.ReadString('\n')
	if err != nil {
		return err
	}
	if !strings.Contains(status, " 101 ") && !strings.Contains(status, " 200 ") {
		return fmt.Errorf("Docker attach refused: %s", strings.TrimSpace(status))
	}
	for {
		line, er := br.ReadString('\n')
		if er != nil {
			return er
		}
		if line == "\r\n" {
			break
		}
	}
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
	_, err = io.WriteString(conn, line+"\n")
	return err
}

func (e *Engine) Stats(ctx context.Context, id string) (float64, uint64, error) {
	r, err := e.do(ctx, http.MethodGet, "/containers/"+url.PathEscape(id)+"/stats?stream=false&one-shot=true", nil)
	if err != nil {
		return 0, 0, err
	}
	defer r.Body.Close()
	var x struct {
		Memory struct {
			Usage uint64 `json:"usage"`
		} `json:"memory_stats"`
		CPU struct {
			CPU struct {
				Total uint64 `json:"total_usage"`
			} `json:"cpu_usage"`
			System uint64 `json:"system_cpu_usage"`
		} `json:"cpu_stats"`
		PreCPU struct {
			CPU struct {
				Total uint64 `json:"total_usage"`
			} `json:"cpu_usage"`
			System uint64 `json:"system_cpu_usage"`
		} `json:"precpu_stats"`
	}
	if err = json.NewDecoder(r.Body).Decode(&x); err != nil {
		return 0, 0, err
	}
	cpuDelta := float64(x.CPU.CPU.Total) - float64(x.PreCPU.CPU.Total)
	sysDelta := float64(x.CPU.System) - float64(x.PreCPU.System)
	pct := 0.0
	if cpuDelta > 0 && sysDelta > 0 {
		pct = cpuDelta / sysDelta * 100
		if pct > 100 {
			pct = 100
		}
	}
	return pct, x.Memory.Usage, nil
}

// SocketPath exposes the configured Unix endpoint for the WebSocket proxy guard.
func (e *Engine) SocketPath() string { return e.socket }
func SafeContainerName(id string) string {
	if len(id) > 8 {
		id = id[:8]
	}
	return "ygg-" + strings.ToLower(path.Clean(id))
}
func ParsePort(s string) (int, error) { return strconv.Atoi(s) }
