package docker

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (fn roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) { return fn(req) }

func dockerResponse(req *http.Request, status int, body string) *http.Response {
	return &http.Response{StatusCode: status, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(body)), Request: req}
}

func TestStackNetworkAndContainerAPIPayloads(t *testing.T) {
	var requests []struct {
		method string
		path   string
		body   string
	}
	client := &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		var body []byte
		if req.Body != nil {
			body, _ = io.ReadAll(req.Body)
		}
		requests = append(requests, struct {
			method string
			path   string
			body   string
		}{req.Method, req.URL.RequestURI(), string(body)})
		switch req.URL.Path {
		case "/v1.45/networks/create":
			return dockerResponse(req, http.StatusCreated, `{"Id":"network-123"}`), nil
		case "/v1.45/containers/create":
			return dockerResponse(req, http.StatusCreated, `{"Id":"container-123"}`), nil
		case "/v1.45/networks/network-123":
			return dockerResponse(req, http.StatusOK, `{"Id":"network-123","Name":"docklight-stack","Labels":{"docklight.server_id":"server-123"}}`), nil
		case "/v1.45/containers/json":
			return dockerResponse(req, http.StatusOK, `[{"Id":"container-123","State":"running","Labels":{"docklight.service":"database"}}]`), nil
		case "/v1.45/networks/docklight-stack":
			return dockerResponse(req, http.StatusNoContent, ""), nil
		default:
			return dockerResponse(req, http.StatusNotFound, `{"message":"not found"}`), nil
		}
	})}
	e := NewWithHTTPClient("test-socket", "1.45", client)

	networkID, err := e.CreateNetwork(context.Background(), "docklight-stack", NetworkCreateConfig{Driver: "bridge", Labels: map[string]string{"docklight.server_id": "server-123"}})
	if err != nil || networkID != "network-123" {
		t.Fatalf("create network: id=%q err=%v", networkID, err)
	}
	cfg := CreateConfig{Image: "mariadb:11", HostConfig: HostConfig{Binds: []string{"/srv/data:/var/lib/mysql"}}, NetworkingConfig: &NetworkingConfig{EndpointsConfig: map[string]EndpointSettings{"docklight-stack": {Aliases: []string{"database"}}}}}
	containerID, err := e.Create(context.Background(), "docklight-abc-database", cfg)
	if err != nil || containerID != "container-123" {
		t.Fatalf("create sidecar: id=%q err=%v", containerID, err)
	}
	info, err := e.InspectNetwork(context.Background(), networkID)
	if err != nil || info.Name != "docklight-stack" || info.Labels["docklight.server_id"] != "server-123" {
		t.Fatalf("inspect network: %#v err=%v", info, err)
	}
	containers, err := e.ListContainers(context.Background(), true, map[string]string{"docklight.server_id": "server-123", "docklight.role": "sidecar"})
	if err != nil || len(containers) != 1 || containers[0].Labels["docklight.service"] != "database" {
		t.Fatalf("list sidecars: %#v err=%v", containers, err)
	}
	if len(requests) != 4 {
		t.Fatalf("expected four Docker requests, got %#v", requests)
	}
	if !strings.Contains(requests[0].path, "name=docklight-stack") || !strings.Contains(requests[1].body, `"docklight-stack":{"Aliases":["database"]}`) {
		t.Fatalf("Docker network membership was not encoded correctly: %#v", requests)
	}
	query, err := url.ParseQuery(strings.TrimPrefix(requests[3].path, "/containers/json?"))
	if err != nil || !strings.Contains(query.Get("filters"), `docklight.server_id=server-123`) || !strings.Contains(query.Get("filters"), `docklight.role=sidecar`) {
		t.Fatalf("sidecar label filters were not encoded: %s", requests[3].path)
	}
	if err := e.RemoveNetwork(context.Background(), "docklight-stack"); err != nil {
		t.Fatalf("remove network: %v", err)
	}
}

func TestIsNotFoundOnlyAcceptsDocker404(t *testing.T) {
	client := &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		return dockerResponse(req, http.StatusNotFound, `{"message":"No such network"}`), nil
	})}
	e := NewWithHTTPClient("test-socket", "1.45", client)
	_, err := e.InspectNetwork(context.Background(), "missing")
	if !IsNotFound(err) {
		t.Fatalf("expected typed Docker 404, got %T %v", err, err)
	}
	if err.Error() != "Docker Engine: No such network" {
		t.Fatalf("Docker API error text changed: %v", err)
	}
}

func TestStatsCPUIsShareOfWholeHost(t *testing.T) {
	client := &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		return dockerResponse(req, http.StatusOK, `{"memory_stats":{"usage":1048576},"cpu_stats":{"cpu_usage":{"total_usage":150,"percpu_usage":[0,0,0,0,0,0,0,0]},"system_cpu_usage":1100},"precpu_stats":{"cpu_usage":{"total_usage":100},"system_cpu_usage":1000}}`), nil
	})}
	e := NewWithHTTPClient("test-socket", "1.45", client)
	cpu, memory, err := e.Stats(context.Background(), "container-123")
	if err != nil || cpu != 50 || memory != 1048576 {
		t.Fatalf("stats cpu/memory=%v/%d err=%v, want host CPU share 50%% and 1 MiB", cpu, memory, err)
	}
}

func TestPullWithAuthSendsCredentialsOnlyInRegistryHeader(t *testing.T) {
	var received RegistryAuthConfig
	client := &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		if req.Method != http.MethodPost || req.URL.Path != "/v1.45/images/create" || req.URL.Query().Get("fromImage") != "ghcr.io/team/private:latest" {
			t.Fatalf("unexpected pull request: %s %s", req.Method, req.URL.String())
		}
		if req.Body != nil {
			t.Fatal("pull credentials were written into the request body")
		}
		header := req.Header.Get("X-Registry-Auth")
		decoded, err := base64.URLEncoding.DecodeString(header)
		if err != nil {
			t.Fatalf("X-Registry-Auth is not base64url encoded: %v", err)
		}
		if err = json.Unmarshal(decoded, &received); err != nil {
			t.Fatalf("decode registry auth header: %v", err)
		}
		if strings.Contains(req.URL.String(), "private-pat") {
			t.Fatal("registry secret appeared in the pull URL")
		}
		return dockerResponse(req, http.StatusOK, `{"status":"Pulled"}`), nil
	})}
	e := NewWithHTTPClient("test-socket", "1.45", client)
	err := e.PullWithAuth(context.Background(), "ghcr.io/team/private:latest", RegistryAuthConfig{Username: "docklight", Password: "private-pat", ServerAddress: "ghcr.io"})
	if err != nil {
		t.Fatal(err)
	}
	if received.Username != "docklight" || received.Password != "private-pat" || received.ServerAddress != "ghcr.io" {
		t.Fatalf("wrong auth payload: %#v", received)
	}
}

func TestTestRegistryAuthUsesDaemonCheckEndpointAndDiscardsResponse(t *testing.T) {
	client := &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		if req.Method != http.MethodPost || req.URL.Path != "/v1.45/auth" {
			t.Fatalf("unexpected registry auth check request: %s %s", req.Method, req.URL.Path)
		}
		var received RegistryAuthConfig
		if err := json.NewDecoder(req.Body).Decode(&received); err != nil {
			t.Fatalf("decode auth-check body: %v", err)
		}
		if received.Username != "docklight" || received.Password != "private-pat" || received.ServerAddress != "docker.io" {
			t.Fatalf("wrong auth-check payload: %#v", received)
		}
		return dockerResponse(req, http.StatusOK, `{"Status":"Login Succeeded","IdentityToken":"daemon-only-token"}`), nil
	})}
	e := NewWithHTTPClient("test-socket", "1.45", client)
	if err := e.TestRegistryAuth(context.Background(), RegistryAuthConfig{Username: "docklight", Password: "private-pat", ServerAddress: "docker.io"}); err != nil {
		t.Fatal(err)
	}
}

func TestActionableRegistryDenialSaysLoginRequired(t *testing.T) {
	for _, message := range []string{"unauthorized: authentication required", "pull access denied, repository does not exist"} {
		if got := actionable(message); !strings.Contains(strings.ToLower(got), "login required") {
			t.Errorf("actionable(%q) = %q", message, got)
		}
	}
}
