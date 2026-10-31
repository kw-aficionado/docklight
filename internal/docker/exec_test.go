package docker

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

func TestRunExecCreatesStartsAndInspectsCommand(t *testing.T) {
	var create ExecConfig
	var start execStartConfig
	requests := []string{}
	client := &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		requests = append(requests, req.Method+" "+req.URL.Path)
		switch req.URL.Path {
		case "/v1.45/containers/container-123/exec":
			if req.Method != http.MethodPost {
				t.Fatalf("exec create method = %s", req.Method)
			}
			if err := json.NewDecoder(req.Body).Decode(&create); err != nil {
				t.Fatal(err)
			}
			return dockerResponse(req, http.StatusCreated, `{"Id":"exec-123"}`), nil
		case "/v1.45/exec/exec-123/start":
			if err := json.NewDecoder(req.Body).Decode(&start); err != nil {
				t.Fatal(err)
			}
			output := append(dockerLogFrame(1, "stdout\n"), dockerLogFrame(2, "stderr\n")...)
			return dockerResponse(req, http.StatusOK, string(output)), nil
		case "/v1.45/exec/exec-123/json":
			return dockerResponse(req, http.StatusOK, `{"Running":false,"ExitCode":7}`), nil
		default:
			return dockerResponse(req, http.StatusNotFound, `{"message":"unexpected exec request"}`), nil
		}
	})}
	e := NewWithHTTPClient("test-socket", "1.45", client)
	result, err := e.RunExec(context.Background(), "container-123", []string{"/bin/sh", "-lc", "printf safe"}, 128)
	if err != nil {
		t.Fatalf("RunExec() error = %v", err)
	}
	if result.Output != "stdout\nstderr\n" || result.ExitCode != 7 {
		t.Fatalf("RunExec() = %#v; want demultiplexed output and exit code 7", result)
	}
	if len(create.Cmd) != 3 || create.Cmd[0] != "/bin/sh" || create.Cmd[1] != "-lc" || create.Cmd[2] != "printf safe" || create.AttachStdout != true || create.AttachStderr != true || create.Tty {
		t.Fatalf("Docker exec config = %+v", create)
	}
	if start.Detach || start.Tty {
		t.Fatalf("Docker exec start config = %+v", start)
	}
	wantRequests := []string{"POST /v1.45/containers/container-123/exec", "POST /v1.45/exec/exec-123/start", "GET /v1.45/exec/exec-123/json"}
	if strings.Join(requests, "|") != strings.Join(wantRequests, "|") {
		t.Fatalf("Docker exec requests = %v; want %v", requests, wantRequests)
	}
}

func TestRunExecCapsOutput(t *testing.T) {
	client := &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		switch req.URL.Path {
		case "/v1.45/containers/container-123/exec":
			return dockerResponse(req, http.StatusCreated, `{"Id":"exec-123"}`), nil
		case "/v1.45/exec/exec-123/start":
			return dockerResponse(req, http.StatusOK, string(dockerLogFrame(1, "0123456789"))), nil
		case "/v1.45/exec/exec-123/json":
			return dockerResponse(req, http.StatusOK, `{"Running":false,"ExitCode":0}`), nil
		default:
			return dockerResponse(req, http.StatusNotFound, `{"message":"not found"}`), nil
		}
	})}
	e := NewWithHTTPClient("test-socket", "1.45", client)
	result, err := e.RunExec(context.Background(), "container-123", []string{"echo", "large"}, 4)
	if err != nil {
		t.Fatalf("RunExec() error = %v", err)
	}
	if result.Output != "0123\n[output truncated]" {
		t.Fatalf("bounded output = %q", result.Output)
	}
}

func dockerLogFrame(stream byte, body string) []byte {
	frame := make([]byte, 8+len(body))
	frame[0] = stream
	binary.BigEndian.PutUint32(frame[4:8], uint32(len(body)))
	copy(frame[8:], body)
	return frame
}
