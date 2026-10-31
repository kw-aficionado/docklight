package docker

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
)

type ExecConfig struct {
	Cmd          []string `json:"Cmd"`
	AttachStdin  bool     `json:"AttachStdin"`
	AttachStdout bool     `json:"AttachStdout"`
	AttachStderr bool     `json:"AttachStderr"`
	Tty          bool     `json:"Tty"`
}

type execStartConfig struct {
	Detach bool `json:"Detach"`
	Tty    bool `json:"Tty"`
}

type ExecResult struct {
	Output   string `json:"output"`
	ExitCode int    `json:"exit_code"`
}

// RunExec executes a one-shot command in an existing container. Output is
// demultiplexed and capped so a noisy command cannot consume unbounded memory.
func (e *Engine) RunExec(ctx context.Context, containerID string, command []string, outputLimit int) (ExecResult, error) {
	var result ExecResult
	if containerID == "" || len(command) == 0 {
		return result, errors.New("Docker exec needs a container and a command")
	}
	if outputLimit < 1 {
		return result, errors.New("Docker exec output limit must be positive")
	}
	createBody := ExecConfig{Cmd: command, AttachStdout: true, AttachStderr: true}
	created, err := e.do(ctx, http.MethodPost, "/containers/"+url.PathEscape(containerID)+"/exec", createBody)
	if err != nil {
		return result, fmt.Errorf("create Docker exec: %w", err)
	}
	var createdExec struct {
		ID string `json:"Id"`
	}
	err = json.NewDecoder(io.LimitReader(created.Body, 1<<20)).Decode(&createdExec)
	closeErr := created.Body.Close()
	if err != nil {
		return result, fmt.Errorf("read Docker exec ID: %w", err)
	}
	if closeErr != nil {
		return result, fmt.Errorf("close Docker exec response: %w", closeErr)
	}
	if createdExec.ID == "" {
		return result, errors.New("Docker returned an empty exec ID")
	}

	started, err := e.do(ctx, http.MethodPost, "/exec/"+url.PathEscape(createdExec.ID)+"/start", execStartConfig{})
	if err != nil {
		return result, fmt.Errorf("start Docker exec: %w", err)
	}
	output := &boundedOutput{limit: outputLimit}
	copyErr := CopyLogs(output, started.Body)
	closeErr = started.Body.Close()
	result.Output = output.String()
	if copyErr != nil {
		return result, fmt.Errorf("read Docker exec output: %w", copyErr)
	}
	if closeErr != nil {
		return result, fmt.Errorf("close Docker exec output: %w", closeErr)
	}

	inspected, err := e.do(ctx, http.MethodGet, "/exec/"+url.PathEscape(createdExec.ID)+"/json", nil)
	if err != nil {
		return result, fmt.Errorf("inspect Docker exec: %w", err)
	}
	defer inspected.Body.Close()
	var state struct {
		Running  bool `json:"Running"`
		ExitCode int  `json:"ExitCode"`
	}
	if err = json.NewDecoder(io.LimitReader(inspected.Body, 1<<20)).Decode(&state); err != nil {
		return result, fmt.Errorf("read Docker exec status: %w", err)
	}
	if state.Running {
		return result, errors.New("Docker exec is still running after its output stream ended")
	}
	result.ExitCode = state.ExitCode
	return result, nil
}

type boundedOutput struct {
	buffer    bytes.Buffer
	limit     int
	truncated bool
}

func (b *boundedOutput) Write(p []byte) (int, error) {
	remaining := b.limit - b.buffer.Len()
	if remaining > len(p) {
		remaining = len(p)
	}
	if remaining > 0 {
		if _, err := b.buffer.Write(p[:remaining]); err != nil {
			return 0, err
		}
	}
	if remaining < len(p) {
		b.truncated = true
	}
	return len(p), nil
}

func (b *boundedOutput) String() string {
	output := b.buffer.String()
	if b.truncated {
		output += "\n[output truncated]"
	}
	return output
}
