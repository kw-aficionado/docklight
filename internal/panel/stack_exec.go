package panel

import (
	"context"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"example.com/yggdrasil-panel/internal/docker"
	"github.com/go-chi/chi/v5"
)

const stackCommandLimit = 4096
const stackCommandOutputLimit = 64 * 1024

type stackCommandRequest struct {
	Command string `json:"command"`
}

func (a *App) execStackService(w http.ResponseWriter, r *http.Request) {
	s, err := a.getServer(chi.URLParam(r, "id"))
	if err != nil {
		writeError(w, http.StatusNotFound, "server not found")
		return
	}
	user := principal(r)
	if !a.requirePerm(w, user, s, "server.console") {
		return
	}
	var input stackCommandRequest
	if decodeJSON(w, r, &input, 8*1024) != nil {
		return
	}
	input.Command = strings.TrimSpace(input.Command)
	if input.Command == "" {
		writeError(w, http.StatusBadRequest, "enter a command to run")
		return
	}
	if len(input.Command) > stackCommandLimit {
		writeError(w, http.StatusBadRequest, "command is longer than 4096 characters")
		return
	}
	if strings.ContainsAny(input.Command, "\r\n\x00") {
		writeError(w, http.StatusBadRequest, "commands must be a single line")
		return
	}
	serviceName := chi.URLParam(r, "service")
	containerID, secrets, err := a.stackServiceExecTarget(r.Context(), s, serviceName)
	if err != nil {
		var targetErr *stackServiceTargetError
		if errors.As(err, &targetErr) {
			writeError(w, targetErr.status, targetErr.message)
		} else {
			writeError(w, http.StatusInternalServerError, "could not prepare private service command")
		}
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	result, err := a.engine.RunExec(ctx, containerID, []string{"/bin/sh", "-c", input.Command}, stackCommandOutputLimit)
	if err != nil {
		a.audit(user, "server.stack.command", "server", s.ID, "service="+serviceName+" outcome=failed")
		if errors.Is(err, context.DeadlineExceeded) {
			writeError(w, http.StatusGatewayTimeout, "command did not finish within 30 seconds; check whether it is still running in the container")
			return
		}
		if docker.IsNotFound(err) {
			writeError(w, http.StatusConflict, "private service stopped before the command could finish; refresh the stack and try again")
			return
		}
		var dockerErr *docker.APIError
		if errors.As(err, &dockerErr) && dockerErr.StatusCode == http.StatusConflict {
			writeError(w, http.StatusConflict, "private service rejected the command; confirm that it is running and provides /bin/sh")
			return
		}
		writeError(w, http.StatusBadGateway, "private service command failed; confirm the service is running and its image provides /bin/sh")
		return
	}
	output := redactSecrets(result.Output, secrets)
	a.audit(user, "server.stack.command", "server", s.ID, "service="+serviceName+" exit_code="+strconv.Itoa(result.ExitCode))
	writeJSON(w, http.StatusOK, map[string]any{
		"service":   serviceName,
		"output":    output,
		"exit_code": result.ExitCode,
		"success":   result.ExitCode == 0,
	})
}
