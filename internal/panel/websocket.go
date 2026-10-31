package panel

import (
	"bufio"
	"context"
	"crypto/sha1"
	"database/sql"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"example.com/yggdrasil-panel/internal/docker"
	"github.com/go-chi/chi/v5"
)

type wsConn struct {
	c  net.Conn
	r  *bufio.Reader
	mu sync.Mutex
}

func upgradeWS(w http.ResponseWriter, r *http.Request) (*wsConn, error) {
	if origin := r.Header.Get("Origin"); origin != "" {
		if !sameOrigin(r, origin) {
			return nil, errors.New("cross-origin WebSocket blocked")
		}
	}
	if !strings.Contains(strings.ToLower(r.Header.Get("Connection")), "upgrade") || !strings.EqualFold(r.Header.Get("Upgrade"), "websocket") {
		return nil, errors.New("WebSocket upgrade required")
	}
	key := r.Header.Get("Sec-WebSocket-Key")
	decoded, e := base64.StdEncoding.DecodeString(key)
	if e != nil || len(decoded) != 16 {
		return nil, errors.New("invalid WebSocket key")
	}
	h, ok := w.(http.Hijacker)
	if !ok {
		return nil, errors.New("WebSocket hijacking is unavailable")
	}
	c, brw, e := h.Hijack()
	if e != nil {
		return nil, e
	}
	sum := sha1.Sum([]byte(key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"))
	accept := base64.StdEncoding.EncodeToString(sum[:])
	_, e = fmt.Fprintf(brw, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: %s\r\n\r\n", accept)
	if e == nil {
		e = brw.Flush()
	}
	if e != nil {
		c.Close()
		return nil, e
	}
	return &wsConn{c: c, r: brw.Reader}, nil
}
func (c *wsConn) write(op byte, p []byte) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	head := []byte{0x80 | op}
	switch {
	case len(p) < 126:
		head = append(head, byte(len(p)))
	case len(p) <= 65535:
		head = append(head, 126, byte(len(p)>>8), byte(len(p)))
	default:
		head = append(head, 127, 0, 0, 0, 0, byte(len(p)>>24), byte(len(p)>>16), byte(len(p)>>8), byte(len(p)))
	}
	if _, e := c.c.Write(head); e != nil {
		return e
	}
	if len(p) == 0 {
		return nil
	}
	_, e := c.c.Write(p)
	return e
}
func (c *wsConn) text(s string) error { return c.write(1, []byte(s)) }
func (c *wsConn) ping() error         { return c.write(9, nil) }
func (c *wsConn) close()              { _ = c.write(8, nil); _ = c.c.Close() }
func (c *wsConn) read() (byte, []byte, error) {
	h := make([]byte, 2)
	if _, e := io.ReadFull(c.r, h); e != nil {
		return 0, nil, e
	}
	fin := h[0]&0x80 != 0
	op := h[0] & 0x0f
	masked := h[1]&0x80 != 0
	n := uint64(h[1] & 0x7f)
	if n == 126 {
		var b [2]byte
		if _, e := io.ReadFull(c.r, b[:]); e != nil {
			return 0, nil, e
		}
		n = uint64(binary.BigEndian.Uint16(b[:]))
	} else if n == 127 {
		var b [8]byte
		if _, e := io.ReadFull(c.r, b[:]); e != nil {
			return 0, nil, e
		}
		n = binary.BigEndian.Uint64(b[:])
	}
	if n > 1<<20 {
		return 0, nil, errors.New("WebSocket message exceeds 1 MiB")
	}
	var mask [4]byte
	if masked {
		if _, e := io.ReadFull(c.r, mask[:]); e != nil {
			return 0, nil, e
		}
	}
	payload := make([]byte, n)
	if _, e := io.ReadFull(c.r, payload); e != nil {
		return 0, nil, e
	}
	if masked {
		for i := range payload {
			payload[i] ^= mask[i%4]
		}
	}
	if !fin {
		return 0, nil, errors.New("fragmented WebSocket messages are not supported")
	}
	return op, payload, nil
}

func (a *App) logsWS(w http.ResponseWriter, r *http.Request) {
	s, e := a.getServer(chi.URLParam(r, "id"))
	if e != nil {
		http.Error(w, "server not found", 404)
		return
	}
	u := principal(r)
	if !a.requirePerm(w, u, s, "server.view") {
		return
	}
	a.streamLogs(w, r, s, false)
}
func (a *App) consoleWS(w http.ResponseWriter, r *http.Request) {
	s, e := a.getServer(chi.URLParam(r, "id"))
	if e != nil {
		http.Error(w, "server not found", 404)
		return
	}
	u := principal(r)
	if !a.requirePerm(w, u, s, "server.console") {
		return
	}
	a.streamLogs(w, r, s, true)
}

type stackServiceTargetError struct {
	status  int
	message string
}

func (e *stackServiceTargetError) Error() string { return e.message }

func (a *App) stackServiceLogTarget(ctx context.Context, s Server, serviceName string) (string, []string, error) {
	return a.stackServiceTarget(ctx, s, serviceName, false)
}

func (a *App) stackServiceExecTarget(ctx context.Context, s Server, serviceName string) (string, []string, error) {
	return a.stackServiceTarget(ctx, s, serviceName, true)
}

func (a *App) stackServiceTarget(ctx context.Context, s Server, serviceName string, requireRunning bool) (string, []string, error) {
	gs, err := a.loadRune(s.GameskillID)
	if err != nil {
		return "", nil, &stackServiceTargetError{status: http.StatusNotFound, message: "server template is unavailable"}
	}
	if gs.Stack == nil {
		return "", nil, &stackServiceTargetError{status: http.StatusNotFound, message: "server has no private services"}
	}
	found := false
	for _, service := range gs.Stack.Services {
		if service.Name == serviceName {
			found = true
			break
		}
	}
	if !found {
		return "", nil, &stackServiceTargetError{status: http.StatusNotFound, message: "private service not found"}
	}
	var containerID string
	if err = a.db.QueryRowContext(ctx, `SELECT container_id FROM server_sidecars WHERE server_id=? AND service_name=?`, s.ID, serviceName).Scan(&containerID); errors.Is(err, sql.ErrNoRows) || err == nil && containerID == "" {
		return "", nil, &stackServiceTargetError{status: http.StatusConflict, message: "private service has not started yet"}
	} else if err != nil {
		return "", nil, &stackServiceTargetError{status: http.StatusInternalServerError, message: "private service state could not be read"}
	}
	inspectCtx, cancel := context.WithTimeout(ctx, runtimeInspectTimeout)
	ins, inspectErr := a.engine.Inspect(inspectCtx, containerID)
	cancel()
	if docker.IsNotFound(inspectErr) {
		return "", nil, &stackServiceTargetError{status: http.StatusConflict, message: "Docker no longer has this private service container; restart the server stack"}
	}
	if inspectErr != nil {
		return "", nil, &stackServiceTargetError{status: http.StatusServiceUnavailable, message: "Docker could not inspect this private service; check Docker Engine and try again"}
	}
	labels := ins.Config.Labels
	if labels[docklightServerLabel] != s.ID || labels[docklightRoleLabel] != "sidecar" || labels[docklightServiceLabel] != serviceName {
		return "", nil, &stackServiceTargetError{status: http.StatusNotFound, message: "private service container ownership could not be verified"}
	}
	if requireRunning && !ins.State.Running {
		return "", nil, &stackServiceTargetError{status: http.StatusConflict, message: "private service must be running before commands can be sent"}
	}
	env, err := a.runtimeEnv(s, gs)
	if err != nil {
		return "", nil, &stackServiceTargetError{status: http.StatusInternalServerError, message: "server secrets could not be loaded for log redaction"}
	}
	return containerID, runeSecretValues(gs, env), nil
}

func (a *App) stackServiceLogsWS(w http.ResponseWriter, r *http.Request) {
	s, err := a.getServer(chi.URLParam(r, "id"))
	if err != nil {
		writeError(w, http.StatusNotFound, "server not found")
		return
	}
	if !a.requirePerm(w, principal(r), s, "server.view") {
		return
	}
	containerID, secrets, err := a.stackServiceLogTarget(r.Context(), s, chi.URLParam(r, "service"))
	if err != nil {
		var targetErr *stackServiceTargetError
		if errors.As(err, &targetErr) {
			writeError(w, targetErr.status, targetErr.message)
		} else {
			writeError(w, http.StatusInternalServerError, "could not prepare private service logs")
		}
		return
	}
	c, err := upgradeWS(w, r)
	if err != nil {
		return
	}
	defer c.close()
	ctx, cancel := context.WithCancel(r.Context())
	defer cancel()
	type event struct {
		line string
		err  error
		done bool
	}
	ch := make(chan event, 64)
	go func() {
		body, streamErr := a.engine.Logs(ctx, containerID, "2000", true)
		if streamErr != nil {
			ch <- event{err: streamErr, done: true}
			return
		}
		defer body.Close()
		writer := &wsLineWriter{secrets: secrets, send: func(line string) error {
			select {
			case ch <- event{line: line}:
				return nil
			case <-ctx.Done():
				return ctx.Err()
			}
		}}
		streamErr = docker.CopyLogs(writer, body)
		if streamErr == nil && writer.carry != "" {
			_ = writer.send(writer.carry)
		}
		ch <- event{err: streamErr, done: true}
	}()
	go func() {
		for {
			op, payload, readErr := c.read()
			if readErr != nil {
				cancel()
				return
			}
			switch op {
			case 8:
				cancel()
				return
			case 9:
				_ = c.write(10, payload)
			}
		}
	}()
	keepalive := time.NewTicker(30 * time.Second)
	defer keepalive.Stop()
	for {
		select {
		case item := <-ch:
			if item.line != "" {
				if err = c.text(item.line); err != nil {
					return
				}
			}
			if item.err != nil {
				message := redactSecrets(item.err.Error(), secrets)
				_ = c.text("Log stream ended: " + message)
				return
			}
			if item.done {
				return
			}
		case <-keepalive.C:
			if err = c.ping(); err != nil {
				return
			}
		case <-ctx.Done():
			return
		}
	}
}

func (a *App) streamLogs(w http.ResponseWriter, r *http.Request, s Server, console bool) {
	c, err := upgradeWS(w, r)
	if err != nil {
		return
	}
	defer c.close()
	if s.ContainerID == "" {
		_ = c.text("Server container is not available.")
		return
	}
	ctx, cancel := context.WithCancel(r.Context())
	defer cancel()
	gs, gsErr := a.loadRune(s.GameskillID)
	var secrets []string
	if gsErr == nil {
		if env, envErr := a.runtimeEnv(s, gs); envErr == nil {
			secrets = runeSecretValues(gs, env)
		}
	}
	type event struct {
		line string
		err  error
		done bool
	}
	ch := make(chan event, 64)
	go func() {
		body, err := a.engine.Logs(ctx, s.ContainerID, "2000", true)
		if err != nil {
			ch <- event{err: err, done: true}
			return
		}
		defer body.Close()
		writer := &wsLineWriter{secrets: secrets, send: func(line string) error {
			select {
			case ch <- event{line: line}:
				return nil
			case <-ctx.Done():
				return ctx.Err()
			}
		}}
		err = docker.CopyLogs(writer, body)
		if err == nil && writer.carry != "" {
			_ = writer.send(writer.carry)
		}
		ch <- event{err: err, done: true}
	}()
	go func() {
		for {
			op, payload, readErr := c.read()
			if readErr != nil {
				cancel()
				return
			}
			switch op {
			case 8:
				cancel()
				return
			case 9:
				_ = c.write(10, payload)
			case 1:
				if !console {
					continue
				}
				var msg struct {
					Command string `json:"command"`
				}
				command := string(payload)
				if json.Unmarshal(payload, &msg) == nil && msg.Command != "" {
					command = msg.Command
				}
				command = strings.TrimSpace(command)
				if command == "" {
					continue
				}
				if len(command) > 4096 {
					_ = c.text("Command is longer than 4096 characters.")
					continue
				}
				response, sendErr := a.sendCommand(ctx, s, command)
				if sendErr != nil {
					_ = c.text("Command could not be sent: " + sendErr.Error())
				} else if response != "" {
					_ = c.text(response)
				}
			}
		}
	}()
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case ev := <-ch:
			if ev.line != "" {
				if err := c.text(ev.line); err != nil {
					return
				}
			}
			if ev.err != nil {
				_ = c.text("Log stream ended: " + ev.err.Error())
				return
			}
			if ev.done {
				return
			}
		case <-ticker.C:
			if c.ping() != nil {
				return
			}
		case <-ctx.Done():
			return
		}
	}
}

type wsLineWriter struct {
	send    func(string) error
	carry   string
	secrets []string
}

func (w *wsLineWriter) Write(p []byte) (int, error) {
	s := w.carry + string(p)
	lines := strings.Split(s, "\n")
	w.carry = lines[len(lines)-1]
	for _, line := range lines[:len(lines)-1] {
		line = strings.TrimSuffix(line, "\r")
		if line != "" {
			line = redactSecrets(line, w.secrets)
			if err := w.send(line); err != nil {
				return 0, err
			}
		}
	}
	return len(p), nil
}

func (a *App) installWS(w http.ResponseWriter, r *http.Request) {
	s, e := a.getServer(chi.URLParam(r, "id"))
	if e != nil {
		http.Error(w, "server not found", 404)
		return
	}
	u := principal(r)
	if !a.requirePerm(w, u, s, "server.view") {
		return
	}
	a.jobsMu.RLock()
	j := a.jobs[s.ID]
	a.jobsMu.RUnlock()
	c, e := upgradeWS(w, r)
	if e != nil {
		return
	}
	defer c.close()
	if j == nil {
		_ = c.text("No install output is available.")
		return
	}
	sent := 0
	ticker := time.NewTicker(200 * time.Millisecond)
	defer ticker.Stop()
	keep := time.NewTicker(30 * time.Second)
	defer keep.Stop()
	for {
		j.mu.Lock()
		lines := append([]string(nil), j.lines...)
		done := j.done
		j.mu.Unlock()
		for sent < len(lines) {
			if c.text(lines[sent]) != nil {
				return
			}
			sent++
		}
		if done {
			return
		}
		select {
		case <-ticker.C:
		case <-keep.C:
			if c.ping() != nil {
				return
			}
		case <-r.Context().Done():
			return
		}
	}
}
