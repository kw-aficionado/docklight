package panel

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"
	"unicode"

	"example.com/yggdrasil-panel/internal/gameproto"
	gameskill "example.com/yggdrasil-panel/internal/rune"
	"github.com/go-chi/chi/v5"
)

func (a *App) serverQuery(w http.ResponseWriter, r *http.Request) {
	s, e := a.getServer(chi.URLParam(r, "id"))
	if e != nil {
		writeError(w, 404, "server not found")
		return
	}
	u := principal(r)
	if !a.requirePerm(w, u, s, "server.view") {
		return
	}
	if s.Status != "running" {
		writeError(w, 409, "start the server before querying player status")
		return
	}
	gs, e := a.loadRune(s.GameskillID)
	if e != nil || gs.Query == nil {
		writeError(w, 404, "this template does not define a player query protocol")
		return
	}
	port := s.Ports["game"]
	if (gs.Query.Type == "a2s" || gs.Query.Type == "source") && s.Ports["query"] != 0 {
		port = s.Ports["query"]
	}
	if port == 0 {
		writeError(w, 409, "this server has no allocated query or game port")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 4*time.Second)
	defer cancel()
	var result gameproto.Result
	switch gs.Query.Type {
	case "minecraft", "minecraft-java":
		result, e = gameproto.Minecraft(ctx, "127.0.0.1", port)
	case "minecraft-bedrock":
		result, e = gameproto.Bedrock(ctx, "127.0.0.1", port)
	case "a2s", "source":
		result, e = gameproto.A2S(ctx, "127.0.0.1", port)
	default:
		writeError(w, 400, "the template uses an unsupported query protocol")
		return
	}
	if e != nil {
		writeError(w, 502, e.Error())
		return
	}
	writeJSON(w, 200, result)
}

func (a *App) serverRCON(w http.ResponseWriter, r *http.Request) {
	s, e := a.getServer(chi.URLParam(r, "id"))
	if e != nil {
		writeError(w, 404, "server not found")
		return
	}
	u := principal(r)
	if !a.requirePerm(w, u, s, "server.console") {
		return
	}
	var in struct {
		Command string `json:"command"`
	}
	if decodeJSON(w, r, &in, 8*1024) != nil {
		return
	}
	command := collapseControl(in.Command)
	if command == "" || len(command) > 4096 {
		writeError(w, 400, "enter a command of 1 to 4096 characters")
		return
	}
	gs, e := a.loadRune(s.GameskillID)
	if e != nil || gs.RCON == nil || !gs.RCON.Enabled {
		writeError(w, 409, "RCON is not enabled by this template")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 8*time.Second)
	defer cancel()
	out, e := a.runRCON(ctx, s, gs, command)
	if e != nil {
		writeError(w, 502, e.Error())
		return
	}
	a.audit(u, "server.rcon", "server", s.ID, "")
	writeJSON(w, 200, map[string]string{"response": out})
}

func (a *App) runRCON(ctx context.Context, s Server, gs gameskill.Rune, command string) (string, error) {
	port := s.Ports["rcon"]
	if port == 0 {
		port = s.Ports["game"]
	}
	if port == 0 {
		return "", fmt.Errorf("server has no allocated RCON or game port")
	}
	env, err := a.runtimeEnv(s, gs)
	if err != nil {
		return "", err
	}
	password := env[gs.RCON.PasswordVar]
	if password == "" {
		return "", errors.New("the template's RCON password is empty; set it in server settings and restart")
	}
	return gameproto.SourceRCON(ctx, "127.0.0.1", port, password, command)
}

func (a *App) sendCommand(ctx context.Context, s Server, command string) (string, error) {
	if s.ContainerID == "" || s.Status != "running" {
		return "", errors.New("server is not running")
	}
	gs, err := a.loadRune(s.GameskillID)
	if err != nil {
		return "", err
	}
	if gs.RCON != nil && gs.RCON.Enabled {
		rctx, cancel := context.WithTimeout(ctx, 5*time.Second)
		response, e := a.runRCON(rctx, s, gs, command)
		cancel()
		if e == nil {
			return response, nil
		}
		if inputErr := a.engine.SendInput(ctx, s.ContainerID, command); inputErr != nil {
			return "", inputErr
		}
		return "RCON is not responding; command was sent to server input instead.", nil
	}
	if err = a.engine.SendInput(ctx, s.ContainerID, command); err != nil {
		return "", err
	}
	return "", nil
}

func collapseControl(s string) string {
	return strings.TrimSpace(strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return ' '
		}
		return r
	}, s))
}
