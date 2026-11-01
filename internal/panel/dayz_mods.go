package panel

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	gameskill "example.com/yggdrasil-panel/internal/rune"
	"example.com/yggdrasil-panel/internal/security"
	"github.com/go-chi/chi/v5"
)

const (
	dayzWorkshopAppID     = 221100
	dayzMaxModCount       = 256
	dayzMaxWorkshopBatch  = 256
	dayzMaxWorkshopResult = 2 << 20
	dayzSteamKeyMask      = "••••••••••••"
)

var (
	dayzModTokenPattern = regexp.MustCompile(`^@?[A-Za-z0-9_-][A-Za-z0-9._-]{0,119}$`)
	dayzWorkshopID      = regexp.MustCompile(`^[0-9]{1,20}$`)
	dayzSteamKeyPattern = regexp.MustCompile(`^[A-Fa-f0-9]{32}$`)
)

type dayzMod struct {
	Token          string `json:"token"`
	ID             string `json:"id,omitempty"`
	OnDisk         bool   `json:"on_disk"`
	WorkshopStatus string `json:"workshop_status"`
	Title          string `json:"title,omitempty"`
}

type dayzModFolder struct {
	Token string `json:"token"`
	Name  string `json:"name"`
}

type dayzModsSummary struct {
	Supported           bool            `json:"supported"`
	Message             string          `json:"message,omitempty"`
	Mods                []dayzMod       `json:"mods"`
	Orphans             []dayzModFolder `json:"orphans"`
	OrphansTruncated    bool            `json:"orphans_truncated"`
	WorkshopUnavailable bool            `json:"workshop_unavailable"`
	RequiresUpdate      bool            `json:"requires_update"`
	ServerStatus        string          `json:"server_status"`
}

type dayzWorkshopItem struct {
	ID     string
	Result int
	Title  string
}

func (a *App) dayzModsContext(w http.ResponseWriter, r *http.Request, permission string) (Server, gameskill.Rune, map[string]string, string, bool, bool) {
	server, err := a.getServer(chi.URLParam(r, "id"))
	if err != nil {
		writeError(w, http.StatusNotFound, "server not found")
		return Server{}, gameskill.Rune{}, nil, "", false, false
	}
	if !a.allowedServer(principal(r), permission, server.ID, server.GameskillID, server.RealmID) {
		writeError(w, http.StatusForbidden, permission+" permission is required")
		return Server{}, gameskill.Rune{}, nil, "", false, false
	}
	if server.GameskillID != "dayz" {
		writeError(w, http.StatusNotFound, "DayZ mods are available only for servers using the dayz template")
		return Server{}, gameskill.Rune{}, nil, "", false, false
	}
	gs, err := a.loadRune(server.GameskillID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "DayZ template is unavailable")
		return Server{}, gameskill.Rune{}, nil, "", false, false
	}
	env, err := a.runtimeEnv(server, gs)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "DayZ server settings could not be read")
		return Server{}, gameskill.Rune{}, nil, "", false, false
	}
	root, err := a.serverFilesRoot(server)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not resolve the DayZ server data directory")
		return Server{}, gameskill.Rune{}, nil, "", false, false
	}
	supported := false
	for _, variable := range gs.Variables {
		if variable.Key == "MODS" {
			supported = true
			break
		}
	}
	return server, gs, env, root, supported, true
}

func (a *App) getDayZMods(w http.ResponseWriter, r *http.Request) {
	server, _, env, root, supported, ok := a.dayzModsContext(w, r, "server.view")
	if !ok {
		return
	}
	summary := a.buildDayZModsSummary(r.Context(), server, env, root, supported)
	writeJSON(w, http.StatusOK, summary)
}

func (a *App) buildDayZModsSummary(parent context.Context, server Server, env map[string]string, root string, supported bool) dayzModsSummary {
	summary := dayzModsSummary{Supported: supported, Mods: []dayzMod{}, Orphans: []dayzModFolder{}, ServerStatus: server.Status, RequiresUpdate: true}
	if !supported {
		summary.Message = "This DayZ template does not declare a MODS setting; choose a compatible template to manage load order."
	}
	tokens := parseDayZModTokens(env["MODS"])
	if len(tokens) > dayzMaxModCount {
		tokens = tokens[:dayzMaxModCount]
		summary.Message = "Only the first 256 MODS entries are shown; reduce the template setting before changing this list."
		supported = false
		summary.Supported = false
	}
	for _, token := range tokens {
		mod := dayzMod{Token: token, WorkshopStatus: "unknown"}
		if id, ok := dayzModWorkshopID(token); ok {
			mod.ID = id
		}
		mod.OnDisk = dayzModFolderExists(root, token)
		summary.Mods = append(summary.Mods, mod)
	}
	orphans, truncated := findDayZModOrphans(root, tokens)
	summary.Orphans = orphans
	summary.OrphansTruncated = truncated
	if len(summary.Mods) == 0 {
		return summary
	}
	ids := make([]string, 0, len(summary.Mods))
	seenIDs := map[string]bool{}
	for _, mod := range summary.Mods {
		if mod.ID != "" && !seenIDs[mod.ID] {
			ids = append(ids, mod.ID)
			seenIDs[mod.ID] = true
		}
	}
	if len(ids) == 0 {
		return summary
	}
	if len(ids) > dayzMaxWorkshopBatch {
		summary.WorkshopUnavailable = true
		return summary
	}
	items, err := lookupDayZWorkshopItems(parent, ids)
	if err != nil {
		summary.WorkshopUnavailable = true
		return summary
	}
	byID := make(map[string]dayzWorkshopItem, len(items))
	for _, item := range items {
		byID[item.ID] = item
	}
	for i := range summary.Mods {
		if summary.Mods[i].ID == "" {
			summary.WorkshopUnavailable = true
			continue
		}
		item, found := byID[summary.Mods[i].ID]
		if !found {
			summary.WorkshopUnavailable = true
			continue
		}
		switch item.Result {
		case 1:
			summary.Mods[i].WorkshopStatus = "available"
		case 9:
			summary.Mods[i].WorkshopStatus = "removed"
		default:
			summary.WorkshopUnavailable = true
		}
		summary.Mods[i].Title = item.Title
	}
	return summary
}

func parseDayZModTokens(raw string) []string {
	fields := strings.FieldsFunc(raw, func(char rune) bool {
		return char == ';' || char == ',' || char == ' ' || char == '\t' || char == '\r' || char == '\n'
	})
	seen := map[string]bool{}
	out := make([]string, 0, len(fields))
	for _, item := range fields {
		token := strings.TrimSpace(item)
		if token == "" || seen[token] {
			continue
		}
		seen[token] = true
		out = append(out, token)
	}
	return out
}

func validateDayZModToken(token string) error {
	if !dayzModTokenPattern.MatchString(token) {
		return errors.New("mod entries must be a folder name or Workshop ID without spaces or path separators")
	}
	return nil
}

func dayzModWorkshopID(token string) (string, bool) {
	id := strings.TrimPrefix(token, "@")
	if !dayzWorkshopID.MatchString(id) {
		return "", false
	}
	parsed, err := strconv.ParseUint(id, 10, 64)
	if err != nil {
		return "", false
	}
	return strconv.FormatUint(parsed, 10), true
}

func dayzModFolderName(token string) string {
	if strings.HasPrefix(token, "@") {
		return token
	}
	return "@" + token
}

func dayzModFolderExists(root, token string) bool {
	if validateDayZModToken(token) != nil {
		return false
	}
	full := filepath.Join(root, dayzModFolderName(token))
	info, err := os.Lstat(full)
	return err == nil && info.IsDir() && info.Mode()&os.ModeSymlink == 0
}

func findDayZModOrphans(root string, tokens []string) ([]dayzModFolder, bool) {
	known := make(map[string]bool, len(tokens))
	for _, token := range tokens {
		known[dayzModFolderName(token)] = true
	}
	directory, err := os.Open(root)
	if err != nil {
		return []dayzModFolder{}, false
	}
	defer directory.Close()
	entries, readErr := directory.ReadDir(10001)
	truncated := len(entries) > 10000
	if truncated {
		entries = entries[:10000]
	}
	orphans := make([]dayzModFolder, 0)
	for _, entry := range entries {
		name := entry.Name()
		if !strings.HasPrefix(name, "@") || len(name) < 2 || len(name) > 121 || known[name] || !entry.IsDir() || entry.Type()&os.ModeSymlink != 0 {
			continue
		}
		token := name
		if validateDayZModToken(token) != nil {
			continue
		}
		orphans = append(orphans, dayzModFolder{Token: token, Name: strings.TrimPrefix(name, "@")})
	}
	if readErr != nil && !errors.Is(readErr, io.EOF) {
		return []dayzModFolder{}, false
	}
	sort.Slice(orphans, func(i, j int) bool { return strings.ToLower(orphans[i].Token) < strings.ToLower(orphans[j].Token) })
	return orphans, truncated
}

func lookupDayZWorkshopItems(parent context.Context, ids []string) ([]dayzWorkshopItem, error) {
	if len(ids) == 0 || len(ids) > dayzMaxWorkshopBatch {
		return nil, errors.New("Workshop status batch is outside the supported range")
	}
	form := url.Values{}
	form.Set("itemcount", strconv.Itoa(len(ids)))
	for index, id := range ids {
		form.Set(fmt.Sprintf("publishedfileids[%d]", index), id)
	}
	ctx, cancel := context.WithTimeout(parent, 6*time.Second)
	defer cancel()
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://api.steampowered.com/ISteamRemoteStorage/GetPublishedFileDetails/v1/", strings.NewReader(form.Encode()))
	if err != nil {
		return nil, errors.New("could not prepare the Steam Workshop status request")
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	response, err := newDayZSteamHTTPClient().Do(request)
	if err != nil {
		return nil, errors.New("Steam Workshop status could not be reached")
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return nil, errors.New("Steam Workshop status returned an unsuccessful response")
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, dayzMaxWorkshopResult+1))
	if err != nil || len(body) > dayzMaxWorkshopResult {
		return nil, errors.New("Steam Workshop status returned an invalid or oversized response")
	}
	var decoded struct {
		Response struct {
			Items []struct {
				ID     string `json:"publishedfileid"`
				Result int    `json:"result"`
				Title  string `json:"title"`
			} `json:"publishedfiledetails"`
		} `json:"response"`
	}
	if err = json.Unmarshal(body, &decoded); err != nil {
		return nil, errors.New("Steam Workshop status returned invalid JSON")
	}
	items := make([]dayzWorkshopItem, 0, len(decoded.Response.Items))
	for _, item := range decoded.Response.Items {
		title := strings.TrimSpace(item.Title)
		if len(title) > 160 {
			title = title[:160]
		}
		items = append(items, dayzWorkshopItem{ID: item.ID, Result: item.Result, Title: title})
	}
	return items, nil
}

func newDayZSteamHTTPClient() *http.Client {
	return &http.Client{
		Timeout: 6 * time.Second,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

func (a *App) reorderDayZMods(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Mods []string `json:"mods"`
	}
	if decodeJSON(w, r, &in, 64*1024) != nil {
		return
	}
	if err := validateDayZModTokens(in.Mods); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	a.dataMu.Lock()
	defer a.dataMu.Unlock()
	server, gs, env, _, supported, ok := a.dayzModsContext(w, r, "server.control")
	if !ok {
		return
	}
	if !supported {
		writeError(w, http.StatusConflict, "this DayZ template does not declare a MODS setting")
		return
	}
	current := parseDayZModTokens(env["MODS"])
	if len(current) > dayzMaxModCount || !sameDayZModPermutation(current, in.Mods) {
		writeError(w, http.StatusConflict, "mod order must be a permutation of the current MODS list; refresh the page and try again")
		return
	}
	if err := a.saveDayZModTokens(r.Context(), server, gs, env, in.Mods); err != nil {
		writeError(w, http.StatusInternalServerError, "could not save the DayZ MODS setting")
		return
	}
	a.audit(principal(r), "dayz.mods.order", "server", server.ID, fmt.Sprintf("mods=%d", len(in.Mods)))
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "mods": in.Mods, "requires_update": true})
}

func (a *App) addDayZMods(w http.ResponseWriter, r *http.Request) {
	var in struct {
		IDs []string `json:"ids"`
	}
	if decodeJSON(w, r, &in, 32*1024) != nil {
		return
	}
	if len(in.IDs) == 0 || len(in.IDs) > 128 {
		writeError(w, http.StatusBadRequest, "select between 1 and 128 Workshop items")
		return
	}
	ids := make([]string, 0, len(in.IDs))
	seen := map[string]bool{}
	for _, raw := range in.IDs {
		id := strings.TrimSpace(raw)
		if !dayzWorkshopID.MatchString(id) {
			writeError(w, http.StatusBadRequest, "Workshop IDs must contain digits only")
			return
		}
		parsedID, err := strconv.ParseUint(id, 10, 64)
		if err != nil {
			writeError(w, http.StatusBadRequest, "Workshop ID is outside the supported range")
			return
		}
		id = strconv.FormatUint(parsedID, 10)
		if !seen[id] {
			seen[id] = true
			ids = append(ids, id)
		}
	}
	a.dataMu.Lock()
	defer a.dataMu.Unlock()
	server, gs, env, _, supported, ok := a.dayzModsContext(w, r, "server.control")
	if !ok {
		return
	}
	if !supported {
		writeError(w, http.StatusConflict, "this DayZ template does not declare a MODS setting")
		return
	}
	current := parseDayZModTokens(env["MODS"])
	next := append([]string(nil), current...)
	currentSet := make(map[string]bool, len(current))
	for _, token := range current {
		currentSet[token] = true
	}
	for _, id := range ids {
		token := "@" + id
		if !currentSet[token] && !dayzModIDInList(current, id) {
			if len(next) >= dayzMaxModCount {
				writeError(w, http.StatusBadRequest, "a DayZ MODS list can contain at most 256 entries")
				return
			}
			next = append(next, token)
			currentSet[token] = true
		}
	}
	if len(next) == len(current) {
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "mods": current, "requires_update": true})
		return
	}
	if err := a.saveDayZModTokens(r.Context(), server, gs, env, next); err != nil {
		writeError(w, http.StatusInternalServerError, "could not save the DayZ MODS setting")
		return
	}
	a.audit(principal(r), "dayz.mods.add", "server", server.ID, fmt.Sprintf("mods=%d", len(ids)))
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "mods": next, "requires_update": true})
}

func (a *App) removeDayZMod(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Token string `json:"token"`
	}
	if decodeJSON(w, r, &in, 4096) != nil {
		return
	}
	if err := validateDayZModToken(in.Token); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	a.dataMu.Lock()
	defer a.dataMu.Unlock()
	server, gs, env, _, supported, ok := a.dayzModsContext(w, r, "server.control")
	if !ok {
		return
	}
	if !supported {
		writeError(w, http.StatusConflict, "this DayZ template does not declare a MODS setting")
		return
	}
	current := parseDayZModTokens(env["MODS"])
	next := make([]string, 0, len(current))
	removed := false
	for _, token := range current {
		if token == in.Token {
			removed = true
			continue
		}
		next = append(next, token)
	}
	if !removed {
		writeError(w, http.StatusNotFound, "that mod is no longer in the MODS list; refresh the page")
		return
	}
	if err := validateDayZModTokens(next); err != nil {
		writeError(w, http.StatusBadRequest, "the remaining MODS values are not valid for this template")
		return
	}
	env["MODS"] = strings.Join(next, ";")
	if err := gs.ValidateEnv(env); err != nil {
		writeError(w, http.StatusBadRequest, "the remaining MODS values are not valid for this template")
		return
	}
	if err := a.saveDayZModTokens(r.Context(), server, gs, env, next); err != nil {
		writeError(w, http.StatusInternalServerError, "could not save the DayZ MODS setting")
		return
	}
	a.audit(principal(r), "dayz.mods.remove", "server", server.ID, "one entry removed")
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "mods": next, "requires_update": true})
}

func (a *App) addDayZModOrphans(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Tokens []string `json:"tokens"`
	}
	if decodeJSON(w, r, &in, 32*1024) != nil {
		return
	}
	if len(in.Tokens) == 0 || len(in.Tokens) > 128 {
		writeError(w, http.StatusBadRequest, "select between 1 and 128 mod folders")
		return
	}
	for _, token := range in.Tokens {
		if err := validateDayZModToken(token); err != nil || !strings.HasPrefix(token, "@") {
			writeError(w, http.StatusBadRequest, "only valid @mod folders can be added")
			return
		}
	}
	a.dataMu.Lock()
	defer a.dataMu.Unlock()
	server, gs, env, root, supported, ok := a.dayzModsContext(w, r, "server.control")
	if !ok {
		return
	}
	if !supported {
		writeError(w, http.StatusConflict, "this DayZ template does not declare a MODS setting")
		return
	}
	current := parseDayZModTokens(env["MODS"])
	orphans, _ := findDayZModOrphans(root, current)
	available := map[string]bool{}
	for _, orphan := range orphans {
		available[orphan.Token] = true
	}
	currentSet := map[string]bool{}
	for _, token := range current {
		currentSet[token] = true
	}
	next := append([]string(nil), current...)
	for _, token := range in.Tokens {
		if !available[token] || !dayzModFolderExists(root, token) {
			writeError(w, http.StatusConflict, "a selected orphan folder is no longer available; refresh the mod list")
			return
		}
		if !currentSet[token] && !dayzModEquivalentInList(current, token) {
			if len(next) >= dayzMaxModCount {
				writeError(w, http.StatusBadRequest, "a DayZ MODS list can contain at most 256 entries")
				return
			}
			next = append(next, token)
			currentSet[token] = true
		}
	}
	if len(next) == len(current) {
		writeError(w, http.StatusBadRequest, "all selected folders are already in the MODS list")
		return
	}
	if err := a.saveDayZModTokens(r.Context(), server, gs, env, next); err != nil {
		writeError(w, http.StatusInternalServerError, "could not save the DayZ MODS setting")
		return
	}
	a.audit(principal(r), "dayz.mods.add_orphans", "server", server.ID, fmt.Sprintf("folders=%d", len(next)-len(current)))
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "mods": next, "requires_update": true})
}

func (a *App) removeBrokenDayZMods(w http.ResponseWriter, r *http.Request) {
	server, _, env, root, supported, ok := a.dayzModsContext(w, r, "server.control")
	if !ok {
		return
	}
	if !supported {
		writeError(w, http.StatusConflict, "this DayZ template does not declare a MODS setting")
		return
	}
	if !server.Installed {
		writeError(w, http.StatusConflict, "install the server before checking which mods are on disk")
		return
	}
	current := parseDayZModTokens(env["MODS"])
	if len(current) > dayzMaxModCount {
		writeError(w, http.StatusConflict, "the current MODS list exceeds 256 entries; reduce it in server settings first")
		return
	}
	summary := a.buildDayZModsSummary(r.Context(), server, env, root, supported)
	remove := map[string]bool{}
	for _, mod := range summary.Mods {
		if mod.WorkshopStatus == "removed" {
			remove[mod.Token] = true
		}
	}
	if len(remove) == 0 {
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "removed": 0, "requires_update": false})
		return
	}
	next := make([]string, 0, len(current)-len(remove))
	for _, token := range current {
		if !remove[token] {
			next = append(next, token)
		}
	}
	if err := a.saveDayZModListExpected(w, r, current, next); err != nil {
		return
	}
	a.audit(principal(r), "dayz.mods.remove_broken", "server", server.ID, fmt.Sprintf("mods=%d", len(remove)))
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "removed": len(remove), "requires_update": true})
}

func (a *App) saveDayZModListExpected(w http.ResponseWriter, r *http.Request, expected, next []string) error {
	a.dataMu.Lock()
	defer a.dataMu.Unlock()
	server, gs, env, _, supported, ok := a.dayzModsContext(w, r, "server.control")
	if !ok {
		return errors.New("server access changed")
	}
	current := parseDayZModTokens(env["MODS"])
	if !supported || !sameDayZModTokens(current, expected) {
		writeError(w, http.StatusConflict, "the DayZ MODS list changed while checking Workshop status; refresh the page")
		return errors.New("MODS list changed")
	}
	if err := a.saveDayZModTokens(r.Context(), server, gs, env, next); err != nil {
		writeError(w, http.StatusInternalServerError, "could not save the DayZ MODS setting")
		return err
	}
	return nil
}

func (a *App) saveDayZModTokens(ctx context.Context, server Server, gs gameskill.Rune, env map[string]string, tokens []string) error {
	if err := validateDayZModTokens(tokens); err != nil {
		return err
	}
	if len(tokens) > dayzMaxModCount {
		return errors.New("DayZ MODS list exceeds 256 entries")
	}
	env["MODS"] = strings.Join(tokens, ";")
	if err := gs.ValidateEnv(env); err != nil {
		return fmt.Errorf("MODS setting is not valid for this template: %w", err)
	}
	cipherMap := make(map[string]string, len(gs.Variables))
	secret := secretVariables(gs)
	for _, variable := range gs.Variables {
		value, exists := env[variable.Key]
		if !exists {
			continue
		}
		if secret[variable.Key] {
			encrypted, err := security.Encrypt([]byte(a.cfg.Auth.SecretKey), value)
			if err != nil {
				return err
			}
			cipherMap[variable.Key] = encrypted
		} else {
			cipherMap[variable.Key] = value
		}
	}
	encoded, err := json.Marshal(cipherMap)
	if err != nil {
		return err
	}
	_, err = a.db.ExecContext(ctx, `UPDATE servers SET env_json=?,updated_at=CURRENT_TIMESTAMP WHERE id=?`, string(encoded), server.ID)
	return err
}

func validateDayZModTokens(tokens []string) error {
	if len(tokens) > dayzMaxModCount {
		return errors.New("a DayZ MODS list can contain at most 256 entries")
	}
	seen := map[string]bool{}
	for _, token := range tokens {
		if err := validateDayZModToken(token); err != nil {
			return err
		}
		key := "token:" + token
		if id, ok := dayzModWorkshopID(token); ok {
			key = "id:" + id
		}
		if seen[key] {
			return errors.New("a DayZ MODS list cannot contain duplicate entries")
		}
		seen[key] = true
	}
	return nil
}

func dayzModIDInList(tokens []string, id string) bool {
	for _, token := range tokens {
		if existingID, ok := dayzModWorkshopID(token); ok && existingID == id {
			return true
		}
	}
	return false
}

func dayzModEquivalentInList(tokens []string, token string) bool {
	if id, ok := dayzModWorkshopID(token); ok {
		return dayzModIDInList(tokens, id)
	}
	for _, existing := range tokens {
		if existing == token {
			return true
		}
	}
	return false
}

func sameDayZModPermutation(current, requested []string) bool {
	return sameDayZModTokens(current, requested)
}

func sameDayZModTokens(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	counts := map[string]int{}
	for _, token := range left {
		counts[token]++
	}
	for _, token := range right {
		counts[token]--
	}
	for _, count := range counts {
		if count != 0 {
			return false
		}
	}
	return true
}

func (a *App) readDayZSteamAPIKey() (string, error) {
	var encrypted string
	err := a.db.QueryRow(`SELECT api_key_enc FROM dayz_steam_settings WHERE id=1`).Scan(&encrypted)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	if encrypted == "" {
		return "", nil
	}
	key, err := security.Decrypt([]byte(a.cfg.Auth.SecretKey), encrypted)
	if err != nil {
		return "", errors.New("the saved Steam Web API key cannot be decrypted; check auth.secret_key")
	}
	return key, nil
}

func (a *App) getDayZSteamKey(w http.ResponseWriter, _ *http.Request) {
	key, err := a.readDayZSteamAPIKey()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"has_key": key != ""})
}

func (a *App) updateDayZSteamKey(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Key string `json:"key"`
	}
	if decodeJSON(w, r, &in, 8*1024) != nil {
		return
	}
	key := strings.TrimSpace(in.Key)
	if key == dayzSteamKeyMask || key == "********" {
		saved, err := a.readDayZSteamAPIKey()
		if err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		writeJSON(w, http.StatusOK, map[string]bool{"has_key": saved != ""})
		return
	}
	if key != "" && !dayzSteamKeyPattern.MatchString(key) {
		writeError(w, http.StatusBadRequest, "Steam Web API key must be a 32-character hexadecimal key")
		return
	}
	encrypted := ""
	if key != "" {
		var err error
		encrypted, err = security.Encrypt([]byte(a.cfg.Auth.SecretKey), key)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "could not encrypt Steam Web API key")
			return
		}
	}
	if _, err := a.db.ExecContext(r.Context(), `INSERT INTO dayz_steam_settings(id,api_key_enc,updated_at) VALUES(1,?,CURRENT_TIMESTAMP) ON CONFLICT(id) DO UPDATE SET api_key_enc=excluded.api_key_enc,updated_at=CURRENT_TIMESTAMP`, encrypted); err != nil {
		writeError(w, http.StatusInternalServerError, "could not save Steam Web API key")
		return
	}
	a.audit(principal(r), "dayz.steam_key.update", "settings", "dayz", "")
	writeJSON(w, http.StatusOK, map[string]bool{"has_key": key != ""})
}

func (a *App) getDayZModsSearch(w http.ResponseWriter, r *http.Request) {
	if _, _, _, _, _, ok := a.dayzModsContext(w, r, "server.view"); !ok {
		return
	}
	query := strings.TrimSpace(r.URL.Query().Get("q"))
	if len(query) < 2 || len(query) > 80 || strings.ContainsAny(query, "\r\n\x00") {
		writeError(w, http.StatusBadRequest, "search text must contain 2–80 characters")
		return
	}
	key, err := a.readDayZSteamAPIKey()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "the saved Steam API key could not be read; check panel encryption settings")
		return
	}
	if key == "" {
		writeJSON(w, http.StatusOK, map[string]any{"needs_key": true, "results": []any{}})
		return
	}
	results, err := searchDayZWorkshop(r.Context(), query, key)
	if err != nil {
		writeError(w, http.StatusBadGateway, "Steam Workshop search failed; check the saved API key and panel network access")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"needs_key": false, "results": results})
}

func searchDayZWorkshop(parent context.Context, query, key string) ([]map[string]string, error) {
	input, err := json.Marshal(map[string]any{
		"query_type":               12,
		"page":                     1,
		"numperpage":               20,
		"appid":                    dayzWorkshopAppID,
		"search_text":              query,
		"filetype":                 0,
		"return_tags":              false,
		"return_previews":          false,
		"return_short_description": true,
		"return_vote_data":         false,
		"return_kv_tags":           false,
		"return_children":          false,
		"return_for_sale_data":     false,
		"return_playtime_stats":    0,
		"totalonly":                false,
		"ids_only":                 false,
		"requiredtags":             "",
		"required_flags":           "",
		"omitted_flags":            "",
	})
	if err != nil {
		return nil, errors.New("could not encode Workshop search")
	}
	u, _ := url.Parse("https://api.steampowered.com/IPublishedFileService/QueryFiles/v1/")
	queryValues := u.Query()
	queryValues.Set("key", key)
	queryValues.Set("input_json", string(input))
	u.RawQuery = queryValues.Encode()
	ctx, cancel := context.WithTimeout(parent, 6*time.Second)
	defer cancel()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, errors.New("could not prepare Workshop search")
	}
	response, err := newDayZSteamHTTPClient().Do(request)
	if err != nil {
		return nil, errors.New("Steam Workshop search could not be reached")
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return nil, errors.New("Steam Workshop search returned an unsuccessful response")
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, dayzMaxWorkshopResult+1))
	if err != nil || len(body) > dayzMaxWorkshopResult {
		return nil, errors.New("Steam Workshop search returned an invalid or oversized response")
	}
	var decoded struct {
		Response struct {
			Items []struct {
				ID            string `json:"publishedfileid"`
				Title         string `json:"title"`
				Description   string `json:"short_description"`
				ConsumerAppID int    `json:"consumer_app_id"`
			} `json:"publishedfiledetails"`
		} `json:"response"`
	}
	if err = json.Unmarshal(body, &decoded); err != nil {
		return nil, errors.New("Steam Workshop search returned invalid JSON")
	}
	results := make([]map[string]string, 0, len(decoded.Response.Items))
	seen := map[string]bool{}
	for _, item := range decoded.Response.Items {
		if item.ConsumerAppID != dayzWorkshopAppID || !dayzWorkshopID.MatchString(item.ID) || seen[item.ID] {
			continue
		}
		if _, err = strconv.ParseUint(item.ID, 10, 64); err != nil {
			continue
		}
		seen[item.ID] = true
		title := cleanModerationText(item.Title, 160)
		description := cleanModerationText(item.Description, 320)
		results = append(results, map[string]string{"id": item.ID, "title": title, "description": description})
		if len(results) == 20 {
			break
		}
	}
	return results, nil
}
