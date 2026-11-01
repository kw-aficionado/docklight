package panel

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"syscall"

	"github.com/go-chi/chi/v5"
)

const (
	dayzMaxXMLBytes        = 8 << 20
	dayzMaxMissionScanSize = 128 << 20
)

var (
	dayzMissionPattern = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,96}$`)
	dayzLifetimeText   = regexp.MustCompile(`^\s*([0-9]+)\s*$`)
	dayzGlobalNames    = map[string]bool{
		"CleanupLifetimeDefault":      true,
		"CleanupLifetimeRuined":       true,
		"CleanupLifetimeDeployed":     true,
		"CleanupLifetimeDeadPlayer":   true,
		"CleanupLifetimeLimit":        true,
		"CleanupLifetimeDeadAnimal":   true,
		"CleanupLifetimeDeadInfected": true,
	}
)

type dayzEconomyState struct {
	MinLifetimeHours int            `json:"min_lifetime_hours"`
	Globals          map[string]int `json:"globals"`
	RegisteredFiles  []string       `json:"registered_files"`
}

type dayzTypeFile struct {
	Path                  string  `json:"path"`
	TypeCount             int     `json:"type_count"`
	ShortestLifetimeHours float64 `json:"shortest_lifetime_hours,omitempty"`
	Modded                bool    `json:"modded"`
}

type dayzTypeCandidate struct {
	Path  string `json:"path"`
	Types int    `json:"types"`
}

type dayzEconomySummary struct {
	Mission               string              `json:"mission"`
	Files                 []dayzTypeFile      `json:"files"`
	Candidates            []dayzTypeCandidate `json:"candidates"`
	CandidatesTruncated   bool                `json:"candidates_truncated"`
	TypeCount             int                 `json:"type_count"`
	ShortestLifetimeHours float64             `json:"shortest_lifetime_hours,omitempty"`
	WarnShortLifetime     bool                `json:"warn_short_lifetime"`
	MinLifetimeHours      int                 `json:"min_lifetime_hours"`
	Globals               map[string]int      `json:"globals"`
	GlobalNames           []string            `json:"global_names"`
	EconomyCorePath       string              `json:"economy_core_path,omitempty"`
	RegisteredFiles       []string            `json:"registered_files"`
	UpdatedAt             string              `json:"updated_at,omitempty"`
}

type dayzLifetimePatch struct {
	start, end int
	value      int64
}

type dayzGlobalPatch struct {
	start, end int
	name       string
	value      int
}

func (a *App) dayzEconomyAccess(w http.ResponseWriter, r *http.Request, permission string) (Server, string, string, string, bool) {
	server, err := a.getServer(chi.URLParam(r, "id"))
	if err != nil {
		writeError(w, http.StatusNotFound, "server not found")
		return Server{}, "", "", "", false
	}
	if !a.requirePerm(w, principal(r), server, permission) {
		return Server{}, "", "", "", false
	}
	if server.GameskillID != "dayz" {
		writeError(w, http.StatusNotFound, "DayZ Economy is available only for servers using the dayz template")
		return Server{}, "", "", "", false
	}
	gs, err := a.loadRune(server.GameskillID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "DayZ template is unavailable")
		return Server{}, "", "", "", false
	}
	env, err := a.runtimeEnv(server, gs)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "DayZ server settings could not be read")
		return Server{}, "", "", "", false
	}
	mission := strings.TrimSpace(env["MISSION"])
	if mission == "" {
		mission = "dayzOffline.chernarusplus"
	}
	if !dayzMissionPattern.MatchString(mission) || mission == "." || mission == ".." {
		writeError(w, http.StatusBadRequest, "MISSION must be a simple folder name containing letters, numbers, dots, underscores, or hyphens")
		return Server{}, "", "", "", false
	}
	root, err := a.serverFilesRoot(server)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not resolve the DayZ server data directory")
		return Server{}, "", "", "", false
	}
	missionRoot, err := safePath(root, filepath.ToSlash(filepath.Join("mpmissions", mission)), true)
	if err != nil {
		writeError(w, http.StatusConflict, "DayZ mission files are not available yet; install the server and confirm its MISSION setting")
		return Server{}, "", "", "", false
	}
	info, err := os.Stat(missionRoot)
	if err != nil || !info.IsDir() {
		writeError(w, http.StatusConflict, "DayZ mission directory is unavailable; install the server and confirm its MISSION setting")
		return Server{}, "", "", "", false
	}
	return server, root, mission, missionRoot, true
}

func (a *App) getDayZEconomy(w http.ResponseWriter, r *http.Request) {
	server, _, mission, missionRoot, ok := a.dayzEconomyAccess(w, r, "server.view")
	if !ok {
		return
	}
	a.dataMu.Lock()
	defer a.dataMu.Unlock()
	server, _, mission, missionRoot, ok = a.dayzEconomyAccess(w, r, "server.view")
	if !ok {
		return
	}
	state, updatedAt, err := a.loadDayZEconomyState(server.ID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not read saved DayZ Economy settings")
		return
	}
	summary, err := buildDayZEconomySummary(mission, missionRoot, state)
	if err != nil {
		writeError(w, http.StatusConflict, err.Error())
		return
	}
	summary.UpdatedAt = updatedAt
	writeJSON(w, http.StatusOK, summary)
}

func (a *App) updateDayZLifetimeFloor(w http.ResponseWriter, r *http.Request) {
	server, _, mission, missionRoot, ok := a.dayzEconomyAccess(w, r, "server.control")
	if !ok {
		return
	}
	var in struct {
		Hours int `json:"hours"`
	}
	if decodeJSON(w, r, &in, 4096) != nil {
		return
	}
	if in.Hours < 0 || in.Hours > 8760 {
		writeError(w, http.StatusBadRequest, "minimum lifetime must be 0–8760 hours; 0 disables the automatic floor")
		return
	}
	a.dataMu.Lock()
	defer a.dataMu.Unlock()
	server, _, mission, missionRoot, ok = a.dayzEconomyAccess(w, r, "server.control")
	if !ok {
		return
	}
	state, _, err := a.loadDayZEconomyState(server.ID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not read saved DayZ Economy settings")
		return
	}
	if in.Hours > 0 {
		if _, err = applyDayZLifetimeFloor(missionRoot, in.Hours); err != nil {
			writeError(w, http.StatusConflict, "could not apply minimum lifetime: "+err.Error())
			return
		}
	}
	state.MinLifetimeHours = in.Hours
	if err = a.saveDayZEconomyState(r.Context(), server.ID, state); err != nil {
		writeError(w, http.StatusInternalServerError, "the files were updated but the saved setting could not be recorded")
		return
	}
	a.audit(principal(r), "dayz.economy.minimum_lifetime", "server", server.ID, fmt.Sprintf("hours=%d mission=%s", in.Hours, mission))
	summary, err := buildDayZEconomySummary(mission, missionRoot, state)
	if err != nil {
		writeError(w, http.StatusConflict, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, summary)
}

func (a *App) updateDayZGlobals(w http.ResponseWriter, r *http.Request) {
	server, _, mission, missionRoot, ok := a.dayzEconomyAccess(w, r, "server.control")
	if !ok {
		return
	}
	var in struct {
		Values map[string]int `json:"values"`
	}
	if decodeJSON(w, r, &in, 16*1024) != nil {
		return
	}
	if len(in.Values) == 0 || len(in.Values) > len(dayzGlobalNames) {
		writeError(w, http.StatusBadRequest, "provide one or more supported cleanup lifetime values")
		return
	}
	for key, value := range in.Values {
		if !dayzGlobalNames[key] {
			writeError(w, http.StatusBadRequest, "unsupported DayZ global: "+cleanModerationText(key, 80))
			return
		}
		if value < 0 || value > 2147483647 {
			writeError(w, http.StatusBadRequest, key+" must be between 0 and 2147483647 seconds")
			return
		}
	}
	a.dataMu.Lock()
	defer a.dataMu.Unlock()
	server, _, mission, missionRoot, ok = a.dayzEconomyAccess(w, r, "server.control")
	if !ok {
		return
	}
	state, _, err := a.loadDayZEconomyState(server.ID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not read saved DayZ Economy settings")
		return
	}
	for key, value := range in.Values {
		state.Globals[key] = value
	}
	if err = applyDayZGlobals(missionRoot, state.Globals); err != nil {
		writeError(w, http.StatusConflict, "could not update globals.xml: "+err.Error())
		return
	}
	if err = a.saveDayZEconomyState(r.Context(), server.ID, state); err != nil {
		writeError(w, http.StatusInternalServerError, "globals.xml was updated but the saved settings could not be recorded")
		return
	}
	a.audit(principal(r), "dayz.economy.globals", "server", server.ID, fmt.Sprintf("values=%d mission=%s", len(in.Values), mission))
	summary, err := buildDayZEconomySummary(mission, missionRoot, state)
	if err != nil {
		writeError(w, http.StatusConflict, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, summary)
}

func (a *App) registerDayZTypes(w http.ResponseWriter, r *http.Request) {
	server, _, mission, missionRoot, ok := a.dayzEconomyAccess(w, r, "server.control")
	if !ok {
		return
	}
	var in struct {
		Paths []string `json:"paths"`
	}
	if decodeJSON(w, r, &in, 128*1024) != nil {
		return
	}
	if len(in.Paths) == 0 || len(in.Paths) > 128 {
		writeError(w, http.StatusBadRequest, "select between 1 and 128 types files to register")
		return
	}
	a.dataMu.Lock()
	defer a.dataMu.Unlock()
	server, _, mission, missionRoot, ok = a.dayzEconomyAccess(w, r, "server.control")
	if !ok {
		return
	}
	state, _, err := a.loadDayZEconomyState(server.ID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not read saved DayZ Economy settings")
		return
	}
	corePath, coreData, err := readDayZEconomyCore(missionRoot)
	if err != nil {
		writeError(w, http.StatusConflict, err.Error())
		return
	}
	registered, err := parseDayZCoreFiles(coreData)
	if err != nil {
		writeError(w, http.StatusConflict, "could not read the mission economy registration file: "+err.Error())
		return
	}
	existing := map[string]bool{"db/types.xml": true}
	for _, item := range registered {
		existing[item] = true
	}
	chosen := make([]string, 0, len(in.Paths))
	for _, raw := range in.Paths {
		rel, cleanErr := cleanDayZMissionPath(raw)
		if cleanErr != nil || rel == "db/types.xml" || path.Dir(rel) == "." || hasDayZStoragePart(rel) {
			writeError(w, http.StatusBadRequest, "only types.xml files in a mission subfolder can be registered")
			return
		}
		if existing[rel] {
			continue
		}
		full, pathErr := safePath(missionRoot, filepath.FromSlash(rel), false)
		if pathErr != nil {
			writeError(w, http.StatusBadRequest, "invalid types file path")
			return
		}
		data, readErr := readDayZRegularFile(full)
		if readErr != nil {
			writeError(w, http.StatusConflict, "could not read "+rel+": "+readErr.Error())
			return
		}
		parsed, parseErr := parseDayZTypes(data)
		if parseErr != nil || parsed.count == 0 || len(parsed.lifetimes) == 0 {
			writeError(w, http.StatusBadRequest, rel+" must be a valid <types> file containing named types and lifetimes")
			return
		}
		existing[rel] = true
		chosen = append(chosen, rel)
	}
	if len(chosen) == 0 {
		writeError(w, http.StatusBadRequest, "all selected types files are already registered")
		return
	}
	updatedCore, err := addDayZCoreFiles(coreData, chosen)
	if err != nil {
		writeError(w, http.StatusConflict, "could not update the mission economy registration file: "+err.Error())
		return
	}
	coreFull, err := safePath(missionRoot, corePath, false)
	if err != nil {
		writeError(w, http.StatusBadRequest, "could not resolve the mission economy registration file safely")
		return
	}
	if err = writeDayZAtomic(coreFull, updatedCore); err != nil {
		writeError(w, http.StatusInternalServerError, "could not save the mission economy registration file; check server data permissions and disk space")
		return
	}
	state.RegisteredFiles = uniqueDayZPaths(append(state.RegisteredFiles, chosen...))
	if err = a.saveDayZEconomyState(r.Context(), server.ID, state); err != nil {
		writeError(w, http.StatusInternalServerError, "mission registrations were written but could not be saved for future reinstalls")
		return
	}
	a.audit(principal(r), "dayz.economy.register_types", "server", server.ID, fmt.Sprintf("files=%d mission=%s", len(chosen), mission))
	summary, err := buildDayZEconomySummary(mission, missionRoot, state)
	if err != nil {
		writeError(w, http.StatusConflict, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, summary)
}

func (a *App) resetDayZEconomy(w http.ResponseWriter, r *http.Request) {
	server, err := a.getServer(chi.URLParam(r, "id"))
	if err != nil {
		writeError(w, http.StatusNotFound, "server not found")
		return
	}
	if server.GameskillID != "dayz" {
		writeError(w, http.StatusNotFound, "DayZ Economy is available only for servers using the dayz template")
		return
	}
	if !a.requirePerm(w, principal(r), server, "server.control") {
		return
	}
	a.dataMu.Lock()
	defer a.dataMu.Unlock()
	server, err = a.getServer(server.ID)
	if err != nil {
		writeError(w, http.StatusNotFound, "server not found")
		return
	}
	if server.GameskillID != "dayz" {
		writeError(w, http.StatusNotFound, "DayZ Economy is available only for servers using the dayz template")
		return
	}
	if !a.requirePerm(w, principal(r), server, "server.control") {
		return
	}
	if _, err := a.db.ExecContext(r.Context(), `DELETE FROM dayz_economy_settings WHERE server_id=?`, server.ID); err != nil {
		writeError(w, http.StatusInternalServerError, "could not clear saved DayZ Economy settings")
		return
	}
	a.audit(principal(r), "dayz.economy.reset", "server", server.ID, "saved settings cleared; mission files left unchanged")
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (a *App) loadDayZEconomyState(serverID string) (dayzEconomyState, string, error) {
	state := dayzEconomyState{Globals: map[string]int{}, RegisteredFiles: []string{}}
	var globalsJSON, registeredJSON, updatedAt string
	err := a.db.QueryRow(`SELECT min_lifetime_hours,globals_json,registered_files_json,updated_at FROM dayz_economy_settings WHERE server_id=?`, serverID).Scan(&state.MinLifetimeHours, &globalsJSON, &registeredJSON, &updatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return state, "", nil
	}
	if err != nil {
		return state, "", err
	}
	if err = json.Unmarshal([]byte(globalsJSON), &state.Globals); err != nil {
		return state, "", errors.New("saved cleanup lifetime settings are invalid; reset DayZ Economy settings")
	}
	if state.Globals == nil {
		state.Globals = map[string]int{}
	}
	if err = json.Unmarshal([]byte(registeredJSON), &state.RegisteredFiles); err != nil {
		return state, "", errors.New("saved DayZ types registrations are invalid; reset DayZ Economy settings")
	}
	if state.RegisteredFiles == nil {
		state.RegisteredFiles = []string{}
	}
	return state, updatedAt, nil
}

func (a *App) saveDayZEconomyState(ctx context.Context, serverID string, state dayzEconomyState) error {
	if state.Globals == nil {
		state.Globals = map[string]int{}
	}
	if state.RegisteredFiles == nil {
		state.RegisteredFiles = []string{}
	}
	globals, err := json.Marshal(state.Globals)
	if err != nil {
		return err
	}
	registered, err := json.Marshal(uniqueDayZPaths(state.RegisteredFiles))
	if err != nil {
		return err
	}
	_, err = a.db.ExecContext(ctx, `INSERT INTO dayz_economy_settings(server_id,min_lifetime_hours,globals_json,registered_files_json,updated_at) VALUES(?,?,?,?,CURRENT_TIMESTAMP)
		ON CONFLICT(server_id) DO UPDATE SET min_lifetime_hours=excluded.min_lifetime_hours,globals_json=excluded.globals_json,registered_files_json=excluded.registered_files_json,updated_at=CURRENT_TIMESTAMP`, serverID, state.MinLifetimeHours, string(globals), string(registered))
	return err
}

func buildDayZEconomySummary(mission, missionRoot string, state dayzEconomyState) (dayzEconomySummary, error) {
	summary := dayzEconomySummary{Mission: mission, MinLifetimeHours: state.MinLifetimeHours, Globals: map[string]int{}, GlobalNames: sortedDayZGlobals(), Files: []dayzTypeFile{}, Candidates: []dayzTypeCandidate{}, RegisteredFiles: []string{}}
	for key, value := range state.Globals {
		if dayzGlobalNames[key] {
			summary.Globals[key] = value
		}
	}
	registered, corePath, coreErr := registeredDayZTypes(missionRoot)
	if coreErr != nil && !errors.Is(coreErr, fs.ErrNotExist) {
		return summary, coreErr
	}
	summary.EconomyCorePath = corePath
	registeredSet := map[string]bool{"db/types.xml": true}
	paths := []string{"db/types.xml"}
	for _, rel := range registered {
		registeredSet[rel] = true
		paths = append(paths, rel)
	}
	summary.RegisteredFiles = append([]string(nil), registered...)
	sort.Strings(paths)
	var shortest int64
	for _, rel := range paths {
		full, err := safePath(missionRoot, filepath.FromSlash(rel), false)
		if err != nil {
			continue
		}
		data, err := readDayZRegularFile(full)
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				continue
			}
			return summary, fmt.Errorf("could not read %s: %w", rel, err)
		}
		parsed, err := parseDayZTypes(data)
		if err != nil {
			return summary, fmt.Errorf("%s is not a valid types file: %w", rel, err)
		}
		file := dayzTypeFile{Path: rel, TypeCount: parsed.count, Modded: rel != "db/types.xml"}
		if parsed.shortest > 0 {
			file.ShortestLifetimeHours = float64(parsed.shortest) / 3600
			if shortest == 0 || parsed.shortest < shortest {
				shortest = parsed.shortest
			}
		}
		summary.TypeCount += parsed.count
		summary.Files = append(summary.Files, file)
	}
	if shortest > 0 {
		summary.ShortestLifetimeHours = float64(shortest) / 3600
		summary.WarnShortLifetime = shortest < 3600
	}
	if coreErr == nil {
		candidates, truncated, err := findDayZTypeCandidates(missionRoot, registeredSet)
		if err != nil {
			return summary, err
		}
		summary.Candidates = candidates
		summary.CandidatesTruncated = truncated
	}
	globalsPath, err := dayzMissionGlobalsPath(missionRoot)
	if err != nil {
		return summary, err
	}
	data, err := readDayZRegularFile(globalsPath)
	if err != nil {
		return summary, fmt.Errorf("could not read globals.xml: %w", err)
	}
	values, err := parseDayZGlobals(data)
	if err != nil {
		return summary, fmt.Errorf("could not parse globals.xml: %w", err)
	}
	for key, value := range values {
		if _, overridden := summary.Globals[key]; !overridden {
			summary.Globals[key] = value
		}
	}
	return summary, nil
}

type parsedDayZTypes struct {
	count     int
	shortest  int64
	lifetimes []dayzLifetimePatch
}

func parseDayZTypes(data []byte) (parsedDayZTypes, error) {
	var parsed parsedDayZTypes
	if len(data) == 0 || len(data) > dayzMaxXMLBytes {
		return parsed, errors.New("file is empty or exceeds the 8 MiB limit")
	}
	decoder := xml.NewDecoder(bytes.NewReader(data))
	decoder.Strict = true
	rootSeen := false
	typeDepth := 0
	for {
		token, err := decoder.Token()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return parsed, err
		}
		switch item := token.(type) {
		case xml.StartElement:
			if !rootSeen {
				rootSeen = true
				if item.Name.Local != "types" {
					return parsed, errors.New("root element must be <types>")
				}
			}
			if item.Name.Local == "type" {
				typeDepth++
				for _, attr := range item.Attr {
					if attr.Name.Local == "name" && strings.TrimSpace(attr.Value) != "" {
						parsed.count++
						break
					}
				}
			}
			if item.Name.Local == "lifetime" && typeDepth > 0 {
				patch, value, readErr := readDayZIntegerElement(decoder, data, "lifetime")
				if readErr != nil {
					return parsed, fmt.Errorf("lifetime values must be plain integer seconds: %w", readErr)
				}
				patch.value = value
				parsed.lifetimes = append(parsed.lifetimes, patch)
				if value > 0 && (parsed.shortest == 0 || value < parsed.shortest) {
					parsed.shortest = value
				}
			}
		case xml.EndElement:
			if item.Name.Local == "type" && typeDepth > 0 {
				typeDepth--
			}
		}
	}
	if !rootSeen {
		return parsed, errors.New("file has no XML root element")
	}
	return parsed, nil
}

func parseDayZGlobals(data []byte) (map[string]int, error) {
	values := map[string]int{}
	decoder := xml.NewDecoder(bytes.NewReader(data))
	decoder.Strict = true
	rootSeen := false
	for {
		token, err := decoder.Token()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, err
		}
		element, ok := token.(xml.StartElement)
		if !ok {
			continue
		}
		if !rootSeen {
			rootSeen = true
			if element.Name.Local != "globals" {
				return nil, errors.New("root element must be <globals>")
			}
		}
		if element.Name.Local != "var" {
			continue
		}
		name := ""
		for _, attr := range element.Attr {
			if attr.Name.Local == "name" {
				name = attr.Value
				break
			}
		}
		if !dayzGlobalNames[name] {
			continue
		}
		var raw string
		if err = decoder.DecodeElement(&raw, &element); err != nil {
			return nil, err
		}
		value, parseErr := strconv.Atoi(strings.TrimSpace(raw))
		if parseErr != nil || value < 0 {
			return nil, fmt.Errorf("%s is not a non-negative integer", name)
		}
		if _, duplicate := values[name]; duplicate {
			return nil, fmt.Errorf("%s is listed more than once", name)
		}
		values[name] = value
	}
	if !rootSeen {
		return nil, errors.New("file has no XML root element")
	}
	return values, nil
}

func findDayZGlobalPatches(data []byte, desired map[string]int) ([]dayzGlobalPatch, error) {
	patches := []dayzGlobalPatch{}
	decoder := xml.NewDecoder(bytes.NewReader(data))
	decoder.Strict = true
	rootSeen := false
	found := map[string]bool{}
	for {
		token, err := decoder.Token()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, err
		}
		start, ok := token.(xml.StartElement)
		if !ok {
			continue
		}
		if !rootSeen {
			rootSeen = true
			if start.Name.Local != "globals" {
				return nil, errors.New("root element must be <globals>")
			}
		}
		if start.Name.Local != "var" {
			continue
		}
		name := ""
		for _, attr := range start.Attr {
			if attr.Name.Local == "name" {
				name = attr.Value
				break
			}
		}
		newValue, replace := desired[name]
		if !replace {
			continue
		}
		if found[name] {
			return nil, fmt.Errorf("%s is listed more than once", name)
		}
		patch, _, readErr := readDayZIntegerElement(decoder, data, "var")
		if readErr != nil {
			return nil, fmt.Errorf("%s must contain a plain integer value: %w", name, readErr)
		}
		patches = append(patches, dayzGlobalPatch{start: patch.start, end: patch.end, name: name, value: newValue})
		found[name] = true
	}
	if !rootSeen {
		return nil, errors.New("file has no XML root element")
	}
	for name := range desired {
		if !found[name] {
			return nil, fmt.Errorf("%s is not present in globals.xml", name)
		}
	}
	return patches, nil
}

func readDayZIntegerElement(decoder *xml.Decoder, data []byte, tag string) (dayzLifetimePatch, int64, error) {
	var patch dayzLifetimePatch
	found := false
	cursor := int(decoder.InputOffset())
	for {
		token, err := decoder.Token()
		if err != nil {
			return patch, 0, err
		}
		end := int(decoder.InputOffset())
		switch item := token.(type) {
		case xml.CharData:
			text := string(item)
			if strings.TrimSpace(text) == "" {
				cursor = end
				continue
			}
			if found {
				return patch, 0, errors.New("element contains more than one text value")
			}
			if cursor < 0 || cursor > end || end > len(data) {
				return patch, 0, errors.New("invalid XML text position")
			}
			raw := data[cursor:end]
			if normalizeDayZXMLText(raw) != text {
				return patch, 0, errors.New("integer text uses an unsupported XML entity")
			}
			match := dayzLifetimeText.FindSubmatchIndex(raw)
			if match == nil {
				return patch, 0, errors.New("element contains non-integer text")
			}
			value, parseErr := strconv.ParseInt(string(raw[match[2]:match[3]]), 10, 32)
			if parseErr != nil {
				return patch, 0, errors.New("integer is outside the non-negative 32-bit range")
			}
			patch = dayzLifetimePatch{start: cursor + match[2], end: cursor + match[3], value: value}
			found = true
			cursor = end
		case xml.Comment:
			// Comments are intentionally retained; only the number span is changed.
			cursor = end
		case xml.StartElement:
			return patch, 0, fmt.Errorf("unexpected nested <%s> element", item.Name.Local)
		case xml.EndElement:
			if item.Name.Local != tag {
				return patch, 0, errors.New("unexpected closing tag")
			}
			if !found {
				return patch, 0, errors.New("integer value is missing")
			}
			return patch, patch.value, nil
		default:
			cursor = end
		}
	}
}

func applyDayZLifetimeFloor(missionRoot string, hours int) (int, error) {
	files, _, err := registeredDayZTypes(missionRoot)
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return 0, err
	}
	paths := uniqueDayZPaths(append([]string{"db/types.xml"}, files...))
	changed := 0
	for _, rel := range paths {
		full, pathErr := safePath(missionRoot, filepath.FromSlash(rel), false)
		if pathErr != nil {
			continue
		}
		data, readErr := readDayZRegularFile(full)
		if readErr != nil {
			if errors.Is(readErr, fs.ErrNotExist) {
				continue
			}
			return changed, fmt.Errorf("%s: %w", rel, readErr)
		}
		parsed, parseErr := parseDayZTypes(data)
		if parseErr != nil {
			return changed, fmt.Errorf("%s: %w", rel, parseErr)
		}
		patches := make([]dayzLifetimePatch, 0)
		floorSeconds := int64(hours) * 3600
		for _, item := range parsed.lifetimes {
			if item.value > 0 && item.value < floorSeconds {
				item.value = floorSeconds
				patches = append(patches, item)
			}
		}
		if len(patches) == 0 {
			continue
		}
		updated := replaceDayZLifetimeValues(data, patches)
		if writeErr := writeDayZAtomic(full, updated); writeErr != nil {
			return changed, fmt.Errorf("could not save %s: %w", rel, writeErr)
		}
		changed += len(patches)
	}
	return changed, nil
}

func replaceDayZLifetimeValues(data []byte, patches []dayzLifetimePatch) []byte {
	for i := len(patches) - 1; i >= 0; i-- {
		item := patches[i]
		replacement := []byte(strconv.FormatInt(item.value, 10))
		data = append(data[:item.start], append(replacement, data[item.end:]...)...)
	}
	return data
}

func applyDayZGlobals(missionRoot string, desired map[string]int) error {
	if len(desired) == 0 {
		return nil
	}
	for key, value := range desired {
		if !dayzGlobalNames[key] || value < 0 || value > 2147483647 {
			return fmt.Errorf("saved cleanup lifetime %q is invalid", cleanModerationText(key, 80))
		}
	}
	full, err := dayzMissionGlobalsPath(missionRoot)
	if err != nil {
		return err
	}
	data, err := readDayZRegularFile(full)
	if err != nil {
		return err
	}
	patches, err := findDayZGlobalPatches(data, desired)
	if err != nil {
		return err
	}
	for i := len(patches) - 1; i >= 0; i-- {
		item := patches[i]
		replacement := []byte(strconv.Itoa(item.value))
		data = append(data[:item.start], append(replacement, data[item.end:]...)...)
	}
	return writeDayZAtomic(full, data)
}

func (a *App) applyDayZEconomySettings(server Server) error {
	if server.GameskillID != "dayz" {
		return nil
	}
	state, _, err := a.loadDayZEconomyState(server.ID)
	if err != nil {
		return fmt.Errorf("read saved DayZ Economy settings: %w", err)
	}
	if state.MinLifetimeHours == 0 && len(state.Globals) == 0 && len(state.RegisteredFiles) == 0 {
		return nil
	}
	if state.MinLifetimeHours < 0 || state.MinLifetimeHours > 8760 {
		return errors.New("saved minimum lifetime is outside 0–8760 hours; reset DayZ Economy settings")
	}
	gs, err := a.loadRune(server.GameskillID)
	if err != nil {
		return fmt.Errorf("load DayZ template: %w", err)
	}
	env, err := a.runtimeEnv(server, gs)
	if err != nil {
		return fmt.Errorf("read DayZ settings: %w", err)
	}
	mission := strings.TrimSpace(env["MISSION"])
	if mission == "" {
		mission = "dayzOffline.chernarusplus"
	}
	if !dayzMissionPattern.MatchString(mission) || mission == "." || mission == ".." {
		return errors.New("MISSION must be a simple folder name before saved DayZ Economy settings can be applied")
	}
	root, err := a.serverFilesRoot(server)
	if err != nil {
		return fmt.Errorf("resolve DayZ server data directory: %w", err)
	}
	missionRoot, err := safePath(root, filepath.ToSlash(filepath.Join("mpmissions", mission)), true)
	if err != nil {
		return errors.New("DayZ mission directory is missing; restore it or clear saved Economy settings before reinstalling")
	}
	if len(state.RegisteredFiles) > 0 {
		for _, raw := range state.RegisteredFiles {
			rel, cleanErr := cleanDayZMissionPath(raw)
			if cleanErr != nil || rel == "db/types.xml" || path.Dir(rel) == "." || hasDayZStoragePart(rel) {
				return errors.New("saved DayZ types registration contains an unsafe path; reset DayZ Economy settings")
			}
			full, pathErr := safePath(missionRoot, filepath.FromSlash(rel), false)
			if pathErr != nil {
				return errors.New("saved DayZ types registration cannot be resolved safely")
			}
			data, readErr := readDayZRegularFile(full)
			if readErr != nil {
				return fmt.Errorf("registered types file %s is missing or unreadable; restore it or reset DayZ Economy settings: %w", rel, readErr)
			}
			parsed, parseErr := parseDayZTypes(data)
			if parseErr != nil || parsed.count == 0 || len(parsed.lifetimes) == 0 {
				return fmt.Errorf("registered types file %s is no longer valid; restore it or reset DayZ Economy settings", rel)
			}
		}
		corePath, coreData, coreErr := readDayZEconomyCore(missionRoot)
		if coreErr != nil {
			return coreErr
		}
		updated, updateErr := addDayZCoreFiles(coreData, state.RegisteredFiles)
		if updateErr != nil {
			return updateErr
		}
		full, pathErr := safePath(missionRoot, corePath, false)
		if pathErr != nil {
			return pathErr
		}
		if err = writeDayZAtomic(full, updated); err != nil {
			return fmt.Errorf("restore registered types in %s: %w", corePath, err)
		}
	}
	if err = applyDayZGlobals(missionRoot, state.Globals); err != nil {
		return fmt.Errorf("reapply DayZ cleanup lifetime values: %w", err)
	}
	if state.MinLifetimeHours > 0 {
		if _, err = applyDayZLifetimeFloor(missionRoot, state.MinLifetimeHours); err != nil {
			return fmt.Errorf("reapply DayZ minimum lifetime: %w", err)
		}
	}
	return nil
}

func registeredDayZTypes(missionRoot string) ([]string, string, error) {
	corePath, data, err := readDayZEconomyCore(missionRoot)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, "", fs.ErrNotExist
		}
		return nil, "", err
	}
	registered, err := parseDayZCoreFiles(data)
	if err != nil {
		return nil, "", err
	}
	available := make([]string, 0, len(registered))
	for _, rel := range registered {
		full, pathErr := safePath(missionRoot, filepath.FromSlash(rel), false)
		if pathErr != nil {
			continue
		}
		if _, statErr := os.Lstat(full); statErr == nil {
			available = append(available, rel)
		}
	}
	return uniqueDayZPaths(available), corePath, nil
}

func readDayZEconomyCore(missionRoot string) (string, []byte, error) {
	entries, err := os.ReadDir(missionRoot)
	if err != nil {
		return "", nil, err
	}
	var name string
	for _, entry := range entries {
		if !entry.IsDir() && strings.EqualFold(entry.Name(), "cfgeconomycore.xml") {
			name = entry.Name()
			break
		}
	}
	if name == "" {
		return "", nil, fs.ErrNotExist
	}
	full, err := safePath(missionRoot, name, false)
	if err != nil {
		return "", nil, err
	}
	data, err := readDayZRegularFile(full)
	if err != nil {
		return "", nil, err
	}
	if err = validateDayZCore(data); err != nil {
		return "", nil, err
	}
	return name, data, nil
}

func dayzMissionGlobalsPath(missionRoot string) (string, error) {
	dbDir, err := safePath(missionRoot, "db", true)
	if err != nil {
		return "", errors.New("mission db/globals.xml is missing; install or restore the DayZ mission files first")
	}
	entries, err := os.ReadDir(dbDir)
	if err != nil {
		return "", fmt.Errorf("could not list mission db files: %w", err)
	}
	for _, entry := range entries {
		if !entry.IsDir() && strings.EqualFold(entry.Name(), "globals.xml") {
			return safePath(missionRoot, filepath.Join("db", entry.Name()), false)
		}
	}
	return "", errors.New("mission db/globals.xml is missing; install or restore the DayZ mission files first")
}

func parseDayZCoreFiles(data []byte) ([]string, error) {
	var document struct {
		XMLName xml.Name `xml:"economycore"`
		CE      []struct {
			Folder string `xml:"folder,attr"`
			Files  []struct {
				Name string `xml:"name,attr"`
				Type string `xml:"type,attr"`
			} `xml:"file"`
		} `xml:"ce"`
	}
	if len(data) > dayzMaxXMLBytes {
		return nil, errors.New("economy core file exceeds the 8 MiB limit")
	}
	if err := xml.Unmarshal(data, &document); err != nil {
		return nil, err
	}
	if document.XMLName.Local != "economycore" {
		return nil, errors.New("root element must be <economycore>")
	}
	var out []string
	for _, section := range document.CE {
		folder := strings.TrimSpace(section.Folder)
		for _, file := range section.Files {
			if !strings.EqualFold(strings.TrimSpace(file.Type), "types") {
				continue
			}
			name := strings.TrimSpace(file.Name)
			if name == "" || path.IsAbs(name) || path.IsAbs(folder) {
				continue
			}
			rel, err := cleanDayZMissionPath(path.Join(folder, name))
			if err == nil {
				out = append(out, rel)
			}
		}
	}
	return uniqueDayZPaths(out), nil
}

func validateDayZCore(data []byte) error {
	if len(data) == 0 || len(data) > dayzMaxXMLBytes {
		return errors.New("economy core file is empty or exceeds the 8 MiB limit")
	}
	var root struct{ XMLName xml.Name }
	if err := xml.Unmarshal(data, &root); err != nil {
		return err
	}
	if root.XMLName.Local != "economycore" {
		return errors.New("root element must be <economycore>")
	}
	return nil
}

func addDayZCoreFiles(data []byte, paths []string) ([]byte, error) {
	if err := validateDayZCore(data); err != nil {
		return nil, err
	}
	registered, err := parseDayZCoreFiles(data)
	if err != nil {
		return nil, err
	}
	known := map[string]bool{}
	for _, item := range registered {
		known[item] = true
	}
	byFolder := map[string][]string{}
	for _, raw := range paths {
		rel, cleanErr := cleanDayZMissionPath(raw)
		if cleanErr != nil {
			return nil, cleanErr
		}
		if known[rel] {
			continue
		}
		folder, name := path.Split(rel)
		folder = strings.TrimSuffix(folder, "/")
		byFolder[folder] = append(byFolder[folder], name)
		known[rel] = true
	}
	if len(byFolder) == 0 {
		return data, nil
	}
	folders := make([]string, 0, len(byFolder))
	for folder := range byFolder {
		folders = append(folders, folder)
	}
	sort.Strings(folders)
	for folder := range byFolder {
		sort.Strings(byFolder[folder])
	}
	newline := "\n"
	if bytes.Contains(data, []byte("\r\n")) {
		newline = "\r\n"
	}
	closeStart, err := dayzEconomyCoreClosingTag(data)
	if err != nil {
		return nil, errors.New("economy core closing tag is missing")
	}
	lineStart := bytes.LastIndexByte(data[:closeStart], '\n') + 1
	indent := string(data[lineStart:closeStart])
	if strings.TrimSpace(indent) != "" {
		lineStart = closeStart
		indent = ""
	}
	childIndent := indent + "    "
	var block strings.Builder
	for _, folder := range folders {
		block.WriteString(childIndent)
		block.WriteString("<ce folder=\"")
		block.WriteString(dayzXMLAttribute(folder))
		block.WriteString("\">")
		block.WriteString(newline)
		for _, name := range byFolder[folder] {
			block.WriteString(childIndent)
			block.WriteString("    <file name=\"")
			block.WriteString(dayzXMLAttribute(name))
			block.WriteString("\" type=\"types\" />")
			block.WriteString(newline)
		}
		block.WriteString(childIndent)
		block.WriteString("</ce>")
		block.WriteString(newline)
	}
	insert := []byte(block.String() + indent)
	if lineStart == closeStart {
		insert = append([]byte(newline), []byte(block.String()+indent)...)
	}
	out := make([]byte, 0, len(data)+len(insert))
	out = append(out, data[:lineStart]...)
	out = append(out, insert...)
	out = append(out, data[closeStart:]...)
	if err = validateDayZCore(out); err != nil {
		return nil, fmt.Errorf("updated economy core would be invalid: %w", err)
	}
	return out, nil
}

func dayzEconomyCoreClosingTag(data []byte) (int, error) {
	decoder := xml.NewDecoder(bytes.NewReader(data))
	decoder.Strict = true
	rootSeen := false
	depth := 0
	for {
		token, err := decoder.Token()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return 0, err
		}
		switch element := token.(type) {
		case xml.StartElement:
			if !rootSeen {
				rootSeen = true
				if element.Name.Local != "economycore" {
					return 0, errors.New("root element must be <economycore>")
				}
			}
			depth++
		case xml.EndElement:
			depth--
			if depth == 0 && element.Name.Local == "economycore" {
				end := int(decoder.InputOffset())
				if end > len(data) {
					return 0, errors.New("invalid economy core closing position")
				}
				start := bytes.LastIndex(data[:end], []byte("</"))
				if start < 0 {
					return 0, errors.New("economy core closing tag is missing")
				}
				return start, nil
			}
		}
	}
	return 0, errors.New("economy core closing tag is missing")
}

func dayzXMLAttribute(value string) string {
	var out bytes.Buffer
	_ = xml.EscapeText(&out, []byte(value))
	return out.String()
}

func normalizeDayZXMLText(raw []byte) string {
	text := strings.ReplaceAll(string(raw), "\r\n", "\n")
	return strings.ReplaceAll(text, "\r", "\n")
}

func findDayZTypeCandidates(missionRoot string, registered map[string]bool) ([]dayzTypeCandidate, bool, error) {
	candidates := []dayzTypeCandidate{}
	visited := 0
	var scannedBytes int64
	truncated := false
	err := filepath.WalkDir(missionRoot, func(full string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		visited++
		if visited > 20000 {
			truncated = true
			return filepath.SkipAll
		}
		rel, err := filepath.Rel(missionRoot, full)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		if entry.IsDir() {
			if full != missionRoot && strings.HasPrefix(strings.ToLower(entry.Name()), "storage") {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.EqualFold(filepath.Ext(entry.Name()), ".xml") || path.Dir(rel) == "." || rel == "db/types.xml" || registered[rel] || hasDayZStoragePart(rel) {
			return nil
		}
		info, err := entry.Info()
		if err != nil || info.Size() <= 0 || info.Size() > dayzMaxXMLBytes {
			return nil
		}
		if len(candidates) >= 256 || scannedBytes+info.Size() > dayzMaxMissionScanSize {
			truncated = true
			return filepath.SkipAll
		}
		scannedBytes += info.Size()
		data, err := readDayZRegularFile(full)
		if err != nil {
			return nil
		}
		parsed, err := parseDayZTypes(data)
		if err == nil && parsed.count > 0 && len(parsed.lifetimes) > 0 {
			candidates = append(candidates, dayzTypeCandidate{Path: rel, Types: parsed.count})
		}
		return nil
	})
	if err != nil {
		return nil, false, fmt.Errorf("could not scan mission files: %w", err)
	}
	sort.Slice(candidates, func(i, j int) bool { return candidates[i].Path < candidates[j].Path })
	return candidates, truncated, nil
}

func cleanDayZMissionPath(raw string) (string, error) {
	raw = strings.TrimSpace(strings.ReplaceAll(raw, "\\", "/"))
	if raw == "" || strings.ContainsRune(raw, 0) || strings.ContainsAny(raw, "\r\n") || strings.HasPrefix(raw, "/") {
		return "", errors.New("path must be relative to the DayZ mission")
	}
	clean := path.Clean(raw)
	if clean == "." || clean == ".." || strings.HasPrefix(clean, "../") || strings.HasPrefix(clean, "storage") {
		return "", errors.New("path is outside the allowed mission files")
	}
	if !strings.EqualFold(path.Ext(clean), ".xml") {
		return "", errors.New("mission types path must end in .xml")
	}
	return clean, nil
}

func hasDayZStoragePart(rel string) bool {
	for _, part := range strings.Split(filepath.ToSlash(rel), "/") {
		if strings.HasPrefix(strings.ToLower(part), "storage") {
			return true
		}
	}
	return false
}

func uniqueDayZPaths(paths []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(paths))
	for _, raw := range paths {
		clean, err := cleanDayZMissionPath(raw)
		if err != nil || seen[clean] {
			continue
		}
		seen[clean] = true
		out = append(out, clean)
	}
	sort.Strings(out)
	return out
}

func readDayZRegularFile(full string) ([]byte, error) {
	info, err := os.Lstat(full)
	if err != nil {
		return nil, err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return nil, errors.New("path must be a regular file, not a link or special file")
	}
	if info.Size() > dayzMaxXMLBytes {
		return nil, errors.New("file exceeds the 8 MiB limit")
	}
	file, err := os.OpenFile(full, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if !opened.Mode().IsRegular() {
		return nil, errors.New("path must be a regular file, not a link or special file")
	}
	data, err := io.ReadAll(io.LimitReader(file, dayzMaxXMLBytes+1))
	if err != nil {
		return nil, err
	}
	if len(data) > dayzMaxXMLBytes {
		return nil, errors.New("file exceeds the 8 MiB limit")
	}
	return data, nil
}

func writeDayZAtomic(full string, data []byte) error {
	info, err := os.Lstat(full)
	mode := os.FileMode(0640)
	if err == nil {
		if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
			return errors.New("target must be a regular file, not a link or special file")
		}
		mode = info.Mode().Perm()
	} else if !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(full), ".docklight-dayz-*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if err = tmp.Chmod(mode); err == nil {
		_, err = tmp.Write(data)
	}
	if err == nil {
		err = tmp.Sync()
	}
	if closeErr := tmp.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	return os.Rename(tmpName, full)
}

func sortedDayZGlobals() []string {
	names := make([]string, 0, len(dayzGlobalNames))
	for name := range dayzGlobalNames {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}
