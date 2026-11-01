package panel

import (
	"bytes"
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
	"strings"
	"unicode"
)

const (
	dayzModLootMaxEntries    = 20000
	dayzModLootMaxBytes      = 128 << 20
	dayzModLootMaxCandidates = 256
	dayzModLootMaxImports    = 64
)

var (
	dayzModNamePattern = regexp.MustCompile(`(?im)^\s*name\s*=\s*"([^"\r\n]{1,120})"\s*;`)
	dayzXMLDeclaration = regexp.MustCompile(`(?is)^\s*<\?xml[^?]*\?>\s*`)
)

type dayzModTypesImport struct {
	SourcePath string `json:"source_path"`
	TargetPath string `json:"target_path"`
	ModName    string `json:"mod_name"`
}

type dayzModLootCandidate struct {
	SourcePath   string `json:"source_path"`
	ModToken     string `json:"mod_token"`
	DisplayName  string `json:"display_name"`
	ModName      string `json:"mod_name"`
	TargetPath   string `json:"target_path"`
	TypeCount    int    `json:"type_count"`
	Fragment     bool   `json:"fragment"`
	Expansion    bool   `json:"expansion"`
	Imported     bool   `json:"imported"`
	TargetExists bool   `json:"target_exists"`
	TargetClash  bool   `json:"target_clash"`
}

type dayzModLootSummary struct {
	Candidates []dayzModLootCandidate `json:"candidates"`
	Truncated  bool                   `json:"truncated"`
}

func (a *App) getDayZModLoot(w http.ResponseWriter, r *http.Request) {
	server, root, _, missionRoot, ok := a.dayzEconomyAccess(w, r, "server.view")
	if !ok {
		return
	}
	a.dataMu.Lock()
	defer a.dataMu.Unlock()
	server, root, _, missionRoot, ok = a.dayzEconomyAccess(w, r, "server.view")
	if !ok {
		return
	}
	state, _, err := a.loadDayZEconomyState(server.ID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not read saved DayZ mod imports")
		return
	}
	summary, err := scanDayZModLoot(root, missionRoot, state.ModImports)
	if err != nil {
		writeError(w, http.StatusConflict, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, summary)
}

func (a *App) importDayZModTypes(w http.ResponseWriter, r *http.Request) {
	server, _, _, _, ok := a.dayzEconomyAccess(w, r, "server.control")
	if !ok {
		return
	}
	var in struct {
		Paths []string `json:"source_paths"`
	}
	if decodeJSON(w, r, &in, 128*1024) != nil {
		return
	}
	if len(in.Paths) == 0 || len(in.Paths) > dayzModLootMaxImports {
		writeError(w, http.StatusBadRequest, "select between 1 and 64 mod loot files to import")
		return
	}
	a.dataMu.Lock()
	defer a.dataMu.Unlock()
	server, root, mission, missionRoot, ok := a.dayzEconomyAccess(w, r, "server.control")
	if !ok {
		return
	}
	state, _, err := a.loadDayZEconomyState(server.ID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not read saved DayZ mod imports")
		return
	}
	summary, err := scanDayZModLoot(root, missionRoot, state.ModImports)
	if err != nil {
		writeError(w, http.StatusConflict, err.Error())
		return
	}
	bySource := make(map[string]dayzModLootCandidate, len(summary.Candidates))
	for _, candidate := range summary.Candidates {
		bySource[candidate.SourcePath] = candidate
	}
	selected := make([]dayzModLootCandidate, 0, len(in.Paths))
	seen := map[string]bool{}
	for _, raw := range in.Paths {
		source, cleanErr := cleanDayZModSourcePath(raw)
		if cleanErr != nil || seen[source] {
			writeError(w, http.StatusBadRequest, "select valid, unique XML files from installed @mod folders")
			return
		}
		seen[source] = true
		candidate, found := bySource[source]
		if !found || candidate.Imported || candidate.TargetClash || candidate.TargetExists {
			writeError(w, http.StatusConflict, "a selected mod loot file is missing, already imported, or conflicts with an existing mission file; refresh the list")
			return
		}
		selected = append(selected, candidate)
	}

	corePath, coreData, err := readDayZEconomyCore(missionRoot)
	if err != nil {
		writeError(w, http.StatusConflict, "could not read the mission economy registration file: "+err.Error())
		return
	}
	chosenTargets := make([]string, 0, len(selected))
	imports := append([]dayzModTypesImport(nil), state.ModImports...)
	prepared := make([][]byte, 0, len(selected))
	for _, candidate := range selected {
		sourceRel, sourceErr := cleanDayZModSourcePath(candidate.SourcePath)
		if sourceErr != nil {
			writeError(w, http.StatusBadRequest, "invalid mod loot source path")
			return
		}
		if err = ensureDayZNoLinks(root, sourceRel, false); err != nil {
			writeError(w, http.StatusConflict, "mod loot source is no longer a safe regular file")
			return
		}
		sourceFull, pathErr := safePath(root, filepath.FromSlash(sourceRel), false)
		if pathErr != nil {
			writeError(w, http.StatusBadRequest, "invalid mod loot source path")
			return
		}
		rawData, readErr := readDayZRegularFile(sourceFull)
		if readErr != nil {
			writeError(w, http.StatusConflict, "could not read "+candidate.SourcePath+": "+readErr.Error())
			return
		}
		data, parsed, _, normalizeErr := normalizeDayZModTypes(rawData)
		if normalizeErr != nil || parsed.count != candidate.TypeCount {
			writeError(w, http.StatusConflict, candidate.SourcePath+" changed or is no longer a valid DayZ types file")
			return
		}
		target, cleanErr := cleanDayZMissionPath(candidate.TargetPath)
		if cleanErr != nil || target == "db/types.xml" || path.Dir(target) == "." || hasDayZStoragePart(target) {
			writeError(w, http.StatusBadRequest, "derived mission path is not safe")
			return
		}
		if err = ensureDayZNoLinks(missionRoot, target, true); err != nil {
			writeError(w, http.StatusConflict, "mission target contains a link or unsafe path")
			return
		}
		targetFull, pathErr := safePath(missionRoot, filepath.FromSlash(target), false)
		if pathErr != nil {
			writeError(w, http.StatusBadRequest, "could not resolve mission target safely")
			return
		}
		if _, statErr := os.Lstat(targetFull); statErr == nil {
			writeError(w, http.StatusConflict, "mission target already exists; move it before importing this file")
			return
		} else if !errors.Is(statErr, fs.ErrNotExist) {
			writeError(w, http.StatusConflict, "could not inspect the mission target")
			return
		}
		chosenTargets = append(chosenTargets, target)
		prepared = append(prepared, data)
		imports = append(imports, dayzModTypesImport{SourcePath: sourceRel, TargetPath: target, ModName: candidate.ModName})
	}
	updatedCore, err := addDayZCoreFiles(coreData, chosenTargets)
	if err != nil {
		writeError(w, http.StatusConflict, "could not update the mission economy registration file: "+err.Error())
		return
	}
	coreFull, err := safePath(missionRoot, filepath.FromSlash(corePath), false)
	if err != nil {
		writeError(w, http.StatusConflict, "could not resolve the mission economy registration file safely")
		return
	}
	if err = ensureDayZNoLinks(missionRoot, filepath.ToSlash(corePath), false); err != nil {
		writeError(w, http.StatusConflict, "mission economy registration file contains an unsafe path")
		return
	}
	for i, target := range chosenTargets {
		if err = ensureDayZSafeDirectories(missionRoot, path.Dir(target)); err != nil {
			writeError(w, http.StatusConflict, "could not create the imported types directory: "+err.Error())
			return
		}
		full, pathErr := safePath(missionRoot, filepath.FromSlash(target), false)
		if pathErr != nil {
			writeError(w, http.StatusConflict, "could not resolve the imported types file safely")
			return
		}
		if err = writeDayZAtomic(full, prepared[i]); err != nil {
			writeError(w, http.StatusInternalServerError, "some mission files may have been copied, but the import could not finish; inspect the mission before retrying")
			return
		}
	}
	if err = writeDayZAtomic(coreFull, updatedCore); err != nil {
		writeError(w, http.StatusInternalServerError, "mod types were copied, but the economy registration file could not be saved; inspect the mission before retrying")
		return
	}
	state.RegisteredFiles = uniqueDayZPaths(append(state.RegisteredFiles, chosenTargets...))
	state.ModImports = uniqueDayZModImports(imports)
	if err = a.saveDayZEconomyState(r.Context(), server.ID, state); err != nil {
		writeError(w, http.StatusInternalServerError, "files were copied and registered, but Docklight could not save their reinstall mappings")
		return
	}
	if state.MinLifetimeHours > 0 {
		if _, err = applyDayZLifetimeFloor(missionRoot, state.MinLifetimeHours); err != nil {
			writeError(w, http.StatusConflict, "files were copied and registered, but the saved lifetime floor could not be applied: "+err.Error())
			return
		}
	}
	a.audit(principal(r), "dayz.economy.import_mod_types", "server", server.ID, fmt.Sprintf("files=%d mission=%s", len(selected), mission))
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "imported": len(selected)})
}

func scanDayZModLoot(root, missionRoot string, imports []dayzModTypesImport) (dayzModLootSummary, error) {
	summary := dayzModLootSummary{Candidates: []dayzModLootCandidate{}}
	dir, err := os.Open(root)
	if err != nil {
		return summary, fmt.Errorf("could not list installed mod folders: %w", err)
	}
	entries, readErr := dir.ReadDir(dayzModLootMaxEntries + 1)
	_ = dir.Close()
	if readErr != nil && !errors.Is(readErr, io.EOF) {
		return summary, fmt.Errorf("could not list installed mod folders: %w", readErr)
	}
	if len(entries) > dayzModLootMaxEntries {
		entries = entries[:dayzModLootMaxEntries]
		summary.Truncated = true
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })
	importedBySource := make(map[string]dayzModTypesImport, len(imports))
	for _, item := range imports {
		if source, sourceErr := cleanDayZModSourcePath(item.SourcePath); sourceErr == nil {
			importedBySource[source] = item
		}
	}
	type targetOwner struct{ source string }
	owners := map[string]targetOwner{}
	entriesSeen, bytesSeen := 0, int64(0)
	stop := false
	for _, entry := range entries {
		if !entry.IsDir() || entry.Type()&os.ModeSymlink != 0 || !strings.HasPrefix(entry.Name(), "@") || !dayzModTokenPattern.MatchString(entry.Name()) {
			continue
		}
		modRoot := filepath.Join(root, entry.Name())
		displayName := dayzModDisplayName(modRoot, strings.TrimPrefix(entry.Name(), "@"))
		targetName := sanitizeDayZModFolder(displayName)
		if targetName == "" {
			targetName = sanitizeDayZModFolder(strings.TrimPrefix(entry.Name(), "@"))
		}
		err = filepath.WalkDir(modRoot, func(full string, item fs.DirEntry, walkErr error) error {
			if walkErr != nil {
				return nil
			}
			if item.Type()&os.ModeSymlink != 0 {
				return nil
			}
			entriesSeen++
			if entriesSeen > dayzModLootMaxEntries || len(summary.Candidates) >= dayzModLootMaxCandidates {
				summary.Truncated = true
				stop = true
				return filepath.SkipAll
			}
			if item.IsDir() {
				if full != modRoot && strings.HasPrefix(strings.ToLower(item.Name()), "storage") {
					return filepath.SkipDir
				}
				return nil
			}
			if !strings.EqualFold(filepath.Ext(item.Name()), ".xml") {
				return nil
			}
			info, infoErr := item.Info()
			if infoErr != nil || !info.Mode().IsRegular() {
				return nil
			}
			if info.Size() < 0 || bytesSeen+info.Size() > dayzModLootMaxBytes {
				summary.Truncated = true
				stop = true
				return filepath.SkipAll
			}
			bytesSeen += info.Size()
			rel, relErr := filepath.Rel(root, full)
			if relErr != nil {
				return nil
			}
			source := filepath.ToSlash(rel)
			cleanSource, sourceErr := cleanDayZModSourcePath(source)
			if sourceErr != nil || cleanSource != source || ensureDayZNoLinks(root, source, false) != nil {
				return nil
			}
			sourceFull, safeErr := safePath(root, filepath.FromSlash(source), false)
			if safeErr != nil {
				return nil
			}
			data, readErr := readDayZRegularFile(sourceFull)
			if readErr != nil {
				return nil
			}
			_, parsed, fragment, normalizeErr := normalizeDayZModTypes(data)
			if normalizeErr != nil {
				return nil
			}
			modRel, relErr := filepath.Rel(modRoot, full)
			if relErr != nil {
				return nil
			}
			target := path.Join(targetName, filepath.ToSlash(modRel))
			target, cleanErr := cleanDayZMissionPath(target)
			if cleanErr != nil || target == "db/types.xml" || hasDayZStoragePart(target) {
				return nil
			}
			candidate := dayzModLootCandidate{
				SourcePath: source, ModToken: entry.Name(), DisplayName: displayName, ModName: targetName,
				TargetPath: target, TypeCount: parsed.count,
				Fragment:  fragment,
				Expansion: strings.Contains(strings.ToLower(displayName), "expansion") || strings.Contains(strings.ToLower(entry.Name()), "expansion"),
			}
			if imported, found := importedBySource[source]; found {
				if _, importedTarget, validErr := validateSavedDayZModImport(root, missionRoot, imported); validErr == nil {
					candidate.Imported = true
					candidate.TargetPath = importedTarget
				} else {
					candidate.TargetClash = true
				}
			}
			if _, statErr := os.Lstat(filepath.Join(missionRoot, filepath.FromSlash(candidate.TargetPath))); statErr == nil {
				candidate.TargetExists = !candidate.Imported
			} else if !errors.Is(statErr, fs.ErrNotExist) {
				candidate.TargetClash = true
			}
			if previous, found := owners[candidate.TargetPath]; found && previous.source != source {
				candidate.TargetClash = true
				for i := range summary.Candidates {
					if summary.Candidates[i].TargetPath == candidate.TargetPath {
						summary.Candidates[i].TargetClash = true
					}
				}
			} else {
				owners[candidate.TargetPath] = targetOwner{source: source}
			}
			summary.Candidates = append(summary.Candidates, candidate)
			return nil
		})
		if err != nil && !errors.Is(err, filepath.SkipAll) {
			return summary, fmt.Errorf("could not scan mod folder %s: %w", entry.Name(), err)
		}
		if stop {
			break
		}
	}
	sort.Slice(summary.Candidates, func(i, j int) bool { return summary.Candidates[i].SourcePath < summary.Candidates[j].SourcePath })
	return summary, nil
}

func dayzModDisplayName(modRoot, fallback string) string {
	meta, err := safePath(modRoot, "meta.cpp", false)
	if err != nil || ensureDayZNoLinks(modRoot, "meta.cpp", true) != nil {
		return fallback
	}
	info, err := os.Lstat(meta)
	if err != nil || !info.Mode().IsRegular() || info.Size() > 256*1024 {
		return fallback
	}
	data, err := readDayZRegularFile(meta)
	if err != nil {
		return fallback
	}
	match := dayzModNamePattern.FindSubmatch(data)
	if len(match) != 2 {
		return fallback
	}
	name := strings.TrimSpace(string(match[1]))
	if name == "" {
		return fallback
	}
	return name
}

func sanitizeDayZModFolder(name string) string {
	var out strings.Builder
	underscore := false
	for _, r := range strings.TrimSpace(name) {
		if unicode.IsLetter(r) || unicode.IsDigit(r) || r == '-' || r == '_' {
			out.WriteRune(r)
			underscore = false
			continue
		}
		if !underscore && out.Len() > 0 {
			out.WriteByte('_')
			underscore = true
		}
		if out.Len() >= 64 {
			break
		}
	}
	return strings.Trim(out.String(), "_-.")
}

func cleanDayZModSourcePath(raw string) (string, error) {
	raw = strings.TrimSpace(strings.ReplaceAll(raw, "\\", "/"))
	if raw == "" || strings.ContainsRune(raw, 0) || strings.ContainsAny(raw, "\r\n") || strings.HasPrefix(raw, "/") {
		return "", errors.New("source path must be relative to the server data directory")
	}
	clean := path.Clean(raw)
	parts := strings.Split(clean, "/")
	if clean == "." || clean == ".." || strings.HasPrefix(clean, "../") || len(parts) < 2 || !strings.HasPrefix(parts[0], "@") || !dayzModTokenPattern.MatchString(parts[0]) || !strings.EqualFold(path.Ext(clean), ".xml") || hasDayZStoragePart(clean) {
		return "", errors.New("source must be an XML file inside a top-level @mod folder")
	}
	for _, part := range parts {
		if part == "" || part == "." || part == ".." {
			return "", errors.New("source path contains an unsafe segment")
		}
	}
	return clean, nil
}

func validateSavedDayZModImport(root, missionRoot string, item dayzModTypesImport) (string, string, error) {
	source, err := cleanDayZModSourcePath(item.SourcePath)
	if err != nil {
		return "", "", err
	}
	parts := strings.Split(source, "/")
	if item.ModName == "" || sanitizeDayZModFolder(item.ModName) != item.ModName || path.Dir(item.TargetPath) == "." {
		return "", "", errors.New("invalid saved mod name or target")
	}
	target, err := cleanDayZMissionPath(item.TargetPath)
	if err != nil || target == "db/types.xml" || hasDayZStoragePart(target) || !strings.HasPrefix(target, item.ModName+"/") || path.Base(target) != path.Base(source) || path.Join(item.ModName, strings.Join(parts[1:], "/")) != target {
		return "", "", errors.New("saved target does not match the source file")
	}
	if err = ensureDayZNoLinks(root, source, true); err != nil {
		return "", "", err
	}
	if err = ensureDayZNoLinks(missionRoot, target, true); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return "", "", err
	}
	sourceFull, err := safePath(root, filepath.FromSlash(source), false)
	if err != nil {
		return "", "", err
	}
	return sourceFull, target, nil
}

func normalizeDayZModTypes(data []byte) ([]byte, parsedDayZTypes, bool, error) {
	var zero parsedDayZTypes
	if len(data) == 0 || len(data) > dayzMaxXMLBytes {
		return nil, zero, false, errors.New("file is empty or exceeds the 8 MiB limit")
	}
	content := bytes.TrimPrefix(data, []byte{0xef, 0xbb, 0xbf})
	if parsed, err := validateDayZModTypesDocument(content); err == nil {
		return append([]byte(nil), content...), parsed, false, nil
	}
	fragment := dayzXMLDeclaration.ReplaceAll(content, nil)
	wrapped := make([]byte, 0, len(fragment)+16)
	wrapped = append(wrapped, "<types>\n"...)
	wrapped = append(wrapped, fragment...)
	wrapped = append(wrapped, "\n</types>\n"...)
	parsed, err := validateDayZModTypesDocument(wrapped)
	if err != nil {
		return nil, zero, true, errors.New("XML must be a <types> document or a fragment of named <type> entries with integer lifetimes")
	}
	return wrapped, parsed, true, nil
}

func validateDayZModTypesDocument(data []byte) (parsedDayZTypes, error) {
	parsed, err := parseDayZTypes(data)
	if err != nil {
		return parsed, err
	}
	if parsed.count == 0 || len(parsed.lifetimes) == 0 {
		return parsed, errors.New("types file must contain named types and lifetimes")
	}
	decoder := xml.NewDecoder(bytes.NewReader(data))
	decoder.Strict = true
	depth, directTypes := 0, 0
	rootSeen := false
	for {
		token, tokenErr := decoder.Token()
		if errors.Is(tokenErr, io.EOF) {
			break
		}
		if tokenErr != nil {
			return parsed, tokenErr
		}
		switch item := token.(type) {
		case xml.Directive:
			return parsed, errors.New("XML directives are not accepted")
		case xml.StartElement:
			if !rootSeen {
				rootSeen = true
				if item.Name.Local != "types" || item.Name.Space != "" {
					return parsed, errors.New("root element must be <types>")
				}
				depth = 1
				continue
			}
			if depth == 1 {
				if item.Name.Local != "type" || item.Name.Space != "" {
					return parsed, errors.New("<types> may contain only direct <type> entries")
				}
				named := false
				for _, attr := range item.Attr {
					if attr.Name.Local == "name" && strings.TrimSpace(attr.Value) != "" {
						named = true
					}
				}
				if !named {
					return parsed, errors.New("every <type> entry needs a name")
				}
				directTypes++
			} else if item.Name.Local == "types" || item.Name.Local == "type" {
				return parsed, errors.New("nested types roots and nested type entries are not accepted")
			}
			depth++
		case xml.EndElement:
			depth--
		}
	}
	if !rootSeen || depth != 0 || directTypes != parsed.count {
		return parsed, errors.New("types structure is invalid")
	}
	return parsed, nil
}

func ensureDayZNoLinks(root, rel string, allowMissing bool) error {
	clean := filepath.Clean(filepath.FromSlash(rel))
	if filepath.IsAbs(clean) || clean == "." || clean == ".." || strings.HasPrefix(clean, ".."+string(filepath.Separator)) {
		return errors.New("path is outside its allowed root")
	}
	current := root
	parts := strings.Split(filepath.ToSlash(clean), "/")
	for i, part := range parts {
		current = filepath.Join(current, part)
		info, err := os.Lstat(current)
		if errors.Is(err, fs.ErrNotExist) && allowMissing {
			return nil
		}
		if err != nil {
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return errors.New("path contains a symbolic link")
		}
		if i < len(parts)-1 && !info.IsDir() {
			return errors.New("path parent is not a directory")
		}
		if i == len(parts)-1 && !info.Mode().IsRegular() && !info.IsDir() {
			return errors.New("path is not a regular file or directory")
		}
	}
	return nil
}

func ensureDayZSafeDirectories(root, rel string) error {
	if rel == "." || rel == "" {
		return nil
	}
	clean := path.Clean(strings.ReplaceAll(rel, "\\", "/"))
	if clean == ".." || strings.HasPrefix(clean, "../") || strings.HasPrefix(clean, "/") || hasDayZStoragePart(clean) {
		return errors.New("directory path is unsafe")
	}
	current := root
	for _, part := range strings.Split(clean, "/") {
		current = filepath.Join(current, part)
		info, err := os.Lstat(current)
		if errors.Is(err, fs.ErrNotExist) {
			if err = os.Mkdir(current, 0750); err != nil && !errors.Is(err, fs.ErrExist) {
				return err
			}
			info, err = os.Lstat(current)
		}
		if err != nil {
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
			return errors.New("directory path contains a link or non-directory")
		}
	}
	return nil
}

func uniqueDayZModImports(items []dayzModTypesImport) []dayzModTypesImport {
	seen := map[string]bool{}
	seenTargets := map[string]bool{}
	out := make([]dayzModTypesImport, 0, len(items))
	for _, item := range items {
		source, sourceErr := cleanDayZModSourcePath(item.SourcePath)
		target, targetErr := cleanDayZMissionPath(item.TargetPath)
		parts := strings.Split(source, "/")
		if sourceErr != nil || targetErr != nil || item.ModName == "" || sanitizeDayZModFolder(item.ModName) != item.ModName || seen[source] || seenTargets[target] || target == "db/types.xml" || hasDayZStoragePart(target) || path.Dir(target) == "." || !strings.HasPrefix(target, item.ModName+"/") || path.Join(item.ModName, strings.Join(parts[1:], "/")) != target {
			continue
		}
		item.SourcePath, item.TargetPath = source, target
		seen[source] = true
		seenTargets[target] = true
		out = append(out, item)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].SourcePath < out[j].SourcePath })
	return out
}
