package panel

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"example.com/yggdrasil-panel/internal/compose"
	"example.com/yggdrasil-panel/internal/rune"
	"go.yaml.in/yaml/v3"
)

func (a *App) importCompose(w http.ResponseWriter, r *http.Request) {
	if !a.requireAdmin(w, r) {
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, compose.MaxSize+(64<<10))
	var input []byte
	mainService := r.URL.Query().Get("main")
	name := r.URL.Query().Get("name")
	if strings.HasPrefix(strings.ToLower(r.Header.Get("Content-Type")), "multipart/form-data") {
		if err := r.ParseMultipartForm(64 << 10); err != nil {
			writeError(w, http.StatusBadRequest, "upload a valid multipart form with one Compose YAML file (maximum 1 MiB)")
			return
		}
		if r.MultipartForm != nil {
			defer r.MultipartForm.RemoveAll()
		}
		if value := strings.TrimSpace(r.FormValue("main")); value != "" {
			mainService = value
		}
		if value := strings.TrimSpace(r.FormValue("name")); value != "" {
			name = value
		}
		file, _, err := r.FormFile("file")
		if err != nil {
			writeError(w, http.StatusBadRequest, "select a Compose YAML file in the file field")
			return
		}
		defer file.Close()
		input, err = io.ReadAll(io.LimitReader(file, compose.MaxSize+1))
		if err != nil {
			writeError(w, http.StatusBadRequest, "could not read the Compose file")
			return
		}
	} else {
		var err error
		input, err = io.ReadAll(io.LimitReader(r.Body, compose.MaxSize+1))
		if err != nil {
			writeError(w, http.StatusBadRequest, "could not read the Compose file")
			return
		}
	}
	if len(input) > compose.MaxSize {
		writeError(w, http.StatusBadRequest, "Compose file exceeds the 1 MiB upload limit")
		return
	}
	gs, warnings, err := compose.Translate(input, mainService, name)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	encoded, err := marshalRuneYAML(gs)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not serialize the imported template")
		return
	}
	if len(encoded) > 512*1024 {
		writeError(w, http.StatusBadRequest, "generated template exceeds the 512 KiB template limit; remove unused environment entries and try again")
		return
	}
	validated, err := rune.Parse(string(encoded))
	if err != nil {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("generated template did not pass Docklight validation: %v", err))
		return
	}
	var builtin int
	_ = a.db.QueryRow(`SELECT builtin FROM gameskills WHERE id=?`, validated.ID).Scan(&builtin)
	if builtin != 0 {
		writeError(w, http.StatusConflict, "built-in templates cannot be overwritten; change the Compose project name or template name")
		return
	}
	_, err = a.db.Exec(`INSERT INTO gameskills(id,name,category,version,yaml_blob,builtin) VALUES(?,?,?,?,?,0)
		ON CONFLICT(id) DO UPDATE SET name=excluded.name,category=excluded.category,version=excluded.version,yaml_blob=excluded.yaml_blob,builtin=0,source_host='',source_repo='',source_path='',source_ref=''`,
		validated.ID, validated.Name, validated.Category, validated.Version, string(encoded))
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not save the imported template")
		return
	}
	a.audit(principal(r), "template.compose_import", "gameskill", validated.ID, fmt.Sprintf("services=%d warnings=%d", composeServiceCount(validated), len(warnings)))
	writeJSON(w, http.StatusCreated, map[string]any{"id": validated.ID, "name": validated.Name, "warnings": warnings})
}

func marshalRuneYAML(gs rune.Rune) ([]byte, error) {
	encoded, err := json.Marshal(gs)
	if err != nil {
		return nil, err
	}
	var body map[string]any
	if err = json.Unmarshal(encoded, &body); err != nil {
		return nil, err
	}
	removeEmptyMaps(body)
	return yaml.Marshal(map[string]any{"gameskill": body})
}

func removeEmptyMaps(value any) {
	switch node := value.(type) {
	case map[string]any:
		for key, child := range node {
			removeEmptyMaps(child)
			if childMap, ok := child.(map[string]any); ok && len(childMap) == 0 {
				delete(node, key)
			}
		}
	case []any:
		for _, child := range node {
			removeEmptyMaps(child)
		}
	}
}

func composeServiceCount(gs rune.Rune) int {
	count := 1
	if gs.Stack != nil {
		count += len(gs.Stack.Services)
	}
	return count
}
