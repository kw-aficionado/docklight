package panel

import (
	"database/sql"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"

	"example.com/yggdrasil-panel/internal/rune"
	"example.com/yggdrasil-panel/internal/runeimport"
)

func (a *App) importEgg(w http.ResponseWriter, r *http.Request) {
	a.importExternalRune(w, r, "Pterodactyl egg", "template.egg_import", runeimport.ImportEgg)
}

func (a *App) importXML(w http.ResponseWriter, r *http.Request) {
	a.importExternalRune(w, r, "XML template", "template.xml_import", runeimport.ImportXML)
}

func (a *App) importYggdrasilRune(w http.ResponseWriter, r *http.Request) {
	a.importExternalRune(w, r, "Yggdrasil Rune", "template.yggdrasil_import", runeimport.ImportYggdrasil)
}

func (a *App) importExternalRune(w http.ResponseWriter, r *http.Request, label, action string, translate func([]byte) (rune.Rune, []string, error)) {
	if !a.requireAdmin(w, r) {
		return
	}
	input, err := readRuneImportFile(w, r, label)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	gs, warnings, err := translate(input)
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
		writeError(w, http.StatusBadRequest, "generated template exceeds the 512 KiB template limit")
		return
	}
	validated, err := rune.Parse(string(encoded))
	if err != nil {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("generated template did not pass Docklight validation: %v", err))
		return
	}

	tx, err := a.db.BeginTx(r.Context(), nil)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not save the imported template")
		return
	}
	defer tx.Rollback()
	var builtin int
	err = tx.QueryRowContext(r.Context(), `SELECT builtin FROM gameskills WHERE id=?`, validated.ID).Scan(&builtin)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		writeError(w, http.StatusInternalServerError, "could not check the imported template ID")
		return
	}
	if builtin != 0 {
		writeError(w, http.StatusConflict, "built-in templates cannot be overwritten; change the imported template name or ID")
		return
	}
	if _, err = tx.ExecContext(r.Context(), `INSERT INTO gameskills(id,name,category,version,yaml_blob,builtin) VALUES(?,?,?,?,?,0)
		ON CONFLICT(id) DO UPDATE SET name=excluded.name,category=excluded.category,version=excluded.version,yaml_blob=excluded.yaml_blob,builtin=0,source_host='',source_repo='',source_path='',source_ref=''`,
		validated.ID, validated.Name, validated.Category, validated.Version, string(encoded)); err != nil {
		writeError(w, http.StatusInternalServerError, "could not save the imported template")
		return
	}
	if err = tx.Commit(); err != nil {
		writeError(w, http.StatusInternalServerError, "could not save the imported template")
		return
	}
	a.audit(principal(r), action, "gameskill", validated.ID, fmt.Sprintf("warnings=%d", len(warnings)))
	writeJSON(w, http.StatusCreated, map[string]any{"id": validated.ID, "name": validated.Name, "warnings": warnings})
}

func readRuneImportFile(w http.ResponseWriter, r *http.Request, label string) ([]byte, error) {
	r.Body = http.MaxBytesReader(w, r.Body, runeimport.MaxSize+(64<<10))
	var input []byte
	if strings.HasPrefix(strings.ToLower(r.Header.Get("Content-Type")), "multipart/form-data") {
		if err := r.ParseMultipartForm(64 << 10); err != nil {
			return nil, fmt.Errorf("upload a valid multipart form with one %s file (maximum 1 MiB)", label)
		}
		if r.MultipartForm != nil {
			defer r.MultipartForm.RemoveAll()
		}
		file, _, err := r.FormFile("file")
		if err != nil {
			return nil, fmt.Errorf("select a %s file in the file field", label)
		}
		defer file.Close()
		input, err = io.ReadAll(io.LimitReader(file, runeimport.MaxSize+1))
		if err != nil {
			return nil, fmt.Errorf("could not read the %s file", label)
		}
	} else {
		var err error
		input, err = io.ReadAll(io.LimitReader(r.Body, runeimport.MaxSize+1))
		if err != nil {
			return nil, fmt.Errorf("could not read the %s file", label)
		}
	}
	if len(input) > runeimport.MaxSize {
		return nil, fmt.Errorf("%s exceeds the 1 MiB upload limit", label)
	}
	return input, nil
}
