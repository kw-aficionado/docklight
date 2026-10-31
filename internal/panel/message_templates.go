package panel

import (
	"database/sql"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"unicode"

	"github.com/go-chi/chi/v5"
)

type messageTemplate struct {
	ID         string   `json:"id"`
	Name       string   `json:"name"`
	Body       string   `json:"body,omitempty"`
	Parameters []string `json:"parameters"`
	BuiltIn    bool     `json:"builtin"`
}

type scheduledMessagePayload struct {
	Body   string         `json:"body"`
	Values map[string]int `json:"values"`
}

var messagePlaceholder = regexp.MustCompile(`{{([^{}]*)}}`)

func messageTemplateParameters(body string) ([]string, error) {
	allowed := map[string]bool{"server_name": true, "minutes": true, "seconds": true}
	seen := map[string]bool{}
	parameters := []string{}
	withoutMatches := messagePlaceholder.ReplaceAllString(body, "")
	for _, match := range messagePlaceholder.FindAllStringSubmatch(body, -1) {
		key := match[1]
		if !allowed[key] {
			return nil, fmt.Errorf("unsupported message placeholder {{%s}}; use {{server_name}}, {{minutes}}, or {{seconds}}", key)
		}
		if !seen[key] {
			seen[key] = true
			parameters = append(parameters, key)
		}
	}
	if strings.Contains(withoutMatches, "{{") || strings.Contains(withoutMatches, "}}") {
		return nil, errors.New("message template contains an unclosed placeholder")
	}
	return parameters, nil
}

func normalizeMessageTemplate(name, body string) (string, string, []string, error) {
	name = strings.TrimSpace(name)
	body = strings.TrimSpace(body)
	if name == "" || len(name) > 80 {
		return "", "", nil, errors.New("template name must contain 1 to 80 characters")
	}
	if body == "" || len(body) > 4096 {
		return "", "", nil, errors.New("template body must contain 1 to 4096 characters")
	}
	if strings.IndexFunc(body, unicode.IsControl) >= 0 {
		return "", "", nil, errors.New("template body must be a single console command")
	}
	parameters, err := messageTemplateParameters(body)
	if err != nil {
		return "", "", nil, err
	}
	return name, body, parameters, nil
}

func prepareScheduledMessage(body string, values map[string]int) (scheduledMessagePayload, error) {
	parameters, err := messageTemplateParameters(body)
	if err != nil {
		return scheduledMessagePayload{}, err
	}
	needed := map[string]bool{}
	for _, parameter := range parameters {
		if parameter != "server_name" {
			needed[parameter] = true
		}
	}
	for parameter, value := range values {
		if !needed[parameter] {
			return scheduledMessagePayload{}, fmt.Errorf("%s is not used by this message template", parameter)
		}
		limit := 10080
		if parameter == "seconds" {
			limit = 86400
		} else if parameter != "minutes" {
			return scheduledMessagePayload{}, fmt.Errorf("unsupported message value %q", parameter)
		}
		if value < 0 || value > limit {
			return scheduledMessagePayload{}, fmt.Errorf("%s must be from 0 to %d", parameter, limit)
		}
	}
	for parameter := range needed {
		if _, ok := values[parameter]; !ok {
			return scheduledMessagePayload{}, fmt.Errorf("enter a value for {{%s}}", parameter)
		}
	}
	if len(values) != len(needed) {
		return scheduledMessagePayload{}, errors.New("message values do not match the selected template")
	}
	copyValues := make(map[string]int, len(values))
	for key, value := range values {
		copyValues[key] = value
	}
	return scheduledMessagePayload{Body: body, Values: copyValues}, nil
}

func renderScheduledMessage(payload scheduledMessagePayload, serverName string) (string, error) {
	parameters, err := messageTemplateParameters(payload.Body)
	if err != nil {
		return "", err
	}
	values := map[string]string{"server_name": strings.TrimSpace(collapseControl(serverName))}
	if values["server_name"] == "" {
		return "", errors.New("server name is required to render the message")
	}
	for _, parameter := range parameters {
		if parameter == "server_name" {
			continue
		}
		value, ok := payload.Values[parameter]
		if !ok {
			return "", fmt.Errorf("saved message is missing the %s value", parameter)
		}
		values[parameter] = strconv.Itoa(value)
	}
	command := messagePlaceholder.ReplaceAllStringFunc(payload.Body, func(token string) string {
		match := messagePlaceholder.FindStringSubmatch(token)
		return values[match[1]]
	})
	return validateScheduledCommand(command)
}

func (a *App) listMessageTemplates(w http.ResponseWriter, r *http.Request) {
	rows, err := a.db.Query(`SELECT id,name,body,builtin FROM message_templates ORDER BY builtin DESC,name,id`)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not list message templates")
		return
	}
	defer rows.Close()
	out := []messageTemplate{}
	u := principal(r)
	admin := u.Role == "admin" && (!u.IsAPIToken || u.APIScopes["admin"])
	for rows.Next() {
		var item messageTemplate
		var builtin int
		if err = rows.Scan(&item.ID, &item.Name, &item.Body, &builtin); err != nil {
			writeError(w, http.StatusInternalServerError, "could not read message template metadata")
			return
		}
		item.BuiltIn = builtin != 0
		_, item.Body, item.Parameters, err = normalizeMessageTemplate(item.Name, item.Body)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "a saved message template is invalid; edit or remove it as an administrator")
			return
		}
		if !admin {
			item.Body = ""
		}
		out = append(out, item)
	}
	if err = rows.Err(); err != nil {
		writeError(w, http.StatusInternalServerError, "could not read message templates")
		return
	}
	writeJSON(w, http.StatusOK, out)
}

func (a *App) createMessageTemplate(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Name string `json:"name"`
		Body string `json:"body"`
	}
	if decodeJSON(w, r, &in, 12*1024) != nil {
		return
	}
	name, body, parameters, err := normalizeMessageTemplate(in.Name, in.Body)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	id, err := newID()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not generate a message template ID")
		return
	}
	if _, err = a.db.Exec(`INSERT INTO message_templates(id,name,body,builtin) VALUES(?,?,?,0)`, id, name, body); err != nil {
		writeError(w, http.StatusInternalServerError, "could not save message template")
		return
	}
	a.audit(principal(r), "message_template.create", "message_template", id, "name="+name)
	writeJSON(w, http.StatusCreated, messageTemplate{ID: id, Name: name, Body: body, Parameters: parameters})
}

func (a *App) updateMessageTemplate(w http.ResponseWriter, r *http.Request) {
	var builtin int
	err := a.db.QueryRow(`SELECT builtin FROM message_templates WHERE id=?`, chi.URLParam(r, "id")).Scan(&builtin)
	if errors.Is(err, sql.ErrNoRows) {
		writeError(w, http.StatusNotFound, "message template not found")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not read message template")
		return
	}
	if builtin != 0 {
		writeError(w, http.StatusConflict, "built-in message templates cannot be changed; create a custom copy")
		return
	}
	var in struct {
		Name string `json:"name"`
		Body string `json:"body"`
	}
	if decodeJSON(w, r, &in, 12*1024) != nil {
		return
	}
	name, body, parameters, err := normalizeMessageTemplate(in.Name, in.Body)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	result, err := a.db.Exec(`UPDATE message_templates SET name=?,body=?,updated_at=CURRENT_TIMESTAMP WHERE id=? AND builtin=0`, name, body, chi.URLParam(r, "id"))
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not update message template")
		return
	}
	changed, _ := result.RowsAffected()
	if changed == 0 {
		writeError(w, http.StatusNotFound, "message template no longer exists")
		return
	}
	a.audit(principal(r), "message_template.update", "message_template", chi.URLParam(r, "id"), "name="+name)
	writeJSON(w, http.StatusOK, messageTemplate{ID: chi.URLParam(r, "id"), Name: name, Body: body, Parameters: parameters})
}

func (a *App) deleteMessageTemplate(w http.ResponseWriter, r *http.Request) {
	result, err := a.db.Exec(`DELETE FROM message_templates WHERE id=? AND builtin=0`, chi.URLParam(r, "id"))
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not delete message template")
		return
	}
	changed, _ := result.RowsAffected()
	if changed == 0 {
		var exists int
		if err = a.db.QueryRow(`SELECT count(*) FROM message_templates WHERE id=?`, chi.URLParam(r, "id")).Scan(&exists); err != nil {
			writeError(w, http.StatusInternalServerError, "could not verify message template")
			return
		}
		if exists != 0 {
			writeError(w, http.StatusConflict, "built-in message templates cannot be deleted")
		} else {
			writeError(w, http.StatusNotFound, "message template not found")
		}
		return
	}
	a.audit(principal(r), "message_template.delete", "message_template", chi.URLParam(r, "id"), "")
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (a *App) messageTemplateByID(id string) (string, string, error) {
	var name, body string
	if err := a.db.QueryRow(`SELECT name,body FROM message_templates WHERE id=?`, id).Scan(&name, &body); err != nil {
		return "", "", err
	}
	_, normalizedBody, _, err := normalizeMessageTemplate(name, body)
	if err != nil {
		return "", "", errors.New("saved message template is invalid; edit it as an administrator")
	}
	return name, normalizedBody, nil
}
