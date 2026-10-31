package panel

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"example.com/yggdrasil-panel/internal/docker"
	"example.com/yggdrasil-panel/internal/security"
	"github.com/go-chi/chi/v5"
)

type registryLogin struct {
	ID        string `json:"id"`
	Registry  string `json:"registry"`
	Username  string `json:"username"`
	HasSecret bool   `json:"has_secret"`
}

type registryLoginInput struct {
	Registry string `json:"registry"`
	Username string `json:"username"`
	Secret   string `json:"secret"`
}

func normalizeRegistryName(value string) (string, error) {
	raw := strings.TrimSpace(value)
	if raw == "" || strings.ContainsAny(raw, "\r\n\x00") {
		return "", errors.New("registry must be a hostname, optionally with a port")
	}
	if strings.EqualFold(raw, "docker hub") || strings.EqualFold(raw, "dockerhub") {
		return "docker.io", nil
	}
	if strings.EqualFold(raw, "https://index.docker.io/v1/") || strings.EqualFold(raw, "https://index.docker.io/v1") {
		return "docker.io", nil
	}
	if strings.Contains(raw, "://") {
		u, err := url.Parse(raw)
		if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
			return "", errors.New("registry URL must contain only an HTTP(S) host")
		}
		path := strings.TrimRight(u.EscapedPath(), "/")
		if strings.EqualFold(u.Hostname(), "index.docker.io") && (path == "/v1" || path == "") {
			return "docker.io", nil
		}
		if path != "" {
			return "", errors.New("registry URL cannot contain a path")
		}
		raw = u.Host
	}
	if strings.ContainsAny(raw, "/\\?#@") {
		return "", errors.New("registry must be a hostname, optionally with a port")
	}

	host, port := raw, ""
	if strings.HasPrefix(raw, "[") {
		if h, p, err := net.SplitHostPort(raw); err == nil {
			host, port = h, p
		} else if strings.HasSuffix(raw, "]") {
			host = strings.TrimSuffix(strings.TrimPrefix(raw, "["), "]")
		} else {
			return "", errors.New("registry IPv6 addresses must be valid and bracketed when a port is used")
		}
	} else if strings.Count(raw, ":") == 1 {
		var err error
		host, port, err = net.SplitHostPort(raw)
		if err != nil || port == "" {
			return "", errors.New("registry port is invalid")
		}
	} else if strings.Count(raw, ":") > 1 {
		if net.ParseIP(raw) == nil {
			return "", errors.New("registry IPv6 address is invalid")
		}
	}
	if port != "" {
		n, err := strconv.Atoi(port)
		if err != nil || n < 1 || n > 65535 {
			return "", errors.New("registry port must be between 1 and 65535")
		}
		port = strconv.Itoa(n)
	}
	host = strings.TrimSuffix(strings.ToLower(host), ".")
	if host == "" {
		return "", errors.New("registry hostname is required")
	}
	if ip := net.ParseIP(host); ip != nil {
		host = ip.String()
		if strings.Contains(host, ":") {
			host = "[" + host + "]"
		}
	} else if !validRegistryDNSName(host) {
		return "", errors.New("registry hostname is invalid")
	}
	if port != "" {
		return host + ":" + port, nil
	}
	switch host {
	case "index.docker.io", "registry-1.docker.io":
		return "docker.io", nil
	default:
		return host, nil
	}
}

func validRegistryDNSName(host string) bool {
	if len(host) > 253 || host == "localhost" {
		return host == "localhost"
	}
	for _, label := range strings.Split(host, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, r := range label {
			if !(r >= 'a' && r <= 'z') && !(r >= '0' && r <= '9') && r != '-' {
				return false
			}
		}
	}
	return true
}

// imageRegistry follows Docker's reference split: a registry is explicit only
// in the first path component when it contains a dot, a port, or is localhost.
func imageRegistry(image string) (string, error) {
	value := strings.TrimSpace(image)
	if value == "" || strings.ContainsAny(value, " \t\r\n\x00\\") {
		return "", errors.New("image reference is empty or invalid")
	}
	slash := strings.IndexByte(value, '/')
	if slash < 0 {
		return "docker.io", nil
	}
	first := value[:slash]
	if first == "" {
		return "", errors.New("image reference has no registry or repository")
	}
	if strings.Contains(first, ".") || strings.Contains(first, ":") || strings.EqualFold(first, "localhost") || strings.HasPrefix(first, "[") {
		return normalizeRegistryName(first)
	}
	return "docker.io", nil
}

func registryAuthServerAddress(registry string) string {
	if registry == "docker.io" {
		return "https://index.docker.io/v1/"
	}
	return registry
}

func (a *App) listRegistryLogins(w http.ResponseWriter, _ *http.Request) {
	rows, err := a.db.Query(`SELECT id,registry,username,secret_enc FROM registry_logins ORDER BY registry COLLATE NOCASE`)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not read registry logins")
		return
	}
	defer rows.Close()
	out := make([]registryLogin, 0)
	for rows.Next() {
		var item registryLogin
		var encrypted string
		if err = rows.Scan(&item.ID, &item.Registry, &item.Username, &encrypted); err != nil {
			writeError(w, http.StatusInternalServerError, "could not read registry logins")
			return
		}
		item.HasSecret = encrypted != ""
		out = append(out, item)
	}
	if err = rows.Err(); err != nil {
		writeError(w, http.StatusInternalServerError, "could not read registry logins")
		return
	}
	writeJSON(w, http.StatusOK, out)
}

func (a *App) saveRegistryLogin(w http.ResponseWriter, r *http.Request) {
	var in registryLoginInput
	if decodeJSON(w, r, &in, 32*1024) != nil {
		return
	}
	registry, err := normalizeRegistryName(in.Registry)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	username := strings.TrimSpace(in.Username)
	if username == "" || len(username) > 512 || strings.ContainsAny(username, "\r\n\x00") {
		writeError(w, http.StatusBadRequest, "registry username must contain 1 to 512 characters")
		return
	}
	if in.Secret == "" || len(in.Secret) > 16*1024 || strings.ContainsRune(in.Secret, '\x00') {
		writeError(w, http.StatusBadRequest, "registry secret is required and must be at most 16384 bytes")
		return
	}
	encrypted, err := security.Encrypt([]byte(a.cfg.Auth.SecretKey), in.Secret)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not encrypt registry secret")
		return
	}
	id, err := newID()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not create registry login id")
		return
	}
	_, lookupErr := a.db.Exec(`INSERT INTO registry_logins(id,registry,username,secret_enc) VALUES(?,?,?,?)
		ON CONFLICT(registry) DO UPDATE SET username=excluded.username,secret_enc=excluded.secret_enc,updated_at=CURRENT_TIMESTAMP`, id, registry, username, encrypted)
	if lookupErr != nil {
		writeError(w, http.StatusInternalServerError, "could not save registry login")
		return
	}
	if err = a.db.QueryRow(`SELECT id FROM registry_logins WHERE registry=?`, registry).Scan(&id); err != nil {
		writeError(w, http.StatusInternalServerError, "could not save registry login")
		return
	}
	a.audit(principal(r), "registry_login.save", "registry_login", id, registry)
	writeJSON(w, http.StatusOK, registryLogin{ID: id, Registry: registry, Username: username, HasSecret: true})
}

func (a *App) deleteRegistryLogin(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	var registry string
	err := a.db.QueryRow(`SELECT registry FROM registry_logins WHERE id=?`, id).Scan(&registry)
	if errors.Is(err, sql.ErrNoRows) {
		writeError(w, http.StatusNotFound, "registry login not found")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not read registry login")
		return
	}
	if _, err = a.db.Exec(`DELETE FROM registry_logins WHERE id=?`, id); err != nil {
		writeError(w, http.StatusInternalServerError, "could not delete registry login")
		return
	}
	a.audit(principal(r), "registry_login.delete", "registry_login", id, registry)
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (a *App) readRegistryLogin(id string) (registryLoginInput, string, error) {
	var login registryLoginInput
	var encrypted string
	err := a.db.QueryRow(`SELECT registry,username,secret_enc FROM registry_logins WHERE id=?`, id).Scan(&login.Registry, &login.Username, &encrypted)
	if err != nil {
		return registryLoginInput{}, "", err
	}
	login.Secret, err = security.Decrypt([]byte(a.cfg.Auth.SecretKey), encrypted)
	if err != nil {
		return registryLoginInput{}, "", errors.New("saved registry secret cannot be decrypted; check auth.secret_key")
	}
	return login, login.Secret, nil
}

func (a *App) testRegistryLogin(w http.ResponseWriter, r *http.Request) {
	login, secret, err := a.readRegistryLogin(chi.URLParam(r, "id"))
	if errors.Is(err, sql.ErrNoRows) {
		writeError(w, http.StatusNotFound, "registry login not found")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()
	err = a.engine.TestRegistryAuth(ctx, docker.RegistryAuthConfig{Username: login.Username, Password: secret, ServerAddress: registryAuthServerAddress(login.Registry)})
	if err != nil {
		message := strings.ReplaceAll(err.Error(), secret, "[redacted]")
		writeError(w, http.StatusBadGateway, "registry login test failed: "+message)
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (a *App) pullImage(ctx context.Context, image string) error {
	registry, err := imageRegistry(image)
	if err != nil {
		return fmt.Errorf("invalid image registry: %w", err)
	}
	var id, username, encrypted string
	err = a.db.QueryRow(`SELECT id,username,secret_enc FROM registry_logins WHERE registry=?`, registry).Scan(&id, &username, &encrypted)
	if errors.Is(err, sql.ErrNoRows) {
		return a.engine.Pull(ctx, image)
	}
	if err != nil {
		return fmt.Errorf("read registry login: %w", err)
	}
	secret, err := security.Decrypt([]byte(a.cfg.Auth.SecretKey), encrypted)
	if err != nil {
		return errors.New("saved registry secret cannot be decrypted; check auth.secret_key")
	}
	err = a.engine.PullWithAuth(ctx, image, docker.RegistryAuthConfig{Username: username, Password: secret, ServerAddress: registryAuthServerAddress(registry)})
	if err != nil {
		return errors.New(strings.ReplaceAll(err.Error(), secret, "[redacted]"))
	}
	return nil
}
