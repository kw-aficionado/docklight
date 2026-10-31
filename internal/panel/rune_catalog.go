package panel

import (
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path"
	"regexp"
	"sort"
	"strings"
	"time"

	"example.com/yggdrasil-panel/internal/rune"
	"example.com/yggdrasil-panel/internal/security"
	"github.com/go-chi/chi/v5"
)

const (
	runeCatalogFileLimit     = 512 * 1024
	runeCatalogResponseLimit = 4 * 1024 * 1024
	runeCatalogCacheTTL      = 10 * time.Minute
	runeCatalogFileScanLimit = 200
	runeRepoTokenMask        = "••••••••"
)

var (
	runeRepoNamePattern = regexp.MustCompile(`^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$`)
	runeRepoRefPattern  = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._/-]{0,127}$`)
)

type runeCatalogCacheEntry struct {
	Entries []runeCatalogEntry
	Expires time.Time
}

type runeCatalogEntry struct {
	Name string `json:"name"`
	Path string `json:"path"`
	Type string `json:"type"`
	Size int64  `json:"size,omitempty"`
}

type runeRepoConfig struct {
	ID    string
	Name  string
	Host  string
	Repo  string
	Path  string
	Ref   string
	Token string
}

type runeRepoInput struct {
	Name  string `json:"name"`
	Host  string `json:"host"`
	Repo  string `json:"repo"`
	Path  string `json:"path"`
	Ref   string `json:"ref"`
	Token string `json:"token"`
}

type runeCatalogAPIEntry struct {
	Name     string `json:"name"`
	Path     string `json:"path"`
	Type     string `json:"type"`
	Size     int64  `json:"size"`
	Encoding string `json:"encoding"`
	Content  string `json:"content"`
}

type installedRuneSource struct {
	ID      string
	Name    string
	Version int
	Builtin bool
	Host    string
	Repo    string
	Path    string
	Ref     string
}

func (a *App) runeCatalogClient() *http.Client {
	var client http.Client
	if a.runeCatalogHTTPClient != nil {
		client = *a.runeCatalogHTTPClient
	}
	if client.Timeout <= 0 {
		client.Timeout = 8 * time.Second
	}
	client.CheckRedirect = func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }
	return &client
}

func normalizeRuneRepo(in runeRepoInput) (runeRepoConfig, error) {
	name := strings.TrimSpace(in.Name)
	if name == "" || len(name) > 80 || strings.ContainsAny(name, "\r\n\x00") {
		return runeRepoConfig{}, errors.New("repository name must contain 1 to 80 printable characters")
	}
	repo := strings.Trim(strings.TrimSpace(in.Repo), "/")
	if err := validateCatalogRepoName(repo); err != nil {
		return runeRepoConfig{}, err
	}
	host := strings.TrimSpace(in.Host)
	if strings.EqualFold(host, "github.com") || strings.EqualFold(host, "https://github.com") {
		host = ""
	}
	if host != "" {
		u, err := url.Parse(host)
		if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
			return runeRepoConfig{}, errors.New("repository host must be an HTTPS base URL without credentials, query, or fragment")
		}
		for _, part := range strings.Split(u.Path, "/") {
			if part == "." || part == ".." {
				return runeRepoConfig{}, errors.New("repository host path cannot contain dot segments")
			}
		}
		u.Scheme = "https"
		u.Host = strings.ToLower(u.Host)
		u.Path = strings.TrimRight(u.Path, "/")
		u.RawPath = ""
		host = strings.TrimRight(u.String(), "/")
	}
	repoPath, err := safeCatalogPath(in.Path)
	if err != nil {
		return runeRepoConfig{}, fmt.Errorf("repository folder: %w", err)
	}
	ref, err := safeCatalogRef(in.Ref)
	if err != nil {
		return runeRepoConfig{}, err
	}
	token := strings.TrimSpace(in.Token)
	if len(token) > 4096 || strings.ContainsAny(token, "\r\n\x00") {
		return runeRepoConfig{}, errors.New("repository token is invalid or too long")
	}
	return runeRepoConfig{Name: name, Host: host, Repo: repo, Path: repoPath, Ref: ref, Token: token}, nil
}

func validateCatalogRepoName(repo string) error {
	if len(repo) > 200 || !runeRepoNamePattern.MatchString(repo) {
		return errors.New("repository must use owner/name format")
	}
	for _, part := range strings.Split(repo, "/") {
		if part == "." || part == ".." {
			return errors.New("repository path is invalid")
		}
	}
	return nil
}

func safeCatalogPath(value string) (string, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return "", nil
	}
	if strings.ContainsAny(value, "\\\x00") || strings.HasPrefix(value, "/") || strings.HasSuffix(value, "/") || len(value) > 512 {
		return "", errors.New("use a relative slash-separated path")
	}
	for _, part := range strings.Split(value, "/") {
		if part == "" || part == "." || part == ".." || strings.ContainsAny(part, "\r\n") {
			return "", errors.New("path contains an invalid segment")
		}
	}
	return value, nil
}

func safeCatalogBrowsePath(base, relative string) (string, error) {
	relative, err := safeCatalogPath(relative)
	if err != nil {
		return "", err
	}
	if relative != "" && strings.Count(relative, "/") > 0 {
		return "", errors.New("catalog browsing supports one subfolder level")
	}
	if base == "" {
		return relative, nil
	}
	if relative == "" {
		return base, nil
	}
	return path.Join(base, relative), nil
}

func safeCatalogRef(value string) (string, error) {
	ref := strings.TrimSpace(value)
	if ref == "" {
		ref = "main"
	}
	if !runeRepoRefPattern.MatchString(ref) || strings.Contains(ref, "..") || strings.Contains(ref, "//") || strings.HasSuffix(ref, "/") || strings.ContainsAny(ref, "\\\x00") {
		return "", errors.New("branch or tag name is invalid")
	}
	return ref, nil
}

func safeCatalogInstallPath(base, requested string) (string, error) {
	requested, err := safeCatalogPath(requested)
	if err != nil || requested == "" {
		if err == nil {
			err = errors.New("choose a YAML file")
		}
		return "", err
	}
	if strings.Count(requested, "/") > 1 {
		return "", errors.New("catalog files may be at the root or one subfolder deep")
	}
	if !strings.EqualFold(path.Ext(requested), ".yaml") && !strings.EqualFold(path.Ext(requested), ".yml") {
		return "", errors.New("only .yaml and .yml files can be installed")
	}
	if base == "" {
		return requested, nil
	}
	return path.Join(base, requested), nil
}

func safeCatalogSelectedFilePath(base, selected string) (string, error) {
	selected = strings.TrimSpace(selected)
	if base != "" && strings.HasPrefix(selected, base+"/") {
		selected = strings.TrimPrefix(selected, base+"/")
	} else if base != "" && selected == base {
		return "", errors.New("choose a YAML file")
	}
	return safeCatalogInstallPath(base, selected)
}

func runeSourceHost(repo runeRepoConfig) string {
	if repo.Host == "" {
		return "github.com"
	}
	return repo.Host
}

func runeRepoSourceKey(host, name string) string {
	normalizedHost := strings.TrimRight(host, "/")
	if strings.EqualFold(normalizedHost, "github.com") {
		normalizedHost = "github.com"
	} else if parsed, err := url.Parse(normalizedHost); err == nil && parsed.Host != "" {
		normalizedHost = strings.ToLower(parsed.Scheme) + "://" + strings.ToLower(parsed.Host) + strings.TrimRight(parsed.EscapedPath(), "/")
	}
	return normalizedHost + "\x00" + name
}

func (a *App) getRuneRepo(id string) (runeRepoConfig, error) {
	var out runeRepoConfig
	var encrypted string
	err := a.db.QueryRow(`SELECT id,name,host,repo,path,ref,token_enc FROM rune_repos WHERE id=?`, id).Scan(&out.ID, &out.Name, &out.Host, &out.Repo, &out.Path, &out.Ref, &encrypted)
	if err != nil {
		return runeRepoConfig{}, err
	}
	if encrypted != "" {
		out.Token, err = security.Decrypt([]byte(a.cfg.Auth.SecretKey), encrypted)
		if err != nil {
			return runeRepoConfig{}, errors.New("stored repository token cannot be decrypted; check auth.secret_key")
		}
	}
	return out, nil
}

func runeRepoSummary(repo runeRepoConfig) map[string]any {
	host := repo.Host
	if host == "" {
		host = "github.com"
	}
	return map[string]any{"id": repo.ID, "name": repo.Name, "host": host, "repo": repo.Repo, "path": repo.Path, "ref": repo.Ref, "has_token": repo.Token != ""}
}

func (a *App) listRuneRepos(w http.ResponseWriter, _ *http.Request) {
	rows, err := a.db.Query(`SELECT id,name,host,repo,path,ref,token_enc FROM rune_repos ORDER BY name COLLATE NOCASE,id`)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not list catalog repositories")
		return
	}
	defer rows.Close()
	out := make([]map[string]any, 0)
	for rows.Next() {
		var repo runeRepoConfig
		var encrypted string
		if err = rows.Scan(&repo.ID, &repo.Name, &repo.Host, &repo.Repo, &repo.Path, &repo.Ref, &encrypted); err != nil {
			writeError(w, http.StatusInternalServerError, "could not read catalog repositories")
			return
		}
		repo.Token = ""
		if encrypted != "" {
			if _, err = security.Decrypt([]byte(a.cfg.Auth.SecretKey), encrypted); err != nil {
				writeError(w, http.StatusInternalServerError, "a saved catalog token cannot be decrypted; check auth.secret_key")
				return
			}
			repo.Token = "configured"
		}
		out = append(out, runeRepoSummary(repo))
	}
	if err = rows.Err(); err != nil {
		writeError(w, http.StatusInternalServerError, "could not read catalog repositories")
		return
	}
	writeJSON(w, http.StatusOK, out)
}

func (a *App) createRuneRepo(w http.ResponseWriter, r *http.Request) {
	var in runeRepoInput
	if decodeJSON(w, r, &in, 12*1024) != nil {
		return
	}
	repo, err := normalizeRuneRepo(in)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	var count int
	if err = a.db.QueryRow(`SELECT count(*) FROM rune_repos`).Scan(&count); err != nil {
		writeError(w, http.StatusInternalServerError, "could not check repository limit")
		return
	}
	if count >= 50 {
		writeError(w, http.StatusConflict, "the panel supports up to 50 catalog repositories")
		return
	}
	repo, err = a.saveRuneRepo(w, r, repo, "catalog_repository.create")
	if err != nil {
		return
	}
	writeJSON(w, http.StatusCreated, runeRepoSummary(repo))
}

func (a *App) updateRuneRepo(w http.ResponseWriter, r *http.Request) {
	current, err := a.getRuneRepo(chi.URLParam(r, "id"))
	if errors.Is(err, sql.ErrNoRows) {
		writeError(w, http.StatusNotFound, "catalog repository not found")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not read catalog repository")
		return
	}
	var in runeRepoInput
	if decodeJSON(w, r, &in, 12*1024) != nil {
		return
	}
	repo, err := normalizeRuneRepo(in)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if isRuneRepoTokenMask(in.Token) {
		repo.Token = current.Token
	}
	repo.ID = current.ID
	repo, err = a.saveRuneRepo(w, r, repo, "catalog_repository.update")
	if err != nil {
		return
	}
	writeJSON(w, http.StatusOK, runeRepoSummary(repo))
}

func isRuneRepoTokenMask(value string) bool {
	value = strings.TrimSpace(value)
	return value == runeRepoTokenMask || value == "********" || value == "••••••••••••"
}

func (a *App) saveRuneRepo(w http.ResponseWriter, r *http.Request, repo runeRepoConfig, action string) (runeRepoConfig, error) {
	var encrypted string
	if repo.Token != "" {
		var err error
		encrypted, err = security.Encrypt([]byte(a.cfg.Auth.SecretKey), repo.Token)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "could not encrypt repository token")
			return runeRepoConfig{}, err
		}
	}
	if repo.ID == "" {
		var err error
		repo.ID, err = newID()
		if err != nil {
			writeError(w, http.StatusInternalServerError, "could not create repository id")
			return runeRepoConfig{}, err
		}
		_, err = a.db.Exec(`INSERT INTO rune_repos(id,name,host,repo,path,ref,token_enc) VALUES(?,?,?,?,?,?,?)`, repo.ID, repo.Name, repo.Host, repo.Repo, repo.Path, repo.Ref, encrypted)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "could not save catalog repository")
			return runeRepoConfig{}, err
		}
	} else {
		result, err := a.db.Exec(`UPDATE rune_repos SET name=?,host=?,repo=?,path=?,ref=?,token_enc=?,updated_at=CURRENT_TIMESTAMP WHERE id=?`, repo.Name, repo.Host, repo.Repo, repo.Path, repo.Ref, encrypted, repo.ID)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "could not save catalog repository")
			return runeRepoConfig{}, err
		}
		changed, _ := result.RowsAffected()
		if changed == 0 {
			writeError(w, http.StatusNotFound, "catalog repository not found")
			return runeRepoConfig{}, sql.ErrNoRows
		}
	}
	a.runeCatalogMu.Lock()
	clear(a.runeCatalogCache)
	a.runeCatalogMu.Unlock()
	a.audit(principal(r), action, "catalog_repository", repo.ID, runeSourceHost(repo)+" "+repo.Repo)
	return repo, nil
}

func (a *App) deleteRuneRepo(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	repo, err := a.getRuneRepo(id)
	if errors.Is(err, sql.ErrNoRows) {
		writeError(w, http.StatusNotFound, "catalog repository not found")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not read catalog repository")
		return
	}
	if _, err = a.db.Exec(`DELETE FROM rune_repos WHERE id=?`, id); err != nil {
		writeError(w, http.StatusInternalServerError, "could not delete catalog repository")
		return
	}
	a.runeCatalogMu.Lock()
	clear(a.runeCatalogCache)
	a.runeCatalogMu.Unlock()
	a.audit(principal(r), "catalog_repository.delete", "catalog_repository", id, runeSourceHost(repo)+" "+repo.Repo)
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (a *App) getGitHubCatalogSettings(w http.ResponseWriter, _ *http.Request) {
	var encrypted string
	err := a.db.QueryRow(`SELECT token_enc FROM github_catalog_settings WHERE id=1`).Scan(&encrypted)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		writeError(w, http.StatusInternalServerError, "could not read GitHub catalog settings")
		return
	}
	if encrypted != "" {
		if _, err = security.Decrypt([]byte(a.cfg.Auth.SecretKey), encrypted); err != nil {
			writeError(w, http.StatusInternalServerError, "the saved GitHub token cannot be decrypted; check auth.secret_key")
			return
		}
	}
	writeJSON(w, http.StatusOK, map[string]bool{"has_token": encrypted != ""})
}

func (a *App) updateGitHubCatalogSettings(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Token string `json:"token"`
	}
	if decodeJSON(w, r, &in, 8*1024) != nil {
		return
	}
	token := strings.TrimSpace(in.Token)
	if token == "********" || token == runeRepoTokenMask || token == "••••••••••••" {
		var current string
		if err := a.db.QueryRow(`SELECT token_enc FROM github_catalog_settings WHERE id=1`).Scan(&current); err != nil && !errors.Is(err, sql.ErrNoRows) {
			writeError(w, http.StatusInternalServerError, "could not read GitHub catalog settings")
			return
		}
		writeJSON(w, http.StatusOK, map[string]bool{"has_token": current != ""})
		return
	}
	if len(token) > 4096 || strings.ContainsAny(token, "\r\n\x00") {
		writeError(w, http.StatusBadRequest, "GitHub token is invalid or too long")
		return
	}
	encrypted := ""
	if token != "" {
		var err error
		encrypted, err = security.Encrypt([]byte(a.cfg.Auth.SecretKey), token)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "could not encrypt GitHub token")
			return
		}
	}
	if _, err := a.db.Exec(`INSERT INTO github_catalog_settings(id,token_enc) VALUES(1,?) ON CONFLICT(id) DO UPDATE SET token_enc=excluded.token_enc,updated_at=CURRENT_TIMESTAMP`, encrypted); err != nil {
		writeError(w, http.StatusInternalServerError, "could not save GitHub catalog settings")
		return
	}
	a.runeCatalogMu.Lock()
	clear(a.runeCatalogCache)
	a.runeCatalogMu.Unlock()
	a.audit(principal(r), "catalog.github_token.update", "catalog_settings", "github", "")
	writeJSON(w, http.StatusOK, map[string]bool{"has_token": token != ""})
}

func (a *App) readGitHubCatalogToken() (string, error) {
	var encrypted string
	err := a.db.QueryRow(`SELECT token_enc FROM github_catalog_settings WHERE id=1`).Scan(&encrypted)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	if encrypted == "" {
		return "", nil
	}
	plain, err := security.Decrypt([]byte(a.cfg.Auth.SecretKey), encrypted)
	if err != nil {
		return "", errors.New("the saved GitHub token cannot be decrypted; check auth.secret_key")
	}
	return plain, nil
}

func (a *App) listRuneRepoConfigs() ([]runeRepoConfig, error) {
	rows, err := a.db.Query(`SELECT id,name,host,repo,path,ref,token_enc FROM rune_repos ORDER BY name COLLATE NOCASE,id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]runeRepoConfig, 0)
	for rows.Next() {
		var repo runeRepoConfig
		var encrypted string
		if err = rows.Scan(&repo.ID, &repo.Name, &repo.Host, &repo.Repo, &repo.Path, &repo.Ref, &encrypted); err != nil {
			return nil, err
		}
		if encrypted != "" {
			repo.Token, err = security.Decrypt([]byte(a.cfg.Auth.SecretKey), encrypted)
			if err != nil {
				return nil, errors.New("a saved repository token cannot be decrypted; check auth.secret_key")
			}
		}
		out = append(out, repo)
	}
	return out, rows.Err()
}

func (a *App) githubRepoConfig(repoName, ref string) (runeRepoConfig, error) {
	if err := validateCatalogRepoName(repoName); err != nil {
		return runeRepoConfig{}, err
	}
	requestedRef := ref
	ref, err := safeCatalogRef(ref)
	if err != nil {
		return runeRepoConfig{}, err
	}
	repo := runeRepoConfig{Name: repoName, Repo: repoName, Ref: ref}
	repos, err := a.listRuneRepoConfigs()
	if err != nil {
		return runeRepoConfig{}, err
	}
	for _, saved := range repos {
		if saved.Host == "" && strings.EqualFold(saved.Repo, repoName) {
			repo.Token = saved.Token
			if requestedRef == "" && saved.Ref != "" {
				repo.Ref = saved.Ref
			}
			if saved.Path != "" {
				repo.Path = saved.Path
			}
			if saved.ID != "" {
				repo.ID = saved.ID
			}
			if repo.Token == "" {
				repo.Token, err = a.readGitHubCatalogToken()
			}
			return repo, err
		}
	}
	repo.Token, err = a.readGitHubCatalogToken()
	return repo, err
}

func (a *App) catalogBaseURL(repo runeRepoConfig) (*url.URL, error) {
	base := "https://api.github.com"
	if repo.Host != "" {
		base = repo.Host
	}
	u, err := url.Parse(base)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil {
		return nil, errors.New("saved catalog host is invalid")
	}
	return u, nil
}

func appendURLPath(base *url.URL, segments ...string) string {
	u := *base
	rawPath := strings.TrimRight(u.EscapedPath(), "/")
	for _, segment := range segments {
		if segment == "" {
			continue
		}
		for _, item := range strings.Split(segment, "/") {
			rawPath += "/" + url.PathEscape(item)
		}
	}
	decoded, err := url.PathUnescape(rawPath)
	if err == nil {
		u.Path = decoded
		u.RawPath = rawPath
	}
	return u.String()
}

func (a *App) catalogAPIRequest(ctx context.Context, repo runeRepoConfig, remotePath string) (*http.Response, error) {
	base, err := a.catalogBaseURL(repo)
	if err != nil {
		return nil, err
	}
	segments := []string{"repos", repo.Repo, "contents"}
	if repo.Host != "" {
		segments = append([]string{"api", "v1"}, segments...)
	}
	if remotePath != "" {
		segments = append(segments, remotePath)
	}
	endpoint := appendURLPath(base, segments...)
	u, err := url.Parse(endpoint)
	if err != nil {
		return nil, errors.New("could not build catalog request")
	}
	query := u.Query()
	query.Set("ref", repo.Ref)
	u.RawQuery = query.Encode()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, errors.New("could not prepare catalog request")
	}
	request.Header.Set("Accept", "application/vnd.github+json, application/json")
	request.Header.Set("User-Agent", "Docklight-Panel")
	if repo.Token != "" {
		if repo.Host == "" {
			request.Header.Set("Authorization", "Bearer "+repo.Token)
		} else {
			request.Header.Set("Authorization", "token "+repo.Token)
		}
	}
	response, err := a.runeCatalogClient().Do(request)
	if err != nil {
		return nil, fmt.Errorf("catalog host could not be reached: %w", err)
	}
	if response.Request != nil && (response.Request.URL.Scheme != u.Scheme || !strings.EqualFold(response.Request.URL.Host, u.Host) || response.Request.URL.Path != u.Path) {
		_ = response.Body.Close()
		return nil, errors.New("catalog host redirected the request; redirects are not followed")
	}
	return response, nil
}

func readCatalogResponse(response *http.Response, limit int64) ([]byte, error) {
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return nil, fmt.Errorf("catalog host returned HTTP %d", response.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, limit+1))
	if err != nil {
		return nil, errors.New("could not read catalog response")
	}
	if int64(len(body)) > limit {
		return nil, errors.New("catalog response exceeded its size limit")
	}
	return body, nil
}

func validateCatalogEntry(entry runeCatalogAPIEntry, requestedDir string) (runeCatalogEntry, bool) {
	name := strings.TrimSpace(entry.Name)
	if name == "" || name == "." || name == ".." || strings.ContainsAny(name, "/\\\x00\r\n") {
		return runeCatalogEntry{}, false
	}
	remotePath, err := safeCatalogPath(entry.Path)
	if err != nil || remotePath == "" {
		return runeCatalogEntry{}, false
	}
	remoteDir := path.Dir(remotePath)
	if remoteDir == "." {
		remoteDir = ""
	}
	if remoteDir != requestedDir || path.Base(remotePath) != name {
		return runeCatalogEntry{}, false
	}
	switch entry.Type {
	case "dir":
		return runeCatalogEntry{Name: name, Path: remotePath, Type: "dir"}, true
	case "file":
		if entry.Size > runeCatalogFileLimit || (strings.ToLower(path.Ext(name)) != ".yaml" && strings.ToLower(path.Ext(name)) != ".yml") {
			return runeCatalogEntry{}, false
		}
		return runeCatalogEntry{Name: name, Path: remotePath, Type: "file", Size: entry.Size}, true
	default:
		return runeCatalogEntry{}, false
	}
}

func (a *App) listCatalogEntries(ctx context.Context, repo runeRepoConfig, remotePath string) ([]runeCatalogEntry, error) {
	key := runeRepoSourceKey(runeSourceHost(repo), repo.Repo) + "\x00" + repo.Ref + "\x00" + remotePath
	now := time.Now()
	a.runeCatalogMu.Lock()
	if cached, ok := a.runeCatalogCache[key]; ok && now.Before(cached.Expires) {
		entries := append([]runeCatalogEntry(nil), cached.Entries...)
		a.runeCatalogMu.Unlock()
		return entries, nil
	}
	a.runeCatalogMu.Unlock()

	response, err := a.catalogAPIRequest(ctx, repo, remotePath)
	if err != nil {
		return nil, err
	}
	body, err := readCatalogResponse(response, runeCatalogResponseLimit)
	if err != nil {
		return nil, err
	}
	var raw []runeCatalogAPIEntry
	if err = json.Unmarshal(body, &raw); err != nil {
		return nil, errors.New("catalog response was not a directory listing")
	}
	entries := make([]runeCatalogEntry, 0, len(raw))
	for _, entry := range raw {
		if parsed, ok := validateCatalogEntry(entry, remotePath); ok {
			if parsed.Type != "dir" || remotePath == repo.Path {
				entries = append(entries, parsed)
			}
		}
	}
	sort.Slice(entries, func(i, j int) bool {
		if entries[i].Type != entries[j].Type {
			return entries[i].Type == "dir"
		}
		return strings.ToLower(entries[i].Name) < strings.ToLower(entries[j].Name)
	})
	a.runeCatalogMu.Lock()
	if a.runeCatalogCache == nil {
		a.runeCatalogCache = make(map[string]runeCatalogCacheEntry)
	}
	if len(a.runeCatalogCache) >= 256 {
		var oldestKey string
		var oldest time.Time
		for cacheKey, cached := range a.runeCatalogCache {
			if oldestKey == "" || cached.Expires.Before(oldest) {
				oldestKey, oldest = cacheKey, cached.Expires
			}
		}
		delete(a.runeCatalogCache, oldestKey)
	}
	a.runeCatalogCache[key] = runeCatalogCacheEntry{Entries: append([]runeCatalogEntry(nil), entries...), Expires: now.Add(runeCatalogCacheTTL)}
	a.runeCatalogMu.Unlock()
	return entries, nil
}

func (a *App) browseGitHubCatalog(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query()
	repo, err := a.githubRepoConfig(strings.TrimSpace(query.Get("repo")), strings.TrimSpace(query.Get("ref")))
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	relative, err := safeCatalogPath(query.Get("path"))
	if err != nil || relative != "" && strings.Count(relative, "/") > 0 {
		writeError(w, http.StatusBadRequest, "catalog browsing supports one subfolder level")
		return
	}
	remotePath, err := safeCatalogBrowsePath(repo.Path, relative)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	entries, err := a.listCatalogEntries(r.Context(), repo, remotePath)
	if err != nil {
		writeError(w, http.StatusBadGateway, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"host": "github.com", "repo": repo.Repo, "ref": repo.Ref, "path": relative, "entries": entries})
}

func (a *App) browseSavedRuneRepo(w http.ResponseWriter, r *http.Request) {
	repo, err := a.getRuneRepo(chi.URLParam(r, "id"))
	if errors.Is(err, sql.ErrNoRows) {
		writeError(w, http.StatusNotFound, "catalog repository not found")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not read catalog repository")
		return
	}
	remotePath, err := safeCatalogBrowsePath(repo.Path, r.URL.Query().Get("path"))
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	entries, err := a.listCatalogEntries(r.Context(), repo, remotePath)
	if err != nil {
		writeError(w, http.StatusBadGateway, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"repository": runeRepoSummary(repo), "path": r.URL.Query().Get("path"), "entries": entries})
}

func (a *App) catalogFile(ctx context.Context, repo runeRepoConfig, remotePath string) ([]byte, error) {
	response, err := a.catalogAPIRequest(ctx, repo, remotePath)
	if err != nil {
		return nil, err
	}
	body, err := readCatalogResponse(response, 2*runeCatalogFileLimit+64*1024)
	if err != nil {
		return nil, err
	}
	var file runeCatalogAPIEntry
	if err = json.Unmarshal(body, &file); err != nil || file.Type != "file" {
		return nil, errors.New("catalog file response was invalid")
	}
	responsePath, pathErr := safeCatalogPath(file.Path)
	if pathErr != nil || responsePath != remotePath {
		return nil, errors.New("catalog file path did not match the requested path")
	}
	if file.Size > runeCatalogFileLimit {
		return nil, errors.New("catalog file exceeds the 512 KiB limit")
	}
	if !strings.EqualFold(path.Ext(remotePath), ".yaml") && !strings.EqualFold(path.Ext(remotePath), ".yml") {
		return nil, errors.New("only YAML catalog files can be installed")
	}
	if !strings.EqualFold(file.Encoding, "base64") {
		return nil, errors.New("catalog file did not use the expected base64 encoding")
	}
	decoded, err := base64.StdEncoding.DecodeString(strings.Join(strings.Fields(file.Content), ""))
	if err != nil {
		return nil, errors.New("catalog file content was not valid base64")
	}
	if len(decoded) > runeCatalogFileLimit {
		return nil, errors.New("catalog file exceeds the 512 KiB limit")
	}
	return decoded, nil
}

func (a *App) installGitHubRune(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Repo string `json:"repo"`
		Path string `json:"path"`
		Ref  string `json:"ref"`
	}
	if decodeJSON(w, r, &in, 8*1024) != nil {
		return
	}
	repo, err := a.githubRepoConfig(strings.TrimSpace(in.Repo), strings.TrimSpace(in.Ref))
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	remotePath, err := safeCatalogSelectedFilePath(repo.Path, in.Path)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	a.installCatalogRune(w, r, repo, remotePath)
}

func (a *App) installSavedRuneRepo(w http.ResponseWriter, r *http.Request) {
	repo, err := a.getRuneRepo(chi.URLParam(r, "id"))
	if errors.Is(err, sql.ErrNoRows) {
		writeError(w, http.StatusNotFound, "catalog repository not found")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not read catalog repository")
		return
	}
	var in struct {
		Path string `json:"path"`
		Ref  string `json:"ref"`
	}
	if decodeJSON(w, r, &in, 8*1024) != nil {
		return
	}
	if strings.TrimSpace(in.Ref) != "" {
		repo.Ref, err = safeCatalogRef(in.Ref)
		if err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
	}
	remotePath, err := safeCatalogSelectedFilePath(repo.Path, in.Path)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	a.installCatalogRune(w, r, repo, remotePath)
}

func (a *App) installCatalogRune(w http.ResponseWriter, r *http.Request, repo runeRepoConfig, remotePath string) {
	body, err := a.catalogFile(r.Context(), repo, remotePath)
	if err != nil {
		writeError(w, http.StatusBadGateway, err.Error())
		return
	}
	gs, err := rune.Parse(string(body))
	if err != nil {
		writeError(w, http.StatusBadRequest, "catalog YAML failed validation: "+err.Error())
		return
	}
	var builtin int
	err = a.db.QueryRow(`SELECT builtin FROM gameskills WHERE id=?`, gs.ID).Scan(&builtin)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		writeError(w, http.StatusInternalServerError, "could not check existing template")
		return
	}
	if builtin != 0 {
		writeError(w, http.StatusConflict, "built-in templates cannot be overwritten")
		return
	}
	host := runeSourceHost(repo)
	_, err = a.db.Exec(`INSERT INTO gameskills(id,name,category,version,yaml_blob,builtin,source_host,source_repo,source_path,source_ref)
		VALUES(?,?,?,?,?,0,?,?,?,?)
		ON CONFLICT(id) DO UPDATE SET name=excluded.name,category=excluded.category,version=excluded.version,yaml_blob=excluded.yaml_blob,source_host=excluded.source_host,source_repo=excluded.source_repo,source_path=excluded.source_path,source_ref=excluded.source_ref
		WHERE gameskills.builtin=0`, gs.ID, gs.Name, gs.Category, gs.Version, string(body), host, repo.Repo, remotePath, repo.Ref)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not install template from the catalog")
		return
	}
	var builtinAfter int
	if err = a.db.QueryRow(`SELECT builtin FROM gameskills WHERE id=?`, gs.ID).Scan(&builtinAfter); err != nil || builtinAfter != 0 {
		writeError(w, http.StatusConflict, "built-in templates cannot be overwritten")
		return
	}
	a.audit(principal(r), "template.catalog_import", "gameskill", gs.ID, host+" "+repo.Repo+"/"+remotePath)
	writeJSON(w, http.StatusOK, map[string]any{"id": gs.ID, "name": gs.Name, "version": gs.Version, "source_host": host, "source_repo": repo.Repo, "source_path": remotePath, "source_ref": repo.Ref})
}

func (a *App) runeSourceList() ([]installedRuneSource, error) {
	rows, err := a.db.Query(`SELECT id,name,version,builtin,source_host,source_repo,source_path,source_ref FROM gameskills ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]installedRuneSource, 0)
	for rows.Next() {
		var item installedRuneSource
		var builtin int
		if err = rows.Scan(&item.ID, &item.Name, &item.Version, &builtin, &item.Host, &item.Repo, &item.Path, &item.Ref); err != nil {
			return nil, err
		}
		item.Builtin = builtin != 0
		out = append(out, item)
	}
	return out, rows.Err()
}

func (a *App) checkRuneUpdates(w http.ResponseWriter, r *http.Request) {
	installed, err := a.runeSourceList()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not load installed templates")
		return
	}
	repos, err := a.listRuneRepoConfigs()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not read catalog repositories")
		return
	}
	updates := make([]map[string]any, 0)
	notes := make([]string, 0)
	if len(repos) == 0 {
		unsourced := false
		for _, item := range installed {
			if !item.Builtin {
				if item.Host != "" && item.Repo != "" && item.Path != "" {
					notes = append(notes, fmt.Sprintf("Source gone for %s: no saved repository matches %s/%s.", item.Name, item.Host, item.Repo))
				} else {
					unsourced = true
				}
			}
		}
		if unsourced {
			notes = append(notes, "No catalog repository is saved; templates without a source cannot be checked for updates.")
		}
		writeJSON(w, http.StatusOK, map[string]any{"updates": updates, "notes": notes})
		return
	}
	bySource := make(map[string]runeRepoConfig, len(repos))
	for _, repo := range repos {
		bySource[runeRepoSourceKey(runeSourceHost(repo), repo.Repo)] = repo
	}
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Minute)
	defer cancel()
	for _, item := range installed {
		if item.Builtin {
			continue
		}
		if item.Host != "" && item.Repo != "" && item.Path != "" {
			repo, found := bySource[runeRepoSourceKey(item.Host, item.Repo)]
			if !found {
				notes = append(notes, fmt.Sprintf("Source gone for %s: no saved repository matches %s/%s.", item.Name, item.Host, item.Repo))
				continue
			}
			if item.Ref != "" {
				repo.Ref = item.Ref
			}
			available, checkErr := a.fetchCatalogRune(ctx, repo, item.Path)
			if checkErr != nil {
				notes = append(notes, fmt.Sprintf("Could not check %s from %s/%s: %s.", item.Name, item.Host, item.Repo, safeCatalogError(checkErr)))
				continue
			}
			if available.ID != item.ID {
				notes = append(notes, fmt.Sprintf("Catalog file for %s now declares a different template id; no update was applied.", item.Name))
				continue
			}
			if available.Version > item.Version {
				updates = append(updates, runeUpdateSummary(item, available, repo, item.Path))
			}
			continue
		}
		available, source, sourcePath, checkErr := a.findUnsourcedRuneUpdate(ctx, repos, item.ID)
		if checkErr != nil {
			notes = append(notes, fmt.Sprintf("Could not check %s against saved catalogs: %s.", item.Name, safeCatalogError(checkErr)))
			continue
		}
		if available.ID != "" && available.Version > item.Version {
			updates = append(updates, runeUpdateSummary(item, available, source, sourcePath))
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"updates": updates, "notes": notes})
}

func safeCatalogError(err error) string {
	message := strings.TrimSpace(err.Error())
	if message == "" {
		return "the repository could not be reached"
	}
	return message
}

func (a *App) fetchCatalogRune(ctx context.Context, repo runeRepoConfig, remotePath string) (rune.Rune, error) {
	remotePath, err := safeCatalogPath(remotePath)
	if err != nil || remotePath == "" || (!strings.EqualFold(path.Ext(remotePath), ".yaml") && !strings.EqualFold(path.Ext(remotePath), ".yml")) {
		return rune.Rune{}, errors.New("saved source path is invalid")
	}
	body, err := a.catalogFile(ctx, repo, remotePath)
	if err != nil {
		return rune.Rune{}, err
	}
	return rune.Parse(string(body))
}

func (a *App) findUnsourcedRuneUpdate(ctx context.Context, repos []runeRepoConfig, id string) (rune.Rune, runeRepoConfig, string, error) {
	var best rune.Rune
	var source runeRepoConfig
	var sourcePath string
	checked := 0
	var firstErr error
	for _, repo := range repos {
		root, err := a.listCatalogEntries(ctx, repo, repo.Path)
		if err != nil {
			if firstErr == nil {
				firstErr = fmt.Errorf("%s/%s: %w", runeSourceHost(repo), repo.Repo, err)
			}
			continue
		}
		folders := []string{""}
		for _, entry := range root {
			if entry.Type == "dir" {
				folders = append(folders, strings.TrimPrefix(entry.Path, strings.TrimSuffix(repo.Path, "/")+"/"))
			}
		}
		for _, folder := range folders {
			folderPath, pathErr := safeCatalogBrowsePath(repo.Path, folder)
			if pathErr != nil {
				continue
			}
			entries := root
			if folder != "" {
				entries, err = a.listCatalogEntries(ctx, repo, folderPath)
				if err != nil {
					if firstErr == nil {
						firstErr = fmt.Errorf("%s/%s: %w", runeSourceHost(repo), repo.Repo, err)
					}
					continue
				}
			}
			for _, entry := range entries {
				if entry.Type != "file" {
					continue
				}
				checked++
				if checked > runeCatalogFileScanLimit {
					return best, source, sourcePath, fmt.Errorf("update scan reached the %d-file limit", runeCatalogFileScanLimit)
				}
				candidate, fileErr := a.fetchCatalogRune(ctx, repo, entry.Path)
				if fileErr != nil {
					if firstErr == nil {
						firstErr = fmt.Errorf("%s/%s/%s: %w", runeSourceHost(repo), repo.Repo, entry.Name, fileErr)
					}
					continue
				}
				if candidate.ID == id && candidate.Version > best.Version {
					best, source, sourcePath = candidate, repo, entry.Path
				}
			}
		}
	}
	if best.ID != "" {
		return best, source, sourcePath, nil
	}
	return best, source, sourcePath, firstErr
}

func runeUpdateSummary(installed installedRuneSource, available rune.Rune, repo runeRepoConfig, remotePath string) map[string]any {
	return map[string]any{
		"id": installed.ID, "name": available.Name,
		"installed_version": installed.Version, "available_version": available.Version,
		"download_url":  catalogBrowserURL(repo, remotePath),
		"repository_id": repo.ID, "source_host": runeSourceHost(repo), "source_repo": repo.Repo,
		"path": remotePath, "ref": repo.Ref,
	}
}

func catalogBrowserURL(repo runeRepoConfig, remotePath string) string {
	remotePath = escapeCatalogURLPath(remotePath)
	if repo.Host == "" {
		return "https://github.com/" + repo.Repo + "/blob/" + escapeCatalogURLPath(repo.Ref) + "/" + remotePath
	}
	return strings.TrimRight(repo.Host, "/") + "/" + repo.Repo + "/src/branch/" + escapeCatalogURLPath(repo.Ref) + "/" + remotePath
}

func escapeCatalogURLPath(value string) string {
	parts := strings.Split(value, "/")
	for i := range parts {
		parts[i] = url.PathEscape(parts[i])
	}
	return strings.Join(parts, "/")
}
