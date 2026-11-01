package panel

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
)

func TestDocklightInstallableAppShellRoutes(t *testing.T) {
	a, _, _ := testApp(t)
	h := a.Router()

	manifestResponse := httptest.NewRecorder()
	h.ServeHTTP(manifestResponse, httptest.NewRequest(http.MethodGet, "/manifest.webmanifest", nil))
	if manifestResponse.Code != http.StatusOK || manifestResponse.Header().Get("Cache-Control") != "no-cache" {
		t.Fatalf("manifest response: %d, cache=%q", manifestResponse.Code, manifestResponse.Header().Get("Cache-Control"))
	}
	var manifest struct {
		Name        string `json:"name"`
		ShortName   string `json:"short_name"`
		StartURL    string `json:"start_url"`
		Scope       string `json:"scope"`
		Display     string `json:"display"`
		ThemeColor  string `json:"theme_color"`
		Background  string `json:"background_color"`
		Description string `json:"description"`
		Icons       []struct {
			Src     string `json:"src"`
			Sizes   string `json:"sizes"`
			Type    string `json:"type"`
			Purpose string `json:"purpose"`
		} `json:"icons"`
	}
	if err := json.Unmarshal(manifestResponse.Body.Bytes(), &manifest); err != nil {
		t.Fatal(err)
	}
	if manifest.Name != "Docklight" || manifest.ShortName != "Docklight" || manifest.StartURL != "/" || manifest.Scope != "/" || manifest.Display != "standalone" || manifest.ThemeColor == "" || manifest.Background == "" || manifest.Description == "" {
		t.Fatalf("incomplete install manifest: %+v", manifest)
	}
	if len(manifest.Icons) != 1 || manifest.Icons[0].Src != "/brand.svg" || manifest.Icons[0].Sizes != "any" || manifest.Icons[0].Type != "image/svg+xml" || manifest.Icons[0].Purpose != "any maskable" {
		t.Fatalf("unexpected app icons: %+v", manifest.Icons)
	}

	workerResponse := httptest.NewRecorder()
	h.ServeHTTP(workerResponse, httptest.NewRequest(http.MethodGet, "/service-worker.js", nil))
	worker := workerResponse.Body.String()
	if workerResponse.Code != http.StatusOK || workerResponse.Header().Get("Cache-Control") != "no-cache" || workerResponse.Header().Get("Service-Worker-Allowed") != "/" {
		t.Fatalf("worker response: %d, headers=%v", workerResponse.Code, workerResponse.Header())
	}
	if strings.Contains(worker, "__DOCKLIGHT_CACHE_VERSION__") || !regexp.MustCompile("CACHE_NAME = `\\$\\{CACHE_PREFIX\\}[a-f0-9]{24}`;").MatchString(worker) {
		t.Fatalf("worker cache version was not resolved: %q", worker)
	}
	for _, required := range []string{"'/app.js'", "'/manifest.webmanifest'", "url.pathname === '/'", "request.method !== 'GET'"} {
		if !strings.Contains(worker, required) {
			t.Errorf("worker missing allowlist guard %q", required)
		}
	}
	post := testRequest(h, http.MethodPost, "/service-worker.js", "{}", "")
	if post.Code != http.StatusMethodNotAllowed {
		t.Fatalf("POST worker status %d: %s", post.Code, post.Body.String())
	}
	api := testRequest(h, http.MethodGet, "/api/health", "", "")
	if api.Code != http.StatusOK || api.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("API cache policy: %d, cache=%q", api.Code, api.Header().Get("Cache-Control"))
	}
}
