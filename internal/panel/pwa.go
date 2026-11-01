package panel

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"strings"

	yggdrasil "example.com/yggdrasil-panel"
)

var pwaShellAssets = []struct {
	url  string
	file string
}{
	{url: "/", file: "web/index.html"},
	{url: "/app.js", file: "web/app.js"},
	{url: "/ui-utils.mjs", file: "web/ui-utils.mjs"},
	{url: "/style.css", file: "web/style.css"},
	{url: "/config-editor.css", file: "web/config-editor.css"},
	{url: "/brand.svg", file: "web/brand.svg"},
}

func docklightManifest() map[string]any {
	return map[string]any{
		"id":               "/",
		"name":             "Docklight",
		"short_name":       "Docklight",
		"description":      "A self-hosted control panel for game servers and apps.",
		"start_url":        "/",
		"scope":            "/",
		"display":          "standalone",
		"background_color": "#0a1013",
		"theme_color":      "#0a1013",
		"icons": []map[string]string{{
			"src": "/brand.svg", "sizes": "any", "type": "image/svg+xml", "purpose": "any maskable",
		}},
	}
}

func (a *App) serviceWorker(w http.ResponseWriter, r *http.Request) {
	worker, err := yggdrasil.WebFS.ReadFile("web/service-worker.js")
	if err != nil {
		http.Error(w, "service worker unavailable", http.StatusInternalServerError)
		return
	}
	hash := sha256.New()
	for _, asset := range pwaShellAssets {
		contents, readErr := yggdrasil.WebFS.ReadFile(asset.file)
		if readErr != nil {
			http.Error(w, "app shell unavailable", http.StatusInternalServerError)
			return
		}
		_, _ = hash.Write([]byte(asset.url + "\x00"))
		_, _ = hash.Write(contents)
	}
	manifest, err := json.Marshal(docklightManifest())
	if err != nil {
		http.Error(w, "app manifest unavailable", http.StatusInternalServerError)
		return
	}
	_, _ = hash.Write([]byte("/manifest.webmanifest\x00"))
	_, _ = hash.Write(manifest)
	_, _ = hash.Write(worker)
	version := hex.EncodeToString(hash.Sum(nil)[:12])
	worker = []byte(strings.Replace(string(worker), "__DOCKLIGHT_CACHE_VERSION__", version, 1))

	w.Header().Set("Content-Type", "text/javascript; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Service-Worker-Allowed", "/")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(worker)
}
