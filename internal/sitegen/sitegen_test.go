package sitegen

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestGenerateDocsIsDeterministicAndEscapesSource(t *testing.T) {
	root := t.TempDir()
	writeTestFile(t, filepath.Join(root, "docs", "getting-started.md"), `# Start here

Read the [next page](guides/steam.md#account).

<script>alert("not markup")</script>

[bad link](javascript:alert(1))
`)
	writeTestFile(t, filepath.Join(root, "docs", "guides", "steam.md"), "# Steam setup\n\nA short guide.\n")
	writeTestFile(t, filepath.Join(root, "docs", "brand.md"), "# Internal brand notes\n")

	if err := GenerateDocs(root); err != nil {
		t.Fatal(err)
	}
	first := treeSnapshot(t, filepath.Join(root, "website", "docs"))
	if err := GenerateDocs(root); err != nil {
		t.Fatal(err)
	}
	second := treeSnapshot(t, filepath.Join(root, "website", "docs"))
	if !equalSnapshot(first, second) {
		t.Fatal("docs generation changed output on the second run")
	}
	page := string(first["getting-started.html"])
	for _, want := range []string{
		`href="guides/steam.html#account"`,
		`&lt;script&gt;alert(&#34;not markup&#34;)&lt;/script&gt;`,
		`href="#"`,
		`href="../index.html"`,
	} {
		if !strings.Contains(page, want) {
			t.Errorf("generated docs page missing %q", want)
		}
	}
	if strings.Contains(page, "<script>alert") {
		t.Fatal("raw HTML from a Markdown source was emitted")
	}
	if _, ok := first["brand.html"]; ok {
		t.Fatal("internal brand decision file was published")
	}
}

func TestGenerateAppsIsDeterministicAndDoesNotExposeDefaults(t *testing.T) {
	root := t.TempDir()
	writeTestFile(t, filepath.Join(root, "builtin-runes", "demo.yaml"), `gameskill:
  id: demo-app
  name: Demo App
  category: Apps
  version: 2
  description: A demo service.
  docker:
    image: example/demo:1
    data_path: /var/lib/demo
    user: "0:0"
    keep_entrypoint: true
  variables:
    - key: ADMIN_PASSWORD
      name: Admin password
      type: string
      secret: true
      default: never-publish-this-value
  startup:
    done_regex: Started
  ports:
    - name: web
      default: 8080
      protocol: tcp
  stack:
    services:
      - name: database
        image: mariadb:11
        data_path: /var/lib/mysql
        user: "0:0"
`)
	if err := GenerateApps(root); err != nil {
		t.Fatal(err)
	}
	firstApps := treeSnapshot(t, filepath.Join(root, "website", "apps"))
	firstIcons := treeSnapshot(t, filepath.Join(root, "website", "icons"))
	if err := GenerateApps(root); err != nil {
		t.Fatal(err)
	}
	if !equalSnapshot(firstApps, treeSnapshot(t, filepath.Join(root, "website", "apps"))) || !equalSnapshot(firstIcons, treeSnapshot(t, filepath.Join(root, "website", "icons"))) {
		t.Fatal("template generation changed output on the second run")
	}
	page := string(firstApps["demo-app.html"])
	for _, want := range []string{"Demo App", "example/demo:1", "ADMIN_PASSWORD", "8080", "Persistent application data", "mariadb:11", "/var/lib/mysql"} {
		if !strings.Contains(page, want) {
			t.Errorf("generated template page missing %q", want)
		}
	}
	if strings.Contains(page, "never-publish-this-value") {
		t.Fatal("secret template default was included in the public catalogue")
	}
	if _, ok := firstIcons["demo-app.svg"]; !ok {
		t.Fatal("template icon was not generated")
	}
}

func TestDayZTemplateLinksItsSetupGuide(t *testing.T) {
	root := t.TempDir()
	writeTestFile(t, filepath.Join(root, "builtin-runes", "dayz.yaml"), `gameskill:
  id: dayz
  name: DayZ
  category: Games
  version: 1
  docker:
    image: example/dayz:1
    keep_entrypoint: true
  startup:
    exec: [DayZServer]
`)
	if err := GenerateApps(root); err != nil {
		t.Fatal(err)
	}
	page, err := os.ReadFile(filepath.Join(root, "website", "apps", "dayz.html"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(page), `href="../docs/guides/dayz-server.html">Read the DayZ server guide`) {
		t.Fatal("DayZ catalogue page did not link to its setup guide")
	}
}

func TestMarkdownSlugAndUnsafeProtocols(t *testing.T) {
	if got := slug("Steam Guard: email code"); got != "steam-guard-email-code" {
		t.Fatalf("slug() = %q", got)
	}
	if got := safeMarkdownHref("data:text/html,<svg onload=alert(1)>"); got != "#" {
		t.Fatalf("unsafe link was retained: %q", got)
	}
}

func writeTestFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func treeSnapshot(t *testing.T, root string) map[string][]byte {
	t.Helper()
	files := map[string][]byte{}
	err := filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			return nil
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		content, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		files[filepath.ToSlash(rel)] = content
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return files
}

func equalSnapshot(a, b map[string][]byte) bool {
	if len(a) != len(b) {
		return false
	}
	for path, content := range a {
		other, ok := b[path]
		if !ok || string(content) != string(other) {
			return false
		}
	}
	return true
}
