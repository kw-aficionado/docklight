package sitegen

import (
	"bytes"
	"fmt"
	"html"
	"html/template"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	runemodel "example.com/yggdrasil-panel/internal/rune"
)

// GenerateDocs turns the checked-in Markdown guides into a self-contained,
// deterministic HTML reference under website/docs.
func GenerateDocs(root string) error {
	root, err := filepath.Abs(root)
	if err != nil {
		return err
	}
	sourceRoot := filepath.Join(root, "docs")
	var sources []string
	err = filepath.WalkDir(sourceRoot, func(file string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() || filepath.Ext(file) != ".md" || filepath.Base(file) == "brand.md" {
			return nil
		}
		sources = append(sources, file)
		return nil
	})
	if err != nil {
		return fmt.Errorf("list documentation: %w", err)
	}
	sort.Strings(sources)
	docs := make([]docPage, 0, len(sources))
	for _, file := range sources {
		rel, err := filepath.Rel(sourceRoot, file)
		if err != nil {
			return err
		}
		src, err := os.ReadFile(file)
		if err != nil {
			return fmt.Errorf("read %s: %w", file, err)
		}
		name := filepath.ToSlash(strings.TrimSuffix(rel, ".md") + ".html")
		content := string(src)
		docs = append(docs, docPage{
			Title:    markdownTitle(content, strings.TrimSuffix(filepath.Base(rel), ".md")),
			Path:     name,
			Category: docCategory(rel),
			Body:     template.HTML(renderMarkdown(stripLeadingTitle(content))), // The renderer escapes text and permits only safe links.
		})
	}
	sort.SliceStable(docs, func(i, j int) bool {
		left, right := categoryOrder(docs[i].Category), categoryOrder(docs[j].Category)
		if left != right {
			return left < right
		}
		return docs[i].Title < docs[j].Title
	})
	if err := os.RemoveAll(filepath.Join(root, "website", "docs")); err != nil {
		return err
	}
	for _, doc := range docs {
		output := filepath.Join(root, "website", "docs", filepath.FromSlash(doc.Path))
		if err := os.MkdirAll(filepath.Dir(output), 0o755); err != nil {
			return err
		}
		page := pageFor(outputRel("docs/"+doc.Path), doc.Title, docs)
		if err := writePage(output, page); err != nil {
			return err
		}
	}
	index := docsIndexPage(docs)
	return writePage(filepath.Join(root, "website", "docs", "index.html"), index)
}

// GenerateApps builds the public template catalogue and individual template
// pages from the same validated YAML files that ship with Docklight.
func GenerateApps(root string) error {
	root, err := filepath.Abs(root)
	if err != nil {
		return err
	}
	files, err := filepath.Glob(filepath.Join(root, "builtin-runes", "*.yaml"))
	if err != nil {
		return err
	}
	sort.Strings(files)
	apps := make([]appPage, 0, len(files))
	for _, file := range files {
		src, err := os.ReadFile(file)
		if err != nil {
			return err
		}
		r, err := runemodel.Parse(string(src))
		if err != nil {
			return fmt.Errorf("parse %s: %w", file, err)
		}
		ports := make([]string, 0, len(r.Ports))
		for _, port := range r.Ports {
			ports = append(ports, fmt.Sprintf("%s · %s %d", port.Name, strings.ToUpper(port.Protocol), port.Default))
		}
		variables := make([]variablePage, 0, len(r.Variables))
		for _, v := range r.Variables {
			label := v.Name
			if label == "" {
				label = v.Key
			}
			requirement := "Optional"
			if v.Required {
				requirement = "Required"
			}
			note := ""
			if v.Secret || runemodel.SensitiveVariableName(v.Key) {
				note = "Secret value"
			}
			variables = append(variables, variablePage{Key: v.Key, Name: label, Type: v.Type, Options: append([]string(nil), v.Options...), Requirement: requirement, Note: note})
		}
		stableSortVariables(variables)
		description := strings.TrimSpace(r.Description)
		if description == "" {
			description = fallbackDescription(r)
		}
		guidePath := "../docs/getting-started.html"
		guideLabel := "Read the getting started guide"
		if r.ID == "dayz" {
			guidePath = "../docs/guides/dayz-server.html"
			guideLabel = "Read the DayZ server guide"
		}
		apps = append(apps, appPage{
			ID: r.ID, Name: r.Name, Category: r.Category, Description: description,
			Image: r.Docker.Image, DataPath: r.Docker.DataPath, Ports: ports,
			Variables: variables, Version: r.Version, GuidePath: guidePath, GuideLabel: guideLabel,
			Steam:    r.Steam != nil,
			Initials: initials(r.Name),
		})
		if r.Stack != nil {
			for _, service := range r.Stack.Services {
				last := len(apps) - 1
				apps[last].Services = append(apps[last].Services, servicePage{Name: service.Name, Image: service.Image, DataPath: service.DataPath})
			}
		}
	}
	sort.Slice(apps, func(i, j int) bool {
		if apps[i].Category != apps[j].Category {
			return apps[i].Category < apps[j].Category
		}
		return apps[i].Name < apps[j].Name
	})
	if err := os.RemoveAll(filepath.Join(root, "website", "apps")); err != nil {
		return err
	}
	if err := os.RemoveAll(filepath.Join(root, "website", "icons")); err != nil {
		return err
	}
	for _, app := range apps {
		if err := writeFile(filepath.Join(root, "website", "icons", app.ID+".svg"), []byte(appIcon(app)), 0o644); err != nil {
			return err
		}
		outputRelPath := "apps/" + app.ID + ".html"
		app.IconPath = relativeSitePath(outputRelPath, "icons/"+app.ID+".svg")
		page := appDetailPage(app)
		if err := writePage(filepath.Join(root, "website", filepath.FromSlash(outputRelPath)), page); err != nil {
			return err
		}
	}
	index := appsIndexPage(apps)
	return writePage(filepath.Join(root, "website", "apps", "index.html"), index)
}

type docPage struct {
	Title, Path, Category string
	Body                  template.HTML
}

type appPage struct {
	ID, Name, Category, Description, Image, DataPath, Initials, IconPath string
	GuidePath, GuideLabel                                                string
	Ports                                                                []string
	Variables                                                            []variablePage
	Services                                                             []servicePage
	Version                                                              int
	Steam                                                                bool
}

type variablePage struct {
	Key, Name, Type, Requirement, Note string
	Options                            []string
}
type servicePage struct{ Name, Image, DataPath string }

type pageData struct {
	Title, Root, Active string
	Body                template.HTML
}

var sitePage = template.Must(template.New("site").Parse(`<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta name="theme-color" content="#101817">
  <meta name="description" content="Docklight is a self-hosted control panel for game servers and apps.">
  <link rel="icon" href="{{.Root}}assets/brand.svg" type="image/svg+xml">
  <link rel="stylesheet" href="{{.Root}}assets/site.css">
  <title>{{.Title}} · Docklight</title>
</head>
<body>
  <header class="site-header"><a class="brand" href="{{.Root}}index.html"><img src="{{.Root}}assets/brand.svg" alt=""><span>Docklight</span></a>
    <nav aria-label="Main navigation"><a {{if eq .Active "docs"}}aria-current="page"{{end}} href="{{.Root}}docs/index.html">Documentation</a><a {{if eq .Active "apps"}}aria-current="page"{{end}} href="{{.Root}}apps/index.html">Templates</a><a class="nav-cta" href="{{.Root}}docs/getting-started.html">Get started <span aria-hidden="true">↗</span></a></nav>
  </header>
  {{.Body}}
  <footer class="site-footer"><a class="brand" href="{{.Root}}index.html"><img src="{{.Root}}assets/brand.svg" alt=""><span>Docklight</span></a><p>Self-hosted operations for the things you run.</p><div><a href="{{.Root}}docs/index.html">Documentation</a><a href="{{.Root}}apps/index.html">Templates</a><a href="https://docklight.app">docklight.app</a></div></footer>
</body>
</html>`))

func pageFor(outputRel, title string, docs []docPage) pageData {
	root := siteRootPrefix(outputRel)
	var sidebar strings.Builder
	category := ""
	for _, d := range docs {
		if d.Category != category {
			category = d.Category
			fmt.Fprintf(&sidebar, `<h2>%s</h2>`, html.EscapeString(category))
		}
		target := relativeSitePath(outputRel, "docs/"+d.Path)
		current := ""
		if strings.TrimPrefix(outputRel, "docs/") == d.Path {
			current = ` aria-current="page"`
		}
		fmt.Fprintf(&sidebar, `<a%s href="%s">%s</a>`, current, html.EscapeString(target), html.EscapeString(d.Title))
	}
	body := template.HTML(fmt.Sprintf(`<main class="page-wrap page-generated docs-wrap"><div class="page-kicker">DOCKLIGHT HANDBOOK</div><div class="docs-grid"><aside class="docs-index"><a class="docs-home" href="%sdocs/index.html">All documentation <span>→</span></a>%s</aside><article class="docs-article"><h1>%s</h1><div class="docs-content">%s</div></article></div></main>`, html.EscapeString(root), sidebar.String(), html.EscapeString(title), string(markdownBody(outputRel, docs))))
	return pageData{Title: title, Root: root, Active: "docs", Body: body}
}

func docsIndexPage(docs []docPage) pageData {
	root := "../"
	var b strings.Builder
	b.WriteString(`<main class="page-wrap page-generated"><div class="page-kicker">DOCKLIGHT HANDBOOK</div><section class="page-intro"><h1>Run it your way.</h1><p>Practical guides for installing Docklight, configuring services, and keeping your data in your hands.</p></section><div class="doc-cards">`)
	for _, doc := range docs {
		fmt.Fprintf(&b, `<a class="doc-card" href="%s"><span class="card-kicker">%s</span><h2>%s</h2><p>Open the guide <span aria-hidden="true">↗</span></p></a>`, html.EscapeString(doc.Path), html.EscapeString(doc.Category), html.EscapeString(doc.Title))
	}
	b.WriteString(`</div></main>`)
	return pageData{Title: "Documentation", Root: root, Active: "docs", Body: template.HTML(b.String())}
}

func markdownBody(outputRel string, docs []docPage) template.HTML {
	for _, doc := range docs {
		if strings.TrimPrefix(outputRel, "docs/") == doc.Path {
			// The generated source body is captured on the index list, while the
			// full Markdown is read by GenerateDocs and passed through pageForBody.
			return doc.Body
		}
	}
	return template.HTML("<p>Document unavailable.</p>")
}

func appsIndexPage(apps []appPage) pageData {
	root := "../"
	var b strings.Builder
	categories := make(map[string][]appPage)
	var order []string
	for _, app := range apps {
		if _, ok := categories[app.Category]; !ok {
			order = append(order, app.Category)
		}
		categories[app.Category] = append(categories[app.Category], app)
	}
	b.WriteString(`<main class="page-wrap page-generated"><div class="page-kicker">TEMPLATE LIBRARY</div><section class="page-intro"><h1>A good place to start.</h1><p>Choose a built-in game or app template, then shape the install around your own host.</p><div class="catalog-count">`)
	fmt.Fprintf(&b, `<strong>%d</strong> built-in templates`, len(apps))
	b.WriteString(`</div></section>`)
	for _, category := range order {
		fmt.Fprintf(&b, `<section class="catalog-section"><div class="catalog-heading"><h2>%s</h2><span>%d</span></div><div class="app-grid">`, html.EscapeString(category), len(categories[category]))
		for _, app := range categories[category] {
			icon := "../icons/" + app.ID + ".svg"
			fmt.Fprintf(&b, `<a class="app-card" href="%s.html"><img class="app-icon" src="%s" alt=""><div><h3>%s</h3><p>%s</p><span class="app-link">View template <b aria-hidden="true">↗</b></span></div></a>`, html.EscapeString(app.ID), html.EscapeString(icon), html.EscapeString(app.Name), html.EscapeString(app.Description))
		}
		b.WriteString(`</div></section>`)
	}
	b.WriteString(`<p class="catalog-note">These pages describe Docklight’s built-in templates. You can also import templates you author or trust.</p></main>`)
	return pageData{Title: "Templates", Root: root, Active: "apps", Body: template.HTML(b.String())}
}

func appDetailPage(app appPage) pageData {
	root := "../"
	var b strings.Builder
	fmt.Fprintf(&b, `<main class="page-wrap page-generated app-detail"><a class="back-link" href="index.html">← All templates</a><section class="app-hero"><img class="app-icon app-icon-large" src="%s" alt=""><div><div class="page-kicker">%s TEMPLATE · VERSION %d</div><h1>%s</h1><p>%s</p></div></section>`, html.EscapeString(app.IconPath), html.EscapeString(strings.ToUpper(app.Category)), app.Version, html.EscapeString(app.Name), html.EscapeString(app.Description))
	b.WriteString(`<div class="spec-grid"><section class="spec-card"><div class="card-kicker">IMAGE</div><code>`)
	b.WriteString(html.EscapeString(app.Image))
	b.WriteString(`</code></section><section class="spec-card"><div class="card-kicker">PERSISTENCE</div><p>`)
	if app.DataPath != "" {
		fmt.Fprintf(&b, `Persistent application data at <code>%s</code>.`, html.EscapeString(app.DataPath))
	} else {
		b.WriteString(`The template does not override the image's in-container data path.`)
	}
	b.WriteString(`</p></section><section class="spec-card"><div class="card-kicker">NETWORK</div><p>`)
	if len(app.Ports) == 0 {
		b.WriteString(`No public ports are declared by this template.`)
	} else {
		for _, port := range app.Ports {
			fmt.Fprintf(&b, `<span class="spec-tag">%s</span> `, html.EscapeString(port))
		}
	}
	b.WriteString(`</p></section><section class="spec-card"><div class="card-kicker">SETUP</div><p>`)
	if len(app.Variables) == 0 {
		b.WriteString(`This template has no additional setup fields.`)
	} else {
		fmt.Fprintf(&b, `Configure %d declared value(s) when creating a server.`, len(app.Variables))
	}
	if app.Steam {
		b.WriteString(` A Steam account is needed for installation.`)
	}
	b.WriteString(`</p></section></div>`)
	if len(app.Services) != 0 {
		b.WriteString(`<section class="variables stack-services"><div class="catalog-heading"><h2>Stack services</h2><span>Sidecars are not published to host ports</span></div><div class="table-scroll"><table><thead><tr><th>Service</th><th>Image</th><th>Data path</th></tr></thead><tbody>`)
		for _, service := range app.Services {
			fmt.Fprintf(&b, `<tr><td><span class="setting-name">%s</span></td><td><code>%s</code></td><td><code>%s</code></td></tr>`, html.EscapeString(service.Name), html.EscapeString(service.Image), html.EscapeString(service.DataPath))
		}
		b.WriteString(`</tbody></table></div></section>`)
	}
	if len(app.Variables) != 0 {
		b.WriteString(`<section class="variables"><div class="catalog-heading"><h2>Configuration</h2><span>Values stay with your panel</span></div><div class="table-scroll"><table><thead><tr><th>Setting</th><th>Type</th><th>Requirement</th><th>Notes</th></tr></thead><tbody>`)
		for _, v := range app.Variables {
			typeName := v.Type
			if len(v.Options) != 0 {
				typeName += " · " + strings.Join(v.Options, ", ")
			}
			fmt.Fprintf(&b, `<tr><td><span class="setting-name">%s</span><code>%s</code></td><td>%s</td><td>%s</td><td>%s</td></tr>`, html.EscapeString(v.Name), html.EscapeString(v.Key), html.EscapeString(typeName), html.EscapeString(v.Requirement), html.EscapeString(v.Note))
		}
		b.WriteString(`</tbody></table></div></section>`)
	}
	fmt.Fprintf(&b, `<section class="next-step"><div><div class="page-kicker">READY TO RUN IT?</div><h2>Start with the Docklight handbook.</h2></div><a class="button" href="%s">%s <span aria-hidden="true">↗</span></a></section></main>`, html.EscapeString(app.GuidePath), html.EscapeString(app.GuideLabel))
	return pageData{Title: app.Name, Root: root, Active: "apps", Body: template.HTML(b.String())}
}

func writePage(path string, data pageData) error {
	var out bytes.Buffer
	if err := sitePage.Execute(&out, data); err != nil {
		return err
	}
	return writeFile(path, out.Bytes(), 0o644)
}

func writeFile(path string, data []byte, mode os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	return os.WriteFile(path, data, mode)
}

func outputRel(path string) string { return filepath.ToSlash(path) }

func relativeSitePath(pageRel, targetRel string) string {
	from := filepath.Dir(filepath.FromSlash(pageRel))
	to := filepath.FromSlash(targetRel)
	if targetRel == "" {
		to = "."
	}
	rel, err := filepath.Rel(from, to)
	if err != nil {
		return "./"
	}
	return filepath.ToSlash(rel)
}

func siteRootPrefix(pageRel string) string {
	root := relativeSitePath(pageRel, "")
	if root != "" && !strings.HasSuffix(root, "/") {
		root += "/"
	}
	return root
}

func docCategory(rel string) string {
	if strings.HasPrefix(rel, "guides"+string(filepath.Separator)) {
		return "Guides"
	}
	if filepath.Base(rel) == "getting-started.md" {
		return "Start here"
	}
	return "Reference"
}

func categoryOrder(category string) int {
	switch category {
	case "Start here":
		return 0
	case "Guides":
		return 1
	default:
		return 2
	}
}

func stripLeadingTitle(source string) string {
	lines := strings.Split(source, "\n")
	for i, line := range lines {
		if strings.TrimSpace(line) == "" {
			continue
		}
		if strings.HasPrefix(strings.TrimSpace(line), "# ") {
			lines = append(lines[:i], lines[i+1:]...)
		}
		break
	}
	return strings.Join(lines, "\n")
}

func markdownTitle(source, fallback string) string {
	for _, line := range strings.Split(source, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "# ") {
			return strings.TrimSpace(strings.TrimPrefix(line, "# "))
		}
	}
	return strings.ReplaceAll(fallback, "-", " ")
}

func fallbackDescription(r runemodel.Rune) string {
	switch r.ID {
	case "cloudflared":
		return "Run the cloudflared connector with a stored tunnel token. The template does not create a route or DNS record by itself."
	case "minecraft-bedrock":
		return "A Bedrock server template with setup fields for version, game mode, and difficulty."
	case "uptime-kuma":
		return "A self-hosted uptime monitor with persistent application data at /app/data."
	case "vaultwarden":
		return "A self-hosted password service with a configurable signup policy and persistent data at /data."
	}
	switch r.Category {
	case "Games":
		return "A game server template with the configuration and ports Docklight needs to manage it."
	case "Networking":
		return "A networking template for connecting services to your self-hosted setup."
	default:
		return "A self-hosted app template managed from your Docklight panel."
	}
}

func initials(name string) string {
	words := strings.Fields(name)
	var letters []rune
	for _, word := range words {
		for _, r := range word {
			if (r >= 'A' && r <= 'Z') || (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
				letters = append(letters, r)
				break
			}
		}
		if len(letters) == 2 {
			break
		}
	}
	if len(letters) == 0 {
		return "D"
	}
	return strings.ToUpper(string(letters))
}

func appIcon(app appPage) string {
	bg, accent := "#172321", "#66ddc9"
	if app.Category == "Games" {
		bg, accent = "#27271e", "#e3c98d"
	} else if app.Category == "Networking" {
		bg, accent = "#1d2636", "#a6c7f4"
	}
	return fmt.Sprintf(`<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 80 80" role="img" aria-labelledby="title"><title id="title">%s</title><rect width="80" height="80" rx="21" fill="%s"/><path d="M19 15h30a8 8 0 0 1 8 8v34a8 8 0 0 1-8 8H19z" fill="%s"/><path d="M57 15h4a8 8 0 0 1 8 8v34a8 8 0 0 1-8 8h-4z" fill="#dce8e5" opacity=".86"/><circle cx="61.5" cy="40" r="3" fill="#f3c97a"/><text x="34" y="46" fill="#10201d" font-family="Arial,sans-serif" font-size="18" font-weight="700" text-anchor="middle">%s</text></svg>`, html.EscapeString(app.Name), bg, accent, html.EscapeString(app.Initials))
}

func stableSortVariables(v []variablePage) {
	sort.Slice(v, func(i, j int) bool { return v[i].Key < v[j].Key })
}

var (
	inlineToken = regexp.MustCompile("`[^`]+`|\\[[^\\]]+\\]\\([^)]+\\)|\\*\\*[^*]+\\*\\*|__[^_]+__|\\*[^*]+\\*")
	linkToken   = regexp.MustCompile(`^\[([^\]]+)\]\(([^)]+)\)$`)
	tableRule   = regexp.MustCompile(`^\s*\|?\s*:?-{3,}:?\s*(\|\s*:?-{3,}:?\s*)+\|?\s*$`)
	headingLine = regexp.MustCompile(`^(#{1,6})\s+`)
	orderedItem = regexp.MustCompile(`^\d+\. `)
)

func renderMarkdown(source string) string {
	lines := strings.Split(strings.ReplaceAll(source, "\r\n", "\n"), "\n")
	var out strings.Builder
	for i := 0; i < len(lines); {
		line := strings.TrimSpace(lines[i])
		if line == "" {
			i++
			continue
		}
		if strings.HasPrefix(line, "```") {
			lang := strings.TrimSpace(strings.TrimPrefix(line, "```"))
			i++
			var code strings.Builder
			for i < len(lines) && !strings.HasPrefix(strings.TrimSpace(lines[i]), "```") {
				code.WriteString(lines[i])
				code.WriteByte('\n')
				i++
			}
			if i < len(lines) {
				i++
			}
			fmt.Fprintf(&out, `<pre><code class="language-%s">%s</code></pre>`, html.EscapeString(lang), html.EscapeString(code.String()))
			continue
		}
		if i+1 < len(lines) && strings.Contains(line, "|") && tableRule.MatchString(strings.TrimSpace(lines[i+1])) {
			head := splitTable(line)
			out.WriteString(`<div class="table-scroll"><table><thead><tr>`)
			for _, cell := range head {
				fmt.Fprintf(&out, `<th>%s</th>`, renderInline(cell))
			}
			out.WriteString(`</tr></thead><tbody>`)
			i += 2
			for i < len(lines) && strings.Contains(strings.TrimSpace(lines[i]), "|") && strings.TrimSpace(lines[i]) != "" {
				out.WriteString(`<tr>`)
				for _, cell := range splitTable(lines[i]) {
					fmt.Fprintf(&out, `<td>%s</td>`, renderInline(cell))
				}
				out.WriteString(`</tr>`)
				i++
			}
			out.WriteString(`</tbody></table></div>`)
			continue
		}
		if heading := headingLine.FindString(line); heading != "" {
			level := len(strings.TrimSpace(heading))
			text := strings.TrimSpace(line[level:])
			fmt.Fprintf(&out, `<h%d id="%s">%s</h%d>`, level, html.EscapeString(slug(text)), renderInline(text), level)
			i++
			continue
		}
		if strings.HasPrefix(line, "---") || strings.Trim(line, "-") == "" || strings.Trim(line, "*") == "" {
			out.WriteString(`<hr>`)
			i++
			continue
		}
		if strings.HasPrefix(line, "> ") {
			var quote []string
			for i < len(lines) && strings.HasPrefix(strings.TrimSpace(lines[i]), "> ") {
				quote = append(quote, strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(lines[i]), "> ")))
				i++
			}
			fmt.Fprintf(&out, `<blockquote><p>%s</p></blockquote>`, renderInline(strings.Join(quote, " ")))
			continue
		}
		if strings.HasPrefix(line, "- ") || strings.HasPrefix(line, "* ") {
			out.WriteString(`<ul>`)
			for i < len(lines) {
				item := strings.TrimSpace(lines[i])
				if !strings.HasPrefix(item, "- ") && !strings.HasPrefix(item, "* ") {
					break
				}
				fmt.Fprintf(&out, `<li>%s</li>`, renderInline(strings.TrimSpace(item[2:])))
				i++
			}
			out.WriteString(`</ul>`)
			continue
		}
		if orderedItem.MatchString(line) {
			out.WriteString(`<ol>`)
			for i < len(lines) {
				item := strings.TrimSpace(lines[i])
				match := orderedItem.FindStringIndex(item)
				if match == nil {
					break
				}
				fmt.Fprintf(&out, `<li>%s</li>`, renderInline(strings.TrimSpace(item[match[1]:])))
				i++
			}
			out.WriteString(`</ol>`)
			continue
		}
		var paragraph []string
		for i < len(lines) {
			next := strings.TrimSpace(lines[i])
			if next == "" || headingLine.MatchString(next) || strings.HasPrefix(next, "```") || strings.HasPrefix(next, "- ") || strings.HasPrefix(next, "* ") || strings.HasPrefix(next, "> ") || orderedItem.MatchString(next) {
				break
			}
			paragraph = append(paragraph, next)
			i++
		}
		if len(paragraph) == 0 {
			i++
			continue
		}
		fmt.Fprintf(&out, `<p>%s</p>`, renderInline(strings.Join(paragraph, " ")))
	}
	return out.String()
}

func renderInline(text string) string {
	var out strings.Builder
	last := 0
	for _, index := range inlineToken.FindAllStringIndex(text, -1) {
		out.WriteString(html.EscapeString(text[last:index[0]]))
		token := text[index[0]:index[1]]
		switch {
		case strings.HasPrefix(token, "`"):
			fmt.Fprintf(&out, `<code>%s</code>`, html.EscapeString(strings.Trim(token, "`")))
		case linkToken.MatchString(token):
			parts := linkToken.FindStringSubmatch(token)
			href := safeMarkdownHref(parts[2])
			fmt.Fprintf(&out, `<a href="%s">%s</a>`, html.EscapeString(href), renderInlineLabel(parts[1]))
		case strings.HasPrefix(token, "**") || strings.HasPrefix(token, "__"):
			fmt.Fprintf(&out, `<strong>%s</strong>`, html.EscapeString(token[2:len(token)-2]))
		default:
			fmt.Fprintf(&out, `<em>%s</em>`, html.EscapeString(token[1:len(token)-1]))
		}
		last = index[1]
	}
	out.WriteString(html.EscapeString(text[last:]))
	return out.String()
}

func renderInlineLabel(s string) string { return html.EscapeString(strings.TrimSpace(s)) }

func safeMarkdownHref(target string) string {
	target = strings.TrimSpace(target)
	if target == "" {
		return "#"
	}
	if strings.HasPrefix(target, "#") || strings.HasPrefix(target, "/") {
		return target
	}
	parts := strings.SplitN(target, "#", 2)
	pathPart := parts[0]
	fragment := ""
	if len(parts) == 2 {
		fragment = "#" + parts[1]
	}
	if strings.HasSuffix(pathPart, ".md") {
		pathPart = strings.TrimSuffix(pathPart, ".md") + ".html"
	}
	if strings.Contains(pathPart, ":") {
		if !strings.HasPrefix(pathPart, "https://") && !strings.HasPrefix(pathPart, "http://") && !strings.HasPrefix(pathPart, "mailto:") {
			return "#"
		}
	}
	return pathPart + fragment
}

func splitTable(line string) []string {
	line = strings.TrimSpace(line)
	line = strings.TrimPrefix(line, "|")
	line = strings.TrimSuffix(line, "|")
	cells := strings.Split(line, "|")
	for i := range cells {
		cells[i] = strings.TrimSpace(cells[i])
	}
	return cells
}

func slug(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	var b strings.Builder
	separator := false
	for _, r := range value {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			if separator && b.Len() > 0 {
				b.WriteByte('-')
			}
			b.WriteRune(r)
			separator = false
		} else if r == ' ' || r == '-' || r == '_' {
			separator = true
		}
	}
	return b.String()
}
