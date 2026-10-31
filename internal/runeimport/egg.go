package runeimport

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"regexp"
	"sort"
	"strings"

	"example.com/yggdrasil-panel/internal/rune"
)

const MaxSize = 1 << 20

type eggDocument struct {
	Name         string            `json:"name"`
	Author       string            `json:"author"`
	Description  string            `json:"description"`
	Image        string            `json:"image"`
	DockerImage  string            `json:"docker_image"`
	DockerImages map[string]string `json:"docker_images"`
	Startup      string            `json:"startup"`
	Config       struct {
		Files   map[string]json.RawMessage `json:"files"`
		Startup struct {
			Done json.RawMessage `json:"done"`
		} `json:"startup"`
	} `json:"config"`
	Scripts struct {
		Installation struct {
			Script    string `json:"script"`
			Container string `json:"container"`
		} `json:"installation"`
	} `json:"scripts"`
	Variables []struct {
		Name         string `json:"name"`
		EnvVariable  string `json:"env_variable"`
		DefaultValue any    `json:"default_value"`
		Rules        any    `json:"rules"`
	} `json:"variables"`
}

// ImportEgg translates the portable parts of a Pterodactyl egg export. Image
// selection and map-derived fields are sorted so the output is reproducible.
func ImportEgg(input []byte) (rune.Rune, []string, error) {
	if len(input) == 0 {
		return rune.Rune{}, nil, fmt.Errorf("egg file is empty")
	}
	if len(input) > MaxSize {
		return rune.Rune{}, nil, fmt.Errorf("egg file exceeds the 1 MiB upload limit")
	}
	decoder := json.NewDecoder(bytes.NewReader(input))
	decoder.UseNumber()
	var source eggDocument
	if err := decoder.Decode(&source); err != nil {
		return rune.Rune{}, nil, fmt.Errorf("read Pterodactyl egg JSON: %w", err)
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		if err == nil {
			return rune.Rune{}, nil, fmt.Errorf("egg import accepts one JSON document")
		}
		return rune.Rune{}, nil, fmt.Errorf("read Pterodactyl egg JSON: %w", err)
	}

	name := strings.TrimSpace(source.Name)
	id := slug(name)
	if id == "" {
		return rune.Rune{}, nil, fmt.Errorf("egg name must contain at least one ASCII letter or digit")
	}
	image := strings.TrimSpace(source.DockerImage)
	if image == "" {
		image = strings.TrimSpace(source.Image)
	}
	if keys := sortedKeys(source.DockerImages); len(keys) != 0 {
		image = strings.TrimSpace(source.DockerImages[keys[0]])
	}
	gs := rune.Rune{
		ID: id, Name: name, Category: "Imported", Description: source.Description,
		Author: source.Author, Version: 1,
		Docker:  rune.Docker{Image: image},
		Startup: rune.Startup{Command: source.Startup},
	}
	if done := eggDoneValue(source.Config.Startup.Done); done != "" {
		gs.Startup.DoneRegex = regexp.QuoteMeta(done)
	}
	if script := source.Scripts.Installation.Script; strings.TrimSpace(script) != "" {
		installImage := strings.TrimSpace(source.Scripts.Installation.Container)
		if installImage == "" {
			installImage = image
		}
		gs.Install = &rune.Install{Image: installImage, Script: script}
	}
	gs.ConfigFiles = sortedKeys(source.Config.Files)

	secretDefaultsRemoved := false
	for _, variable := range source.Variables {
		key := strings.TrimSpace(variable.EnvVariable)
		if key == "" {
			continue
		}
		variableType, options, required := eggVariableRules(variable.Rules)
		secret := rune.SensitiveVariableName(key)
		defaultValue := variable.DefaultValue
		if secret && defaultValue != nil && defaultValue != "" {
			defaultValue = nil
			secretDefaultsRemoved = true
		}
		label := strings.TrimSpace(variable.Name)
		if label == "" {
			label = key
		}
		gs.Variables = append(gs.Variables, rune.Variable{
			Key: key, Name: label, Type: variableType, Options: options,
			Default: defaultValue, Required: required, Secret: secret,
		})
	}
	warnings := []string{}
	if secretDefaultsRemoved {
		warnings = append(warnings, "Secret-looking variable defaults were removed; enter those values when creating a server.")
	}
	if err := gs.Validate(); err != nil {
		return rune.Rune{}, nil, fmt.Errorf("imported egg did not pass Docklight validation: %w", err)
	}
	return gs, warnings, nil
}

func eggVariableRules(value any) (string, []string, bool) {
	rules := ""
	switch rule := value.(type) {
	case string:
		rules = rule
	case []any:
		parts := make([]string, 0, len(rule))
		for _, item := range rule {
			if part, ok := item.(string); ok {
				parts = append(parts, part)
			}
		}
		rules = strings.Join(parts, "|")
	}
	var required bool
	for _, rule := range strings.Split(rules, "|") {
		rule = strings.TrimSpace(rule)
		switch {
		case rule == "boolean":
			return "bool", nil, required || rulesHaveRequired(rules)
		case rule == "integer" || rule == "numeric":
			return "int", nil, required || rulesHaveRequired(rules)
		case strings.HasPrefix(rule, "in:"):
			options := []string{}
			seen := map[string]bool{}
			for _, option := range strings.Split(strings.TrimPrefix(rule, "in:"), ",") {
				option = strings.TrimSpace(option)
				if option != "" && !seen[option] {
					seen[option] = true
					options = append(options, option)
				}
			}
			if len(options) != 0 {
				return "select", options, required || rulesHaveRequired(rules)
			}
		case rule == "required":
			required = true
		}
	}
	return "string", nil, required
}

func rulesHaveRequired(value string) bool {
	for _, item := range strings.Split(value, "|") {
		if strings.TrimSpace(item) == "required" {
			return true
		}
	}
	return false
}

func eggDoneValue(raw json.RawMessage) string {
	var value string
	if json.Unmarshal(raw, &value) == nil {
		return value
	}
	var values []string
	if json.Unmarshal(raw, &values) == nil && len(values) != 0 {
		return values[0]
	}
	return ""
}

func sortedKeys[V any](values map[string]V) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func slug(value string) string {
	var out strings.Builder
	separator := false
	for _, char := range strings.ToLower(strings.TrimSpace(value)) {
		if char >= 'a' && char <= 'z' || char >= '0' && char <= '9' {
			if separator && out.Len() != 0 {
				out.WriteByte('-')
			}
			out.WriteRune(char)
			separator = false
		} else {
			separator = true
		}
	}
	return strings.Trim(out.String(), "-")
}
