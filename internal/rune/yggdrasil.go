package rune

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

// ImportYggdrasil converts an upstream Yggdrasil Rune into Docklight's
// supported template model. Features Docklight cannot represent are removed
// only with an explicit warning.
func ImportYggdrasil(src string) (Rune, []string, error) {
	document, err := parseYAML(src)
	if err != nil {
		return Rune{}, nil, fmt.Errorf("parse Yggdrasil Rune: %w", err)
	}
	if len(document) != 1 {
		return Rune{}, nil, errors.New("Yggdrasil Rune must contain only one top-level gameskill mapping")
	}
	raw, ok := document["gameskill"].(map[string]any)
	if !ok {
		return Rune{}, nil, errors.New("Yggdrasil Rune must use a top-level gameskill mapping")
	}
	for key := range raw {
		if !supportedYggdrasilField(key) {
			return Rune{}, nil, fmt.Errorf("unsupported Yggdrasil Rune field %q", key)
		}
	}

	warnings := []string{}
	if err := convertYggdrasilServices(raw, &warnings); err != nil {
		return Rune{}, nil, err
	}
	if err := convertYggdrasilUnsupportedFields(raw, &warnings); err != nil {
		return Rune{}, nil, err
	}
	if err := removeYggdrasilLegacyFields(raw, &warnings); err != nil {
		return Rune{}, nil, err
	}
	if err := normalizeYggdrasilEnvironment(raw, &warnings); err != nil {
		return Rune{}, nil, err
	}
	if err := normalizeYggdrasilSecrets(raw, &warnings); err != nil {
		return Rune{}, nil, err
	}
	if err := removeUnsupportedYggdrasilRCON(raw, &warnings); err != nil {
		return Rune{}, nil, err
	}

	encoded, err := json.Marshal(map[string]any{"gameskill": raw})
	if err != nil {
		return Rune{}, nil, fmt.Errorf("encode converted Yggdrasil Rune: %w", err)
	}
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	var envelope struct {
		Gameskill Rune `json:"gameskill"`
	}
	if err := decoder.Decode(&envelope); err != nil {
		return Rune{}, nil, fmt.Errorf("converted Yggdrasil Rune fields: %w", err)
	}
	if err := envelope.Gameskill.Validate(); err != nil {
		return Rune{}, nil, fmt.Errorf("converted Yggdrasil Rune failed Docklight validation: %w", err)
	}
	return envelope.Gameskill, warnings, nil
}

func supportedYggdrasilField(key string) bool {
	switch key {
	case "id", "name", "category", "version", "description", "author", "icon",
		"docker", "variables", "install", "update", "startup", "ports", "query",
		"rcon", "steam", "bans", "players", "events", "admin_log", "wipe",
		"restart", "backup", "anticheat", "services", "import", "watchers",
		"config_files", "stack":
		return true
	default:
		return false
	}
}

func convertYggdrasilServices(gameskill map[string]any, warnings *[]string) error {
	value, exists := gameskill["services"]
	if !exists {
		return nil
	}
	if _, exists := gameskill["stack"]; exists {
		return errors.New("Yggdrasil Rune cannot define both services and Docklight stack")
	}
	services, ok := value.([]any)
	if !ok || len(services) == 0 {
		return errors.New("Yggdrasil Rune services must be a non-empty list")
	}
	for index, value := range services {
		service, ok := value.(map[string]any)
		if !ok {
			return fmt.Errorf("Yggdrasil Rune services[%d] must be a mapping", index)
		}
		ports, exists := service["ports"]
		if !exists {
			continue
		}
		portList, ok := ports.([]any)
		if !ok && ports != nil {
			return fmt.Errorf("Yggdrasil Rune services[%d].ports must be a list", index)
		}
		if len(portList) > 0 {
			name, _ := service["name"].(string)
			if name == "" {
				name = fmt.Sprintf("services[%d]", index)
			}
			*warnings = append(*warnings, fmt.Sprintf("Sidecar %q publishes ports in Yggdrasil; Docklight does not publish sidecar ports, so those ports were omitted.", name))
		}
		delete(service, "ports")
	}
	gameskill["stack"] = map[string]any{"services": services}
	delete(gameskill, "services")
	return nil
}

func convertYggdrasilUnsupportedFields(gameskill map[string]any, warnings *[]string) error {
	unsupported := []struct {
		key     string
		feature string
	}{
		{"players", "live player roster and player actions"},
		{"events", "persistent aggregated event tracking"},
		{"admin_log", "parsed admin activity log"},
		{"wipe", "the template-specific world wipe action"},
		{"import", "the template-specific app-data import workflow"},
	}
	for _, item := range unsupported {
		value, exists := gameskill[item.key]
		if exists && hasRuneValue(value) {
			*warnings = append(*warnings, fmt.Sprintf("Yggdrasil %s is not supported in Docklight and was omitted.", item.feature))
		}
		delete(gameskill, item.key)
	}

	backup, exists := gameskill["backup"]
	if exists && hasRuneValue(backup) {
		if settings, ok := backup.(map[string]any); ok {
			if rawInclude, hasInclude := settings["include"]; hasInclude && rawInclude != nil {
				include, ok := rawInclude.([]any)
				if !ok {
					return errors.New("Yggdrasil Rune backup.include must be a list")
				}
				includesEverything := false
				for _, value := range include {
					if path, ok := value.(string); ok && path == "." {
						includesEverything = true
						break
					}
				}
				if len(include) > 0 && !includesEverything {
					*warnings = append(*warnings, "Yggdrasil backup.include was not applied; Docklight backups include the full persistent data directory.")
				}
			}
			unknownOption := false
			for key, value := range settings {
				if key != "include" && hasRuneValue(value) {
					unknownOption = true
				}
			}
			if unknownOption {
				*warnings = append(*warnings, "Additional Yggdrasil backup options were not imported; Docklight backup behavior is managed by the panel.")
			}
		} else {
			*warnings = append(*warnings, "Yggdrasil backup options are not supported in Docklight; its backup policy is managed by the panel.")
		}
	}
	delete(gameskill, "backup")
	return nil
}

func removeYggdrasilLegacyFields(gameskill map[string]any, warnings *[]string) error {
	for _, item := range []struct {
		block string
		field string
	}{
		{"query", "port"},
		{"rcon", "port_var"},
	} {
		value, exists := gameskill[item.block]
		if !exists || value == nil {
			continue
		}
		block, ok := value.(map[string]any)
		if !ok {
			return fmt.Errorf("Yggdrasil Rune %s must be a mapping", item.block)
		}
		if _, exists := block[item.field]; exists {
			delete(block, item.field)
			*warnings = append(*warnings, fmt.Sprintf("Legacy Yggdrasil %s.%s was ignored; Docklight uses the declared port mapping.", item.block, item.field))
		}
	}
	return nil
}

func normalizeYggdrasilEnvironment(gameskill map[string]any, warnings *[]string) error {
	removed := 0
	docker, exists := gameskill["docker"]
	if exists && docker != nil {
		block, ok := docker.(map[string]any)
		if !ok {
			return errors.New("Yggdrasil Rune docker must be a mapping")
		}
		if err := normalizeYggdrasilEnvironmentMap(block, "env", "docker.env", &removed); err != nil {
			return err
		}
	}
	stack, exists := gameskill["stack"]
	if exists && stack != nil {
		block, ok := stack.(map[string]any)
		if !ok {
			return errors.New("Docklight stack must be a mapping")
		}
		services, exists := block["services"]
		if exists {
			list, ok := services.([]any)
			if !ok {
				return errors.New("Docklight stack.services must be a list")
			}
			for index, value := range list {
				service, ok := value.(map[string]any)
				if !ok {
					return fmt.Errorf("Docklight stack.services[%d] must be a mapping", index)
				}
				if err := normalizeYggdrasilEnvironmentMap(service, "env", fmt.Sprintf("stack.services[%d].env", index), &removed); err != nil {
					return err
				}
			}
		}
	}
	if removed > 0 {
		*warnings = append(*warnings, fmt.Sprintf("Removed %d static sensitive environment value(s); replace them with secret variables before creating the Docklight server.", removed))
	}
	return nil
}

func normalizeYggdrasilEnvironmentMap(parent map[string]any, key, field string, removed *int) error {
	value, exists := parent[key]
	if !exists || value == nil {
		return nil
	}
	environment, ok := value.(map[string]any)
	if !ok {
		return fmt.Errorf("Yggdrasil Rune %s must be a mapping", field)
	}
	for name, raw := range environment {
		var text string
		switch value := raw.(type) {
		case string:
			text = value
		case nil:
			text = ""
		case bool, int64, float64:
			text = fmt.Sprint(value)
		default:
			return fmt.Errorf("Yggdrasil Rune %s[%s] must be a scalar", field, name)
		}
		if SensitiveVariableName(name) && strings.TrimSpace(text) != "" && !isRuneVariableReference(text) {
			delete(environment, name)
			(*removed)++
			continue
		}
		environment[name] = text
	}
	if len(environment) == 0 {
		delete(parent, key)
	}
	return nil
}

func isRuneVariableReference(value string) bool {
	if len(value) < 4 || !strings.HasPrefix(value, "{{") || !strings.HasSuffix(value, "}}") {
		return false
	}
	name := value[2 : len(value)-2]
	if name == "" {
		return false
	}
	for _, r := range name {
		if !((r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '_') {
			return false
		}
	}
	return true
}

func normalizeYggdrasilSecrets(gameskill map[string]any, warnings *[]string) error {
	value, exists := gameskill["variables"]
	if !exists || value == nil {
		return nil
	}
	variables, ok := value.([]any)
	if !ok {
		return errors.New("Yggdrasil Rune variables must be a list")
	}
	removed := 0
	for index, value := range variables {
		variable, ok := value.(map[string]any)
		if !ok {
			return fmt.Errorf("Yggdrasil Rune variables[%d] must be a mapping", index)
		}
		key, _ := variable["key"].(string)
		declaredSecret, _ := variable["secret"].(bool)
		if !declaredSecret && !SensitiveVariableName(key) {
			continue
		}
		variable["secret"] = true
		if defaultValue, exists := variable["default"]; exists && defaultValue != nil && fmt.Sprint(defaultValue) != "" {
			delete(variable, "default")
			removed++
		}
	}
	if removed > 0 {
		*warnings = append(*warnings, fmt.Sprintf("Removed %d sensitive variable default(s); enter them when creating the Docklight server.", removed))
	}
	return nil
}

func removeUnsupportedYggdrasilRCON(gameskill map[string]any, warnings *[]string) error {
	value, exists := gameskill["rcon"]
	if !exists || value == nil {
		return nil
	}
	rcon, ok := value.(map[string]any)
	if !ok {
		return errors.New("Yggdrasil Rune rcon must be a mapping")
	}
	typeName, _ := rcon["type"].(string)
	switch typeName {
	case "", "minecraft", "source":
		return nil
	default:
		delete(gameskill, "rcon")
		*warnings = append(*warnings, fmt.Sprintf("Yggdrasil RCON protocol %q is not supported in Docklight; the RCON configuration was omitted.", typeName))
		return nil
	}
}

func hasRuneValue(value any) bool {
	switch typed := value.(type) {
	case nil:
		return false
	case string:
		return strings.TrimSpace(typed) != ""
	case []any:
		return len(typed) > 0
	case map[string]any:
		return len(typed) > 0
	default:
		return true
	}
}
