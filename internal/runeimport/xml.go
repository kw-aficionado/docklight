package runeimport

import (
	"encoding/xml"
	"fmt"
	"strings"

	"example.com/yggdrasil-panel/internal/rune"
)

type xmlRuneDocument struct {
	XMLName     xml.Name `xml:"gameskill"`
	ID          string   `xml:"id"`
	Name        string   `xml:"name"`
	Category    string   `xml:"category"`
	Description string   `xml:"description"`
	Author      string   `xml:"author"`
	Version     int      `xml:"version"`
	Icon        string   `xml:"icon"`
	Docker      struct {
		Image string `xml:"image"`
	} `xml:"docker"`
	Variables []xmlRuneVariable `xml:"variables>variable"`
	Install   struct {
		Image  string `xml:"image"`
		Script string `xml:"script"`
	} `xml:"install"`
	Startup struct {
		Command   string `xml:"command"`
		DoneRegex string `xml:"done_regex"`
		Stop      string `xml:"stop"`
	} `xml:"startup"`
	ConfigFiles []string      `xml:"config_files>file"`
	Ports       []xmlRunePort `xml:"ports>port"`
}

type xmlRuneVariable struct {
	Key      string   `xml:"key"`
	Name     string   `xml:"name"`
	Type     string   `xml:"type"`
	Options  []string `xml:"options>option"`
	Default  *string  `xml:"default"`
	Required bool     `xml:"required"`
}

type xmlRunePort struct {
	Name     string `xml:"name"`
	Default  int    `xml:"default"`
	Protocol string `xml:"protocol"`
}

// ImportXML accepts the documented <gameskill> subset. encoding/xml ignores
// unrelated elements; generated runes still pass the same strict validator.
func ImportXML(input []byte) (rune.Rune, []string, error) {
	if len(input) == 0 {
		return rune.Rune{}, nil, fmt.Errorf("XML template is empty")
	}
	if len(input) > MaxSize {
		return rune.Rune{}, nil, fmt.Errorf("XML template exceeds the 1 MiB upload limit")
	}
	var source xmlRuneDocument
	if err := xml.Unmarshal(input, &source); err != nil {
		return rune.Rune{}, nil, fmt.Errorf("read XML template: %w", err)
	}
	if source.XMLName.Local != "gameskill" {
		return rune.Rune{}, nil, fmt.Errorf("XML root element must be <gameskill>")
	}
	if source.Version < 0 {
		return rune.Rune{}, nil, fmt.Errorf("XML template version cannot be negative")
	}
	version := source.Version
	if version == 0 {
		version = 1
	}
	category := strings.TrimSpace(source.Category)
	if category == "" {
		category = "Imported"
	}
	gs := rune.Rune{
		ID: strings.TrimSpace(source.ID), Name: strings.TrimSpace(source.Name),
		Category: category, Description: source.Description, Author: strings.TrimSpace(source.Author),
		Icon: strings.TrimSpace(source.Icon), Version: version,
		Docker:      rune.Docker{Image: strings.TrimSpace(source.Docker.Image)},
		Startup:     rune.Startup{Command: source.Startup.Command, DoneRegex: source.Startup.DoneRegex, Stop: source.Startup.Stop},
		ConfigFiles: append([]string(nil), source.ConfigFiles...),
	}
	if strings.TrimSpace(source.Install.Script) != "" {
		gs.Install = &rune.Install{Image: strings.TrimSpace(source.Install.Image), Script: source.Install.Script}
	}
	secretDefaultsRemoved := false
	for _, variable := range source.Variables {
		key := strings.TrimSpace(variable.Key)
		if key == "" {
			return rune.Rune{}, nil, fmt.Errorf("XML variable key is required")
		}
		secret := rune.SensitiveVariableName(key)
		var defaultValue any
		if variable.Default != nil {
			defaultValue = *variable.Default
		}
		if secret && defaultValue != nil && defaultValue != "" {
			defaultValue = nil
			secretDefaultsRemoved = true
		}
		gs.Variables = append(gs.Variables, rune.Variable{
			Key: key, Name: strings.TrimSpace(variable.Name), Type: strings.TrimSpace(variable.Type),
			Options: append([]string(nil), variable.Options...), Default: defaultValue,
			Required: variable.Required, Secret: secret,
		})
	}
	for _, port := range source.Ports {
		protocol := strings.TrimSpace(port.Protocol)
		if protocol == "" {
			protocol = "tcp"
		}
		gs.Ports = append(gs.Ports, rune.Port{Name: strings.TrimSpace(port.Name), Default: port.Default, Protocol: protocol})
	}
	warnings := []string{}
	if secretDefaultsRemoved {
		warnings = append(warnings, "Secret-looking variable defaults were removed; enter those values when creating a server.")
	}
	if err := gs.Validate(); err != nil {
		return rune.Rune{}, nil, fmt.Errorf("imported XML template did not pass Docklight validation: %w", err)
	}
	return gs, warnings, nil
}
