package rune

import (
	"encoding/json"
	"errors"
	"fmt"
	"path"
	"regexp"
	"strconv"
	"strings"
	"time"
)

type Rune struct {
	ID          string     `json:"id"`
	Name        string     `json:"name"`
	Category    string     `json:"category"`
	Description string     `json:"description,omitempty"`
	Version     int        `json:"version"`
	Docker      Docker     `json:"docker"`
	Variables   []Variable `json:"variables,omitempty"`
	Install     *Install   `json:"install,omitempty"`
	Startup     Startup    `json:"startup"`
	Ports       []Port     `json:"ports,omitempty"`
	Query       *Query     `json:"query,omitempty"`
	RCON        *RCON      `json:"rcon,omitempty"`
	Restart     *Restart   `json:"restart,omitempty"`
	Steam       *Steam     `json:"steam,omitempty"`
	ConfigFiles []string   `json:"config_files,omitempty"`
}
type Docker struct {
	Image          string            `json:"image"`
	DataPath       string            `json:"data_path,omitempty"`
	User           string            `json:"user,omitempty"`
	KeepEntrypoint bool              `json:"keep_entrypoint,omitempty"`
	ExtraVolumes   []string          `json:"extra_volumes,omitempty"`
	Capabilities   []string          `json:"capabilities,omitempty"`
	Devices        []string          `json:"devices,omitempty"`
	Sysctls        map[string]string `json:"sysctls,omitempty"`
	Env            map[string]string `json:"env,omitempty"`
}
type Variable struct {
	Key      string   `json:"key"`
	Name     string   `json:"name,omitempty"`
	Type     string   `json:"type"`
	Options  []string `json:"options,omitempty"`
	Default  any      `json:"default,omitempty"`
	Required bool     `json:"required,omitempty"`
	Min      *int     `json:"min,omitempty"`
	Max      *int     `json:"max,omitempty"`
	Secret   bool     `json:"secret,omitempty"`
	Pattern  string   `json:"pattern,omitempty"`
	Hint     string   `json:"hint,omitempty"`
}
type Install struct {
	Image  string `json:"image,omitempty"`
	Script string `json:"script"`
}
type Startup struct {
	Command     string   `json:"command,omitempty"`
	Exec        []string `json:"exec,omitempty"`
	DoneRegex   string   `json:"done_regex,omitempty"`
	Stop        string   `json:"stop,omitempty"`
	SaveCommand string   `json:"save_command,omitempty"`
	StopTimeout int      `json:"stop_timeout,omitempty"`
}
type Port struct {
	Name     string `json:"name"`
	Default  int    `json:"default"`
	Protocol string `json:"protocol"`
}
type Query struct {
	Type string `json:"type"`
}
type RCON struct {
	Enabled     bool   `json:"enabled"`
	Type        string `json:"type,omitempty"`
	PasswordVar string `json:"password_var,omitempty"`
}
type Restart struct {
	Warnings []RestartWarning `json:"warnings,omitempty"`
}
type RestartWarning struct {
	At  string `json:"at"`
	Msg string `json:"msg"`
}
type Steam struct {
	AppID     int  `json:"app_id"`
	Anonymous bool `json:"anonymous"`
}

var runeID = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,63}$`)
var restartPlaceholder = regexp.MustCompile(`{{([^{}]*)}}`)

func Parse(src string) (Rune, error) {
	var env struct {
		Gameskill Rune `json:"gameskill"`
	}
	if err := Decode(src, &env); err != nil {
		return Rune{}, err
	}
	if err := env.Gameskill.Validate(); err != nil {
		return Rune{}, err
	}
	return env.Gameskill, nil
}
func (g Rune) Validate() error {
	if !runeID.MatchString(g.ID) {
		return errors.New("gameskill.id must use lowercase letters, digits, hyphens or underscores")
	}
	if strings.TrimSpace(g.Name) == "" {
		return errors.New("gameskill.name is required")
	}
	if strings.TrimSpace(g.Docker.Image) == "" {
		return errors.New("gameskill.docker.image is required")
	}
	if len(g.Startup.Exec) == 0 && strings.TrimSpace(g.Startup.Command) == "" && !g.Docker.KeepEntrypoint {
		return errors.New("gameskill.startup requires command, exec or docker.keep_entrypoint")
	}
	if g.Startup.StopTimeout < 0 {
		return errors.New("startup.stop_timeout cannot be negative")
	}
	if g.Startup.DoneRegex != "" {
		if _, err := regexp.Compile(g.Startup.DoneRegex); err != nil {
			return fmt.Errorf("startup.done_regex: %w", err)
		}
	}
	if g.Restart != nil {
		seen := map[time.Duration]bool{}
		for i, warning := range g.Restart.Warnings {
			at, err := time.ParseDuration(strings.TrimSpace(warning.At))
			if err != nil || at <= 0 || at > 24*time.Hour {
				return fmt.Errorf("restart.warnings[%d].at must be a duration greater than 0 and at most 24h", i)
			}
			if seen[at] {
				return fmt.Errorf("restart.warnings contains duplicate duration %q", warning.At)
			}
			seen[at] = true
			if strings.TrimSpace(warning.Msg) == "" || len(warning.Msg) > 4096 || strings.ContainsAny(warning.Msg, "\r\n\x00") {
				return fmt.Errorf("restart.warnings[%d].msg must be a single command of 1 to 4096 characters", i)
			}
			for _, match := range restartPlaceholder.FindAllStringSubmatch(warning.Msg, -1) {
				switch match[1] {
				case "server_name", "minutes", "seconds":
				default:
					return fmt.Errorf("restart.warnings[%d].msg contains unsupported placeholder %q", i, match[0])
				}
			}
			withoutPlaceholders := restartPlaceholder.ReplaceAllString(warning.Msg, "")
			if strings.Contains(withoutPlaceholders, "{{") || strings.Contains(withoutPlaceholders, "}}") {
				return fmt.Errorf("restart.warnings[%d].msg contains an incomplete placeholder", i)
			}
		}
	}
	declared := map[string]bool{}
	for _, v := range g.Variables {
		if v.Key == "" {
			return errors.New("variable.key is required")
		}
		if declared[v.Key] {
			return fmt.Errorf("variable %q is declared more than once", v.Key)
		}
		declared[v.Key] = true
		switch v.Type {
		case "string", "int", "bool":
		case "select":
			if len(v.Options) == 0 {
				return fmt.Errorf("variable %q: select requires options", v.Key)
			}
		default:
			return fmt.Errorf("variable %q has unsupported type %q", v.Key, v.Type)
		}
		if v.Pattern != "" {
			if _, err := regexp.Compile(v.Pattern); err != nil {
				return fmt.Errorf("variable %q pattern: %w", v.Key, err)
			}
		}
		if reservedVariable(v.Key) {
			return fmt.Errorf("variable %q conflicts with a name injected by the panel", v.Key)
		}
	}
	portNames := map[string]bool{}
	for _, p := range g.Ports {
		if p.Name == "" {
			return errors.New("port.name is required")
		}
		if portNames[strings.ToLower(p.Name)] {
			return fmt.Errorf("port %q is declared more than once", p.Name)
		}
		portNames[strings.ToLower(p.Name)] = true
		if p.Protocol != "tcp" && p.Protocol != "udp" && p.Protocol != "tcp+udp" {
			return fmt.Errorf("port %q protocol must be tcp, udp or tcp+udp", p.Name)
		}
		if p.Default < 1 || p.Default > 65535 {
			return fmt.Errorf("port %q default must be from 1 to 65535", p.Name)
		}
	}
	for _, v := range g.Docker.Capabilities {
		switch strings.ToUpper(strings.TrimSpace(v)) {
		case "NET_ADMIN", "NET_RAW", "NET_BIND_SERVICE", "SYS_NICE":
		default:
			return fmt.Errorf("docker.capabilities contains disallowed capability %q", v)
		}
	}
	for _, v := range g.Docker.Devices {
		parts := strings.Split(v, ":")
		if len(parts) > 3 {
			return fmt.Errorf("docker.devices entry %q must be host[:container[:permissions]]", v)
		}
		allowed := map[string]bool{"/dev/net/tun": true, "/dev/dri": true, "/dev/fuse": true}
		host, container := parts[0], parts[0]
		if len(parts) > 1 && parts[1] != "" {
			container = parts[1]
		}
		if !allowed[host] || !allowed[container] {
			return fmt.Errorf("docker.devices entry %q uses a device outside /dev/net/tun, /dev/dri or /dev/fuse", v)
		}
		if len(parts) == 3 {
			perms := parts[2]
			if perms == "" {
				return fmt.Errorf("docker.devices entry %q has empty permissions", v)
			}
			seen := map[rune]bool{}
			for _, permission := range perms {
				if !strings.ContainsRune("rwm", permission) || seen[permission] {
					return fmt.Errorf("docker.devices entry %q permissions may contain r, w and m once each", v)
				}
				seen[permission] = true
			}
		}
	}
	for k := range g.Docker.Sysctls {
		switch k {
		case "net.ipv4.ip_forward", "net.ipv6.conf.all.forwarding", "net.ipv4.conf.all.src_valid_mark":
		default:
			return fmt.Errorf("docker.sysctls contains disallowed key %q", k)
		}
	}
	for _, p := range g.Docker.ExtraVolumes {
		if err := validateContainerPath(p); err != nil {
			return fmt.Errorf("docker.extra_volumes: %w", err)
		}
	}
	for _, p := range g.ConfigFiles {
		if p == "" || strings.HasPrefix(p, "/") || path.Clean(p) != p || strings.HasPrefix(p, "..") {
			return fmt.Errorf("config_files path %q must be a clean relative path", p)
		}
	}
	if g.Query != nil {
		switch g.Query.Type {
		case "a2s", "source", "minecraft", "minecraft-java", "minecraft-bedrock":
		default:
			return fmt.Errorf("query.type %q is unsupported", g.Query.Type)
		}
	}
	if g.RCON != nil && g.RCON.Enabled {
		switch g.RCON.Type {
		case "", "minecraft", "source":
		default:
			return fmt.Errorf("rcon.type %q is unsupported", g.RCON.Type)
		}
	}
	if g.RCON != nil && g.RCON.PasswordVar != "" && !declared[g.RCON.PasswordVar] {
		return fmt.Errorf("rcon.password_var %q is not a declared variable", g.RCON.PasswordVar)
	}
	if len(g.ConfigFiles) != 0 {
		return errors.New("gameskill.config_files is not supported in this release; use the server Files tab")
	}
	if g.Steam != nil {
		return errors.New("gameskill.steam installation metadata is not supported in this release")
	}
	return nil
}
func reservedVariable(k string) bool {
	u := strings.ToUpper(k)
	if u == "SERVER_NAME" || u == "PUBLIC_URL" || u == "HOME" || u == "PUID" || u == "PGID" || u == "UID" || u == "GID" || strings.HasPrefix(u, "PORT_") {
		return true
	}
	return strings.HasSuffix(u, "_PORT")
}
func validateContainerPath(p string) error {
	if p == "" {
		return nil
	}
	if !strings.HasPrefix(p, "/") || strings.Contains(p, "..") || path.Clean(p) != p {
		return fmt.Errorf("path %q must be an absolute clean container path", p)
	}
	denied := []string{"/", "/etc", "/var", "/var/run", "/run", "/home", "/usr", "/root", "/bin", "/sbin", "/lib", "/lib64", "/proc", "/sys", "/dev", "/boot", "/usr/bin", "/usr/sbin", "/usr/lib", "/usr/lib64", "/usr/libexec", "/usr/local/bin", "/usr/local/sbin", "/usr/local/lib"}
	for _, d := range denied {
		if p == d || strings.HasPrefix(p, d+"/") {
			return fmt.Errorf("path %q would shadow a protected system directory", p)
		}
	}
	return nil
}
func (g Rune) DefaultEnv() map[string]string {
	out := map[string]string{}
	for _, v := range g.Variables {
		if v.Default != nil {
			out[v.Key] = fmt.Sprint(v.Default)
		}
	}
	return out
}
func (g Rune) ValidateEnv(values map[string]string) error {
	for _, v := range g.Variables {
		value, ok := values[v.Key]
		if !ok || value == "" {
			if v.Default != nil {
				value = fmt.Sprint(v.Default)
			} else if v.Required {
				return fmt.Errorf("%s is required", label(v))
			} else {
				continue
			}
		}
		if err := validateValue(v, value); err != nil {
			return fmt.Errorf("%s: %w", label(v), err)
		}
	}
	return nil
}
func label(v Variable) string {
	if v.Name != "" {
		return v.Name
	}
	return v.Key
}
func validateValue(v Variable, s string) error {
	switch v.Type {
	case "int":
		n, e := strconv.Atoi(s)
		if e != nil {
			return errors.New("must be a whole number")
		}
		if v.Min != nil && n < *v.Min {
			return fmt.Errorf("must be at least %d", *v.Min)
		}
		if v.Max != nil && n > *v.Max {
			return fmt.Errorf("must be at most %d", *v.Max)
		}
	case "bool":
		if _, e := strconv.ParseBool(s); e != nil {
			return errors.New("must be true or false")
		}
	case "select":
		for _, o := range v.Options {
			if s == o {
				return nil
			}
		}
		return fmt.Errorf("must be one of %s", strings.Join(v.Options, ", "))
	}
	if v.Pattern != "" {
		r, _ := regexp.Compile(v.Pattern)
		if !r.MatchString(s) {
			if v.Hint != "" {
				return errors.New(v.Hint)
			}
			return errors.New("does not match the required format")
		}
	}
	return nil
}
func ApplyTemplate(s string, env map[string]string) string {
	for k, v := range env {
		s = strings.ReplaceAll(s, "{{"+k+"}}", v)
	}
	return s
}
func ToJSON(g Rune) string { b, _ := json.Marshal(g); return string(b) }
