package config

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

type Config struct {
	Server struct {
		Host string
		Port int
	}
	Database struct{ Path string }
	Auth     struct {
		SecretKey       string
		SessionTTLHours int
	}
	Admin struct {
		Username string
		Password string
	}
	Docker struct {
		Socket     string
		APIVersion string
	}
	Backups struct {
		Path      string
		Retention int
	}
	Ports struct {
		RangeMin int
		RangeMax int
	}
}

func Defaults() Config {
	var c Config
	c.Server.Host, c.Server.Port = "0.0.0.0", 8080
	c.Database.Path = "/var/lib/yggdrasil/yggdrasil.db"
	c.Auth.SessionTTLHours = 168
	c.Admin.Username = "admin"
	c.Docker.Socket, c.Docker.APIVersion = "unix:///var/run/docker.sock", "v1.45"
	c.Backups.Retention = 10
	c.Ports.RangeMin, c.Ports.RangeMax = 25000, 30000
	return c
}

// Load reads the deliberately small configuration surface used by the core.
// It accepts ordinary block-style YAML for these scalar keys.
func Load(path string) (Config, error) {
	c := Defaults()
	b, err := os.ReadFile(path)
	if err != nil {
		return c, err
	}
	section := ""
	for n, raw := range strings.Split(string(b), "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		indent := len(raw) - len(strings.TrimLeft(raw, " \t"))
		if !strings.Contains(line, ":") {
			return c, fmt.Errorf("config line %d: expected key: value", n+1)
		}
		pair := strings.SplitN(line, ":", 2)
		key, val := strings.TrimSpace(pair[0]), strings.TrimSpace(pair[1])
		if indent == 0 && val == "" {
			section = key
			continue
		}
		if indent > 0 {
			key = section + "." + key
		}
		val = strings.Trim(val, "\"'")
		setString := func(dst *string) { *dst = val }
		setInt := func(dst *int) error {
			v, e := strconv.Atoi(val)
			if e == nil {
				*dst = v
			}
			return e
		}
		setBool := func(dst *bool) error {
			v, e := strconv.ParseBool(val)
			if e == nil {
				*dst = v
			}
			return e
		}
		var setErr error
		switch key {
		case "server.host":
			setString(&c.Server.Host)
		case "server.port":
			setErr = setInt(&c.Server.Port)
		case "server.demo_mode": // accepted for compatibility with early generated configs
			var ignored bool
			setErr = setBool(&ignored)
		case "database.path":
			setString(&c.Database.Path)
		case "auth.secret_key":
			setString(&c.Auth.SecretKey)
		case "auth.session_ttl_hours":
			setErr = setInt(&c.Auth.SessionTTLHours)
		case "admin.username":
			setString(&c.Admin.Username)
		case "admin.password":
			setString(&c.Admin.Password)
		case "docker.socket":
			setString(&c.Docker.Socket)
		case "docker.api_version":
			setString(&c.Docker.APIVersion)
		case "backups.path":
			setString(&c.Backups.Path)
		case "backups.retention":
			setErr = setInt(&c.Backups.Retention)
		case "ports.range_min":
			setErr = setInt(&c.Ports.RangeMin)
		case "ports.range_max":
			setErr = setInt(&c.Ports.RangeMax)
		default:
			return c, fmt.Errorf("config line %d: unknown key %q", n+1, key)
		}
		if setErr != nil {
			return c, fmt.Errorf("config line %d (%s): %w", n+1, key, setErr)
		}
	}
	if c.Server.Port < 1 || c.Server.Port > 65535 {
		return c, errors.New("server.port must be from 1 to 65535")
	}
	if c.Ports.RangeMin < 1024 || c.Ports.RangeMin >= c.Ports.RangeMax || c.Ports.RangeMax > 65535 {
		return c, errors.New("ports.range_min and range_max must satisfy 1024 <= min < max <= 65535")
	}
	if c.Database.Path == "" {
		return c, errors.New("database.path cannot be empty")
	}
	if c.Auth.SessionTTLHours < 1 {
		return c, errors.New("auth.session_ttl_hours must be at least 1")
	}
	if c.Backups.Retention < 1 || c.Backups.Retention > 100 {
		return c, errors.New("backups.retention must be from 1 to 100")
	}
	return c, nil
}

func Generate(path string) (Config, error) {
	if _, err := os.Stat(path); err == nil {
		return Config{}, fmt.Errorf("config already exists at %s; it was left untouched", path)
	} else if !errors.Is(err, os.ErrNotExist) {
		return Config{}, err
	}
	c := Defaults()
	if err := ensureSecret(&c); err != nil {
		return c, err
	}
	pw, err := Password()
	if err != nil {
		return c, err
	}
	c.Admin.Password = pw
	if err := Save(path, c); err != nil {
		return c, err
	}
	return c, nil
}

func EnsureSecret(path string, c *Config) error {
	if c.Auth.SecretKey != "" {
		if len(c.Auth.SecretKey) < 32 {
			return errors.New("auth.secret_key must contain at least 32 characters")
		}
		return nil
	}
	if err := ensureSecret(c); err != nil {
		return err
	}
	return Save(path, *c)
}
func ensureSecret(c *Config) error {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return err
	}
	c.Auth.SecretKey = base64.RawStdEncoding.EncodeToString(raw)
	return nil
}

func Save(path string, c Config) error {
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	s := fmt.Sprintf("server:\n  host: %s\n  port: %d\ndatabase:\n  path: %s\nauth:\n  secret_key: %s\n  session_ttl_hours: %d\nadmin:\n  username: %s\n", c.Server.Host, c.Server.Port, c.Database.Path, c.Auth.SecretKey, c.Auth.SessionTTLHours, c.Admin.Username)
	if c.Admin.Password != "" {
		s += fmt.Sprintf("  password: %s\n", c.Admin.Password)
	}
	s += fmt.Sprintf("docker:\n  socket: %s\n  api_version: %s\nbackups:\n  path: %s\n  retention: %d\nports:\n  range_min: %d\n  range_max: %d\n", c.Docker.Socket, c.Docker.APIVersion, c.Backups.Path, c.Backups.Retention, c.Ports.RangeMin, c.Ports.RangeMax)
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, []byte(s), 0600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func Password() (string, error) {
	const alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789!@#$%_-"
	b := make([]byte, 24)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	for i := range b {
		b[i] = alphabet[int(b[i])%len(alphabet)]
	}
	return string(b), nil
}
