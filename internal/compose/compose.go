// Package compose translates the useful, portable part of a Compose project
// into a Docklight template. Host-specific settings are reported as warnings.
package compose

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"example.com/yggdrasil-panel/internal/rune"
	"go.yaml.in/yaml/v3"
)

const MaxSize = 1 << 20

var envNamePattern = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

type service struct {
	name string
	node *yaml.Node
}

type warningSet struct {
	items []string
	seen  map[string]bool
}

func (w *warningSet) add(message string) {
	if w.seen == nil {
		w.seen = map[string]bool{}
	}
	if !w.seen[message] {
		w.seen[message] = true
		w.items = append(w.items, message)
	}
}

// Translate reads one Compose YAML document and returns its selected main
// service as the Docklight app plus other image-based services as sidecars.
// requestedMain and preferredName are optional operator-provided overrides.
func Translate(input []byte, requestedMain, preferredName string) (rune.Rune, []string, error) {
	if len(input) == 0 {
		return rune.Rune{}, nil, fmt.Errorf("Compose file is empty")
	}
	if len(input) > MaxSize {
		return rune.Rune{}, nil, fmt.Errorf("Compose file exceeds the 1 MiB upload limit")
	}

	decoder := yaml.NewDecoder(bytes.NewReader(input))
	var document yaml.Node
	if err := decoder.Decode(&document); err != nil {
		return rune.Rune{}, nil, fmt.Errorf("read Compose YAML: %w", err)
	}
	var extra yaml.Node
	if err := decoder.Decode(&extra); err != io.EOF {
		if err == nil {
			return rune.Rune{}, nil, fmt.Errorf("Compose import accepts one YAML document")
		}
		return rune.Rune{}, nil, fmt.Errorf("read Compose YAML: %w", err)
	}
	if len(document.Content) != 1 || document.Content[0].Kind != yaml.MappingNode {
		return rune.Rune{}, nil, fmt.Errorf("Compose document must be a mapping with a services section")
	}
	root := document.Content[0]
	servicesNode := mappingValue(root, "services")
	if servicesNode == nil || servicesNode.Kind != yaml.MappingNode || len(servicesNode.Content) == 0 {
		return rune.Rune{}, nil, fmt.Errorf("Compose file must define at least one service under services:")
	}

	services := make([]service, 0, len(servicesNode.Content)/2)
	byName := make(map[string]service, len(servicesNode.Content)/2)
	for i := 0; i+1 < len(servicesNode.Content); i += 2 {
		key, value := servicesNode.Content[i], servicesNode.Content[i+1]
		if key.Kind != yaml.ScalarNode || strings.TrimSpace(key.Value) == "" || len(key.Value) > 128 || strings.ContainsAny(key.Value, "\r\n\x00") || value.Kind != yaml.MappingNode {
			return rune.Rune{}, nil, fmt.Errorf("Compose services must be named mappings")
		}
		item := service{name: key.Value, node: value}
		if _, exists := byName[item.name]; exists {
			return rune.Rune{}, nil, fmt.Errorf("Compose service %q is declared more than once", item.name)
		}
		services = append(services, item)
		byName[item.name] = item
	}
	if len(services) == 0 {
		return rune.Rune{}, nil, fmt.Errorf("Compose file must define at least one service under services:")
	}

	warnings := &warningSet{}
	if requestedMain != "" {
		if _, ok := byName[requestedMain]; !ok {
			return rune.Rune{}, nil, fmt.Errorf("requested main service %q was not found in the Compose services", requestedMain)
		}
	}
	main := chooseMain(services, byName, requestedMain, warnings)
	if main == nil {
		return rune.Rune{}, nil, fmt.Errorf("could not choose a main service; set the main service field to a service name")
	}
	mainImage := scalarValue(mappingValue(main.node, "image"))
	if mainImage == "" {
		return rune.Rune{}, nil, fmt.Errorf("main service %q has no image; Compose build instructions are not imported, so add a pullable image first", main.name)
	}
	if strings.Contains(mainImage, "${") {
		warnings.add(fmt.Sprintf("Compose variable interpolation in service %s image is not evaluated; use a concrete image reference.", main.name))
	}

	name := strings.TrimSpace(preferredName)
	if name == "" {
		name = scalarValue(mappingValue(root, "name"))
	}
	if name == "" {
		name = scalarValue(mappingValue(main.node, "container_name"))
	}
	if name == "" {
		name = main.name
	}
	if len(name) > 80 || strings.TrimSpace(name) == "" || strings.ContainsAny(name, "\r\n\x00") {
		return rune.Rune{}, nil, fmt.Errorf("template name must contain 1 to 80 characters without line breaks")
	}
	id := slug(name)
	if id == "" {
		return rune.Rune{}, nil, fmt.Errorf("template name must include at least one letter or digit")
	}

	result := rune.Rune{
		ID: id, Name: name, Category: "Apps", Version: 1,
		Description: "Imported from Docker Compose service " + main.name + ".",
		Docker:      rune.Docker{Image: mainImage, KeepEntrypoint: true},
		Startup:     rune.Startup{},
	}

	declaredSecrets := map[string]bool{}
	mainEnv, vars := translateEnvironment(main.name, mappingValue(main.node, "environment"), warnings, declaredSecrets)
	result.Docker.Env = mainEnv
	result.Variables = append(result.Variables, vars...)
	result.Ports = translatePorts(main.name, mappingValue(main.node, "ports"), warnings)
	mainVolumes := translateVolumes(main.name, mappingValue(main.node, "volumes"), warnings)
	if len(mainVolumes) > 0 {
		result.Docker.DataPath = mainVolumes[0]
		result.Docker.ExtraVolumes = append(result.Docker.ExtraVolumes, mainVolumes[1:]...)
	}

	checkIgnoredFields(main, warnings)
	stack := &rune.Stack{}
	for _, item := range services {
		if item.name == main.name {
			continue
		}
		image := scalarValue(mappingValue(item.node, "image"))
		if image == "" {
			warnings.add(fmt.Sprintf("Service %s has no image and was skipped; build instructions are not imported.", item.name))
			continue
		}
		checkIgnoredFields(&item, warnings)
		env, serviceVars := translateEnvironment(item.name, mappingValue(item.node, "environment"), warnings, declaredSecrets)
		result.Variables = append(result.Variables, serviceVars...)
		volumes := translateVolumes(item.name, mappingValue(item.node, "volumes"), warnings)
		sidecar := rune.Service{Name: dnsName(item.name), Image: image, Environment: env}
		if len(volumes) > 0 {
			sidecar.DataPath = volumes[0]
			sidecar.ExtraVolumes = append(sidecar.ExtraVolumes, volumes[1:]...)
		}
		if ports := mappingValue(item.node, "ports"); ports != nil && ports.Kind != yaml.ScalarNode {
			if len(ports.Content) > 0 {
				warnings.add(fmt.Sprintf("Service %s published ports were dropped; only the main service can publish ports.", item.name))
			}
		}
		stack.Services = append(stack.Services, sidecar)
	}
	if len(stack.Services) > 0 {
		result.Stack = stack
	}

	if err := result.Validate(); err != nil {
		return rune.Rune{}, nil, fmt.Errorf("generated template is invalid: %w", err)
	}
	sort.Strings(warnings.items)
	if warnings.items == nil {
		warnings.items = []string{}
	}
	return result, warnings.items, nil
}

func chooseMain(services []service, byName map[string]service, requested string, warnings *warningSet) *service {
	if requested != "" {
		item, ok := byName[requested]
		if !ok {
			warnings.add(fmt.Sprintf("Requested main service %q was not found.", requested))
			return nil
		}
		return &item
	}
	var published []service
	for _, item := range services {
		node := mappingValue(item.node, "ports")
		if node != nil && node.Kind == yaml.SequenceNode && len(node.Content) > 0 {
			published = append(published, item)
		}
	}
	if len(published) == 1 {
		return &published[0]
	}
	if len(published) > 1 {
		for _, preferred := range []string{"app", "web", "server", "main", "game", "frontend"} {
			for i := range published {
				if strings.EqualFold(published[i].name, preferred) {
					return &published[i]
				}
			}
		}
		warnings.add(fmt.Sprintf("Several services publish ports; selected %q. Set the main service field to choose another.", published[0].name))
		return &published[0]
	}
	warnings.add(fmt.Sprintf("No service publishes ports; selected the first service, %q.", services[0].name))
	return &services[0]
}

func translateEnvironment(serviceName string, node *yaml.Node, warnings *warningSet, declared map[string]bool) (map[string]string, []rune.Variable) {
	values := map[string]string{}
	if node == nil {
		return values, nil
	}
	if node.Kind == yaml.MappingNode {
		for i := 0; i+1 < len(node.Content); i += 2 {
			key, value := node.Content[i], node.Content[i+1]
			if key.Kind != yaml.ScalarNode {
				warnings.add(fmt.Sprintf("Service %s has a non-text environment key; it was skipped.", serviceName))
				continue
			}
			if value.Tag == "!!null" {
				warnings.add(fmt.Sprintf("Service %s environment key %s has no value and was skipped; enter it directly in Docklight if needed.", serviceName, key.Value))
				continue
			}
			if value.Kind != yaml.ScalarNode {
				warnings.add(fmt.Sprintf("Service %s environment key %s is not a scalar and was skipped.", serviceName, key.Value))
				continue
			}
			values[key.Value] = value.Value
		}
	} else if node.Kind == yaml.SequenceNode {
		for _, value := range node.Content {
			if value.Kind != yaml.ScalarNode {
				warnings.add(fmt.Sprintf("Service %s has a non-text environment entry; it was skipped.", serviceName))
				continue
			}
			key, val, hasValue := strings.Cut(value.Value, "=")
			if !hasValue {
				warnings.add(fmt.Sprintf("Service %s environment key %s has no value and was skipped; enter it directly in Docklight if needed.", serviceName, key))
				continue
			}
			values[key] = val
		}
	} else {
		warnings.add(fmt.Sprintf("Service %s environment must be a mapping or list; it was skipped.", serviceName))
		return map[string]string{}, nil
	}

	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	variables := []rune.Variable{}
	output := make(map[string]string, len(values))
	for _, key := range keys {
		value := values[key]
		if !envNamePattern.MatchString(key) {
			warnings.add(fmt.Sprintf("Service %s environment key %q is invalid and was skipped.", serviceName, key))
			continue
		}
		if reservedEnv(key) {
			warnings.add(fmt.Sprintf("Service %s environment key %s is controlled by Docklight and was skipped.", serviceName, key))
			continue
		}
		if sensitiveEnv(key, value) {
			variableKey := secretVariableKey(serviceName, key)
			if declared[variableKey] {
				hash := sha256.Sum256([]byte(serviceName + "\x00" + key))
				suffix := "_" + hex.EncodeToString(hash[:3])
				variableKey = strings.TrimRight(variableKey[:min(len(variableKey), 64-len(suffix))], "_") + suffix
			}
			declared[variableKey] = true
			variables = append(variables, rune.Variable{
				Key: variableKey, Name: serviceName + " " + key, Type: "string", Secret: true, Required: value != "",
				Hint: "This value was present in the Compose file but was omitted for security. Enter it again when creating a server.",
			})
			output[key] = "{{" + variableKey + "}}"
			warnings.add(fmt.Sprintf("Secret environment values for service %s were omitted; enter %s again when creating a server.", serviceName, key))
			continue
		}
		output[key] = value
		if strings.Contains(value, "${") {
			warnings.add(fmt.Sprintf("Compose variable interpolation in service %s environment key %s is not evaluated; review its value after import.", serviceName, key))
		}
	}
	return output, variables
}

func translatePorts(serviceName string, node *yaml.Node, warnings *warningSet) []rune.Port {
	if node == nil {
		return nil
	}
	if node.Kind != yaml.SequenceNode {
		warnings.add(fmt.Sprintf("Service %s uses long-form or invalid ports; only short-form ports are imported.", serviceName))
		return nil
	}
	ports := []rune.Port{}
	seen := map[string]bool{}
	for _, entry := range node.Content {
		if entry.Kind != yaml.ScalarNode {
			warnings.add(fmt.Sprintf("Service %s has a long-form port mapping that was skipped; use short syntax such as '8080:80/tcp'.", serviceName))
			continue
		}
		value := strings.TrimSpace(entry.Value)
		parts := strings.Split(value, "/")
		protocol := "tcp"
		if len(parts) > 1 {
			protocol = strings.ToLower(parts[1])
		}
		if len(parts) > 2 || (protocol != "tcp" && protocol != "udp") {
			warnings.add(fmt.Sprintf("Service %s port %q uses an unsupported protocol and was skipped.", serviceName, value))
			continue
		}
		portParts := strings.Split(parts[0], ":")
		containerPort := portParts[len(portParts)-1]
		if len(portParts) >= 3 {
			hostIP := strings.Trim(strings.Join(portParts[:len(portParts)-2], ":"), "[]")
			if hostIP != "" && hostIP != "0.0.0.0" && hostIP != "::" {
				if strings.HasPrefix(hostIP, "127.") || hostIP == "::1" {
					warnings.add(fmt.Sprintf("Service %s localhost-only port %q was not imported because Docklight cannot preserve its host binding.", serviceName, value))
				} else {
					warnings.add(fmt.Sprintf("Service %s port %q has a specific host binding that Docklight cannot preserve; it was not imported.", serviceName, value))
				}
				continue
			}
		}
		hasRange := strings.Contains(containerPort, "-")
		if len(portParts) > 1 {
			for _, hostPort := range portParts[:len(portParts)-1] {
				if strings.Contains(hostPort, "-") {
					hasRange = true
				}
			}
		}
		if hasRange {
			warnings.add(fmt.Sprintf("Service %s port range %q was skipped; declare individual container ports instead.", serviceName, value))
			continue
		}
		port, err := strconv.Atoi(containerPort)
		if err != nil || port < 1 || port > 65535 {
			warnings.add(fmt.Sprintf("Service %s port %q is not a valid container port and was skipped.", serviceName, value))
			continue
		}
		key := fmt.Sprintf("%d/%s", port, protocol)
		if seen[key] {
			continue
		}
		seen[key] = true
		name := fmt.Sprintf("port-%d-%s", port, protocol)
		if port == 80 && protocol == "tcp" {
			name = "web"
		}
		ports = append(ports, rune.Port{Name: name, Default: port, Protocol: protocol})
		if len(portParts) > 1 {
			warnings.add("Published host ports are replaced with free ports allocated by Docklight.")
		}
	}
	return ports
}

func translateVolumes(serviceName string, node *yaml.Node, warnings *warningSet) []string {
	if node == nil {
		return nil
	}
	if node.Kind != yaml.SequenceNode {
		warnings.add(fmt.Sprintf("Service %s volume mounts are not a list and were skipped.", serviceName))
		return nil
	}
	var targets []string
	seen := map[string]bool{}
	for _, entry := range node.Content {
		if entry.Kind == yaml.MappingNode {
			kind := scalarValue(mappingValue(entry, "type"))
			target := scalarValue(mappingValue(entry, "target"))
			if kind == "bind" {
				warnings.add(fmt.Sprintf("Service %s bind mounts are not imported; add host mounts after creating the server.", serviceName))
				continue
			}
			if kind != "volume" || target == "" {
				warnings.add(fmt.Sprintf("Service %s uses an unsupported long-form volume mount that was skipped.", serviceName))
				continue
			}
			if mountReadOnly(entry) {
				warnings.add(fmt.Sprintf("Service %s read-only volume flags are not retained.", serviceName))
			}
			addVolumeTarget(serviceName, target, &targets, seen, warnings)
			continue
		}
		if entry.Kind != yaml.ScalarNode {
			warnings.add(fmt.Sprintf("Service %s has a non-text volume mount that was skipped.", serviceName))
			continue
		}
		parts := strings.Split(entry.Value, ":")
		var source, target string
		if len(parts) == 1 {
			target = parts[0]
		} else {
			source, target = parts[0], parts[1]
		}
		if len(parts) > 2 {
			for _, mode := range strings.Split(parts[2], ",") {
				if mode == "ro" {
					warnings.add(fmt.Sprintf("Service %s read-only volume flags are not retained.", serviceName))
					break
				}
			}
		}
		if isBindPath(source) {
			warnings.add(fmt.Sprintf("Service %s bind mounts are not imported; add host mounts after creating the server.", serviceName))
			continue
		}
		addVolumeTarget(serviceName, target, &targets, seen, warnings)
	}
	return targets
}

func addVolumeTarget(serviceName, target string, targets *[]string, seen map[string]bool, warnings *warningSet) {
	if !strings.HasPrefix(target, "/") || strings.Contains(target, "..") {
		warnings.add(fmt.Sprintf("Service %s volume target %q is not a safe absolute container path and was skipped.", serviceName, target))
		return
	}
	if seen[target] {
		warnings.add(fmt.Sprintf("Service %s repeats volume target %s; the duplicate was skipped.", serviceName, target))
		return
	}
	seen[target] = true
	*targets = append(*targets, target)
	warnings.add(fmt.Sprintf("Service %s volume contents for %s are not copied; Docklight creates new persistent storage there.", serviceName, target))
}

func checkIgnoredFields(item *service, warnings *warningSet) {
	ignored := []struct{ key, description string }{
		{"build", "build instructions"}, {"command", "command overrides"}, {"entrypoint", "entrypoint overrides"},
		{"env_file", "env_file contents"}, {"depends_on", "dependency health ordering"}, {"healthcheck", "health checks"},
		{"configs", "configs"}, {"secrets", "Compose secrets"}, {"network_mode", "network mode"},
		{"restart", "restart policy"}, {"user", "container user"},
	}
	for _, field := range ignored {
		if mappingValue(item.node, field.key) != nil {
			warnings.add(fmt.Sprintf("Service %s %s are not imported; review the generated template.", item.name, field.description))
		}
	}
	if networks := mappingValue(item.node, "networks"); networks != nil {
		warnings.add(fmt.Sprintf("Service %s network declarations are ignored; Docklight creates a private per-server network for sidecars.", item.name))
	}
}

func mappingValue(node *yaml.Node, key string) *yaml.Node {
	if node == nil || node.Kind != yaml.MappingNode {
		return nil
	}
	for i := 0; i+1 < len(node.Content); i += 2 {
		if node.Content[i].Value == key {
			return node.Content[i+1]
		}
	}
	return nil
}

func scalarValue(node *yaml.Node) string {
	if node == nil || node.Kind != yaml.ScalarNode || node.Tag == "!!null" {
		return ""
	}
	return node.Value
}

func mountReadOnly(node *yaml.Node) bool {
	readOnly := mappingValue(node, "read_only")
	return readOnly != nil && strings.EqualFold(scalarValue(readOnly), "true")
}

func isBindPath(source string) bool {
	if source == "" {
		return false // anonymous volumes are persistent in the generated template
	}
	return strings.HasPrefix(source, ".") || strings.HasPrefix(source, "/") || strings.HasPrefix(source, "~") || strings.Contains(source, "/")
}

func reservedEnv(key string) bool {
	upper := strings.ToUpper(key)
	if strings.HasSuffix(upper, "_PORT") || strings.HasPrefix(upper, "PORT_") {
		return true
	}
	switch upper {
	case "SERVER_NAME", "PUBLIC_URL", "HOME", "PUID", "PGID", "UID", "GID":
		return true
	}
	return false
}

func sensitiveEnv(key, value string) bool {
	normalized := strings.NewReplacer("_", "", "-", "", ".", "").Replace(strings.ToLower(key))
	for _, suffix := range []string{"password", "passwd", "pass", "secret", "secretkey", "token", "credential", "apikey", "privatekey", "accesskey", "clientsecret", "signingkey", "encryptionkey", "databaseurl", "redisurl", "connectionstring", "dsn"} {
		if strings.HasSuffix(normalized, suffix) {
			return true
		}
	}
	if strings.HasSuffix(normalized, "url") || strings.HasSuffix(normalized, "uri") {
		if parsed, err := url.Parse(value); err == nil {
			if parsed.User != nil {
				return true
			}
			for key := range parsed.Query() {
				if sensitiveEnv(key, "") {
					return true
				}
			}
		}
	}
	return false
}

func secretVariableKey(serviceName, envName string) string {
	base := "IMPORT_" + serviceName + "_" + envName
	var normalized strings.Builder
	for _, r := range strings.ToUpper(base) {
		if r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '_' {
			normalized.WriteRune(r)
		} else {
			normalized.WriteRune('_')
		}
	}
	key := strings.Trim(normalized.String(), "_")
	if len(key) > 64 {
		hash := sha256.Sum256([]byte(base))
		key = strings.TrimRight(key[:57], "_") + "_" + hex.EncodeToString(hash[:3])
	}
	return key
}

func slug(value string) string {
	var out strings.Builder
	lastDash := false
	for _, r := range strings.ToLower(strings.TrimSpace(value)) {
		if r >= 'a' && r <= 'z' || r >= '0' && r <= '9' {
			out.WriteRune(r)
			lastDash = false
		} else if out.Len() > 0 && !lastDash {
			out.WriteByte('-')
			lastDash = true
		}
	}
	result := strings.Trim(out.String(), "-")
	if len(result) > 64 {
		result = strings.TrimRight(result[:64], "-")
	}
	return result
}

func dnsName(value string) string {
	name := slug(value)
	name = strings.Trim(name, "-")
	if name == "" {
		return "service"
	}
	if len(name) > 63 {
		name = name[:63]
	}
	return name
}
