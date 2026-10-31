package panel

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"example.com/yggdrasil-panel/internal/gameproto"
	"example.com/yggdrasil-panel/internal/rune"
	"github.com/go-chi/chi/v5"
)

const (
	publicIPCacheTTL         = time.Hour
	publicIPRetryDelay       = time.Minute
	reachabilityCacheTTL     = 30 * time.Second
	publicIPRequestTimeout   = 3 * time.Second
	reachabilityProbeTimeout = 4 * time.Second
)

var dnsLabelPattern = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`)

type networkSettingsResponse struct {
	PublicHostname   string `json:"public_hostname"`
	Detected         string `json:"detected"`
	DetectedStale    bool   `json:"detected_stale"`
	Effective        string `json:"effective"`
	DetectionMessage string `json:"detection_message,omitempty"`
}

type reachabilityResponse struct {
	Host      string `json:"host"`
	Port      int    `json:"port"`
	Protocol  string `json:"protocol"`
	Reachable bool   `json:"reachable"`
	Checked   bool   `json:"checked"`
	CheckedAt string `json:"checked_at,omitempty"`
	Message   string `json:"message"`
}

type reachabilityCacheEntry struct {
	response reachabilityResponse
	expires  time.Time
}

func (a *App) getNetworkSettings(w http.ResponseWriter, r *http.Request) {
	configured, err := a.savedPublicHostname()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not read network settings")
		return
	}
	detected, stale, message := a.detectedPublicIP(r.Context())
	effective := configured
	if effective == "" {
		effective = detected
	}
	if effective == "" {
		effective = "your-host"
	}
	writeJSON(w, http.StatusOK, networkSettingsResponse{
		PublicHostname: configured, Detected: detected, DetectedStale: stale,
		Effective: effective, DetectionMessage: message,
	})
}

func (a *App) updateNetworkSettings(w http.ResponseWriter, r *http.Request) {
	var in struct {
		PublicHostname string `json:"public_hostname"`
	}
	if decodeJSON(w, r, &in, 8*1024) != nil {
		return
	}
	hostname, err := normalizePublicHostname(in.PublicHostname)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if _, err = a.db.ExecContext(r.Context(), `INSERT INTO network_settings(id,public_hostname,updated_at) VALUES(1,?,CURRENT_TIMESTAMP)
		ON CONFLICT(id) DO UPDATE SET public_hostname=excluded.public_hostname,updated_at=CURRENT_TIMESTAMP`, hostname); err != nil {
		writeError(w, http.StatusInternalServerError, "could not save network settings")
		return
	}
	a.audit(principal(r), "network.update", "network", "1", "public_hostname="+hostname)
	a.getNetworkSettings(w, r)
}

func normalizePublicHostname(value string) (string, error) {
	host := strings.TrimSpace(value)
	if host == "" {
		return "", nil
	}
	if strings.Contains(host, "://") {
		u, err := url.Parse(host)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") {
			return "", errors.New("enter a hostname or an http(s) URL containing only a hostname")
		}
		if u.Port() != "" {
			return "", errors.New("enter the hostname only; Docklight uses each server's allocated port")
		}
		host = u.Hostname()
	} else {
		host = strings.TrimRight(host, "/")
	}
	if ip := net.ParseIP(host); ip != nil {
		if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsUnspecified() || ip.IsMulticast() {
			return "", errors.New("the public hostname cannot be a loopback, link-local, unspecified, or multicast address")
		}
		return ip.String(), nil
	}
	host = strings.TrimSuffix(strings.ToLower(host), ".")
	if host == "localhost" || strings.HasSuffix(host, ".localhost") || strings.ContainsAny(host, "/\\:@?#[]") || len(host) > 253 {
		return "", errors.New("enter a valid public hostname without a path or port")
	}
	for _, label := range strings.Split(host, ".") {
		if !dnsLabelPattern.MatchString(label) {
			return "", errors.New("enter a valid public hostname without a path or port")
		}
	}
	return host, nil
}

func (a *App) savedPublicHostname() (string, error) {
	var hostname string
	err := a.db.QueryRow(`SELECT public_hostname FROM network_settings WHERE id=1`).Scan(&hostname)
	if err != nil {
		return "", err
	}
	return hostname, nil
}

// detectedPublicIP uses one process-wide cache. It serializes refreshes and
// keeps the last successful address available when ipify is temporarily down.
func (a *App) detectedPublicIP(ctx context.Context) (string, bool, string) {
	a.networkMu.Lock()
	defer a.networkMu.Unlock()
	now := time.Now()
	if a.networkDetected != "" && now.Sub(a.networkDetectedAt) < publicIPCacheTTL {
		return a.networkDetected, false, ""
	}
	if !a.networkAttemptAt.IsZero() && now.Sub(a.networkAttemptAt) < publicIPRetryDelay {
		if a.networkDetected != "" {
			return a.networkDetected, true, "Public IP detection is temporarily unavailable; showing the last detected address."
		}
		return "", false, "Public IP detection is temporarily unavailable; set a public hostname to enable connection checks."
	}
	a.networkAttemptAt = now
	requestCtx, cancel := context.WithTimeout(ctx, publicIPRequestTimeout)
	defer cancel()
	request, err := http.NewRequestWithContext(requestCtx, http.MethodGet, "https://api.ipify.org?format=json", nil)
	if err == nil {
		client := a.networkHTTPClient
		if client == nil {
			client = &http.Client{Timeout: publicIPRequestTimeout, CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }}
		}
		var response *http.Response
		response, err = client.Do(request)
		if err == nil {
			defer response.Body.Close()
			if response.StatusCode != http.StatusOK {
				err = fmt.Errorf("public IP service returned HTTP %d", response.StatusCode)
			} else {
				var result struct {
					IP string `json:"ip"`
				}
				decodeErr := json.NewDecoder(io.LimitReader(response.Body, 4096)).Decode(&result)
				ip := net.ParseIP(strings.TrimSpace(result.IP))
				if decodeErr != nil || !isPublicIP(ip) {
					err = errors.New("public IP service returned an invalid address")
				} else {
					a.networkDetected = ip.String()
					a.networkDetectedAt = time.Now()
					return a.networkDetected, false, ""
				}
			}
		}
	}
	if a.networkDetected != "" {
		return a.networkDetected, true, "Public IP detection is temporarily unavailable; showing the last detected address."
	}
	return "", false, "Public IP detection is temporarily unavailable; set a public hostname to enable connection checks."
}

func (a *App) currentProbeHostname(ctx context.Context) (string, string, error) {
	hostname, err := a.savedPublicHostname()
	if err != nil {
		return "", "", err
	}
	if hostname != "" {
		return hostname, "", nil
	}
	detected, _, message := a.detectedPublicIP(ctx)
	return detected, message, nil
}

func isPublicIP(ip net.IP) bool {
	return ip != nil && ip.IsGlobalUnicast() && !ip.IsPrivate() && !ip.IsLoopback() && !ip.IsLinkLocalUnicast() && !ip.IsUnspecified() && !ip.IsMulticast()
}

func (a *App) serverReachability(w http.ResponseWriter, r *http.Request) {
	s, err := a.getServer(chi.URLParam(r, "id"))
	if err != nil {
		writeError(w, http.StatusNotFound, "server not found")
		return
	}
	if !a.requirePerm(w, principal(r), s, "server.view") {
		return
	}
	if s.Status != "running" && s.Status != "starting" {
		writeJSON(w, http.StatusOK, reachabilityResponse{Reachable: false, Checked: false, Message: "Start the server to check external reachability."})
		return
	}
	gs, err := a.loadRune(s.GameskillID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "server template is unavailable for the reachability check")
		return
	}
	hostname, hostMessage, err := a.currentProbeHostname(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not read network settings")
		return
	}
	if hostname == "" {
		writeJSON(w, http.StatusOK, reachabilityResponse{Reachable: false, Checked: false, Message: hostMessage})
		return
	}
	port, protocol, err := reachabilityPort(s, gs)
	if err != nil {
		writeJSON(w, http.StatusOK, reachabilityResponse{Host: hostname, Protocol: protocolForRune(gs), Reachable: false, Checked: false, Message: err.Error()})
		return
	}
	cacheKey := fmt.Sprintf("%s\x00%s\x00%d\x00%s\x00%s", s.ID, hostname, port, protocol, s.ContainerID)
	now := time.Now()
	a.reachabilityMu.Lock()
	if cached, ok := a.reachabilityCache[cacheKey]; ok && now.Before(cached.expires) {
		a.reachabilityMu.Unlock()
		writeJSON(w, http.StatusOK, cached.response)
		return
	}
	a.reachabilityMu.Unlock()

	ctx, cancel := context.WithTimeout(r.Context(), reachabilityProbeTimeout)
	defer cancel()
	probeErr := a.probePublicEndpoint(ctx, hostname, port, gs)
	result := reachabilityResponse{Host: hostname, Port: port, Protocol: protocol, Reachable: probeErr == nil, Checked: true, CheckedAt: time.Now().UTC().Format(time.RFC3339), Message: "The public endpoint responded from this panel host."}
	if probeErr != nil {
		result.Message = "No response from this public endpoint. Check the host firewall and router forwarding; NAT loopback can affect this check."
	}
	a.reachabilityMu.Lock()
	if a.reachabilityCache == nil {
		a.reachabilityCache = map[string]reachabilityCacheEntry{}
	}
	for key, cached := range a.reachabilityCache {
		if !time.Now().Before(cached.expires) {
			delete(a.reachabilityCache, key)
		}
	}
	if len(a.reachabilityCache) >= 2048 {
		clear(a.reachabilityCache)
	}
	a.reachabilityCache[cacheKey] = reachabilityCacheEntry{response: result, expires: time.Now().Add(reachabilityCacheTTL)}
	a.reachabilityMu.Unlock()
	writeJSON(w, http.StatusOK, result)
}

func reachabilityPort(s Server, gs rune.Rune) (int, string, error) {
	protocol := protocolForRune(gs)
	if gs.Query != nil {
		port, err := queryPort(s, gs)
		if err != nil {
			return 0, protocol, errors.New("this template has no allocated game or query port to check")
		}
		return port, protocol, nil
	}
	if port := s.Ports["game"]; port > 0 {
		return port, "tcp", nil
	}
	for _, declared := range gs.Ports {
		if strings.EqualFold(declared.Name, "rcon") {
			continue
		}
		if port := s.Ports[declared.Name]; port > 0 {
			return port, "tcp", nil
		}
	}
	return 0, "tcp", errors.New("this template has no allocated game port to check")
}

func protocolForRune(gs rune.Rune) string {
	if gs.Query != nil {
		return gs.Query.Type
	}
	return "tcp"
}

func (a *App) probePublicEndpoint(ctx context.Context, hostname string, port int, gs rune.Rune) error {
	ips, err := resolveProbeIPs(ctx, hostname)
	if err != nil {
		return err
	}
	var lastErr error
	for _, ip := range ips {
		if a.reachabilityProbe != nil {
			lastErr = a.reachabilityProbe(ctx, ip, port, gs)
		} else {
			lastErr = probeGameEndpoint(ctx, ip, port, gs)
		}
		if lastErr == nil {
			return nil
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
	}
	return lastErr
}

func resolveProbeIPs(ctx context.Context, hostname string) ([]string, error) {
	if ip := net.ParseIP(hostname); ip != nil {
		if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsUnspecified() || ip.IsMulticast() {
			return nil, errors.New("external reachability checks never target loopback or reserved addresses")
		}
		return []string{ip.String()}, nil
	}
	addresses, err := net.DefaultResolver.LookupIP(ctx, "ip", hostname)
	if err != nil {
		return nil, errors.New("the public hostname could not be resolved")
	}
	ips := make([]string, 0, len(addresses))
	seen := map[string]bool{}
	for _, ip := range addresses {
		if ip == nil || ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsUnspecified() || ip.IsMulticast() {
			continue
		}
		value := ip.String()
		if !seen[value] {
			seen[value] = true
			ips = append(ips, value)
		}
	}
	if len(ips) == 0 {
		return nil, errors.New("the public hostname resolved only to loopback or reserved addresses")
	}
	sort.Strings(ips)
	return ips, nil
}

func probeGameEndpoint(ctx context.Context, host string, port int, gs rune.Rune) error {
	if gs.Query != nil {
		switch gs.Query.Type {
		case "minecraft", "minecraft-java":
			_, err := gameproto.Minecraft(ctx, host, port)
			return err
		case "minecraft-bedrock":
			_, err := gameproto.Bedrock(ctx, host, port)
			return err
		case "a2s", "source":
			_, err := gameproto.A2S(ctx, host, port)
			return err
		default:
			return errors.New("template uses an unsupported query protocol")
		}
	}
	conn, err := (&net.Dialer{}).DialContext(ctx, "tcp", net.JoinHostPort(host, strconv.Itoa(port)))
	if err != nil {
		return err
	}
	return conn.Close()
}
