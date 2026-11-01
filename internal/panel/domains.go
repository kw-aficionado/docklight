package panel

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

const domainProbeTimeout = 6 * time.Second

type domainProbeCacheEntry struct {
	result    domainProbeResult
	expiresAt time.Time
}

type domainProbeResult struct {
	Reachable  bool   `json:"reachable"`
	URL        string `json:"url,omitempty"`
	StatusCode int    `json:"status_code,omitempty"`
	SelfSigned bool   `json:"self_signed,omitempty"`
	Warning    string `json:"warning,omitempty"`
	Error      string `json:"error,omitempty"`
	CheckedAt  string `json:"checked_at,omitempty"`
}

type domainRow struct {
	ServerID        string            `json:"server_id"`
	ServerName      string            `json:"server_name"`
	RouteID         string            `json:"route_id,omitempty"`
	PortName        string            `json:"port_name,omitempty"`
	DeletePending   bool              `json:"delete_pending,omitempty"`
	Provider        string            `json:"provider"`
	Hostname        string            `json:"hostname"`
	ProviderEnabled bool              `json:"provider_enabled"`
	Provisioned     bool              `json:"provisioned"`
	ErrorCode       string            `json:"error_code,omitempty"`
	LastError       string            `json:"last_error,omitempty"`
	Probe           domainProbeResult `json:"probe"`
}

type domainProbeTask struct {
	index    int
	hostname string
}

func (a *App) listDomains(w http.ResponseWriter, r *http.Request) {
	u := principal(r)
	cfConfig, err := a.readCloudflareConfig()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not read Cloudflare settings")
		return
	}
	npmConfig, err := a.readNPMConfig()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not read Nginx Proxy Manager settings")
		return
	}
	rows, err := a.db.QueryContext(r.Context(), `SELECT id FROM servers ORDER BY name,id`)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not list server domains")
		return
	}
	var serverIDs []string
	for rows.Next() {
		var id string
		if err = rows.Scan(&id); err != nil {
			_ = rows.Close()
			writeError(w, http.StatusInternalServerError, "could not read server list")
			return
		}
		serverIDs = append(serverIDs, id)
	}
	if err = rows.Err(); err != nil {
		_ = rows.Close()
		writeError(w, http.StatusInternalServerError, "could not read server list")
		return
	}
	_ = rows.Close()
	var domains []domainRow
	for _, id := range serverIDs {
		server, getErr := a.getServer(id)
		if getErr != nil || !a.allowedServer(u, "server.view", server.ID, server.GameskillID, server.RealmID) {
			continue
		}
		var cfValue, npmValue string
		if err = a.db.QueryRowContext(r.Context(), `SELECT cf_hostname,npm_subdomain FROM servers WHERE id=?`, id).Scan(&cfValue, &npmValue); err != nil {
			writeError(w, http.StatusInternalServerError, "could not read server hostname settings")
			return
		}
		if hostname, hostErr := cloudflareHostname(cfValue, cfConfig.BaseDomain); hostErr == nil && hostname != "" {
			state, stateErr := a.readServerCloudflareState(r.Context(), id)
			if stateErr != nil {
				writeError(w, http.StatusInternalServerError, "could not read Cloudflare route state")
				return
			}
			row := domainRow{ServerID: id, ServerName: server.Name, Provider: "cloudflare", Hostname: hostname, ProviderEnabled: cfConfig.Enabled && cfConfig.configured(), Provisioned: state.Hostname == hostname && !state.CleanupPending, LastError: state.LastError}
			row.ErrorCode = domainErrorCode(row.Provider, row.LastError)
			domains = append(domains, row)
		}
		if hostname, hostErr := npmHostname(npmValue, npmConfig.BaseDomain); hostErr == nil && hostname != "" {
			state, stateErr := a.readServerNPMState(r.Context(), id)
			if stateErr != nil {
				writeError(w, http.StatusInternalServerError, "could not read Nginx Proxy Manager host state")
				return
			}
			row := domainRow{ServerID: id, ServerName: server.Name, Provider: "npm", Hostname: hostname, ProviderEnabled: npmConfig.Enabled && npmConfig.configured(), Provisioned: state.HostID != "" && !state.CleanupPending, LastError: state.LastError}
			row.ErrorCode = domainErrorCode(row.Provider, row.LastError)
			domains = append(domains, row)
		}
		routes, routeErr := a.serverRoutes(r.Context(), id)
		if routeErr != nil {
			writeError(w, http.StatusInternalServerError, "could not read additional server hostnames")
			return
		}
		for _, route := range routes {
			cfRow := domainRow{ServerID: id, ServerName: server.Name, RouteID: route.ID, PortName: route.PortName, DeletePending: route.DeletePending, Provider: "cloudflare", Hostname: route.Hostname, ProviderEnabled: cfConfig.Enabled && cfConfig.configured(), Provisioned: route.CFActive, LastError: route.CFLastError}
			cfRow.ErrorCode = domainErrorCode(cfRow.Provider, cfRow.LastError)
			domains = append(domains, cfRow)
			npmRow := domainRow{ServerID: id, ServerName: server.Name, RouteID: route.ID, PortName: route.PortName, DeletePending: route.DeletePending, Provider: "npm", Hostname: route.Hostname, ProviderEnabled: npmConfig.Enabled && npmConfig.configured(), Provisioned: route.NPMActive, LastError: route.NPMLastError}
			npmRow.ErrorCode = domainErrorCode(npmRow.Provider, npmRow.LastError)
			domains = append(domains, npmRow)
		}
	}
	if len(domains) == 0 {
		writeJSON(w, http.StatusOK, []domainRow{})
		return
	}
	tasks := make(chan domainProbeTask)
	var workers sync.WaitGroup
	workerCount := 8
	if len(domains) < workerCount {
		workerCount = len(domains)
	}
	for i := 0; i < workerCount; i++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for task := range tasks {
				domains[task.index].Probe = a.probeDomainCached(r.Context(), task.hostname)
			}
		}()
	}
	for index := range domains {
		tasks <- domainProbeTask{index: index, hostname: domains[index].Hostname}
	}
	close(tasks)
	workers.Wait()
	writeJSON(w, http.StatusOK, domains)
}

func domainErrorCode(provider, message string) string {
	if provider == "cloudflare" {
		lower := strings.ToLower(message)
		if strings.Contains(lower, "different cloudflare tunnel") || strings.Contains(lower, "dns conflict") || strings.Contains(lower, "multiple cname") || strings.Contains(lower, "already has an ingress rule") || strings.Contains(lower, "already assigned through cloudflare") || strings.Contains(lower, "does not own") {
			return "cf_conflict"
		}
		if strings.Contains(lower, "no published tcp") || strings.Contains(lower, "internal host") || strings.Contains(lower, "internal ip") {
			return "cf_target"
		}
	}
	if strings.TrimSpace(message) != "" {
		return "provider_error"
	}
	return ""
}

func (a *App) probeDomainCached(ctx context.Context, hostname string) domainProbeResult {
	now := time.Now()
	a.domainProbeMu.Lock()
	if cached, ok := a.domainProbeCache[hostname]; ok && now.Before(cached.expiresAt) {
		a.domainProbeMu.Unlock()
		return cached.result
	}
	a.domainProbeMu.Unlock()
	probeCtx, cancel := context.WithTimeout(ctx, domainProbeTimeout)
	defer cancel()
	result := probePublicDomain(probeCtx, hostname)
	a.domainProbeMu.Lock()
	if a.domainProbeCache == nil {
		a.domainProbeCache = make(map[string]domainProbeCacheEntry)
	}
	a.domainProbeCache[hostname] = domainProbeCacheEntry{result: result, expiresAt: now.Add(30 * time.Second)}
	for key, entry := range a.domainProbeCache {
		if now.After(entry.expiresAt) {
			delete(a.domainProbeCache, key)
		}
	}
	a.domainProbeMu.Unlock()
	return result
}

func probePublicDomain(ctx context.Context, hostname string) domainProbeResult {
	result := domainProbeResult{CheckedAt: time.Now().UTC().Format(time.RFC3339)}
	name, err := normalizeCloudflareDomain(hostname, false)
	if err != nil {
		result.Error = "invalid hostname"
		return result
	}
	response, probeErr := probeDomainURL(ctx, name, "https", false)
	if probeErr == nil {
		return domainResponse(response, "https", false, "")
	}
	var unknownAuthority x509.UnknownAuthorityError
	if errors.As(probeErr, &unknownAuthority) {
		response, retryErr := probeDomainURL(ctx, name, "https", true)
		if retryErr == nil {
			return domainResponse(response, "https", true, "HTTPS certificate is not trusted; the response was checked with certificate validation disabled.")
		}
	}
	if ctx.Err() != nil {
		result.Error = "domain check timed out"
		return result
	}
	response, httpErr := probeDomainURL(ctx, name, "http", false)
	if httpErr == nil {
		return domainResponse(response, "http", false, "HTTPS did not complete; HTTP responded instead.")
	}
	if ctx.Err() != nil {
		result.Error = "domain check timed out"
	} else {
		result.Error = safeProbeError(httpErr)
		if result.Error == "" {
			result.Error = safeProbeError(probeErr)
		}
	}
	return result
}

func domainResponse(response *http.Response, scheme string, selfSigned bool, warning string) domainProbeResult {
	if response.Body != nil {
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 64*1024))
		_ = response.Body.Close()
	}
	result := domainProbeResult{Reachable: true, URL: scheme + "://" + response.Request.URL.Host, StatusCode: response.StatusCode, SelfSigned: selfSigned, Warning: warning, CheckedAt: time.Now().UTC().Format(time.RFC3339)}
	if response.StatusCode >= 500 {
		result.Warning = strings.TrimSpace(strings.Join([]string{warning, fmt.Sprintf("Server returned HTTP %d.", response.StatusCode)}, " "))
	}
	if response.StatusCode >= 300 && response.StatusCode < 400 {
		result.Warning = strings.TrimSpace(strings.Join([]string{warning, "Redirects are not followed."}, " "))
	}
	return result
}

func probeDomainURL(ctx context.Context, hostname, scheme string, insecureTLS bool) (*http.Response, error) {
	port := "443"
	if scheme == "http" {
		port = "80"
	}
	transport := &http.Transport{Proxy: nil, DialContext: guardedPublicDialer{}.DialContext}
	if insecureTLS {
		transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true} // Retried only after the standard verifier reports an unknown certificate authority.
	}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }}
	u := url.URL{Scheme: scheme, Host: net.JoinHostPort(hostname, port), Path: "/"}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, err
	}
	request.Header.Set("User-Agent", "Docklight-domain-check/1.0")
	response, err := client.Do(request)
	if err != nil {
		return nil, err
	}
	return response, nil
}

type guardedPublicDialer struct{}

func (guardedPublicDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, errors.New("invalid domain target")
	}
	var ips []net.IP
	if literal := net.ParseIP(strings.Trim(host, "[]")); literal != nil {
		ips = []net.IP{literal}
	} else {
		addresses, resolveErr := net.DefaultResolver.LookupIPAddr(ctx, host)
		if resolveErr != nil {
			return nil, errors.New("domain did not resolve")
		}
		for _, candidate := range addresses {
			ips = append(ips, candidate.IP)
		}
	}
	if len(ips) == 0 {
		return nil, errors.New("domain did not resolve")
	}
	for _, ip := range ips {
		if !isPublicProbeIP(ip) {
			return nil, errors.New("domain resolves to a private, local, or reserved address")
		}
	}
	dialer := net.Dialer{Timeout: 4 * time.Second, KeepAlive: 15 * time.Second}
	var failures []error
	for _, ip := range ips {
		connection, dialErr := dialer.DialContext(ctx, network, net.JoinHostPort(ip.String(), port))
		if dialErr == nil {
			return connection, nil
		}
		failures = append(failures, dialErr)
	}
	if len(failures) == 0 {
		return nil, errors.New("domain connection failed")
	}
	return nil, errors.Join(failures...)
}

func isPublicProbeIP(ip net.IP) bool {
	if ip == nil || ip.IsUnspecified() || ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsMulticast() || ip.IsPrivate() || !ip.IsGlobalUnicast() {
		return false
	}
	if v4 := ip.To4(); v4 != nil {
		blocked := []string{"0.0.0.0/8", "100.64.0.0/10", "192.0.0.0/24", "192.0.2.0/24", "192.88.99.0/24", "198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24", "224.0.0.0/4", "240.0.0.0/4"}
		for _, prefix := range blocked {
			_, network, _ := net.ParseCIDR(prefix)
			if network.Contains(v4) {
				return false
			}
		}
		return true
	}
	blocked := []string{"64:ff9b::/96", "64:ff9b:1::/48", "100::/64", "2001::/23", "2001:db8::/32", "2002::/16"}
	for _, prefix := range blocked {
		_, network, _ := net.ParseCIDR(prefix)
		if network.Contains(ip) {
			return false
		}
	}
	return true
}

func safeProbeError(err error) string {
	if err == nil {
		return ""
	}
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) {
		return "DNS lookup failed"
	}
	if strings.Contains(strings.ToLower(err.Error()), "private, local, or reserved") {
		return "domain resolves to a private, local, or reserved address"
	}
	if strings.Contains(strings.ToLower(err.Error()), "certificate") || strings.Contains(strings.ToLower(err.Error()), "tls") {
		return "HTTPS certificate check failed"
	}
	var opErr *net.OpError
	if errors.As(err, &opErr) {
		return "domain connection failed"
	}
	return "domain could not be reached"
}
