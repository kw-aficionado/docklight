package panel

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/netip"
	"sort"
	"strings"
	"time"

	cfapi "example.com/yggdrasil-panel/internal/cloudflare"
	"example.com/yggdrasil-panel/internal/firewall"
	"github.com/go-chi/chi/v5"
)

const (
	blockReconcileEvery = time.Minute
	blockRequestTimeout = 20 * time.Second
)

var (
	protectedBlockPrefixes = parseBlockPrefixes([]string{
		"173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22",
		"141.101.64.0/18", "108.162.192.0/18", "190.93.240.0/20", "188.114.96.0/20",
		"197.234.240.0/22", "198.41.128.0/17", "162.158.0.0/15", "104.16.0.0/13",
		"104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22",
		"2400:cb00::/32", "2606:4700::/32", "2803:f800::/32", "2405:b500::/32",
		"2405:8100::/32", "2a06:98c0::/29", "2c0f:f248::/32",
		"100.64.0.0/10", "192.0.0.0/24", "192.0.2.0/24", "192.88.99.0/24",
		"198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24", "240.0.0.0/4",
		"::/96", "100::/64", "100:0:0:1::/64", "2001::/23", "2001:db8::/32", "2002::/16",
		"3fff::/20", "5f00::/16", "64:ff9b::/96", "64:ff9b:1::/48", "fec0::/10",
	})
	errCloudflareBlockConflict = errors.New("Cloudflare already has a different IP Access Rule for this address")
)

type blockingSettings struct {
	Enabled    bool     `json:"enabled"`
	Mode       string   `json:"mode"`
	NFTEnabled bool     `json:"nft_enabled"`
	Allowlist  []string `json:"allowlist"`
}

type blockedIPRecord struct {
	ID        string
	IP        string
	Backend   string
	Scope     string
	RuleID    string
	ServerID  string
	Reason    string
	Source    string
	CreatedAt string
	ExpiresAt string
	LastError string
}

type blockedIPResponse struct {
	ID        string `json:"id"`
	IP        string `json:"ip"`
	Backend   string `json:"backend"`
	Scope     string `json:"scope,omitempty"`
	ServerID  string `json:"server_id,omitempty"`
	Reason    string `json:"reason"`
	Source    string `json:"source"`
	CreatedAt string `json:"created_at"`
	ExpiresAt string `json:"expires_at,omitempty"`
	LastError string `json:"last_error,omitempty"`
	Active    bool   `json:"active"`
}

func parseBlockPrefixes(values []string) []netip.Prefix {
	out := make([]netip.Prefix, 0, len(values))
	for _, value := range values {
		out = append(out, netip.MustParsePrefix(value))
	}
	return out
}

func (a *App) recordRecentAdminIP(r *http.Request) {
	address, err := netip.ParseAddr(strings.TrimSpace(clientIP(r)))
	if err != nil {
		return
	}
	_, err = a.db.ExecContext(r.Context(), `INSERT INTO admin_ip_history(ip,last_seen) VALUES(?,CURRENT_TIMESTAMP)
		ON CONFLICT(ip) DO UPDATE SET last_seen=CURRENT_TIMESTAMP`, address.Unmap().String())
	if err != nil {
		log.Printf("could not record recent administrator address")
		return
	}
	_, _ = a.db.ExecContext(r.Context(), `DELETE FROM admin_ip_history WHERE last_seen < datetime('now','-30 days')`)
}

func (a *App) readBlockingSettings(ctx context.Context) (blockingSettings, error) {
	var enabled, nftEnabled int
	var rawAllowlist string
	var settings blockingSettings
	err := a.db.QueryRowContext(ctx, `SELECT enabled,mode,nft_enabled,allowlist FROM blocking_settings WHERE id=1`).Scan(&enabled, &settings.Mode, &nftEnabled, &rawAllowlist)
	if err != nil {
		return settings, err
	}
	settings.Allowlist, _, err = parseBlockingAllowlist(rawAllowlist)
	settings.Enabled = enabled != 0
	settings.NFTEnabled = nftEnabled != 0
	return settings, err
}

func (a *App) getBlockingSettings(w http.ResponseWriter, r *http.Request) {
	settings, err := a.readBlockingSettings(r.Context())
	if err != nil {
		writeError(w, 500, "could not read IP blocking settings")
		return
	}
	probeCtx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
	available, message := firewall.Available(probeCtx)
	cancel()
	var cloudflareBlocks, nftBlocks int
	_ = a.db.QueryRowContext(r.Context(), `SELECT count(*) FROM blocked_ips WHERE backend='cloudflare'`).Scan(&cloudflareBlocks)
	_ = a.db.QueryRowContext(r.Context(), `SELECT count(*) FROM blocked_ips WHERE backend='nftables'`).Scan(&nftBlocks)
	writeJSON(w, 200, map[string]any{
		"enabled": settings.Enabled, "mode": settings.Mode, "nft_enabled": settings.NFTEnabled,
		"allowlist":     settings.Allowlist,
		"nft_available": available, "nft_message": message,
		"cloudflare_blocks": cloudflareBlocks, "nft_blocks": nftBlocks,
		"protected_ranges": "private, local, Cloudflare, CGNAT/Tailscale, documentation, benchmark and reserved addresses, configured allowlist, and recent administrator addresses",
	})
}

func (a *App) updateBlockingSettings(w http.ResponseWriter, r *http.Request) {
	var in blockingSettings
	if decodeJSON(w, r, &in, 24*1024) != nil {
		return
	}
	in.Mode = strings.ToLower(strings.TrimSpace(in.Mode))
	if in.Mode != "off" && in.Mode != "propose" && in.Mode != "auto" {
		writeError(w, 400, "mode must be off, propose, or auto")
		return
	}
	allowlist, allowlistPrefixes, err := normalizeBlockingAllowlist(in.Allowlist)
	if err != nil {
		writeError(w, 400, err.Error())
		return
	}
	in.Allowlist = allowlist
	allowlistJSON, err := json.Marshal(in.Allowlist)
	if err != nil {
		writeError(w, 400, "could not encode the address allowlist")
		return
	}
	a.blockingMu.Lock()
	defer a.blockingMu.Unlock()
	current, err := a.readBlockingSettings(r.Context())
	if err != nil {
		writeError(w, 500, "could not read current IP blocking settings")
		return
	}
	if len(allowlistPrefixes) != 0 {
		rows, queryErr := a.db.QueryContext(r.Context(), `SELECT ip FROM blocked_ips`)
		if queryErr != nil {
			writeError(w, 500, "could not check saved IP blocks against the allowlist")
			return
		}
		var conflicts []string
		for rows.Next() {
			var raw string
			if queryErr = rows.Scan(&raw); queryErr != nil {
				_ = rows.Close()
				writeError(w, 500, "could not read saved IP blocks against the allowlist")
				return
			}
			address, parseErr := netip.ParseAddr(raw)
			if parseErr != nil {
				_ = rows.Close()
				writeError(w, 500, "saved IP block has an invalid address; allowlist was not changed")
				return
			}
			for _, prefix := range allowlistPrefixes {
				if prefix.Contains(address.Unmap()) {
					conflicts = append(conflicts, address.String())
					break
				}
			}
		}
		if queryErr = rows.Err(); queryErr != nil {
			_ = rows.Close()
			writeError(w, 500, "could not read saved IP blocks against the allowlist")
			return
		}
		_ = rows.Close()
		if len(conflicts) != 0 {
			writeError(w, 409, "remove the existing block for "+strings.Join(conflicts, ", ")+" before adding that address to the allowlist")
			return
		}
	}
	removeAll := current.Enabled && !in.Enabled
	removeNFT := current.NFTEnabled && !in.NFTEnabled && !removeAll
	if removeAll || removeNFT {
		if err = a.cleanupBlockingRecordsLocked(r.Context(), func(row blockedIPRecord) bool {
			return removeAll || row.Backend == "nftables"
		}); err != nil {
			writeError(w, 409, "Docklight could not safely remove every affected IP block; settings were not changed: "+err.Error())
			return
		}
	}
	if _, err = a.db.ExecContext(r.Context(), `UPDATE blocking_settings SET enabled=?,mode=?,nft_enabled=?,allowlist=?,updated_at=CURRENT_TIMESTAMP WHERE id=1`, boolInt(in.Enabled), in.Mode, boolInt(in.NFTEnabled), string(allowlistJSON)); err != nil {
		writeError(w, 500, "could not save IP blocking settings")
		return
	}
	a.audit(principal(r), "blocking.settings", "network", "blocking", fmt.Sprintf("enabled=%t mode=%s nft_enabled=%t", in.Enabled, in.Mode, in.NFTEnabled))
	writeJSON(w, 200, in)
}

func (a *App) listBlockedIPs(w http.ResponseWriter, r *http.Request) {
	settings, err := a.readBlockingSettings(r.Context())
	if err != nil {
		writeError(w, 500, "could not read IP blocking settings")
		return
	}
	rows, err := a.db.QueryContext(r.Context(), `SELECT id,ip,backend,scope,cf_rule_id,server_id,reason,source,created_at,expires_at,last_error FROM blocked_ips ORDER BY created_at DESC,id`)
	if err != nil {
		writeError(w, 500, "could not list blocked IP addresses")
		return
	}
	defer rows.Close()
	out := make([]blockedIPResponse, 0)
	for rows.Next() {
		var row blockedIPRecord
		if err = rows.Scan(&row.ID, &row.IP, &row.Backend, &row.Scope, &row.RuleID, &row.ServerID, &row.Reason, &row.Source, &row.CreatedAt, &row.ExpiresAt, &row.LastError); err != nil {
			writeError(w, 500, "could not read blocked IP addresses")
			return
		}
		active := settings.Enabled && row.LastError == ""
		if row.Backend == "nftables" && !settings.NFTEnabled {
			active = false
		}
		if row.Backend == "cloudflare" && row.RuleID == "" {
			active = false
		}
		out = append(out, blockedIPResponse{ID: row.ID, IP: row.IP, Backend: row.Backend, Scope: row.Scope, ServerID: row.ServerID, Reason: row.Reason, Source: row.Source, CreatedAt: row.CreatedAt, ExpiresAt: row.ExpiresAt, LastError: row.LastError, Active: active})
	}
	if err = rows.Err(); err != nil {
		writeError(w, 500, "could not read blocked IP addresses")
		return
	}
	writeJSON(w, 200, out)
}

func (a *App) createBlockedIP(w http.ResponseWriter, r *http.Request) {
	var in struct {
		IP             string `json:"ip"`
		Reason         string `json:"reason"`
		ExpiresInHours int    `json:"expires_in_hours"`
	}
	if decodeJSON(w, r, &in, 8*1024) != nil {
		return
	}
	address, err := normalizeBlockAddress(in.IP)
	if err != nil {
		writeError(w, 400, err.Error())
		return
	}
	reason := cleanBlockReason(in.Reason)
	if len(reason) > 240 {
		writeError(w, 400, "reason must be 240 characters or fewer")
		return
	}
	if in.ExpiresInHours != 0 && (in.ExpiresInHours < 1 || in.ExpiresInHours > 24*365) {
		writeError(w, 400, "expiry must be 0 for no expiry, or between 1 and 8760 hours")
		return
	}
	expiresAt := ""
	if in.ExpiresInHours > 0 {
		expiresAt = time.Now().UTC().Add(time.Duration(in.ExpiresInHours) * time.Hour).Format(time.RFC3339)
	}
	a.blockingMu.Lock()
	defer a.blockingMu.Unlock()
	settings, err := a.readBlockingSettings(r.Context())
	if err != nil {
		writeError(w, 500, "could not read IP blocking settings")
		return
	}
	if !settings.Enabled {
		writeError(w, 409, "IP blocking is off; enable it in the IP blocking page before adding a rule")
		return
	}
	if err = a.protectBlockAddress(r.Context(), address, clientIP(r)); err != nil {
		writeError(w, 400, err.Error())
		return
	}
	var existing string
	err = a.db.QueryRowContext(r.Context(), `SELECT id FROM blocked_ips WHERE ip=? LIMIT 1`, address.String()).Scan(&existing)
	if err == nil {
		writeError(w, 409, "this IP address already has a Docklight block; remove the existing rule before adding it again")
		return
	}
	if !errors.Is(err, sql.ErrNoRows) {
		writeError(w, 500, "could not check existing IP blocks")
		return
	}
	id, err := newID()
	if err != nil {
		writeError(w, 500, "could not create IP block identity")
		return
	}
	row := blockedIPRecord{ID: id, IP: address.String(), Reason: reason, Source: "manual", CreatedAt: time.Now().UTC().Format(time.RFC3339), ExpiresAt: expiresAt}
	cfg, configErr := a.readCloudflareConfig()
	var zoneID string
	var cfClient *cfapi.Client
	var zoneErr error
	if configErr == nil && cfg.APIToken != "" && cfg.AccountID != "" && cfg.BaseDomain != "" {
		cfClient = a.cloudflareClient(cfg)
		zoneID, zoneErr = a.resolveCloudflareZone(r.Context(), cfClient, cfg)
	}
	if zoneErr == nil && zoneID != "" && cfClient != nil {
		row.Backend, row.Scope = "cloudflare", zoneID
		row.LastError = "Cloudflare rule is pending reconciliation"
		if err = a.insertBlockedIP(r.Context(), row); err != nil {
			writeError(w, 409, "this IP address already has a Docklight block, or its record could not be saved")
			return
		}
		if err = a.ensureCloudflareBlock(r.Context(), row, cfClient); err == nil {
			a.audit(principal(r), "ip_block.create", "ip", row.IP, "backend=cloudflare reason="+reason)
			saved, _ := a.readBlockedIP(r.Context(), id)
			writeJSON(w, 201, blockedIPToResponse(saved, settings))
			return
		}
		if cloudflareBlockFailureUncertain(err) {
			_ = a.setBlockedIPError(r.Context(), id, err.Error())
			a.audit(principal(r), "ip_block.pending", "ip", row.IP, "backend=cloudflare reason="+reason)
			row.LastError = err.Error()
			writeJSON(w, 202, blockedIPToResponse(row, settings))
			return
		}
		if !settings.NFTEnabled {
			_ = a.deleteBlockedIPRow(r.Context(), id)
			writeError(w, 502, "Cloudflare IP Access Rules could not be used: "+err.Error()+". Grant this token Zone → Firewall Services → Edit permission, or enable nftables fallback and grant the Docklight service CAP_NET_ADMIN.")
			return
		}
		row.Backend, row.Scope, row.LastError = "nftables", "", ""
		if err = a.convertBlockedIPBackend(r.Context(), row); err != nil {
			writeError(w, 500, "could not switch the IP block to host nftables")
			return
		}
		if err = a.syncNftablesFromDB(r.Context()); err != nil {
			_ = a.deleteBlockedIPRow(r.Context(), id)
			_ = a.syncNftablesFromDB(r.Context())
			writeError(w, 502, err.Error())
			return
		}
		a.audit(principal(r), "ip_block.create", "ip", row.IP, "backend=nftables reason="+reason)
		saved, _ := a.readBlockedIP(r.Context(), id)
		writeJSON(w, 201, blockedIPToResponse(saved, settings))
		return
	}
	if configErr != nil {
		zoneErr = configErr
	}
	if !settings.NFTEnabled {
		if zoneErr != nil {
			writeError(w, 502, "Cloudflare zone could not be resolved: "+zoneErr.Error()+". Set a valid Cloudflare base domain and zone, or enable nftables fallback with CAP_NET_ADMIN.")
		} else {
			writeError(w, 409, "no Cloudflare zone is configured; configure Cloudflare IP Access Rules or enable nftables fallback with CAP_NET_ADMIN")
		}
		return
	}
	row.Backend = "nftables"
	if err = a.insertBlockedIP(r.Context(), row); err != nil {
		writeError(w, 409, "this IP address already has a Docklight block, or its record could not be saved")
		return
	}
	if err = a.syncNftablesFromDB(r.Context()); err != nil {
		_ = a.deleteBlockedIPRow(r.Context(), id)
		_ = a.syncNftablesFromDB(r.Context())
		writeError(w, 502, err.Error())
		return
	}
	a.audit(principal(r), "ip_block.create", "ip", row.IP, "backend=nftables reason="+reason)
	saved, _ := a.readBlockedIP(r.Context(), id)
	writeJSON(w, 201, blockedIPToResponse(saved, settings))
}

func (a *App) deleteBlockedIP(w http.ResponseWriter, r *http.Request) {
	a.blockingMu.Lock()
	defer a.blockingMu.Unlock()
	id := chi.URLParam(r, "id")
	row, err := a.readBlockedIP(r.Context(), id)
	if err != nil {
		writeError(w, 404, "IP block not found")
		return
	}
	if err = a.removeBlockedIPExternal(r.Context(), row); err != nil {
		writeError(w, 409, "Docklight could not safely remove this IP rule: "+err.Error())
		return
	}
	if err = a.deleteBlockedIPRow(r.Context(), id); err != nil {
		writeError(w, 500, "external rule was removed, but Docklight could not update its saved record; reconciliation will retry")
		return
	}
	a.audit(principal(r), "ip_block.delete", "ip", row.IP, "backend="+row.Backend+" reason="+row.Reason)
	writeJSON(w, 200, map[string]any{"ok": true})
}

func (a *App) insertBlockedIP(ctx context.Context, row blockedIPRecord) error {
	_, err := a.db.ExecContext(ctx, `INSERT INTO blocked_ips(id,ip,backend,scope,cf_rule_id,server_id,reason,source,created_at,expires_at,last_error) VALUES(?,?,?,?,?,?,?,?,?,?,?)`, row.ID, row.IP, row.Backend, row.Scope, row.RuleID, row.ServerID, row.Reason, row.Source, row.CreatedAt, row.ExpiresAt, row.LastError)
	return err
}

func (a *App) readBlockedIP(ctx context.Context, id string) (blockedIPRecord, error) {
	var row blockedIPRecord
	err := a.db.QueryRowContext(ctx, `SELECT id,ip,backend,scope,cf_rule_id,server_id,reason,source,created_at,expires_at,last_error FROM blocked_ips WHERE id=?`, id).Scan(&row.ID, &row.IP, &row.Backend, &row.Scope, &row.RuleID, &row.ServerID, &row.Reason, &row.Source, &row.CreatedAt, &row.ExpiresAt, &row.LastError)
	return row, err
}

func (a *App) deleteBlockedIPRow(ctx context.Context, id string) error {
	_, err := a.db.ExecContext(ctx, `DELETE FROM blocked_ips WHERE id=?`, id)
	return err
}

func (a *App) setBlockedIPError(ctx context.Context, id, message string) error {
	_, err := a.db.ExecContext(ctx, `UPDATE blocked_ips SET last_error=? WHERE id=?`, message, id)
	return err
}

func (a *App) convertBlockedIPBackend(ctx context.Context, row blockedIPRecord) error {
	_, err := a.db.ExecContext(ctx, `UPDATE blocked_ips SET backend=?,scope='',cf_rule_id='',last_error='' WHERE id=?`, row.Backend, row.ID)
	return err
}

func (a *App) protectBlockAddress(ctx context.Context, address netip.Addr, currentPeer string) error {
	if !address.IsValid() || !address.IsGlobalUnicast() || address.IsPrivate() || address.IsLoopback() || address.IsLinkLocalUnicast() || address.IsLinkLocalMulticast() || address.IsMulticast() || address.IsUnspecified() {
		return errors.New("private, local, link-local, multicast, and non-public IP addresses cannot be blocked")
	}
	for _, prefix := range protectedBlockPrefixes {
		if prefix.Contains(address) {
			return errors.New("Cloudflare, CGNAT/Tailscale, documentation, benchmarking, and reserved IP ranges are protected")
		}
	}
	settings, err := a.readBlockingSettings(ctx)
	if err != nil {
		return errors.New("the blocking allowlist could not be checked; no IP rule was created")
	}
	_, allowlistPrefixes, err := normalizeBlockingAllowlist(settings.Allowlist)
	if err != nil {
		return errors.New("the blocking allowlist is invalid; no IP rule was created")
	}
	for _, prefix := range allowlistPrefixes {
		if prefix.Contains(address) {
			return fmt.Errorf("%s is protected by the administrator-defined IP allowlist", address)
		}
	}
	if peer, parseErr := netip.ParseAddr(strings.TrimSpace(currentPeer)); parseErr == nil && peer.Unmap() == address.Unmap() {
		return errors.New("this is the address connected to the current administrator session and cannot be blocked")
	}
	rows, err := a.db.QueryContext(ctx, `SELECT ip FROM admin_ip_history WHERE last_seen >= datetime('now','-30 days')`)
	if err != nil {
		return errors.New("recent administrator addresses could not be checked; no IP rule was created")
	}
	defer rows.Close()
	for rows.Next() {
		var saved string
		if err = rows.Scan(&saved); err != nil {
			return errors.New("recent administrator addresses could not be checked; no IP rule was created")
		}
		adminAddress, parseErr := netip.ParseAddr(saved)
		if parseErr == nil && adminAddress.Unmap() == address.Unmap() {
			return errors.New("this address was used by an administrator in the last 30 days and cannot be blocked")
		}
	}
	if err = rows.Err(); err != nil {
		return errors.New("recent administrator addresses could not be checked; no IP rule was created")
	}
	return nil
}

func normalizeBlockingAllowlist(values []string) ([]string, []netip.Prefix, error) {
	if len(values) > 256 {
		return nil, nil, errors.New("the IP allowlist can contain at most 256 addresses or ranges")
	}
	seen := make(map[string]struct{}, len(values))
	normalized := make([]string, 0, len(values))
	prefixes := make([]netip.Prefix, 0, len(values))
	for _, raw := range values {
		value := strings.TrimSpace(raw)
		if value == "" {
			continue
		}
		if len(value) > 64 {
			return nil, nil, errors.New("each allowlist entry must be 64 characters or fewer")
		}
		prefix, err := netip.ParsePrefix(value)
		if err != nil {
			address, addrErr := netip.ParseAddr(value)
			if addrErr != nil {
				return nil, nil, fmt.Errorf("invalid allowlist entry %q; use an IP address or CIDR range", value)
			}
			if address.Zone() != "" {
				return nil, nil, errors.New("IPv6 zone identifiers are not valid in the allowlist")
			}
			address = address.Unmap()
			prefix = netip.PrefixFrom(address, address.BitLen())
		} else {
			if prefix.Addr().Zone() != "" {
				return nil, nil, errors.New("IPv6 zone identifiers are not valid in the allowlist")
			}
			if prefix.Addr().Is4In6() {
				if prefix.Bits() < 96 {
					return nil, nil, errors.New("IPv4-mapped IPv6 allowlist ranges must be within the mapped IPv4 prefix")
				}
				prefix = netip.PrefixFrom(prefix.Addr().Unmap(), prefix.Bits()-96)
			}
			prefix = prefix.Masked()
		}
		canonical := prefix.String()
		if _, ok := seen[canonical]; ok {
			continue
		}
		seen[canonical] = struct{}{}
		normalized = append(normalized, canonical)
		prefixes = append(prefixes, prefix)
	}
	sort.Strings(normalized)
	return normalized, prefixes, nil
}

func parseBlockingAllowlist(raw string) ([]string, []netip.Prefix, error) {
	var values []string
	if err := json.Unmarshal([]byte(raw), &values); err != nil {
		return nil, nil, errors.New("saved IP allowlist is invalid")
	}
	return normalizeBlockingAllowlist(values)
}

func normalizeBlockAddress(raw string) (netip.Addr, error) {
	address, err := netip.ParseAddr(strings.TrimSpace(raw))
	if err != nil {
		return netip.Addr{}, errors.New("enter one IPv4 or IPv6 address; CIDR ranges are not accepted")
	}
	return address.Unmap(), nil
}

func cleanBlockReason(raw string) string {
	clean := strings.Map(func(r rune) rune {
		if r < 32 || r == 127 {
			return ' '
		}
		return r
	}, raw)
	return strings.Join(strings.Fields(clean), " ")
}

func blockedIPToResponse(row blockedIPRecord, settings blockingSettings) blockedIPResponse {
	active := settings.Enabled && row.LastError == ""
	if row.Backend == "nftables" && !settings.NFTEnabled {
		active = false
	}
	if row.Backend == "cloudflare" && row.RuleID == "" {
		active = false
	}
	return blockedIPResponse{ID: row.ID, IP: row.IP, Backend: row.Backend, Scope: row.Scope, ServerID: row.ServerID, Reason: row.Reason, Source: row.Source, CreatedAt: row.CreatedAt, ExpiresAt: row.ExpiresAt, LastError: row.LastError, Active: active}
}

func (a *App) blockCloudflareZone(ctx context.Context) (*cfapi.Client, string, error) {
	cfg, err := a.readCloudflareConfig()
	if err != nil {
		return nil, "", err
	}
	if cfg.APIToken == "" || cfg.AccountID == "" || cfg.BaseDomain == "" {
		return nil, "", nil
	}
	client := a.cloudflareClient(cfg)
	zoneID, err := a.resolveCloudflareZone(ctx, client, cfg)
	return client, zoneID, err
}

func (a *App) blockCloudflareClient() (*cfapi.Client, error) {
	cfg, err := a.readCloudflareConfig()
	if err != nil {
		return nil, err
	}
	if cfg.APIToken == "" {
		return nil, errors.New("Cloudflare API token is not configured")
	}
	return a.cloudflareClient(cfg), nil
}

func (a *App) ensureCloudflareBlock(ctx context.Context, row blockedIPRecord, client *cfapi.Client) error {
	rules, err := client.ListIPAccessRules(ctx, row.Scope)
	if err != nil {
		return fmt.Errorf("list Cloudflare IP Access Rules for zone %s: %w", row.Scope, err)
	}
	return a.ensureCloudflareBlockWithRules(ctx, row, client, rules)
}

func (a *App) ensureCloudflareBlockWithRules(ctx context.Context, row blockedIPRecord, client *cfapi.Client, rules []cfapi.IPAccessRule) error {
	marker := cloudflareBlockMarker(row.ID)
	var owned *cfapi.IPAccessRule
	for i := range rules {
		rule := rules[i]
		if noteHasMarker(rule.Notes, marker) {
			if !cloudflareRuleMatchesIP(rule, row.IP) || !strings.EqualFold(rule.Mode, "block") {
				return errors.New("the saved Cloudflare IP Access Rule was changed outside Docklight; review it before retrying")
			}
			if owned != nil {
				return errors.New("Cloudflare returned duplicate Docklight IP Access Rules; remove the duplicate before retrying")
			}
			owned = &rules[i]
			continue
		}
		if cloudflareRuleMatchesIP(rule, row.IP) {
			return fmt.Errorf("%w (%s); Docklight will not claim or remove it", errCloudflareBlockConflict, row.IP)
		}
	}
	if owned != nil {
		if err := a.saveCloudflareRuleID(ctx, row.ID, owned.ID); err != nil {
			return fmt.Errorf("Cloudflare rule exists but its ID could not be saved: %w", err)
		}
		return nil
	}
	created, err := client.CreateIPAccessRule(ctx, row.Scope, row.IP, row.Reason, row.ID)
	if err != nil {
		return fmt.Errorf("create Cloudflare IP Access Rule: %w", err)
	}
	if created.ID == "" || !cloudflareRuleMatchesIP(created, row.IP) || !strings.EqualFold(created.Mode, "block") || !noteHasMarker(created.Notes, marker) {
		return errors.New("Cloudflare created a rule but returned unexpected ownership details; reconciliation will inspect it")
	}
	if err = a.saveCloudflareRuleID(ctx, row.ID, created.ID); err != nil {
		return fmt.Errorf("Cloudflare rule was created but its ID could not be saved: %w", err)
	}
	return nil
}

func (a *App) saveCloudflareRuleID(ctx context.Context, id, ruleID string) error {
	_, err := a.db.ExecContext(ctx, `UPDATE blocked_ips SET cf_rule_id=?,last_error='' WHERE id=?`, ruleID, id)
	return err
}

func cloudflareBlockMarker(id string) string { return "Docklight IP block " + id }

func noteHasMarker(notes, marker string) bool {
	return notes == marker || strings.HasPrefix(notes, marker+":")
}

func cloudflareRuleMatchesIP(rule cfapi.IPAccessRule, rawIP string) bool {
	if !strings.EqualFold(rule.Configuration.Target, "ip") && !strings.EqualFold(rule.Configuration.Target, "ip6") {
		return false
	}
	want, err := netip.ParseAddr(rawIP)
	if err != nil {
		return false
	}
	have, err := netip.ParseAddr(rule.Configuration.Value)
	return err == nil && have.Unmap() == want.Unmap()
}

func cloudflareBlockFailureUncertain(err error) bool {
	if errors.Is(err, errCloudflareBlockConflict) {
		return false
	}
	var apiErr *cfapi.APIError
	if errors.As(err, &apiErr) {
		return apiErr.Status >= 500 || apiErr.Status == 0
	}
	return true
}

func (a *App) removeBlockedIPExternal(ctx context.Context, row blockedIPRecord) error {
	switch row.Backend {
	case "cloudflare":
		cfg, err := a.readCloudflareConfig()
		if err != nil {
			return err
		}
		if cfg.APIToken == "" {
			return errors.New("Cloudflare credentials are missing; restore the token to remove this rule")
		}
		client := a.cloudflareClient(cfg)
		rules, err := client.ListIPAccessRules(ctx, row.Scope)
		if err != nil {
			return fmt.Errorf("verify the saved Cloudflare rule before removal: %w", err)
		}
		marker := cloudflareBlockMarker(row.ID)
		var owned []cfapi.IPAccessRule
		for _, rule := range rules {
			if !noteHasMarker(rule.Notes, marker) {
				continue
			}
			if !cloudflareRuleMatchesIP(rule, row.IP) || !strings.EqualFold(rule.Mode, "block") {
				return errors.New("Cloudflare rule no longer matches Docklight's saved block; it was left untouched")
			}
			owned = append(owned, rule)
		}
		for _, rule := range owned {
			if err = client.DeleteIPAccessRule(ctx, row.Scope, rule.ID); err != nil {
				return fmt.Errorf("delete Docklight Cloudflare IP Access Rule: %w", err)
			}
		}
		return nil
	case "nftables":
		addresses, err := a.nftAddressesExcept(ctx, row.ID)
		if err != nil {
			return err
		}
		return firewall.Reconcile(ctx, addresses)
	default:
		return fmt.Errorf("unknown IP block backend %q", row.Backend)
	}
}

func (a *App) nftAddressesExcept(ctx context.Context, exceptID string) ([]netip.Addr, error) {
	rows, err := a.db.QueryContext(ctx, `SELECT id,ip FROM blocked_ips WHERE backend='nftables' ORDER BY ip,id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var addresses []netip.Addr
	for rows.Next() {
		var id, raw string
		if err = rows.Scan(&id, &raw); err != nil {
			return nil, err
		}
		if id == exceptID {
			continue
		}
		address, parseErr := netip.ParseAddr(raw)
		if parseErr != nil {
			return nil, errors.New("saved nftables block contains an invalid IP address")
		}
		addresses = append(addresses, address.Unmap())
	}
	return addresses, rows.Err()
}

func (a *App) syncNftablesFromDB(ctx context.Context) error {
	addresses, err := a.nftAddressesExcept(ctx, "")
	if err != nil {
		return fmt.Errorf("read saved nftables IP blocks: %w", err)
	}
	return firewall.Reconcile(ctx, addresses)
}

func (a *App) cleanupBlockingRecordsLocked(ctx context.Context, shouldRemove func(blockedIPRecord) bool) error {
	rows, err := a.db.QueryContext(ctx, `SELECT id,ip,backend,scope,cf_rule_id,server_id,reason,source,created_at,expires_at,last_error FROM blocked_ips ORDER BY created_at,id`)
	if err != nil {
		return err
	}
	var records []blockedIPRecord
	for rows.Next() {
		var row blockedIPRecord
		if err = rows.Scan(&row.ID, &row.IP, &row.Backend, &row.Scope, &row.RuleID, &row.ServerID, &row.Reason, &row.Source, &row.CreatedAt, &row.ExpiresAt, &row.LastError); err != nil {
			_ = rows.Close()
			return err
		}
		if shouldRemove(row) {
			records = append(records, row)
		}
	}
	if err = rows.Err(); err != nil {
		_ = rows.Close()
		return err
	}
	_ = rows.Close()
	var failures []error
	for _, row := range records {
		if err = a.removeBlockedIPExternal(ctx, row); err != nil {
			failures = append(failures, fmt.Errorf("%s: %w", row.IP, err))
			continue
		}
		if err = a.deleteBlockedIPRow(ctx, row.ID); err != nil {
			failures = append(failures, fmt.Errorf("%s: external rule removed but database cleanup failed: %w", row.IP, err))
			continue
		}
		a.audit(User{Username: "system"}, "ip_block.cleanup", "ip", row.IP, "backend="+row.Backend+" reason="+row.Reason)
	}
	return errors.Join(failures...)
}

func (a *App) reconcileBlocking(ctx context.Context) error {
	a.blockingMu.Lock()
	defer a.blockingMu.Unlock()
	settings, err := a.readBlockingSettings(ctx)
	if err != nil {
		return err
	}
	if !settings.Enabled {
		return a.cleanupBlockingRecordsLocked(ctx, func(blockedIPRecord) bool { return true })
	}
	rows, err := a.loadBlockedIPRecords(ctx)
	if err != nil {
		return err
	}
	now := time.Now().UTC()
	for _, row := range rows {
		if row.ExpiresAt == "" {
			continue
		}
		expires, parseErr := time.Parse(time.RFC3339, row.ExpiresAt)
		if parseErr != nil {
			_ = a.setBlockedIPError(ctx, row.ID, "saved expiry time is invalid; the rule was left in place")
			continue
		}
		if now.Before(expires) {
			continue
		}
		if err = a.removeBlockedIPExternal(ctx, row); err != nil {
			_ = a.setBlockedIPError(ctx, row.ID, "expiry cleanup failed: "+err.Error())
			continue
		}
		if err = a.deleteBlockedIPRow(ctx, row.ID); err != nil {
			return fmt.Errorf("expired IP rule was removed but its record could not be cleared: %w", err)
		}
		a.audit(User{Username: "system"}, "ip_block.expire", "ip", row.IP, "backend="+row.Backend)
	}
	rows, err = a.loadBlockedIPRecords(ctx)
	if err != nil {
		return err
	}
	byZone := make(map[string][]blockedIPRecord)
	var nftRows []blockedIPRecord
	for _, row := range rows {
		if row.Backend == "cloudflare" {
			byZone[row.Scope] = append(byZone[row.Scope], row)
		} else if row.Backend == "nftables" {
			nftRows = append(nftRows, row)
		}
	}
	var failures []error
	for zoneID, zoneRows := range byZone {
		if err = a.reconcileCloudflareBlockZone(ctx, zoneID, zoneRows); err != nil {
			failures = append(failures, err)
		}
	}
	if settings.NFTEnabled {
		if err = a.syncNftablesFromDB(ctx); err != nil && len(nftRows) != 0 {
			failures = append(failures, err)
		}
	} else if len(nftRows) != 0 {
		failures = append(failures, a.cleanupBlockingRecordsLocked(ctx, func(row blockedIPRecord) bool { return row.Backend == "nftables" }))
	}
	return errors.Join(failures...)
}

func (a *App) loadBlockedIPRecords(ctx context.Context) ([]blockedIPRecord, error) {
	rows, err := a.db.QueryContext(ctx, `SELECT id,ip,backend,scope,cf_rule_id,server_id,reason,source,created_at,expires_at,last_error FROM blocked_ips ORDER BY created_at,id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []blockedIPRecord
	for rows.Next() {
		var row blockedIPRecord
		if err = rows.Scan(&row.ID, &row.IP, &row.Backend, &row.Scope, &row.RuleID, &row.ServerID, &row.Reason, &row.Source, &row.CreatedAt, &row.ExpiresAt, &row.LastError); err != nil {
			return nil, err
		}
		out = append(out, row)
	}
	return out, rows.Err()
}

func (a *App) reconcileCloudflareBlockZone(ctx context.Context, zoneID string, records []blockedIPRecord) error {
	client, err := a.blockCloudflareClient()
	if err != nil {
		for _, row := range records {
			_ = a.setBlockedIPError(ctx, row.ID, "Cloudflare credentials or zone are unavailable: "+err.Error())
		}
		return err
	}
	if client == nil {
		return errors.New("Cloudflare IP block records remain but the API token is missing")
	}
	rules, err := client.ListIPAccessRules(ctx, zoneID)
	if err != nil {
		for _, row := range records {
			_ = a.setBlockedIPError(ctx, row.ID, "Cloudflare rule list could not be read: "+err.Error())
		}
		return fmt.Errorf("list Cloudflare IP rules for zone %s: %w", zoneID, err)
	}
	var failures []error
	for _, row := range records {
		if err = a.ensureCloudflareBlockWithRules(ctx, row, client, rules); err != nil {
			_ = a.setBlockedIPError(ctx, row.ID, err.Error())
			failures = append(failures, fmt.Errorf("Cloudflare IP rule %s: %w", row.IP, err))
		}
	}
	return errors.Join(failures...)
}

func (a *App) StartIPBlockingReconciler(ctx context.Context) {
	go func() {
		workCtx, cancel := context.WithTimeout(ctx, blockRequestTimeout)
		if err := a.reconcileBlocking(workCtx); err != nil && !errors.Is(err, context.Canceled) {
			log.Printf("IP blocking reconciliation: %v", err)
		}
		cancel()
		ticker := time.NewTicker(blockReconcileEvery)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				workCtx, cancel := context.WithTimeout(ctx, blockRequestTimeout)
				if err := a.reconcileBlocking(workCtx); err != nil && !errors.Is(err, context.Canceled) {
					log.Printf("IP blocking reconciliation: %v", err)
				}
				cancel()
			}
		}
	}()
}
