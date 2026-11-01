package panel

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"example.com/yggdrasil-panel/internal/rune"
	"example.com/yggdrasil-panel/internal/upnp"
	"github.com/go-chi/chi/v5"
)

const upnpRequestTimeout = 30 * time.Second

type serverUPnPMapping struct {
	ServerID       string `json:"server_id,omitempty"`
	PortName       string `json:"port_name"`
	ExternalPort   uint16 `json:"external_port"`
	Protocol       string `json:"protocol"`
	InternalPort   uint16 `json:"internal_port"`
	InternalClient string `json:"internal_client"`
	Description    string `json:"description"`
}

type serverUPnPResponse struct {
	AutoForward   bool                `json:"auto_forward"`
	GlobalEnabled bool                `json:"global_enabled"`
	LastError     string              `json:"last_error,omitempty"`
	Mappings      []serverUPnPMapping `json:"mappings"`
}

type upnpStatusResponse struct {
	Enabled        bool   `json:"enabled"`
	Available      bool   `json:"available"`
	LANIP          string `json:"lan_ip,omitempty"`
	WANIP          string `json:"wan_ip,omitempty"`
	OwnedMappings  int    `json:"owned_mappings"`
	PendingCleanup int    `json:"pending_cleanup"`
	Message        string `json:"message,omitempty"`
}

func (a *App) getUPnPSettings(w http.ResponseWriter, r *http.Request) {
	enabled, err := a.globalUPnPEnabled()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not read UPnP settings")
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"enabled": enabled})
}

func (a *App) updateUPnPSettings(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Enabled *bool `json:"enabled"`
	}
	if decodeJSON(w, r, &in, 8*1024) != nil {
		return
	}
	if in.Enabled == nil {
		writeError(w, http.StatusBadRequest, "enabled is required")
		return
	}
	a.dataMu.Lock()
	defer a.dataMu.Unlock()
	if _, err := a.db.ExecContext(r.Context(), `UPDATE upnp_settings SET enabled=?,updated_at=CURRENT_TIMESTAMP WHERE id=1`, boolInt(*in.Enabled)); err != nil {
		writeError(w, http.StatusInternalServerError, "could not save UPnP settings")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 90*time.Second)
	defer cancel()
	response := upnpStatusResponse{Enabled: *in.Enabled}
	if err := a.syncGlobalUPnP(ctx, *in.Enabled, &response); err != nil {
		response.Message = err.Error()
	}
	a.audit(principal(r), "upnp.settings", "network", "upnp", fmt.Sprintf("enabled=%t", *in.Enabled))
	writeJSON(w, http.StatusOK, response)
}

func (a *App) getUPnPStatus(w http.ResponseWriter, r *http.Request) {
	enabled, err := a.globalUPnPEnabled()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not read UPnP settings")
		return
	}
	response := upnpStatusResponse{Enabled: enabled}
	var owned, pending int
	if err = a.db.QueryRow(`SELECT count(*) FROM server_upnp_mappings`).Scan(&owned); err != nil {
		writeError(w, http.StatusInternalServerError, "could not read recorded UPnP mappings")
		return
	}
	if err = a.db.QueryRow(`SELECT count(DISTINCT m.server_id) FROM server_upnp_mappings m LEFT JOIN servers s ON s.id=m.server_id
		WHERE ?=0 OR s.id IS NULL OR s.auto_forward=0 OR s.status NOT IN ('running','starting')`, boolInt(enabled)).Scan(&pending); err != nil {
		writeError(w, http.StatusInternalServerError, "could not read pending UPnP cleanup")
		return
	}
	response.OwnedMappings = owned
	response.PendingCleanup = pending
	ctx, cancel := context.WithTimeout(r.Context(), upnpRequestTimeout)
	defer cancel()
	gateway, err := a.discoverUPnPGateway(ctx)
	if err != nil {
		response.Message = "No compatible UPnP router is available from this host. Check that the host and router share a LAN and that UPnP IGD is enabled."
		writeJSON(w, http.StatusOK, response)
		return
	}
	response.Available = true
	if ip := gateway.LocalIP(); ip != nil {
		response.LANIP = ip.String()
	}
	if ip, ipErr := gateway.ExternalIP(ctx); ipErr == nil && ip != nil {
		response.WANIP = ip.String()
	} else if ipErr != nil {
		response.Message = "The router was discovered, but its WAN address could not be read: " + ipErr.Error()
	}
	writeJSON(w, http.StatusOK, response)
}

func (a *App) updateServerUPnPSettings(w http.ResponseWriter, r *http.Request) {
	s, err := a.getServer(chi.URLParam(r, "id"))
	if err != nil {
		writeError(w, http.StatusNotFound, "server not found")
		return
	}
	u := principal(r)
	if !a.allowedServer(u, "server.control", s.ID, s.GameskillID, s.RealmID) {
		writeError(w, http.StatusForbidden, "server.control permission is required")
		return
	}
	var in struct {
		AutoForward *bool `json:"auto_forward"`
	}
	if decodeJSON(w, r, &in, 8*1024) != nil {
		return
	}
	if in.AutoForward == nil {
		writeError(w, http.StatusBadRequest, "auto_forward is required")
		return
	}
	a.dataMu.Lock()
	defer a.dataMu.Unlock()
	s, err = a.getServer(s.ID)
	if err != nil {
		writeError(w, http.StatusNotFound, "server not found")
		return
	}
	if _, err = a.db.ExecContext(r.Context(), `UPDATE servers SET auto_forward=?,updated_at=CURRENT_TIMESTAMP WHERE id=?`, boolInt(*in.AutoForward), s.ID); err != nil {
		writeError(w, http.StatusInternalServerError, "could not save server port-forwarding preference")
		return
	}
	s.AutoForward = *in.AutoForward
	ctx, cancel := context.WithTimeout(r.Context(), upnpRequestTimeout)
	defer cancel()
	globalEnabled, err := a.globalUPnPEnabled()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not read global UPnP settings")
		return
	}
	if !s.AutoForward {
		_ = a.removeServerUPnPMappings(ctx, s.ID, nil)
	} else if globalEnabled && (s.Status == "running" || s.Status == "starting") {
		_ = a.openServerUPnPMappings(ctx, s)
	} else {
		_ = a.setServerUPnPError(s.ID, nil)
	}
	a.audit(u, "server.upnp_settings", "server", s.ID, fmt.Sprintf("auto_forward=%t", *in.AutoForward))
	response, err := a.serverUPnPStatus(s)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "port-forwarding preference was saved, but its status could not be read")
		return
	}
	writeJSON(w, http.StatusOK, response)
}

func (a *App) getServerUPnPSettingsHandler(w http.ResponseWriter, r *http.Request) {
	s, err := a.getServer(chi.URLParam(r, "id"))
	if err != nil {
		writeError(w, http.StatusNotFound, "server not found")
		return
	}
	u := principal(r)
	if !a.allowedServer(u, "server.view", s.ID, s.GameskillID, s.RealmID) {
		writeError(w, http.StatusForbidden, "server.view permission is required")
		return
	}
	response, err := a.getServerUPnPSettings(s)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not read server port-forwarding state")
		return
	}
	writeJSON(w, http.StatusOK, response)
}

func (a *App) getServerUPnPSettings(s Server) (serverUPnPResponse, error) {
	enabled, err := a.globalUPnPEnabled()
	if err != nil {
		return serverUPnPResponse{}, err
	}
	response := serverUPnPResponse{AutoForward: s.AutoForward, GlobalEnabled: enabled, Mappings: []serverUPnPMapping{}}
	_ = a.db.QueryRow(`SELECT last_error FROM server_upnp_state WHERE server_id=?`, s.ID).Scan(&response.LastError)
	rows, err := a.db.Query(`SELECT server_id,port_name,external_port,protocol,internal_port,internal_client,description FROM server_upnp_mappings WHERE server_id=? ORDER BY external_port,protocol`, s.ID)
	if err != nil {
		return response, err
	}
	defer rows.Close()
	for rows.Next() {
		var mapping serverUPnPMapping
		if err := rows.Scan(&mapping.ServerID, &mapping.PortName, &mapping.ExternalPort, &mapping.Protocol, &mapping.InternalPort, &mapping.InternalClient, &mapping.Description); err != nil {
			return response, err
		}
		response.Mappings = append(response.Mappings, mapping)
	}
	return response, rows.Err()
}

func (a *App) serverUPnPStatus(s Server) (serverUPnPResponse, error) {
	return a.getServerUPnPSettings(s)
}

func (a *App) globalUPnPEnabled() (bool, error) {
	var enabled int
	if err := a.db.QueryRow(`SELECT enabled FROM upnp_settings WHERE id=1`).Scan(&enabled); err != nil {
		return false, err
	}
	return enabled != 0, nil
}

func (a *App) discoverUPnPGateway(ctx context.Context) (upnp.Gateway, error) {
	if a.upnpDiscover != nil {
		return a.upnpDiscover(ctx)
	}
	return upnp.Discover(ctx)
}

func (a *App) syncGlobalUPnP(ctx context.Context, enabled bool, response *upnpStatusResponse) error {
	var serverIDs []string
	var rows *sql.Rows
	var err error
	if enabled {
		rows, err = a.db.QueryContext(ctx, `SELECT id FROM servers WHERE auto_forward=1 AND installed=1 AND status IN ('running','starting') ORDER BY id`)
	} else {
		rows, err = a.db.QueryContext(ctx, `SELECT DISTINCT server_id FROM server_upnp_mappings ORDER BY server_id`)
	}
	if err != nil {
		return fmt.Errorf("could not read servers for UPnP synchronization: %w", err)
	}
	for rows.Next() {
		var id string
		if err = rows.Scan(&id); err != nil {
			_ = rows.Close()
			return err
		}
		serverIDs = append(serverIDs, id)
	}
	if err = rows.Err(); err != nil {
		_ = rows.Close()
		return err
	}
	_ = rows.Close()
	if len(serverIDs) == 0 {
		return nil
	}
	gateway, err := a.discoverUPnPGateway(ctx)
	if err != nil {
		message := "UPnP is saved, but the router could not be discovered. Confirm that UPnP IGD is enabled and Docklight shares the router's LAN."
		for _, id := range serverIDs {
			_ = a.setServerUPnPError(id, errors.New(message))
		}
		return errors.New(message)
	}
	var failures []error
	for _, id := range serverIDs {
		if err = ctx.Err(); err != nil {
			failures = append(failures, err)
			break
		}
		if enabled {
			s, loadErr := a.getServer(id)
			if loadErr == nil {
				loadErr = a.openServerUPnPMappingsWithGateway(ctx, s, gateway)
			}
			err = loadErr
		} else {
			err = a.removeServerUPnPMappings(ctx, id, gateway)
		}
		if err != nil {
			failures = append(failures, fmt.Errorf("%s: %w", id, err))
		}
	}
	if len(failures) > 0 {
		combined := errors.Join(failures...)
		if response != nil {
			response.Message = combined.Error()
		}
		return combined
	}
	return nil
}

func (a *App) openServerUPnPMappings(ctx context.Context, s Server) error {
	globalEnabled, err := a.globalUPnPEnabled()
	if err != nil {
		return err
	}
	if !globalEnabled || !s.AutoForward {
		return nil
	}
	gateway, err := a.discoverUPnPGateway(ctx)
	if err != nil {
		message := "UPnP port forwarding could not reach a compatible router. The server started without external mappings."
		_ = a.setServerUPnPError(s.ID, errors.New(message))
		return errors.New(message)
	}
	return a.openServerUPnPMappingsWithGateway(ctx, s, gateway)
}

func (a *App) openServerUPnPMappingsWithGateway(ctx context.Context, s Server, gateway upnp.Gateway) error {
	a.upnpMu.Lock()
	defer a.upnpMu.Unlock()
	localIP := gateway.LocalIP()
	if localIP == nil || localIP.To4() == nil || localIP.IsUnspecified() || localIP.IsLoopback() || localIP.IsMulticast() {
		return a.recordUPnPError(s.ID, errors.New("the router did not provide a usable LAN IPv4 address"))
	}
	r, err := a.loadRune(s.GameskillID)
	if err != nil {
		return a.recordUPnPError(s.ID, fmt.Errorf("could not load the server template: %w", err))
	}
	desired := desiredServerMappings(s, r, localIP.To4().String())
	tracked, err := a.listServerUPnPMappings(s.ID)
	if err != nil {
		return a.recordUPnPError(s.ID, err)
	}
	trackedByKey := make(map[string]serverUPnPMapping, len(tracked))
	for _, existing := range tracked {
		trackedByKey[mappingKey(existing.Protocol, existing.ExternalPort)] = existing
	}
	desiredByKey := make(map[string]serverUPnPMapping, len(desired))
	for _, item := range desired {
		desiredByKey[mappingKey(item.Protocol, item.ExternalPort)] = item
	}
	var failures []error

	// Remove old Docklight-owned entries first. A recorded entry is deleted only
	// after the router confirms that its target and Docklight marker still match.
	for _, old := range tracked {
		key := mappingKey(old.Protocol, old.ExternalPort)
		want, keep := desiredByKey[key]
		if keep && sameRecordedTarget(old, want) {
			continue
		}
		if err := a.removeOneUPnPMapping(ctx, old, gateway); err != nil {
			failures = append(failures, fmt.Errorf("remove obsolete %s/%d mapping: %w", old.Protocol, old.ExternalPort, err))
		}
		delete(trackedByKey, key)
	}

	for _, want := range desired {
		key := mappingKey(want.Protocol, want.ExternalPort)
		if old, ok := trackedByKey[key]; ok && sameRecordedTarget(old, want) {
			actual, exists, checkErr := gateway.GetMapping(ctx, want.Protocol, want.ExternalPort)
			if checkErr != nil {
				failures = append(failures, fmt.Errorf("check %s/%d mapping: %w", want.Protocol, want.ExternalPort, checkErr))
				continue
			}
			if exists && routerMappingMatches(old, actual) {
				continue
			}
			if exists {
				_ = a.deleteUPnPRecord(old)
				delete(trackedByKey, key)
				failures = append(failures, fmt.Errorf("router port %s/%d is now owned by a different mapping", want.Protocol, want.ExternalPort))
				continue
			}
			_ = a.deleteUPnPRecord(old)
			delete(trackedByKey, key)
		}

		actual, exists, checkErr := gateway.GetMapping(ctx, want.Protocol, want.ExternalPort)
		if checkErr != nil {
			failures = append(failures, fmt.Errorf("check %s/%d mapping: %w", want.Protocol, want.ExternalPort, checkErr))
			continue
		}
		if exists {
			if routerMappingMatches(want, actual) {
				if saveErr := a.saveUPnPRecord(want); saveErr != nil {
					failures = append(failures, saveErr)
				}
				continue
			}
			failures = append(failures, fmt.Errorf("router port %s/%d is already used by a mapping Docklight does not own", want.Protocol, want.ExternalPort))
			continue
		}
		mapping := upnp.Mapping{
			RemoteHost: "", ExternalPort: want.ExternalPort, Protocol: strings.ToUpper(want.Protocol),
			InternalPort: want.InternalPort, InternalClient: want.InternalClient, Enabled: true,
			Description: want.Description, LeaseDuration: 0,
		}
		if saveErr := a.saveUPnPRecord(want); saveErr != nil {
			failures = append(failures, fmt.Errorf("record %s/%d mapping before router update: %w", want.Protocol, want.ExternalPort, saveErr))
			continue
		}
		if addErr := gateway.AddMapping(ctx, mapping); addErr != nil {
			// Keep a pending record when router state cannot be verified. Cleanup
			// still rechecks every router field before deleting anything.
			actual, exists, checkErr = gateway.GetMapping(ctx, want.Protocol, want.ExternalPort)
			if exists && checkErr == nil && routerMappingMatches(want, actual) {
			} else if checkErr == nil {
				if saveErr := a.deleteUPnPRecord(want); saveErr != nil {
					addErr = errors.Join(addErr, saveErr)
				}
			} else {
				addErr = errors.Join(addErr, fmt.Errorf("could not verify router state: %w", checkErr))
			}
			failures = append(failures, fmt.Errorf("add %s/%d mapping: %w", want.Protocol, want.ExternalPort, addErr))
			continue
		}
	}
	return a.recordUPnPError(s.ID, errors.Join(failures...))
}

func desiredServerMappings(s Server, game rune.Rune, internalIP string) []serverUPnPMapping {
	ports := append([]rune.Port(nil), game.Ports...)
	sort.Slice(ports, func(i, j int) bool { return ports[i].Name < ports[j].Name })
	var desired []serverUPnPMapping
	for _, declared := range ports {
		name := strings.TrimSpace(declared.Name)
		lowerName := strings.ToLower(name)
		if name == "" || strings.Contains(lowerName, "rcon") || strings.Contains(lowerName, "admin") || strings.Contains(lowerName, "management") || strings.Contains(lowerName, "console") {
			continue
		}
		port := s.Ports[name]
		if port < 1 || port > 65535 {
			continue
		}
		protocols := []string{}
		switch strings.ToLower(declared.Protocol) {
		case "tcp":
			protocols = []string{"TCP"}
		case "udp":
			protocols = []string{"UDP"}
		case "tcp+udp":
			protocols = []string{"TCP", "UDP"}
		default:
			continue
		}
		for _, protocol := range protocols {
			portName := name
			if len(portName) > 20 {
				portName = portName[:20]
			}
			description := fmt.Sprintf("Docklight:%s:%s", s.ID, portName)
			if len(description) > 63 {
				description = description[:63]
			}
			desired = append(desired, serverUPnPMapping{
				ServerID: s.ID, PortName: name, ExternalPort: uint16(port), Protocol: protocol,
				InternalPort: uint16(port), InternalClient: internalIP, Description: description,
			})
		}
	}
	return desired
}

func (a *App) listServerUPnPMappings(serverID string) ([]serverUPnPMapping, error) {
	rows, err := a.db.Query(`SELECT server_id,port_name,external_port,protocol,internal_port,internal_client,description FROM server_upnp_mappings WHERE server_id=? ORDER BY external_port,protocol`, serverID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var mappings []serverUPnPMapping
	for rows.Next() {
		var mapping serverUPnPMapping
		if err := rows.Scan(&mapping.ServerID, &mapping.PortName, &mapping.ExternalPort, &mapping.Protocol, &mapping.InternalPort, &mapping.InternalClient, &mapping.Description); err != nil {
			return nil, err
		}
		mappings = append(mappings, mapping)
	}
	return mappings, rows.Err()
}

func mappingKey(protocol string, port uint16) string {
	return strings.ToUpper(protocol) + ":" + strconv.Itoa(int(port))
}

func sameRecordedTarget(a, b serverUPnPMapping) bool {
	return a.ServerID == b.ServerID && a.ExternalPort == b.ExternalPort && strings.EqualFold(a.Protocol, b.Protocol) &&
		a.InternalPort == b.InternalPort && a.InternalClient == b.InternalClient && a.Description == b.Description
}

func routerMappingMatches(record serverUPnPMapping, actual upnp.Mapping) bool {
	return actual.RemoteHost == "" && actual.ExternalPort == record.ExternalPort && strings.EqualFold(actual.Protocol, record.Protocol) &&
		actual.InternalPort == record.InternalPort && actual.InternalClient == record.InternalClient && actual.Description == record.Description
}

func (a *App) saveUPnPRecord(mapping serverUPnPMapping) error {
	_, err := a.db.Exec(`INSERT INTO server_upnp_mappings(server_id,port_name,external_port,protocol,internal_port,internal_client,description)
		VALUES(?,?,?,?,?,?,?) ON CONFLICT(server_id,external_port,protocol) DO UPDATE SET port_name=excluded.port_name,internal_port=excluded.internal_port,internal_client=excluded.internal_client,description=excluded.description`,
		mapping.ServerID, mapping.PortName, mapping.ExternalPort, strings.ToUpper(mapping.Protocol), mapping.InternalPort, mapping.InternalClient, mapping.Description)
	return err
}

func (a *App) deleteUPnPRecord(mapping serverUPnPMapping) error {
	_, err := a.db.Exec(`DELETE FROM server_upnp_mappings WHERE server_id=? AND external_port=? AND protocol=?`, mapping.ServerID, mapping.ExternalPort, strings.ToUpper(mapping.Protocol))
	return err
}

func (a *App) removeServerUPnPMappings(ctx context.Context, serverID string, gateway upnp.Gateway) error {
	a.upnpMu.Lock()
	defer a.upnpMu.Unlock()
	mappings, err := a.listServerUPnPMappings(serverID)
	if err != nil || len(mappings) == 0 {
		if err != nil {
			return a.recordUPnPError(serverID, err)
		}
		return a.recordUPnPError(serverID, nil)
	}
	if gateway == nil {
		gateway, err = a.discoverUPnPGateway(ctx)
		if err != nil {
			return a.recordUPnPError(serverID, errors.New("Docklight has recorded router mappings, but the UPnP router is unavailable; cleanup will retry when the router returns"))
		}
	}
	var failures []error
	for _, mapping := range mappings {
		if err = ctx.Err(); err != nil {
			failures = append(failures, err)
			break
		}
		if err = a.removeOneUPnPMapping(ctx, mapping, gateway); err != nil {
			failures = append(failures, fmt.Errorf("%s/%d: %w", mapping.Protocol, mapping.ExternalPort, err))
		}
	}
	return a.recordUPnPError(serverID, errors.Join(failures...))
}

func (a *App) removeOneUPnPMapping(ctx context.Context, mapping serverUPnPMapping, gateway upnp.Gateway) error {
	actual, exists, err := gateway.GetMapping(ctx, mapping.Protocol, mapping.ExternalPort)
	if err != nil {
		return err
	}
	if !exists || !routerMappingMatches(mapping, actual) {
		// If the mapping changed, discard our stale ownership record but never
		// delete the new rule that now occupies that router port.
		return a.deleteUPnPRecord(mapping)
	}
	if err = gateway.DeleteMapping(ctx, mapping.Protocol, mapping.ExternalPort); err != nil {
		return fmt.Errorf("router refused to delete an owned mapping: %w", err)
	}
	return a.deleteUPnPRecord(mapping)
}

func (a *App) recordUPnPError(serverID string, err error) error {
	if saveErr := a.setServerUPnPError(serverID, err); saveErr != nil {
		if err != nil {
			return errors.Join(err, saveErr)
		}
		return saveErr
	}
	return err
}

func (a *App) setServerUPnPError(serverID string, err error) error {
	message := ""
	if err != nil {
		message = err.Error()
		if len(message) > 1000 {
			message = message[:1000]
		}
	}
	_, saveErr := a.db.Exec(`INSERT INTO server_upnp_state(server_id,last_error,updated_at) VALUES(?,?,CURRENT_TIMESTAMP)
		ON CONFLICT(server_id) DO UPDATE SET last_error=excluded.last_error,updated_at=CURRENT_TIMESTAMP`, serverID, message)
	return saveErr
}
