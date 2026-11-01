package panel

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const (
	defaultBeaconURL = "https://beacon.docklight.app/api/beacon"
	beaconInterval   = 30 * time.Minute
	beaconFirstDelay = 30 * time.Second
	beaconTimeout    = 8 * time.Second
)

type beaconPayload struct {
	InstanceID string `json:"instance_id"`
	Version    string `json:"version"`
}

type beaconSettingsResponse struct {
	Enabled            bool          `json:"enabled"`
	InstanceID         string        `json:"instance_id"`
	Payload            beaconPayload `json:"payload"`
	URL                string        `json:"url"`
	LastSuccessAt      string        `json:"last_success_at"`
	LastError          string        `json:"last_error"`
	LastErrorAt        string        `json:"last_error_at"`
	NoticeAck          bool          `json:"notice_ack"`
	NoticeRequired     bool          `json:"notice_required"`
	ReceiverEnabled    bool          `json:"receiver_enabled"`
	PublicCountEnabled bool          `json:"public_count_enabled"`
	PublicCountMin     int           `json:"public_count_min"`
}

type beaconSettingsRecord struct {
	Enabled            bool
	InstanceID         string
	LastDay            string
	LastVersion        string
	LastSuccessAt      string
	LastError          string
	LastErrorAt        string
	NoticeAck          bool
	ReceiverEnabled    bool
	URL                string
	PublicCountEnabled bool
	PublicCountMin     int
}

type beaconCountResponse struct {
	Count      *int `json:"count"`
	WindowDays int  `json:"window_days"`
}

type beaconVersionCount struct {
	Version string `json:"version"`
	Count   int    `json:"count"`
}

func (a *App) ensureBeaconInstanceID(ctx context.Context) (string, error) {
	var id string
	if err := a.db.QueryRowContext(ctx, `SELECT instance_id FROM beacon_settings WHERE id=1`).Scan(&id); err != nil {
		return "", err
	}
	if id != "" {
		return id, nil
	}
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", err
	}
	raw[6] = (raw[6] & 0x0f) | 0x40
	raw[8] = (raw[8] & 0x3f) | 0x80
	generated := fmt.Sprintf("%s-%s-%s-%s-%s", hex.EncodeToString(raw[0:4]), hex.EncodeToString(raw[4:6]), hex.EncodeToString(raw[6:8]), hex.EncodeToString(raw[8:10]), hex.EncodeToString(raw[10:16]))
	if _, err := a.db.ExecContext(ctx, `UPDATE beacon_settings SET instance_id=? WHERE id=1 AND instance_id=''`, generated); err != nil {
		return "", err
	}
	if err := a.db.QueryRowContext(ctx, `SELECT instance_id FROM beacon_settings WHERE id=1`).Scan(&id); err != nil {
		return "", err
	}
	return id, nil
}

func (a *App) readBeaconSettings(ctx context.Context) (beaconSettingsRecord, error) {
	id, err := a.ensureBeaconInstanceID(ctx)
	if err != nil {
		return beaconSettingsRecord{}, err
	}
	var rec beaconSettingsRecord
	var enabled, noticeAck, receiverEnabled, publicCountEnabled int
	err = a.db.QueryRowContext(ctx, `SELECT enabled,instance_id,last_day,last_version,last_success_at,last_error,last_error_at,notice_ack,receiver_enabled,url,public_count_enabled,public_count_min FROM beacon_settings WHERE id=1`).Scan(
		&enabled, &rec.InstanceID, &rec.LastDay, &rec.LastVersion, &rec.LastSuccessAt, &rec.LastError, &rec.LastErrorAt, &noticeAck, &receiverEnabled, &rec.URL, &publicCountEnabled, &rec.PublicCountMin,
	)
	if err != nil {
		return beaconSettingsRecord{}, err
	}
	rec.Enabled = enabled != 0
	rec.NoticeAck = noticeAck != 0
	rec.ReceiverEnabled = receiverEnabled != 0
	rec.PublicCountEnabled = publicCountEnabled != 0
	if rec.InstanceID == "" {
		rec.InstanceID = id
	}
	if rec.URL == "" {
		rec.URL = defaultBeaconURL
	}
	return rec, nil
}

func (a *App) getBeaconSettings(w http.ResponseWriter, r *http.Request) {
	rec, err := a.readBeaconSettings(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not read beacon settings")
		return
	}
	writeJSON(w, http.StatusOK, beaconSettingsToResponse(rec, a.version))
}

func beaconSettingsToResponse(rec beaconSettingsRecord, version string) beaconSettingsResponse {
	return beaconSettingsResponse{
		Enabled: rec.Enabled, InstanceID: rec.InstanceID,
		Payload: beaconPayload{InstanceID: rec.InstanceID, Version: version}, URL: rec.URL,
		LastSuccessAt: rec.LastSuccessAt, LastError: rec.LastError, LastErrorAt: rec.LastErrorAt,
		NoticeAck: rec.NoticeAck, NoticeRequired: rec.Enabled && !rec.NoticeAck,
		ReceiverEnabled: rec.ReceiverEnabled, PublicCountEnabled: rec.PublicCountEnabled, PublicCountMin: rec.PublicCountMin,
	}
}

func beaconTimestamp(value time.Time) string {
	return value.UTC().Format("2006-01-02T15:04:05.000Z")
}

func (a *App) ackBeaconNotice(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Keep *bool `json:"keep"`
	}
	if decodeJSON(w, r, &in, 1024) != nil {
		return
	}
	if in.Keep == nil {
		writeError(w, http.StatusBadRequest, "choose whether to keep the beacon enabled")
		return
	}
	a.beaconSendMu.Lock()
	defer a.beaconSendMu.Unlock()
	enabled := 0
	if *in.Keep {
		enabled = 1
	}
	if _, err := a.db.ExecContext(r.Context(), `UPDATE beacon_settings SET enabled=?,notice_ack=1,updated_at=CURRENT_TIMESTAMP WHERE id=1`, enabled); err != nil {
		writeError(w, http.StatusInternalServerError, "could not save the beacon choice")
		return
	}
	a.audit(principal(r), "beacon.notice", "settings", "beacon", fmt.Sprintf("enabled=%t", *in.Keep))
	message := ""
	if *in.Keep {
		if err := a.dispatchBeaconLocked(r.Context(), false); err != nil {
			message = err.Error()
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"enabled": *in.Keep, "notice_ack": true, "message": message})
}

func (a *App) updateBeaconSettings(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Enabled            *bool   `json:"enabled"`
		URL                *string `json:"url"`
		ReceiverEnabled    *bool   `json:"receiver_enabled"`
		PublicCountEnabled *bool   `json:"public_count_enabled"`
		PublicCountMin     *int    `json:"public_count_min"`
	}
	if decodeJSON(w, r, &in, 8192) != nil {
		return
	}
	if in.Enabled == nil || in.URL == nil || in.ReceiverEnabled == nil || in.PublicCountEnabled == nil || in.PublicCountMin == nil {
		writeError(w, http.StatusBadRequest, "provide all beacon settings")
		return
	}
	if *in.PublicCountMin < 1 || *in.PublicCountMin > 1000000 {
		writeError(w, http.StatusBadRequest, "public count minimum must be from 1 to 1000000")
		return
	}
	collectorURL := strings.TrimSpace(*in.URL)
	if collectorURL == "" {
		collectorURL = defaultBeaconURL
	}
	if _, err := validateBeaconURL(collectorURL); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	a.beaconSendMu.Lock()
	defer a.beaconSendMu.Unlock()
	var wasEnabled int
	if err := a.db.QueryRowContext(r.Context(), `SELECT enabled FROM beacon_settings WHERE id=1`).Scan(&wasEnabled); err != nil {
		writeError(w, http.StatusInternalServerError, "could not read current beacon settings")
		return
	}
	if _, err := a.db.ExecContext(r.Context(), `UPDATE beacon_settings SET enabled=?,url=?,receiver_enabled=?,public_count_enabled=?,public_count_min=?,notice_ack=CASE WHEN ?=0 THEN 1 ELSE notice_ack END,updated_at=CURRENT_TIMESTAMP WHERE id=1`, boolInt(*in.Enabled), collectorURL, boolInt(*in.ReceiverEnabled), boolInt(*in.PublicCountEnabled), *in.PublicCountMin, boolInt(*in.Enabled)); err != nil {
		writeError(w, http.StatusInternalServerError, "could not save beacon settings")
		return
	}
	a.clearBeaconCountCache()
	a.audit(principal(r), "beacon.settings", "settings", "beacon", fmt.Sprintf("enabled=%t receiver=%t public_count=%t", *in.Enabled, *in.ReceiverEnabled, *in.PublicCountEnabled))
	message := ""
	if *in.Enabled && wasEnabled == 0 {
		if err := a.dispatchBeaconLocked(r.Context(), true); err != nil {
			message = err.Error()
		}
	}
	rec, err := a.readBeaconSettings(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "settings were saved but could not be read back")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"settings": beaconSettingsToResponse(rec, a.version), "message": message})
}

func validateBeaconURL(raw string) (*url.URL, error) {
	u, err := url.ParseRequestURI(raw)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Hostname() == "" || u.User != nil || u.Fragment != "" {
		return nil, errors.New("collector URL must be an http or https URL without credentials or a fragment")
	}
	return u, nil
}

func (a *App) testBeacon(w http.ResponseWriter, r *http.Request) {
	a.beaconSendMu.Lock()
	defer a.beaconSendMu.Unlock()
	var enabled int
	if err := a.db.QueryRowContext(r.Context(), `SELECT enabled FROM beacon_settings WHERE id=1`).Scan(&enabled); err != nil {
		writeError(w, http.StatusInternalServerError, "could not read beacon settings")
		return
	}
	if enabled == 0 {
		writeError(w, http.StatusConflict, "the beacon is turned off; turn it on before sending a test ping")
		return
	}
	var in struct {
		URL string `json:"url"`
	}
	if decodeJSON(w, r, &in, 8192) != nil {
		return
	}
	rawURL := strings.TrimSpace(in.URL)
	if rawURL == "" {
		rawURL = defaultBeaconURL
	}
	u, err := validateBeaconURL(rawURL)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	id, err := a.ensureBeaconInstanceID(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not read the beacon identity")
		return
	}
	if err := sendBeacon(r.Context(), *u, beaconPayload{InstanceID: id, Version: a.version}); err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"message": "The collector accepted the beacon payload."})
}

func sendBeacon(ctx context.Context, target url.URL, payload beaconPayload) error {
	body, err := json.Marshal(payload)
	if err != nil {
		return errors.New("could not encode beacon payload")
	}
	ctx, cancel := context.WithTimeout(ctx, beaconTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, target.String(), bytes.NewReader(body))
	if err != nil {
		return errors.New("could not create beacon request")
	}
	req.Header.Set("Content-Type", "application/json")
	client := &http.Client{Timeout: beaconTimeout, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := client.Do(req)
	if err != nil {
		return errors.New("collector request failed; check the collector URL and network connection")
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
	if resp.StatusCode == http.StatusNotFound {
		return errors.New("collector returned 404; confirm that its beacon receiver is enabled and the URL ends with /api/beacon")
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("collector returned HTTP %d", resp.StatusCode)
	}
	return nil
}

func (a *App) receiveBeacon(w http.ResponseWriter, r *http.Request) {
	var enabled int
	if err := a.db.QueryRowContext(r.Context(), `SELECT receiver_enabled FROM beacon_settings WHERE id=1`).Scan(&enabled); err != nil {
		writeError(w, http.StatusInternalServerError, "could not read beacon collector settings")
		return
	}
	if enabled == 0 {
		http.NotFound(w, r)
		return
	}
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 2048))
	dec.DisallowUnknownFields()
	var in beaconPayload
	if err := dec.Decode(&in); err != nil {
		writeError(w, http.StatusBadRequest, "beacon payload must contain only instance_id and version")
		return
	}
	var extra any
	if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
		writeError(w, http.StatusBadRequest, "beacon payload must contain one JSON object")
		return
	}
	in.InstanceID = strings.ToLower(strings.TrimSpace(in.InstanceID))
	in.Version = strings.TrimSpace(in.Version)
	if !validBeaconUUID(in.InstanceID) || in.Version == "" || len(in.Version) > 128 || strings.IndexFunc(in.Version, func(r rune) bool { return r < 0x20 || r == 0x7f }) >= 0 {
		writeError(w, http.StatusBadRequest, "beacon instance_id must be a UUID and version must contain 1 to 128 printable characters")
		return
	}
	seen := beaconTimestamp(time.Now())
	if _, err := a.db.ExecContext(r.Context(), `INSERT INTO beacon_pings(instance_id,version,first_seen,last_seen,ping_count) VALUES(?,?,?,?,1)
		ON CONFLICT(instance_id) DO UPDATE SET version=excluded.version,last_seen=excluded.last_seen,ping_count=beacon_pings.ping_count+1`, in.InstanceID, in.Version, seen, seen); err != nil {
		writeError(w, http.StatusInternalServerError, "could not record beacon ping")
		return
	}
	a.clearBeaconCountCache()
	w.WriteHeader(http.StatusAccepted)
}

func validBeaconUUID(id string) bool {
	if len(id) != 36 || id[8] != '-' || id[13] != '-' || id[18] != '-' || id[23] != '-' {
		return false
	}
	for i, c := range id {
		if i == 8 || i == 13 || i == 18 || i == 23 {
			continue
		}
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return false
		}
	}
	return true
}

func (a *App) publicBeaconCount(w http.ResponseWriter, r *http.Request) {
	var enabled, publicCountEnabled, minimum int
	if err := a.db.QueryRowContext(r.Context(), `SELECT receiver_enabled,public_count_enabled,public_count_min FROM beacon_settings WHERE id=1`).Scan(&enabled, &publicCountEnabled, &minimum); err != nil {
		writeError(w, http.StatusInternalServerError, "could not read beacon collector settings")
		return
	}
	if enabled == 0 || publicCountEnabled == 0 {
		http.NotFound(w, r)
		return
	}
	now := time.Now().UTC()
	a.beaconMu.Lock()
	if a.beaconCountCache != nil && now.Before(a.beaconCountCacheUntil) {
		cached := *a.beaconCountCache
		a.beaconMu.Unlock()
		writeJSON(w, http.StatusOK, cached)
		return
	}
	a.beaconMu.Unlock()
	cutoff := beaconTimestamp(now.Add(-30 * 24 * time.Hour))
	var total int
	if err := a.db.QueryRowContext(r.Context(), `SELECT count(*) FROM beacon_pings WHERE last_seen>=?`, cutoff).Scan(&total); err != nil {
		writeError(w, http.StatusInternalServerError, "could not count active beacon instances")
		return
	}
	result := beaconCountResponse{WindowDays: 30}
	if total >= minimum {
		result.Count = &total
	}
	a.beaconMu.Lock()
	a.beaconCountCache = &result
	a.beaconCountCacheUntil = now.Add(time.Minute)
	a.beaconMu.Unlock()
	writeJSON(w, http.StatusOK, result)
}

func (a *App) clearBeaconCountCache() {
	a.beaconMu.Lock()
	a.beaconCountCache = nil
	a.beaconCountCacheUntil = time.Time{}
	a.beaconMu.Unlock()
}

func (a *App) beaconStats(w http.ResponseWriter, r *http.Request) {
	now := time.Now().UTC()
	var total, active7, active30 int
	if err := a.db.QueryRowContext(r.Context(), `SELECT count(*),COALESCE(sum(CASE WHEN last_seen>=? THEN 1 ELSE 0 END),0),COALESCE(sum(CASE WHEN last_seen>=? THEN 1 ELSE 0 END),0) FROM beacon_pings`, beaconTimestamp(now.Add(-7*24*time.Hour)), beaconTimestamp(now.Add(-30*24*time.Hour))).Scan(&total, &active7, &active30); err != nil {
		writeError(w, http.StatusInternalServerError, "could not read beacon statistics")
		return
	}
	rows, err := a.db.QueryContext(r.Context(), `SELECT version,count(*) FROM beacon_pings WHERE last_seen>=? GROUP BY version ORDER BY count(*) DESC,version`, beaconTimestamp(now.Add(-30*24*time.Hour)))
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not list beacon versions")
		return
	}
	defer rows.Close()
	versions := []beaconVersionCount{}
	for rows.Next() {
		var item beaconVersionCount
		if err = rows.Scan(&item.Version, &item.Count); err != nil {
			writeError(w, http.StatusInternalServerError, "could not read beacon versions")
			return
		}
		versions = append(versions, item)
	}
	if err = rows.Err(); err != nil {
		writeError(w, http.StatusInternalServerError, "could not read beacon versions")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"total": total, "active_7d": active7, "active_30d": active30, "versions": versions})
}

func (a *App) StartBeaconWorker(ctx context.Context) {
	go func() {
		timer := time.NewTimer(beaconFirstDelay)
		defer timer.Stop()
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
		}
		a.dispatchBeacon(ctx, false)
		ticker := time.NewTicker(beaconInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				a.dispatchBeacon(ctx, false)
			}
		}
	}()
}

func (a *App) dispatchBeacon(ctx context.Context, force bool) error {
	a.beaconSendMu.Lock()
	defer a.beaconSendMu.Unlock()
	return a.dispatchBeaconLocked(ctx, force)
}

func (a *App) dispatchBeaconLocked(ctx context.Context, force bool) error {
	rec, err := a.readBeaconSettings(ctx)
	if err != nil {
		return err
	}
	if !rec.Enabled {
		return nil
	}
	today := time.Now().UTC().Format("2006-01-02")
	if !force && rec.LastDay == today && rec.LastVersion == a.version {
		return nil
	}
	target, err := validateBeaconURL(rec.URL)
	if err == nil {
		err = sendBeacon(ctx, *target, beaconPayload{InstanceID: rec.InstanceID, Version: a.version})
	}
	if err != nil {
		message := err.Error()
		if len(message) > 500 {
			message = message[:500]
		}
		_, _ = a.db.ExecContext(ctx, `UPDATE beacon_settings SET last_error=?,last_error_at=?,updated_at=CURRENT_TIMESTAMP WHERE id=1`, message, beaconTimestamp(time.Now()))
		return err
	}
	now := time.Now().UTC()
	_, err = a.db.ExecContext(ctx, `UPDATE beacon_settings SET last_day=?,last_version=?,last_success_at=?,last_error='',last_error_at='',updated_at=CURRENT_TIMESTAMP WHERE id=1`, now.Format("2006-01-02"), a.version, beaconTimestamp(now))
	return err
}
