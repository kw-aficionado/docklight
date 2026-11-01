package cloudflare

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const apiRoot = "https://api.cloudflare.com/client/v4"

var ErrForeignTunnel = errors.New("the DNS record points to a different Cloudflare Tunnel")

type Client struct {
	BaseURL string
	Token   string
	HTTP    *http.Client
}

type APIError struct {
	Status int
	Errors []string
}

func (e *APIError) Error() string {
	if len(e.Errors) == 0 {
		return fmt.Sprintf("Cloudflare API returned HTTP %d", e.Status)
	}
	return fmt.Sprintf("Cloudflare API: %s", strings.Join(e.Errors, "; "))
}

type TunnelConfiguration struct {
	Config map[string]json.RawMessage `json:"config"`
}

type Zone struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

type DNSRecord struct {
	ID      string `json:"id"`
	Type    string `json:"type"`
	Name    string `json:"name"`
	Content string `json:"content"`
	Proxied bool   `json:"proxied"`
	TTL     int    `json:"ttl"`
}

func NewClient(token string, httpClient *http.Client) *Client {
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 25 * time.Second, CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }}
	} else {
		copy := *httpClient
		copy.CheckRedirect = func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }
		httpClient = &copy
	}
	return &Client{BaseURL: apiRoot, Token: token, HTTP: httpClient}
}

func (c *Client) endpoint(path string, query url.Values) string {
	base := strings.TrimRight(c.BaseURL, "/")
	if base == "" {
		base = apiRoot
	}
	u := base + path
	if len(query) != 0 {
		u += "?" + query.Encode()
	}
	return u
}

func (c *Client) request(ctx context.Context, method, path string, query url.Values, body any, out any) error {
	var reader io.Reader
	if body != nil {
		encoded, err := json.Marshal(body)
		if err != nil {
			return err
		}
		reader = bytes.NewReader(encoded)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.endpoint(path, query), reader)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+c.Token)
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	response, err := c.HTTP.Do(req)
	if err != nil {
		return fmt.Errorf("Cloudflare API request failed: %w", err)
	}
	defer response.Body.Close()
	data, err := io.ReadAll(io.LimitReader(response.Body, 2<<20))
	if err != nil {
		return fmt.Errorf("read Cloudflare API response: %w", err)
	}
	var envelope struct {
		Success bool `json:"success"`
		Errors  []struct {
			Message string `json:"message"`
		} `json:"errors"`
		Result json.RawMessage `json:"result"`
	}
	if len(data) != 0 {
		if err = json.Unmarshal(data, &envelope); err != nil {
			return fmt.Errorf("Cloudflare API returned invalid JSON (HTTP %d)", response.StatusCode)
		}
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 || !envelope.Success {
		messages := make([]string, 0, len(envelope.Errors))
		for _, item := range envelope.Errors {
			if item.Message != "" {
				messages = append(messages, item.Message)
			}
		}
		return &APIError{Status: response.StatusCode, Errors: messages}
	}
	if out != nil && len(envelope.Result) != 0 && string(envelope.Result) != "null" {
		if err = json.Unmarshal(envelope.Result, out); err != nil {
			return fmt.Errorf("decode Cloudflare API result: %w", err)
		}
	}
	return nil
}

func (c *Client) GetTunnelConfiguration(ctx context.Context, accountID, tunnelID string) (TunnelConfiguration, error) {
	var result TunnelConfiguration
	path := "/accounts/" + url.PathEscape(accountID) + "/cfd_tunnel/" + url.PathEscape(tunnelID) + "/configurations"
	err := c.request(ctx, http.MethodGet, path, nil, nil, &result)
	return result, err
}

func (c *Client) UpdateTunnelConfiguration(ctx context.Context, accountID, tunnelID string, config map[string]json.RawMessage) error {
	path := "/accounts/" + url.PathEscape(accountID) + "/cfd_tunnel/" + url.PathEscape(tunnelID) + "/configurations"
	return c.request(ctx, http.MethodPut, path, nil, map[string]any{"config": config}, nil)
}

func (c *Client) ListZones(ctx context.Context, accountID, name string) ([]Zone, error) {
	var out []Zone
	for page := 1; page <= 20; page++ {
		query := url.Values{"account.id": {accountID}, "name": {name}, "page": {strconv.Itoa(page)}, "per_page": {"50"}}
		var result []Zone
		if err := c.request(ctx, http.MethodGet, "/zones", query, nil, &result); err != nil {
			return nil, err
		}
		out = append(out, result...)
		if len(result) < 50 {
			return out, nil
		}
	}
	return nil, errors.New("Cloudflare returned too many zones to resolve safely")
}

func (c *Client) ListDNSRecords(ctx context.Context, zoneID, name string) ([]DNSRecord, error) {
	var out []DNSRecord
	for page := 1; page <= 20; page++ {
		query := url.Values{"name.exact": {name}, "page": {strconv.Itoa(page)}, "per_page": {"100"}}
		var result []DNSRecord
		path := "/zones/" + url.PathEscape(zoneID) + "/dns_records"
		if err := c.request(ctx, http.MethodGet, path, query, nil, &result); err != nil {
			return nil, err
		}
		out = append(out, result...)
		if len(result) < 100 {
			return out, nil
		}
	}
	return nil, errors.New("Cloudflare returned too many DNS records for one hostname")
}

func (c *Client) CreateDNSRecord(ctx context.Context, zoneID string, record DNSRecord) (DNSRecord, error) {
	var result DNSRecord
	path := "/zones/" + url.PathEscape(zoneID) + "/dns_records"
	body := map[string]any{"type": record.Type, "name": record.Name, "content": record.Content, "ttl": 1, "proxied": record.Proxied}
	err := c.request(ctx, http.MethodPost, path, nil, body, &result)
	return result, err
}

func (c *Client) UpdateDNSRecord(ctx context.Context, zoneID string, record DNSRecord) (DNSRecord, error) {
	var result DNSRecord
	path := "/zones/" + url.PathEscape(zoneID) + "/dns_records/" + url.PathEscape(record.ID)
	body := map[string]any{"type": record.Type, "name": record.Name, "content": record.Content, "ttl": 1, "proxied": record.Proxied}
	err := c.request(ctx, http.MethodPatch, path, nil, body, &result)
	return result, err
}

func (c *Client) DeleteDNSRecord(ctx context.Context, zoneID, recordID string) error {
	path := "/zones/" + url.PathEscape(zoneID) + "/dns_records/" + url.PathEscape(recordID)
	return c.request(ctx, http.MethodDelete, path, nil, nil, nil)
}
