package npm

import (
	"bytes"
	"context"
	"crypto/tls"
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

const maxResponseBytes = 2 << 20

type Client struct {
	baseURL string
	email   string
	secret  string
	token   string
	http    *http.Client
}

type ProxyHost struct {
	ID            json.RawMessage `json:"id"`
	DomainNames   []string        `json:"domain_names"`
	ForwardHost   string          `json:"forward_host"`
	ForwardPort   int             `json:"forward_port"`
	CertificateID json.RawMessage `json:"certificate_id"`
	SSLForced     bool            `json:"ssl_forced"`
	Meta          map[string]any  `json:"meta"`
}

type ProxyHostCreate struct {
	DomainNames           []string       `json:"domain_names"`
	ForwardScheme         string         `json:"forward_scheme"`
	ForwardHost           string         `json:"forward_host"`
	ForwardPort           int            `json:"forward_port"`
	CertificateID         any            `json:"certificate_id"`
	SSLForced             bool           `json:"ssl_forced"`
	HTTP2Support          bool           `json:"http2_support"`
	BlockExploits         bool           `json:"block_exploits"`
	AllowWebsocketUpgrade bool           `json:"allow_websocket_upgrade"`
	AccessListID          int            `json:"access_list_id"`
	Enabled               bool           `json:"enabled"`
	Meta                  map[string]any `json:"meta"`
}

type ProxyHostUpdate struct {
	CertificateID any             `json:"certificate_id,omitempty"`
	SSLForced     *bool           `json:"ssl_forced,omitempty"`
	Meta          *map[string]any `json:"meta,omitempty"`
}

func NewClient(rawURL, email, secret string, httpClient *http.Client) (*Client, error) {
	base, err := normalizeBaseURL(rawURL)
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(email) == "" || secret == "" {
		return nil, errors.New("Nginx Proxy Manager email and password are required")
	}
	if httpClient == nil {
		transport := http.DefaultTransport.(*http.Transport).Clone()
		transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true} // Local NPM instances often use a self-signed certificate.
		httpClient = &http.Client{Timeout: 20 * time.Second, Transport: transport}
	}
	copyClient := *httpClient
	copyClient.CheckRedirect = func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }
	if copyClient.Timeout == 0 {
		copyClient.Timeout = 20 * time.Second
	}
	return &Client{baseURL: base, email: strings.TrimSpace(email), secret: secret, http: &copyClient}, nil
}

func normalizeBaseURL(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", errors.New("Nginx Proxy Manager URL is required")
	}
	if !strings.Contains(raw, "://") {
		raw = "http://" + raw
	}
	u, err := url.Parse(raw)
	if err != nil || u.Hostname() == "" || (u.Scheme != "http" && u.Scheme != "https") || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return "", errors.New("enter a valid Nginx Proxy Manager URL using http or https, without credentials or query parameters")
	}
	if u.Port() != "" {
		port, portErr := strconv.Atoi(u.Port())
		if portErr != nil || port < 1 || port > 65535 {
			return "", errors.New("Nginx Proxy Manager URL has an invalid port")
		}
	}
	u.Path = strings.TrimRight(u.Path, "/")
	u.RawPath = ""
	return strings.TrimRight(u.String(), "/"), nil
}

func (c *Client) Authenticate(ctx context.Context) error {
	var out struct {
		Token string `json:"token"`
	}
	if err := c.request(ctx, http.MethodPost, "/tokens", map[string]string{"identity": c.email, "secret": c.secret}, &out, false); err != nil {
		return fmt.Errorf("Nginx Proxy Manager login failed: %w", err)
	}
	if strings.TrimSpace(out.Token) == "" {
		return errors.New("Nginx Proxy Manager returned an empty access token")
	}
	c.token = out.Token
	return nil
}

func (c *Client) ListProxyHosts(ctx context.Context) ([]ProxyHost, error) {
	if c.token == "" {
		if err := c.Authenticate(ctx); err != nil {
			return nil, err
		}
	}
	var hosts []ProxyHost
	if err := c.request(ctx, http.MethodGet, "/nginx/proxy-hosts", nil, &hosts, true); err != nil {
		return nil, err
	}
	return hosts, nil
}

func (c *Client) CreateProxyHost(ctx context.Context, in ProxyHostCreate) (string, error) {
	if c.token == "" {
		if err := c.Authenticate(ctx); err != nil {
			return "", err
		}
	}
	var out struct {
		ID json.RawMessage `json:"id"`
	}
	if err := c.request(ctx, http.MethodPost, "/nginx/proxy-hosts", in, &out, true); err != nil {
		return "", err
	}
	id, err := parseID(out.ID)
	if err != nil {
		return "", errors.New("Nginx Proxy Manager created a proxy host without returning its ID")
	}
	id, err = normalizeHostID(id)
	if err != nil {
		return "", errors.New("Nginx Proxy Manager returned an invalid proxy host ID")
	}
	return id, nil
}

func (c *Client) DeleteProxyHost(ctx context.Context, id string) error {
	id, err := normalizeHostID(id)
	if err != nil {
		return err
	}
	if c.token == "" {
		if err = c.Authenticate(ctx); err != nil {
			return err
		}
	}
	err = c.request(ctx, http.MethodDelete, "/nginx/proxy-hosts/"+url.PathEscape(id), nil, nil, true)
	if isHTTPStatus(err, http.StatusNotFound) {
		return nil
	}
	return err
}

func (c *Client) UpdateProxyHost(ctx context.Context, id string, in ProxyHostUpdate) error {
	id, err := normalizeHostID(id)
	if err != nil {
		return err
	}
	if c.token == "" {
		if err = c.Authenticate(ctx); err != nil {
			return err
		}
	}
	return c.request(ctx, http.MethodPut, "/nginx/proxy-hosts/"+url.PathEscape(id), in, nil, true)
}

func normalizeHostID(id string) (string, error) {
	id = strings.TrimSpace(id)
	if id == "" || len(id) > 20 {
		return "", errors.New("invalid Nginx Proxy Manager host ID")
	}
	for _, r := range id {
		if r < '0' || r > '9' {
			return "", errors.New("invalid Nginx Proxy Manager host ID")
		}
	}
	numericID, err := strconv.ParseUint(id, 10, 64)
	if err != nil || numericID == 0 {
		return "", errors.New("invalid Nginx Proxy Manager host ID")
	}
	return strconv.FormatUint(numericID, 10), nil
}

func (c *Client) request(ctx context.Context, method, path string, input, output any, authenticated bool) error {
	var body io.Reader
	if input != nil {
		encoded, err := json.Marshal(input)
		if err != nil {
			return err
		}
		body = bytes.NewReader(encoded)
	}
	apiBase := c.baseURL
	if !strings.HasSuffix(strings.ToLower(apiBase), "/api") {
		apiBase += "/api"
	}
	endpoint := apiBase + path
	req, err := http.NewRequestWithContext(ctx, method, endpoint, body)
	if err != nil {
		return err
	}
	if input != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if authenticated {
		if c.token == "" {
			return errors.New("Nginx Proxy Manager access token is not available")
		}
		req.Header.Set("Authorization", "Bearer "+c.token)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("Nginx Proxy Manager request failed: %w", err)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes+1))
	if err != nil {
		return fmt.Errorf("read Nginx Proxy Manager response: %w", err)
	}
	if len(data) > maxResponseBytes {
		return errors.New("Nginx Proxy Manager response is too large")
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return &httpStatusError{status: resp.StatusCode}
	}
	if output == nil || len(bytes.TrimSpace(data)) == 0 {
		return nil
	}
	if err = json.Unmarshal(data, output); err != nil {
		return fmt.Errorf("invalid Nginx Proxy Manager response: %w", err)
	}
	return nil
}

type httpStatusError struct{ status int }

func (e *httpStatusError) Error() string {
	return fmt.Sprintf("Nginx Proxy Manager returned HTTP %d", e.status)
}

func isHTTPStatus(err error, status int) bool {
	var responseErr *httpStatusError
	return errors.As(err, &responseErr) && responseErr.status == status
}

func parseID(raw json.RawMessage) (string, error) {
	if len(raw) == 0 || string(raw) == "null" {
		return "", errors.New("missing id")
	}
	var text string
	if raw[0] == '"' {
		if err := json.Unmarshal(raw, &text); err != nil {
			return "", err
		}
		if text == "" {
			return "", errors.New("empty id")
		}
		return text, nil
	}
	var number json.Number
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if err := decoder.Decode(&number); err != nil {
		return "", err
	}
	return number.String(), nil
}
