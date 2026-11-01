// Package unifi provides the local UniFi Network controller API used by Docklight.
package unifi

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"
	"time"
)

const maxResponseBytes = 1 << 20

type PortForward struct {
	ID       string          `json:"_id"`
	Name     string          `json:"name"`
	Enabled  bool            `json:"enabled"`
	Proto    string          `json:"proto"`
	Protocol string          `json:"protocol"`
	DstPort  json.RawMessage `json:"dst_port"`
	Fwd      string          `json:"fwd"`
	FwdPort  json.RawMessage `json:"fwd_port"`
	Internal string          `json:"internal_ip"`
	IntPort  json.RawMessage `json:"internal_port"`
}

type PortForwardCreate struct {
	Name        string `json:"name"`
	Enabled     bool   `json:"enabled"`
	Proto       string `json:"proto"`
	Source      string `json:"src"`
	Destination string `json:"dst"`
	SrcPort     string `json:"src_port"`
	DstPort     string `json:"dst_port"`
	ForwardTo   string `json:"fwd"`
	ForwardPort string `json:"fwd_port"`
}

type envelope struct {
	Meta struct {
		RC string `json:"rc"`
	} `json:"meta"`
	Data json.RawMessage `json:"data"`
}

type Client struct {
	base   *url.URL
	http   *http.Client
	csrf   string
	prefix string
}

// New authenticates to a local controller and returns a cookie-scoped session.
// A caller-supplied client is useful for tests; otherwise a TLS client that accepts
// locally issued controller certificates is configured as requested by Docklight.
func New(ctx context.Context, controllerURL, username, password string, injected *http.Client) (*Client, error) {
	base, err := url.Parse(controllerURL)
	if err != nil || base.Hostname() == "" || (base.Scheme != "http" && base.Scheme != "https") {
		return nil, errors.New("UniFi controller URL is invalid")
	}
	var client http.Client
	if injected != nil {
		client = *injected
	} else {
		transport := http.DefaultTransport.(*http.Transport).Clone()
		// The integration explicitly accepts locally issued and self-signed certificates.
		transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
		client.Transport = transport
	}
	if client.Timeout <= 0 {
		client.Timeout = 12 * time.Second
	}
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	jar, err := cookiejar.New(nil)
	if err != nil {
		return nil, errors.New("could not prepare UniFi login session")
	}
	client.Jar = jar
	controller := &Client{base: base, http: &client}
	if err = controller.login(ctx, username, password); err != nil {
		return nil, err
	}
	return controller, nil
}

func (c *Client) login(ctx context.Context, username, password string) error {
	body, _ := json.Marshal(map[string]any{"username": username, "password": password, "rememberMe": true})
	for _, route := range []string{"/api/auth/login", "/api/login"} {
		resp, raw, err := c.request(ctx, http.MethodPost, route, body)
		if err != nil {
			return errors.New("could not reach the UniFi controller")
		}
		if resp.StatusCode == http.StatusNotFound || resp.StatusCode == http.StatusMethodNotAllowed {
			continue
		}
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			return fmt.Errorf("UniFi login failed with HTTP %d; verify the local account and controller URL", resp.StatusCode)
		}
		if err = checkEnvelope(raw); err != nil {
			return errors.New("UniFi rejected the local login; verify the username and password")
		}
		if len(c.http.Jar.Cookies(c.base)) == 0 {
			return errors.New("UniFi login did not establish an authenticated session")
		}
		c.csrf = resp.Header.Get("X-CSRF-Token")
		return nil
	}
	return errors.New("UniFi controller does not expose a supported local login endpoint")
}

func (c *Client) ListPortForwards(ctx context.Context, site string) ([]PortForward, error) {
	if err := c.ensurePrefix(ctx, site); err != nil {
		return nil, err
	}
	resp, raw, err := c.request(ctx, http.MethodGet, c.rulePath(site, ""), nil)
	if err != nil {
		return nil, errors.New("could not read UniFi port-forward rules")
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("UniFi rule listing returned HTTP %d", resp.StatusCode)
	}
	if err = checkEnvelope(raw); err != nil {
		return nil, err
	}
	var result envelope
	if err = json.Unmarshal(raw, &result); err != nil {
		return nil, errors.New("UniFi returned an invalid port-forward rule list")
	}
	if len(result.Data) == 0 || string(result.Data) == "null" {
		return nil, errors.New("UniFi returned no port-forward rule data; cleanup was not attempted")
	}
	var rules []PortForward
	if err = json.Unmarshal(result.Data, &rules); err != nil {
		return nil, errors.New("UniFi returned an invalid port-forward rule list")
	}
	return rules, nil
}

func (c *Client) CreatePortForward(ctx context.Context, site string, rule PortForwardCreate) error {
	if err := c.ensurePrefix(ctx, site); err != nil {
		return err
	}
	body, _ := json.Marshal(rule)
	resp, raw, err := c.request(ctx, http.MethodPost, c.rulePath(site, ""), body)
	if err != nil {
		return errors.New("could not create the UniFi port-forward rule")
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("UniFi rejected a port-forward rule with HTTP %d", resp.StatusCode)
	}
	return checkEnvelope(raw)
}

func (c *Client) DeletePortForward(ctx context.Context, site, id string) error {
	if id == "" || strings.Contains(id, "/") {
		return errors.New("UniFi returned an invalid rule ID")
	}
	if err := c.ensurePrefix(ctx, site); err != nil {
		return err
	}
	resp, raw, err := c.request(ctx, http.MethodDelete, c.rulePath(site, id), nil)
	if err != nil {
		return errors.New("could not remove the UniFi port-forward rule")
	}
	if resp.StatusCode == http.StatusNotFound {
		return nil
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("UniFi rule removal returned HTTP %d", resp.StatusCode)
	}
	return checkEnvelope(raw)
}

func (c *Client) ensurePrefix(ctx context.Context, site string) error {
	if c.prefix != "" {
		return nil
	}
	for _, prefix := range []string{"/proxy/network/api", "/api"} {
		path := prefix + "/s/" + url.PathEscape(site) + "/rest/portforward"
		resp, raw, err := c.request(ctx, http.MethodGet, path, nil)
		if err != nil {
			return errors.New("could not reach the UniFi port-forward API")
		}
		if resp.StatusCode == http.StatusNotFound || resp.StatusCode == http.StatusMethodNotAllowed {
			continue
		}
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			return fmt.Errorf("UniFi rule listing returned HTTP %d", resp.StatusCode)
		}
		if err = checkEnvelope(raw); err != nil {
			return err
		}
		c.prefix = prefix
		return nil
	}
	return errors.New("UniFi controller did not provide the classic site port-forward endpoint; check its Network > Integrations API documentation")
}

func (c *Client) rulePath(site, id string) string {
	path := c.prefix + "/s/" + url.PathEscape(site) + "/rest/portforward"
	if id != "" {
		path += "/" + url.PathEscape(id)
	}
	return path
}

func (c *Client) request(ctx context.Context, method, route string, body []byte) (*http.Response, []byte, error) {
	u := *c.base
	u.Path = strings.TrimRight(c.base.Path, "/") + route
	var reader io.Reader
	if body != nil {
		reader = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, u.String(), reader)
	if err != nil {
		return nil, nil, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "Docklight/1.0")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if c.csrf != "" {
		req.Header.Set("X-CSRF-Token", c.csrf)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, nil, err
	}
	data, readErr := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes+1))
	_ = resp.Body.Close()
	if readErr != nil {
		return resp, nil, readErr
	}
	if len(data) > maxResponseBytes {
		return resp, nil, errors.New("UniFi response exceeded the 1 MiB limit")
	}
	return resp, data, nil
}

func checkEnvelope(raw []byte) error {
	if len(bytes.TrimSpace(raw)) == 0 {
		return nil
	}
	var result envelope
	if json.Unmarshal(raw, &result) != nil || result.Meta.RC == "" || strings.EqualFold(result.Meta.RC, "ok") {
		return nil
	}
	return fmt.Errorf("UniFi controller returned status %q", result.Meta.RC)
}
