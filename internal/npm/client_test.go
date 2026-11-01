package npm

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
)

type roundTripperFunc func(*http.Request) (*http.Response, error)

func (fn roundTripperFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return fn(request)
}

func jsonResponse(status int, body string) *http.Response {
	return &http.Response{StatusCode: status, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(body))}
}

func TestClientAuthenticatesAndManagesProxyHost(t *testing.T) {
	var auth, create, update, deleted bool
	client, err := NewClient("npm.example.test:81/proxy/", "admin@example.test", "secret", &http.Client{Transport: roundTripperFunc(func(r *http.Request) (*http.Response, error) {
		if r.URL.Scheme != "http" || r.URL.Host != "npm.example.test:81" || !strings.HasPrefix(r.URL.Path, "/proxy/api/") {
			t.Fatalf("unexpected request URL %s", r.URL)
		}
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/proxy/api/tokens":
			var body map[string]string
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body["identity"] != "admin@example.test" || body["secret"] != "secret" {
				t.Fatalf("unexpected token request: %#v, err=%v", body, err)
			}
			auth = true
			return jsonResponse(http.StatusOK, `{"token":"jwt-test"}`), nil
		case r.Method == http.MethodGet && r.URL.Path == "/proxy/api/nginx/proxy-hosts":
			if r.Header.Get("Authorization") != "Bearer jwt-test" {
				t.Fatalf("list request omitted bearer token: %#v", r.Header)
			}
			return jsonResponse(http.StatusOK, `[{"id":12,"domain_names":["play.example.test"]}]`), nil
		case r.Method == http.MethodPost && r.URL.Path == "/proxy/api/nginx/proxy-hosts":
			var body ProxyHostCreate
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Fatal(err)
			}
			if body.ForwardPort != 30100 || body.ForwardHost != "192.168.1.40" || !body.AllowWebsocketUpgrade || !body.BlockExploits || body.HTTP2Support || body.SSLForced {
				t.Fatalf("unexpected proxy-host payload: %#v", body)
			}
			create = true
			return jsonResponse(http.StatusCreated, `{"id":42}`), nil
		case r.Method == http.MethodDelete && r.URL.Path == "/proxy/api/nginx/proxy-hosts/42":
			if r.Header.Get("Authorization") != "Bearer jwt-test" {
				t.Fatalf("delete request omitted bearer token: %#v", r.Header)
			}
			deleted = true
			return jsonResponse(http.StatusOK, `{}`), nil
		case r.Method == http.MethodPut && r.URL.Path == "/proxy/api/nginx/proxy-hosts/42":
			if r.Header.Get("Authorization") != "Bearer jwt-test" {
				t.Fatalf("update request omitted bearer token: %#v", r.Header)
			}
			var body ProxyHostUpdate
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Fatal(err)
			}
			if body.CertificateID != "new" || body.SSLForced == nil || !*body.SSLForced || body.Meta == nil || (*body.Meta)["dns_challenge"] != false {
				t.Fatalf("unexpected proxy-host update payload: %#v", body)
			}
			update = true
			return jsonResponse(http.StatusOK, `{}`), nil
		default:
			t.Fatalf("unexpected request %s %s", r.Method, r.URL.Path)
			return nil, nil
		}
	})})
	if err != nil {
		t.Fatal(err)
	}
	hosts, err := client.ListProxyHosts(context.Background())
	if err != nil || len(hosts) != 1 {
		t.Fatalf("list hosts returned %#v, err=%v", hosts, err)
	}
	hostID, err := client.CreateProxyHost(context.Background(), ProxyHostCreate{DomainNames: []string{"play.example.test"}, ForwardScheme: "http", ForwardHost: "192.168.1.40", ForwardPort: 30100, BlockExploits: true, AllowWebsocketUpgrade: true, Enabled: true})
	if err != nil || hostID != "42" {
		t.Fatalf("create host id=%q err=%v", hostID, err)
	}
	sslForced := true
	meta := map[string]any{"dns_challenge": false}
	if err = client.UpdateProxyHost(context.Background(), hostID, ProxyHostUpdate{CertificateID: "new", SSLForced: &sslForced, Meta: &meta}); err != nil {
		t.Fatalf("update host: %v", err)
	}
	if err = client.DeleteProxyHost(context.Background(), hostID); err != nil {
		t.Fatal(err)
	}
	if !auth || !create || !update || !deleted {
		t.Fatalf("request sequence incomplete: auth=%t create=%t update=%t deleted=%t", auth, create, update, deleted)
	}
}

func TestClientDoesNotFollowRedirectsAndTreatsMissingDeleteAsDone(t *testing.T) {
	calls := 0
	client, err := NewClient("http://npm.example.test:81", "admin@example.test", "secret", &http.Client{Transport: roundTripperFunc(func(r *http.Request) (*http.Response, error) {
		calls++
		if r.URL.Path == "/api/tokens" {
			return jsonResponse(http.StatusOK, `{"token":"jwt-test"}`), nil
		}
		if r.Method == http.MethodDelete {
			return jsonResponse(http.StatusNotFound, `{"error":"missing"}`), nil
		}
		return &http.Response{StatusCode: http.StatusFound, Header: http.Header{"Location": []string{"http://other.example.test/"}}, Body: io.NopCloser(strings.NewReader("redirect"))}, nil
	})})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = client.ListProxyHosts(context.Background()); err == nil || calls != 2 {
		t.Fatalf("redirect should fail without a follow-up request: err=%v calls=%d", err, calls)
	}
	if err = client.DeleteProxyHost(context.Background(), "12"); err != nil {
		t.Fatalf("deleting an already-removed host should succeed: %v", err)
	}
}

func TestClientRejectsUnsafeURLsAndHostIDs(t *testing.T) {
	for _, raw := range []string{"", "ftp://npm.example.test", "http://user:pass@npm.example.test", "http://npm.example.test?token=x"} {
		if _, err := NewClient(raw, "admin@example.test", "secret", nil); err == nil {
			t.Errorf("NewClient(%q) unexpectedly succeeded", raw)
		}
	}
	client, err := NewClient("npm.example.test:81", "admin@example.test", "secret", &http.Client{Transport: roundTripperFunc(func(*http.Request) (*http.Response, error) {
		t.Fatal("unsafe host ID must be rejected before an HTTP request")
		return nil, nil
	})})
	if err != nil {
		t.Fatal(err)
	}
	if err = client.DeleteProxyHost(context.Background(), "../1"); err == nil {
		t.Fatal("path-like proxy-host ID was accepted")
	}
}
