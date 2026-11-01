package backup

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/xml"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"
)

type azureRoundTripper func(*http.Request) (*http.Response, error)

func (roundTrip azureRoundTripper) RoundTrip(request *http.Request) (*http.Response, error) {
	return roundTrip(request)
}

func azureTestResponse(status int, body string) *http.Response {
	return &http.Response{StatusCode: status, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(body))}
}

func TestAzureClientSignsAndStreamsBlockBlobLifecycle(t *testing.T) {
	const accountKey = "ZmFrZS1hY2NvdW50LWtleQ=="
	keyBytes, _ := base64.StdEncoding.DecodeString(accountKey)
	var calls []string
	clientHTTP := &http.Client{Transport: azureRoundTripper(func(request *http.Request) (*http.Response, error) {
		query := request.URL.Query()
		wantPath := "/tenant/backups/folder/archive%20one.tar.gz"
		if request.Method == http.MethodGet && query.Get("comp") == "list" {
			wantPath = "/tenant/backups"
		}
		if request.URL.Host != "storageaccount.blob.core.windows.net" || request.URL.EscapedPath() != wantPath {
			t.Fatalf("unexpected Azure URL: %s", request.URL.String())
		}
		if request.Header.Get("x-ms-version") != azureAPIversion || request.Header.Get("x-ms-date") != "Sun, 01 Nov 2026 12:00:00 GMT" {
			t.Fatalf("missing fixed Azure request headers: %#v", request.Header)
		}
		wantPrefix := "SharedKey storageaccount:"
		authorization := request.Header.Get("Authorization")
		if !strings.HasPrefix(authorization, wantPrefix) {
			t.Fatalf("request did not use Shared Key authorization: %q", authorization)
		}
		wantSignature := azureSharedKeySignature(request, "storageaccount", keyBytes)
		if authorization != wantPrefix+wantSignature {
			t.Fatalf("invalid Shared Key signature: got %q want %q", authorization, wantPrefix+wantSignature)
		}
		switch {
		case request.Method == http.MethodPut && query.Get("comp") == "block":
			if request.ContentLength < 1 || request.ContentLength > 4 {
				t.Fatalf("unexpected block length: %d", request.ContentLength)
			}
			calls = append(calls, "block")
			return azureTestResponse(http.StatusCreated, ""), nil
		case request.Method == http.MethodPut && query.Get("comp") == "blocklist":
			body, err := io.ReadAll(request.Body)
			if err != nil {
				t.Fatal(err)
			}
			var blocks struct {
				XMLName xml.Name `xml:"BlockList"`
				Latest  []string `xml:"Latest"`
			}
			if err = xml.Unmarshal(body, &blocks); err != nil || len(blocks.Latest) != 2 {
				t.Fatalf("invalid committed block list: %#v err=%v body=%s", blocks, err, body)
			}
			calls = append(calls, "commit")
			return azureTestResponse(http.StatusCreated, ""), nil
		case request.Method == http.MethodGet && query.Get("comp") == "list":
			if query.Get("restype") != "container" || query.Get("maxresults") != "1" || query.Get("prefix") != "nightly/" {
				t.Fatalf("unexpected container list query: %s", request.URL.RawQuery)
			}
			calls = append(calls, "list")
			return azureTestResponse(http.StatusOK, "<EnumerationResults></EnumerationResults>"), nil
		case request.Method == http.MethodGet:
			calls = append(calls, "get")
			return azureTestResponse(http.StatusOK, "downloaded archive"), nil
		case request.Method == http.MethodDelete:
			calls = append(calls, "delete")
			return azureTestResponse(http.StatusAccepted, ""), nil
		default:
			t.Fatalf("unexpected Azure request: %s %s", request.Method, request.URL.String())
			return nil, errors.New("unexpected request")
		}
	})}
	client, err := NewAzureClient("https://storageaccount.blob.core.windows.net/tenant", "storageaccount", "backups", "key", accountKey, clientHTTP)
	if err != nil {
		t.Fatal(err)
	}
	client.blockSize = 4
	client.now = func() time.Time { return time.Date(2026, time.November, 1, 12, 0, 0, 0, time.UTC) }
	if err = client.Put(context.Background(), "folder/archive one.tar.gz", strings.NewReader("12345678")); err != nil {
		t.Fatalf("stream Azure object: %v", err)
	}
	if err = client.List(context.Background(), "nightly"); err != nil {
		t.Fatalf("list Azure container: %v", err)
	}
	var downloaded bytes.Buffer
	if err = client.GetObject(context.Background(), "folder/archive one.tar.gz", &downloaded); err != nil {
		t.Fatalf("download Azure object: %v", err)
	}
	if downloaded.String() != "downloaded archive" {
		t.Fatalf("downloaded %q", downloaded.String())
	}
	if err = client.DeleteObject(context.Background(), "folder/archive one.tar.gz"); err != nil {
		t.Fatalf("delete Azure object: %v", err)
	}
	wantCalls := []string{"block", "block", "commit", "list", "get", "delete"}
	if strings.Join(calls, ",") != strings.Join(wantCalls, ",") {
		t.Fatalf("Azure request sequence %v, want %v", calls, wantCalls)
	}
}

func TestAzureSharedKeyCanonicalization(t *testing.T) {
	u, err := url.Parse("https://account.blob.core.windows.net/container/blob?restype=container&comp=metadata&include=snapshots&include=metadata")
	if err != nil {
		t.Fatal(err)
	}
	resource := azureCanonicalizedResource(u, "account")
	wantResource := "/account/container/blob\ncomp:metadata\ninclude:metadata,snapshots\nrestype:container"
	if resource != wantResource {
		t.Fatalf("canonicalized resource\n got: %q\nwant: %q", resource, wantResource)
	}
	request, err := http.NewRequest(http.MethodPut, u.String(), strings.NewReader("payload"))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Content-Type", "application/xml")
	request.Header.Set("x-ms-version", azureAPIversion)
	request.Header.Set("x-ms-date", "Sun, 01 Nov 2026 12:00:00 GMT")
	request.Header.Set("x-ms-meta-z", "  one\t two ")
	request.Header.Set("x-ms-meta-a", "value")
	wantHeaders := "x-ms-date:Sun, 01 Nov 2026 12:00:00 GMT\nx-ms-meta-a:value\nx-ms-meta-z:one two\nx-ms-version:" + azureAPIversion + "\n"
	if got := azureCanonicalizedHeaders(request.Header); got != wantHeaders {
		t.Fatalf("canonicalized headers\n got: %q\nwant: %q", got, wantHeaders)
	}
	key := []byte("test-key")
	got := azureSharedKeySignature(request, "account", key)
	const want = "6hGGeHbpKT1322/mRUKMie7qcGqtsHjMo60vpwrabpA="
	if got != want {
		t.Fatalf("signature = %q, want %q", got, want)
	}
}

func TestAzureSASDoesNotLeakTokenOrFollowRedirects(t *testing.T) {
	const sasToken = "?sv=2023-11-03&sr=c&sp=rwd&se=2027-01-01T00%3A00%3A00Z&sig=topsecret%2Bsignature"
	var calls int
	clientHTTP := &http.Client{Transport: azureRoundTripper(func(request *http.Request) (*http.Response, error) {
		calls++
		if request.Header.Get("Authorization") != "" {
			t.Fatalf("SAS request also had an Authorization header")
		}
		if request.URL.Query().Get("sig") != "topsecret+signature" || request.URL.Query().Get("comp") != "block" {
			t.Fatalf("SAS or operation query was lost: %s", request.URL.String())
		}
		response := azureTestResponse(http.StatusTemporaryRedirect, "")
		response.Header.Set("Location", "https://other.example/steal")
		return response, nil
	})}
	client, err := NewAzureClient("", "storageaccount", "backups", "sas", sasToken, clientHTTP)
	if err != nil {
		t.Fatal(err)
	}
	client.blockSize = 4
	err = client.Put(context.Background(), "backup.tar.gz", strings.NewReader("data"))
	if err == nil || !strings.Contains(err.Error(), "HTTP 307") || strings.Contains(err.Error(), "topsecret") {
		t.Fatalf("expected a redacted redirect error, got %v", err)
	}
	if calls != 1 {
		t.Fatalf("Azure client followed a redirect: received %d requests", calls)
	}

	transportFailure := &http.Client{Transport: azureRoundTripper(func(request *http.Request) (*http.Response, error) {
		return nil, errors.New("failed URL was https://account.blob.core.windows.net/?sig=topsecret")
	})}
	client, err = NewAzureClient("", "storageaccount", "backups", "sas", sasToken, transportFailure)
	if err != nil {
		t.Fatal(err)
	}
	err = client.DeleteObject(context.Background(), "backup.tar.gz")
	if err == nil || strings.Contains(err.Error(), "topsecret") || strings.Contains(err.Error(), "sig=") {
		t.Fatalf("transport error leaked SAS material: %v", err)
	}
}

func TestAzureListReturnsServiceErrorCodeWithoutSAS(t *testing.T) {
	const sasToken = "sv=2023-11-03&sr=c&sp=rlwd&sig=topsecret%2Bsignature"
	clientHTTP := &http.Client{Transport: azureRoundTripper(func(request *http.Request) (*http.Response, error) {
		response := azureTestResponse(http.StatusForbidden, "")
		response.Header.Set("x-ms-error-code", "AuthorizationPermissionMismatch")
		return response, nil
	})}
	client, err := NewAzureClient("", "storageaccount", "backups", "sas", sasToken, clientHTTP)
	if err != nil {
		t.Fatal(err)
	}
	err = client.List(context.Background(), "nightly")
	if err == nil || !strings.Contains(err.Error(), "AuthorizationPermissionMismatch") || !strings.Contains(err.Error(), "HTTP 403") || strings.Contains(err.Error(), "topsecret") {
		t.Fatalf("list error should retain the Azure service code and redact SAS: %v", err)
	}
	clientHTTP.Transport = azureRoundTripper(func(request *http.Request) (*http.Response, error) {
		response := azureTestResponse(http.StatusForbidden, "")
		response.Header.Set("x-ms-error-code", "topsecret")
		return response, nil
	})
	client, err = NewAzureClient("", "storageaccount", "backups", "sas", sasToken, clientHTTP)
	if err != nil {
		t.Fatal(err)
	}
	err = client.List(context.Background(), "nightly")
	if err == nil || strings.Contains(err.Error(), "topsecret") {
		t.Fatalf("server-supplied error code leaked part of the SAS secret: %v", err)
	}
}

func TestAzureEndpointCredentialAndBlobValidation(t *testing.T) {
	cases := []struct {
		name, endpoint, account, container, mode, credential string
		wantErr                                              bool
	}{
		{name: "default endpoint and key", account: "storageaccount", container: "backup-data", mode: "key", credential: "ZmFrZQ=="},
		{name: "custom sovereign endpoint", endpoint: "https://account.blob.core.usgovcloudapi.net", account: "account", container: "backup-data", mode: "sas", credential: "sv=2023-11-03&sr=c&sig=signature"},
		{name: "public plaintext endpoint", endpoint: "http://blob.example.com", account: "storageaccount", container: "backup-data", mode: "key", credential: "ZmFrZQ==", wantErr: true},
		{name: "invalid account key", account: "storageaccount", container: "backup-data", mode: "key", credential: "not-base64", wantErr: true},
		{name: "incomplete SAS", account: "storageaccount", container: "backup-data", mode: "sas", credential: "sv=2023-11-03&sp=r", wantErr: true},
		{name: "uppercase container", account: "storageaccount", container: "Backup-Data", mode: "key", credential: "ZmFrZQ==", wantErr: true},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			_, err := NewAzureClient(test.endpoint, test.account, test.container, test.mode, test.credential, nil)
			if (err != nil) != test.wantErr {
				t.Fatalf("NewAzureClient error = %v, wantErr %t", err, test.wantErr)
			}
		})
	}
}

func TestAzureSharedKeySignatureMatchesExpectedHMAC(t *testing.T) {
	request, err := http.NewRequest(http.MethodDelete, "https://account.blob.core.windows.net/container/blob", nil)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("x-ms-date", "Sun, 01 Nov 2026 12:00:00 GMT")
	request.Header.Set("x-ms-version", azureAPIversion)
	want := "BcWYLHyVqjcArvjW6+jOTFmQshgzV2UrxmPbOnq13v4="
	key := []byte("test-key")
	if got := azureSharedKeySignature(request, "account", key); got != want {
		t.Fatalf("signature = %q, want %q", got, want)
	}
}
