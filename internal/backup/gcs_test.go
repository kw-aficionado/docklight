package backup

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type gcsRoundTripper func(*http.Request) (*http.Response, error)

func (roundTrip gcsRoundTripper) RoundTrip(request *http.Request) (*http.Response, error) {
	return roundTrip(request)
}

type gcsErrorReader struct{}

func (gcsErrorReader) Read([]byte) (int, error) { return 0, errors.New("sensitive source failure") }

func gcsTestResponse(status int, body string, headers http.Header) *http.Response {
	if headers == nil {
		headers = make(http.Header)
	}
	return &http.Response{StatusCode: status, Header: headers, Body: io.NopCloser(strings.NewReader(body))}
}

func gcsTestCredentials(t *testing.T) (string, *rsa.PrivateKey) {
	t.Helper()
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		t.Fatal(err)
	}
	key := gcsServiceAccountKey{
		Type:         "service_account",
		PrivateKeyID: "test-key-id",
		PrivateKey:   string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: encoded})),
		ClientEmail:  "docklight-backups@example-project.iam.gserviceaccount.com",
		TokenURI:     gcsTokenEndpoint,
	}
	data, err := json.MarshalIndent(key, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	return string(data), privateKey
}

func TestGCSClientNativeAPIAndStreamingOAuth(t *testing.T) {
	credentials, privateKey := gcsTestCredentials(t)
	now := time.Date(2026, time.November, 1, 12, 30, 0, 0, time.UTC)
	objectName := "docklight/server-1/backup-1.dlbak"
	payload := bytes.Repeat([]byte("g"), (256<<10)+3)
	var tokenRequests, listRequests, initRequests, chunkRequests, getRequests, deleteRequests int
	clientHTTP := &http.Client{Transport: gcsRoundTripper(func(request *http.Request) (*http.Response, error) {
		switch {
		case request.URL.String() == gcsTokenEndpoint:
			tokenRequests++
			if request.Method != http.MethodPost || request.Header.Get("Content-Type") != "application/x-www-form-urlencoded" || request.Header.Get("Authorization") != "" {
				t.Fatalf("unexpected OAuth request: %s %s %#v", request.Method, request.URL, request.Header)
			}
			form, err := io.ReadAll(request.Body)
			if err != nil {
				t.Fatal(err)
			}
			values, err := url.ParseQuery(string(form))
			if err != nil || values.Get("grant_type") != "urn:ietf:params:oauth:grant-type:jwt-bearer" {
				t.Fatalf("invalid OAuth form %q err=%v", form, err)
			}
			parts := strings.Split(values.Get("assertion"), ".")
			if len(parts) != 3 {
				t.Fatalf("malformed JWT assertion %q", values.Get("assertion"))
			}
			headerData, _ := base64.RawURLEncoding.DecodeString(parts[0])
			claimData, _ := base64.RawURLEncoding.DecodeString(parts[1])
			var header map[string]string
			var claims map[string]any
			if json.Unmarshal(headerData, &header) != nil || json.Unmarshal(claimData, &claims) != nil {
				t.Fatalf("decode service-account JWT: header=%s claims=%s", headerData, claimData)
			}
			if header["alg"] != "RS256" || header["kid"] != "test-key-id" || claims["iss"] != "docklight-backups@example-project.iam.gserviceaccount.com" || claims["scope"] != gcsStorageScope || claims["aud"] != gcsTokenEndpoint || claims["iat"] != float64(now.Unix()) || claims["exp"] != float64(now.Unix()+3600) {
				t.Fatalf("unexpected service-account JWT: header=%v claims=%v", header, claims)
			}
			unsigned := parts[0] + "." + parts[1]
			digest := sha256.Sum256([]byte(unsigned))
			signature, err := base64.RawURLEncoding.DecodeString(parts[2])
			if err != nil || rsa.VerifyPKCS1v15(&privateKey.PublicKey, crypto.SHA256, digest[:], signature) != nil {
				t.Fatal("service-account JWT signature was not valid")
			}
			return gcsTestResponse(http.StatusOK, `{"access_token":"gcs-access-token","token_type":"Bearer","expires_in":3600}`, nil), nil
		case request.Method == http.MethodGet && request.URL.Path == "/storage/v1/b/docklight-backups/o":
			listRequests++
			if request.Header.Get("Authorization") != "Bearer gcs-access-token" || request.URL.Query().Get("maxResults") != "1" || request.URL.Query().Get("prefix") != "nightly/" {
				t.Fatalf("unexpected GCS list request: %s %s %#v", request.URL, request.URL.RawQuery, request.Header)
			}
			return gcsTestResponse(http.StatusOK, `{"kind":"storage#objects"}`, nil), nil
		case request.Method == http.MethodPost && request.URL.Path == "/upload/storage/v1/b/docklight-backups/o":
			initRequests++
			metadata, _ := io.ReadAll(request.Body)
			var object map[string]string
			if request.Header.Get("Authorization") != "Bearer gcs-access-token" || request.URL.Query().Get("uploadType") != "resumable" || request.Header.Get("X-Upload-Content-Type") != "application/octet-stream" || json.Unmarshal(metadata, &object) != nil || object["name"] != objectName || request.Header.Get("X-Upload-Content-Length") != "" {
				t.Fatalf("unexpected GCS upload initiation: %s %s %#v metadata=%s", request.URL, request.URL.RawQuery, request.Header, metadata)
			}
			headers := make(http.Header)
			headers.Set("Location", "https://storage.googleapis.com/upload/storage/v1/b/docklight-backups/o?upload_id=opaque-session")
			return gcsTestResponse(http.StatusOK, "", headers), nil
		case request.Method == http.MethodPut && strings.Contains(request.URL.RawQuery, "upload_id=opaque-session"):
			chunkRequests++
			if request.Header.Get("Authorization") != "" {
				t.Fatal("OAuth token was sent to the resumable-upload session URL")
			}
			chunk, _ := io.ReadAll(request.Body)
			if int64(len(chunk)) != request.ContentLength {
				t.Fatalf("chunk Content-Length=%d, actual=%d", request.ContentLength, len(chunk))
			}
			if chunkRequests == 1 {
				if len(chunk) != 256<<10 || request.Header.Get("Content-Range") != "bytes 0-262143/*" {
					t.Fatalf("first streamed chunk: size=%d range=%q", len(chunk), request.Header.Get("Content-Range"))
				}
				headers := make(http.Header)
				headers.Set("Range", "bytes=0-262143")
				return gcsTestResponse(308, "", headers), nil
			}
			if len(chunk) != 3 || request.Header.Get("Content-Range") != "bytes 262144-262146/262147" {
				t.Fatalf("final streamed chunk: size=%d range=%q", len(chunk), request.Header.Get("Content-Range"))
			}
			all := append(bytes.Repeat([]byte("g"), 256<<10), chunk...)
			if !bytes.Equal(all, payload) {
				t.Fatal("resumable upload data changed between chunks")
			}
			return gcsTestResponse(http.StatusOK, `{"name":"docklight/server-1/backup-1.dlbak"}`, nil), nil
		case request.Method == http.MethodGet && request.URL.Query().Get("alt") == "media":
			getRequests++
			if request.Header.Get("Authorization") != "Bearer gcs-access-token" || !strings.Contains(request.URL.EscapedPath(), "docklight%2Fserver-1%2Fbackup-1.dlbak") {
				t.Fatalf("unexpected GCS object download: path=%s escaped=%s", request.URL.Path, request.URL.EscapedPath())
			}
			return gcsTestResponse(http.StatusOK, string(payload), nil), nil
		case request.Method == http.MethodDelete:
			deleteRequests++
			if request.Header.Get("Authorization") != "Bearer gcs-access-token" || !strings.Contains(request.URL.EscapedPath(), "docklight%2Fserver-1%2Fbackup-1.dlbak") {
				t.Fatalf("unexpected GCS object delete: %s", request.URL)
			}
			return gcsTestResponse(http.StatusNoContent, "", nil), nil
		default:
			t.Fatalf("unexpected request: %s %s", request.Method, request.URL)
			return nil, nil
		}
	})}
	client, err := NewGCSClient("docklight-backups", credentials, clientHTTP)
	if err != nil {
		t.Fatal(err)
	}
	client.now = func() time.Time { return now }
	client.chunkSize = 256 << 10
	ctx := context.Background()
	if err = client.List(ctx, "nightly"); err != nil {
		t.Fatal(err)
	}
	if err = client.Put(ctx, objectName, bytes.NewReader(payload)); err != nil {
		t.Fatal(err)
	}
	var downloaded bytes.Buffer
	if err = client.GetObject(ctx, objectName, &downloaded); err != nil || !bytes.Equal(downloaded.Bytes(), payload) {
		t.Fatalf("downloaded GCS object differs: bytes=%d err=%v", downloaded.Len(), err)
	}
	if err = client.DeleteObject(ctx, objectName); err != nil {
		t.Fatal(err)
	}
	if tokenRequests != 1 || listRequests != 1 || initRequests != 1 || chunkRequests != 2 || getRequests != 1 || deleteRequests != 1 {
		t.Fatalf("request counts: token=%d list=%d init=%d chunks=%d get=%d delete=%d", tokenRequests, listRequests, initRequests, chunkRequests, getRequests, deleteRequests)
	}
}

func TestGCSClientPutFileUsesKnownLengthAndEmptyObject(t *testing.T) {
	credentials, _ := gcsTestCredentials(t)
	var tokenCount, startCount, uploadCount int
	clientHTTP := &http.Client{Transport: gcsRoundTripper(func(request *http.Request) (*http.Response, error) {
		switch {
		case request.URL.String() == gcsTokenEndpoint:
			tokenCount++
			return gcsTestResponse(http.StatusOK, `{"access_token":"ok","expires_in":3600}`, nil), nil
		case request.Method == http.MethodPost:
			startCount++
			wantSize := "3"
			if startCount == 2 {
				wantSize = "0"
			}
			if request.Header.Get("X-Upload-Content-Length") != wantSize {
				t.Fatalf("upload initiation size=%q, want %q", request.Header.Get("X-Upload-Content-Length"), wantSize)
			}
			headers := make(http.Header)
			headers.Set("Location", "https://www.googleapis.com/upload/storage/v1/b/docklight-backups/o?upload_id=test")
			return gcsTestResponse(http.StatusOK, "", headers), nil
		case request.Method == http.MethodPut:
			uploadCount++
			if uploadCount == 1 && request.Header.Get("Content-Range") != "bytes 0-2/3" {
				t.Fatalf("known-size upload headers: %#v", request.Header)
			}
			if uploadCount == 2 && (request.Header.Get("Content-Range") != "bytes */0" || request.ContentLength != 0) {
				t.Fatalf("empty-object upload headers: %#v content-length=%d", request.Header, request.ContentLength)
			}
			return gcsTestResponse(http.StatusOK, "", nil), nil
		default:
			t.Fatalf("unexpected request %s %s", request.Method, request.URL)
			return nil, nil
		}
	})}
	client, err := NewGCSClient("docklight-backups", credentials, clientHTTP)
	if err != nil {
		t.Fatal(err)
	}
	filePath := filepath.Join(t.TempDir(), "small.dlbak")
	if err = os.WriteFile(filePath, []byte("abc"), 0600); err != nil {
		t.Fatal(err)
	}
	file, err := os.Open(filePath)
	if err != nil {
		t.Fatal(err)
	}
	if err = client.PutFile(context.Background(), "small.dlbak", file); err != nil {
		t.Fatal(err)
	}
	_ = file.Close()
	emptyPath := filepath.Join(t.TempDir(), "empty.dlbak")
	if err = os.WriteFile(emptyPath, nil, 0600); err != nil {
		t.Fatal(err)
	}
	empty, err := os.Open(emptyPath)
	if err != nil {
		t.Fatal(err)
	}
	if err = client.PutFile(context.Background(), "empty.dlbak", empty); err != nil {
		t.Fatal(err)
	}
	_ = empty.Close()
	if tokenCount != 1 || startCount != 2 || uploadCount != 2 {
		t.Fatalf("request counts: token=%d start=%d uploads=%d", tokenCount, startCount, uploadCount)
	}
}

func TestGCSClientRejectsUnsafeCredentialsSessionAndRedirect(t *testing.T) {
	credentials, _ := gcsTestCredentials(t)
	var key gcsServiceAccountKey
	if err := json.Unmarshal([]byte(credentials), &key); err != nil {
		t.Fatal(err)
	}
	key.TokenURI = "https://attacker.example/token"
	unsafe, _ := json.Marshal(key)
	if _, err := NewGCSClient("docklight-backups", string(unsafe), nil); err == nil {
		t.Fatal("accepted a service-account token endpoint outside Google's OAuth endpoint")
	}
	for _, bucket := range []string{"", "..bad", "1.2.3.4", "a", "Bad_Bucket"} {
		if _, err := NewGCSClient(bucket, credentials, nil); err == nil {
			t.Fatalf("accepted invalid bucket %q", bucket)
		}
	}
	longDottedBucket := strings.Repeat("backup.", 30) + "backup"
	if _, err := NewGCSClient(longDottedBucket, credentials, nil); err != nil {
		t.Fatalf("rejected a valid dotted GCS bucket name: %v", err)
	}
	if _, err := NewGCSClient("docklight_backups", credentials, nil); err != nil {
		t.Fatalf("rejected a valid underscore GCS bucket name: %v", err)
	}
	var storageRequests int
	clientHTTP := &http.Client{Transport: gcsRoundTripper(func(request *http.Request) (*http.Response, error) {
		if request.URL.String() == gcsTokenEndpoint {
			return gcsTestResponse(http.StatusOK, `{"access_token":"do-not-leak-this-token","expires_in":3600}`, nil), nil
		}
		storageRequests++
		headers := make(http.Header)
		headers.Set("Location", "https://storage.googleapis.com:8443/upload/storage/v1/b/docklight-backups/o?token=secret")
		return gcsTestResponse(http.StatusFound, "sensitive error details", headers), nil
	})}
	client, err := NewGCSClient("docklight-backups", credentials, clientHTTP)
	if err != nil {
		t.Fatal(err)
	}
	err = client.List(context.Background(), "")
	if err == nil || strings.Contains(err.Error(), "do-not-leak-this-token") || strings.Contains(err.Error(), "sensitive error details") || storageRequests != 1 {
		t.Fatalf("redirect response was followed or leaked data: err=%v storage requests=%d", err, storageRequests)
	}

	clientHTTP.Transport = gcsRoundTripper(func(request *http.Request) (*http.Response, error) {
		if request.URL.String() == gcsTokenEndpoint {
			return gcsTestResponse(http.StatusOK, `{"access_token":"ok","expires_in":3600}`, nil), nil
		}
		headers := make(http.Header)
		headers.Set("Location", "https://storage.googleapis.com:8443/upload/storage/v1/b/docklight-backups/o?token=secret")
		return gcsTestResponse(http.StatusOK, "", headers), nil
	})
	clientHTTP2 := &http.Client{Transport: clientHTTP.Transport}
	badSessionClient, err := NewGCSClient("docklight-backups", credentials, clientHTTP2)
	if err != nil {
		t.Fatal(err)
	}
	if err = badSessionClient.Put(context.Background(), "backup.dlbak", strings.NewReader("data")); err == nil || strings.Contains(err.Error(), "storage.googleapis.com") || strings.Contains(err.Error(), "secret") {
		t.Fatalf("unsafe resumable upload URL was accepted or exposed: %v", err)
	}
}

func TestGCSClientCancelsIncompleteUploadWithoutExposingSessionURL(t *testing.T) {
	credentials, _ := gcsTestCredentials(t)
	var cancelRequests int
	clientHTTP := &http.Client{Transport: gcsRoundTripper(func(request *http.Request) (*http.Response, error) {
		switch {
		case request.URL.String() == gcsTokenEndpoint:
			return gcsTestResponse(http.StatusOK, `{"access_token":"ok","expires_in":3600}`, nil), nil
		case request.Method == http.MethodPost:
			headers := make(http.Header)
			headers.Set("Location", "https://storage.googleapis.com/upload/storage/v1/b/docklight-backups/o?upload_id=private-session-token")
			return gcsTestResponse(http.StatusOK, "", headers), nil
		case request.Method == http.MethodDelete:
			cancelRequests++
			if request.Header.Get("Authorization") != "" || request.ContentLength != 0 || !strings.Contains(request.URL.RawQuery, "private-session-token") {
				t.Fatalf("unexpected resumable-session cancellation: %#v url=%s", request.Header, request.URL)
			}
			return gcsTestResponse(499, "", nil), nil
		default:
			t.Fatalf("unexpected request: %s %s", request.Method, request.URL)
			return nil, nil
		}
	})}
	client, err := NewGCSClient("docklight-backups", credentials, clientHTTP)
	if err != nil {
		t.Fatal(err)
	}
	err = client.Put(context.Background(), "backup.dlbak", gcsErrorReader{})
	if err == nil || strings.Contains(err.Error(), "sensitive source failure") || strings.Contains(err.Error(), "private-session-token") || cancelRequests != 1 {
		t.Fatalf("incomplete upload was not safely canceled: err=%v cancel requests=%d", err, cancelRequests)
	}
}
