package backup

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"
)

type s3RoundTripper func(*http.Request) (*http.Response, error)

func (f s3RoundTripper) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestS3ClientValidatesEndpointAndBucket(t *testing.T) {
	for _, tc := range []struct {
		name, endpoint, bucket string
		valid                  bool
	}{
		{"secure remote endpoint", "https://objects.example.com", "docklight-backups", true},
		{"loopback emulator", "http://127.0.0.1:9000", "docklight-backups", true},
		{"remote plain HTTP", "http://objects.example.com", "docklight-backups", false},
		{"endpoint credentials", "https://user:password@objects.example.com", "docklight-backups", false},
		{"endpoint query", "https://objects.example.com/?key=hidden", "docklight-backups", false},
		{"invalid bucket", "https://objects.example.com", "My Bucket", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := NewS3Client(tc.endpoint, tc.bucket, "us-east-1", "access", "secret", nil)
			if (err == nil) != tc.valid {
				t.Fatalf("NewS3Client valid=%t err=%v", tc.valid, err)
			}
		})
	}
}

func TestS3SignatureMatchesAWSV4Example(t *testing.T) {
	request, err := http.NewRequest(http.MethodGet, "https://examplebucket.s3.amazonaws.com/?max-keys=2&prefix=J", nil)
	if err != nil {
		t.Fatal(err)
	}
	client := &S3Client{region: "us-east-1", accessKey: "AKIAIOSFODNN7EXAMPLE", secretKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"}
	client.sign(request, emptySHA256(), time.Date(2013, 5, 24, 0, 0, 0, 0, time.UTC))
	want := "AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request,SignedHeaders=host;x-amz-content-sha256;x-amz-date,Signature=34b48302e7b5fa45bde8084f4b7868a86f0a534bc59db6670ed5711ef69dc6f7"
	if got := request.Header.Get("Authorization"); got != want {
		t.Fatalf("Signature V4 header=%q, want %q", got, want)
	}
}

func TestS3ClientPutGetAndDeleteObject(t *testing.T) {
	payload := []byte("encrypted backup archive")
	requests := []string{}
	client, err := NewS3Client("https://objects.example.com/s3", "docklight-backups", "us-east-1", "access", "secret", &http.Client{Transport: s3RoundTripper(func(request *http.Request) (*http.Response, error) {
		requests = append(requests, request.Method+" "+request.URL.EscapedPath())
		if request.URL.EscapedPath() != "/s3/docklight-backups/docklight/server-1/backup-1.dlbak" {
			t.Errorf("path-style object path=%q", request.URL.EscapedPath())
		}
		if !strings.HasPrefix(request.Header.Get("Authorization"), "AWS4-HMAC-SHA256 Credential=access/") || request.Header.Get("X-Amz-Date") == "" {
			t.Errorf("request is not signed: auth=%q date=%q", request.Header.Get("Authorization"), request.Header.Get("X-Amz-Date"))
		}
		switch request.Method {
		case http.MethodPut:
			body, readErr := io.ReadAll(request.Body)
			if readErr != nil || !bytes.Equal(body, payload) {
				t.Errorf("PUT body=%q err=%v", body, readErr)
			}
			hash := sha256.Sum256(payload)
			if got := request.Header.Get("X-Amz-Content-Sha256"); got != hex.EncodeToString(hash[:]) {
				t.Errorf("PUT payload hash=%q", got)
			}
			return s3Response(http.StatusOK, "", nil), nil
		case http.MethodGet:
			if request.Header.Get("X-Amz-Content-Sha256") != emptySHA256() {
				t.Errorf("GET empty payload hash=%q", request.Header.Get("X-Amz-Content-Sha256"))
			}
			return s3Response(http.StatusOK, string(payload), nil), nil
		case http.MethodDelete:
			return s3Response(http.StatusNoContent, "", nil), nil
		default:
			t.Errorf("unexpected method %s", request.Method)
			return s3Response(http.StatusMethodNotAllowed, "", nil), nil
		}
	})})
	if err != nil {
		t.Fatal(err)
	}
	file, err := os.CreateTemp(t.TempDir(), "archive-*.dlbak")
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	if _, err = file.Write(payload); err != nil {
		t.Fatal(err)
	}
	if err = client.PutFile(context.Background(), "docklight/server-1/backup-1.dlbak", file); err != nil {
		t.Fatalf("upload object: %v", err)
	}
	var downloaded bytes.Buffer
	if err = client.GetObject(context.Background(), "docklight/server-1/backup-1.dlbak", &downloaded); err != nil {
		t.Fatalf("download object: %v", err)
	}
	if !bytes.Equal(downloaded.Bytes(), payload) {
		t.Fatalf("downloaded body=%q, want %q", downloaded.Bytes(), payload)
	}
	if err = client.DeleteObject(context.Background(), "docklight/server-1/backup-1.dlbak"); err != nil {
		t.Fatalf("delete object: %v", err)
	}
	wantRequests := []string{
		"PUT /s3/docklight-backups/docklight/server-1/backup-1.dlbak",
		"GET /s3/docklight-backups/docklight/server-1/backup-1.dlbak",
		"DELETE /s3/docklight-backups/docklight/server-1/backup-1.dlbak",
	}
	if strings.Join(requests, "\n") != strings.Join(wantRequests, "\n") {
		t.Fatalf("S3 operations=%v, want %v", requests, wantRequests)
	}
}

func TestS3ClientStreamsSmallObject(t *testing.T) {
	payload := []byte("small streamed backup")
	client, err := NewS3Client("https://objects.example.com", "docklight-backups", "us-east-1", "access", "secret", &http.Client{Transport: s3RoundTripper(func(request *http.Request) (*http.Response, error) {
		if request.Method != http.MethodPut || request.ContentLength != int64(len(payload)) {
			t.Errorf("stream PUT method=%s content-length=%d", request.Method, request.ContentLength)
		}
		body, readErr := io.ReadAll(request.Body)
		if readErr != nil || !bytes.Equal(body, payload) {
			t.Errorf("stream PUT body=%q err=%v", body, readErr)
		}
		hash := sha256.Sum256(payload)
		if request.Header.Get("X-Amz-Content-Sha256") != hex.EncodeToString(hash[:]) {
			t.Errorf("stream PUT did not sign its payload hash")
		}
		return s3Response(http.StatusOK, "", nil), nil
	})})
	if err != nil {
		t.Fatal(err)
	}
	if err = client.Put(context.Background(), "docklight/server-1/backup.dlbak", bytes.NewReader(payload)); err != nil {
		t.Fatalf("stream small object: %v", err)
	}
}

func TestS3ClientMultipartUploadCompletesParts(t *testing.T) {
	const partSize = int64(5 << 20)
	payload := make([]byte, partSize+1)
	client, err := NewS3Client("https://objects.example.com", "docklight-backups", "us-east-1", "access", "secret", &http.Client{Transport: s3RoundTripper(func(request *http.Request) (*http.Response, error) {
		switch request.Method {
		case http.MethodPost:
			if request.URL.RawQuery == "uploads=" {
				return s3Response(http.StatusOK, `<InitiateMultipartUploadResult><UploadId>upload-1</UploadId></InitiateMultipartUploadResult>`, nil), nil
			}
			if request.URL.Query().Get("uploadId") == "upload-1" {
				body, readErr := io.ReadAll(request.Body)
				if readErr != nil || !strings.Contains(string(body), `<PartNumber>1</PartNumber>`) || !strings.Contains(string(body), `<PartNumber>2</PartNumber>`) || !strings.Contains(string(body), `&#34;etag-2&#34;`) {
					t.Errorf("multipart completion body=%s err=%v", body, readErr)
				}
				return s3Response(http.StatusOK, `<CompleteMultipartUploadResult/>`, nil), nil
			}
		case http.MethodPut:
			part := request.URL.Query().Get("partNumber")
			body, readErr := io.ReadAll(request.Body)
			if readErr != nil {
				t.Errorf("read upload part: %v", readErr)
			}
			wantSize := int(partSize)
			if part == "2" {
				wantSize = 1
			}
			if len(body) != wantSize {
				t.Errorf("part %s size=%d, want %d", part, len(body), wantSize)
			}
			headers := make(http.Header)
			headers.Set("ETag", `"etag-`+part+`"`)
			return s3Response(http.StatusOK, "", headers), nil
		}
		t.Errorf("unexpected multipart request %s %s", request.Method, request.URL.String())
		return s3Response(http.StatusBadRequest, "", nil), nil
	})})
	if err != nil {
		t.Fatal(err)
	}
	client.multipartThreshold = partSize
	client.multipartPartSize = partSize
	if err = client.Put(context.Background(), "docklight/server-1/large.dlbak", bytes.NewReader(payload)); err != nil {
		t.Fatalf("multipart upload: %v", err)
	}
}

func TestS3ClientDoesNotFollowRedirects(t *testing.T) {
	calls := 0
	client, err := NewS3Client("https://objects.example.com", "docklight-backups", "us-east-1", "access", "secret", &http.Client{Transport: s3RoundTripper(func(request *http.Request) (*http.Response, error) {
		calls++
		return s3Response(http.StatusTemporaryRedirect, "", http.Header{"Location": []string{"https://other.example.com/"}}), nil
	})})
	if err != nil {
		t.Fatal(err)
	}
	if err = client.GetObject(context.Background(), "docklight/server-1/backup-1.dlbak", io.Discard); err == nil || !strings.Contains(err.Error(), "HTTP 307") {
		t.Fatalf("redirect result=%v, want HTTP 307 failure", err)
	}
	if calls != 1 {
		t.Fatalf("redirect followed %d requests, want one", calls)
	}
}

func TestS3CompatibleEmulatorIntegration(t *testing.T) {
	endpoint := os.Getenv("DOCKLIGHT_S3_TEST_ENDPOINT")
	bucket := os.Getenv("DOCKLIGHT_S3_TEST_BUCKET")
	region := os.Getenv("DOCKLIGHT_S3_TEST_REGION")
	accessKey := os.Getenv("DOCKLIGHT_S3_TEST_ACCESS_KEY")
	secretKey := os.Getenv("DOCKLIGHT_S3_TEST_SECRET_KEY")
	if endpoint == "" || bucket == "" || region == "" || accessKey == "" || secretKey == "" {
		t.Skip("set DOCKLIGHT_S3_TEST_ENDPOINT, _BUCKET, _REGION, _ACCESS_KEY, and _SECRET_KEY to run the S3-compatible emulator acceptance")
	}
	client, err := NewS3Client(endpoint, bucket, region, accessKey, secretKey, nil)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	key := "docklight-integration-checks/" + time.Now().UTC().Format("20060102T150405.000000000") + ".bin"
	payload := []byte("Docklight S3-compatible object-store check")
	if err = client.Put(ctx, key, bytes.NewReader(payload)); err != nil {
		t.Fatalf("upload emulator object: %v", err)
	}
	defer func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cleanupCancel()
		_ = client.DeleteObject(cleanupCtx, key)
	}()
	var got bytes.Buffer
	if err = client.GetObject(ctx, key, &got); err != nil {
		t.Fatalf("download emulator object: %v", err)
	}
	if !bytes.Equal(got.Bytes(), payload) {
		t.Fatalf("emulator returned %d bytes with different contents; want %d", got.Len(), len(payload))
	}
	if err = client.DeleteObject(ctx, key); err != nil {
		t.Fatalf("delete emulator object: %v", err)
	}
}

func s3Response(status int, body string, headers http.Header) *http.Response {
	if headers == nil {
		headers = make(http.Header)
	}
	return &http.Response{StatusCode: status, Header: headers, Body: io.NopCloser(strings.NewReader(body))}
}
