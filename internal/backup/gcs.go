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
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"
)

const (
	gcsAPIEndpoint       = "https://storage.googleapis.com"
	gcsTokenEndpoint     = "https://oauth2.googleapis.com/token"
	gcsStorageScope      = "https://www.googleapis.com/auth/devstorage.read_write"
	gcsDefaultChunkSize  = 16 << 20
	gcsMaximumObjectSize = int64(5 << 40)
)

type gcsServiceAccountKey struct {
	Type         string `json:"type"`
	PrivateKeyID string `json:"private_key_id"`
	PrivateKey   string `json:"private_key"`
	ClientEmail  string `json:"client_email"`
	TokenURI     string `json:"token_uri"`
}

type gcsTokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int64  `json:"expires_in"`
}

// GCSClient stores backup archives as Google Cloud Storage objects using the
// native JSON API. Service-account credentials and OAuth tokens stay in memory,
// requests never follow redirects, and streaming uploads buffer one 16 MiB chunk.
type GCSClient struct {
	bucket     string
	account    gcsServiceAccountKey
	privateKey *rsa.PrivateKey
	httpClient *http.Client
	chunkSize  int
	now        func() time.Time

	tokenMu     sync.Mutex
	accessToken string
	tokenExpiry time.Time
}

func NewGCSClient(bucket, serviceAccountJSON string, httpClient *http.Client) (*GCSClient, error) {
	if !validGCSBucket(bucket) {
		return nil, errors.New("Google Cloud Storage bucket name is invalid")
	}
	if len(serviceAccountJSON) == 0 || len(serviceAccountJSON) > 16*1024 {
		return nil, errors.New("Google service-account JSON must contain 1 to 16384 characters")
	}
	var account gcsServiceAccountKey
	decoder := json.NewDecoder(strings.NewReader(serviceAccountJSON))
	if err := decoder.Decode(&account); err != nil {
		return nil, errors.New("Google service-account credential must be valid JSON")
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return nil, errors.New("Google service-account credential must contain one JSON object")
	}
	if account.Type != "service_account" || account.ClientEmail == "" || len(account.ClientEmail) > 320 || hasControl(account.ClientEmail) {
		return nil, errors.New("Google credential must be a service-account JSON key with a valid client email")
	}
	// Pin the token exchange endpoint instead of trusting a URL from the key file.
	// Google service-account keys use this endpoint; pinning prevents credential SSRF.
	if account.TokenURI != gcsTokenEndpoint {
		return nil, errors.New("Google service-account token_uri must be https://oauth2.googleapis.com/token")
	}
	block, _ := pem.Decode([]byte(account.PrivateKey))
	if block == nil {
		return nil, errors.New("Google service-account private key must be a valid RSA PEM key")
	}
	var privateKey *rsa.PrivateKey
	if parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
		privateKey, _ = parsed.(*rsa.PrivateKey)
	}
	if privateKey == nil {
		privateKey, _ = x509.ParsePKCS1PrivateKey(block.Bytes)
	}
	if privateKey == nil || privateKey.N.BitLen() < 2048 || privateKey.Validate() != nil {
		return nil, errors.New("Google service-account private key must be an RSA key of at least 2048 bits")
	}
	if account.PrivateKeyID != "" && (len(account.PrivateKeyID) > 256 || hasControl(account.PrivateKeyID)) {
		return nil, errors.New("Google service-account private_key_id is invalid")
	}
	if httpClient == nil {
		httpClient = &http.Client{}
	} else {
		copy := *httpClient
		httpClient = &copy
	}
	httpClient.CheckRedirect = func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }
	return &GCSClient{
		bucket:     bucket,
		account:    account,
		privateKey: privateKey,
		httpClient: httpClient,
		chunkSize:  gcsDefaultChunkSize,
		now:        time.Now,
	}, nil
}

func validGCSBucket(value string) bool {
	maximumLength := 63
	if strings.Contains(value, ".") {
		maximumLength = 222
	}
	if len(value) < 3 || len(value) > maximumLength || net.ParseIP(value) != nil || strings.Contains(value, "..") || strings.HasPrefix(value, "goog") {
		return false
	}
	lower := strings.ToLower(value)
	for _, reserved := range []string{"google", "g00gle", "g0ogle", "go0gle", "goog1e"} {
		if strings.Contains(lower, reserved) {
			return false
		}
	}
	for i, r := range value {
		if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '.' || r == '-' || r == '_') {
			return false
		}
		if (i == 0 || i == len(value)-1) && !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9') {
			return false
		}
	}
	for _, label := range strings.Split(value, ".") {
		if label == "" || len(label) > 63 {
			return false
		}
		if strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") || strings.HasPrefix(label, "_") || strings.HasSuffix(label, "_") {
			return false
		}
	}
	return true
}

func validGCSObjectName(name string) bool {
	if name == "" || len(name) > 1024 || !utf8.ValidString(name) || strings.HasPrefix(name, "/") || strings.ContainsAny(name, "\\\x00") || hasControl(name) {
		return false
	}
	for _, segment := range strings.Split(name, "/") {
		if segment == "" || segment == "." || segment == ".." {
			return false
		}
	}
	return true
}

func (c *GCSClient) PutFile(ctx context.Context, name string, file *os.File) error {
	if file == nil {
		return errors.New("Google Cloud Storage upload source file is required")
	}
	if !validGCSObjectName(name) {
		return errors.New("Google Cloud Storage object name is invalid")
	}
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() {
		return errors.New("Google Cloud Storage upload source must be a regular file")
	}
	if info.Size() < 0 || info.Size() > gcsMaximumObjectSize {
		return errors.New("Google Cloud Storage backup must be 5 TiB or smaller")
	}
	if _, err = file.Seek(0, io.SeekStart); err != nil {
		return errors.New("could not rewind Google Cloud Storage backup file")
	}
	return c.put(ctx, name, file, info.Size())
}

// Put streams an unknown-length archive through the GCS resumable-upload API.
// Intermediate Content-Range values use '*' and the final chunk carries the
// completed size, as required for streams whose length is not known in advance.
func (c *GCSClient) Put(ctx context.Context, name string, source io.Reader) error {
	if !validGCSObjectName(name) {
		return errors.New("Google Cloud Storage object name is invalid")
	}
	if source == nil {
		return errors.New("Google Cloud Storage upload source is required")
	}
	return c.put(ctx, name, source, -1)
}

func (c *GCSClient) put(ctx context.Context, name string, source io.Reader, knownSize int64) error {
	if knownSize > gcsMaximumObjectSize {
		return errors.New("Google Cloud Storage backup must be 5 TiB or smaller")
	}
	session, err := c.startResumableUpload(ctx, name, knownSize)
	if err != nil {
		return err
	}
	completed := false
	defer func() {
		if !completed {
			c.cancelResumableUpload(session)
		}
	}()
	chunkSize := c.chunkSize
	if chunkSize < 256<<10 || chunkSize > gcsDefaultChunkSize || chunkSize%(256<<10) != 0 {
		chunkSize = gcsDefaultChunkSize
	}
	buffer := make([]byte, chunkSize)
	var offset int64
	for {
		want := len(buffer)
		if knownSize >= 0 && int64(want) > knownSize-offset {
			want = int(knownSize - offset)
		}
		if want == 0 {
			if knownSize == 0 {
				err = c.uploadChunk(ctx, session, nil, 0, 0, 0, true)
				completed = err == nil
				return err
			}
			completed = true
			return nil
		}
		n, readErr := io.ReadFull(source, buffer[:want])
		if readErr != nil && readErr != io.EOF && readErr != io.ErrUnexpectedEOF {
			return errors.New("could not read Google Cloud Storage backup stream")
		}
		if n == 0 && readErr == io.EOF {
			if knownSize >= 0 && offset != knownSize {
				return errors.New("Google Cloud Storage backup source ended before its declared size")
			}
			if offset == 0 {
				err = c.uploadChunk(ctx, session, nil, 0, 0, 0, true)
				completed = err == nil
				return err
			}
			completed = true
			return nil
		}
		end := offset + int64(n)
		if end > gcsMaximumObjectSize {
			return errors.New("Google Cloud Storage backup must be 5 TiB or smaller")
		}
		final := false
		total := int64(-1)
		if knownSize >= 0 {
			if readErr != nil && end != knownSize {
				return errors.New("Google Cloud Storage backup source ended before its declared size")
			}
			if end == knownSize {
				final = true
				total = knownSize
			}
		} else if readErr == io.EOF || readErr == io.ErrUnexpectedEOF {
			final = true
			total = end
		} else {
			var lookahead [1]byte
			lookaheadN, lookaheadErr := io.ReadFull(source, lookahead[:])
			if lookaheadN == 0 && lookaheadErr == io.EOF {
				final = true
				total = end
			} else if lookaheadN == 1 && lookaheadErr == nil {
				if err = c.uploadChunk(ctx, session, buffer[:n], offset, end-1, -1, false); err != nil {
					return err
				}
				offset = end
				source = io.MultiReader(bytes.NewReader(lookahead[:]), source)
				continue
			} else {
				return errors.New("could not read Google Cloud Storage backup stream")
			}
		}
		if err = c.uploadChunk(ctx, session, buffer[:n], offset, end-1, total, final); err != nil {
			return err
		}
		offset = end
		if final {
			if knownSize < 0 || offset == knownSize {
				completed = true
				return nil
			}
		}
	}
}

func (c *GCSClient) cancelResumableUpload(session *url.URL) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, session.String(), nil)
	if err != nil {
		return
	}
	req.ContentLength = 0
	response, err := c.httpClient.Do(req)
	if err != nil {
		return
	}
	closeGCSResponse(response)
}

func (c *GCSClient) startResumableUpload(ctx context.Context, name string, knownSize int64) (*url.URL, error) {
	token, err := c.token(ctx)
	if err != nil {
		return nil, err
	}
	metadata, err := json.Marshal(struct {
		Name string `json:"name"`
	}{Name: name})
	if err != nil {
		return nil, errors.New("could not prepare Google Cloud Storage object metadata")
	}
	u := url.URL{Scheme: "https", Host: "storage.googleapis.com", Path: "/upload/storage/v1/b/" + c.bucket + "/o"}
	query := url.Values{"uploadType": {"resumable"}}
	u.RawQuery = query.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u.String(), bytes.NewReader(metadata))
	if err != nil {
		return nil, errors.New("could not prepare Google Cloud Storage upload request")
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json; charset=UTF-8")
	req.Header.Set("X-Upload-Content-Type", "application/octet-stream")
	if knownSize >= 0 {
		req.Header.Set("X-Upload-Content-Length", strconv.FormatInt(knownSize, 10))
	}
	response, err := c.httpClient.Do(req)
	if err != nil {
		return nil, safeGCSTransportError("start upload", err)
	}
	defer closeGCSResponse(response)
	if response.StatusCode != http.StatusOK {
		return nil, gcsResponseError("start upload", response.StatusCode)
	}
	session, err := validateGCSSessionURL(response.Header.Get("Location"))
	if err != nil {
		return nil, err
	}
	return session, nil
}

func validateGCSSessionURL(value string) (*url.URL, error) {
	u, err := url.Parse(value)
	hostname := ""
	if u != nil {
		hostname = strings.ToLower(u.Hostname())
	}
	if err != nil || u == nil || !strings.EqualFold(u.Scheme, "https") || u.User != nil || u.Fragment != "" || (u.Port() != "" && u.Port() != "443") || (hostname != "storage.googleapis.com" && hostname != "www.googleapis.com") || !strings.HasPrefix(u.EscapedPath(), "/upload/storage/v1/") {
		return nil, errors.New("Google Cloud Storage returned an invalid resumable upload URL")
	}
	return u, nil
}

func (c *GCSClient) uploadChunk(ctx context.Context, session *url.URL, data []byte, start, end, total int64, final bool) error {
	var body io.Reader
	if len(data) != 0 {
		body = bytes.NewReader(data)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, session.String(), body)
	if err != nil {
		return errors.New("could not prepare Google Cloud Storage upload chunk")
	}
	req.ContentLength = int64(len(data))
	req.Header.Set("Content-Type", "application/octet-stream")
	if len(data) == 0 {
		req.Header.Set("Content-Range", "bytes */0")
	} else if total < 0 {
		req.Header.Set("Content-Range", fmt.Sprintf("bytes %d-%d/*", start, end))
	} else {
		req.Header.Set("Content-Range", fmt.Sprintf("bytes %d-%d/%d", start, end, total))
	}
	response, err := c.httpClient.Do(req)
	if err != nil {
		return safeGCSTransportError("upload", err)
	}
	defer closeGCSResponse(response)
	if final {
		if response.StatusCode != http.StatusOK && response.StatusCode != http.StatusCreated {
			return gcsResponseError("upload", response.StatusCode)
		}
		return nil
	}
	if response.StatusCode != 308 {
		return gcsResponseError("continue upload", response.StatusCode)
	}
	if response.Header.Get("Range") != fmt.Sprintf("bytes=0-%d", end) {
		return errors.New("Google Cloud Storage resumable upload acknowledged an unexpected byte range")
	}
	return nil
}

func (c *GCSClient) GetObject(ctx context.Context, name string, destination io.Writer) error {
	if !validGCSObjectName(name) {
		return errors.New("Google Cloud Storage object name is invalid")
	}
	if destination == nil {
		return errors.New("Google Cloud Storage download destination is required")
	}
	response, err := c.objectRequest(ctx, http.MethodGet, name, url.Values{"alt": {"media"}})
	if err != nil {
		return err
	}
	defer closeGCSResponse(response)
	if response.StatusCode != http.StatusOK {
		return gcsResponseError("download", response.StatusCode)
	}
	if _, err = io.Copy(destination, response.Body); err != nil {
		return errors.New("could not write downloaded Google Cloud Storage backup")
	}
	return nil
}

func (c *GCSClient) DeleteObject(ctx context.Context, name string) error {
	if !validGCSObjectName(name) {
		return errors.New("Google Cloud Storage object name is invalid")
	}
	response, err := c.objectRequest(ctx, http.MethodDelete, name, nil)
	if err != nil {
		return err
	}
	defer closeGCSResponse(response)
	if response.StatusCode != http.StatusNoContent {
		return gcsResponseError("delete", response.StatusCode)
	}
	return nil
}

// List requests at most one result to verify bucket and prefix access without
// downloading a large object listing.
func (c *GCSClient) List(ctx context.Context, prefix string) error {
	prefix = strings.Trim(prefix, "/")
	if prefix != "" && !validGCSObjectName(prefix) {
		return errors.New("Google Cloud Storage object prefix is invalid")
	}
	token, err := c.token(ctx)
	if err != nil {
		return err
	}
	query := url.Values{"maxResults": {"1"}}
	if prefix != "" {
		query.Set("prefix", prefix+"/")
	}
	u := url.URL{Scheme: "https", Host: "storage.googleapis.com", Path: "/storage/v1/b/" + c.bucket + "/o", RawQuery: query.Encode()}
	response, err := c.doAuthorized(ctx, http.MethodGet, u.String(), token, nil)
	if err != nil {
		return err
	}
	defer closeGCSResponse(response)
	if response.StatusCode != http.StatusOK {
		return gcsResponseError("list bucket objects", response.StatusCode)
	}
	return nil
}

func (c *GCSClient) objectRequest(ctx context.Context, method, name string, query url.Values) (*http.Response, error) {
	token, err := c.token(ctx)
	if err != nil {
		return nil, err
	}
	escapedBucket := url.PathEscape(c.bucket)
	escapedName := url.PathEscape(name)
	u := url.URL{
		Scheme:  "https",
		Host:    "storage.googleapis.com",
		Path:    "/storage/v1/b/" + c.bucket + "/o/" + name,
		RawPath: "/storage/v1/b/" + escapedBucket + "/o/" + escapedName,
	}
	if query != nil {
		u.RawQuery = query.Encode()
	}
	return c.doAuthorized(ctx, method, u.String(), token, nil)
}

func (c *GCSClient) doAuthorized(ctx context.Context, method, endpoint, token string, body io.Reader) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, method, endpoint, body)
	if err != nil {
		return nil, errors.New("could not prepare Google Cloud Storage request")
	}
	req.Header.Set("Authorization", "Bearer "+token)
	response, err := c.httpClient.Do(req)
	if err != nil {
		return nil, safeGCSTransportError(strings.ToLower(method), err)
	}
	return response, nil
}

func (c *GCSClient) token(ctx context.Context) (string, error) {
	c.tokenMu.Lock()
	defer c.tokenMu.Unlock()
	now := c.now()
	if c.accessToken != "" && now.Before(c.tokenExpiry) {
		return c.accessToken, nil
	}
	assertion, err := c.serviceAccountJWT(now)
	if err != nil {
		return "", errors.New("could not sign Google service-account assertion")
	}
	form := url.Values{
		"grant_type": {"urn:ietf:params:oauth:grant-type:jwt-bearer"},
		"assertion":  {assertion},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, gcsTokenEndpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return "", errors.New("could not prepare Google OAuth token request")
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	response, err := c.httpClient.Do(req)
	if err != nil {
		return "", safeGCSTransportError("token exchange", err)
	}
	defer closeGCSResponse(response)
	if response.StatusCode != http.StatusOK {
		return "", gcsResponseError("OAuth token exchange", response.StatusCode)
	}
	var result gcsTokenResponse
	decoder := json.NewDecoder(io.LimitReader(response.Body, 1<<20))
	if err = decoder.Decode(&result); err != nil || result.AccessToken == "" || len(result.AccessToken) > 8192 || hasControl(result.AccessToken) || strings.Contains(result.AccessToken, " ") || result.ExpiresIn <= 0 || result.ExpiresIn > 24*60*60 || (result.TokenType != "" && !strings.EqualFold(result.TokenType, "Bearer")) {
		return "", errors.New("Google OAuth returned an invalid access token response")
	}
	c.accessToken = result.AccessToken
	c.tokenExpiry = now.Add(time.Duration(result.ExpiresIn) * time.Second)
	if result.ExpiresIn > 30 {
		c.tokenExpiry = c.tokenExpiry.Add(-30 * time.Second)
	}
	return c.accessToken, nil
}

func (c *GCSClient) serviceAccountJWT(now time.Time) (string, error) {
	header := map[string]string{"alg": "RS256", "typ": "JWT"}
	if c.account.PrivateKeyID != "" {
		header["kid"] = c.account.PrivateKeyID
	}
	headerJSON, err := json.Marshal(header)
	if err != nil {
		return "", err
	}
	issuedAt := now.Unix()
	claimsJSON, err := json.Marshal(map[string]any{
		"iss":   c.account.ClientEmail,
		"scope": gcsStorageScope,
		"aud":   gcsTokenEndpoint,
		"iat":   issuedAt,
		"exp":   issuedAt + 3600,
	})
	if err != nil {
		return "", err
	}
	unsigned := base64.RawURLEncoding.EncodeToString(headerJSON) + "." + base64.RawURLEncoding.EncodeToString(claimsJSON)
	digest := sha256.Sum256([]byte(unsigned))
	signature, err := rsa.SignPKCS1v15(rand.Reader, c.privateKey, crypto.SHA256, digest[:])
	if err != nil {
		return "", err
	}
	return unsigned + "." + base64.RawURLEncoding.EncodeToString(signature), nil
}

func safeGCSTransportError(operation string, err error) error {
	if errors.Is(err, context.Canceled) {
		return fmt.Errorf("Google Cloud Storage %s request was canceled", operation)
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return fmt.Errorf("Google Cloud Storage %s request timed out", operation)
	}
	var networkErr net.Error
	if errors.As(err, &networkErr) && networkErr.Timeout() {
		return fmt.Errorf("Google Cloud Storage %s request timed out", operation)
	}
	return fmt.Errorf("Google Cloud Storage %s request failed; check panel-host connectivity", operation)
}

func gcsResponseError(operation string, status int) error {
	return fmt.Errorf("Google Cloud Storage %s failed with HTTP %d", operation, status)
}

func closeGCSResponse(response *http.Response) {
	if response == nil || response.Body == nil {
		return
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 1<<20))
	_ = response.Body.Close()
}
