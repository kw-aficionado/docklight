package backup

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	azureAPIversion       = "2023-11-03"
	azureDefaultBlockSize = 16 << 20
	azureMaximumObject    = int64(800_000_000_000)
	azureMaximumBlocks    = 50_000
)

// AzureClient stores backup objects as Azure block blobs. It supports Shared
// Key account credentials and SAS tokens, and never follows redirects so that
// credentials cannot be forwarded to another host.
type AzureClient struct {
	endpoint   *url.URL
	account    string
	container  string
	authMode   string
	credential string
	httpClient *http.Client
	blockSize  int64
	now        func() time.Time
}

func NewAzureClient(endpoint, account, container, authMode, credential string, httpClient *http.Client) (*AzureClient, error) {
	account = strings.TrimSpace(account)
	if !validAzureAccountName(account) {
		return nil, errors.New("Azure account name must contain 3 to 24 lowercase letters or numbers")
	}
	if !validAzureContainer(container) {
		return nil, errors.New("Azure container must be a 3 to 63 character lowercase DNS-style name")
	}
	if credential == "" || len(credential) > 8192 || hasControl(credential) {
		return nil, errors.New("Azure credential must contain 1 to 8192 printable characters")
	}
	authMode = strings.TrimSpace(authMode)
	switch authMode {
	case "key":
		key, err := base64.StdEncoding.Strict().DecodeString(credential)
		if err != nil || len(key) == 0 {
			return nil, errors.New("Azure account key must be a valid base64 value")
		}
	case "sas":
		normalized, err := normalizeAzureSAS(credential)
		if err != nil {
			return nil, err
		}
		credential = normalized
	default:
		return nil, errors.New("Azure authentication must be account key or SAS token")
	}
	u, err := normalizeAzureEndpoint(endpoint, account)
	if err != nil {
		return nil, err
	}
	if httpClient == nil {
		httpClient = &http.Client{}
	} else {
		copy := *httpClient
		httpClient = &copy
	}
	httpClient.CheckRedirect = func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }
	return &AzureClient{
		endpoint:   u,
		account:    account,
		container:  container,
		authMode:   authMode,
		credential: credential,
		httpClient: httpClient,
		blockSize:  azureDefaultBlockSize,
		now:        time.Now,
	}, nil
}

func validAzureAccountName(value string) bool {
	if len(value) < 3 || len(value) > 24 {
		return false
	}
	for _, r := range value {
		if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9') {
			return false
		}
	}
	return true
}

func validAzureContainer(value string) bool {
	if len(value) < 3 || len(value) > 63 || value[0] == '-' || value[len(value)-1] == '-' || strings.Contains(value, "--") {
		return false
	}
	for _, r := range value {
		if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-') {
			return false
		}
	}
	return true
}

func normalizeAzureEndpoint(value, account string) (*url.URL, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		value = "https://" + account + ".blob.core.windows.net"
	}
	u, err := url.Parse(value)
	if err != nil || !u.IsAbs() || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return nil, errors.New("Azure endpoint must be an absolute HTTP(S) URL without credentials, a query, or a fragment")
	}
	u.Scheme = strings.ToLower(u.Scheme)
	switch u.Scheme {
	case "https":
	case "http":
		host := strings.TrimSuffix(strings.ToLower(u.Hostname()), ".")
		ip := net.ParseIP(host)
		if host != "localhost" && (ip == nil || !ip.IsLoopback()) {
			return nil, errors.New("Azure endpoints must use HTTPS; plain HTTP is allowed only for localhost loopback testing")
		}
	default:
		return nil, errors.New("Azure endpoint must use HTTPS")
	}
	for _, segment := range strings.Split(u.EscapedPath(), "/") {
		decoded, decodeErr := url.PathUnescape(segment)
		if decodeErr != nil || decoded == "." || decoded == ".." {
			return nil, errors.New("Azure endpoint path cannot contain dot segments")
		}
	}
	u.Path = strings.TrimRight(u.Path, "/")
	u.RawPath = ""
	return u, nil
}

func normalizeAzureSAS(value string) (string, error) {
	value = strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(value), "?"))
	if value == "" || len(value) > 8192 || hasControl(value) || strings.Contains(value, "#") {
		return "", errors.New("enter a valid Azure SAS token")
	}
	values, err := url.ParseQuery(value)
	if err != nil || values.Get("sv") == "" || values.Get("sig") == "" {
		return "", errors.New("Azure SAS token must include its service version and signature")
	}
	return values.Encode(), nil
}

func validAzureObjectKey(key string) bool {
	if key == "" || len(key) > 1024 || strings.HasPrefix(key, "/") || strings.ContainsAny(key, "\\\x00") || hasControl(key) {
		return false
	}
	for _, segment := range strings.Split(key, "/") {
		if segment == "" || segment == "." || segment == ".." {
			return false
		}
	}
	return true
}

func (c *AzureClient) PutFile(ctx context.Context, key string, file *os.File) error {
	if file == nil {
		return errors.New("Azure upload source file is required")
	}
	if !validAzureObjectKey(key) {
		return errors.New("Azure blob name is invalid")
	}
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() {
		return errors.New("Azure upload source must be a regular file")
	}
	if info.Size() < 0 || info.Size() > azureMaximumObject {
		return errors.New("Azure backup must be 800 GB or smaller")
	}
	if _, err = file.Seek(0, io.SeekStart); err != nil {
		return errors.New("could not rewind Azure backup file")
	}
	return c.put(ctx, key, file)
}

// Put streams each block directly to Azure and commits the block list after
// the source has been read successfully. Memory use is limited to one block.
func (c *AzureClient) Put(ctx context.Context, key string, source io.Reader) error {
	if !validAzureObjectKey(key) {
		return errors.New("Azure blob name is invalid")
	}
	if source == nil {
		return errors.New("Azure upload source is required")
	}
	return c.put(ctx, key, source)
}

func (c *AzureClient) put(ctx context.Context, key string, source io.Reader) error {
	blockSize := c.blockSize
	if blockSize < 1 || blockSize > 4_000_000_000 {
		blockSize = azureDefaultBlockSize
	}
	buffer := make([]byte, int(blockSize))
	blockIDs := make([]string, 0, 1)
	var total int64
	for {
		n, readErr := io.ReadFull(source, buffer)
		if readErr != nil && readErr != io.EOF && readErr != io.ErrUnexpectedEOF {
			return errors.New("could not read Azure backup source")
		}
		if n == 0 && readErr == io.EOF {
			if len(blockIDs) == 0 {
				return c.putEmpty(ctx, key)
			}
			break
		}
		total += int64(n)
		if total > azureMaximumObject {
			return errors.New("Azure backup must be 800 GB or smaller")
		}
		if len(blockIDs) >= azureMaximumBlocks {
			return errors.New("Azure backup exceeds the 50,000 block limit")
		}
		idBytes := make([]byte, 4)
		binary.BigEndian.PutUint32(idBytes, uint32(len(blockIDs)))
		blockID := base64.StdEncoding.EncodeToString(idBytes)
		response, err := c.request(ctx, http.MethodPut, key, url.Values{"comp": {"block"}, "blockid": {blockID}}, buffer[:n], "", "")
		if err != nil {
			return err
		}
		if response.StatusCode != http.StatusCreated {
			err = c.responseError("upload block", response)
			closeAzureResponse(response)
			return err
		}
		closeAzureResponse(response)
		blockIDs = append(blockIDs, blockID)
		if readErr == io.EOF || readErr == io.ErrUnexpectedEOF {
			break
		}
	}
	body, err := xml.Marshal(struct {
		XMLName xml.Name `xml:"BlockList"`
		Blocks  []string `xml:"Latest"`
	}{Blocks: blockIDs})
	if err != nil {
		return errors.New("could not prepare Azure block list")
	}
	body = append([]byte(xml.Header), body...)
	response, err := c.request(ctx, http.MethodPut, key, url.Values{"comp": {"blocklist"}}, body, "application/xml", "")
	if err != nil {
		return err
	}
	defer closeAzureResponse(response)
	if response.StatusCode != http.StatusCreated {
		return c.responseError("commit block list", response)
	}
	return nil
}

func (c *AzureClient) putEmpty(ctx context.Context, key string) error {
	response, err := c.request(ctx, http.MethodPut, key, nil, nil, "application/octet-stream", "BlockBlob")
	if err != nil {
		return err
	}
	defer closeAzureResponse(response)
	if response.StatusCode != http.StatusCreated {
		return c.responseError("upload empty blob", response)
	}
	return nil
}

func (c *AzureClient) GetObject(ctx context.Context, key string, destination io.Writer) error {
	if !validAzureObjectKey(key) {
		return errors.New("Azure blob name is invalid")
	}
	if destination == nil {
		return errors.New("Azure download destination is required")
	}
	response, err := c.request(ctx, http.MethodGet, key, nil, nil, "", "")
	if err != nil {
		return err
	}
	defer closeAzureResponse(response)
	if response.StatusCode != http.StatusOK {
		return c.responseError("download", response)
	}
	if _, err = io.Copy(destination, response.Body); err != nil {
		return errors.New("could not write downloaded Azure backup")
	}
	return nil
}

func (c *AzureClient) DeleteObject(ctx context.Context, key string) error {
	if !validAzureObjectKey(key) {
		return errors.New("Azure blob name is invalid")
	}
	response, err := c.request(ctx, http.MethodDelete, key, nil, nil, "", "")
	if err != nil {
		return err
	}
	defer closeAzureResponse(response)
	if response.StatusCode != http.StatusAccepted && response.StatusCode != http.StatusNoContent {
		return c.responseError("delete", response)
	}
	return nil
}

// List checks container access and requests only the first page so test probes
// stay bounded even when a container holds many backup blobs.
func (c *AzureClient) List(ctx context.Context, prefix string) error {
	prefix = strings.Trim(prefix, "/")
	if prefix != "" && !validAzureObjectKey(prefix) {
		return errors.New("Azure blob prefix is invalid")
	}
	query := url.Values{"comp": {"list"}, "maxresults": {"1"}, "restype": {"container"}}
	if prefix != "" {
		query.Set("prefix", prefix+"/")
	}
	response, err := c.request(ctx, http.MethodGet, "", query, nil, "", "")
	if err != nil {
		return err
	}
	defer closeAzureResponse(response)
	if response.StatusCode != http.StatusOK {
		return c.responseError("list container", response)
	}
	return nil
}

func (c *AzureClient) request(ctx context.Context, method, key string, query url.Values, body []byte, contentType, blobType string) (*http.Response, error) {
	u := *c.endpoint
	basePath := strings.TrimRight(c.endpoint.Path, "/")
	u.Path = basePath + "/" + c.container
	if key != "" {
		u.Path += "/" + key
	}
	u.RawPath = ""
	values := make(url.Values)
	if c.authMode == "sas" {
		sas, _ := url.ParseQuery(c.credential)
		for name, items := range sas {
			values[name] = append([]string(nil), items...)
		}
	}
	for name, items := range query {
		values[name] = append([]string(nil), items...)
	}
	u.RawQuery = values.Encode()
	var reader io.Reader
	if body != nil {
		reader = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, u.String(), reader)
	if err != nil {
		return nil, errors.New("could not prepare Azure Blob request")
	}
	date := c.now().UTC().Format(http.TimeFormat)
	req.Header.Set("x-ms-date", date)
	req.Header.Set("x-ms-version", azureAPIversion)
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	if blobType != "" {
		req.Header.Set("x-ms-blob-type", blobType)
	}
	if c.authMode == "key" {
		keyBytes, _ := base64.StdEncoding.Strict().DecodeString(c.credential)
		signature := azureSharedKeySignature(req, c.account, keyBytes)
		req.Header.Set("Authorization", "SharedKey "+c.account+":"+signature)
	}
	response, err := c.httpClient.Do(req)
	if err != nil {
		return nil, safeAzureTransportError(method, err)
	}
	return response, nil
}

func azureSharedKeySignature(req *http.Request, account string, key []byte) string {
	contentLength := ""
	if req.ContentLength > 0 {
		contentLength = strconv.FormatInt(req.ContentLength, 10)
	}
	canonical := strings.Join([]string{
		req.Method,
		req.Header.Get("Content-Encoding"),
		req.Header.Get("Content-Language"),
		contentLength,
		req.Header.Get("Content-MD5"),
		req.Header.Get("Content-Type"),
		"",
		req.Header.Get("If-Modified-Since"),
		req.Header.Get("If-Match"),
		req.Header.Get("If-None-Match"),
		req.Header.Get("If-Unmodified-Since"),
		req.Header.Get("Range"),
	}, "\n")
	canonical += "\n" + azureCanonicalizedHeaders(req.Header) + azureCanonicalizedResource(req.URL, account)
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write([]byte(canonical))
	return base64.StdEncoding.EncodeToString(mac.Sum(nil))
}

func azureCanonicalizedHeaders(header http.Header) string {
	names := make([]string, 0)
	for name := range header {
		if strings.HasPrefix(strings.ToLower(name), "x-ms-") {
			names = append(names, name)
		}
	}
	sort.Slice(names, func(i, j int) bool { return strings.ToLower(names[i]) < strings.ToLower(names[j]) })
	var canonical strings.Builder
	for _, name := range names {
		values := header.Values(name)
		clean := make([]string, len(values))
		for i, value := range values {
			clean[i] = strings.Join(strings.Fields(value), " ")
		}
		canonical.WriteString(strings.ToLower(name))
		canonical.WriteByte(':')
		canonical.WriteString(strings.Join(clean, ","))
		canonical.WriteByte('\n')
	}
	return canonical.String()
}

func azureCanonicalizedResource(u *url.URL, account string) string {
	resource := "/" + account + u.EscapedPath()
	query := u.Query()
	names := make([]string, 0, len(query))
	for name := range query {
		names = append(names, strings.ToLower(name))
	}
	sort.Strings(names)
	previous := ""
	for _, name := range names {
		if name == previous {
			continue
		}
		previous = name
		var matching []string
		for original, values := range query {
			if strings.ToLower(original) == name {
				matching = append(matching, values...)
			}
		}
		sort.Strings(matching)
		resource += "\n" + name + ":" + strings.Join(matching, ",")
	}
	return resource
}

func safeAzureTransportError(method string, err error) error {
	verb := strings.ToLower(method)
	switch {
	case errors.Is(err, context.Canceled):
		return fmt.Errorf("Azure Blob %s request was canceled", verb)
	case errors.Is(err, context.DeadlineExceeded):
		return fmt.Errorf("Azure Blob %s request timed out", verb)
	default:
		var networkErr net.Error
		if errors.As(err, &networkErr) && networkErr.Timeout() {
			return fmt.Errorf("Azure Blob %s request timed out", verb)
		}
		return fmt.Errorf("Azure Blob %s request failed; check endpoint connectivity", verb)
	}
}

func (c *AzureClient) responseError(operation string, response *http.Response) error {
	code := response.Header.Get("x-ms-error-code")
	secrets := []string{c.credential}
	if c.authMode == "sas" {
		values, _ := url.ParseQuery(c.credential)
		for _, items := range values {
			secrets = append(secrets, items...)
		}
	}
	for _, secret := range secrets {
		if len(secret) >= 4 && (strings.Contains(code, secret) || strings.Contains(secret, code)) {
			code = ""
			break
		}
	}
	var clean strings.Builder
	for _, r := range code {
		if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '_' || r == '-' {
			clean.WriteRune(r)
		}
		if clean.Len() >= 80 {
			break
		}
	}
	if clean.Len() == 0 {
		return fmt.Errorf("Azure Blob %s failed with HTTP %d", operation, response.StatusCode)
	}
	return fmt.Errorf("Azure Blob %s failed with HTTP %d (%s)", operation, response.StatusCode, clean.String())
}

func closeAzureResponse(response *http.Response) {
	if response == nil || response.Body == nil {
		return
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 1<<20))
	_ = response.Body.Close()
}
