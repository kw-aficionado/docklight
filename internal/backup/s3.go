package backup

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"
	"time"
)

const (
	s3Service               = "s3"
	s3DefaultPartSize       = int64(64 << 20)
	s3MinimumPartSize       = int64(5 << 20)
	s3MaximumPartSize       = int64(5 << 30)
	s3MaximumObjectSize     = int64(5 << 40)
	s3MaximumMultipartParts = int64(10000)
)

// S3Client speaks the S3 REST API using path-style requests and Signature V4.
// Its HTTP client never follows redirects, which keeps signed requests and
// credentials scoped to the configured endpoint.
type S3Client struct {
	endpoint           *url.URL
	bucket             string
	region             string
	accessKey          string
	secretKey          string
	httpClient         *http.Client
	multipartThreshold int64
	multipartPartSize  int64
	now                func() time.Time
}

func NewS3Client(endpoint, bucket, region, accessKey, secretKey string, httpClient *http.Client) (*S3Client, error) {
	u, err := normalizeS3Endpoint(endpoint)
	if err != nil {
		return nil, err
	}
	if !validS3Bucket(bucket) {
		return nil, errors.New("S3 bucket must be a 3 to 63 character lowercase DNS-style name")
	}
	if !validS3Region(region) {
		return nil, errors.New("S3 region must contain 1 to 64 letters, numbers, or hyphens")
	}
	if accessKey == "" || len(accessKey) > 256 || hasControl(accessKey) {
		return nil, errors.New("S3 access key must contain 1 to 256 printable characters")
	}
	if secretKey == "" || len(secretKey) > 4096 || hasControl(secretKey) {
		return nil, errors.New("S3 secret key must contain 1 to 4096 printable characters")
	}
	if httpClient == nil {
		httpClient = &http.Client{}
	} else {
		copy := *httpClient
		httpClient = &copy
	}
	httpClient.CheckRedirect = func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }
	return &S3Client{
		endpoint:           u,
		bucket:             bucket,
		region:             region,
		accessKey:          accessKey,
		secretKey:          secretKey,
		httpClient:         httpClient,
		multipartThreshold: s3DefaultPartSize,
		multipartPartSize:  s3DefaultPartSize,
		now:                time.Now,
	}, nil
}

func normalizeS3Endpoint(value string) (*url.URL, error) {
	u, err := url.Parse(strings.TrimSpace(value))
	if err != nil || !u.IsAbs() || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return nil, errors.New("S3 endpoint must be an absolute HTTP(S) URL without credentials, a query, or a fragment")
	}
	u.Scheme = strings.ToLower(u.Scheme)
	switch u.Scheme {
	case "https":
	case "http":
		host := strings.TrimSuffix(strings.ToLower(u.Hostname()), ".")
		ip := net.ParseIP(host)
		if host != "localhost" && (ip == nil || !ip.IsLoopback()) {
			return nil, errors.New("S3 endpoints must use HTTPS; plain HTTP is allowed only for localhost loopback testing")
		}
	default:
		return nil, errors.New("S3 endpoint must use HTTPS")
	}
	for _, segment := range strings.Split(u.EscapedPath(), "/") {
		decoded, decodeErr := url.PathUnescape(segment)
		if decodeErr != nil || decoded == "." || decoded == ".." {
			return nil, errors.New("S3 endpoint path cannot contain dot segments")
		}
	}
	u.Path = strings.TrimRight(u.Path, "/")
	u.RawPath = strings.TrimRight(u.RawPath, "/")
	if u.Path == "" {
		u.Path = "/"
	}
	return u, nil
}

func validS3Bucket(bucket string) bool {
	if len(bucket) < 3 || len(bucket) > 63 || bucket[0] == '.' || bucket[0] == '-' || bucket[len(bucket)-1] == '.' || bucket[len(bucket)-1] == '-' || strings.Contains(bucket, "..") || strings.Contains(bucket, ".-") || strings.Contains(bucket, "-.") || net.ParseIP(bucket) != nil {
		return false
	}
	for _, r := range bucket {
		if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '.' || r == '-') {
			return false
		}
	}
	return true
}

func validS3Region(region string) bool {
	if region == "" || len(region) > 64 {
		return false
	}
	for _, r := range region {
		if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-') {
			return false
		}
	}
	return true
}

func hasControl(value string) bool {
	for _, r := range value {
		if r < 0x20 || r == 0x7f {
			return true
		}
	}
	return false
}

func validS3ObjectKey(key string) bool {
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

func (c *S3Client) PutFile(ctx context.Context, key string, file *os.File) error {
	if file == nil {
		return errors.New("S3 upload source file is required")
	}
	if !validS3ObjectKey(key) {
		return errors.New("S3 object key is invalid")
	}
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() {
		return errors.New("S3 upload source must be a regular file")
	}
	size := info.Size()
	if size < 0 || size > s3MaximumObjectSize {
		return errors.New("S3 backup must be 5 TiB or smaller")
	}
	wholeHash, err := hashSection(file, 0, size)
	if err != nil {
		return fmt.Errorf("could not hash S3 backup: %w", err)
	}
	if size < c.multipartThreshold {
		if _, err = file.Seek(0, io.SeekStart); err != nil {
			return errors.New("could not rewind S3 backup file")
		}
		response, requestErr := c.request(ctx, http.MethodPut, key, nil, file, size, wholeHash)
		if requestErr != nil {
			return requestErr
		}
		defer response.Body.Close()
		if response.StatusCode != http.StatusOK {
			return s3ResponseError("upload", response)
		}
		return nil
	}
	return c.putMultipart(ctx, key, file, size)
}

// Put streams an object to S3 without writing an intermediate file. It buffers
// one part at a time so each request can be signed with its payload hash.
func (c *S3Client) Put(ctx context.Context, key string, source io.Reader) error {
	if !validS3ObjectKey(key) {
		return errors.New("S3 object key is invalid")
	}
	if source == nil {
		return errors.New("S3 upload source is required")
	}
	partSize := c.multipartPartSize
	if partSize < s3MinimumPartSize {
		partSize = s3MinimumPartSize
	}
	first := make([]byte, 0, 1<<20)
	buffer := make([]byte, 1<<20)
	for int64(len(first)) < partSize {
		remaining := partSize - int64(len(first))
		readSize := int64(len(buffer))
		if remaining < readSize {
			readSize = remaining
		}
		n, readErr := io.ReadFull(source, buffer[:int(readSize)])
		first = append(first, buffer[:n]...)
		if readErr == io.EOF || readErr == io.ErrUnexpectedEOF {
			return c.putBytes(ctx, key, first)
		}
		if readErr != nil {
			return fmt.Errorf("could not read S3 backup stream: %w", readErr)
		}
	}
	lookahead := []byte{0}
	n, readErr := io.ReadFull(source, lookahead)
	if n == 0 && readErr == io.EOF {
		return c.putBytes(ctx, key, first)
	}
	if readErr != nil {
		return fmt.Errorf("could not read S3 backup stream: %w", readErr)
	}
	return c.putMultipartReader(ctx, key, first, io.MultiReader(bytes.NewReader(lookahead), source), partSize)
}

func (c *S3Client) putBytes(ctx context.Context, key string, data []byte) error {
	hash := sha256.Sum256(data)
	response, err := c.request(ctx, http.MethodPut, key, nil, bytes.NewReader(data), int64(len(data)), hex.EncodeToString(hash[:]))
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return s3ResponseError("upload", response)
	}
	return nil
}

func (c *S3Client) putMultipartReader(ctx context.Context, key string, first []byte, remainder io.Reader, partSize int64) error {
	initResponse, err := c.request(ctx, http.MethodPost, key, url.Values{"uploads": {""}}, nil, 0, emptySHA256())
	if err != nil {
		return err
	}
	if initResponse.StatusCode != http.StatusOK {
		initErr := s3ResponseError("start multipart upload", initResponse)
		_ = initResponse.Body.Close()
		return initErr
	}
	var initiated struct {
		UploadID string `xml:"UploadId"`
	}
	decodeErr := xml.NewDecoder(io.LimitReader(initResponse.Body, 64*1024)).Decode(&initiated)
	_ = initResponse.Body.Close()
	if decodeErr != nil || initiated.UploadID == "" || len(initiated.UploadID) > 2048 {
		return errors.New("S3 did not return a valid multipart upload ID")
	}
	abort := func() {
		abortCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		response, abortErr := c.request(abortCtx, http.MethodDelete, key, url.Values{"uploadId": {initiated.UploadID}}, nil, 0, emptySHA256())
		if abortErr == nil {
			_ = response.Body.Close()
		}
	}
	parts := make([]s3CompletedPart, 0, 4)
	total := int64(0)
	partNumber := int64(0)
	uploadPart := func(data []byte) error {
		if len(data) == 0 {
			return nil
		}
		partNumber++
		if partNumber > s3MaximumMultipartParts {
			return errors.New("S3 backup requires more than 10,000 upload parts")
		}
		total += int64(len(data))
		if total > s3MaximumObjectSize {
			return errors.New("S3 backup must be 5 TiB or smaller")
		}
		hash := sha256.Sum256(data)
		query := url.Values{"partNumber": {fmt.Sprint(partNumber)}, "uploadId": {initiated.UploadID}}
		response, requestErr := c.request(ctx, http.MethodPut, key, query, bytes.NewReader(data), int64(len(data)), hex.EncodeToString(hash[:]))
		if requestErr != nil {
			return requestErr
		}
		if response.StatusCode != http.StatusOK {
			partErr := s3ResponseError("upload multipart part", response)
			_ = response.Body.Close()
			return partErr
		}
		etag := response.Header.Get("ETag")
		_ = response.Body.Close()
		if etag == "" || hasControl(etag) {
			return fmt.Errorf("S3 did not return an ETag for upload part %d", partNumber)
		}
		parts = append(parts, s3CompletedPart{Number: partNumber, ETag: etag})
		return nil
	}
	if err = uploadPart(first); err != nil {
		abort()
		return err
	}
	for {
		buffer := make([]byte, partSize)
		n, readErr := io.ReadFull(remainder, buffer)
		if n > 0 {
			if err = uploadPart(buffer[:n]); err != nil {
				abort()
				return err
			}
		}
		if readErr == io.EOF || readErr == io.ErrUnexpectedEOF {
			break
		}
		if readErr != nil {
			abort()
			return fmt.Errorf("could not read S3 backup stream: %w", readErr)
		}
	}
	completionBody, err := xml.Marshal(s3CompleteUpload{Parts: parts})
	if err != nil {
		abort()
		return errors.New("could not encode S3 multipart completion request")
	}
	completionHash := sha256.Sum256(completionBody)
	response, err := c.request(ctx, http.MethodPost, key, url.Values{"uploadId": {initiated.UploadID}}, bytes.NewReader(completionBody), int64(len(completionBody)), hex.EncodeToString(completionHash[:]))
	if err != nil {
		abort()
		return err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		completeErr := s3ResponseError("complete multipart upload", response)
		abort()
		return completeErr
	}
	responseBody, err := io.ReadAll(io.LimitReader(response.Body, 64*1024))
	if err != nil {
		abort()
		return errors.New("could not read S3 multipart completion response")
	}
	if len(responseBody) != 0 {
		var root struct{ XMLName xml.Name }
		if err = xml.Unmarshal(responseBody, &root); err != nil || root.XMLName.Local == "Error" {
			abort()
			return errors.New("S3 rejected multipart completion")
		}
	}
	return nil
}

func (c *S3Client) GetObject(ctx context.Context, key string, dst io.Writer) error {
	if !validS3ObjectKey(key) {
		return errors.New("S3 object key is invalid")
	}
	response, err := c.request(ctx, http.MethodGet, key, nil, nil, 0, emptySHA256())
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return s3ResponseError("download", response)
	}
	if _, err = io.Copy(dst, response.Body); err != nil {
		return fmt.Errorf("S3 download failed while reading the object: %w", err)
	}
	return nil
}

func (c *S3Client) DeleteObject(ctx context.Context, key string) error {
	if !validS3ObjectKey(key) {
		return errors.New("S3 object key is invalid")
	}
	response, err := c.request(ctx, http.MethodDelete, key, nil, nil, 0, emptySHA256())
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusNoContent && response.StatusCode != http.StatusOK {
		return s3ResponseError("delete", response)
	}
	return nil
}

func (c *S3Client) putMultipart(ctx context.Context, key string, file *os.File, size int64) error {
	partSize := c.multipartPartSize
	if partSize < s3MinimumPartSize {
		partSize = s3MinimumPartSize
	}
	minimumForLimit := (size + s3MaximumMultipartParts - 1) / s3MaximumMultipartParts
	if partSize < minimumForLimit {
		partSize = ((minimumForLimit + s3MinimumPartSize - 1) / s3MinimumPartSize) * s3MinimumPartSize
	}
	if partSize > s3MaximumPartSize {
		return errors.New("S3 backup is too large for the supported multipart upload limits")
	}
	partCount := (size + partSize - 1) / partSize
	if partCount > s3MaximumMultipartParts {
		return errors.New("S3 backup requires more than 10,000 upload parts")
	}
	initResponse, err := c.request(ctx, http.MethodPost, key, url.Values{"uploads": {""}}, nil, 0, emptySHA256())
	if err != nil {
		return err
	}
	if initResponse.StatusCode != http.StatusOK {
		initErr := s3ResponseError("start multipart upload", initResponse)
		_ = initResponse.Body.Close()
		return initErr
	}
	var initiated struct {
		UploadID string `xml:"UploadId"`
	}
	decodeErr := xml.NewDecoder(io.LimitReader(initResponse.Body, 64*1024)).Decode(&initiated)
	_ = initResponse.Body.Close()
	if decodeErr != nil || initiated.UploadID == "" || len(initiated.UploadID) > 2048 {
		return errors.New("S3 did not return a valid multipart upload ID")
	}
	parts := make([]s3CompletedPart, 0, partCount)
	abort := func() {
		abortCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		response, abortErr := c.request(abortCtx, http.MethodDelete, key, url.Values{"uploadId": {initiated.UploadID}}, nil, 0, emptySHA256())
		if abortErr == nil {
			_ = response.Body.Close()
		}
	}
	for partNumber, offset := int64(1), int64(0); offset < size; partNumber++ {
		length := partSize
		if size-offset < length {
			length = size - offset
		}
		partHash, hashErr := hashSection(file, offset, length)
		if hashErr != nil {
			abort()
			return fmt.Errorf("could not hash S3 backup part %d: %w", partNumber, hashErr)
		}
		query := url.Values{"partNumber": {fmt.Sprint(partNumber)}, "uploadId": {initiated.UploadID}}
		body := io.NewSectionReader(file, offset, length)
		response, requestErr := c.request(ctx, http.MethodPut, key, query, body, length, partHash)
		if requestErr != nil {
			abort()
			return requestErr
		}
		if response.StatusCode != http.StatusOK {
			partErr := s3ResponseError("upload multipart part", response)
			_ = response.Body.Close()
			abort()
			return partErr
		}
		etag := response.Header.Get("ETag")
		_ = response.Body.Close()
		if etag == "" || hasControl(etag) {
			abort()
			return fmt.Errorf("S3 did not return an ETag for upload part %d", partNumber)
		}
		parts = append(parts, s3CompletedPart{Number: partNumber, ETag: etag})
		offset += length
	}
	completion := s3CompleteUpload{Parts: parts}
	completionBody, err := xml.Marshal(completion)
	if err != nil {
		abort()
		return errors.New("could not encode S3 multipart completion request")
	}
	completionHash := sha256.Sum256(completionBody)
	response, err := c.request(ctx, http.MethodPost, key, url.Values{"uploadId": {initiated.UploadID}}, strings.NewReader(string(completionBody)), int64(len(completionBody)), hex.EncodeToString(completionHash[:]))
	if err != nil {
		abort()
		return err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		completeErr := s3ResponseError("complete multipart upload", response)
		abort()
		return completeErr
	}
	responseBody, err := io.ReadAll(io.LimitReader(response.Body, 64*1024))
	if err != nil {
		abort()
		return errors.New("could not read S3 multipart completion response")
	}
	if len(responseBody) != 0 {
		var root struct {
			XMLName xml.Name
		}
		if err = xml.Unmarshal(responseBody, &root); err != nil {
			abort()
			return errors.New("S3 returned an invalid multipart completion response")
		}
		if root.XMLName.Local == "Error" {
			abort()
			return errors.New("S3 rejected multipart completion")
		}
	}
	return nil
}

type s3CompletedPart struct {
	Number int64  `xml:"PartNumber"`
	ETag   string `xml:"ETag"`
}

type s3CompleteUpload struct {
	XMLName xml.Name          `xml:"CompleteMultipartUpload"`
	Parts   []s3CompletedPart `xml:"Part"`
}

func hashSection(file *os.File, offset, size int64) (string, error) {
	h := sha256.New()
	if _, err := io.Copy(h, io.NewSectionReader(file, offset, size)); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func emptySHA256() string {
	return hex.EncodeToString(sha256.New().Sum(nil))
}

func (c *S3Client) request(ctx context.Context, method, key string, query url.Values, body io.Reader, size int64, payloadHash string) (*http.Response, error) {
	requestURL, err := c.objectURL(key, query)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, method, requestURL.String(), body)
	if err != nil {
		return nil, errors.New("could not construct S3 request")
	}
	req.ContentLength = size
	now := c.now().UTC()
	c.sign(req, payloadHash, now)
	return c.httpClient.Do(req)
}

func (c *S3Client) sign(req *http.Request, payloadHash string, now time.Time) {
	date := now.UTC().Format("20060102")
	amzDate := now.UTC().Format("20060102T150405Z")
	req.Header.Set("X-Amz-Date", amzDate)
	req.Header.Set("X-Amz-Content-Sha256", payloadHash)
	canonicalHeaders := "host:" + strings.ToLower(req.URL.Host) + "\n" + "x-amz-content-sha256:" + payloadHash + "\n" + "x-amz-date:" + amzDate + "\n"
	signedHeaders := "host;x-amz-content-sha256;x-amz-date"
	canonicalRequest := strings.Join([]string{req.Method, req.URL.EscapedPath(), req.URL.RawQuery, canonicalHeaders, signedHeaders, payloadHash}, "\n")
	canonicalHash := sha256.Sum256([]byte(canonicalRequest))
	scope := date + "/" + c.region + "/" + s3Service + "/aws4_request"
	stringToSign := "AWS4-HMAC-SHA256\n" + amzDate + "\n" + scope + "\n" + hex.EncodeToString(canonicalHash[:])
	dateKey := hmacSHA256([]byte("AWS4"+c.secretKey), date)
	regionKey := hmacSHA256(dateKey, c.region)
	serviceKey := hmacSHA256(regionKey, s3Service)
	signingKey := hmacSHA256(serviceKey, "aws4_request")
	signature := hex.EncodeToString(hmacSHA256(signingKey, stringToSign))
	req.Header.Set("Authorization", "AWS4-HMAC-SHA256 Credential="+c.accessKey+"/"+scope+",SignedHeaders="+signedHeaders+",Signature="+signature)
}

func (c *S3Client) objectURL(key string, query url.Values) (*url.URL, error) {
	if key != "" && !validS3ObjectKey(key) {
		return nil, errors.New("S3 object key is invalid")
	}
	u := *c.endpoint
	path := strings.TrimRight(c.endpoint.EscapedPath(), "/") + "/" + awsURIEncode(c.bucket, false)
	if key != "" {
		path += "/" + awsURIEncode(key, true)
	}
	decoded, err := url.PathUnescape(path)
	if err != nil {
		return nil, errors.New("S3 request path is invalid")
	}
	u.Path = decoded
	u.RawPath = path
	u.RawQuery = canonicalS3Query(query)
	return &u, nil
}

func canonicalS3Query(values url.Values) string {
	type pair struct{ key, value string }
	pairs := []pair{}
	for key, items := range values {
		if len(items) == 0 {
			pairs = append(pairs, pair{key: awsURIEncode(key, false)})
			continue
		}
		for _, value := range items {
			pairs = append(pairs, pair{key: awsURIEncode(key, false), value: awsURIEncode(value, false)})
		}
	}
	sort.Slice(pairs, func(i, j int) bool {
		if pairs[i].key == pairs[j].key {
			return pairs[i].value < pairs[j].value
		}
		return pairs[i].key < pairs[j].key
	})
	encoded := make([]string, 0, len(pairs))
	for _, item := range pairs {
		encoded = append(encoded, item.key+"="+item.value)
	}
	return strings.Join(encoded, "&")
}

func awsURIEncode(value string, preserveSlash bool) string {
	const hexDigits = "0123456789ABCDEF"
	var encoded strings.Builder
	for i := 0; i < len(value); i++ {
		b := value[i]
		if b >= 'A' && b <= 'Z' || b >= 'a' && b <= 'z' || b >= '0' && b <= '9' || strings.ContainsRune("-_.~", rune(b)) || preserveSlash && b == '/' {
			encoded.WriteByte(b)
		} else {
			encoded.WriteByte('%')
			encoded.WriteByte(hexDigits[b>>4])
			encoded.WriteByte(hexDigits[b&15])
		}
	}
	return encoded.String()
}

func hmacSHA256(key []byte, value string) []byte {
	h := hmac.New(sha256.New, key)
	_, _ = h.Write([]byte(value))
	return h.Sum(nil)
}

func s3ResponseError(action string, response *http.Response) error {
	defer response.Body.Close()
	var envelope struct {
		Code string `xml:"Code"`
	}
	_ = xml.NewDecoder(io.LimitReader(response.Body, 4096)).Decode(&envelope)
	if envelope.Code != "" && !hasControl(envelope.Code) && len(envelope.Code) <= 80 {
		return fmt.Errorf("S3 %s failed with HTTP %d (%s)", action, response.StatusCode, envelope.Code)
	}
	return fmt.Errorf("S3 %s failed with HTTP %d", action, response.StatusCode)
}
