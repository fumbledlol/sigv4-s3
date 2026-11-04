package sigv4s3

import (
	"bytes"
	"cmp"
	"context"
	"crypto/hmac"
	"crypto/md5" // #nosec G501 -- required by AWS S3 SSE-C protocol specification
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/http"
	"slices"
	"strings"
	"sync"
	"time"
)

const (
	sigV4Algorithm = "AWS4-HMAC-SHA256"
	sigV4Service   = "s3"
	sigV4Terminus  = "aws4_request"
	maxAttempts    = 3
)

// Config defines connection coordinates and credentials for the S3 client.
type Config struct {
	Endpoint     string // e.g. "https://s3.us-east-1.amazonaws.com" or "https://s3.us-west-004.backblazeb2.com"
	Region       string // e.g. "us-east-1"
	Bucket       string
	AccessKey    string
	SecretKey    string
	UsePathStyle bool // Set true for MinIO or path-style endpoints
	HTTPClient   *http.Client
}

// Error represents an S3 XML error response.
type Error struct {
	Status  int
	Code    string
	Message string
}

func (e *Error) Error() string {
	if e.Message != "" {
		return fmt.Sprintf("s3: status=%d code=%s message=%s", e.Status, e.Code, e.Message)
	}
	return fmt.Sprintf("s3: status=%d code=%s", e.Status, e.Code)
}

type s3ErrorXML struct {
	Code    string `xml:"Code"`
	Message string `xml:"Message"`
}

// Client executes S3-compatible API requests using AWS SigV4 signing.
type Client struct {
	httpClient   *http.Client
	endpoint     string
	region       string
	bucket       string
	pathStyle    bool
	accessKey    string
	secretKey    string
	keyCacheLock sync.RWMutex
	keyCacheDate string
	keyCacheVal  []byte
}

// New creates an initialized S3 client.
func New(cfg Config) (*Client, error) {
	endpoint := strings.TrimRight(strings.TrimSpace(cfg.Endpoint), "/")
	if endpoint == "" {
		if cfg.Region != "" {
			endpoint = "https://s3." + cfg.Region + ".amazonaws.com"
		} else {
			return nil, errors.New("sigv4s3: endpoint or region required")
		}
	}

	httpClient := cfg.HTTPClient
	if httpClient == nil {
		httpClient = &http.Client{
			Timeout: 60 * time.Second,
		}
	}

	region := cmp.Or(cfg.Region, "us-east-1")

	return &Client{
		httpClient: httpClient,
		endpoint:   endpoint,
		region:     region,
		bucket:     strings.TrimSpace(cfg.Bucket),
		pathStyle:  cfg.UsePathStyle,
		accessKey:  strings.TrimSpace(cfg.AccessKey),
		secretKey:  strings.TrimSpace(cfg.SecretKey),
	}, nil
}

// ObjectURL returns the fully qualified URL for the object key.
func (c *Client) ObjectURL(key string) string {
	escaped := EscapePath(key)
	if c.pathStyle {
		return c.endpoint + "/" + c.bucket + "/" + escaped
	}
	scheme, host := splitSchemeHost(c.endpoint)
	return scheme + "://" + c.bucket + "." + host + "/" + escaped
}

func splitSchemeHost(endpoint string) (scheme, host string) {
	if before, after, ok := strings.Cut(endpoint, "://"); ok {
		return before, after
	}
	return "https", endpoint
}

// EscapePath percent-encodes key preserving '/' separators per SigV4 rules.
func EscapePath(key string) string {
	segments := strings.Split(key, "/")
	for i, s := range segments {
		segments[i] = escapeSegment(s)
	}
	return strings.Join(segments, "/")
}

func escapeSegment(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for i := range len(s) {
		ch := s[i]
		if (ch >= 'A' && ch <= 'Z') || (ch >= 'a' && ch <= 'z') || (ch >= '0' && ch <= '9') ||
			ch == '-' || ch == '_' || ch == '.' || ch == '~' {
			b.WriteByte(ch)
			continue
		}
		fmt.Fprintf(&b, "%%%02X", ch)
	}
	return b.String()
}

func hmacSHA256(key, data []byte) []byte {
	h := hmac.New(sha256.New, key)
	h.Write(data)
	return h.Sum(nil)
}

// SigningKey returns the derived signing key for a given scope date (YYYYMMDD).
// Results are cached across calls on the same date.
func (c *Client) SigningKey(date string) []byte {
	c.keyCacheLock.RLock()
	if c.keyCacheDate == date && len(c.keyCacheVal) > 0 {
		cached := c.keyCacheVal
		c.keyCacheLock.RUnlock()
		return cached
	}
	c.keyCacheLock.RUnlock()

	c.keyCacheLock.Lock()
	defer c.keyCacheLock.Unlock()
	if c.keyCacheDate == date && len(c.keyCacheVal) > 0 {
		return c.keyCacheVal
	}

	kDate := hmacSHA256([]byte("AWS4"+c.secretKey), []byte(date))
	kRegion := hmacSHA256(kDate, []byte(c.region))
	kService := hmacSHA256(kRegion, []byte(sigV4Service))
	kSigning := hmacSHA256(kService, []byte(sigV4Terminus))

	c.keyCacheDate = date
	c.keyCacheVal = kSigning
	return kSigning
}

// Authorize computes the Authorization header for a request.
func (c *Client) Authorize(method, reqURL string, headers map[string]string, payloadHash string, now time.Time) string {
	amzDate := now.UTC().Format("20060102T150405Z")
	date := amzDate[:8]
	host, path, query := splitURL(reqURL)

	headers["host"] = host
	headers["x-amz-date"] = amzDate
	headers["x-amz-content-sha256"] = payloadHash

	names := make([]string, 0, len(headers))
	for name := range headers {
		names = append(names, name)
	}
	slices.Sort(names)

	var canonicalHeaders strings.Builder
	for _, name := range names {
		canonicalHeaders.WriteString(name)
		canonicalHeaders.WriteByte(':')
		canonicalHeaders.WriteString(strings.TrimSpace(headers[name]))
		canonicalHeaders.WriteByte('\n')
	}

	canonicalRequest := strings.Join([]string{
		method,
		path,
		query,
		canonicalHeaders.String(),
		strings.Join(names, ";"),
		payloadHash,
	}, "\n")

	scope := date + "/" + c.region + "/" + sigV4Service + "/" + sigV4Terminus
	hash := sha256.Sum256([]byte(canonicalRequest))

	stringToSign := sigV4Algorithm + "\n" + amzDate + "\n" + scope + "\n" + hex.EncodeToString(hash[:])
	signature := hex.EncodeToString(hmacSHA256(c.SigningKey(date), []byte(stringToSign)))

	return sigV4Algorithm + " Credential=" + c.accessKey + "/" + scope +
		", SignedHeaders=" + strings.Join(names, ";") + ", Signature=" + signature
}

func splitURL(rawURL string) (host, path, query string) {
	rest := rawURL
	if _, after, ok := strings.Cut(rest, "://"); ok {
		rest = after
	}
	var ok bool
	host, path, ok = strings.Cut(rest, "/")
	if ok {
		path = "/" + path
	} else {
		path = "/"
	}
	path, query, _ = strings.Cut(path, "?")
	return host, path, query
}

// SSECHeaders returns standard S3 customer-provided encryption headers.
func SSECHeaders(keyBytes []byte) map[string]string {
	if len(keyBytes) != 32 {
		return nil
	}
	// #nosec G401 -- MD5 is required by AWS S3 SSE-C protocol specification
	hash := md5.Sum(keyBytes)
	return map[string]string{
		"x-amz-server-side-encryption-customer-algorithm": "AES256",
		"x-amz-server-side-encryption-customer-key":       base64.StdEncoding.EncodeToString(keyBytes),
		"x-amz-server-side-encryption-customer-key-md5":   base64.StdEncoding.EncodeToString(hash[:]),
	}
}

// HashBody computes the SHA256 of body without buffering all content in heap memory,
// then seeks back to the starting offset.
func HashBody(body io.ReadSeeker) (sum []byte, length int64, err error) {
	start, err := body.Seek(0, io.SeekCurrent)
	if err != nil {
		return nil, 0, fmt.Errorf("seek start: %w", err)
	}
	h := sha256.New()
	n, err := io.Copy(h, body)
	if err != nil {
		return nil, 0, fmt.Errorf("hash body: %w", err)
	}
	if _, err := body.Seek(start, io.SeekStart); err != nil {
		return nil, 0, fmt.Errorf("rewind body: %w", err)
	}
	return h.Sum(nil), n, nil
}

// Do executes an S3 request with SigV4 authorization and retries on retryable errors.
func (c *Client) Do(ctx context.Context, method, key string, body io.ReadSeeker, contentType string, extraHeaders map[string]string) error {
	reqURL := c.ObjectURL(key)

	var payloadHash string
	var contentLength int64 = -1
	var startOffset int64
	if body == nil {
		empty := sha256.Sum256(nil)
		payloadHash = hex.EncodeToString(empty[:])
	} else {
		off, err := body.Seek(0, io.SeekCurrent)
		if err != nil {
			return fmt.Errorf("seek body: %w", err)
		}
		startOffset = off
		sum, n, err := HashBody(body)
		if err != nil {
			return err
		}
		payloadHash = hex.EncodeToString(sum)
		contentLength = n
	}

	var lastErr error
	for attempt := range maxAttempts {
		if attempt > 0 {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(time.Duration(attempt) * 200 * time.Millisecond):
			}
			if body != nil {
				if _, err := body.Seek(startOffset, io.SeekStart); err != nil {
					return fmt.Errorf("rewind body for retry: %w", err)
				}
			}
		}

		if err := ctx.Err(); err != nil {
			return err
		}

		headers := make(map[string]string, len(extraHeaders)+5)
		for k, v := range extraHeaders {
			headers[strings.ToLower(k)] = v
		}
		if contentType != "" {
			headers["content-type"] = contentType
		}

		now := time.Now()
		auth := c.Authorize(method, reqURL, headers, payloadHash, now)

		var reqBody io.Reader
		if body != nil {
			reqBody = body
		}
		req, err := http.NewRequestWithContext(ctx, method, reqURL, reqBody)
		if err != nil {
			return fmt.Errorf("build request: %w", err)
		}
		for name, value := range headers {
			req.Header.Set(name, value)
		}
		req.Header.Set("Authorization", auth)
		if contentLength >= 0 {
			req.ContentLength = contentLength
		}

		resp, err := c.httpClient.Do(req)
		if err != nil {
			lastErr = fmt.Errorf("s3 request: %w", err)
			continue
		}
		respBody, readErr := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		closeErr := resp.Body.Close()
		if readErr != nil {
			lastErr = fmt.Errorf("read response: %w", readErr)
			continue
		}
		if closeErr != nil {
			lastErr = fmt.Errorf("close response: %w", closeErr)
			continue
		}

		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			return nil
		}
		if resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500 {
			lastErr = parseS3Error(resp.StatusCode, respBody)
			continue
		}
		return parseS3Error(resp.StatusCode, respBody)
	}

	if lastErr == nil {
		lastErr = errors.New("s3: request failed without response")
	}
	return lastErr
}

// PutObject uploads an object key to the S3 bucket.
func (c *Client) PutObject(ctx context.Context, key string, body io.ReadSeeker, contentType string, headers map[string]string) error {
	return c.Do(ctx, http.MethodPut, key, body, contentType, headers)
}

// DeleteObject deletes an object key from the S3 bucket.
func (c *Client) DeleteObject(ctx context.Context, key string) error {
	return c.Do(ctx, http.MethodDelete, key, nil, "", nil)
}

// CopyObject copies an object from srcKey to dstKey.
func (c *Client) CopyObject(ctx context.Context, srcKey, dstKey string, headers map[string]string) error {
	if headers == nil {
		headers = make(map[string]string, 2)
	}
	headers["x-amz-copy-source"] = EscapePath("/" + c.bucket + "/" + srcKey)
	return c.Do(ctx, http.MethodPut, dstKey, nil, "", headers)
}

func parseS3Error(status int, body []byte) error {
	trimmed := bytes.TrimSpace(body)
	if len(trimmed) > 0 {
		var parsed s3ErrorXML
		if err := xml.Unmarshal(trimmed, &parsed); err == nil && parsed.Code != "" {
			return &Error{Status: status, Code: parsed.Code, Message: strings.TrimSpace(parsed.Message)}
		}
		return &Error{Status: status, Code: "Unknown", Message: string(trimmed)}
	}
	return &Error{Status: status, Code: fmt.Sprintf("HTTP%d", status)}
}
