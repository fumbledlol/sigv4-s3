package sigv4s3

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestSigV4Signing(t *testing.T) {
	client, err := New(Config{
		Endpoint:  "https://s3.us-east-1.amazonaws.com",
		Region:    "us-east-1",
		Bucket:    "my-test-bucket",
		AccessKey: "AKIAIOSFODNN7EXAMPLE",
		SecretKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
	})
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}

	now := time.Date(2026, 9, 17, 12, 0, 0, 0, time.UTC)
	headers := map[string]string{
		"content-type": "image/jpeg",
	}

	auth := client.Authorize("PUT", client.ObjectURL("avatars/user-123.jpg"), headers, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", now)

	if !strings.HasPrefix(auth, "AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20260917/us-east-1/s3/aws4_request") {
		t.Fatalf("unexpected auth credential header: %s", auth)
	}

	if !strings.Contains(auth, "Signature=") {
		t.Fatalf("missing signature: %s", auth)
	}
}

func TestSSECHeaders(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i + 1)
	}
	headers := SSECHeaders(key)
	if headers == nil {
		t.Fatal("expected headers, got nil")
	}
	if headers["x-amz-server-side-encryption-customer-algorithm"] != "AES256" {
		t.Errorf("unexpected algo")
	}
	if headers["x-amz-server-side-encryption-customer-key"] == "" {
		t.Errorf("missing key")
	}
	if headers["x-amz-server-side-encryption-customer-key-md5"] == "" {
		t.Errorf("missing md5")
	}
}

func TestPutAndCopy(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.Header.Get("Authorization"), "AWS4-HMAC-SHA256") {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	client, err := New(Config{
		Endpoint:     server.URL,
		Region:       "us-east-1",
		Bucket:       "test-bucket",
		AccessKey:    "test-key",
		SecretKey:    "test-secret",
		UsePathStyle: true,
		HTTPClient:   server.Client(),
	})
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}

	data := []byte("hello world")
	err = client.PutObject(context.Background(), "test.txt", bytes.NewReader(data), "text/plain", nil)
	if err != nil {
		t.Fatalf("PutObject failed: %v", err)
	}

	err = client.CopyObject(context.Background(), "test.txt", "test-copy.txt", nil)
	if err != nil {
		t.Fatalf("CopyObject failed: %v", err)
	}

	err = client.DeleteObject(context.Background(), "test.txt")
	if err != nil {
		t.Fatalf("DeleteObject failed: %v", err)
	}
}

func BenchmarkAuthorize(b *testing.B) {
	client, _ := New(Config{
		Endpoint:  "https://s3.us-east-1.amazonaws.com",
		Region:    "us-east-1",
		Bucket:    "my-test-bucket",
		AccessKey: "AKIAIOSFODNN7EXAMPLE",
		SecretKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
	})
	now := time.Now()
	url := client.ObjectURL("test-key/nested/image.jpg")
	payloadHash := "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

	b.ReportAllocs()
	for b.Loop() {
		headers := map[string]string{"content-type": "image/jpeg"}
		_ = client.Authorize("PUT", url, headers, payloadHash, now)
	}
}
