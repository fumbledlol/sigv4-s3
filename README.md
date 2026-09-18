# sigv4-s3

[![Go Reference](https://pkg.go.dev/badge/github.com/fumbledlol/sigv4-s3.svg)](https://pkg.go.dev/github.com/fumbledlol/sigv4-s3)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

Minimal AWS Signature Version 4 (SigV4) client for S3 and S3-compatible object storage such as AWS S3, MinIO, Backblaze B2, and Cloudflare R2.

## Why this exists

The official AWS Go SDK v2 is large and brings in dozens of transitive dependencies. If your application only needs basic object operations (`PUT`, `GET`, `DELETE`, `COPY`) with streaming uploads, `sigv4-s3` provides a lightweight client using only the Go standard library.

## Features

- Standard library only (`crypto/*`, `net/http`, `encoding/*`)
- Streaming uploads by hashing payload data via `io.ReadSeeker` without loading entire files into memory
- Daily SigV4 derived key caching to avoid redundant HMAC calculations
- SSE-C header formatting for customer-managed encryption keys
- Path-style (MinIO) and virtual-hosted bucket addressing
- Retries with backoff and stream rewind on transient HTTP 429 and 5xx responses

## Installation

```bash
go get github.com/fumbledlol/sigv4-s3
```

## Quick start

```go
package main

import (
	"context"
	"os"

	"github.com/fumbledlol/sigv4-s3"
)

func main() {
	client, err := sigv4s3.New(sigv4s3.Config{
		Endpoint:  "https://s3.us-east-1.amazonaws.com",
		Region:    "us-east-1",
		Bucket:    "my-bucket",
		AccessKey: os.Getenv("AWS_ACCESS_KEY_ID"),
		SecretKey: os.Getenv("AWS_SECRET_ACCESS_KEY"),
	})
	if err != nil {
		panic(err)
	}

	ctx := context.Background()

	// Upload file
	file, err := os.Open("avatar.png")
	if err != nil {
		panic(err)
	}
	defer file.Close()

	err = client.PutObject(ctx, "users/1/avatar.png", file, "image/png", nil)
	if err != nil {
		panic(err)
	}

	// Copy object
	err = client.CopyObject(ctx, "users/1/avatar.png", "users/1/avatar-backup.png", nil)
	if err != nil {
		panic(err)
	}

	// Delete object
	err = client.DeleteObject(ctx, "users/1/avatar.png")
	if err != nil {
		panic(err)
	}
}
```

## Benchmarks

```
BenchmarkAuthorize-12    454682    2785 ns/op    2848 B/op    25 allocs/op
```

## License

[MIT](LICENSE)