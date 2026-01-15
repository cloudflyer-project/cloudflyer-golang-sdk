# CloudFlyer Go SDK

[![Go Reference](https://pkg.go.dev/badge/github.com/cloudflyer-project/cloudflyer-golang-sdk.svg)](https://pkg.go.dev/github.com/cloudflyer-project/cloudflyer-golang-sdk)
[![Go 1.18+](https://img.shields.io/badge/go-1.18+-blue.svg)](https://golang.org/dl/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Docker](https://img.shields.io/badge/docker-ghcr.io-blue.svg)](https://ghcr.io/cloudflyer-project/cfsolver)

Go SDK for [CloudFlyer](https://cloudflyer.zetx.site) - automatically bypass Cloudflare challenges and solve Turnstile CAPTCHAs.

## Features

- **Simple HTTP Client** - Drop-in replacement for `net/http` with automatic challenge handling
- **Automatic Challenge Detection** - Detects and solves Cloudflare protection transparently
- **Turnstile Support** - Solve Cloudflare Turnstile CAPTCHA and retrieve tokens
- **TLS Fingerprint Matching** - Uses [azuretls-client](https://github.com/Noooste/azuretls-client) for browser-like TLS fingerprints
- **Clearance Caching** - Cache solved clearance data per host to avoid redundant API calls
- **Proxy Support** - HTTP/HTTPS/SOCKS5 proxies for requests and API calls
- **Context Support** - Full `context.Context` support for cancellation and timeouts
- **Multiple Solving Modes** - On-demand detection, pre-solve, or manual control

## Installation

```bash
go get github.com/cloudflyer-project/cloudflyer-golang-sdk
```

### Docker

The CLI is also available as a Docker image:

```bash
# Pull from GitHub Container Registry
docker pull ghcr.io/cloudflyer-project/cfsolver:latest

# Run with API key
docker run --rm -e CLOUDFLYER_API_KEY=your_api_key ghcr.io/cloudflyer-project/cfsolver solve cloudflare https://example.com

# Run proxy mode (expose port 8080)
docker run --rm -p 8080:8080 -e CLOUDFLYER_API_KEY=your_api_key ghcr.io/cloudflyer-project/cfsolver proxy -P 8080

# Check balance
docker run --rm -e CLOUDFLYER_API_KEY=your_api_key ghcr.io/cloudflyer-project/cfsolver balance
```

## Quick Start

### Bypass Cloudflare Challenge

```go
package main

import (
    "fmt"
    "io"
    "log"

    cfsolver "github.com/cloudflyer-project/cloudflyer-golang-sdk"
)

func main() {
    solver := cfsolver.New("your-api-key")
    defer solver.Close()

    resp, err := solver.Get("https://protected-site.com")
    if err != nil {
        log.Fatal(err)
    }
    defer resp.Body.Close()

    body, _ := io.ReadAll(resp.Body)
    fmt.Println("Status:", resp.StatusCode)
    fmt.Println("Body:", string(body))
}
```

### Solve Turnstile CAPTCHA

```go
package main

import (
    "fmt"
    "log"

    cfsolver "github.com/cloudflyer-project/cloudflyer-golang-sdk"
)

func main() {
    solver := cfsolver.New("your-api-key")

    token, err := solver.SolveTurnstile(
        "https://example.com/page-with-turnstile",
        "0x4AAAAAACJkAlPHW8xr1T2J", // sitekey
    )
    if err != nil {
        log.Fatal(err)
    }

    fmt.Println("Turnstile Token:", token)
}
```

## Configuration Options

```go
solver := cfsolver.New(apiKey,
    // API Configuration
    cfsolver.WithAPIBase("https://solver.zetx.site"),  // Custom API endpoint
    cfsolver.WithAPIProxy("http://proxy:8080"),        // Proxy for API requests
    cfsolver.WithTimeout(30*time.Second),              // Request timeout

    // Challenge Solving Behavior
    cfsolver.WithSolve(true),        // Enable automatic solving (default: true)
    cfsolver.WithOnChallenge(true),  // Solve only when challenge detected (default: true)
    cfsolver.WithUseCache(true),     // Cache clearance data (default: true)
    cfsolver.WithUsePolling(false),  // Use interval polling instead of long-polling

    // Request Configuration
    cfsolver.WithProxy("http://proxy:8080"),           // Proxy for target requests
    cfsolver.WithTaskProxy("http://task-proxy:8080"),  // Proxy for solver task
    cfsolver.WithUserAgent("custom-ua"),               // Custom User-Agent
    cfsolver.WithImpersonate("chrome"),                // Browser to impersonate (chrome/firefox/safari/edge)
)
defer solver.Close()
```

## API Reference

### HTTP Methods

All HTTP methods return `*http.Response` compatible with standard library:

```go
// GET
resp, err := solver.Get(url)
resp, err := solver.GetWithHeaders(url, headers)
resp, err := solver.GetContext(ctx, url)
resp, err := solver.GetWithHeadersContext(ctx, url, headers)

// POST
resp, err := solver.Post(url, contentType, body)
resp, err := solver.PostJSON(url, data)
resp, err := solver.PostForm(url, formData)
resp, err := solver.PostContext(ctx, url, contentType, body)
resp, err := solver.PostJSONContext(ctx, url, data)
resp, err := solver.PostFormContext(ctx, url, formData)

// PUT / PATCH / DELETE / HEAD / OPTIONS
resp, err := solver.Put(url, contentType, body)
resp, err := solver.Patch(url, contentType, body)
resp, err := solver.Delete(url)
resp, err := solver.Head(url)
resp, err := solver.Options(url)
```

### Challenge Solving

```go
// Solve Cloudflare challenge and get cookies/user-agent
result, err := solver.SolveCloudflare(websiteURL)
if err != nil {
    log.Fatal(err)
}
fmt.Println("Cookies:", result.Cookies)
fmt.Println("User-Agent:", result.UserAgent)

// Solve Turnstile CAPTCHA and get token
token, err := solver.SolveTurnstile(websiteURL, sitekey)
if err != nil {
    log.Fatal(err)
}
fmt.Println("Token:", token)
```

### Cache Management

```go
// Clear all cached clearance data
solver.ClearCache("")

// Clear cache for specific host
solver.ClearCache("example.com")
```

### Request-Level Overrides

```go
opts := &cfsolver.RequestOptions{
    Solve:       boolPtr(false),  // Disable solving for this request
    OnChallenge: boolPtr(true),
    UseCache:    boolPtr(false),  // Disable cache for this request
}

resp, err := solver.RequestWithOptions(ctx, "GET", url, nil, headers, opts)

func boolPtr(b bool) *bool { return &b }
```

## Error Handling

The SDK provides typed errors for different failure scenarios:

```go
resp, err := solver.Get("https://protected-site.com")
if err != nil {
    switch e := err.(type) {
    case *cfsolver.TimeoutError:
        log.Println("Operation timed out:", e.Message)
    case *cfsolver.ChallengeError:
        log.Println("Challenge solving failed:", e.Message)
    case *cfsolver.APIError:
        log.Printf("API error (status %d): %s", e.StatusCode, e.Message)
    case *cfsolver.ConnectionError:
        log.Println("Connection failed:", e.Message)
    case *cfsolver.ProxyError:
        log.Println("Proxy error:", e.Message)
    default:
        log.Println("Unknown error:", err)
    }
    return
}
defer resp.Body.Close()
```

## Testing

### Run Unit Tests

Unit tests do not require an API key and can be run locally:

```bash
go test -v -short ./...
```

### Run Integration Tests

Integration tests require a valid API key. Set the environment variable and run:

```bash
# Windows
set CLOUDFLYER_API_KEY=your_api_key
go test -v -run "^TestIntegration" ./...

# Linux/macOS
export CLOUDFLYER_API_KEY=your_api_key
go test -v -run "^TestIntegration" ./...
```

### Run All Tests

```bash
# Windows
set CLOUDFLYER_API_KEY=your_api_key
go test -v -race ./...

# Linux/macOS
export CLOUDFLYER_API_KEY=your_api_key
go test -v -race ./...
```

### CI/CD Integration

The GitHub Actions workflow automatically runs:
- **Unit tests**: On every push and pull request (no API key required)
- **Integration tests**: On push to main branch (requires `CLOUDFLYER_API_KEY` secret)
- **Docker build**: On tag push, builds and pushes to GHCR (and optionally DockerHub)

To configure integration tests in your fork:
1. Go to repository Settings → Secrets and variables → Actions
2. Add a new secret named `CLOUDFLYER_API_KEY` with your API key
3. Optionally add `CLOUDFLYER_API_BASE` if using a custom API endpoint

#### Docker Registry Configuration

Docker images are automatically built and pushed to GitHub Container Registry (GHCR) on every release tag.

To also push to DockerHub, configure the following in your repository:

1. Go to repository Settings → Secrets and variables → Actions
2. Add **Variables**:
   - `DOCKERHUB_USERNAME`: Your DockerHub username
   - `DOCKERHUB_IMAGE`: Image name (e.g., `cfsolver`)
3. Add **Secrets**:
   - `DOCKERHUB_TOKEN`: Your DockerHub access token

## Examples

### Run Example Scripts

```bash
# Windows
set CLOUDFLYER_API_KEY=your_api_key
go run ./examples/sdk_challenge
go run ./examples/sdk_turnstile

# Linux/macOS
export CLOUDFLYER_API_KEY=your_api_key
go run ./examples/sdk_challenge
go run ./examples/sdk_turnstile
```

### With Proxy

```go
solver := cfsolver.New(apiKey,
    cfsolver.WithProxy("http://user:pass@proxy:8080"),      // Proxy for target requests
    cfsolver.WithAPIProxy("http://api-proxy:8080"),         // Proxy for API calls
    cfsolver.WithTaskProxy("http://task-proxy:8080"),       // Proxy for solver task
)
defer solver.Close()

resp, err := solver.Get("https://protected-site.com")
```

### Pre-solve Mode

```go
// Always solve challenge before making request (not just on detection)
solver := cfsolver.New(apiKey,
    cfsolver.WithOnChallenge(false),
)
defer solver.Close()

resp, err := solver.Get("https://protected-site.com")
```

### With Context and Timeout

```go
ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
defer cancel()

resp, err := solver.GetContext(ctx, "https://protected-site.com")
```

### Turnstile with Form Submission

```go
solver := cfsolver.New(apiKey)

// Solve Turnstile
token, err := solver.SolveTurnstile(
    "https://example.com/page",
    "0x4AAAAAACJkAlPHW8xr1T2J",
)
if err != nil {
    log.Fatal(err)
}

// Submit form with token
formData := url.Values{}
formData.Set("cf-turnstile-response", token)
formData.Set("username", "user")
formData.Set("password", "pass")

resp, err := solver.PostForm("https://example.com/login", formData)
```

## Environment Variables

| Variable | Description |
|----------|-------------|
| `CLOUDFLYER_API_KEY` | API key for authentication |
| `CLOUDFLYER_API_BASE` | Custom API endpoint (default: `https://solver.zetx.site`) |

## License

MIT License
