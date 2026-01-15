// Package cfsolver provides an HTTP client that automatically bypasses
// Cloudflare challenges using the CloudFlyer cloud API.
//
// Basic usage:
//
//	solver := cfsolver.New("your-api-key")
//	resp, err := solver.Get("https://protected-site.com")
//	if err != nil {
//	    log.Fatal(err)
//	}
//	defer resp.Body.Close()
//
// With options:
//
//	solver := cfsolver.New(apiKey,
//	    cfsolver.WithAPIBase("https://solver.zetx.site"),
//	    cfsolver.WithProxy("http://proxy.example.com:8080"),
//	    cfsolver.WithTimeout(30*time.Second),
//	)
package cfsolver

// Version is the current version of the SDK.
const Version = "0.2.0"
