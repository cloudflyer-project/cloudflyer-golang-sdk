// Example: Solve Cloudflare Turnstile using cfsolver SDK.
//
// This script demonstrates how to use the CloudflareSolver to solve
// Turnstile challenges and obtain the token.
//
// Usage:
//
//	go run examples/sdk_turnstile/main.go
//
// Environment:
//
//	set CLOUDFLYER_API_KEY=your_api_key
package main

import (
	"flag"
	"fmt"
	"os"

	cfsolver "github.com/cloudflyer-project/cloudflyer-golang-sdk"
)

const (
	demoURL = "https://cloudflyer.zetx.site/demo/turnstile"
	siteKey = "0x4AAAAAACJkAlPHW8xr1T2J"
)

func main() {
	proxy := flag.String("proxy", "", "Task proxy for solver (e.g. http://user:pass@host:port)")
	flag.Parse()

	apiKey := os.Getenv("CLOUDFLYER_API_KEY")
	apiBase := os.Getenv("CLOUDFLYER_API_BASE")
	if apiBase == "" {
		apiBase = "https://solver.zetx.site"
	}

	if apiKey == "" {
		fmt.Fprintln(os.Stderr, "Please set CLOUDFLYER_API_KEY environment variable")
		os.Exit(1)
	}

	fmt.Printf("Target URL: %s\n", demoURL)
	fmt.Printf("Site Key: %s\n", siteKey)
	if *proxy != "" {
		fmt.Printf("Task Proxy: %s\n", *proxy)
	}

	options := []cfsolver.Option{
		cfsolver.WithAPIBase(apiBase),
	}
	if *proxy != "" {
		options = append(options, cfsolver.WithTaskProxy(*proxy))
	}

	solver := cfsolver.New(apiKey, options...)

	fmt.Println("Solving Turnstile challenge...")
	token, err := solver.SolveTurnstile(demoURL, siteKey)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("Turnstile solved successfully!")
	tokenPreview := token
	if len(tokenPreview) > 80 {
		tokenPreview = tokenPreview[:80]
	}
	fmt.Printf("Token: %s...\n", tokenPreview)
	fmt.Printf("Token length: %d\n", len(token))
}
