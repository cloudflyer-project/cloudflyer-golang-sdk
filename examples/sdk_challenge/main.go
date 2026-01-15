// Example: Solve Cloudflare Challenge using cfsolver SDK.
//
// This script demonstrates how to use the CloudflareSolver to bypass
// Cloudflare's challenge protection on the demo site.
//
// Usage:
//
//	go run examples/sdk_challenge/main.go
//
// Environment:
//
//	set CLOUDFLYER_API_KEY=your_api_key
package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	cfsolver "github.com/cloudflyer-project/cloudflyer-golang-sdk"
)

const demoURL = "https://cloudflyer.zetx.site/demo/challenge"

func main() {
	proxy := flag.String("proxy", "", "Proxy for user requests (e.g. http://user:pass@host:port)")
	noLinksocks := flag.Bool("no-linksocks", false, "Disable LinkSocks (not recommended)")
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
	fmt.Printf("API Base: %s\n", apiBase)
	fmt.Printf("LinkSocks: %s\n", map[bool]string{true: "disabled", false: "enabled"}[*noLinksocks])
	if *proxy != "" {
		fmt.Printf("Proxy: %s\n", *proxy)
	}

	options := []cfsolver.Option{
		cfsolver.WithAPIBase(apiBase),
		cfsolver.WithSolve(true),
		cfsolver.WithOnChallenge(true),
		cfsolver.WithImpersonate("chrome"),
		cfsolver.WithUseLinkSocks(!*noLinksocks),
	}
	if *proxy != "" {
		options = append(options, cfsolver.WithProxy(*proxy))
	}

	solver := cfsolver.New(apiKey, options...)
	defer solver.Close()

	fmt.Println("Sending request to demo page...")
	resp, err := solver.Get(demoURL)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	defer resp.Body.Close()

	fmt.Printf("Response status: %d\n", resp.StatusCode)

	body, _ := io.ReadAll(resp.Body)
	bodyLower := strings.ToLower(string(body))

	if resp.StatusCode == 200 {
		if strings.Contains(bodyLower, "cf-turnstile") && strings.Contains(bodyLower, "challenge") {
			fmt.Println("WARNING: Challenge page still present - solve may have failed")
		} else {
			fmt.Println("Challenge bypassed successfully!")
		}
	} else {
		fmt.Fprintf(os.Stderr, "Request failed with status %d\n", resp.StatusCode)
		preview := string(body)
		if len(preview) > 500 {
			preview = preview[:500]
		}
		fmt.Fprintf(os.Stderr, "Response: %s\n", preview)
	}
}
