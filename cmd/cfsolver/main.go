// Command cfsolver provides a CLI for solving Cloudflare challenges.
//
// Usage:
//
//	cfsolver solve cloudflare <url>
//	cfsolver solve turnstile <url> <sitekey>
//	cfsolver proxy -P 8080
//	cfsolver request <url>
//	cfsolver balance
package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	cfsolver "github.com/cloudflyer-project/cloudflyer-golang-sdk"
	"github.com/spf13/cobra"
)

var (
	// Global flags
	verbose bool
	apiKey  string
	apiBase string

	// Version info
	version = "0.2.0"
)

func main() {
	rootCmd := &cobra.Command{
		Use:     "cfsolver",
		Short:   "CFSolver - Cloudflare challenge solver using cloud API",
		Version: version,
		PersistentPreRun: func(cmd *cobra.Command, args []string) {
			// Get API key from flag or environment
			if apiKey == "" {
				apiKey = os.Getenv("CLOUDFLYER_API_KEY")
			}
			// Get API base from flag or environment
			if apiBase == "" {
				apiBase = os.Getenv("CLOUDFLYER_API_BASE")
				if apiBase == "" {
					apiBase = "https://solver.zetx.site"
				}
			}
		},
	}

	rootCmd.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, "Enable verbose output")
	rootCmd.PersistentFlags().StringVarP(&apiKey, "api-key", "K", "", "API key (or set CLOUDFLYER_API_KEY env var)")
	rootCmd.PersistentFlags().StringVarP(&apiBase, "api-base", "B", "", "API base URL (default: https://solver.zetx.site)")

	// Add subcommands
	rootCmd.AddCommand(newSolveCmd())
	rootCmd.AddCommand(newProxyCmd())
	rootCmd.AddCommand(newRequestCmd())
	rootCmd.AddCommand(newBalanceCmd())

	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

func requireAPIKey() {
	if apiKey == "" {
		fmt.Fprintln(os.Stderr, "Error: API key required. Use -K/--api-key or set CLOUDFLYER_API_KEY environment variable.")
		os.Exit(1)
	}
}

// solve command group
func newSolveCmd() *cobra.Command {
	solveCmd := &cobra.Command{
		Use:   "solve",
		Short: "Solve Cloudflare challenges",
	}

	solveCmd.AddCommand(newSolveCloudflareCmd())
	solveCmd.AddCommand(newSolveTurnstileCmd())

	return solveCmd
}

// solve cloudflare command
func newSolveCloudflareCmd() *cobra.Command {
	var (
		proxy       string
		apiProxy    string
		impersonate string
		timeout     int
		outputJSON  bool
	)

	cmd := &cobra.Command{
		Use:   "cloudflare <url>",
		Short: "Solve Cloudflare challenge for a URL",
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			requireAPIKey()
			url := args[0]

			if verbose {
				fmt.Printf("Solving Cloudflare challenge for: %s\n", url)
			}

			opts := []cfsolver.Option{
				cfsolver.WithAPIBase(apiBase),
				cfsolver.WithTimeout(time.Duration(timeout) * time.Second),
			}
			if proxy != "" {
				opts = append(opts, cfsolver.WithProxy(proxy))
			}
			if apiProxy != "" {
				opts = append(opts, cfsolver.WithAPIProxy(apiProxy))
			}
			if impersonate != "" {
				opts = append(opts, cfsolver.WithImpersonate(impersonate))
			}

			solver := cfsolver.New(apiKey, opts...)
			defer solver.Close()

			challengeResult, err := solver.SolveCloudflare(url)
			if err != nil {
				if outputJSON {
					printJSON(map[string]interface{}{"success": false, "error": err.Error()})
				} else {
					fmt.Fprintf(os.Stderr, "[x] Error: %v\n", err)
				}
				os.Exit(1)
			}

			result := map[string]interface{}{
				"success":    true,
				"url":        url,
				"cookies":    challengeResult.Cookies,
				"user_agent": challengeResult.UserAgent,
			}

			if outputJSON {
				printJSON(result)
			} else {
				fmt.Println("[+] Challenge solved successfully!")
				fmt.Printf("    User-Agent: %s\n", challengeResult.UserAgent)
				fmt.Println("    Cookies:")
				for k, v := range challengeResult.Cookies {
					fmt.Printf("      %s: %s\n", k, v)
				}
			}
		},
	}

	cmd.Flags().StringVarP(&proxy, "proxy", "X", "", "Proxy for HTTP requests (scheme://host:port)")
	cmd.Flags().StringVar(&apiProxy, "api-proxy", "", "Proxy for API calls (scheme://host:port)")
	cmd.Flags().StringVarP(&impersonate, "impersonate", "I", "chrome", "Browser to impersonate")
	cmd.Flags().IntVarP(&timeout, "timeout", "T", 120, "Timeout in seconds")
	cmd.Flags().BoolVar(&outputJSON, "json", false, "Output result as JSON")

	return cmd
}

// solve turnstile command
func newSolveTurnstileCmd() *cobra.Command {
	var (
		apiProxy   string
		timeout    int
		outputJSON bool
	)

	cmd := &cobra.Command{
		Use:   "turnstile <url> <sitekey>",
		Short: "Solve Turnstile challenge and get token",
		Args:  cobra.ExactArgs(2),
		Run: func(cmd *cobra.Command, args []string) {
			requireAPIKey()
			url := args[0]
			sitekey := args[1]

			if verbose {
				fmt.Printf("Solving Turnstile challenge for: %s\n", url)
				fmt.Printf("Site key: %s\n", sitekey)
			}

			opts := []cfsolver.Option{
				cfsolver.WithAPIBase(apiBase),
				cfsolver.WithTimeout(time.Duration(timeout) * time.Second),
			}
			if apiProxy != "" {
				opts = append(opts, cfsolver.WithAPIProxy(apiProxy))
			}

			solver := cfsolver.New(apiKey, opts...)
			defer solver.Close()

			token, err := solver.SolveTurnstile(url, sitekey)
			if err != nil {
				if outputJSON {
					printJSON(map[string]interface{}{"success": false, "error": err.Error()})
				} else {
					fmt.Fprintf(os.Stderr, "[x] Error: %v\n", err)
				}
				os.Exit(1)
			}

			result := map[string]interface{}{
				"success": true,
				"url":     url,
				"sitekey": sitekey,
				"token":   token,
			}

			if outputJSON {
				printJSON(result)
			} else {
				fmt.Println("[+] Turnstile solved successfully!")
				tokenPreview := token
				if len(token) > 80 {
					tokenPreview = token[:80] + "..."
				}
				fmt.Printf("    Token: %s\n", tokenPreview)
				fmt.Printf("    Token length: %d\n", len(token))
			}
		},
	}

	cmd.Flags().StringVar(&apiProxy, "api-proxy", "", "Proxy for API calls (scheme://host:port)")
	cmd.Flags().IntVarP(&timeout, "timeout", "T", 120, "Timeout in seconds")
	cmd.Flags().BoolVar(&outputJSON, "json", false, "Output result as JSON")

	return cmd
}

// proxy command
func newProxyCmd() *cobra.Command {
	var (
		host             string
		port             int
		proxy            string
		apiProxy         string
		impersonate      string
		disableDetection bool
		noCache          bool
		timeout          int
	)

	cmd := &cobra.Command{
		Use:   "proxy",
		Short: "Start transparent proxy with Cloudflare challenge detection",
		Long: `Start transparent proxy server with Cloudflare challenge detection.

The proxy automatically detects and solves Cloudflare challenges using the cloud API.
Configure your application to use this proxy (http://host:port) for automatic bypass.

Example:
    cfsolver proxy -K your_api_key -P 8080
    cfsolver proxy -K your_api_key -X socks5://127.0.0.1:1080
    curl -x http://127.0.0.1:8080 https://protected-site.com`,
		Run: func(cmd *cobra.Command, args []string) {
			requireAPIKey()

			if verbose {
				fmt.Printf("Starting transparent proxy on %s:%d\n", host, port)
			}

			proxyServer := cfsolver.NewTransparentProxy(
				apiKey,
				cfsolver.WithProxyAPIBase(apiBase),
				cfsolver.WithProxyHost(host),
				cfsolver.WithProxyPort(port),
				cfsolver.WithProxyUpstream(proxy),
				cfsolver.WithProxyAPIProxy(apiProxy),
				cfsolver.WithProxyImpersonate(impersonate),
				cfsolver.WithProxyDetection(!disableDetection),
				cfsolver.WithProxyCache(!noCache),
				cfsolver.WithProxyTimeout(timeout),
			)

			fmt.Printf("Proxy ready at http://%s:%d\n", host, port)
			fmt.Println("Configure your application to use this proxy for automatic Cloudflare bypass")
			fmt.Println("Press Ctrl+C to stop")

			if err := proxyServer.ListenAndServe(); err != nil {
				fmt.Fprintf(os.Stderr, "Error: %v\n", err)
				os.Exit(1)
			}
		},
	}

	cmd.Flags().StringVarP(&host, "host", "H", "127.0.0.1", "Listen address")
	cmd.Flags().IntVarP(&port, "port", "P", 8080, "Listen port")
	cmd.Flags().StringVarP(&proxy, "proxy", "X", "", "Upstream proxy (socks5://host:port or http://host:port)")
	cmd.Flags().StringVar(&apiProxy, "api-proxy", "", "Proxy for API calls (scheme://host:port)")
	cmd.Flags().StringVarP(&impersonate, "impersonate", "I", "chrome", "Browser to impersonate")
	cmd.Flags().BoolVarP(&disableDetection, "disable-detection", "D", false, "Disable challenge detection (proxy-only mode)")
	cmd.Flags().BoolVarP(&noCache, "no-cache", "S", false, "Disable cf_clearance caching")
	cmd.Flags().IntVarP(&timeout, "timeout", "T", 120, "Challenge solve timeout")

	return cmd
}

// request command
func newRequestCmd() *cobra.Command {
	var (
		proxy       string
		apiProxy    string
		impersonate string
		method      string
		data        string
		headers     []string
		output      string
		outputJSON  bool
	)

	cmd := &cobra.Command{
		Use:   "request <url>",
		Short: "Make HTTP request with automatic challenge bypass",
		Long: `Make HTTP request with automatic challenge bypass.

Examples:
    cfsolver request https://example.com
    cfsolver request -m POST -d '{"key":"value"}' https://api.example.com
    cfsolver request -H "Authorization: Bearer token" https://api.example.com`,
		Args: cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			requireAPIKey()
			url := args[0]

			if verbose {
				fmt.Printf("Making %s request to: %s\n", method, url)
			}

			opts := []cfsolver.Option{
				cfsolver.WithAPIBase(apiBase),
				cfsolver.WithSolve(true),
				cfsolver.WithOnChallenge(true),
			}
			if proxy != "" {
				opts = append(opts, cfsolver.WithProxy(proxy))
			}
			if apiProxy != "" {
				opts = append(opts, cfsolver.WithAPIProxy(apiProxy))
			}
			if impersonate != "" {
				opts = append(opts, cfsolver.WithImpersonate(impersonate))
			}

			solver := cfsolver.New(apiKey, opts...)
			defer solver.Close()

			// Parse headers
			headerMap := make(map[string]string)
			for _, h := range headers {
				parts := strings.SplitN(h, ":", 2)
				if len(parts) == 2 {
					headerMap[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
				}
			}

			var resp *http.Response
			var err error

			switch strings.ToUpper(method) {
			case "GET":
				resp, err = solver.GetWithHeaders(url, headerMap)
			case "POST":
				if data != "" {
					resp, err = solver.Post(url, "application/json", strings.NewReader(data))
				} else {
					resp, err = solver.Post(url, "application/json", nil)
				}
			case "PUT":
				resp, err = solver.Put(url, "application/json", strings.NewReader(data))
			case "DELETE":
				resp, err = solver.Delete(url)
			case "PATCH":
				resp, err = solver.Patch(url, "application/json", strings.NewReader(data))
			case "HEAD":
				resp, err = solver.Head(url)
			case "OPTIONS":
				resp, err = solver.Options(url)
			default:
				fmt.Fprintf(os.Stderr, "Unsupported method: %s\n", method)
				os.Exit(1)
			}

			if err != nil {
				if outputJSON {
					printJSON(map[string]interface{}{"success": false, "error": err.Error()})
				} else {
					fmt.Fprintf(os.Stderr, "[x] Error: %v\n", err)
				}
				os.Exit(1)
			}
			defer resp.Body.Close()

			body, _ := io.ReadAll(resp.Body)

			if output != "" {
				if err := os.WriteFile(output, body, 0644); err != nil {
					fmt.Fprintf(os.Stderr, "[x] Error writing file: %v\n", err)
					os.Exit(1)
				}
				fmt.Printf("[+] Response saved to: %s\n", output)
			} else if outputJSON {
				respHeaders := make(map[string]string)
				for k, v := range resp.Header {
					if len(v) > 0 {
						respHeaders[k] = v[0]
					}
				}
				result := map[string]interface{}{
					"url":            url,
					"method":         strings.ToUpper(method),
					"status_code":    resp.StatusCode,
					"headers":        respHeaders,
					"content_length": len(body),
				}
				printJSON(result)
			} else {
				fmt.Print(string(body))
			}
		},
	}

	cmd.Flags().StringVarP(&proxy, "proxy", "X", "", "Proxy for HTTP requests (scheme://host:port)")
	cmd.Flags().StringVar(&apiProxy, "api-proxy", "", "Proxy for API calls (scheme://host:port)")
	cmd.Flags().StringVarP(&impersonate, "impersonate", "I", "chrome", "Browser to impersonate")
	cmd.Flags().StringVarP(&method, "method", "m", "GET", "HTTP method")
	cmd.Flags().StringVarP(&data, "data", "d", "", "Request body data")
	cmd.Flags().StringArrayVarP(&headers, "header", "H", nil, "Request header (can be used multiple times)")
	cmd.Flags().StringVarP(&output, "output", "o", "", "Output file path")
	cmd.Flags().BoolVar(&outputJSON, "json", false, "Output response info as JSON")

	return cmd
}

// balance command
func newBalanceCmd() *cobra.Command {
	var apiProxy string

	cmd := &cobra.Command{
		Use:   "balance",
		Short: "Check account balance",
		Run: func(cmd *cobra.Command, args []string) {
			requireAPIKey()

			client := &http.Client{Timeout: 30 * time.Second}

			// API uses POST method with JSON body
			reqBody := fmt.Sprintf(`{"apiKey":"%s"}`, apiKey)
			req, err := http.NewRequest("POST", apiBase+"/api/getBalance", strings.NewReader(reqBody))
			if err != nil {
				fmt.Fprintf(os.Stderr, "[x] Error: %v\n", err)
				os.Exit(1)
			}
			req.Header.Set("Content-Type", "application/json")

			resp, err := client.Do(req)
			if err != nil {
				fmt.Fprintf(os.Stderr, "[x] Error: %v\n", err)
				os.Exit(1)
			}
			defer resp.Body.Close()

			if resp.StatusCode != 200 {
				fmt.Fprintf(os.Stderr, "[x] Error: HTTP %d\n", resp.StatusCode)
				os.Exit(1)
			}

			body, _ := io.ReadAll(resp.Body)
			var data map[string]interface{}
			if err := json.Unmarshal(body, &data); err != nil {
				fmt.Fprintf(os.Stderr, "[x] Error parsing response: %v\n", err)
				os.Exit(1)
			}

			if errorID, ok := data["errorId"].(float64); ok && errorID != 0 {
				errorDesc := data["errorDescription"]
				fmt.Fprintf(os.Stderr, "[x] Error: %v\n", errorDesc)
				os.Exit(1)
			}

			balance := data["balance"]
			fmt.Printf("[+] Balance: %v\n", balance)
		},
	}

	cmd.Flags().StringVar(&apiProxy, "api-proxy", "", "Proxy for API calls (scheme://host:port)")

	return cmd
}

func printJSON(v interface{}) {
	data, _ := json.MarshalIndent(v, "", "  ")
	fmt.Println(string(data))
}
