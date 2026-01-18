package cfsolver

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/Noooste/azuretls-client"
	"github.com/cloudflyer-project/masktunnel"
)

// CloudflareSolver is an HTTP client that automatically bypasses Cloudflare challenges.
type CloudflareSolver struct {
	apiKey          string
	apiBase         string
	solve           bool
	onChallenge     bool
	proxy           string
	apiProxy        string
	taskProxy       string // Proxy for the solver task (passed to API)
	usePolling      bool
	pollingInterval time.Duration
	timeout         time.Duration
	userAgent       string
	impersonate     string
	useLinkSocks    bool
	useCache        bool

	session          *azuretls.Session
	apiClient        *http.Client
	linkSocksManager *LinkSocksManager

	cookies   map[string]map[string]string
	cookiesMu sync.RWMutex
	sessionMu sync.Mutex

	// Clearance cache: map[cacheKey]ClearanceData
	clearanceCache   map[string]*ClearanceData
	clearanceCacheMu sync.RWMutex
}

// ClearanceData stores cached clearance information for a host.
type ClearanceData struct {
	Cookies   map[string]string
	UserAgent string
}

// CreateTaskRequest represents the request body for creating a task.
type CreateTaskRequest struct {
	APIKey string      `json:"apiKey"`
	Task   interface{} `json:"task"`
}

// CloudflareTask represents a Cloudflare challenge task.
type CloudflareTask struct {
	Type       string `json:"type"`
	WebsiteURL string `json:"websiteURL"`
	Proxy      string `json:"proxy,omitempty"`
}

// TurnstileTask represents a Turnstile challenge task.
type TurnstileTask struct {
	Type       string `json:"type"`
	WebsiteURL string `json:"websiteURL"`
	WebsiteKey string `json:"websiteKey"`
	Proxy      string `json:"proxy,omitempty"`
}

// CreateTaskResponse represents the response from creating a task.
type CreateTaskResponse struct {
	TaskID           string `json:"taskId"`
	ErrorID          int    `json:"errorId"`
	ErrorDescription string `json:"errorDescription"`
}

// TaskResultRequest represents the request body for getting task result.
type TaskResultRequest struct {
	APIKey string `json:"apiKey"`
	TaskID string `json:"taskId"`
}

// TaskResult represents the result of a task.
type TaskResult struct {
	Status  string                 `json:"status"`
	Success bool                   `json:"success"`
	Result  map[string]interface{} `json:"result"`
	Error   string                 `json:"error"`
}

func normalizeProxyString(proxy string) string {
	proxy = strings.TrimSpace(proxy)
	proxy = strings.ReplaceAll(proxy, "：", ":")
	return proxy
}

// New creates a new CloudflareSolver with the given API key and options.
func New(apiKey string, opts ...Option) *CloudflareSolver {
	s := &CloudflareSolver{
		apiKey:          apiKey,
		apiBase:         "https://solver.zetx.site",
		solve:           true,
		onChallenge:     true,
		usePolling:      false,
		pollingInterval: 2 * time.Second,
		timeout:         30 * time.Second,
		cookies:         make(map[string]map[string]string),
		impersonate:     "chrome",
		useLinkSocks:    true, // Enable LinkSocks by default
		useCache:        true, // Enable cache by default
		clearanceCache:  make(map[string]*ClearanceData),
	}

	for _, opt := range opts {
		opt(s)
	}

	// Trim trailing slash from API base
	s.apiBase = strings.TrimSuffix(s.apiBase, "/")

	// Create HTTP client for API requests (standard client is fine)
	s.apiClient = s.createHTTPClient(s.apiProxy)

	// Initialize LinkSocks manager if enabled
	if s.useLinkSocks {
		s.linkSocksManager = NewLinkSocksManager(s.apiBase, s.apiKey, s.apiClient, s.proxy)
	}

	return s
}

// getSession returns the azuretls session, creating one if needed.
// The session is configured based on the current userAgent.
func (s *CloudflareSolver) getSession() (*azuretls.Session, error) {
	s.sessionMu.Lock()
	defer s.sessionMu.Unlock()

	if s.session != nil {
		return s.session, nil
	}

	return s.createSession()
}

// resetSession closes the current session and creates a new one with updated fingerprint.
func (s *CloudflareSolver) resetSession() error {
	s.sessionMu.Lock()
	defer s.sessionMu.Unlock()

	if s.session != nil {
		s.session.Close()
		s.session = nil
	}

	_, err := s.createSession()
	return err
}

// createSession creates a new azuretls session with proper TLS fingerprint.
// Must be called with sessionMu held.
func (s *CloudflareSolver) createSession() (*azuretls.Session, error) {
	session := azuretls.NewSession()

	// Get browser fingerprint from User-Agent using masktunnel's parser
	ua := s.userAgent
	if ua == "" {
		// Use default Chrome UA if not set
		ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36"
	}

	browserFp, err := masktunnel.GetBrowserFingerprint(ua)
	if err != nil {
		log.Printf("Failed to parse User-Agent, using default Chrome: %v", err)
		browserFp = &masktunnel.BrowserFingerprint{
			Browser:          "Chrome",
			HTTP2Fingerprint: "1:65536,2:0,4:6291456,6:262144|15663105|0|m,a,s,p",
			TLSProfile:       "133",
		}
	}

	log.Printf("Creating session with browser: %s, TLS profile: %s", browserFp.Browser, browserFp.TLSProfile)

	// Configure TLS fingerprint based on browser type
	if err := s.configureTLSFingerprint(session, browserFp.Browser); err != nil {
		return nil, fmt.Errorf("failed to configure TLS fingerprint: %v", err)
	}

	// Configure HTTP/2 fingerprint
	if err := session.ApplyHTTP2(browserFp.HTTP2Fingerprint); err != nil {
		return nil, fmt.Errorf("failed to configure HTTP/2 fingerprint: %v", err)
	}

	// Set User-Agent
	session.UserAgent = ua

	// Configure proxy
	if s.proxy != "" {
		if err := session.SetProxy(s.proxy); err != nil {
			return nil, fmt.Errorf("failed to set proxy: %v", err)
		}
		log.Printf("Configured proxy: %s", s.proxy)
	}

	// Disable auto decompression to handle it ourselves
	session.DisableAutoDecompression = true

	// Skip TLS verification
	session.InsecureSkipVerify = true

	s.session = session
	return session, nil
}

// configureTLSFingerprint configures TLS fingerprint for the session.
func (s *CloudflareSolver) configureTLSFingerprint(session *azuretls.Session, browser string) error {
	switch browser {
	case "Chrome":
		session.Browser = azuretls.Chrome
		session.GetClientHelloSpec = azuretls.GetLastChromeVersion
	case "Firefox":
		session.Browser = azuretls.Firefox
		session.GetClientHelloSpec = azuretls.GetLastFirefoxVersion
	case "Safari":
		session.Browser = azuretls.Safari
		session.GetClientHelloSpec = azuretls.GetLastSafariVersion
	case "Edge":
		session.Browser = azuretls.Edge
		session.GetClientHelloSpec = azuretls.GetLastChromeVersion // Edge is Chromium-based
	case "iOS":
		session.Browser = azuretls.Ios
		session.GetClientHelloSpec = azuretls.GetLastIosVersion
	default:
		// Default to Chrome
		session.Browser = azuretls.Chrome
		session.GetClientHelloSpec = azuretls.GetLastChromeVersion
		log.Printf("Unknown browser %s, using default Chrome configuration", browser)
	}
	return nil
}

func (s *CloudflareSolver) createHTTPClient(proxyURL string) *http.Client {
	transport := &http.Transport{}

	if proxyURL != "" {
		if u, err := url.Parse(proxyURL); err == nil {
			transport.Proxy = http.ProxyURL(u)
		}
	}

	return &http.Client{
		Transport: transport,
		Timeout:   s.timeout,
	}
}

// detectChallenge checks if the response contains a Cloudflare challenge.
func (s *CloudflareSolver) detectChallenge(resp *azuretls.Response) bool {
	if resp.StatusCode != 403 && resp.StatusCode != 503 {
		return false
	}

	server := resp.Header.Get("Server")
	if !strings.Contains(strings.ToLower(server), "cloudflare") {
		return false
	}

	bodyStr := string(resp.Body)
	return strings.Contains(bodyStr, "cf-turnstile") ||
		strings.Contains(bodyStr, "cf-challenge") ||
		strings.Contains(bodyStr, "Just a moment")
}

// solveChallenge solves a Cloudflare challenge for the given URL.
func (s *CloudflareSolver) solveChallenge(ctx context.Context, targetURL string) error {
	log.Printf("Starting challenge solve: %s", targetURL)

	// Ensure LinkSocks is connected if enabled
	if err := s.ensureLinkSocksConnected(); err != nil {
		return err
	}

	// Build task with LinkSocks or taskProxy
	var task interface{}
	if s.linkSocksManager != nil {
		// Use LinkSocks instead of taskProxy
		task = map[string]interface{}{
			"type":       "CloudflareTask",
			"websiteURL": targetURL,
			"linksocks": map[string]string{
				"url":   s.linkSocksManager.GetWsURL(),
				"token": s.linkSocksManager.GetConnectorToken(),
			},
		}
	} else {
		proxy := normalizeProxyString(s.taskProxy)
		task = CloudflareTask{
			Type:       "CloudflareTask",
			WebsiteURL: targetURL,
			Proxy:      proxy,
		}
	}

	reqBody := CreateTaskRequest{
		APIKey: s.apiKey,
		Task:   task,
	}

	jsonBody, err := json.Marshal(reqBody)
	if err != nil {
		return NewConnectionError("failed to marshal request", err)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", s.apiBase+"/api/createTask", bytes.NewReader(jsonBody))
	if err != nil {
		return NewConnectionError("failed to create request", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := s.apiClient.Do(req)
	if err != nil {
		return NewConnectionError("failed to send request", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return NewConnectionError("failed to read response", err)
	}

	var createResp CreateTaskResponse
	if err := json.Unmarshal(body, &createResp); err != nil {
		return NewConnectionError("failed to parse response", err)
	}

	if createResp.ErrorID != 0 {
		return NewChallengeError(fmt.Sprintf("challenge solve failed: %s", createResp.ErrorDescription))
	}

	if createResp.TaskID == "" {
		return NewChallengeError("challenge solve failed: no taskId returned")
	}

	log.Printf("Task created: %s", createResp.TaskID)

	result, err := s.waitForResult(ctx, createResp.TaskID, 120*time.Second)
	if err != nil {
		return err
	}

	// Extract solution from result
	s.extractSolution(targetURL, result)

	// Reset session to apply new fingerprint based on updated User-Agent
	if err := s.resetSession(); err != nil {
		log.Printf("Warning: failed to reset session: %v", err)
	}

	log.Println("Challenge solved successfully")
	return nil
}

// waitForResult waits for the task result using either long-polling or interval polling.
func (s *CloudflareSolver) waitForResult(ctx context.Context, taskID string, timeout time.Duration) (*TaskResult, error) {
	deadline := time.Now().Add(timeout)

	for time.Now().Before(deadline) {
		select {
		case <-ctx.Done():
			return nil, NewTimeoutError("context cancelled")
		default:
		}

		endpoint := s.apiBase + "/api/getTaskResult"
		if !s.usePolling {
			endpoint = s.apiBase + "/api/waitTaskResult"
		}

		reqBody := TaskResultRequest{
			APIKey: s.apiKey,
			TaskID: taskID,
		}

		jsonBody, err := json.Marshal(reqBody)
		if err != nil {
			continue
		}

		reqTimeout := 30 * time.Second
		if !s.usePolling {
			remaining := time.Until(deadline)
			reqTimeout = remaining + 10*time.Second
			if reqTimeout > 310*time.Second {
				reqTimeout = 310 * time.Second
			}
		}

		reqCtx, cancel := context.WithTimeout(ctx, reqTimeout)
		req, err := http.NewRequestWithContext(reqCtx, "POST", endpoint, bytes.NewReader(jsonBody))
		if err != nil {
			cancel()
			continue
		}
		req.Header.Set("Content-Type", "application/json")

		resp, err := s.apiClient.Do(req)
		if err != nil {
			cancel()
			if s.usePolling {
				time.Sleep(s.pollingInterval)
			}
			continue
		}

		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		cancel()

		if err != nil || resp.StatusCode != 200 {
			if s.usePolling {
				time.Sleep(s.pollingInterval)
			}
			continue
		}

		var result TaskResult
		if err := json.Unmarshal(body, &result); err != nil {
			continue
		}

		if result.Status == "processing" {
			if s.usePolling {
				time.Sleep(s.pollingInterval)
			}
			continue
		}

		if result.Status == "timeout" {
			continue
		}

		// Determine success
		success := result.Success
		if !success {
			success = (result.Status == "completed" || result.Status == "ready") && result.Error == ""
		}

		if !success {
			errorMsg := result.Error
			if errorMsg == "" {
				if innerResult, ok := result.Result["error"].(string); ok {
					errorMsg = innerResult
				} else {
					errorMsg = "unknown error"
				}
			}
			return nil, NewChallengeError(fmt.Sprintf("task failed: %s", errorMsg))
		}

		return &result, nil
	}

	return nil, NewTimeoutError("task timed out")
}

// extractSolution extracts cookies and user agent from the task result.
func (s *CloudflareSolver) extractSolution(targetURL string, result *TaskResult) {
	if result == nil || result.Result == nil {
		return
	}

	// Navigate to the actual solution data
	solution := result.Result
	if innerResult, ok := solution["result"].(map[string]interface{}); ok {
		solution = innerResult
	}

	// Extract cookies
	extractedCookies := make(map[string]string)
	if cookies, ok := solution["cookies"].(map[string]interface{}); ok {
		u, err := url.Parse(targetURL)
		if err == nil {
			domain := u.Hostname()
			s.cookiesMu.Lock()
			if s.cookies[domain] == nil {
				s.cookies[domain] = make(map[string]string)
			}
			for k, v := range cookies {
				if strVal, ok := v.(string); ok {
					s.cookies[domain][k] = strVal
					extractedCookies[k] = strVal
				}
			}
			s.cookiesMu.Unlock()
		}
	}

	// Extract user agent - this is critical for TLS fingerprint matching
	var extractedUA string
	if ua, ok := solution["userAgent"].(string); ok {
		s.userAgent = ua
		extractedUA = ua
		log.Printf("Extracted User-Agent: %s", ua)
	} else if headers, ok := solution["headers"].(map[string]interface{}); ok {
		if ua, ok := headers["User-Agent"].(string); ok {
			s.userAgent = ua
			extractedUA = ua
			log.Printf("Extracted User-Agent from headers: %s", ua)
		}
	}

	// Save to cache if enabled
	if s.useCache && (len(extractedCookies) > 0 || extractedUA != "") {
		s.saveToClearanceCache(targetURL, extractedCookies, extractedUA)
	}
}

// getCacheKey generates a cache key from URL host and proxy.
func (s *CloudflareSolver) getCacheKey(targetURL string) string {
	u, err := url.Parse(targetURL)
	if err != nil {
		return ""
	}
	host := u.Hostname()
	proxyKey := s.proxy
	if proxyKey == "" {
		proxyKey = "direct"
	}
	return fmt.Sprintf("%s|%s", host, proxyKey)
}

// loadFromClearanceCache loads clearance data from cache if available.
// Returns true if cache was loaded successfully.
func (s *CloudflareSolver) loadFromClearanceCache(targetURL string) bool {
	if !s.useCache {
		return false
	}

	cacheKey := s.getCacheKey(targetURL)
	if cacheKey == "" {
		return false
	}

	s.clearanceCacheMu.RLock()
	cached, ok := s.clearanceCache[cacheKey]
	s.clearanceCacheMu.RUnlock()

	if !ok || cached == nil {
		return false
	}

	log.Printf("Loading clearance from cache for %s", cacheKey)

	// Apply cached cookies
	u, err := url.Parse(targetURL)
	if err == nil {
		domain := u.Hostname()
		s.cookiesMu.Lock()
		if s.cookies[domain] == nil {
			s.cookies[domain] = make(map[string]string)
		}
		for k, v := range cached.Cookies {
			s.cookies[domain][k] = v
		}
		s.cookiesMu.Unlock()
	}

	// Apply cached user agent
	if cached.UserAgent != "" {
		s.userAgent = cached.UserAgent
	}

	return true
}

// saveToClearanceCache saves clearance data to cache.
func (s *CloudflareSolver) saveToClearanceCache(targetURL string, cookies map[string]string, userAgent string) {
	if !s.useCache {
		return
	}

	cacheKey := s.getCacheKey(targetURL)
	if cacheKey == "" {
		return
	}

	s.clearanceCacheMu.Lock()
	s.clearanceCache[cacheKey] = &ClearanceData{
		Cookies:   cookies,
		UserAgent: userAgent,
	}
	s.clearanceCacheMu.Unlock()

	log.Printf("Saved clearance to cache for %s", cacheKey)
}

// ClearCache clears the clearance cache.
// If host is provided, only clears cache for that host. Otherwise clears all.
func (s *CloudflareSolver) ClearCache(host string) {
	s.clearanceCacheMu.Lock()
	defer s.clearanceCacheMu.Unlock()

	if host == "" {
		s.clearanceCache = make(map[string]*ClearanceData)
		return
	}

	// Clear entries matching the host
	for key := range s.clearanceCache {
		if strings.HasPrefix(key, host+"|") {
			delete(s.clearanceCache, key)
		}
	}
}

// ChallengeResult contains the result of solving a Cloudflare challenge.
type ChallengeResult struct {
	Cookies   map[string]string
	UserAgent string
}

// SolveCloudflare solves a Cloudflare challenge and returns the cookies and user agent.
// Unlike Get/Post methods, this does not make a follow-up request to the target URL.
func (s *CloudflareSolver) SolveCloudflare(websiteURL string) (*ChallengeResult, error) {
	return s.SolveCloudflareContext(context.Background(), websiteURL)
}

// SolveCloudflareContext solves a Cloudflare challenge with context support.
func (s *CloudflareSolver) SolveCloudflareContext(ctx context.Context, websiteURL string) (*ChallengeResult, error) {
	log.Printf("Starting challenge solve: %s", websiteURL)

	// Ensure LinkSocks is connected if enabled
	if err := s.ensureLinkSocksConnected(); err != nil {
		return nil, err
	}

	// Build task with LinkSocks or taskProxy
	var task interface{}
	if s.linkSocksManager != nil {
		task = map[string]interface{}{
			"type":       "CloudflareTask",
			"websiteURL": websiteURL,
			"linksocks": map[string]string{
				"url":   s.linkSocksManager.GetWsURL(),
				"token": s.linkSocksManager.GetConnectorToken(),
			},
		}
	} else {
		proxy := normalizeProxyString(s.taskProxy)
		task = CloudflareTask{
			Type:       "CloudflareTask",
			WebsiteURL: websiteURL,
			Proxy:      proxy,
		}
	}

	reqBody := CreateTaskRequest{
		APIKey: s.apiKey,
		Task:   task,
	}

	jsonBody, err := json.Marshal(reqBody)
	if err != nil {
		return nil, NewConnectionError("failed to marshal request", err)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", s.apiBase+"/api/createTask", bytes.NewReader(jsonBody))
	if err != nil {
		return nil, NewConnectionError("failed to create request", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := s.apiClient.Do(req)
	if err != nil {
		return nil, NewConnectionError("failed to send request", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, NewConnectionError("failed to read response", err)
	}

	var createResp CreateTaskResponse
	if err := json.Unmarshal(body, &createResp); err != nil {
		return nil, NewConnectionError("failed to parse response", err)
	}

	if createResp.ErrorID != 0 {
		return nil, NewChallengeError(fmt.Sprintf("challenge solve failed: %s", createResp.ErrorDescription))
	}

	if createResp.TaskID == "" {
		return nil, NewChallengeError("challenge solve failed: no taskId returned")
	}

	log.Printf("Task created: %s", createResp.TaskID)

	result, err := s.waitForResult(ctx, createResp.TaskID, s.timeout)
	if err != nil {
		return nil, err
	}

	// Extract solution from result
	challengeResult := s.extractSolutionResult(websiteURL, result)

	log.Println("Challenge solved successfully")
	return challengeResult, nil
}

// extractSolutionResult extracts cookies and user agent from the task result and returns them.
func (s *CloudflareSolver) extractSolutionResult(targetURL string, result *TaskResult) *ChallengeResult {
	challengeResult := &ChallengeResult{
		Cookies: make(map[string]string),
	}

	if result == nil || result.Result == nil {
		return challengeResult
	}

	// Navigate to the actual solution data
	solution := result.Result
	if innerResult, ok := solution["result"].(map[string]interface{}); ok {
		solution = innerResult
	}

	// Extract cookies
	if cookies, ok := solution["cookies"].(map[string]interface{}); ok {
		u, err := url.Parse(targetURL)
		if err == nil {
			domain := u.Hostname()
			s.cookiesMu.Lock()
			if s.cookies[domain] == nil {
				s.cookies[domain] = make(map[string]string)
			}
			for k, v := range cookies {
				if strVal, ok := v.(string); ok {
					s.cookies[domain][k] = strVal
					challengeResult.Cookies[k] = strVal
				}
			}
			s.cookiesMu.Unlock()
		}
	}

	// Extract user agent
	if ua, ok := solution["userAgent"].(string); ok {
		s.userAgent = ua
		challengeResult.UserAgent = ua
		log.Printf("Extracted User-Agent: %s", ua)
	} else if headers, ok := solution["headers"].(map[string]interface{}); ok {
		if ua, ok := headers["User-Agent"].(string); ok {
			s.userAgent = ua
			challengeResult.UserAgent = ua
			log.Printf("Extracted User-Agent from headers: %s", ua)
		}
	}

	// Save to cache if enabled
	if s.useCache && (len(challengeResult.Cookies) > 0 || challengeResult.UserAgent != "") {
		s.saveToClearanceCache(targetURL, challengeResult.Cookies, challengeResult.UserAgent)
	}

	return challengeResult
}

// SolveTurnstile solves a Turnstile challenge and returns the token.
func (s *CloudflareSolver) SolveTurnstile(websiteURL, sitekey string) (string, error) {
	return s.SolveTurnstileContext(context.Background(), websiteURL, sitekey)
}

// SolveTurnstileContext solves a Turnstile challenge with context support.
func (s *CloudflareSolver) SolveTurnstileContext(ctx context.Context, websiteURL, sitekey string) (string, error) {
	log.Printf("Starting Turnstile solve: %s", websiteURL)

	proxy := normalizeProxyString(s.taskProxy)
	reqBody := CreateTaskRequest{
		APIKey: s.apiKey,
		Task: TurnstileTask{
			Type:       "TurnstileTask",
			WebsiteURL: websiteURL,
			WebsiteKey: sitekey,
			Proxy:      proxy,
		},
	}

	jsonBody, err := json.Marshal(reqBody)
	if err != nil {
		return "", NewConnectionError("failed to marshal request", err)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", s.apiBase+"/api/createTask", bytes.NewReader(jsonBody))
	if err != nil {
		return "", NewConnectionError("failed to create request", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := s.apiClient.Do(req)
	if err != nil {
		return "", NewConnectionError("failed to send request", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", NewConnectionError("failed to read response", err)
	}

	var createResp CreateTaskResponse
	if err := json.Unmarshal(body, &createResp); err != nil {
		return "", NewConnectionError("failed to parse response", err)
	}

	if createResp.ErrorID != 0 {
		return "", NewChallengeError(fmt.Sprintf("Turnstile solve failed: %s", createResp.ErrorDescription))
	}

	if createResp.TaskID == "" {
		return "", NewChallengeError("Turnstile solve failed: no taskId returned")
	}

	result, err := s.waitForResult(ctx, createResp.TaskID, 120*time.Second)
	if err != nil {
		return "", err
	}

	// Extract token from result
	solution := result.Result
	if innerResult, ok := solution["result"].(map[string]interface{}); ok {
		solution = innerResult
	}

	token, ok := solution["token"].(string)
	if !ok || token == "" {
		return "", NewChallengeError("Turnstile solve failed: no token returned")
	}

	log.Println("Turnstile solved successfully")
	return token, nil
}

// doRequest performs an HTTP request using azuretls session.
func (s *CloudflareSolver) doRequest(ctx context.Context, method, targetURL string, body []byte, headers map[string]string) (*azuretls.Response, error) {
	session, err := s.getSession()
	if err != nil {
		return nil, NewConnectionError("failed to get session", err)
	}

	// Build ordered headers
	orderedHeaders := azuretls.OrderedHeaders{}

	// Add cookies first
	u, err := url.Parse(targetURL)
	if err == nil {
		domain := u.Hostname()
		s.cookiesMu.RLock()
		if domainCookies, ok := s.cookies[domain]; ok {
			var cookieParts []string
			for k, v := range domainCookies {
				cookieParts = append(cookieParts, fmt.Sprintf("%s=%s", k, v))
			}
			if len(cookieParts) > 0 {
				orderedHeaders = append(orderedHeaders, []string{"Cookie", strings.Join(cookieParts, "; ")})
			}
		}
		s.cookiesMu.RUnlock()
	}

	// Add custom headers
	for k, v := range headers {
		orderedHeaders = append(orderedHeaders, []string{k, v})
	}

	req := &azuretls.Request{
		Method:           method,
		Url:              targetURL,
		OrderedHeaders:   orderedHeaders,
		DisableRedirects: false,
		TimeOut:          s.timeout,
	}

	if body != nil {
		req.Body = bytes.NewReader(body)
	}

	return session.Do(req)
}

// Get sends a GET request.
func (s *CloudflareSolver) Get(targetURL string) (*http.Response, error) {
	return s.GetContext(context.Background(), targetURL)
}

// GetContext sends a GET request with context.
func (s *CloudflareSolver) GetContext(ctx context.Context, targetURL string) (*http.Response, error) {
	return s.request(ctx, "GET", targetURL, nil, nil)
}

// GetWithHeaders sends a GET request with custom headers.
func (s *CloudflareSolver) GetWithHeaders(targetURL string, headers map[string]string) (*http.Response, error) {
	return s.GetWithHeadersContext(context.Background(), targetURL, headers)
}

// GetWithHeadersContext sends a GET request with context and custom headers.
func (s *CloudflareSolver) GetWithHeadersContext(ctx context.Context, targetURL string, headers map[string]string) (*http.Response, error) {
	return s.request(ctx, "GET", targetURL, nil, headers)
}

// Post sends a POST request.
func (s *CloudflareSolver) Post(targetURL, contentType string, body io.Reader) (*http.Response, error) {
	return s.PostContext(context.Background(), targetURL, contentType, body)
}

// PostContext sends a POST request with context.
func (s *CloudflareSolver) PostContext(ctx context.Context, targetURL, contentType string, body io.Reader) (*http.Response, error) {
	var bodyBytes []byte
	if body != nil {
		var err error
		bodyBytes, err = io.ReadAll(body)
		if err != nil {
			return nil, NewConnectionError("failed to read request body", err)
		}
	}
	headers := map[string]string{"Content-Type": contentType}
	return s.request(ctx, "POST", targetURL, bodyBytes, headers)
}

// PostJSON sends a POST request with JSON body.
func (s *CloudflareSolver) PostJSON(targetURL string, data interface{}) (*http.Response, error) {
	return s.PostJSONContext(context.Background(), targetURL, data)
}

// PostJSONContext sends a POST request with context and JSON body.
func (s *CloudflareSolver) PostJSONContext(ctx context.Context, targetURL string, data interface{}) (*http.Response, error) {
	jsonBody, err := json.Marshal(data)
	if err != nil {
		return nil, NewConnectionError("failed to marshal JSON", err)
	}
	headers := map[string]string{"Content-Type": "application/json"}
	return s.request(ctx, "POST", targetURL, jsonBody, headers)
}

// PostForm sends a POST request with form data.
func (s *CloudflareSolver) PostForm(targetURL string, data url.Values) (*http.Response, error) {
	return s.PostFormContext(context.Background(), targetURL, data)
}

// PostFormContext sends a POST request with context and form data.
func (s *CloudflareSolver) PostFormContext(ctx context.Context, targetURL string, data url.Values) (*http.Response, error) {
	headers := map[string]string{"Content-Type": "application/x-www-form-urlencoded"}
	return s.request(ctx, "POST", targetURL, []byte(data.Encode()), headers)
}

// Put sends a PUT request.
func (s *CloudflareSolver) Put(targetURL, contentType string, body io.Reader) (*http.Response, error) {
	return s.PutContext(context.Background(), targetURL, contentType, body)
}

// PutContext sends a PUT request with context.
func (s *CloudflareSolver) PutContext(ctx context.Context, targetURL, contentType string, body io.Reader) (*http.Response, error) {
	var bodyBytes []byte
	if body != nil {
		var err error
		bodyBytes, err = io.ReadAll(body)
		if err != nil {
			return nil, NewConnectionError("failed to read request body", err)
		}
	}
	headers := map[string]string{"Content-Type": contentType}
	return s.request(ctx, "PUT", targetURL, bodyBytes, headers)
}

// Delete sends a DELETE request.
func (s *CloudflareSolver) Delete(targetURL string) (*http.Response, error) {
	return s.DeleteContext(context.Background(), targetURL)
}

// DeleteContext sends a DELETE request with context.
func (s *CloudflareSolver) DeleteContext(ctx context.Context, targetURL string) (*http.Response, error) {
	return s.request(ctx, "DELETE", targetURL, nil, nil)
}

// Patch sends a PATCH request.
func (s *CloudflareSolver) Patch(targetURL, contentType string, body io.Reader) (*http.Response, error) {
	return s.PatchContext(context.Background(), targetURL, contentType, body)
}

// PatchContext sends a PATCH request with context.
func (s *CloudflareSolver) PatchContext(ctx context.Context, targetURL, contentType string, body io.Reader) (*http.Response, error) {
	var bodyBytes []byte
	if body != nil {
		var err error
		bodyBytes, err = io.ReadAll(body)
		if err != nil {
			return nil, NewConnectionError("failed to read request body", err)
		}
	}
	headers := map[string]string{"Content-Type": contentType}
	return s.request(ctx, "PATCH", targetURL, bodyBytes, headers)
}

// Head sends a HEAD request.
func (s *CloudflareSolver) Head(targetURL string) (*http.Response, error) {
	return s.HeadContext(context.Background(), targetURL)
}

// HeadContext sends a HEAD request with context.
func (s *CloudflareSolver) HeadContext(ctx context.Context, targetURL string) (*http.Response, error) {
	return s.request(ctx, "HEAD", targetURL, nil, nil)
}

// Options sends an OPTIONS request.
func (s *CloudflareSolver) Options(targetURL string) (*http.Response, error) {
	return s.OptionsContext(context.Background(), targetURL)
}

// OptionsContext sends an OPTIONS request with context.
func (s *CloudflareSolver) OptionsContext(ctx context.Context, targetURL string) (*http.Response, error) {
	return s.request(ctx, "OPTIONS", targetURL, nil, nil)
}

// RequestOptions contains per-request override options.
type RequestOptions struct {
	// Solve overrides the instance-level solve setting for this request.
	// nil means use instance default.
	Solve *bool
	// OnChallenge overrides the instance-level on_challenge setting for this request.
	// nil means use instance default.
	OnChallenge *bool
	// UseCache overrides the instance-level use_cache setting for this request.
	// nil means use instance default.
	UseCache *bool
}

// RequestWithOptions sends an HTTP request with per-request option overrides.
func (s *CloudflareSolver) RequestWithOptions(ctx context.Context, method, targetURL string, body []byte, headers map[string]string, opts *RequestOptions) (*http.Response, error) {
	// Determine effective settings
	solve := s.solve
	onChallenge := s.onChallenge
	useCache := s.useCache

	if opts != nil {
		if opts.Solve != nil {
			solve = *opts.Solve
		}
		if opts.OnChallenge != nil {
			onChallenge = *opts.OnChallenge
		}
		if opts.UseCache != nil {
			useCache = *opts.UseCache
		}
	}

	// Try to load from cache first
	if useCache {
		s.loadFromClearanceCache(targetURL)
	}

	if !solve {
		resp, err := s.doRequest(ctx, method, targetURL, body, headers)
		if err != nil {
			return nil, err
		}
		return s.convertResponse(resp), nil
	}

	if !onChallenge {
		if err := s.solveChallengeWithCache(ctx, targetURL, useCache); err != nil {
			log.Printf("Pre-solve failed: %v", err)
		}
	}

	resp, err := s.doRequest(ctx, method, targetURL, body, headers)
	if err != nil {
		return nil, err
	}

	if onChallenge && s.detectChallenge(resp) {
		log.Println("Cloudflare challenge detected")
		if err := s.solveChallengeWithCache(ctx, targetURL, useCache); err != nil {
			return nil, err
		}

		// Retry request with solved cookies and UA
		log.Printf("Retrying with UA: %s", s.userAgent)
		resp, err = s.doRequest(ctx, method, targetURL, body, headers)
		if err != nil {
			return nil, err
		}
	}

	return s.convertResponse(resp), nil
}

// solveChallengeWithCache is like solveChallenge but respects the useCache parameter.
func (s *CloudflareSolver) solveChallengeWithCache(ctx context.Context, targetURL string, useCache bool) error {
	// Temporarily override useCache setting
	originalUseCache := s.useCache
	s.useCache = useCache
	defer func() { s.useCache = originalUseCache }()

	return s.solveChallenge(ctx, targetURL)
}

// request is the internal method that handles all HTTP requests with challenge detection.
func (s *CloudflareSolver) request(ctx context.Context, method, targetURL string, body []byte, headers map[string]string) (*http.Response, error) {
	// Try to load from cache first
	if s.useCache {
		s.loadFromClearanceCache(targetURL)
	}

	if !s.solve {
		resp, err := s.doRequest(ctx, method, targetURL, body, headers)
		if err != nil {
			return nil, err
		}
		return s.convertResponse(resp), nil
	}

	if !s.onChallenge {
		if err := s.solveChallenge(ctx, targetURL); err != nil {
			log.Printf("Pre-solve failed: %v", err)
		}
	}

	resp, err := s.doRequest(ctx, method, targetURL, body, headers)
	if err != nil {
		return nil, err
	}

	if s.onChallenge && s.detectChallenge(resp) {
		log.Println("Cloudflare challenge detected")
		if err := s.solveChallenge(ctx, targetURL); err != nil {
			return nil, err
		}

		// Retry request with solved cookies and UA
		log.Printf("Retrying with UA: %s", s.userAgent)
		resp, err = s.doRequest(ctx, method, targetURL, body, headers)
		if err != nil {
			return nil, err
		}
	}

	return s.convertResponse(resp), nil
}

// convertResponse converts azuretls.Response to http.Response for API compatibility.
func (s *CloudflareSolver) convertResponse(resp *azuretls.Response) *http.Response {
	httpResp := &http.Response{
		Status:        resp.Status,
		StatusCode:    resp.StatusCode,
		Proto:         "HTTP/2.0",
		ProtoMajor:    2,
		ProtoMinor:    0,
		Header:        make(http.Header),
		Body:          io.NopCloser(bytes.NewReader(resp.Body)),
		ContentLength: int64(len(resp.Body)),
	}

	// Copy headers
	for k, v := range resp.Header {
		httpResp.Header[k] = v
	}

	return httpResp
}

// ensureLinkSocksConnected ensures LinkSocks is connected if enabled
func (s *CloudflareSolver) ensureLinkSocksConnected() error {
	if s.linkSocksManager != nil {
		if err := s.linkSocksManager.Connect(); err != nil {
			return NewConnectionError("failed to connect LinkSocks", err)
		}
	}
	return nil
}

// Close closes the solver and releases resources including LinkSocks process
func (s *CloudflareSolver) Close() error {
	s.sessionMu.Lock()
	if s.session != nil {
		s.session.Close()
		s.session = nil
	}
	s.sessionMu.Unlock()

	if s.linkSocksManager != nil {
		return s.linkSocksManager.Close()
	}
	return nil
}
