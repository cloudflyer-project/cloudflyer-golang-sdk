package cfsolver

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"
)

// getTestAPIKey returns the API key from environment variable for integration tests.
// Returns empty string if not set.
func getTestAPIKey() string {
	return os.Getenv("CLOUDFLYER_API_KEY")
}

// getTestAPIBase returns the API base URL from environment variable.
// Defaults to production URL if not set.
func getTestAPIBase() string {
	base := os.Getenv("CLOUDFLYER_API_BASE")
	if base == "" {
		base = "https://solver.zetx.site"
	}
	return base
}

// skipIfNoAPIKey skips the test if API key is not available.
func skipIfNoAPIKey(t *testing.T) string {
	apiKey := getTestAPIKey()
	if apiKey == "" {
		t.Skip("Skipping integration test: CLOUDFLYER_API_KEY not set")
	}
	return apiKey
}

// =============================================================================
// Unit Tests (no API key required)
// =============================================================================

func TestNew(t *testing.T) {
	solver := New("test-api-key")
	defer solver.Close()

	if solver.apiKey != "test-api-key" {
		t.Errorf("Expected apiKey to be 'test-api-key', got '%s'", solver.apiKey)
	}
	if solver.apiBase != "https://solver.zetx.site" {
		t.Errorf("Expected default apiBase, got '%s'", solver.apiBase)
	}
	if !solver.solve {
		t.Error("Expected solve to be true by default")
	}
	if !solver.onChallenge {
		t.Error("Expected onChallenge to be true by default")
	}
	if !solver.useCache {
		t.Error("Expected useCache to be true by default")
	}
	if !solver.useLinkSocks {
		t.Error("Expected useLinkSocks to be true by default")
	}
}

func TestNewWithOptions(t *testing.T) {
	solver := New("test-api-key",
		WithAPIBase("https://custom.api.com"),
		WithSolve(false),
		WithOnChallenge(false),
		WithProxy("http://proxy:8080"),
		WithAPIProxy("http://api-proxy:8080"),
		WithTaskProxy("http://task-proxy:8080"),
		WithTimeout(60*time.Second),
		WithUserAgent("CustomUA/1.0"),
		WithImpersonate("firefox"),
		WithUseLinkSocks(false),
		WithUseCache(false),
		WithUsePolling(true),
	)
	defer solver.Close()

	if solver.apiBase != "https://custom.api.com" {
		t.Errorf("Expected apiBase 'https://custom.api.com', got '%s'", solver.apiBase)
	}
	if solver.solve {
		t.Error("Expected solve to be false")
	}
	if solver.onChallenge {
		t.Error("Expected onChallenge to be false")
	}
	if solver.proxy != "http://proxy:8080" {
		t.Errorf("Expected proxy 'http://proxy:8080', got '%s'", solver.proxy)
	}
	if solver.apiProxy != "http://api-proxy:8080" {
		t.Errorf("Expected apiProxy 'http://api-proxy:8080', got '%s'", solver.apiProxy)
	}
	if solver.taskProxy != "http://task-proxy:8080" {
		t.Errorf("Expected taskProxy 'http://task-proxy:8080', got '%s'", solver.taskProxy)
	}
	if solver.timeout != 60*time.Second {
		t.Errorf("Expected timeout 60s, got %v", solver.timeout)
	}
	if solver.userAgent != "CustomUA/1.0" {
		t.Errorf("Expected userAgent 'CustomUA/1.0', got '%s'", solver.userAgent)
	}
	if solver.impersonate != "firefox" {
		t.Errorf("Expected impersonate 'firefox', got '%s'", solver.impersonate)
	}
	if solver.useLinkSocks {
		t.Error("Expected useLinkSocks to be false")
	}
	if solver.useCache {
		t.Error("Expected useCache to be false")
	}
	if !solver.usePolling {
		t.Error("Expected usePolling to be true")
	}
}

func TestAPIBaseTrailingSlash(t *testing.T) {
	solver := New("test-api-key", WithAPIBase("https://api.example.com/"))
	defer solver.Close()

	if solver.apiBase != "https://api.example.com" {
		t.Errorf("Expected trailing slash to be trimmed, got '%s'", solver.apiBase)
	}
}

func TestNormalizeProxyString(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"http://proxy:8080", "http://proxy:8080"},
		{"  http://proxy:8080  ", "http://proxy:8080"},
		{"http://proxy：8080", "http://proxy:8080"}, // Full-width colon
		{"http：//proxy：8080", "http://proxy:8080"},
	}

	for _, tt := range tests {
		result := normalizeProxyString(tt.input)
		if result != tt.expected {
			t.Errorf("normalizeProxyString(%q) = %q, want %q", tt.input, result, tt.expected)
		}
	}
}

func TestClearanceCache(t *testing.T) {
	solver := New("test-api-key", WithUseLinkSocks(false))
	defer solver.Close()

	// Save to cache
	solver.saveToClearanceCache("https://example.com/page", map[string]string{
		"cf_clearance": "test-cookie",
	}, "TestUA/1.0")

	// Verify cache key generation
	cacheKey := solver.getCacheKey("https://example.com/page")
	if cacheKey != "example.com|direct" {
		t.Errorf("Expected cache key 'example.com|direct', got '%s'", cacheKey)
	}

	// Load from cache
	loaded := solver.loadFromClearanceCache("https://example.com/other-page")
	if !loaded {
		t.Error("Expected cache to be loaded")
	}

	if solver.userAgent != "TestUA/1.0" {
		t.Errorf("Expected userAgent 'TestUA/1.0', got '%s'", solver.userAgent)
	}

	// Clear specific host
	solver.ClearCache("example.com")
	loaded = solver.loadFromClearanceCache("https://example.com/page")
	if loaded {
		t.Error("Expected cache to be cleared for example.com")
	}

	// Test clear all
	solver.saveToClearanceCache("https://test1.com/", map[string]string{"a": "b"}, "UA1")
	solver.saveToClearanceCache("https://test2.com/", map[string]string{"c": "d"}, "UA2")
	solver.ClearCache("")
	if len(solver.clearanceCache) != 0 {
		t.Errorf("Expected all cache to be cleared, got %d entries", len(solver.clearanceCache))
	}
}

func TestCacheKeyWithProxy(t *testing.T) {
	solver := New("test-api-key",
		WithProxy("http://proxy:8080"),
		WithUseLinkSocks(false),
	)
	defer solver.Close()

	cacheKey := solver.getCacheKey("https://example.com/page")
	if cacheKey != "example.com|http://proxy:8080" {
		t.Errorf("Expected cache key with proxy, got '%s'", cacheKey)
	}
}

func TestVersion(t *testing.T) {
	if Version == "" {
		t.Error("Version should not be empty")
	}
}

// =============================================================================
// Error Types Tests
// =============================================================================

func TestAPIError(t *testing.T) {
	err := NewAPIError("test error", 400)
	if err.StatusCode != 400 {
		t.Errorf("Expected status code 400, got %d", err.StatusCode)
	}
	if !strings.Contains(err.Error(), "test error") {
		t.Errorf("Error message should contain 'test error', got '%s'", err.Error())
	}
	if !strings.Contains(err.Error(), "400") {
		t.Errorf("Error message should contain status code, got '%s'", err.Error())
	}
}

func TestChallengeError(t *testing.T) {
	err := NewChallengeError("challenge failed")
	if !strings.Contains(err.Error(), "challenge failed") {
		t.Errorf("Error message should contain 'challenge failed', got '%s'", err.Error())
	}
}

func TestTimeoutError(t *testing.T) {
	err := NewTimeoutError("operation timed out")
	if !strings.Contains(err.Error(), "operation timed out") {
		t.Errorf("Error message should contain 'operation timed out', got '%s'", err.Error())
	}
}

func TestConnectionError(t *testing.T) {
	cause := &APIError{Message: "underlying error", StatusCode: 500}
	err := NewConnectionError("connection failed", cause)

	if !strings.Contains(err.Error(), "connection failed") {
		t.Errorf("Error message should contain 'connection failed', got '%s'", err.Error())
	}
	if err.Unwrap() != cause {
		t.Error("Unwrap should return the cause")
	}

	// Test without cause
	errNoCause := NewConnectionError("no cause", nil)
	if errNoCause.Unwrap() != nil {
		t.Error("Unwrap should return nil when no cause")
	}
}

func TestProxyError(t *testing.T) {
	cause := &APIError{Message: "proxy failed", StatusCode: 502}
	err := NewProxyError("proxy connection failed", cause)

	if !strings.Contains(err.Error(), "proxy connection failed") {
		t.Errorf("Error message should contain 'proxy connection failed', got '%s'", err.Error())
	}
	if err.Unwrap() != cause {
		t.Error("Unwrap should return the cause")
	}
}

// =============================================================================
// Mock Server Tests
// =============================================================================

func TestCreateTaskRequest(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/createTask" {
			t.Errorf("Expected path /api/createTask, got %s", r.URL.Path)
		}
		if r.Method != "POST" {
			t.Errorf("Expected POST method, got %s", r.Method)
		}
		if r.Header.Get("Content-Type") != "application/json" {
			t.Errorf("Expected Content-Type application/json, got %s", r.Header.Get("Content-Type"))
		}

		body, _ := io.ReadAll(r.Body)
		var req CreateTaskRequest
		if err := json.Unmarshal(body, &req); err != nil {
			t.Errorf("Failed to unmarshal request: %v", err)
		}

		if req.APIKey != "test-api-key" {
			t.Errorf("Expected apiKey 'test-api-key', got '%s'", req.APIKey)
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(CreateTaskResponse{
			TaskID:  "task-123",
			ErrorID: 0,
		})
	}))
	defer server.Close()

	solver := New("test-api-key",
		WithAPIBase(server.URL),
		WithUseLinkSocks(false),
	)
	defer solver.Close()

	// Verify the solver was configured correctly
	if solver.apiBase != server.URL {
		t.Errorf("Expected apiBase '%s', got '%s'", server.URL, solver.apiBase)
	}
}

func TestTaskResultPolling(t *testing.T) {
	callCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		if r.URL.Path == "/api/createTask" {
			_ = json.NewEncoder(w).Encode(CreateTaskResponse{
				TaskID:  "task-123",
				ErrorID: 0,
			})
			return
		}

		if r.URL.Path == "/api/getTaskResult" || r.URL.Path == "/api/waitTaskResult" {
			callCount++
			if callCount < 2 {
				_ = json.NewEncoder(w).Encode(TaskResult{
					Status: "processing",
				})
			} else {
				_ = json.NewEncoder(w).Encode(TaskResult{
					Status:  "completed",
					Success: true,
					Result: map[string]interface{}{
						"cookies": map[string]interface{}{
							"cf_clearance": "test-clearance",
						},
						"userAgent": "Mozilla/5.0 Test",
					},
				})
			}
			return
		}
	}))
	defer server.Close()

	solver := New("test-api-key",
		WithAPIBase(server.URL),
		WithUseLinkSocks(false),
		WithUsePolling(true),
		WithTimeout(10*time.Second),
	)
	defer solver.Close()

	ctx := context.Background()
	result, err := solver.waitForResult(ctx, "task-123", 30*time.Second)
	if err != nil {
		t.Fatalf("waitForResult failed: %v", err)
	}

	if result.Status != "completed" {
		t.Errorf("Expected status 'completed', got '%s'", result.Status)
	}
}

func TestTaskResultError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(TaskResult{
			Status:  "failed",
			Success: false,
			Error:   "task execution failed",
		})
	}))
	defer server.Close()

	solver := New("test-api-key",
		WithAPIBase(server.URL),
		WithUseLinkSocks(false),
		WithUsePolling(true),
	)
	defer solver.Close()

	ctx := context.Background()
	_, err := solver.waitForResult(ctx, "task-123", 5*time.Second)
	if err == nil {
		t.Fatal("Expected error, got nil")
	}

	if !strings.Contains(err.Error(), "task execution failed") {
		t.Errorf("Expected error to contain 'task execution failed', got '%s'", err.Error())
	}
}

func TestExtractSolution(t *testing.T) {
	solver := New("test-api-key", WithUseLinkSocks(false))
	defer solver.Close()

	result := &TaskResult{
		Status:  "completed",
		Success: true,
		Result: map[string]interface{}{
			"cookies": map[string]interface{}{
				"cf_clearance": "test-clearance-value",
				"__cf_bm":      "test-bm-value",
			},
			"userAgent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Test",
		},
	}

	solver.extractSolution("https://example.com/page", result)

	// Check cookies were extracted
	solver.cookiesMu.RLock()
	cookies := solver.cookies["example.com"]
	solver.cookiesMu.RUnlock()

	if cookies["cf_clearance"] != "test-clearance-value" {
		t.Errorf("Expected cf_clearance cookie, got '%s'", cookies["cf_clearance"])
	}
	if cookies["__cf_bm"] != "test-bm-value" {
		t.Errorf("Expected __cf_bm cookie, got '%s'", cookies["__cf_bm"])
	}

	// Check user agent was extracted
	if solver.userAgent != "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Test" {
		t.Errorf("Expected userAgent to be set, got '%s'", solver.userAgent)
	}
}

func TestExtractSolutionNested(t *testing.T) {
	solver := New("test-api-key", WithUseLinkSocks(false))
	defer solver.Close()

	// Test nested result structure
	result := &TaskResult{
		Status:  "completed",
		Success: true,
		Result: map[string]interface{}{
			"result": map[string]interface{}{
				"cookies": map[string]interface{}{
					"cf_clearance": "nested-clearance",
				},
				"userAgent": "Nested UA",
			},
		},
	}

	solver.extractSolution("https://nested.example.com/", result)

	solver.cookiesMu.RLock()
	cookies := solver.cookies["nested.example.com"]
	solver.cookiesMu.RUnlock()

	if cookies["cf_clearance"] != "nested-clearance" {
		t.Errorf("Expected nested cf_clearance cookie, got '%s'", cookies["cf_clearance"])
	}
}

func TestRequestOptions(t *testing.T) {
	opts := &RequestOptions{
		Solve:       boolPtr(false),
		OnChallenge: boolPtr(true),
		UseCache:    boolPtr(false),
	}

	if *opts.Solve != false {
		t.Error("Expected Solve to be false")
	}
	if *opts.OnChallenge != true {
		t.Error("Expected OnChallenge to be true")
	}
	if *opts.UseCache != false {
		t.Error("Expected UseCache to be false")
	}
}

func boolPtr(b bool) *bool {
	return &b
}

// =============================================================================
// Integration Tests (require API key)
// =============================================================================

func TestIntegration_SolveCloudflare(t *testing.T) {
	apiKey := skipIfNoAPIKey(t)

	solver := New(apiKey,
		WithAPIBase(getTestAPIBase()),
		WithTimeout(120*time.Second),
	)
	defer solver.Close()

	// Test solving a Cloudflare challenge (using demo URL from examples)
	result, err := solver.SolveCloudflare("https://cloudflyer.zetx.site/demo/challenge")
	if err != nil {
		t.Fatalf("SolveCloudflare failed: %v", err)
	}

	if result == nil {
		t.Fatal("Expected result, got nil")
	}

	if len(result.Cookies) == 0 {
		t.Error("Expected cookies in result")
	}

	if result.UserAgent == "" {
		t.Error("Expected userAgent in result")
	}

	t.Logf("Solved challenge, got %d cookies, UA: %s", len(result.Cookies), result.UserAgent)
}

func TestIntegration_GetProtectedPage(t *testing.T) {
	apiKey := skipIfNoAPIKey(t)

	solver := New(apiKey,
		WithAPIBase(getTestAPIBase()),
		WithTimeout(120*time.Second),
	)
	defer solver.Close()

	// Using demo URL from examples
	resp, err := solver.Get("https://cloudflyer.zetx.site/demo/challenge")
	if err != nil {
		t.Fatalf("Get failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		t.Errorf("Expected status 200, got %d", resp.StatusCode)
	}

	body, _ := io.ReadAll(resp.Body)
	if len(body) == 0 {
		t.Error("Expected non-empty response body")
	}

	t.Logf("Got response: status=%d, body length=%d", resp.StatusCode, len(body))
}

func TestIntegration_SolveTurnstile(t *testing.T) {
	apiKey := skipIfNoAPIKey(t)

	solver := New(apiKey,
		WithAPIBase(getTestAPIBase()),
		WithTimeout(120*time.Second),
	)
	defer solver.Close()

	// Using demo URL and siteKey from examples
	token, err := solver.SolveTurnstile(
		"https://cloudflyer.zetx.site/demo/turnstile",
		"0x4AAAAAACJkAlPHW8xr1T2J",
	)
	if err != nil {
		t.Fatalf("SolveTurnstile failed: %v", err)
	}

	if token == "" {
		t.Error("Expected non-empty token")
	}

	t.Logf("Got Turnstile token: %s...", token[:min(50, len(token))])
}

func TestIntegration_CacheReuse(t *testing.T) {
	apiKey := skipIfNoAPIKey(t)

	solver := New(apiKey,
		WithAPIBase(getTestAPIBase()),
		WithTimeout(120*time.Second),
		WithUseCache(true),
	)
	defer solver.Close()

	// First request - should solve challenge (using demo URL from examples)
	resp1, err := solver.Get("https://cloudflyer.zetx.site/demo/challenge")
	if err != nil {
		t.Fatalf("First Get failed: %v", err)
	}
	resp1.Body.Close()

	// Second request - should use cached clearance
	start := time.Now()
	resp2, err := solver.Get("https://cloudflyer.zetx.site/demo/challenge")
	if err != nil {
		t.Fatalf("Second Get failed: %v", err)
	}
	resp2.Body.Close()
	elapsed := time.Since(start)

	// Second request should be much faster due to cache
	t.Logf("Second request took %v", elapsed)

	if resp2.StatusCode != 200 {
		t.Errorf("Expected status 200, got %d", resp2.StatusCode)
	}
}

func TestIntegration_ContextCancellation(t *testing.T) {
	apiKey := skipIfNoAPIKey(t)

	solver := New(apiKey,
		WithAPIBase(getTestAPIBase()),
		WithTimeout(120*time.Second),
	)
	defer solver.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()

	// Using demo URL from examples
	_, err := solver.SolveCloudflareContext(ctx, "https://cloudflyer.zetx.site/demo/challenge")
	if err == nil {
		t.Log("Request completed before timeout (this is okay)")
	} else {
		// Should get a timeout or context cancelled error
		t.Logf("Got expected error: %v", err)
	}
}

func TestIntegration_PostRequest(t *testing.T) {
	apiKey := skipIfNoAPIKey(t)

	solver := New(apiKey,
		WithAPIBase(getTestAPIBase()),
		WithTimeout(120*time.Second),
		WithSolve(false), // Disable solving for this test
	)
	defer solver.Close()

	// Test POST to httpbin (not Cloudflare protected)
	resp, err := solver.PostJSON("https://httpbin.org/post", map[string]string{
		"test": "value",
	})
	if err != nil {
		t.Fatalf("PostJSON failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		t.Errorf("Expected status 200, got %d", resp.StatusCode)
	}

	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "test") {
		t.Error("Expected response to contain posted data")
	}
}

func TestIntegration_APIKeyValidation(t *testing.T) {
	// Test with invalid API key
	solver := New("invalid-api-key",
		WithAPIBase(getTestAPIBase()),
		WithTimeout(30*time.Second),
	)
	defer solver.Close()

	// Using demo URL from examples
	_, err := solver.SolveCloudflare("https://cloudflyer.zetx.site/demo/challenge")
	if err == nil {
		t.Error("Expected error with invalid API key")
	}

	t.Logf("Got expected error for invalid API key: %v", err)
}

// =============================================================================
// Benchmark Tests
// =============================================================================

func BenchmarkNew(b *testing.B) {
	for i := 0; i < b.N; i++ {
		solver := New("test-api-key", WithUseLinkSocks(false))
		solver.Close()
	}
}

func BenchmarkCacheOperations(b *testing.B) {
	solver := New("test-api-key", WithUseLinkSocks(false))
	defer solver.Close()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		solver.saveToClearanceCache("https://example.com/", map[string]string{
			"cf_clearance": "test",
		}, "TestUA")
		solver.loadFromClearanceCache("https://example.com/page")
	}
}

func BenchmarkNormalizeProxyString(b *testing.B) {
	for i := 0; i < b.N; i++ {
		normalizeProxyString("  http://proxy：8080  ")
	}
}
