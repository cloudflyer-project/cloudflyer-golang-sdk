package cfsolver

import "time"

// Option is a function that configures a CloudflareSolver.
type Option func(*CloudflareSolver)

// WithAPIBase sets the CloudFlyer API base URL.
func WithAPIBase(apiBase string) Option {
	return func(s *CloudflareSolver) {
		s.apiBase = apiBase
	}
}

// WithSolve enables or disables automatic challenge solving.
func WithSolve(solve bool) Option {
	return func(s *CloudflareSolver) {
		s.solve = solve
	}
}

// WithOnChallenge sets whether to solve only when challenge is detected.
// If false, challenges are pre-solved before each request.
func WithOnChallenge(onChallenge bool) Option {
	return func(s *CloudflareSolver) {
		s.onChallenge = onChallenge
	}
}

// WithProxy sets the HTTP proxy for user requests.
func WithProxy(proxy string) Option {
	return func(s *CloudflareSolver) {
		s.proxy = proxy
	}
}

// WithAPIProxy sets the HTTP proxy for API requests.
func WithAPIProxy(apiProxy string) Option {
	return func(s *CloudflareSolver) {
		s.apiProxy = apiProxy
	}
}

// WithUsePolling sets whether to use interval polling instead of long-polling.
func WithUsePolling(usePolling bool) Option {
	return func(s *CloudflareSolver) {
		s.usePolling = usePolling
	}
}

// WithTimeout sets the request timeout.
func WithTimeout(timeout time.Duration) Option {
	return func(s *CloudflareSolver) {
		s.timeout = timeout
	}
}

// WithUserAgent sets a custom User-Agent header.
func WithUserAgent(userAgent string) Option {
	return func(s *CloudflareSolver) {
		s.userAgent = userAgent
	}
}

// WithImpersonate sets the browser to impersonate for TLS fingerprint.
// Supported values: "chrome", "chrome120", "chrome110", "chrome100",
// "firefox", "firefox120", "firefox110", "safari", "edge".
// Default is "chrome" (Chrome 120).
func WithImpersonate(impersonate string) Option {
	return func(s *CloudflareSolver) {
		s.impersonate = impersonate
	}
}

// WithTaskProxy sets the proxy for the solver task (passed to API).
// This proxy will be used by the solver service to access the target website.
// Note: When LinkSocks is enabled (default), this option is ignored.
func WithTaskProxy(taskProxy string) Option {
	return func(s *CloudflareSolver) {
		s.taskProxy = taskProxy
	}
}

// WithUseLinkSocks enables or disables LinkSocks for proper browser fingerprinting.
// When enabled (default), uses LinkSocks to provide correct TLS fingerprint.
// When disabled, falls back to taskProxy (not recommended, may cause 403 errors).
func WithUseLinkSocks(use bool) Option {
	return func(s *CloudflareSolver) {
		s.useLinkSocks = use
	}
}

// WithUseCache enables or disables clearance caching.
// When enabled (default), caches clearance data per host to avoid redundant solves.
// Cached data includes cookies and user agent.
func WithUseCache(use bool) Option {
	return func(s *CloudflareSolver) {
		s.useCache = use
	}
}
