package cfsolver

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// Default challenge page title patterns (multi-language support)
var defaultTitleIndicators = []string{
	"<title>Just a moment...</title>",
	"<title>请稀候…</title>",
	"<title>请稍候...</title>",
	"<title>Un instant...</title>",
	"<title>Einen Moment...</title>",
	"<title>Un momento...</title>",
	"<title>Bir dakika...</title>",
	"<title>Um momento...</title>",
	"<title>Een moment...</title>",
	"<title>ちょっと待ってください...</title>",
	"<title>Подождите...</title>",
}

// Default Cloudflare-specific indicators (high confidence)
var defaultCFIndicators = []string{
	"cf-challenge-running",
	"cloudflare-challenge",
	"cf_challenge_response",
	"cf-under-attack",
	"cf-checking-browser",
	"/cdn-cgi/challenge-platform",
}

// CloudflareDetector detects Cloudflare challenge pages.
type CloudflareDetector struct {
	titleIndicators []string
	cfIndicators    []string
}

// NewCloudflareDetector creates a new detector with optional extra indicators.
func NewCloudflareDetector(extraTitleIndicators, extraCFIndicators []string) *CloudflareDetector {
	d := &CloudflareDetector{
		titleIndicators: append([]string{}, defaultTitleIndicators...),
		cfIndicators:    append([]string{}, defaultCFIndicators...),
	}
	if len(extraTitleIndicators) > 0 {
		d.titleIndicators = append(d.titleIndicators, extraTitleIndicators...)
	}
	if len(extraCFIndicators) > 0 {
		d.cfIndicators = append(d.cfIndicators, extraCFIndicators...)
	}
	return d
}

// IsCloudflareChallenge checks if response contains Cloudflare challenge.
func (d *CloudflareDetector) IsCloudflareChallenge(statusCode int, body []byte) bool {
	// Normal pages with status 200 should not be treated as challenges
	if statusCode == 200 {
		return false
	}

	// Cloudflare challenge pages typically return 403, 503, or 429
	if statusCode != 403 && statusCode != 503 && statusCode != 429 {
		return false
	}

	content := strings.ToLower(string(body))

	// Check title indicators with additional validation
	for _, indicator := range d.titleIndicators {
		if strings.Contains(content, strings.ToLower(indicator)) {
			// Check for CF indicators
			for _, cf := range d.cfIndicators {
				if strings.Contains(content, strings.ToLower(cf)) {
					return true
				}
			}
			// Check for challenge page markers
			if strings.Contains(content, `id="challenge`) || strings.Contains(content, `class="no-js">`) {
				return true
			}
			return true
		}
	}

	// Direct CF indicator matches - only for non-200 responses
	for _, indicator := range d.cfIndicators {
		if strings.Contains(content, strings.ToLower(indicator)) {
			return true
		}
	}

	return false
}

// TransparentProxyOption configures a TransparentProxy.
type TransparentProxyOption func(*TransparentProxy)

// WithProxyAPIBase sets the API base URL.
func WithProxyAPIBase(apiBase string) TransparentProxyOption {
	return func(p *TransparentProxy) {
		p.apiBase = apiBase
	}
}

// WithProxyHost sets the listen host.
func WithProxyHost(host string) TransparentProxyOption {
	return func(p *TransparentProxy) {
		p.host = host
	}
}

// WithProxyPort sets the listen port.
func WithProxyPort(port int) TransparentProxyOption {
	return func(p *TransparentProxy) {
		p.port = port
	}
}

// WithProxyUpstream sets the upstream proxy.
func WithProxyUpstream(upstream string) TransparentProxyOption {
	return func(p *TransparentProxy) {
		p.upstream = upstream
	}
}

// WithProxyAPIProxy sets the proxy for API calls.
func WithProxyAPIProxy(apiProxy string) TransparentProxyOption {
	return func(p *TransparentProxy) {
		p.apiProxy = apiProxy
	}
}

// WithProxyImpersonate sets the browser to impersonate.
func WithProxyImpersonate(impersonate string) TransparentProxyOption {
	return func(p *TransparentProxy) {
		p.impersonate = impersonate
	}
}

// WithProxyDetection enables or disables challenge detection.
func WithProxyDetection(enable bool) TransparentProxyOption {
	return func(p *TransparentProxy) {
		p.enableDetection = enable
	}
}

// WithProxyCache enables or disables cf_clearance caching.
func WithProxyCache(enable bool) TransparentProxyOption {
	return func(p *TransparentProxy) {
		p.enableCache = enable
	}
}

// WithProxyTimeout sets the challenge solve timeout.
func WithProxyTimeout(timeout int) TransparentProxyOption {
	return func(p *TransparentProxy) {
		p.timeout = timeout
	}
}

// WithProxyExtraTitleIndicators adds extra title indicators for detection.
func WithProxyExtraTitleIndicators(indicators []string) TransparentProxyOption {
	return func(p *TransparentProxy) {
		p.extraTitleIndicators = indicators
	}
}

// WithProxyExtraCFIndicators adds extra CF indicators for detection.
func WithProxyExtraCFIndicators(indicators []string) TransparentProxyOption {
	return func(p *TransparentProxy) {
		p.extraCFIndicators = indicators
	}
}

// ClearanceEntry stores cf_clearance data for a host.
type ClearanceEntry struct {
	CFClearance string
	UserAgent   string
}

// TransparentProxy is an HTTP proxy that automatically solves Cloudflare challenges.
type TransparentProxy struct {
	apiKey      string
	apiBase     string
	host        string
	port        int
	upstream    string
	apiProxy    string
	impersonate string

	enableDetection bool
	enableCache     bool
	timeout         int

	extraTitleIndicators []string
	extraCFIndicators    []string

	detector *CloudflareDetector
	solver   *CloudflareSolver

	// cf_clearance store: map[host]map[userAgent]cfClearance
	clearanceStore   map[string]map[string]string
	clearanceStoreMu sync.RWMutex

	// Host-level locks for serializing challenge solving
	hostLocks   map[string]*sync.Mutex
	hostLocksMu sync.Mutex

	server *http.Server
}

// NewTransparentProxy creates a new transparent proxy.
func NewTransparentProxy(apiKey string, opts ...TransparentProxyOption) *TransparentProxy {
	p := &TransparentProxy{
		apiKey:          apiKey,
		apiBase:         "https://solver.zetx.site",
		host:            "127.0.0.1",
		port:            8080,
		impersonate:     "chrome",
		enableDetection: true,
		enableCache:     true,
		timeout:         120,
		clearanceStore:  make(map[string]map[string]string),
		hostLocks:       make(map[string]*sync.Mutex),
	}

	for _, opt := range opts {
		opt(p)
	}

	p.detector = NewCloudflareDetector(p.extraTitleIndicators, p.extraCFIndicators)

	return p
}

// getHostLock gets or creates a lock for a host.
func (p *TransparentProxy) getHostLock(host string) *sync.Mutex {
	p.hostLocksMu.Lock()
	defer p.hostLocksMu.Unlock()

	if lock, ok := p.hostLocks[host]; ok {
		return lock
	}
	lock := &sync.Mutex{}
	p.hostLocks[host] = lock
	return lock
}

// SetCFClearance stores cf_clearance for a host and user agent.
func (p *TransparentProxy) SetCFClearance(host, userAgent, cfClearance string) {
	if host == "" || userAgent == "" || cfClearance == "" {
		return
	}
	host = strings.ToLower(host)

	p.clearanceStoreMu.Lock()
	defer p.clearanceStoreMu.Unlock()

	if p.clearanceStore[host] == nil {
		p.clearanceStore[host] = make(map[string]string)
	}
	p.clearanceStore[host][userAgent] = cfClearance
}

// GetCFClearance retrieves cf_clearance for a host and user agent.
func (p *TransparentProxy) GetCFClearance(host, userAgent string) string {
	if host == "" || userAgent == "" {
		return ""
	}
	host = strings.ToLower(host)

	p.clearanceStoreMu.RLock()
	defer p.clearanceStoreMu.RUnlock()

	if inner, ok := p.clearanceStore[host]; ok {
		return inner[userAgent]
	}
	return ""
}

// GetCFClearanceForHost gets any stored cf_clearance for a host.
func (p *TransparentProxy) GetCFClearanceForHost(host string) (userAgent, cfClearance string) {
	if host == "" {
		return "", ""
	}
	host = strings.ToLower(host)

	p.clearanceStoreMu.RLock()
	defer p.clearanceStoreMu.RUnlock()

	if inner, ok := p.clearanceStore[host]; ok {
		for ua, cf := range inner {
			if ua != "" && cf != "" {
				return ua, cf
			}
		}
	}
	return "", ""
}

// ClearCFClearance clears stored cf_clearance entries.
func (p *TransparentProxy) ClearCFClearance(host, userAgent string) {
	p.clearanceStoreMu.Lock()
	defer p.clearanceStoreMu.Unlock()

	if host == "" && userAgent == "" {
		p.clearanceStore = make(map[string]map[string]string)
		return
	}

	if host != "" {
		host = strings.ToLower(host)
		if userAgent == "" {
			delete(p.clearanceStore, host)
		} else if inner, ok := p.clearanceStore[host]; ok {
			delete(inner, userAgent)
			if len(inner) == 0 {
				delete(p.clearanceStore, host)
			}
		}
	}
}

// injectCookie injects or updates a cookie in the request.
func injectCookie(req *http.Request, name, value string) {
	if name == "" || value == "" {
		return
	}

	cookies := req.Cookies()
	var newCookies []string
	found := false

	for _, c := range cookies {
		if strings.EqualFold(c.Name, name) {
			newCookies = append(newCookies, fmt.Sprintf("%s=%s", name, value))
			found = true
		} else {
			newCookies = append(newCookies, fmt.Sprintf("%s=%s", c.Name, c.Value))
		}
	}

	if !found {
		newCookies = append(newCookies, fmt.Sprintf("%s=%s", name, value))
	}

	req.Header.Set("Cookie", strings.Join(newCookies, "; "))
}

// getSolver lazily initializes the solver.
func (p *TransparentProxy) getSolver() (*CloudflareSolver, error) {
	if p.solver != nil {
		return p.solver, nil
	}

	opts := []Option{
		WithAPIBase(p.apiBase),
		WithSolve(true),
		WithOnChallenge(false),
		WithTimeout(time.Duration(p.timeout) * time.Second),
	}
	if p.upstream != "" {
		opts = append(opts, WithProxy(p.upstream))
	}
	if p.apiProxy != "" {
		opts = append(opts, WithAPIProxy(p.apiProxy))
	}
	if p.impersonate != "" {
		opts = append(opts, WithImpersonate(p.impersonate))
	}

	p.solver = New(p.apiKey, opts...)
	return p.solver, nil
}

// solveChallenge solves a Cloudflare challenge for the given URL.
func (p *TransparentProxy) solveChallenge(targetURL string) (cookies map[string]string, userAgent string, err error) {
	solver, err := p.getSolver()
	if err != nil {
		return nil, "", err
	}

	// Ensure LinkSocks is connected
	if err := solver.ensureLinkSocksConnected(); err != nil {
		return nil, "", err
	}

	log.Printf("Solving challenge for: %s", targetURL)

	// Make a request to trigger challenge solving
	resp, err := solver.Get(targetURL)
	if err != nil {
		return nil, "", err
	}
	defer resp.Body.Close()

	// Extract cookies from solver
	u, err := url.Parse(targetURL)
	if err != nil {
		return nil, "", err
	}

	solver.cookiesMu.RLock()
	domainCookies := solver.cookies[u.Hostname()]
	cookies = make(map[string]string)
	for k, v := range domainCookies {
		cookies[k] = v
	}
	solver.cookiesMu.RUnlock()

	userAgent = solver.userAgent

	log.Printf("Challenge solved, got %d cookies", len(cookies))
	return cookies, userAgent, nil
}

// handleHTTP handles HTTP requests.
func (p *TransparentProxy) handleHTTP(w http.ResponseWriter, req *http.Request) {
	host := req.Host
	userAgent := req.Header.Get("User-Agent")

	// Inject cached cf_clearance if available
	if p.enableCache && userAgent != "" {
		cfClearance := p.GetCFClearance(host, userAgent)
		if cfClearance != "" {
			injectCookie(req, "cf_clearance", cfClearance)
			log.Printf("[Cache HIT] Injected cf_clearance for %s", host)
		} else {
			// Fallback: try any stored clearance for this host
			storedUA, storedCF := p.GetCFClearanceForHost(host)
			if storedCF != "" {
				if storedUA != "" {
					req.Header.Set("User-Agent", storedUA)
				}
				injectCookie(req, "cf_clearance", storedCF)
				log.Printf("[Cache HIT fallback] Injected cf_clearance for %s", host)
			}
		}
	}

	// Create transport with upstream proxy if configured
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	if p.upstream != "" {
		proxyURL, err := url.Parse(p.upstream)
		if err == nil {
			transport.Proxy = http.ProxyURL(proxyURL)
		}
	}

	client := &http.Client{
		Transport: transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	// Build target URL
	targetURL := req.URL.String()
	if !strings.HasPrefix(targetURL, "http") {
		scheme := "http"
		if req.TLS != nil {
			scheme = "https"
		}
		targetURL = fmt.Sprintf("%s://%s%s", scheme, req.Host, req.URL.RequestURI())
	}

	// Create outgoing request
	outReq, err := http.NewRequest(req.Method, targetURL, req.Body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}

	// Copy headers
	for k, vv := range req.Header {
		for _, v := range vv {
			outReq.Header.Add(k, v)
		}
	}

	// Remove hop-by-hop headers
	outReq.Header.Del("Proxy-Connection")
	outReq.Header.Del("Proxy-Authorization")

	// Make request
	resp, err := client.Do(outReq)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	// Read response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}

	// Check for Cloudflare challenge
	if p.enableDetection && p.detector.IsCloudflareChallenge(resp.StatusCode, body) {
		log.Printf("Detected Cloudflare challenge for %s", targetURL)

		// Get host lock to serialize challenge solving
		hostLock := p.getHostLock(host)
		hostLock.Lock()
		defer hostLock.Unlock()

		// Solve challenge
		cookies, solvedUA, err := p.solveChallenge(targetURL)
		if err != nil {
			log.Printf("Failed to solve challenge: %v", err)
			// Return original response on failure
			copyHeaders(w.Header(), resp.Header)
			w.WriteHeader(resp.StatusCode)
			w.Write(body)
			return
		}

		// Store cf_clearance
		if p.enableCache {
			if cf, ok := cookies["cf_clearance"]; ok && solvedUA != "" {
				p.SetCFClearance(host, solvedUA, cf)
				log.Printf("[Cache STORE] Stored cf_clearance for %s", host)
			}
		}

		// Retry request with solved cookies
		for k, v := range cookies {
			injectCookie(outReq, k, v)
		}
		if solvedUA != "" {
			outReq.Header.Set("User-Agent", solvedUA)
		}

		// Reset body for retry
		if req.Body != nil {
			if seeker, ok := req.Body.(io.Seeker); ok {
				seeker.Seek(0, io.SeekStart)
			}
		}

		retryResp, err := client.Do(outReq)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		defer retryResp.Body.Close()

		// Copy retry response
		copyHeaders(w.Header(), retryResp.Header)
		w.WriteHeader(retryResp.StatusCode)
		io.Copy(w, retryResp.Body)
		return
	}

	// Copy original response
	copyHeaders(w.Header(), resp.Header)
	w.WriteHeader(resp.StatusCode)
	w.Write(body)
}

// handleConnect handles HTTPS CONNECT requests.
func (p *TransparentProxy) handleConnect(w http.ResponseWriter, req *http.Request) {
	// Hijack the connection
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "Hijacking not supported", http.StatusInternalServerError)
		return
	}

	clientConn, _, err := hijacker.Hijack()
	if err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
	defer clientConn.Close()

	// Connect to target (or upstream proxy)
	var targetConn net.Conn
	if p.upstream != "" {
		targetConn, err = p.connectViaProxy(req.Host)
	} else {
		targetConn, err = net.DialTimeout("tcp", req.Host, 30*time.Second)
	}
	if err != nil {
		clientConn.Write([]byte("HTTP/1.1 502 Bad Gateway\r\n\r\n"))
		return
	}
	defer targetConn.Close()

	// Send 200 Connection Established
	clientConn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))

	// Tunnel data
	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		io.Copy(targetConn, clientConn)
	}()

	go func() {
		defer wg.Done()
		io.Copy(clientConn, targetConn)
	}()

	wg.Wait()
}

// connectViaProxy connects to target via upstream proxy.
func (p *TransparentProxy) connectViaProxy(target string) (net.Conn, error) {
	proxyURL, err := url.Parse(p.upstream)
	if err != nil {
		return nil, err
	}

	proxyHost := proxyURL.Host
	if proxyURL.Port() == "" {
		if proxyURL.Scheme == "https" {
			proxyHost += ":443"
		} else {
			proxyHost += ":80"
		}
	}

	conn, err := net.DialTimeout("tcp", proxyHost, 30*time.Second)
	if err != nil {
		return nil, err
	}

	// Send CONNECT request
	connectReq := fmt.Sprintf("CONNECT %s HTTP/1.1\r\nHost: %s\r\n", target, target)

	// Add proxy authentication if present
	if proxyURL.User != nil {
		username := proxyURL.User.Username()
		password, _ := proxyURL.User.Password()
		auth := base64.StdEncoding.EncodeToString([]byte(username + ":" + password))
		connectReq += fmt.Sprintf("Proxy-Authorization: Basic %s\r\n", auth)
	}

	connectReq += "\r\n"
	conn.Write([]byte(connectReq))

	// Read response
	reader := bufio.NewReader(conn)
	resp, err := http.ReadResponse(reader, nil)
	if err != nil {
		conn.Close()
		return nil, err
	}

	if resp.StatusCode != 200 {
		conn.Close()
		return nil, fmt.Errorf("proxy CONNECT failed: %s", resp.Status)
	}

	return conn, nil
}

// ServeHTTP implements http.Handler.
func (p *TransparentProxy) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	if req.Method == http.MethodConnect {
		p.handleConnect(w, req)
	} else {
		p.handleHTTP(w, req)
	}
}

// ListenAndServe starts the proxy server.
func (p *TransparentProxy) ListenAndServe() error {
	addr := fmt.Sprintf("%s:%d", p.host, p.port)

	p.server = &http.Server{
		Addr:    addr,
		Handler: p,
	}

	log.Printf("Starting transparent proxy on %s", addr)
	return p.server.ListenAndServe()
}

// Shutdown gracefully shuts down the proxy server.
func (p *TransparentProxy) Shutdown(ctx context.Context) error {
	if p.solver != nil {
		p.solver.Close()
	}
	if p.server != nil {
		return p.server.Shutdown(ctx)
	}
	return nil
}

// Close immediately closes the proxy server.
func (p *TransparentProxy) Close() error {
	if p.solver != nil {
		p.solver.Close()
	}
	if p.server != nil {
		return p.server.Close()
	}
	return nil
}

// copyHeaders copies headers from src to dst.
func copyHeaders(dst, src http.Header) {
	for k, vv := range src {
		for _, v := range vv {
			dst.Add(k, v)
		}
	}
}

// StartTransparentProxy starts a transparent proxy server with the given configuration.
// This is a convenience function that blocks until the server is stopped.
func StartTransparentProxy(
	apiKey string,
	apiBase string,
	host string,
	port int,
	upstream string,
	apiProxy string,
	impersonate string,
	enableDetection bool,
	enableCache bool,
	timeout int,
) error {
	proxy := NewTransparentProxy(
		apiKey,
		WithProxyAPIBase(apiBase),
		WithProxyHost(host),
		WithProxyPort(port),
		WithProxyUpstream(upstream),
		WithProxyAPIProxy(apiProxy),
		WithProxyImpersonate(impersonate),
		WithProxyDetection(enableDetection),
		WithProxyCache(enableCache),
		WithProxyTimeout(timeout),
	)

	return proxy.ListenAndServe()
}
