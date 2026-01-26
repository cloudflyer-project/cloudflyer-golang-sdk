package cfsolver

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/linksocks/linksocks/linksocks"
	"github.com/rs/zerolog"
)

// LinkSocksManager manages the LinkSocks client lifecycle using the library directly
type LinkSocksManager struct {
	apiBase       string
	apiKey        string
	apiClient     *http.Client
	upstreamProxy string

	mu             sync.Mutex
	client         *linksocks.LinkSocksClient
	cancelFunc     context.CancelFunc
	config         *LinkSocksConfig
	connectorToken string
	connected      bool
}

// LinkSocksConfig represents the configuration from the API
type LinkSocksConfig struct {
	URL            string `json:"url"`
	Token          string `json:"token"`
	ConnectorToken string `json:"connector_token"`
}

// GetWsURL converts HTTP(S) URL to WS(S) URL
func (c *LinkSocksConfig) GetWsURL() string {
	if c.URL == "" {
		return ""
	}
	if strings.HasPrefix(c.URL, "https://") {
		return "wss://" + c.URL[8:]
	} else if strings.HasPrefix(c.URL, "http://") {
		return "ws://" + c.URL[7:]
	}
	return c.URL
}

// NewLinkSocksManager creates a new LinkSocks manager
func NewLinkSocksManager(apiBase, apiKey string, apiClient *http.Client, upstreamProxy string) *LinkSocksManager {
	return &LinkSocksManager{
		apiBase:       apiBase,
		apiKey:        apiKey,
		apiClient:     apiClient,
		upstreamProxy: upstreamProxy,
	}
}

// getConfig fetches LinkSocks configuration from the API (internal, no lock)
func (m *LinkSocksManager) getConfig() (*LinkSocksConfig, error) {
	if m.config != nil {
		return m.config, nil
	}

	req, err := http.NewRequest("POST", m.apiBase+"/getLinkSocks", nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	if m.apiKey != "" {
		req.Header.Set("Authorization", "Bearer "+m.apiKey)
	}

	resp, err := m.apiClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to get linksocks config: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("failed to get linksocks config: HTTP %d: %s", resp.StatusCode, string(body))
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	var config LinkSocksConfig
	if err := json.Unmarshal(body, &config); err != nil {
		return nil, fmt.Errorf("failed to parse linksocks config: %w", err)
	}

	if config.URL == "" || config.Token == "" {
		return nil, fmt.Errorf("invalid linksocks config: missing url or token")
	}

	m.config = &config
	return m.config, nil
}

// GetConfig fetches LinkSocks configuration from the API
func (m *LinkSocksManager) GetConfig() (*LinkSocksConfig, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.getConfig()
}

// Connect starts the LinkSocks client as a reverse proxy provider
func (m *LinkSocksManager) Connect() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.connected && m.client != nil {
		return nil
	}

	// Get config from API
	config, err := m.getConfig()
	if err != nil {
		return err
	}

	// Create a quiet logger for linksocks
	logger := zerolog.New(os.Stderr).Level(zerolog.WarnLevel)

	// Build client options
	opt := linksocks.DefaultClientOption().
		WithWSURL(config.GetWsURL()).
		WithReverse(true). // Run as reverse proxy provider
		WithReconnect(true).
		WithReconnectDelay(5 * time.Second).
		WithLogger(logger).
		WithThreads(1)

	// Parse and set upstream proxy if provided
	if m.upstreamProxy != "" {
		proxyAddr, proxyUser, proxyPass, proxyType := parseProxyURL(m.upstreamProxy)
		if proxyAddr != "" {
			opt = opt.WithUpstreamProxy(proxyAddr)
			if proxyUser != "" || proxyPass != "" {
				opt = opt.WithUpstreamAuth(proxyUser, proxyPass)
			}
			if proxyType == "socks5" {
				opt = opt.WithUpstreamProxyType(linksocks.ProxyTypeSocks5)
			} else {
				opt = opt.WithUpstreamProxyType(linksocks.ProxyTypeHTTP)
			}
		}
	}

	// Create LinkSocks client
	m.client = linksocks.NewLinkSocksClient(config.Token, opt)

	// Create context for the client
	ctx, cancel := context.WithCancel(context.Background())
	m.cancelFunc = cancel

	// Start client in background
	go func() {
		if err := m.client.Connect(ctx); err != nil {
			log.Printf("LinkSocks client error: %v", err)
		}
	}()

	// Wait for connection with timeout
	select {
	case <-m.client.Connected:
		log.Println("LinkSocks provider connected")
	case <-time.After(10 * time.Second):
		cancel()
		m.client.Close()
		m.client = nil
		return fmt.Errorf("timeout waiting for LinkSocks connection")
	}

	// Use connector token from config
	m.connectorToken = config.ConnectorToken
	if m.connectorToken == "" {
		m.connectorToken = fmt.Sprintf("connector-%d", time.Now().UnixNano())
	}

	m.connected = true
	return nil
}

// GetConnectorToken returns the connector token for API requests
func (m *LinkSocksManager) GetConnectorToken() string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.connectorToken
}

// GetWsURL returns the WebSocket URL for API requests
func (m *LinkSocksManager) GetWsURL() string {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.config != nil {
		return m.config.GetWsURL()
	}
	return ""
}

// Close terminates the LinkSocks client
func (m *LinkSocksManager) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.cancelFunc != nil {
		m.cancelFunc()
		m.cancelFunc = nil
	}

	if m.client != nil {
		m.client.Close()
		m.client = nil
	}

	m.connected = false
	return nil
}

// parseProxyURL parses a proxy URL and returns address, username, password, and type
func parseProxyURL(proxyURL string) (addr, user, pass, proxyType string) {
	if proxyURL == "" {
		return "", "", "", ""
	}

	// Determine proxy type from scheme
	if strings.HasPrefix(proxyURL, "socks5://") {
		proxyType = "socks5"
		proxyURL = proxyURL[9:]
	} else if strings.HasPrefix(proxyURL, "http://") {
		proxyType = "http"
		proxyURL = proxyURL[7:]
	} else if strings.HasPrefix(proxyURL, "https://") {
		proxyType = "http"
		proxyURL = proxyURL[8:]
	} else {
		proxyType = "http"
	}

	// Parse auth and host
	if idx := strings.LastIndex(proxyURL, "@"); idx != -1 {
		auth := proxyURL[:idx]
		addr = proxyURL[idx+1:]
		if colonIdx := strings.Index(auth, ":"); colonIdx != -1 {
			user = auth[:colonIdx]
			pass = auth[colonIdx+1:]
		} else {
			user = auth
		}
	} else {
		addr = proxyURL
	}

	// Remove trailing path if any
	if idx := strings.Index(addr, "/"); idx != -1 {
		addr = addr[:idx]
	}

	return addr, user, pass, proxyType
}
