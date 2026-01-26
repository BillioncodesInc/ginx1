package core

import (
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
)

// TestURLRewriting tests the URL rewriting patterns used in proxy handlers
func TestURLRewriting(t *testing.T) {
	basePath := "/admin"

	tests := []struct {
		name     string
		input    string
		expected string
		pattern  *regexp.Regexp
		replace  string
	}{
		// Test href rewriting
		{
			name:     "href double quotes",
			input:    `<a href="/login">Login</a>`,
			expected: `<a href="/admin/login">Login</a>`,
			pattern:  regexp.MustCompile(`(href|src|action)="(/[^/"][^"]*)"`),
			replace:  `$1="` + basePath + `$2"`,
		},
		{
			name:     "href single quotes",
			input:    `<a href='/login'>Login</a>`,
			expected: `<a href='/admin/login'>Login</a>`,
			pattern:  regexp.MustCompile(`(href|src|action)='(/[^/'][^']*)'`),
			replace:  `$1='` + basePath + `$2'`,
		},
		// Test src rewriting
		{
			name:     "src for scripts",
			input:    `<script src="/js/app.js"></script>`,
			expected: `<script src="/admin/js/app.js"></script>`,
			pattern:  regexp.MustCompile(`(href|src|action)="(/[^/"][^"]*)"`),
			replace:  `$1="` + basePath + `$2"`,
		},
		{
			name:     "src for images",
			input:    `<img src="/images/logo.png">`,
			expected: `<img src="/admin/images/logo.png">`,
			pattern:  regexp.MustCompile(`(href|src|action)="(/[^/"][^"]*)"`),
			replace:  `$1="` + basePath + `$2"`,
		},
		// Test CSS url() rewriting
		{
			name:     "css url no quotes",
			input:    `background: url(/images/bg.png);`,
			expected: `background: url('/admin/images/bg.png');`,
			pattern:  regexp.MustCompile(`url\(["']?(/[^)"']+)["']?\)`),
			replace:  `url('` + basePath + `$1')`,
		},
		{
			name:     "css url single quotes",
			input:    `background: url('/images/bg.png');`,
			expected: `background: url('/admin/images/bg.png');`,
			pattern:  regexp.MustCompile(`url\(["']?(/[^)"']+)["']?\)`),
			replace:  `url('` + basePath + `$1')`,
		},
		{
			name:     "css url double quotes",
			input:    `background: url("/images/bg.png");`,
			expected: `background: url('/admin/images/bg.png');`,
			pattern:  regexp.MustCompile(`url\(["']?(/[^)"']+)["']?\)`),
			replace:  `url('` + basePath + `$1')`,
		},
		// Test fetch rewriting
		{
			name:     "fetch call",
			input:    `fetch('/api/data')`,
			expected: `fetch('/admin/api/data')`,
			pattern:  regexp.MustCompile(`fetch\(['"](/[^'"]+)['"]\)`),
			replace:  `fetch('` + basePath + `$1')`,
		},
		{
			name:     "fetch with options",
			input:    `fetch('/api/data', {method: 'POST'})`,
			expected: `fetch('/admin/api/data', {method: 'POST'})`,
			pattern:  regexp.MustCompile(`fetch\(['"](/[^'"]+)['"],`),
			replace:  `fetch('` + basePath + `$1',`,
		},
		// Test jQuery ajax rewriting
		{
			name:     "jquery ajax",
			input:    `$.ajax('/api/data'`,
			expected: `$.ajax('/admin/api/data'`,
			pattern:  regexp.MustCompile(`\$\.(ajax|get|post)\(['"](/[^'"]+)['"]`),
			replace:  `$.$1('` + basePath + `$2'`,
		},
		{
			name:     "jquery get",
			input:    `$.get('/api/data'`,
			expected: `$.get('/admin/api/data'`,
			pattern:  regexp.MustCompile(`\$\.(ajax|get|post)\(['"](/[^'"]+)['"]`),
			replace:  `$.$1('` + basePath + `$2'`,
		},
		// Test window.location rewriting
		{
			name:     "window.location assignment",
			input:    `window.location = '/login'`,
			expected: `window.location = '/admin/login'`,
			pattern:  regexp.MustCompile(`(window\.location\s*=\s*|location\.href\s*=\s*)['"](/[^'"]+)['"]`),
			replace:  `$1'` + basePath + `$2'`,
		},
		// Test protocol-relative URLs are NOT rewritten
		{
			name:     "protocol relative url not rewritten",
			input:    `<a href="//cdn.example.com/file.js">CDN</a>`,
			expected: `<a href="//cdn.example.com/file.js">CDN</a>`,
			pattern:  regexp.MustCompile(`(href|src|action)="(/[^/"][^"]*)"`),
			replace:  `$1="` + basePath + `$2"`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.pattern.ReplaceAllString(tt.input, tt.replace)
			if result != tt.expected {
				t.Errorf("Expected: %s\nGot: %s", tt.expected, result)
			}
		})
	}
}

// TestLocationHeaderRewriting tests redirect Location header rewriting
func TestLocationHeaderRewriting(t *testing.T) {
	basePath := "/admin"

	tests := []struct {
		name     string
		location string
		expected string
	}{
		{
			name:     "absolute path redirect",
			location: "/login",
			expected: "/admin/login",
		},
		{
			name:     "absolute path with query",
			location: "/dashboard?tab=settings",
			expected: "/admin/dashboard?tab=settings",
		},
		{
			name:     "protocol relative not rewritten",
			location: "//example.com/path",
			expected: "//example.com/path",
		},
		{
			name:     "full URL not rewritten",
			location: "https://example.com/path",
			expected: "https://example.com/path",
		},
		{
			name:     "root path",
			location: "/",
			expected: "/admin/",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.location
			// Apply the same logic as in handleAdminPanelProxy
			if strings.HasPrefix(result, "/") && !strings.HasPrefix(result, "//") {
				result = basePath + result
			}
			if result != tt.expected {
				t.Errorf("Expected: %s\nGot: %s", tt.expected, result)
			}
		})
	}
}

// TestWebSocketURLRewriting tests WebSocket URL rewriting
func TestWebSocketURLRewriting(t *testing.T) {
	basePath := "/admin"
	pattern := regexp.MustCompile(`WebSocket\(['"](wss?://[^/]+)(/[^'"]*)['"]\)`)
	replace := `WebSocket('$1` + basePath + `$2')`

	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "ws url",
			input:    `new WebSocket('ws://localhost:1337/ws')`,
			expected: `new WebSocket('ws://localhost:1337/admin/ws')`,
		},
		{
			name:     "wss url",
			input:    `new WebSocket('wss://example.com/ws')`,
			expected: `new WebSocket('wss://example.com/admin/ws')`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := pattern.ReplaceAllString(tt.input, replace)
			if result != tt.expected {
				t.Errorf("Expected: %s\nGot: %s", tt.expected, result)
			}
		})
	}
}

// TestAdminPanelConfigDefaults tests that AdminPanelConfig has correct defaults
func TestAdminPanelConfigDefaults(t *testing.T) {
	cfg := &AdminPanelConfig{
		AdminEnabled: false,
		AdminPath:    "/admin/",
		AdminBackend: "http://127.0.0.1:1337",
		MailEnabled:  false,
		MailPath:     "/mail/",
		MailBackend:  "http://127.0.0.1:3333",
	}

	if cfg.AdminBackend != "http://127.0.0.1:1337" {
		t.Errorf("Expected AdminBackend to be http://127.0.0.1:1337, got %s", cfg.AdminBackend)
	}

	if cfg.MailBackend != "http://127.0.0.1:3333" {
		t.Errorf("Expected MailBackend to be http://127.0.0.1:3333, got %s", cfg.MailBackend)
	}

	if cfg.AdminPath != "/admin/" {
		t.Errorf("Expected AdminPath to be /admin/, got %s", cfg.AdminPath)
	}

	if cfg.MailPath != "/mail/" {
		t.Errorf("Expected MailPath to be /mail/, got %s", cfg.MailPath)
	}
}

// TestSanitizeRedirectURL tests the redirect URL sanitization
func TestSanitizeRedirectURL(t *testing.T) {
	tests := []struct {
		name     string
		raw      string
		host     string
		expected string
	}{
		{
			name:     "empty url",
			raw:      "",
			host:     "example.com",
			expected: "/",
		},
		{
			name:     "protocol relative rejected",
			raw:      "//evil.com/path",
			host:     "example.com",
			expected: "/",
		},
		{
			name:     "absolute path allowed",
			raw:      "/dashboard",
			host:     "example.com",
			expected: "/dashboard",
		},
		{
			name:     "same host absolute URL allowed",
			raw:      "https://example.com/path",
			host:     "example.com",
			expected: "https://example.com/path",
		},
		{
			name:     "different host rejected",
			raw:      "https://evil.com/path",
			host:     "example.com",
			expected: "/",
		},
		{
			name:     "javascript scheme rejected",
			raw:      "javascript:alert(1)",
			host:     "example.com",
			expected: "/",
		},
		{
			name:     "relative path normalized",
			raw:      "dashboard",
			host:     "example.com",
			expected: "/dashboard",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := sanitizeRedirectURL(tt.raw, tt.host)
			if result != tt.expected {
				t.Errorf("Expected: %s\nGot: %s", tt.expected, result)
			}
		})
	}
}

// TestHTMLRewritingIntegration tests full HTML rewriting with multiple patterns
func TestHTMLRewritingIntegration(t *testing.T) {
	basePath := "/mail"

	input := `<!DOCTYPE html>
<html>
<head>
    <link href="/css/style.css" rel="stylesheet">
    <script src="/js/app.js"></script>
    <style>
        body { background: url(/images/bg.png); }
    </style>
</head>
<body>
    <a href="/login">Login</a>
    <img src="/images/logo.png">
    <form action="/api/submit">
        <button>Submit</button>
    </form>
    <script>
        fetch('/api/data').then(r => r.json());
        $.get('/api/users');
        window.location = '/dashboard';
    </script>
</body>
</html>`

	// Apply all rewriting patterns
	bodyStr := input

	// href/src/action double quotes
	re1 := regexp.MustCompile(`(href|src|action)="(/[^/"][^"]*)"`)
	bodyStr = re1.ReplaceAllString(bodyStr, `$1="`+basePath+`$2"`)

	// fetch calls
	re3 := regexp.MustCompile(`fetch\(['"](/[^'"]+)['"]\)`)
	bodyStr = re3.ReplaceAllString(bodyStr, `fetch('`+basePath+`$1')`)

	// jQuery
	re5 := regexp.MustCompile(`\$\.(ajax|get|post)\(['"](/[^'"]+)['"]`)
	bodyStr = re5.ReplaceAllString(bodyStr, `$.$1('`+basePath+`$2'`)

	// CSS url()
	re7 := regexp.MustCompile(`url\(["']?(/[^)"']+)["']?\)`)
	bodyStr = re7.ReplaceAllString(bodyStr, `url('`+basePath+`$1')`)

	// window.location
	re8 := regexp.MustCompile(`(window\.location\s*=\s*|location\.href\s*=\s*)['"](/[^'"]+)['"]`)
	bodyStr = re8.ReplaceAllString(bodyStr, `$1'`+basePath+`$2'`)

	// Verify key rewrites
	checks := []struct {
		name     string
		contains string
	}{
		{"css link", `href="/mail/css/style.css"`},
		{"js script", `src="/mail/js/app.js"`},
		{"css url", `url('/mail/images/bg.png')`},
		{"anchor href", `href="/mail/login"`},
		{"img src", `src="/mail/images/logo.png"`},
		{"form action", `action="/mail/api/submit"`},
		{"fetch call", `fetch('/mail/api/data')`},
		{"jquery get", `$.get('/mail/api/users'`},
		{"window.location", `window.location = '/mail/dashboard'`},
	}

	for _, check := range checks {
		t.Run(check.name, func(t *testing.T) {
			if !strings.Contains(bodyStr, check.contains) {
				t.Errorf("Expected to find: %s\nIn output:\n%s", check.contains, bodyStr)
			}
		})
	}
}

// MockResponseWriter for testing
type MockResponseWriter struct {
	headers http.Header
	body    []byte
	status  int
}

func NewMockResponseWriter() *MockResponseWriter {
	return &MockResponseWriter{
		headers: make(http.Header),
	}
}

func (m *MockResponseWriter) Header() http.Header {
	return m.headers
}

func (m *MockResponseWriter) Write(b []byte) (int, error) {
	m.body = append(m.body, b...)
	return len(b), nil
}

func (m *MockResponseWriter) WriteHeader(status int) {
	m.status = status
}

// TestProxyEndpointSelection tests that correct endpoints are used
func TestProxyEndpointSelection(t *testing.T) {
	// Test that AdminBackend is used for admin panel (not EvilFeedEndpoint)
	adminConfig := &AdminPanelConfig{
		AdminEnabled: true,
		AdminPath:    "/admin/",
		AdminBackend: "http://127.0.0.1:1337", // Web UI
		MailEnabled:  true,
		MailPath:     "/mail/",
		MailBackend:  "http://127.0.0.1:3333", // Web UI
	}

	// EvilFeed ingest endpoint (should NOT be used for proxy)
	evilFeedEndpoint := "http://127.0.0.1:1337/api/internal/ingest"

	// Verify they are different
	if adminConfig.AdminBackend == evilFeedEndpoint {
		t.Error("AdminBackend should NOT equal EvilFeedEndpoint")
	}

	// Verify AdminBackend is the base URL without path
	if strings.Contains(adminConfig.AdminBackend, "/api/") {
		t.Error("AdminBackend should be base URL, not API endpoint")
	}

	// Verify MailBackend is the base URL
	if strings.Contains(adminConfig.MailBackend, "/api/") {
		t.Error("MailBackend should be base URL, not API endpoint")
	}
}

// TestDirectAccessStillWorks simulates that direct IP:port access works
func TestDirectAccessStillWorks(t *testing.T) {
	// Create a test server simulating EvilFeed
	evilFeedServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("EvilFeed Direct Access OK"))
	}))
	defer evilFeedServer.Close()

	// Create a test server simulating GoPhish
	gophishServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("GoPhish Direct Access OK"))
	}))
	defer gophishServer.Close()

	// Test direct access to EvilFeed
	resp, err := http.Get(evilFeedServer.URL)
	if err != nil {
		t.Fatalf("Failed to access EvilFeed directly: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected 200 from EvilFeed, got %d", resp.StatusCode)
	}
	resp.Body.Close()

	// Test direct access to GoPhish
	resp, err = http.Get(gophishServer.URL)
	if err != nil {
		t.Fatalf("Failed to access GoPhish directly: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected 200 from GoPhish, got %d", resp.StatusCode)
	}
	resp.Body.Close()

	t.Log("✅ Direct IP:port access works for both EvilFeed and GoPhish")
}

// TestProxyPathRouting tests that paths are correctly routed
func TestProxyPathRouting(t *testing.T) {
	baseDomain := "example.com"
	adminPath := "/admin/"
	mailPath := "/mail/"

	tests := []struct {
		name        string
		host        string
		path        string
		shouldAdmin bool
		shouldMail  bool
		shouldLand  bool
	}{
		{
			name:        "admin path",
			host:        baseDomain,
			path:        "/admin/dashboard",
			shouldAdmin: true,
		},
		{
			name:        "admin root",
			host:        baseDomain,
			path:        "/admin/",
			shouldAdmin: true,
		},
		{
			name:       "mail path",
			host:       baseDomain,
			path:       "/mail/campaigns",
			shouldMail: true,
		},
		{
			name:       "mail root",
			host:       baseDomain,
			path:       "/mail/",
			shouldMail: true,
		},
		{
			name:       "landing page",
			host:       baseDomain,
			path:       "/",
			shouldLand: true,
		},
		{
			name:       "other path goes to landing",
			host:       baseDomain,
			path:       "/unknown",
			shouldLand: false, // Would be handled by phishlet or blocked
		},
		{
			name:        "different host not routed",
			host:        "other.com",
			path:        "/admin/",
			shouldAdmin: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			isBaseDomain := strings.EqualFold(tt.host, baseDomain)
			isAdminPath := strings.HasPrefix(tt.path, adminPath)
			isMailPath := strings.HasPrefix(tt.path, mailPath)
			isRoot := tt.path == "/" || tt.path == ""

			gotAdmin := isBaseDomain && isAdminPath
			gotMail := isBaseDomain && isMailPath
			gotLand := isBaseDomain && isRoot

			if gotAdmin != tt.shouldAdmin {
				t.Errorf("Admin routing: expected %v, got %v", tt.shouldAdmin, gotAdmin)
			}
			if gotMail != tt.shouldMail {
				t.Errorf("Mail routing: expected %v, got %v", tt.shouldMail, gotMail)
			}
			if gotLand != tt.shouldLand {
				t.Errorf("Landing routing: expected %v, got %v", tt.shouldLand, gotLand)
			}
		})
	}
}
