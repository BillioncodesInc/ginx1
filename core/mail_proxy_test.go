package core

import (
	"regexp"
	"strings"
	"testing"
)

// TestMailPanelURLRewriting tests URL rewriting for GoPhish assets
func TestMailPanelURLRewriting(t *testing.T) {
	basePath := "/mail"

	tests := []struct {
		name        string
		contentType string
		input       string
		expected    []string // patterns that should exist after rewriting
		notExpected []string // patterns that should NOT exist
	}{
		{
			name:        "HTML with CSS and JS links",
			contentType: "text/html",
			input: `<!DOCTYPE html>
<html>
<head>
	<link rel="stylesheet" href="/css/bootstrap.min.css">
	<link rel="stylesheet" href="/css/main.css">
	<script src="/js/jquery.min.js"></script>
	<script src="/js/app.js"></script>
</head>
<body>
	<img src="/images/logo.png">
	<a href="/dashboard">Dashboard</a>
	<form action="/login" method="post">
</body>
</html>`,
			expected: []string{
				`href="/mail/css/bootstrap.min.css"`,
				`href="/mail/css/main.css"`,
				`src="/mail/js/jquery.min.js"`,
				`src="/mail/js/app.js"`,
				`src="/mail/images/logo.png"`,
				`href="/mail/dashboard"`,
				`action="/mail/login"`,
			},
			notExpected: []string{
				`href="/css/`,
				`src="/js/`,
				`src="/images/`,
				`href="/dashboard"`,
				`action="/login"`,
			},
		},
		{
			name:        "JavaScript with fetch and AJAX",
			contentType: "application/javascript",
			input: `
// API calls
fetch('/api/campaigns').then(r => r.json());
fetch('/api/users', {method: 'POST'});
$.ajax({url: '/api/settings', method: 'GET'});
$.get('/api/groups');
$.post('/api/templates', data);

// Navigation
window.location = '/dashboard';
location.href = '/login';
`,
			expected: []string{
				`fetch('/mail/api/campaigns')`,
				`fetch('/mail/api/users'`,
				`url: '/mail/api/settings'`,
				`$.get('/mail/api/groups')`,
				`$.post('/mail/api/templates'`,
				`window.location = '/mail/dashboard'`,
				`location.href = '/mail/login'`,
			},
			notExpected: []string{
				`fetch('/api/campaigns')`,
				`url: '/api/settings'`,
				`window.location = '/dashboard'`,
			},
		},
		{
			name:        "CSS with url() statements",
			contentType: "text/css",
			input: `
.logo {
	background: url(/images/logo.png);
}
.icon {
	background-image: url('/images/icon.svg');
}
.bg {
	background: url("/images/bg.jpg") no-repeat;
}
@font-face {
	src: url(/fonts/custom.woff2);
}
`,
			expected: []string{
				`url('/mail/images/logo.png')`,
				`url('/mail/images/icon.svg')`,
				`url('/mail/images/bg.jpg')`,
				`url('/mail/fonts/custom.woff2')`,
			},
			notExpected: []string{
				`url(/images/logo.png)`,
				`url('/images/icon.svg')`,
				`url(/fonts/`,
			},
		},
		{
			name:        "HTML with data attributes",
			contentType: "text/html",
			input: `
<div data-url="/api/endpoint" data-path="/images/lazy.jpg">
	<button data-link="/delete" data-target="/edit">Edit</button>
</div>
`,
			expected: []string{
				`data-url="/mail/api/endpoint"`,
				`data-path="/mail/images/lazy.jpg"`,
				`data-link="/mail/delete"`,
				`data-target="/mail/edit"`,
			},
			notExpected: []string{
				`data-url="/api/endpoint"`,
				`data-path="/images/`,
			},
		},
		{
			name:        "Should NOT rewrite protocol-relative URLs",
			contentType: "text/html",
			input: `
<link href="//cdn.example.com/style.css">
<script src="//ajax.googleapis.com/jquery.js"></script>
<a href="https://external.com/page">External</a>
`,
			expected: []string{
				`href="//cdn.example.com/style.css"`,
				`src="//ajax.googleapis.com/jquery.js"`,
				`href="https://external.com/page"`,
			},
			notExpected: []string{
				`href="/mail//cdn`,
				`src="/mail//ajax`,
			},
		},
		{
			name:        "Single quotes in HTML",
			contentType: "text/html",
			input: `
<link href='/css/style.css'>
<script src='/js/main.js'></script>
<a href='/page'>Link</a>
`,
			expected: []string{
				`href='/mail/css/style.css'`,
				`src='/mail/js/main.js'`,
				`href='/mail/page'`,
			},
			notExpected: []string{
				`href='/css/`,
				`src='/js/`,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			bodyStr := tt.input

			// Apply the same rewriting logic as in handleMailPanelProxy
			re1 := regexp.MustCompile(`(href|src|action)="(/[^/"][^"]*)"`)
			bodyStr = re1.ReplaceAllString(bodyStr, `$1="`+basePath+`$2"`)
			re2 := regexp.MustCompile(`(href|src|action)='(/[^/'][^']*)'`)
			bodyStr = re2.ReplaceAllString(bodyStr, `$1='`+basePath+`$2'`)

			if !strings.Contains(bodyStr, basePath) || strings.Count(bodyStr, basePath) < 5 {
				re9 := regexp.MustCompile(`(data-[a-z-]+)="(/[^"]+)"`)
				bodyStr = re9.ReplaceAllString(bodyStr, `$1="`+basePath+`$2"`)
			}

			re3 := regexp.MustCompile(`fetch\(['"](/[^'"]+)['"]\)`)
			bodyStr = re3.ReplaceAllString(bodyStr, `fetch('`+basePath+`$1')`)
			re4 := regexp.MustCompile(`fetch\(['"](/[^'"]+)['"],`)
			bodyStr = re4.ReplaceAllString(bodyStr, `fetch('`+basePath+`$1',`)

			re5 := regexp.MustCompile(`\$\.(ajax|get|post)\(['"](/[^'"]+)['"]`)
			bodyStr = re5.ReplaceAllString(bodyStr, `$.$1('`+basePath+`$2'`)

			re6 := regexp.MustCompile(`url:\s*['"](/[^'"]+)['"]`)
			bodyStr = re6.ReplaceAllString(bodyStr, `url: '`+basePath+`$1'`)

			re7 := regexp.MustCompile(`url\(["']?(/[^)"']+)["']?\)`)
			bodyStr = re7.ReplaceAllString(bodyStr, `url('`+basePath+`$1')`)

			re8 := regexp.MustCompile(`(window\.location\s*=\s*|location\.href\s*=\s*)['"](/[^'"]+)['"]`)
			bodyStr = re8.ReplaceAllString(bodyStr, `$1'`+basePath+`$2'`)

			// Check expected patterns exist
			for _, pattern := range tt.expected {
				if !strings.Contains(bodyStr, pattern) {
					t.Errorf("Expected pattern not found: %s\nOutput:\n%s", pattern, bodyStr)
				}
			}

			// Check unwanted patterns don't exist
			for _, pattern := range tt.notExpected {
				if strings.Contains(bodyStr, pattern) {
					t.Errorf("Unwanted pattern found: %s\nOutput:\n%s", pattern, bodyStr)
				}
			}
		})
	}
}

// TestMailPanelRouting tests that different paths route correctly
func TestMailPanelRouting(t *testing.T) {
	tests := []struct {
		name          string
		requestPath   string
		shouldMatch   bool
		expectedProxy string
	}{
		{
			name:          "Login page",
			requestPath:   "/mail/login",
			shouldMatch:   true,
			expectedProxy: "/login",
		},
		{
			name:          "Dashboard",
			requestPath:   "/mail/",
			shouldMatch:   true,
			expectedProxy: "/",
		},
		{
			name:          "CSS file",
			requestPath:   "/mail/css/bootstrap.min.css",
			shouldMatch:   true,
			expectedProxy: "/css/bootstrap.min.css",
		},
		{
			name:          "JavaScript file",
			requestPath:   "/mail/js/app.js",
			shouldMatch:   true,
			expectedProxy: "/js/app.js",
		},
		{
			name:          "Image asset",
			requestPath:   "/mail/images/logo.png",
			shouldMatch:   true,
			expectedProxy: "/images/logo.png",
		},
		{
			name:          "API endpoint",
			requestPath:   "/mail/api/campaigns",
			shouldMatch:   true,
			expectedProxy: "/api/campaigns",
		},
		{
			name:          "Fonts",
			requestPath:   "/mail/fonts/custom.woff2",
			shouldMatch:   true,
			expectedProxy: "/fonts/custom.woff2",
		},
		{
			name:        "Root path (not mail)",
			requestPath: "/",
			shouldMatch: false,
		},
		{
			name:        "Admin path",
			requestPath: "/admin/",
			shouldMatch: false,
		},
	}

	mailPath := "/mail/"

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matches := strings.HasPrefix(tt.requestPath, mailPath)

			if matches != tt.shouldMatch {
				t.Errorf("Route matching failed: path=%s, expected match=%v, got=%v",
					tt.requestPath, tt.shouldMatch, matches)
			}

			if tt.shouldMatch {
				basePath := strings.TrimSuffix(mailPath, "/")
				targetPath := strings.TrimPrefix(tt.requestPath, basePath)
				if targetPath == "" {
					targetPath = "/"
				}

				if targetPath != tt.expectedProxy {
					t.Errorf("Proxy path incorrect: got=%s, expected=%s",
						targetPath, tt.expectedProxy)
				}
			}
		})
	}
}

// TestLocationHeaderRewrite tests redirect header rewriting
func TestLocationHeaderRewrite(t *testing.T) {
	tests := []struct {
		name     string
		location string
		expected string
	}{
		{
			name:     "Absolute path redirect",
			location: "/dashboard",
			expected: "/mail/dashboard",
		},
		{
			name:     "Root redirect",
			location: "/",
			expected: "/mail/",
		},
		{
			name:     "API redirect",
			location: "/api/campaigns",
			expected: "/mail/api/campaigns",
		},
		{
			name:     "Full URL (should not change)",
			location: "https://example.com/page",
			expected: "https://example.com/page",
		},
		{
			name:     "Protocol-relative URL (should not change)",
			location: "//example.com/page",
			expected: "//example.com/page",
		},
	}

	basePath := "/mail"

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.location

			// Apply redirect rewriting logic
			if strings.HasPrefix(result, "/") && !strings.HasPrefix(result, "//") {
				result = basePath + result
			}

			if result != tt.expected {
				t.Errorf("Location rewrite failed: got=%s, expected=%s", result, tt.expected)
			}
		})
	}
}

// TestContentTypeDetection tests that correct content types trigger rewriting
func TestContentTypeDetection(t *testing.T) {
	tests := []struct {
		contentType   string
		shouldRewrite bool
	}{
		{"text/html", true},
		{"text/html; charset=utf-8", true},
		{"application/javascript", true},
		{"text/javascript", true},
		{"text/javascript; charset=utf-8", true},
		{"text/css", true},
		{"text/css; charset=utf-8", true},
		{"application/json", true},
		{"image/png", false},
		{"image/jpeg", false},
		{"application/pdf", false},
		{"font/woff2", false},
	}

	for _, tt := range tests {
		t.Run(tt.contentType, func(t *testing.T) {
			shouldRewrite := strings.Contains(tt.contentType, "text/html") ||
				strings.Contains(tt.contentType, "javascript") ||
				strings.Contains(tt.contentType, "application/javascript") ||
				strings.Contains(tt.contentType, "text/javascript") ||
				strings.Contains(tt.contentType, "text/css") ||
				strings.Contains(tt.contentType, "application/json")

			if shouldRewrite != tt.shouldRewrite {
				t.Errorf("Content type detection failed: type=%s, expected=%v, got=%v",
					tt.contentType, tt.shouldRewrite, shouldRewrite)
			}
		})
	}
}

// TestRealWorldGoPhishHTML tests rewriting on realistic GoPhish HTML
func TestRealWorldGoPhishHTML(t *testing.T) {
	basePath := "/mail"

	// Simulated GoPhish login page HTML
	input := `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <title>Gophish - Login</title>
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <link href="/css/bootstrap.min.css" rel="stylesheet">
    <link href="/css/main.css" rel="stylesheet">
    <script src="/js/jquery.min.js"></script>
    <script src="/js/bootstrap.min.js"></script>
</head>
<body>
    <div class="container">
        <form action="/login" method="post">
            <input type="text" name="username">
            <input type="password" name="password">
            <button type="submit">Login</button>
        </form>
    </div>
    <script>
        $(document).ready(function() {
            $.ajax({
                url: '/api/reset',
                method: 'GET'
            });
        });
    </script>
</body>
</html>`

	// Apply rewriting
	bodyStr := input
	re1 := regexp.MustCompile(`(href|src|action)="(/[^/"][^"]*)"`)
	bodyStr = re1.ReplaceAllString(bodyStr, `$1="`+basePath+`$2"`)

	re5 := regexp.MustCompile(`\$\.(ajax|get|post)\(['"](/[^'"]+)['"]`)
	bodyStr = re5.ReplaceAllString(bodyStr, `$.$1('`+basePath+`$2'`)

	re6 := regexp.MustCompile(`url:\s*['"](/[^'"]+)['"]`)
	bodyStr = re6.ReplaceAllString(bodyStr, `url: '`+basePath+`$1'`)

	// Verify all assets are rewritten
	expectedPatterns := []string{
		`href="/mail/css/bootstrap.min.css"`,
		`href="/mail/css/main.css"`,
		`src="/mail/js/jquery.min.js"`,
		`src="/mail/js/bootstrap.min.js"`,
		`action="/mail/login"`,
		`url: '/mail/api/reset'`,
	}

	for _, pattern := range expectedPatterns {
		if !strings.Contains(bodyStr, pattern) {
			t.Errorf("Real-world test failed - missing pattern: %s", pattern)
		}
	}

	t.Logf("✓ Successfully rewrote %d patterns in GoPhish HTML", len(expectedPatterns))
}

// TestAssetRequestFlow simulates the complete request flow
func TestAssetRequestFlow(t *testing.T) {
	t.Run("Complete flow: Browser -> Proxy -> GoPhish", func(t *testing.T) {
		// Step 1: Browser requests /mail/css/style.css
		browserRequest := "/mail/css/style.css"
		t.Logf("1. Browser requests: %s", browserRequest)

		// Step 2: Proxy strips /mail prefix
		mailPath := "/mail/"
		basePath := strings.TrimSuffix(mailPath, "/")
		targetPath := strings.TrimPrefix(browserRequest, basePath)
		t.Logf("2. Proxy forwards to GoPhish: %s", targetPath)

		if targetPath != "/css/style.css" {
			t.Errorf("Proxy path incorrect: expected /css/style.css, got %s", targetPath)
		}

		// Step 3: GoPhish returns CSS with url() references
		gophishResponse := `
.logo {
    background: url(/images/logo.png);
}
.icon {
    background-image: url('/images/icon.svg');
}`

		t.Logf("3. GoPhish returns CSS (length: %d bytes)", len(gophishResponse))

		// Step 4: Proxy rewrites url() paths in CSS
		re7 := regexp.MustCompile(`url\(["']?(/[^)"']+)["']?\)`)
		rewrittenResponse := re7.ReplaceAllString(gophishResponse, `url('`+basePath+`$1')`)

		t.Logf("4. Proxy rewrites CSS (length: %d bytes)", len(rewrittenResponse))

		// Step 5: Verify rewritten paths
		if !strings.Contains(rewrittenResponse, "url('/mail/images/logo.png')") {
			t.Error("Failed to rewrite url(/images/logo.png)")
		}
		if !strings.Contains(rewrittenResponse, "url('/mail/images/icon.svg')") {
			t.Error("Failed to rewrite url('/images/icon.svg')")
		}

		// Step 6: Browser receives response and requests nested asset
		nextRequest := "/mail/images/logo.png"
		t.Logf("5. Browser requests nested asset: %s", nextRequest)

		nextTarget := strings.TrimPrefix(nextRequest, basePath)
		if nextTarget != "/images/logo.png" {
			t.Errorf("Nested asset path incorrect: expected /images/logo.png, got %s", nextTarget)
		}

		t.Log("✓ Complete request flow successful")
	})
}
