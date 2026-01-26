package core

import (
	"crypto/sha256"
	"encoding/hex"
	"net"
	"net/http"
	"strings"
	"time"
)

// VisitorFingerprint represents a unique visitor identification
type VisitorFingerprint struct {
	IP            string
	UserAgent     string
	AcceptLang    string
	Hash          string
	TemplateIndex int
	StyleIndex    int
	ColorIndex    int
	ContentSeed   int64
	FirstSeen     time.Time
}

// VisitorTracker handles visitor identification and tracking
type VisitorTracker struct {
	// In-memory cache for visitor fingerprints (optional persistence)
	visitors map[string]*VisitorFingerprint
}

// NewVisitorTracker creates a new visitor tracker
func NewVisitorTracker() *VisitorTracker {
	return &VisitorTracker{
		visitors: make(map[string]*VisitorFingerprint),
	}
}

// GetVisitorFingerprint extracts and generates a fingerprint for the visitor
func (vt *VisitorTracker) GetVisitorFingerprint(req *http.Request) *VisitorFingerprint {
	// Extract IP address
	ip := extractClientIP(req)

	// Extract browser characteristics
	userAgent := req.Header.Get("User-Agent")
	acceptLang := req.Header.Get("Accept-Language")

	// Create fingerprint hash
	fingerprintData := ip + "|" + userAgent + "|" + acceptLang
	hash := generateHash(fingerprintData)

	// Check if we've seen this visitor before
	if existing, ok := vt.visitors[hash]; ok {
		return existing
	}

	// Generate deterministic indices based on hash
	templateIndex := hashToIndex(hash, 10)  // 10 templates
	styleIndex := hashToIndex(hash[8:], 5)  // 5 style variations per template
	colorIndex := hashToIndex(hash[16:], 8) // 8 color schemes
	contentSeed := hashToSeed(hash)

	fingerprint := &VisitorFingerprint{
		IP:            ip,
		UserAgent:     userAgent,
		AcceptLang:    acceptLang,
		Hash:          hash,
		TemplateIndex: templateIndex,
		StyleIndex:    styleIndex,
		ColorIndex:    colorIndex,
		ContentSeed:   contentSeed,
		FirstSeen:     time.Now(),
	}

	// Cache the fingerprint
	vt.visitors[hash] = fingerprint

	return fingerprint
}

// GetVisitorFingerprintSimple creates a fingerprint without caching (stateless)
func GetVisitorFingerprintSimple(req *http.Request) *VisitorFingerprint {
	// Extract IP address
	ip := extractClientIP(req)

	// Extract browser characteristics
	userAgent := req.Header.Get("User-Agent")
	acceptLang := req.Header.Get("Accept-Language")

	// Create fingerprint hash
	fingerprintData := ip + "|" + userAgent + "|" + acceptLang
	hash := generateHash(fingerprintData)

	// Generate deterministic indices based on hash
	templateIndex := hashToIndex(hash, 10)  // 10 templates
	styleIndex := hashToIndex(hash[8:], 5)  // 5 style variations per template
	colorIndex := hashToIndex(hash[16:], 8) // 8 color schemes
	contentSeed := hashToSeed(hash)

	return &VisitorFingerprint{
		IP:            ip,
		UserAgent:     userAgent,
		AcceptLang:    acceptLang,
		Hash:          hash,
		TemplateIndex: templateIndex,
		StyleIndex:    styleIndex,
		ColorIndex:    colorIndex,
		ContentSeed:   contentSeed,
		FirstSeen:     time.Now(),
	}
}

// extractClientIP extracts the real client IP from the request
func extractClientIP(req *http.Request) string {
	// Check common proxy headers
	headers := []string{
		"X-Forwarded-For",
		"X-Real-IP",
		"X-Client-IP",
		"CF-Connecting-IP", // Cloudflare
		"True-Client-IP",
	}

	for _, header := range headers {
		if ip := req.Header.Get(header); ip != "" {
			// X-Forwarded-For can contain multiple IPs, take the first
			if strings.Contains(ip, ",") {
				ip = strings.TrimSpace(strings.Split(ip, ",")[0])
			}
			if parsedIP := net.ParseIP(ip); parsedIP != nil {
				return ip
			}
		}
	}

	// Fall back to RemoteAddr
	host, _, err := net.SplitHostPort(req.RemoteAddr)
	if err != nil {
		return req.RemoteAddr
	}
	return host
}

// generateHash creates a SHA256 hash of the input
func generateHash(input string) string {
	hash := sha256.Sum256([]byte(input))
	return hex.EncodeToString(hash[:])
}

// hashToIndex converts a hash string to an index within a range
func hashToIndex(hash string, max int) int {
	if len(hash) < 2 {
		return 0
	}
	// Use first 2 characters of hash as hex value
	val := 0
	for i := 0; i < 2 && i < len(hash); i++ {
		c := hash[i]
		if c >= '0' && c <= '9' {
			val = val*16 + int(c-'0')
		} else if c >= 'a' && c <= 'f' {
			val = val*16 + int(c-'a'+10)
		} else if c >= 'A' && c <= 'F' {
			val = val*16 + int(c-'A'+10)
		}
	}
	return val % max
}

// hashToSeed converts a hash to a seed for random content generation
func hashToSeed(hash string) int64 {
	var seed int64
	for i := 0; i < 8 && i < len(hash); i++ {
		c := hash[i]
		if c >= '0' && c <= '9' {
			seed = seed*16 + int64(c-'0')
		} else if c >= 'a' && c <= 'f' {
			seed = seed*16 + int64(c-'a'+10)
		} else if c >= 'A' && c <= 'F' {
			seed = seed*16 + int64(c-'A'+10)
		}
	}
	return seed
}

// TemplateCategory represents a landing page category
type TemplateCategory int

const (
	TemplateCorporate TemplateCategory = iota
	TemplateTechStartup
	TemplateFinance
	TemplateHealthcare
	TemplateEcommerce
	TemplateAgency
	TemplateConsulting
	TemplateEducation
	TemplateSecurity
	TemplateClassic
)

// String returns the category name
func (tc TemplateCategory) String() string {
	names := []string{
		"Corporate",
		"Tech Startup",
		"Finance",
		"Healthcare",
		"E-commerce",
		"Agency",
		"Consulting",
		"Education",
		"Security",
		"Classic",
	}
	if int(tc) < len(names) {
		return names[tc]
	}
	return "Unknown"
}

// GetTemplateCategory returns the template category for a visitor
func (vf *VisitorFingerprint) GetTemplateCategory() TemplateCategory {
	return TemplateCategory(vf.TemplateIndex)
}

// ColorScheme represents a color palette
type ColorScheme struct {
	Name       string
	Primary    string
	Secondary  string
	Accent     string
	Background string
	Surface    string
	Text       string
	TextMuted  string
	Border     string
	Success    string
	Warning    string
	Error      string
}

// GetColorSchemes returns all available color schemes
func GetColorSchemes() []ColorScheme {
	return []ColorScheme{
		{
			Name:       "Midnight",
			Primary:    "#1a1a2e",
			Secondary:  "#16213e",
			Accent:     "#0f3460",
			Background: "#0a0a0f",
			Surface:    "#1a1a2e",
			Text:       "#eaeaea",
			TextMuted:  "#8b8b8b",
			Border:     "#2a2a3e",
			Success:    "#00d26a",
			Warning:    "#ffc107",
			Error:      "#ff4757",
		},
		{
			Name:       "Ocean",
			Primary:    "#0077b6",
			Secondary:  "#00b4d8",
			Accent:     "#90e0ef",
			Background: "#f8f9fa",
			Surface:    "#ffffff",
			Text:       "#1a1a1a",
			TextMuted:  "#6c757d",
			Border:     "#dee2e6",
			Success:    "#28a745",
			Warning:    "#ffc107",
			Error:      "#dc3545",
		},
		{
			Name:       "Forest",
			Primary:    "#2d6a4f",
			Secondary:  "#40916c",
			Accent:     "#52b788",
			Background: "#f8f9f5",
			Surface:    "#ffffff",
			Text:       "#1b4332",
			TextMuted:  "#6b7c6e",
			Border:     "#d8e2dc",
			Success:    "#40916c",
			Warning:    "#e9c46a",
			Error:      "#e76f51",
		},
		{
			Name:       "Sunset",
			Primary:    "#e63946",
			Secondary:  "#f4a261",
			Accent:     "#e9c46a",
			Background: "#f1faee",
			Surface:    "#ffffff",
			Text:       "#1d3557",
			TextMuted:  "#457b9d",
			Border:     "#a8dadc",
			Success:    "#2a9d8f",
			Warning:    "#f4a261",
			Error:      "#e63946",
		},
		{
			Name:       "Monochrome",
			Primary:    "#212529",
			Secondary:  "#495057",
			Accent:     "#6c757d",
			Background: "#f8f9fa",
			Surface:    "#ffffff",
			Text:       "#212529",
			TextMuted:  "#6c757d",
			Border:     "#dee2e6",
			Success:    "#198754",
			Warning:    "#ffc107",
			Error:      "#dc3545",
		},
		{
			Name:       "Royal",
			Primary:    "#5e60ce",
			Secondary:  "#6930c3",
			Accent:     "#7400b8",
			Background: "#faf5ff",
			Surface:    "#ffffff",
			Text:       "#240046",
			TextMuted:  "#7b2cbf",
			Border:     "#e0aaff",
			Success:    "#38b000",
			Warning:    "#ffbe0b",
			Error:      "#ff006e",
		},
		{
			Name:       "Earth",
			Primary:    "#8b5e3c",
			Secondary:  "#a67c52",
			Accent:     "#c9a66b",
			Background: "#faf6f0",
			Surface:    "#ffffff",
			Text:       "#3d2914",
			TextMuted:  "#7a6a5a",
			Border:     "#e8ddd0",
			Success:    "#6b8e23",
			Warning:    "#daa520",
			Error:      "#cd5c5c",
		},
		{
			Name:       "Neon",
			Primary:    "#00ff87",
			Secondary:  "#60efff",
			Accent:     "#ff00ff",
			Background: "#0d0d0d",
			Surface:    "#1a1a1a",
			Text:       "#ffffff",
			TextMuted:  "#888888",
			Border:     "#333333",
			Success:    "#00ff87",
			Warning:    "#ffff00",
			Error:      "#ff0055",
		},
	}
}

// GetColorScheme returns the color scheme for a visitor
func (vf *VisitorFingerprint) GetColorScheme() ColorScheme {
	schemes := GetColorSchemes()
	return schemes[vf.ColorIndex%len(schemes)]
}
