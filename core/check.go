package core

import (
	"bufio"
	"crypto/x509"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"

	"github.com/kgretzky/evilginx2/log"
)

// RequestChecker holds all the blocking lists
type RequestChecker struct {
	asnList       map[string]bool    // ASN numbers to block
	userAgentList map[string]bool    // User agent keywords to block
	ipRanges      []*net.IPNet       // IP ranges to block (CIDR notation)
	ipList        map[string]bool    // Individual IPs to block
	mu            sync.RWMutex       // Mutex for thread-safe operations
	verbose       bool
}

// NewRequestChecker creates a new RequestChecker instance
func NewRequestChecker(asnFile, userAgentFile, ipRangeFile, ipListFile string, verbose bool) (*RequestChecker, error) {
	rc := &RequestChecker{
		asnList:       make(map[string]bool),
		userAgentList: make(map[string]bool),
		ipRanges:      make([]*net.IPNet, 0),
		ipList:        make(map[string]bool),
		verbose:       verbose,
	}

	// Load ASN list
	if err := rc.loadASNList(asnFile); err != nil {
		log.Warning("check: failed to load ASN list: %v", err)
	}

	// Load User Agent wordlist
	if err := rc.loadUserAgentList(userAgentFile); err != nil {
		log.Warning("check: failed to load user agent list: %v", err)
	}

	// Load IP Range list
	if err := rc.loadIPRangeList(ipRangeFile); err != nil {
		log.Warning("check: failed to load IP range list: %v", err)
	}

	// Load IP list
	if err := rc.loadIPList(ipListFile); err != nil {
		log.Warning("check: failed to load IP list: %v", err)
	}

	log.Info("check: loaded %d ASNs, %d user agent keywords, %d IP ranges, %d IPs",
		len(rc.asnList), len(rc.userAgentList), len(rc.ipRanges), len(rc.ipList))

	return rc, nil
}

// loadASNList loads ASN numbers from file
func (rc *RequestChecker) loadASNList(filename string) error {
	if filename == "" {
		return nil
	}

	file, err := os.Open(filename)
	if err != nil {
		if os.IsNotExist(err) {
			if rc.verbose {
				log.Warning("check: ASN list file not found: %s", filename)
			}
			return nil // File doesn't exist, skip
		}
		return err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	count := 0
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		// Skip comments and empty lines
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		// Remove "AS" prefix if present
		line = strings.TrimPrefix(strings.ToUpper(line), "AS")
		rc.asnList[line] = true
		count++
	}

	if rc.verbose {
		log.Debug("check: loaded %d ASN entries from %s", count, filename)
	}

	return scanner.Err()
}

// loadUserAgentList loads user agent keywords from file
func (rc *RequestChecker) loadUserAgentList(filename string) error {
	if filename == "" {
		return nil
	}

	file, err := os.Open(filename)
	if err != nil {
		if os.IsNotExist(err) {
			if rc.verbose {
				log.Warning("check: User agent list file not found: %s", filename)
			}
			return nil
		}
		return err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	count := 0
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		// Skip comments and empty lines
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		rc.userAgentList[strings.ToLower(line)] = true
		count++
	}

	if rc.verbose {
		log.Debug("check: loaded %d user agent keywords from %s", count, filename)
	}

	return scanner.Err()
}

// loadIPRangeList loads IP ranges (CIDR notation) from file
func (rc *RequestChecker) loadIPRangeList(filename string) error {
	if filename == "" {
		return nil
	}

	file, err := os.Open(filename)
	if err != nil {
		if os.IsNotExist(err) {
			if rc.verbose {
				log.Warning("check: IP range list file not found: %s", filename)
			}
			return nil
		}
		return err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	count := 0
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		// Skip comments and empty lines
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}

		// Parse CIDR notation
		_, ipNet, err := net.ParseCIDR(line)
		if err != nil {
			log.Warning("check: invalid IP range '%s': %v", line, err)
			continue
		}
		rc.ipRanges = append(rc.ipRanges, ipNet)
		count++
	}

	if rc.verbose {
		log.Debug("check: loaded %d IP ranges from %s", count, filename)
	}

	return scanner.Err()
}

// loadIPList loads individual IPs from file
func (rc *RequestChecker) loadIPList(filename string) error {
	if filename == "" {
		return nil
	}

	file, err := os.Open(filename)
	if err != nil {
		if os.IsNotExist(err) {
			if rc.verbose {
				log.Warning("check: IP list file not found: %s", filename)
			}
			return nil
		}
		return err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	count := 0
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		// Skip comments and empty lines
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}

		// Validate IP address
		ip := net.ParseIP(line)
		if ip == nil {
			log.Warning("check: invalid IP address '%s'", line)
			continue
		}
		rc.ipList[ip.String()] = true
		count++
	}

	if rc.verbose {
		log.Debug("check: loaded %d IP addresses from %s", count, filename)
	}

	return scanner.Err()
}

// CheckRequest processes the request against all blocking lists
// Returns true if the IP should be blocked, false otherwise
func (rc *RequestChecker) CheckRequest(req *http.Request, clientIP string) (bool, string) {
	rc.mu.RLock()
	defer rc.mu.RUnlock()

	// 1. Check IP list (fastest check first)
	if rc.checkIPList(clientIP) {
		if rc.verbose {
			log.Warning("check: IP '%s' found in IP blocklist", clientIP)
		}
		return true, "ip_list"
	}

	// 2. Check IP range list
	if rc.checkIPRange(clientIP) {
		if rc.verbose {
			log.Warning("check: IP '%s' found in IP range blocklist", clientIP)
		}
		return true, "ip_range"
	}

	// 3. Check user agent wordlist
	if rc.checkUserAgent(req) {
		if rc.verbose {
			log.Warning("check: User-Agent for IP '%s' matched blocklist: %s", clientIP, req.UserAgent())
		}
		return true, "user_agent"
	}

	// 4. Check ASN from certificate (if TLS connection)
	if rc.checkASN(req) {
		if rc.verbose {
			log.Warning("check: ASN for IP '%s' found in blocklist", clientIP)
		}
		return true, "asn"
	}

	return false, ""
}

// checkIPList checks if IP is in the individual IP blocklist
func (rc *RequestChecker) checkIPList(clientIP string) bool {
	ip := net.ParseIP(clientIP)
	if ip == nil {
		return false
	}
	return rc.ipList[ip.String()]
}

// checkIPRange checks if IP falls within any blocked IP range
func (rc *RequestChecker) checkIPRange(clientIP string) bool {
	ip := net.ParseIP(clientIP)
	if ip == nil {
		return false
	}

	for _, ipNet := range rc.ipRanges {
		if ipNet.Contains(ip) {
			return true
		}
	}
	return false
}

// checkUserAgent checks if user agent contains any blocked keywords
func (rc *RequestChecker) checkUserAgent(req *http.Request) bool {
	userAgent := strings.ToLower(req.UserAgent())
	if userAgent == "" {
		return false
	}

	// Check if any keyword from the wordlist is in the user agent
	for keyword := range rc.userAgentList {
		if strings.Contains(userAgent, keyword) {
			return true
		}
	}
	return false
}

// checkASN checks the ASN from the TLS certificate
func (rc *RequestChecker) checkASN(req *http.Request) bool {
	// Check if request has TLS connection state
	if req.TLS == nil {
		return false
	}

	// Extract ASN from certificate if available
	if len(req.TLS.PeerCertificates) > 0 {
		cert := req.TLS.PeerCertificates[0]
		asn := rc.extractASNFromCert(cert)
		if asn != "" && rc.asnList[asn] {
			return true
		}
	}

	return false
}

// extractASNFromCert extracts ASN number from X509 certificate
func (rc *RequestChecker) extractASNFromCert(cert *x509.Certificate) string {
	// Check Organization field for ASN
	for _, org := range cert.Subject.Organization {
		// Look for ASN pattern (e.g., "AS12345" or "12345")
		if strings.HasPrefix(strings.ToUpper(org), "AS") {
			asn := strings.TrimPrefix(strings.ToUpper(org), "AS")
			if _, err := strconv.Atoi(asn); err == nil {
				return asn
			}
		}
	}

	// Check OrganizationalUnit
	for _, ou := range cert.Subject.OrganizationalUnit {
		if strings.HasPrefix(strings.ToUpper(ou), "AS") {
			asn := strings.TrimPrefix(strings.ToUpper(ou), "AS")
			if _, err := strconv.Atoi(asn); err == nil {
				return asn
			}
		}
	}

	return ""
}

// GetClientIP extracts the real client IP from request headers
func GetClientIP(req *http.Request) string {
	// Check proxy headers in order of priority
	proxyHeaders := []string{
		"X-Forwarded-For",
		"X-Real-IP",
		"X-Client-IP",
		"CF-Connecting-IP",
		"True-Client-IP",
		"Fastly-Client-IP",
	}

	for _, header := range proxyHeaders {
		ip := req.Header.Get(header)
		if ip != "" {
			// X-Forwarded-For can contain multiple IPs, take the first one
			ips := strings.Split(ip, ",")
			clientIP := strings.TrimSpace(ips[0])
			if clientIP != "" {
				return clientIP
			}
		}
	}

	// Fallback to RemoteAddr
	ip, _, err := net.SplitHostPort(req.RemoteAddr)
	if err != nil {
		return req.RemoteAddr
	}
	return ip
}

// ReloadLists reloads all blocking lists from files
func (rc *RequestChecker) ReloadLists(asnFile, userAgentFile, ipRangeFile, ipListFile string) error {
	rc.mu.Lock()
	defer rc.mu.Unlock()

	// Clear existing lists
	rc.asnList = make(map[string]bool)
	rc.userAgentList = make(map[string]bool)
	rc.ipRanges = make([]*net.IPNet, 0)
	rc.ipList = make(map[string]bool)

	// Reload all lists
	if err := rc.loadASNList(asnFile); err != nil {
		return err
	}
	if err := rc.loadUserAgentList(userAgentFile); err != nil {
		return err
	}
	if err := rc.loadIPRangeList(ipRangeFile); err != nil {
		return err
	}
	if err := rc.loadIPList(ipListFile); err != nil {
		return err
	}

	log.Info("check: reloaded %d ASNs, %d user agent keywords, %d IP ranges, %d IPs",
		len(rc.asnList), len(rc.userAgentList), len(rc.ipRanges), len(rc.ipList))

	return nil
}

// SetVerbose enables or disables verbose logging
func (rc *RequestChecker) SetVerbose(verbose bool) {
	rc.mu.Lock()
	defer rc.mu.Unlock()
	rc.verbose = verbose
}

// GetStats returns statistics about loaded lists
func (rc *RequestChecker) GetStats() (int, int, int, int) {
	rc.mu.RLock()
	defer rc.mu.RUnlock()
	return len(rc.asnList), len(rc.userAgentList), len(rc.ipRanges), len(rc.ipList)
}
