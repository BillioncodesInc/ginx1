package leadextractor

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/emersion/go-imap/client"
	"github.com/emersion/go-sasl"
	"github.com/gophish/gophish/dialer"
	"github.com/gophish/gophish/models"
	"golang.org/x/oauth2"
)

// OAuth2Config holds OAuth2 configuration for email providers
type OAuth2Config struct {
	ClientID     string
	ClientSecret string
	TenantID     string // For Microsoft (use "common" for multi-tenant)
	RedirectURL  string
	Scopes       []string
}

// MicrosoftOAuth2Config returns the OAuth2 config for Microsoft/Outlook
// Note: You need to register an Azure AD application to get ClientID and ClientSecret
// See: https://docs.microsoft.com/en-us/azure/active-directory/develop/quickstart-register-app
func MicrosoftOAuth2Config(clientID, clientSecret, tenantID string) *oauth2.Config {
	if tenantID == "" {
		tenantID = "common" // Multi-tenant
	}

	return &oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		Endpoint: oauth2.Endpoint{
			AuthURL:  fmt.Sprintf("https://login.microsoftonline.com/%s/oauth2/v2.0/authorize", tenantID),
			TokenURL: fmt.Sprintf("https://login.microsoftonline.com/%s/oauth2/v2.0/token", tenantID),
		},
		RedirectURL: "http://localhost:8080/oauth/callback",
		Scopes: []string{
			"https://outlook.office365.com/IMAP.AccessAsUser.All",
			"offline_access",
		},
	}
}

// GmailOAuth2Config returns the OAuth2 config for Gmail
// Note: You need to create a Google Cloud project and OAuth2 credentials
// See: https://developers.google.com/identity/protocols/oauth2
func GmailOAuth2Config(clientID, clientSecret string) *oauth2.Config {
	return &oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		Endpoint: oauth2.Endpoint{
			AuthURL:  "https://accounts.google.com/o/oauth2/auth",
			TokenURL: "https://oauth2.googleapis.com/token",
		},
		RedirectURL: "http://localhost:8080/oauth/callback",
		Scopes: []string{
			"https://mail.google.com/",
		},
	}
}

// XOAuth2SASL implements SASL XOAUTH2 authentication
type XOAuth2SASL struct {
	Username    string
	AccessToken string
}

// Start begins the XOAUTH2 authentication
func (a *XOAuth2SASL) Start() (mech string, ir []byte, err error) {
	// XOAUTH2 format: "user=" + user + "\x01auth=Bearer " + accessToken + "\x01\x01"
	authString := fmt.Sprintf("user=%s\x01auth=Bearer %s\x01\x01", a.Username, a.AccessToken)
	return "XOAUTH2", []byte(authString), nil
}

// Next handles the server's challenge (not used in XOAUTH2)
func (a *XOAuth2SASL) Next(challenge []byte) (response []byte, err error) {
	// XOAUTH2 doesn't have a challenge-response phase
	// If we get here, authentication failed
	return nil, fmt.Errorf("unexpected challenge: %s", string(challenge))
}

// ConnectWithOAuth2 connects to an IMAP server using OAuth2 authentication
func ConnectWithOAuth2(smtp *models.SMTP, accessToken string) (*client.Client, error) {
	if smtp.IMAPHost == "" || smtp.IMAPPort == 0 {
		return nil, models.ErrIMAPNotConfigured
	}

	host := smtp.IMAPHost + ":" + strconv.Itoa(int(smtp.IMAPPort))
	restrictedDialer := dialer.Dialer()

	var imapClient *client.Client
	var err error

	if smtp.IMAPTLS {
		config := &tls.Config{
			ServerName:         smtp.IMAPHost,
			InsecureSkipVerify: smtp.IMAPIgnoreCertErrors,
		}
		imapClient, err = client.DialWithDialerTLS(restrictedDialer, host, config)
	} else {
		imapClient, err = client.DialWithDialer(restrictedDialer, host)
	}

	if err != nil {
		return nil, fmt.Errorf("connection failed: %w", err)
	}

	// Get username
	username := smtp.IMAPUsername
	if username == "" {
		username = smtp.Username
	}

	// Authenticate using XOAUTH2
	saslClient := &XOAuth2SASL{
		Username:    username,
		AccessToken: accessToken,
	}

	if err := imapClient.Authenticate(saslClient); err != nil {
		imapClient.Logout()
		return nil, fmt.Errorf("OAuth2 authentication failed: %w", err)
	}

	return imapClient, nil
}

// TestOAuth2Connection tests IMAP connection using OAuth2
func TestOAuth2Connection(smtp *models.SMTP, accessToken string) error {
	imapClient, err := ConnectWithOAuth2(smtp, accessToken)
	if err != nil {
		return err
	}
	defer imapClient.Logout()
	return nil
}

// RefreshOAuth2Token refreshes an OAuth2 token using the refresh token
func RefreshOAuth2Token(config *oauth2.Config, refreshToken string) (*oauth2.Token, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	token := &oauth2.Token{
		RefreshToken: refreshToken,
	}

	tokenSource := config.TokenSource(ctx, token)
	newToken, err := tokenSource.Token()
	if err != nil {
		return nil, fmt.Errorf("failed to refresh token: %w", err)
	}

	return newToken, nil
}

// GetOAuth2AuthURL generates the authorization URL for OAuth2 flow
func GetOAuth2AuthURL(config *oauth2.Config, state string) string {
	return config.AuthCodeURL(state, oauth2.AccessTypeOffline)
}

// ExchangeOAuth2Code exchanges an authorization code for tokens
func ExchangeOAuth2Code(config *oauth2.Config, code string) (*oauth2.Token, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	token, err := config.Exchange(ctx, code)
	if err != nil {
		return nil, fmt.Errorf("failed to exchange code: %w", err)
	}

	return token, nil
}

// DetectAuthMethod detects the best authentication method for an email provider
func DetectAuthMethod(domain string) string {
	domain = strings.ToLower(domain)

	// Microsoft domains - prefer OAuth2 but basic auth may work
	microsoftDomains := []string{
		"outlook.com", "hotmail.com", "live.com", "msn.com",
		"outlook.fr", "outlook.de", "outlook.es", "outlook.it",
		"outlook.co.uk", "hotmail.fr", "hotmail.de", "hotmail.es",
		"live.fr", "live.de", "live.nl", "live.ca", "live.co.uk",
	}
	for _, d := range microsoftDomains {
		if strings.HasSuffix(domain, d) {
			return "oauth2_or_basic"
		}
	}

	// Gmail - requires OAuth2 or App Password
	if strings.HasSuffix(domain, "gmail.com") || strings.HasSuffix(domain, "googlemail.com") {
		return "oauth2_or_app_password"
	}

	// Yahoo - requires App Password
	if strings.Contains(domain, "yahoo.") || domain == "ymail.com" || domain == "rocketmail.com" {
		return "app_password"
	}

	// iCloud - requires App Password
	if domain == "icloud.com" || domain == "me.com" || domain == "mac.com" {
		return "app_password"
	}

	// Default - try basic auth
	return "basic"
}

// IMAPServerConfig holds IMAP server configuration
type IMAPServerConfig struct {
	Host string
	Port int
	SSL  bool
}

// GetIMAPServer returns the IMAP server configuration for a domain
func GetIMAPServer(domain string) *IMAPServerConfig {
	domain = strings.ToLower(domain)

	// Microsoft
	microsoftDomains := []string{
		"outlook.com", "hotmail.com", "live.com", "msn.com",
		"outlook.fr", "outlook.de", "outlook.es", "outlook.it",
		"outlook.co.uk", "hotmail.fr", "hotmail.de", "hotmail.es",
		"live.fr", "live.de", "live.nl", "live.ca", "live.co.uk",
	}
	for _, d := range microsoftDomains {
		if strings.HasSuffix(domain, d) {
			return &IMAPServerConfig{Host: "outlook.office365.com", Port: 993, SSL: true}
		}
	}

	// Gmail
	if strings.HasSuffix(domain, "gmail.com") || strings.HasSuffix(domain, "googlemail.com") {
		return &IMAPServerConfig{Host: "imap.gmail.com", Port: 993, SSL: true}
	}

	// Yahoo
	if strings.Contains(domain, "yahoo.") || domain == "ymail.com" || domain == "rocketmail.com" {
		return &IMAPServerConfig{Host: "imap.mail.yahoo.com", Port: 993, SSL: true}
	}

	// iCloud
	if domain == "icloud.com" || domain == "me.com" || domain == "mac.com" {
		return &IMAPServerConfig{Host: "imap.mail.me.com", Port: 993, SSL: true}
	}

	// AOL
	if domain == "aol.com" || domain == "aim.com" {
		return &IMAPServerConfig{Host: "imap.aol.com", Port: 993, SSL: true}
	}

	// Try auto-discovery
	return autoDiscoverIMAP(domain)
}

// autoDiscoverIMAP attempts to auto-discover IMAP server for a domain
func autoDiscoverIMAP(domain string) *IMAPServerConfig {
	patterns := []string{
		"imap." + domain,
		"mail." + domain,
		"imap.mail." + domain,
	}

	for _, host := range patterns {
		// Try SSL on port 993
		if testConnection(host, 993) {
			return &IMAPServerConfig{Host: host, Port: 993, SSL: true}
		}
		// Try STARTTLS on port 143
		if testConnection(host, 143) {
			return &IMAPServerConfig{Host: host, Port: 143, SSL: false}
		}
	}

	// Default guess
	return &IMAPServerConfig{Host: "imap." + domain, Port: 993, SSL: true}
}

// testConnection tests if a host:port is reachable
func testConnection(host string, port int) bool {
	address := fmt.Sprintf("%s:%d", host, port)
	conn, err := net.DialTimeout("tcp", address, 5*time.Second)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

// EncodeXOAuth2 encodes the XOAUTH2 string for IMAP authentication
func EncodeXOAuth2(username, accessToken string) string {
	authString := fmt.Sprintf("user=%s\x01auth=Bearer %s\x01\x01", username, accessToken)
	return base64.StdEncoding.EncodeToString([]byte(authString))
}

// Ensure XOAuth2SASL implements sasl.Client
var _ sasl.Client = (*XOAuth2SASL)(nil)
