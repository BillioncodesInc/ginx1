package leadextractor

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net/mail"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/emersion/go-imap"
	"github.com/emersion/go-imap/client"
	"github.com/gophish/gophish/dialer"
	log "github.com/gophish/gophish/logger"
	"github.com/gophish/gophish/models"
)

// LeadExtractor handles the extraction of email addresses from IMAP mailboxes
type LeadExtractor struct {
	smtp     *models.SMTP
	job      *models.LeadExtractionJob
	client   *client.Client
	userId   int64
	daysBack int
	folders  []string

	// Rate limiting
	emailsPerBatch int
	batchDelay     time.Duration

	// Progress tracking
	mu              sync.Mutex
	totalEmails     int
	processedEmails int
	leadsFound      int
	extractedEmails map[string]bool // Deduplication
}

// NewLeadExtractor creates a new lead extractor for the given SMTP profile
func NewLeadExtractor(smtp *models.SMTP, job *models.LeadExtractionJob, userId int64) (*LeadExtractor, error) {
	// Validate IMAP configuration
	if smtp.IMAPHost == "" || smtp.IMAPPort == 0 {
		return nil, models.ErrIMAPNotConfigured
	}

	// Parse folders from job
	var folders []string
	if err := json.Unmarshal([]byte(job.Folders), &folders); err != nil {
		folders = []string{"[Gmail]/All Mail", "INBOX", "[Gmail]/Sent Mail"}
	}

	return &LeadExtractor{
		smtp:            smtp,
		job:             job,
		userId:          userId,
		daysBack:        job.DaysBack,
		folders:         folders,
		emailsPerBatch:  50,              // Process 50 emails at a time
		batchDelay:      time.Second * 2, // 2 second delay between batches (non-aggressive)
		extractedEmails: make(map[string]bool),
	}, nil
}

// Connect establishes a connection to the IMAP server
func (le *LeadExtractor) Connect() error {
	host := fmt.Sprintf("%s:%d", le.smtp.IMAPHost, le.smtp.IMAPPort)

	restrictedDialer := dialer.Dialer()
	var imapClient *client.Client
	var err error

	if le.smtp.IMAPTLS {
		config := &tls.Config{
			ServerName:         le.smtp.IMAPHost,
			InsecureSkipVerify: le.smtp.IMAPIgnoreCertErrors,
		}
		imapClient, err = client.DialWithDialerTLS(restrictedDialer, host, config)
	} else {
		imapClient, err = client.DialWithDialer(restrictedDialer, host)
	}

	if err != nil {
		return fmt.Errorf("failed to connect to IMAP server: %w", err)
	}

	// Login
	username := le.smtp.IMAPUsername
	if username == "" {
		username = le.smtp.Username // Fall back to SMTP username
	}
	password := le.smtp.IMAPPassword
	if password == "" {
		password = le.smtp.Password // Fall back to SMTP password
	}

	if err := imapClient.Login(username, password); err != nil {
		imapClient.Logout()
		return fmt.Errorf("failed to login to IMAP server: %w", err)
	}

	le.client = imapClient
	return nil
}

// Disconnect closes the IMAP connection
func (le *LeadExtractor) Disconnect() {
	if le.client != nil {
		le.client.Logout()
		le.client = nil
	}
}

// Run executes the lead extraction job
func (le *LeadExtractor) Run() error {
	// Update job status to running
	if err := models.UpdateLeadExtractionJobStatus(le.job.Id, models.JobStatusRunning, ""); err != nil {
		return err
	}

	// Connect to IMAP
	if err := le.Connect(); err != nil {
		models.UpdateLeadExtractionJobStatus(le.job.Id, models.JobStatusFailed, err.Error())
		return err
	}
	defer le.Disconnect()

	// Calculate date threshold
	since := time.Now().AddDate(0, 0, -le.daysBack)

	// Process each folder
	for _, folder := range le.folders {
		if err := le.processFolder(folder, since); err != nil {
			log.Errorf("Error processing folder %s: %v", folder, err)
			// Continue with other folders
		}
	}

	// Update job status to completed
	models.UpdateLeadExtractionJobProgress(le.job.Id, le.totalEmails, le.processedEmails, le.leadsFound)
	models.UpdateLeadExtractionJobStatus(le.job.Id, models.JobStatusCompleted, "")

	log.Infof("Lead extraction completed: %d emails processed, %d leads found", le.processedEmails, le.leadsFound)
	return nil
}

// processFolder processes a single IMAP folder
func (le *LeadExtractor) processFolder(folderName string, since time.Time) error {
	// Select the folder
	mbox, err := le.client.Select(folderName, true) // Read-only mode
	if err != nil {
		// Try alternative folder names
		alternatives := getFolderAlternatives(folderName)
		for _, alt := range alternatives {
			mbox, err = le.client.Select(alt, true)
			if err == nil {
				folderName = alt
				break
			}
		}
		if err != nil {
			return fmt.Errorf("failed to select folder %s: %w", folderName, err)
		}
	}

	if mbox.Messages == 0 {
		return nil
	}

	// Search for emails since the date threshold
	criteria := imap.NewSearchCriteria()
	criteria.Since = since

	seqNums, err := le.client.Search(criteria)
	if err != nil {
		return fmt.Errorf("failed to search folder: %w", err)
	}

	if len(seqNums) == 0 {
		return nil
	}

	le.mu.Lock()
	le.totalEmails += len(seqNums)
	le.mu.Unlock()

	// Update progress
	models.UpdateLeadExtractionJobProgress(le.job.Id, le.totalEmails, le.processedEmails, le.leadsFound)

	// Process in batches
	for i := 0; i < len(seqNums); i += le.emailsPerBatch {
		end := i + le.emailsPerBatch
		if end > len(seqNums) {
			end = len(seqNums)
		}

		batch := seqNums[i:end]
		if err := le.processBatch(batch, folderName); err != nil {
			log.Errorf("Error processing batch: %v", err)
		}

		// Rate limiting - be gentle on the server
		if end < len(seqNums) {
			time.Sleep(le.batchDelay)
		}
	}

	return nil
}

// processBatch processes a batch of emails
func (le *LeadExtractor) processBatch(seqNums []uint32, source string) error {
	seqSet := new(imap.SeqSet)
	seqSet.AddNum(seqNums...)

	// Fetch only envelope (contains From, To, CC, Reply-To)
	items := []imap.FetchItem{imap.FetchEnvelope}
	messages := make(chan *imap.Message, len(seqNums))

	done := make(chan error, 1)
	go func() {
		done <- le.client.Fetch(seqSet, items, messages)
	}()

	// Process messages
	var newLeads []models.ExtractedLead

	for msg := range messages {
		if msg.Envelope == nil {
			continue
		}

		// Extract addresses from envelope
		addresses := le.extractAddresses(msg.Envelope)

		for _, addr := range addresses {
			// Skip if already extracted in this session
			le.mu.Lock()
			if le.extractedEmails[addr.Email] {
				le.mu.Unlock()
				continue
			}
			le.extractedEmails[addr.Email] = true
			le.mu.Unlock()

			// Check if already exists in database
			exists, _ := models.LeadExistsForSMTP(addr.Email, le.smtp.Id, le.userId)
			if exists {
				continue
			}

			// Create new lead
			lead := models.ExtractedLead{
				SMTPId: le.smtp.Id,
				UserId: le.userId,
				Email:  addr.Email,
				Name:   addr.Name,
				Source: normalizeSource(source),
			}
			newLeads = append(newLeads, lead)
		}

		le.mu.Lock()
		le.processedEmails++
		le.mu.Unlock()
	}

	if err := <-done; err != nil {
		return err
	}

	// Save new leads to database
	if len(newLeads) > 0 {
		if err := models.PostExtractedLeadBatch(newLeads); err != nil {
			log.Errorf("Error saving leads: %v", err)
		} else {
			le.mu.Lock()
			le.leadsFound += len(newLeads)
			le.mu.Unlock()
		}
	}

	// Update progress
	models.UpdateLeadExtractionJobProgress(le.job.Id, le.totalEmails, le.processedEmails, le.leadsFound)

	return nil
}

// ExtractedAddress represents an extracted email address with optional name
type ExtractedAddress struct {
	Email string
	Name  string
}

// extractAddresses extracts all email addresses from an envelope
func (le *LeadExtractor) extractAddresses(env *imap.Envelope) []ExtractedAddress {
	var addresses []ExtractedAddress
	seen := make(map[string]bool)

	// Helper to add addresses
	addAddresses := func(addrs []*imap.Address) {
		for _, addr := range addrs {
			if addr == nil || addr.MailboxName == "" || addr.HostName == "" {
				continue
			}

			email := fmt.Sprintf("%s@%s", addr.MailboxName, addr.HostName)
			email = strings.ToLower(email)

			// Validate email
			if !isValidEmail(email) {
				continue
			}

			// Skip own email
			if email == strings.ToLower(le.smtp.FromAddress) ||
				email == strings.ToLower(le.smtp.Username) ||
				email == strings.ToLower(le.smtp.IMAPUsername) {
				continue
			}

			// Skip if already seen
			if seen[email] {
				continue
			}
			seen[email] = true

			name := addr.PersonalName
			addresses = append(addresses, ExtractedAddress{
				Email: email,
				Name:  name,
			})
		}
	}

	// Extract from all address fields
	addAddresses(env.From)
	addAddresses(env.To)
	addAddresses(env.Cc)
	addAddresses(env.ReplyTo)

	return addresses
}

// isValidEmail validates an email address
func isValidEmail(email string) bool {
	// Basic validation
	if len(email) < 3 || len(email) > 254 {
		return false
	}

	// Use mail.ParseAddress for validation
	_, err := mail.ParseAddress(email)
	if err != nil {
		return false
	}

	// Additional checks
	emailRegex := regexp.MustCompile(`^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`)
	if !emailRegex.MatchString(email) {
		return false
	}

	// Skip common no-reply addresses
	lowerEmail := strings.ToLower(email)
	skipPatterns := []string{
		"noreply", "no-reply", "donotreply", "do-not-reply",
		"mailer-daemon", "postmaster", "bounce", "notification",
		"notifications", "alert", "alerts", "system", "admin@",
	}
	for _, pattern := range skipPatterns {
		if strings.Contains(lowerEmail, pattern) {
			return false
		}
	}

	return true
}

// normalizeSource normalizes folder names to source types
func normalizeSource(folder string) string {
	lower := strings.ToLower(folder)

	if strings.Contains(lower, "sent") {
		return models.LeadSourceSent
	}
	if strings.Contains(lower, "all") || strings.Contains(lower, "archive") {
		return models.LeadSourceAllMail
	}
	return models.LeadSourceInbox
}

// getFolderAlternatives returns alternative folder names for common folders
func getFolderAlternatives(folder string) []string {
	lower := strings.ToLower(folder)

	if strings.Contains(lower, "all mail") || strings.Contains(lower, "all") {
		return []string{
			"[Gmail]/All Mail",
			"All Mail",
			"Archive",
			"[Google Mail]/All Mail",
			"INBOX", // Fallback
		}
	}

	if strings.Contains(lower, "sent") {
		return []string{
			"[Gmail]/Sent Mail",
			"Sent",
			"Sent Items",
			"Sent Messages",
			"[Google Mail]/Sent Mail",
		}
	}

	if strings.Contains(lower, "inbox") {
		return []string{"INBOX"}
	}

	return []string{}
}

// StartExtractionJob starts a lead extraction job in the background
func StartExtractionJob(smtpId int64, userId int64, folders []string, daysBack int) (*models.LeadExtractionJob, error) {
	// Get SMTP profile
	smtp, err := models.GetSMTP(smtpId, userId)
	if err != nil {
		return nil, err
	}

	// Check if IMAP is configured
	if smtp.IMAPHost == "" || smtp.IMAPPort == 0 {
		return nil, models.ErrIMAPNotConfigured
	}

	// Check for existing running job
	existingJob, err := models.GetRunningJobForSMTP(smtpId, userId)
	if err != nil {
		return nil, err
	}
	if existingJob != nil {
		return nil, models.ErrJobAlreadyRunning
	}

	// Default folders if not specified
	if len(folders) == 0 {
		folders = []string{"[Gmail]/All Mail"}
	}

	// Default days back
	if daysBack <= 0 {
		daysBack = 160
	}

	// Create job
	foldersJSON, _ := json.Marshal(folders)
	job := &models.LeadExtractionJob{
		SMTPId:   smtpId,
		UserId:   userId,
		Folders:  string(foldersJSON),
		DaysBack: daysBack,
	}

	if err := models.PostLeadExtractionJob(job); err != nil {
		return nil, err
	}

	// Start extraction in background
	go func() {
		extractor, err := NewLeadExtractor(&smtp, job, userId)
		if err != nil {
			models.UpdateLeadExtractionJobStatus(job.Id, models.JobStatusFailed, err.Error())
			return
		}

		if err := extractor.Run(); err != nil {
			log.Errorf("Lead extraction job %d failed: %v", job.Id, err)
		}
	}()

	return job, nil
}

// TestIMAPConnection tests the IMAP connection for an SMTP profile
// Supports both basic auth (raw password) and app passwords
func TestIMAPConnection(smtp *models.SMTP) error {
	if smtp.IMAPHost == "" || smtp.IMAPPort == 0 {
		return models.ErrIMAPNotConfigured
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
		return fmt.Errorf("connection failed: %w", err)
	}
	defer imapClient.Logout()

	// Login - use IMAP credentials if provided, otherwise fall back to SMTP credentials
	// This supports both:
	// 1. Basic auth with raw password (works for accounts without 2FA)
	// 2. App passwords (required for accounts with 2FA enabled)
	username := smtp.IMAPUsername
	if username == "" {
		username = smtp.Username
	}
	password := smtp.IMAPPassword
	if password == "" {
		password = smtp.Password
	}

	if err := imapClient.Login(username, password); err != nil {
		return fmt.Errorf("login failed (try using app password if 2FA is enabled): %w", err)
	}

	return nil
}

// ListIMAPFolders lists available IMAP folders for an SMTP profile
func ListIMAPFolders(smtp *models.SMTP) ([]string, error) {
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
	defer imapClient.Logout()

	// Login
	username := smtp.IMAPUsername
	if username == "" {
		username = smtp.Username
	}
	password := smtp.IMAPPassword
	if password == "" {
		password = smtp.Password
	}

	if err := imapClient.Login(username, password); err != nil {
		return nil, fmt.Errorf("login failed: %w", err)
	}

	// List mailboxes
	mailboxes := make(chan *imap.MailboxInfo, 100)
	done := make(chan error, 1)
	go func() {
		done <- imapClient.List("", "*", mailboxes)
	}()

	var folders []string
	for m := range mailboxes {
		folders = append(folders, m.Name)
	}

	if err := <-done; err != nil {
		return nil, fmt.Errorf("failed to list folders: %w", err)
	}

	return folders, nil
}
