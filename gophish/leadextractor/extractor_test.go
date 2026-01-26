package leadextractor

import (
	"fmt"
	"testing"
	"time"

	"github.com/gophish/gophish/models"
)

// TestIMAPConnectionOutlook tests IMAP connection to Outlook
// Note: Requires valid credentials - Microsoft has disabled basic auth
// Use App Password or OAuth2 for production
func TestIMAPConnectionOutlook(t *testing.T) {
	t.Skip("Skipping - requires valid IMAP credentials with App Password")

	smtp := &models.SMTP{
		Id:                   1,
		IMAPHost:             "outlook.office365.com",
		IMAPPort:             993,
		IMAPUsername:         "your-email@outlook.com",
		IMAPPassword:         "your-app-password",
		IMAPTLS:              true,
		IMAPIgnoreCertErrors: false,
	}

	err := TestIMAPConnection(smtp)
	if err != nil {
		t.Errorf("IMAP connection failed: %v", err)
	} else {
		t.Log("IMAP connection successful!")
	}
}

// TestListFoldersOutlook tests listing IMAP folders
func TestListFoldersOutlook(t *testing.T) {
	t.Skip("Skipping - requires valid IMAP credentials with App Password")

	smtp := &models.SMTP{
		Id:                   1,
		IMAPHost:             "outlook.office365.com",
		IMAPPort:             993,
		IMAPUsername:         "your-email@outlook.com",
		IMAPPassword:         "your-app-password",
		IMAPTLS:              true,
		IMAPIgnoreCertErrors: false,
	}

	folders, err := ListIMAPFolders(smtp)
	if err != nil {
		t.Errorf("Failed to list folders: %v", err)
		return
	}

	t.Log("Available folders:")
	for _, folder := range folders {
		t.Logf("  - %s", folder)
	}
}

// TestExtractAddressesSimple tests the email extraction logic
func TestExtractAddressesSimple(t *testing.T) {
	// Test email validation
	validEmails := []string{
		"test@example.com",
		"user.name@domain.org",
		"first.last@company.co.uk",
	}

	invalidEmails := []string{
		"noreply@example.com",
		"no-reply@domain.com",
		"mailer-daemon@server.com",
		"invalid",
		"@nodomain.com",
	}

	for _, email := range validEmails {
		if !isValidEmail(email) {
			t.Errorf("Expected %s to be valid", email)
		}
	}

	for _, email := range invalidEmails {
		if isValidEmail(email) {
			t.Errorf("Expected %s to be invalid", email)
		}
	}
}

// TestNormalizeSource tests folder name normalization
func TestNormalizeSource(t *testing.T) {
	tests := []struct {
		folder   string
		expected string
	}{
		{"INBOX", models.LeadSourceInbox},
		{"Sent", models.LeadSourceSent},
		{"Sent Items", models.LeadSourceSent},
		{"[Gmail]/Sent Mail", models.LeadSourceSent},
		{"[Gmail]/All Mail", models.LeadSourceAllMail},
		{"Archive", models.LeadSourceAllMail},
	}

	for _, test := range tests {
		result := normalizeSource(test.folder)
		if result != test.expected {
			t.Errorf("normalizeSource(%s) = %s, expected %s", test.folder, result, test.expected)
		}
	}
}

// ManualTestExtraction is a manual test for full extraction
// Run with: go test -v -run ManualTestExtraction -timeout 5m
func ManualTestExtraction(t *testing.T) {
	t.Skip("Manual test - requires valid credentials")

	smtp := &models.SMTP{
		Id:                   1,
		UserId:               1,
		IMAPHost:             "outlook.office365.com",
		IMAPPort:             993,
		IMAPUsername:         "your-email@outlook.com",
		IMAPPassword:         "your-app-password",
		IMAPTLS:              true,
		IMAPIgnoreCertErrors: false,
		FromAddress:          "your-email@outlook.com",
		Username:             "your-email@outlook.com",
	}

	// Create a mock job
	job := &models.LeadExtractionJob{
		Id:       1,
		SMTPId:   1,
		UserId:   1,
		Folders:  `["INBOX", "Sent"]`,
		DaysBack: 30,
	}

	extractor, err := NewLeadExtractor(smtp, job, 1)
	if err != nil {
		t.Fatalf("Failed to create extractor: %v", err)
	}

	// Connect
	err = extractor.Connect()
	if err != nil {
		t.Fatalf("Failed to connect: %v", err)
	}
	defer extractor.Disconnect()

	t.Log("Connected successfully!")

	// Process a small batch
	since := time.Now().AddDate(0, 0, -30)
	err = extractor.processFolder("INBOX", since)
	if err != nil {
		t.Errorf("Failed to process INBOX: %v", err)
	}

	t.Logf("Processed %d emails, found %d leads", extractor.processedEmails, extractor.leadsFound)
}

// PrintTestResults prints a summary of what would happen
func PrintTestResults() {
	fmt.Println("=== Lead Extraction Test Summary ===")
	fmt.Println("")
	fmt.Println("IMAP Configuration:")
	fmt.Println("  Host: outlook.office365.com")
	fmt.Println("  Port: 993")
	fmt.Println("  TLS: true")
	fmt.Println("  Email: kennethjrichard01@outlook.com")
	fmt.Println("")
	fmt.Println("Expected Flow:")
	fmt.Println("1. User adds IMAP settings to SMTP profile")
	fmt.Println("2. User clicks 'Test IMAP Connection' -> API validates credentials")
	fmt.Println("3. User clicks 'Extract Leads' -> Opens modal with folder selection")
	fmt.Println("4. User selects folders and days back -> Starts background job")
	fmt.Println("5. Job connects to IMAP, searches emails since date")
	fmt.Println("6. For each email, extracts From/To/CC/Reply-To addresses")
	fmt.Println("7. Deduplicates and saves to extracted_leads table")
	fmt.Println("8. User can view leads and import to groups")
	fmt.Println("")
}
