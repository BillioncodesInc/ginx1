package leadextractor

import (
	"crypto/tls"
	"testing"
	"time"

	"github.com/emersion/go-imap"
	"github.com/emersion/go-imap/client"
	"github.com/gophish/gophish/models"
)

// TestGmailIMAPConnection tests IMAP connection to Gmail
// To run: Replace credentials and remove t.Skip()
func TestGmailIMAPConnection(t *testing.T) {
	t.Skip("Skipping - requires valid Gmail credentials")

	smtp := &models.SMTP{
		Id:                   1,
		IMAPHost:             "imap.gmail.com",
		IMAPPort:             993,
		IMAPUsername:         "your-email@gmail.com",
		IMAPPassword:         "your-app-password", // App password without spaces
		IMAPTLS:              true,
		IMAPIgnoreCertErrors: false,
	}

	err := TestIMAPConnection(smtp)
	if err != nil {
		t.Errorf("IMAP connection failed: %v", err)
	} else {
		t.Log("✅ IMAP connection successful!")
	}
}

// TestGmailListFolders tests listing IMAP folders from Gmail
// To run: Replace credentials and remove t.Skip()
func TestGmailListFolders(t *testing.T) {
	t.Skip("Skipping - requires valid Gmail credentials")

	smtp := &models.SMTP{
		Id:                   1,
		IMAPHost:             "imap.gmail.com",
		IMAPPort:             993,
		IMAPUsername:         "your-email@gmail.com",
		IMAPPassword:         "your-app-password",
		IMAPTLS:              true,
		IMAPIgnoreCertErrors: false,
	}

	folders, err := ListIMAPFolders(smtp)
	if err != nil {
		t.Errorf("Failed to list folders: %v", err)
		return
	}

	t.Log("✅ Available folders:")
	for _, folder := range folders {
		t.Logf("  📁 %s", folder)
	}
}

// TestGmailExtractLeadsSimple tests lead extraction without database dependency
// To run: Replace credentials and remove t.Skip()
func TestGmailExtractLeadsSimple(t *testing.T) {
	t.Skip("Skipping - requires valid Gmail credentials")

	username := "your-email@gmail.com"
	password := "your-app-password"

	// Connect directly without using the full extractor
	t.Log("🔌 Connecting to Gmail IMAP...")

	host := "imap.gmail.com:993"

	config := &tls.Config{
		ServerName:         "imap.gmail.com",
		InsecureSkipVerify: false,
	}

	imapClient, err := client.DialTLS(host, config)
	if err != nil {
		t.Fatalf("Failed to connect: %v", err)
	}
	defer imapClient.Logout()

	// Login
	err = imapClient.Login(username, password)
	if err != nil {
		t.Fatalf("Failed to login: %v", err)
	}
	t.Log("✅ Connected and logged in successfully!")

	// Select All Mail folder
	mbox, err := imapClient.Select("[Gmail]/All Mail", true)
	if err != nil {
		t.Fatalf("Failed to select folder: %v", err)
	}
	t.Logf("📁 [Gmail]/All Mail has %d total messages", mbox.Messages)

	// Search for emails from last 30 days
	since := time.Now().AddDate(0, 0, -30)
	criteria := imap.NewSearchCriteria()
	criteria.Since = since

	seqNums, err := imapClient.Search(criteria)
	if err != nil {
		t.Fatalf("Failed to search: %v", err)
	}
	t.Logf("📧 Found %d emails from last 30 days", len(seqNums))

	if len(seqNums) == 0 {
		t.Log("✅ No emails to process")
		return
	}

	// Fetch first 20 emails to extract addresses
	maxFetch := 20
	if len(seqNums) < maxFetch {
		maxFetch = len(seqNums)
	}

	seqSet := new(imap.SeqSet)
	seqSet.AddNum(seqNums[:maxFetch]...)

	messages := make(chan *imap.Message, maxFetch)
	done := make(chan error, 1)
	go func() {
		done <- imapClient.Fetch(seqSet, []imap.FetchItem{imap.FetchEnvelope}, messages)
	}()

	extractedEmails := make(map[string]string) // email -> name

	for msg := range messages {
		if msg.Envelope == nil {
			continue
		}

		// Extract From addresses
		for _, addr := range msg.Envelope.From {
			if addr != nil && addr.MailboxName != "" && addr.HostName != "" {
				email := addr.MailboxName + "@" + addr.HostName
				if email != username && isValidEmail(email) {
					extractedEmails[email] = addr.PersonalName
				}
			}
		}

		// Extract To addresses
		for _, addr := range msg.Envelope.To {
			if addr != nil && addr.MailboxName != "" && addr.HostName != "" {
				email := addr.MailboxName + "@" + addr.HostName
				if email != username && isValidEmail(email) {
					extractedEmails[email] = addr.PersonalName
				}
			}
		}
	}

	if err := <-done; err != nil {
		t.Errorf("Fetch error: %v", err)
	}

	t.Logf("✅ Extraction complete!")
	t.Logf("   📊 Emails processed: %d", maxFetch)
	t.Logf("   👥 Unique leads found: %d", len(extractedEmails))

	// Print extracted leads
	if len(extractedEmails) > 0 {
		t.Log("   📝 Extracted leads:")
		count := 0
		for email, name := range extractedEmails {
			if count >= 15 {
				t.Logf("      ... and %d more", len(extractedEmails)-15)
				break
			}
			if name != "" {
				t.Logf("      - %s <%s>", name, email)
			} else {
				t.Logf("      - %s", email)
			}
			count++
		}
	}
}
