package leadextractor

import (
	"testing"

	"github.com/gophish/gophish/models"
)

// TestOutlookBasicAuth tests IMAP connection to Outlook using basic auth (raw password)
// This works for accounts WITHOUT 2FA enabled
func TestOutlookBasicAuth(t *testing.T) {
	t.Skip("Skipping - requires valid Outlook credentials")

	smtp := &models.SMTP{
		Id:                   1,
		IMAPHost:             "outlook.office365.com",
		IMAPPort:             993,
		IMAPUsername:         "your-email@outlook.com",
		IMAPPassword:         "your-password", // Raw password (not app password)
		IMAPTLS:              true,
		IMAPIgnoreCertErrors: false,
	}

	err := TestIMAPConnection(smtp)
	if err != nil {
		t.Logf("❌ Basic auth failed: %v", err)
		t.Log("This is expected if:")
		t.Log("  - 2FA/MFA is enabled on the account")
		t.Log("  - Microsoft has disabled basic auth for this account")
		t.Log("  - The password is incorrect")
		t.Log("")
		t.Log("Solutions:")
		t.Log("  1. Disable 2FA on the account (not recommended)")
		t.Log("  2. Use an App Password (requires 2FA to be enabled)")
		t.Log("  3. Use OAuth2 authentication (requires Azure AD app registration)")
	} else {
		t.Log("✅ IMAP connection successful with basic auth!")
	}
}

// TestOutlookListFolders tests listing IMAP folders from Outlook
func TestOutlookListFolders(t *testing.T) {
	t.Skip("Skipping - requires valid Outlook credentials")

	smtp := &models.SMTP{
		Id:                   1,
		IMAPHost:             "outlook.office365.com",
		IMAPPort:             993,
		IMAPUsername:         "your-email@outlook.com",
		IMAPPassword:         "your-password",
		IMAPTLS:              true,
		IMAPIgnoreCertErrors: false,
	}

	folders, err := ListIMAPFolders(smtp)
	if err != nil {
		t.Logf("❌ Failed to list folders: %v", err)
		return
	}

	t.Log("✅ Available folders:")
	for _, folder := range folders {
		t.Logf("  📁 %s", folder)
	}
}
