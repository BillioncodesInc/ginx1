package core

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/kgretzky/evilginx2/log"
)

type PhishletUpdater struct {
	phishletsDir string
	repositories []string
	lastCheck    time.Time
	updateChan   chan string
}

type GitHubFile struct {
	Name        string `json:"name"`
	Path        string `json:"path"`
	DownloadURL string `json:"download_url"`
	Type        string `json:"type"`
}

// NewPhishletUpdater creates a new phishlet updater
func NewPhishletUpdater(phishletsDir string) *PhishletUpdater {
	return &PhishletUpdater{
		phishletsDir: phishletsDir,
		repositories: []string{
			"https://api.github.com/repos/kgretzky/evilginx2/contents/phishlets",
			"https://api.github.com/repos/An0nUD4Y/Evilginx2-Phishlets/contents/",
		},
		updateChan: make(chan string, 10),
	}
}

// AddRepository adds a custom phishlet repository
func (pu *PhishletUpdater) AddRepository(repoURL string) {
	pu.repositories = append(pu.repositories, repoURL)
	log.Info("Added phishlet repository: %s", repoURL)
}

// CheckForUpdates checks all repositories for new/updated phishlets
func (pu *PhishletUpdater) CheckForUpdates() ([]string, error) {
	log.Info("🔍 Checking for phishlet updates...")

	var availablePhishlets []string
	existingPhishlets := make(map[string]bool)

	// Get list of existing phishlets
	files, err := ioutil.ReadDir(pu.phishletsDir)
	if err != nil {
		return nil, fmt.Errorf("failed to read phishlets directory: %v", err)
	}

	for _, file := range files {
		if strings.HasSuffix(file.Name(), ".yaml") {
			existingPhishlets[file.Name()] = true
		}
	}

	// Check each repository
	for _, repo := range pu.repositories {
		phishlets, err := pu.fetchFromRepository(repo)
		if err != nil {
			log.Warning("Failed to fetch from %s: %v", repo, err)
			continue
		}

		for _, phishlet := range phishlets {
			if !existingPhishlets[phishlet] {
				availablePhishlets = append(availablePhishlets, phishlet)
			}
		}
	}

	pu.lastCheck = time.Now()

	if len(availablePhishlets) > 0 {
		log.Success("✅ Found %d new phishlets available", len(availablePhishlets))
	} else {
		log.Info("📦 All phishlets are up to date")
	}

	return availablePhishlets, nil
}

// fetchFromRepository fetches phishlet list from a GitHub repository
func (pu *PhishletUpdater) fetchFromRepository(repoURL string) ([]string, error) {
	client := &http.Client{
		Timeout: 10 * time.Second,
	}

	req, err := http.NewRequest("GET", repoURL, nil)
	if err != nil {
		return nil, err
	}

	// Set User-Agent to avoid rate limiting
	req.Header.Set("User-Agent", "ProfGinx-Updater/2.1")

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, resp.Status)
	}

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var files []GitHubFile
	if err := json.Unmarshal(body, &files); err != nil {
		return nil, err
	}

	var phishlets []string
	for _, file := range files {
		if file.Type == "file" && strings.HasSuffix(file.Name, ".yaml") {
			phishlets = append(phishlets, file.Name)
		}
	}

	return phishlets, nil
}

// DownloadPhishlet downloads a specific phishlet from repositories
func (pu *PhishletUpdater) DownloadPhishlet(name string) error {
	log.Info("📥 Downloading phishlet: %s", name)

	for _, repo := range pu.repositories {
		if err := pu.downloadFromRepository(repo, name); err == nil {
			log.Success("✅ Downloaded %s successfully", name)
			return nil
		}
	}

	return fmt.Errorf("phishlet %s not found in any repository", name)
}

// downloadFromRepository downloads a phishlet from a specific repository
func (pu *PhishletUpdater) downloadFromRepository(repoURL, name string) error {
	client := &http.Client{
		Timeout: 10 * time.Second,
	}

	// Fetch directory listing
	req, err := http.NewRequest("GET", repoURL, nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", "ProfGinx-Updater/2.1")

	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("HTTP %d", resp.StatusCode)
	}

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	var files []GitHubFile
	if err := json.Unmarshal(body, &files); err != nil {
		return err
	}

	// Find the phishlet
	for _, file := range files {
		if file.Name == name && file.DownloadURL != "" {
			return pu.downloadFile(file.DownloadURL, filepath.Join(pu.phishletsDir, name))
		}
	}

	return fmt.Errorf("phishlet not found in repository")
}

// downloadFile downloads a file from a URL
func (pu *PhishletUpdater) downloadFile(url, destPath string) error {
	client := &http.Client{
		Timeout: 30 * time.Second,
	}

	resp, err := client.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("HTTP %d", resp.StatusCode)
	}

	content, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	// Write to file
	if err := ioutil.WriteFile(destPath, content, 0644); err != nil {
		return err
	}

	return nil
}

// UpdateAll downloads all available new phishlets
func (pu *PhishletUpdater) UpdateAll() (int, error) {
	available, err := pu.CheckForUpdates()
	if err != nil {
		return 0, err
	}

	if len(available) == 0 {
		log.Info("No updates available")
		return 0, nil
	}

	log.Info("📦 Updating %d phishlets...", len(available))

	count := 0
	for _, phishlet := range available {
		if err := pu.DownloadPhishlet(phishlet); err != nil {
			log.Warning("Failed to download %s: %v", phishlet, err)
		} else {
			count++
		}
	}

	log.Success("✅ Successfully updated %d/%d phishlets", count, len(available))
	return count, nil
}

// StartAutoUpdater starts background auto-update checker
func (pu *PhishletUpdater) StartAutoUpdater(checkInterval time.Duration) {
	log.Info("🔄 Auto-updater started (check interval: %v)", checkInterval)

	ticker := time.NewTicker(checkInterval)
	go func() {
		for range ticker.C {
			available, err := pu.CheckForUpdates()
			if err != nil {
				log.Debug("Auto-update check failed: %v", err)
				continue
			}

			if len(available) > 0 {
				log.Important("🆕 %d new phishlets available! Use 'phishlets update' to download", len(available))
				for _, name := range available {
					select {
					case pu.updateChan <- name:
					default:
					}
				}
			}
		}
	}()
}

// GetAvailableUpdates returns list of phishlets that can be updated
func (pu *PhishletUpdater) GetAvailableUpdates() []string {
	var updates []string
	for len(pu.updateChan) > 0 {
		updates = append(updates, <-pu.updateChan)
	}
	return updates
}

// GetLastCheckTime returns when updates were last checked
func (pu *PhishletUpdater) GetLastCheckTime() time.Time {
	return pu.lastCheck
}

// ListRemotePhishlets lists all available phishlets from all repositories
func (pu *PhishletUpdater) ListRemotePhishlets() (map[string][]string, error) {
	result := make(map[string][]string)

	for _, repo := range pu.repositories {
		phishlets, err := pu.fetchFromRepository(repo)
		if err != nil {
			log.Warning("Failed to fetch from %s: %v", repo, err)
			continue
		}

		// Extract repo name from URL
		parts := strings.Split(repo, "/")
		repoName := "unknown"
		if len(parts) >= 5 {
			repoName = parts[4]
		}

		result[repoName] = phishlets
	}

	return result, nil
}

// BackupPhishlet creates a backup of a phishlet before updating
func (pu *PhishletUpdater) BackupPhishlet(name string) error {
	srcPath := filepath.Join(pu.phishletsDir, name)

	// Check if file exists
	if _, err := os.Stat(srcPath); os.IsNotExist(err) {
		return fmt.Errorf("phishlet %s does not exist", name)
	}

	// Create backup directory
	backupDir := filepath.Join(pu.phishletsDir, ".backups")
	if err := os.MkdirAll(backupDir, 0755); err != nil {
		return err
	}

	// Backup filename with timestamp
	timestamp := time.Now().Format("20060102_150405")
	backupName := strings.TrimSuffix(name, ".yaml") + "_" + timestamp + ".yaml"
	backupPath := filepath.Join(backupDir, backupName)

	// Read and write
	content, err := ioutil.ReadFile(srcPath)
	if err != nil {
		return err
	}

	if err := ioutil.WriteFile(backupPath, content, 0644); err != nil {
		return err
	}

	log.Info("💾 Backed up %s to %s", name, backupPath)
	return nil
}
