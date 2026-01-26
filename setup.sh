#!/bin/bash

# ProfGinx V8 - One-Time Setup Script
# Complete installation: deps, DNS, firewall, RID, build

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

clear

echo -e "${CYAN}╔══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${CYAN}║              PROFGINX V8 SETUP SCRIPT                        ║${NC}"
echo -e "${CYAN}║           Complete One-Time Installation                     ║${NC}"
echo -e "${CYAN}╚══════════════════════════════════════════════════════════════╝${NC}"
echo ""

# ============================================
# HELPER FUNCTIONS
# ============================================

print_good() {
    echo -e "${GREEN}[+]${NC} $1"
}

print_error() {
    echo -e "${RED}[-]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[!]${NC} $1"
}

print_info() {
    echo -e "${BLUE}[*]${NC} $1"
}

check_root() {
    if [[ "$EUID" -ne 0 ]]; then
        print_error "This script requires root privileges"
        echo ""
        echo "Usage: sudo ./setup.sh full [--rid <name>]"
        echo ""
        echo "Examples:"
        echo "  sudo ./setup.sh full                # Setup with default RID"
        echo "  sudo ./setup.sh full --rid uid      # Setup with custom RID"
        echo ""
        exit 1
    fi
}

show_usage() {
    echo -e "${BLUE}Usage:${NC} sudo ./setup.sh full [--rid <name>]"
    echo ""
    echo -e "${YELLOW}Options:${NC}"
    echo "  --rid <name>    Replace default tracking parameter with custom value"
    echo ""
    echo -e "${YELLOW}Examples:${NC}"
    echo "  sudo ./setup.sh full                    # Complete setup"
    echo "  sudo ./setup.sh full --rid user_token   # Setup with custom RID"
    echo "  sudo ./setup.sh full --rid uid          # Setup with custom RID 'uid'"
    echo ""
    echo -e "${YELLOW}What this script does:${NC}"
    echo "  1. Installs/updates system dependencies"
    echo "  2. Configures swap (4GB if RAM < 8GB)"
    echo "  3. Installs Google Chrome (for GoogleBypasser + KasadaBypasser)"
    echo "  4. Configures DNS (disables systemd-resolved)"
    echo "  5. Installs Go if not present"
    echo "  6. Clears ports 80/443"
    echo "  7. Configures firewall"
    echo "  8. Downloads GeoIP database"
    echo "  9. Replaces RID (if specified)"
    echo "  10. Builds all binaries"
    echo "  11. Sets up PhishCreator (Python)"
    echo "  12. Sets up GMaps Scraper (Go + Playwright)"
    echo "  13. Sets up DomainHunterPro (Node.js + Playwright)"
    echo ""
}

# ============================================
# SETUP FUNCTIONS
# ============================================

configure_swap() {
    # Check total RAM in MB
    local total_ram=$(free -m | awk '/^Mem:/{print $2}')

    print_info "Detected RAM: ${total_ram}MB"

    # If RAM >= 8GB, skip swap configuration
    if [[ $total_ram -ge 8000 ]]; then
        print_good "RAM is 8GB or more - swap configuration not needed"
        return 0
    fi

    print_warning "RAM is less than 8GB - configuring swap for better performance..."

    # Check if swap already exists
    local current_swap=$(free -m | awk '/^Swap:/{print $2}')
    if [[ $current_swap -gt 0 ]]; then
        print_info "Swap already configured: ${current_swap}MB"

        # If swap is less than 2GB and RAM is low, suggest adding more
        if [[ $current_swap -lt 2000 ]]; then
            print_warning "Current swap (${current_swap}MB) may be insufficient for running all services"
        else
            print_good "Existing swap is sufficient"
            return 0
        fi
    fi

    # Check if /swapfile already exists
    if [[ -f /swapfile ]]; then
        print_info "Swapfile already exists at /swapfile"
        # Ensure it's active
        if ! swapon --show | grep -q "/swapfile"; then
            print_info "Activating existing swapfile..."
            swapon /swapfile 2>/dev/null || true
        fi
        return 0
    fi

    # Calculate swap size: 4GB for servers with less than 8GB RAM
    local swap_size="4G"
    print_info "Creating ${swap_size} swap file..."

    # Create swap file
    if fallocate -l $swap_size /swapfile 2>/dev/null; then
        print_good "Swap file created with fallocate"
    else
        # Fallback for filesystems that don't support fallocate
        print_info "Using dd to create swap file (this may take a moment)..."
        dd if=/dev/zero of=/swapfile bs=1M count=4096 status=progress 2>/dev/null
    fi

    # Set correct permissions
    chmod 600 /swapfile

    # Format as swap
    if mkswap /swapfile; then
        print_good "Swap file formatted"
    else
        print_error "Failed to format swap file"
        rm -f /swapfile
        return 1
    fi

    # Enable swap
    if swapon /swapfile; then
        print_good "Swap enabled"
    else
        print_error "Failed to enable swap"
        rm -f /swapfile
        return 1
    fi

    # Make permanent - add to fstab if not already there
    if ! grep -q "/swapfile" /etc/fstab; then
        echo '/swapfile none swap sw 0 0' >> /etc/fstab
        print_good "Swap added to /etc/fstab (will persist after reboot)"
    fi

    # Optimize swappiness for server workload (lower = prefer RAM)
    local current_swappiness=$(cat /proc/sys/vm/swappiness 2>/dev/null || echo "60")
    if [[ $current_swappiness -gt 10 ]]; then
        echo 'vm.swappiness=10' >> /etc/sysctl.conf
        sysctl vm.swappiness=10 2>/dev/null || true
        print_good "Swappiness set to 10 (optimized for server workload)"
    fi

    # Show final swap status
    local new_swap=$(free -m | awk '/^Swap:/{print $2}')
    print_good "Swap configured successfully: ${new_swap}MB total"
    echo ""
    print_info "Memory status after swap configuration:"
    free -h
}

install_dependencies() {
    print_info "Updating system and installing dependencies..."
    echo ""

    # Full system update and dependency installation
    apt update && apt upgrade -y

    # Install all required packages (including Chrome deps for GoogleBypasser + KasadaBypasser)
    apt install -y \
        build-essential \
        gcc \
        g++ \
        make \
        git \
        wget \
        curl \
        tmux \
        openssl \
        jq \
        net-tools \
        certbot \
        network-manager \
        libsqlite3-dev \
        sqlite3 \
        pkg-config \
        libatk1.0-0 \
        libatk-bridge2.0-0 \
        libcups2 \
        libdrm2 \
        libxkbcommon0 \
        libxcomposite1 \
        libxdamage1 \
        libxfixes3 \
        libxrandr2 \
        libgbm1 \
        libpango-1.0-0 \
        libcairo2 \
        libasound2t64 \
        libnspr4 \
        libnss3 \
        libxss1 \
        fonts-liberation \
        libappindicator3-1 \
        xdg-utils \
        ca-certificates

    print_good "Dependencies installed (CGO/SQLite3 + Chrome libs for GoogleBypasser + KasadaBypasser)!"
}

install_chrome() {
    print_info "Installing Google Chrome for GoogleBypasser + KasadaBypasser (go-rod)..."

    # Check if Chrome is already installed
    if command -v google-chrome &> /dev/null || command -v google-chrome-stable &> /dev/null; then
        local chrome_version=$(google-chrome --version 2>/dev/null || google-chrome-stable --version 2>/dev/null)
        print_info "Chrome already installed: $chrome_version"
        return 0
    fi

    # Download and install Google Chrome
    print_info "Downloading Google Chrome..."
    wget -q https://dl.google.com/linux/direct/google-chrome-stable_current_amd64.deb -O /tmp/chrome.deb

    if [[ ! -f /tmp/chrome.deb ]]; then
        print_error "Failed to download Chrome"
        return 1
    fi

    print_info "Installing Chrome package..."
    dpkg -i /tmp/chrome.deb 2>/dev/null || true

    # Fix any broken dependencies
    apt --fix-broken install -y

    # Clean up
    rm -f /tmp/chrome.deb

    # Verify installation
    if command -v google-chrome &> /dev/null || command -v google-chrome-stable &> /dev/null; then
        local chrome_version=$(google-chrome --version 2>/dev/null || google-chrome-stable --version 2>/dev/null)
        print_good "Chrome installed: $chrome_version"
    else
        print_warning "Chrome installation may have failed - GoogleBypasser may not work"
    fi
}

download_geoip() {
    print_info "Downloading GeoLite2-City database for map geo-location..."
    echo ""

    local GEOIP_URL="https://git.io/GeoLite2-City.mmdb"
    
    # Download for EvilFeed (uses GeoLite2-City.mmdb - mixed case)
    local EVILFEED_GEOIP="$SCRIPT_DIR/evilfeed/GeoLite2-City.mmdb"
    
    # Download for GoPhish (uses geolite2-city.mmdb - lowercase)
    local GOPHISH_GEOIP="$SCRIPT_DIR/gophish/static/db/geolite2-city.mmdb"
    
    # Function to download and validate GeoIP file
    download_geoip_file() {
        local target_file="$1"
        local target_name="$2"
        
        # Check if already exists and is valid (> 1MB)
        if [[ -f "$target_file" ]]; then
            local file_size=$(stat -f%z "$target_file" 2>/dev/null || stat -c%s "$target_file" 2>/dev/null)
            if [[ "$file_size" -gt 1000000 ]]; then
                print_info "$target_name: Already exists ($(numfmt --to=iec $file_size 2>/dev/null || echo "${file_size} bytes"))"
                return 0
            else
                print_warning "$target_name: Existing file is too small, re-downloading..."
                rm -f "$target_file"
            fi
        fi
        
        # Ensure target directory exists
        mkdir -p "$(dirname "$target_file")"
        
        # Download the file
        print_info "$target_name: Downloading from $GEOIP_URL ..."
        if curl -L -o "$target_file" "$GEOIP_URL" --progress-bar; then
            local file_size=$(stat -f%z "$target_file" 2>/dev/null || stat -c%s "$target_file" 2>/dev/null)
            if [[ "$file_size" -gt 1000000 ]]; then
                print_good "$target_name: Downloaded successfully ($(numfmt --to=iec $file_size 2>/dev/null || echo "${file_size} bytes"))"
                return 0
            else
                print_warning "$target_name: Downloaded file is too small"
                return 1
            fi
        else
            print_warning "$target_name: Failed to download"
            return 1
        fi
    }
    
    # Download for EvilFeed
    echo ""
    print_info "Downloading GeoIP for EvilFeed..."
    download_geoip_file "$EVILFEED_GEOIP" "EvilFeed GeoIP"
    
    # Download for GoPhish (separate copy with lowercase filename)
    echo ""
    print_info "Downloading GeoIP for GoPhish..."
    download_geoip_file "$GOPHISH_GEOIP" "GoPhish GeoIP"
    
    echo ""
    print_info "GeoIP database setup complete"
    print_info "  - EvilFeed: $EVILFEED_GEOIP"
    print_info "  - GoPhish:  $GOPHISH_GEOIP"
}

configure_dns() {
    print_info "Configuring DNS (disabling systemd-resolved)..."
    echo ""

    # Stop and disable systemd-resolved
    systemctl stop systemd-resolved 2>/dev/null || true
    systemctl disable systemd-resolved 2>/dev/null || true

    # Configure NetworkManager to handle DNS (if NetworkManager is installed)
    if [[ -d "/etc/NetworkManager" ]]; then
        cat > /etc/NetworkManager/NetworkManager.conf << 'EOF'
[main]
dns=default
EOF
        # Restart NetworkManager
        systemctl restart NetworkManager 2>/dev/null || true
    fi

    # Remove existing resolv.conf and create new one with Cloudflare DNS
    rm -f /etc/resolv.conf
    cat > /etc/resolv.conf << 'EOF'
nameserver 1.1.1.1
nameserver 1.0.0.1
EOF

    print_good "DNS configured with Cloudflare (1.1.1.1, 1.0.0.1)"
}

install_go() {
    if command -v go &> /dev/null; then
        local go_version=$(go version | awk '{print $3}')
        print_info "Go is already installed: $go_version"
        return 0
    fi

    print_info "Installing Go from source..."

    # Get latest Go version
    local v=$(curl -s https://go.dev/dl/?mode=json | jq -r '.[0].version')
    local arch="amd64"
    [[ "$(uname -m)" == "aarch64" ]] && arch="arm64"

    wget -q "https://go.dev/dl/${v}.linux-${arch}.tar.gz" -O /tmp/go.tar.gz
    rm -rf /usr/local/go
    tar -C /usr/local -xzf /tmp/go.tar.gz
    ln -sf /usr/local/go/bin/go /usr/bin/go
    rm /tmp/go.tar.gz

    print_good "Go installed: $(go version | awk '{print $3}')"
}

clear_ports() {
    print_info "Clearing ports 80 and 443..."

    # Kill any processes using ports 80 and 443
    fuser -k 80/tcp 2>/dev/null || true
    fuser -k 443/tcp 2>/dev/null || true

    # Stop common services that use these ports
    systemctl stop apache2 2>/dev/null || true
    systemctl stop nginx 2>/dev/null || true
    systemctl stop httpd 2>/dev/null || true

    # Disable them from starting on boot
    systemctl disable apache2 2>/dev/null || true
    systemctl disable nginx 2>/dev/null || true
    systemctl disable httpd 2>/dev/null || true

    print_good "Ports 80 and 443 cleared"
}

configure_firewall() {
    print_info "Configuring firewall..."

    if command -v ufw &> /dev/null; then
        ufw allow 80/tcp 2>/dev/null || true
        ufw allow 443/tcp 2>/dev/null || true
        ufw allow 1337/tcp 2>/dev/null || true  # EvilFeed
        ufw allow 3333/tcp 2>/dev/null || true  # GoPhish admin
        ufw allow 5050/tcp 2>/dev/null || true  # Phishlet Web
        ufw allow 8080/tcp 2>/dev/null || true  # GMaps Scraper
        ufw allow 9091/tcp 2>/dev/null || true  # Evilginx webpanel
        print_good "UFW firewall rules configured"
    elif command -v firewall-cmd &> /dev/null; then
        firewall-cmd --permanent --add-port=80/tcp 2>/dev/null || true
        firewall-cmd --permanent --add-port=443/tcp 2>/dev/null || true
        firewall-cmd --permanent --add-port=1337/tcp 2>/dev/null || true
        firewall-cmd --permanent --add-port=3333/tcp 2>/dev/null || true
        firewall-cmd --permanent --add-port=5050/tcp 2>/dev/null || true
        firewall-cmd --permanent --add-port=8080/tcp 2>/dev/null || true
        firewall-cmd --permanent --add-port=9091/tcp 2>/dev/null || true
        firewall-cmd --reload 2>/dev/null || true
        print_good "Firewalld rules configured"
    else
        print_warning "No firewall manager detected"
    fi
}

replace_rid() {
    local new_rid="$1"

    if [[ -z "$new_rid" ]]; then
        print_info "No custom RID specified, using default"
        return 0
    fi

    print_info "Replacing RID with: $new_rid"

    # Detect current RID from gophish source
    local rid_file="$SCRIPT_DIR/gophish/models/campaign.go"
    local current_rid=""

    if [[ -f "$rid_file" ]]; then
        current_rid=$(grep -oP 'RecipientParameter\s*=\s*"\K[^"]+' "$rid_file" 2>/dev/null)
    fi

    if [[ -z "$current_rid" ]]; then
        # Fallback search
        current_rid=$(grep -rhoP 'RecipientParameter\s*=\s*"\K[^"]+' --include="*.go" "$SCRIPT_DIR/gophish" 2>/dev/null | head -1)
    fi

    if [[ -z "$current_rid" ]]; then
        print_warning "Could not detect current RID, skipping replacement"
        return 0
    fi

    if [[ "$current_rid" == "$new_rid" ]]; then
        print_info "RID already set to: $new_rid"
        return 0
    fi

    print_info "Replacing: $current_rid -> $new_rid"

    # Do the replacement in all relevant files
    # Use word boundaries to avoid replacing uid inside function names like Getuid/Geteuid
    for ext in go yaml yml json html js; do
        find "$SCRIPT_DIR" -type f -name "*.$ext" \
            ! -path "*/.git/*" ! -path "*/vendor/*" ! -path "*/node_modules/*" \
            ! -path "*/.evilginx/*" -exec grep -l "$current_rid" {} \; 2>/dev/null | \
        while read -r file; do
            # For Go files, be more careful - only replace in string literals and specific patterns
            if [[ "$ext" == "go" ]]; then
                # Replace "uid" (in quotes - string literals)
                sed -i "s|\"${current_rid}\"|\"${new_rid}\"|g" "$file"
                # Replace =uid or = uid (assignments)
                sed -i "s|= ${current_rid}$|= ${new_rid}|g" "$file"
                sed -i "s|=${current_rid}$|=${new_rid}|g" "$file"
                # Replace ?uid= or &uid= (URL parameters)
                sed -i "s|?${current_rid}=|?${new_rid}=|g" "$file"
                sed -i "s|&${current_rid}=|&${new_rid}=|g" "$file"
            else
                sed -i "s|${current_rid}|${new_rid}|g" "$file"
            fi
        done
    done

    print_good "RID replaced: $current_rid -> $new_rid"
}

setup_phishcreator() {
    print_info "Setting up PhishCreator Pro (Python Flask app with Live Traffic Analysis)..."
    echo ""

    local PHISHLET_WEB_DIR="$SCRIPT_DIR/phishcreator"
    local PYTHON_BIN=""

    if [[ ! -d "$PHISHLET_WEB_DIR" ]]; then
        print_warning "phishcreator directory not found, skipping..."
        return 0
    fi

    # Install Python 3.12 specifically (required for Playwright compatibility)
    print_info "Installing Python 3.12 (required for Playwright compatibility)..."
    apt update

    # Check if Python 3.12 is available in default repos
    if apt-cache show python3.12 &>/dev/null; then
        print_info "Python 3.12 found in repositories, installing..."
        apt install -y python3.12 python3.12-venv python3.12-dev
        PYTHON_BIN="python3.12"
    else
        # Add deadsnakes PPA for Python 3.12 (Ubuntu)
        print_info "Adding deadsnakes PPA for Python 3.12..."
        apt install -y software-properties-common
        add-apt-repository -y ppa:deadsnakes/ppa 2>/dev/null || true
        apt update

        if apt-cache show python3.12 &>/dev/null; then
            apt install -y python3.12 python3.12-venv python3.12-dev
            PYTHON_BIN="python3.12"
        else
            # Final fallback: use whatever python3 is available
            print_warning "Python 3.12 not available, using system Python..."
            apt install -y python3 python3-pip python3-venv
            PYTHON_BIN="python3"
        fi
    fi

    # Verify Python installation
    if ! command -v $PYTHON_BIN &>/dev/null; then
        print_error "Python installation failed"
        return 1
    fi

    local py_version=$($PYTHON_BIN -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
    print_good "Using Python $py_version ($PYTHON_BIN)"

    # Pre-install Playwright system dependencies (required for headless Ubuntu)
    print_info "Installing Playwright system dependencies..."
    apt install -y libnss3 libatk1.0-0 libatk-bridge2.0-0 libcups2 libxkbcommon0 \
        libxcomposite1 libxdamage1 libxrandr2 libgbm1 libpango-1.0-0 libcairo2 \
        libasound2t64 libxshmfence1 2>/dev/null || true

    cd "$PHISHLET_WEB_DIR"

    # Remove old venv if exists (ensures clean install with correct Python version)
    if [[ -d "venv" ]]; then
        print_info "Removing old virtual environment..."
        rm -rf venv
    fi

    # Create virtual environment with the correct Python version
    print_info "Creating Python virtual environment..."
    $PYTHON_BIN -m venv venv

    # Activate and install dependencies
    print_info "Installing Python dependencies..."
    source venv/bin/activate
    python -m pip install --upgrade pip > /dev/null 2>&1

    # Install from requirements.txt if available, otherwise install manually
    if [[ -f "requirements.txt" ]]; then
        python -m pip install -r requirements.txt 2>&1 | grep -v "already satisfied" || true
    else
        python -m pip install flask flask-cors pyyaml requests werkzeug playwright 2>&1 | grep -v "already satisfied" || true
    fi

    # Ensure Playwright is installed even if requirements.txt doesn't include it
    if ! python -c "import playwright" >/dev/null 2>&1; then
        print_info "Installing Playwright..."
        python -m pip install playwright 2>&1 || true
    fi

    # Install Playwright browsers for live traffic analysis
    print_info "Installing Playwright browsers for live traffic analysis..."
    # Install browsers into a shared path so running as root/non-root doesn't break
    mkdir -p "$PHISHLET_WEB_DIR/.playwright" 2>/dev/null || true
    PLAYWRIGHT_BROWSERS_PATH="$PHISHLET_WEB_DIR/.playwright" \
        python -m playwright install --with-deps chromium 2>&1 || \
    PLAYWRIGHT_BROWSERS_PATH="$PHISHLET_WEB_DIR/.playwright" \
        python -m playwright install chromium 2>&1 || true

    # Verify Playwright installation
    if python -c "from playwright.sync_api import sync_playwright" >/dev/null 2>&1; then
        print_good "Playwright installed and working"
    else
        print_warning "Playwright may not be fully functional - Live Traffic Analysis may be limited"
        print_warning "Core PhishCreator features (HAR analysis, phishlet fixing) will still work"
    fi

    deactivate

    cd "$SCRIPT_DIR"

    print_good "PhishCreator Pro environment configured (with Playwright for live traffic capture)"
}

setup_gmapscraper() {
    print_info "Setting up GMaps Scraper (Go application with Playwright)..."
    echo ""

    local GMAPS_DIR="$SCRIPT_DIR/gmapscraper"

    if [[ ! -d "$GMAPS_DIR" ]]; then
        print_warning "gmapscraper directory not found, skipping..."
        return 0
    fi

    cd "$GMAPS_DIR"

    # Install Go dependencies
    print_info "Installing Go dependencies for GMaps Scraper..."
    go mod tidy 2>/dev/null || true

    # Build the binary
    print_info "Building GMaps Scraper binary..."
    if go build -o gmapscraper . 2>&1; then
        print_good "gmapscraper built successfully"
    else
        print_warning "Failed to build gmapscraper - will be built on first run"
    fi

    # Install Playwright browsers (required for local scraping mode)
    print_info "Installing Playwright browsers for GMaps Scraper..."

    # Try using Go's playwright-go to install browsers
    if go run github.com/playwright-community/playwright-go/cmd/playwright@latest install --with-deps chromium 2>/dev/null; then
        print_good "Playwright Chromium installed via Go"
    else
        # Fallback to npx if available
        if command -v npx &> /dev/null; then
            npx playwright install chromium 2>/dev/null || true
            print_good "Playwright Chromium installed via npx"
        else
            print_warning "Could not install Playwright browsers automatically"
            print_info "Run manually: go run github.com/playwright-community/playwright-go/cmd/playwright@latest install --with-deps chromium"
        fi
    fi

    cd "$SCRIPT_DIR"

    print_good "GMaps Scraper environment configured"
}

setup_domainhunter() {
    print_info "Setting up DomainHunterPro (Node.js application)..."
    echo ""

    local DOMAINHUNTER_DIR="$SCRIPT_DIR/domainhunterpro"

    if [[ ! -d "$DOMAINHUNTER_DIR" ]]; then
        print_warning "domainhunterpro directory not found, skipping..."
        return 0
    fi

    # Install Node.js if not present
    if ! command -v node &> /dev/null; then
        print_info "Installing Node.js..."
        curl -fsSL https://deb.nodesource.com/setup_20.x | bash -
        apt install -y nodejs
    fi

    # Install pnpm if not present
    if ! command -v pnpm &> /dev/null; then
        print_info "Installing pnpm..."
        npm install -g pnpm
    fi

    # Install build tools for native modules (better-sqlite3)
    print_info "Installing build tools for native Node.js modules..."
    apt install -y python3 make g++ 2>/dev/null || true

    cd "$DOMAINHUNTER_DIR"

    # Install dependencies with build scripts enabled for native modules
    print_info "Installing Node.js dependencies (this may take a while)..."

    # Configure pnpm to allow build scripts for better-sqlite3
    pnpm config set enable-pre-post-scripts true 2>/dev/null || true

    # Install with onlyBuiltDependencies to trigger native builds
    pnpm install --config.onlyBuiltDependencies=better-sqlite3 2>&1 || pnpm install

    # Build native modules (better-sqlite3 requires compilation)
    print_info "Building native modules (better-sqlite3)..."

    # Navigate to better-sqlite3 and build directly
    local SQLITE_DIR=$(find node_modules/.pnpm -type d -name "better-sqlite3" -path "*better-sqlite3@*/node_modules/*" 2>/dev/null | head -1)
    if [[ -n "$SQLITE_DIR" && -d "$SQLITE_DIR" ]]; then
        cd "$SQLITE_DIR"
        if [[ -f "package.json" ]]; then
            print_info "Building better-sqlite3 in $SQLITE_DIR..."
            npm run build-release 2>&1 || npx node-gyp rebuild 2>&1 || {
                print_warning "node-gyp rebuild failed, trying prebuild..."
                npx prebuild-install 2>&1 || true
            }
        fi
        cd "$DOMAINHUNTER_DIR"
    else
        print_warning "Could not find better-sqlite3 directory"
    fi

    # Verify the native module was built
    if find node_modules -name "better_sqlite3.node" 2>/dev/null | grep -q .; then
        print_good "better-sqlite3 native module built successfully"
    else
        print_warning "better-sqlite3 native module may not have built correctly"
    fi

    # Install Playwright browsers
    print_info "Installing Playwright browsers for DomainHunterPro..."
    npx playwright install chromium --with-deps 2>/dev/null || npx playwright install chromium

    # Install Puppeteer browsers (used by puppeteer-extra for stealth scraping)
    print_info "Installing Puppeteer browsers for DomainHunterPro..."
    npx puppeteer browsers install chrome 2>/dev/null || true

    # Build the application for production (removes "Preview mode" banner)
    print_info "Building DomainHunterPro for production..."

    # Ensure we're in the right directory
    cd "$DOMAINHUNTER_DIR"

    # Run the build with verbose output
    if pnpm run build; then
        if [[ -d "$DOMAINHUNTER_DIR/dist" ]]; then
            print_good "DomainHunterPro built successfully (production mode enabled)"
        else
            print_warning "Build completed but dist folder not found - will run in dev mode"
        fi
    else
        print_warning "Failed to build DomainHunterPro - will run in dev mode"
        print_info "You can manually build later with: cd $DOMAINHUNTER_DIR && pnpm run build"
    fi

    cd "$SCRIPT_DIR"

    print_good "DomainHunterPro environment configured"
}

build_binaries() {
    print_info "Building all binaries..."
    echo ""

    # Build Evilginx2
    echo -e "${YELLOW}[1/4]${NC} Building Evilginx2..."
    cd "$SCRIPT_DIR"
    if go build -o evilginx2 . 2>&1; then
        print_good "evilginx2 built successfully"
    else
        print_error "Failed to build evilginx2"
        exit 1
    fi

    # Build EvilFeed (with CGO for SQLite3)
    echo -e "${YELLOW}[2/4]${NC} Building EvilFeed (with CGO for SQLite3)..."

    # Auto-install CGO dependencies if missing (required for SQLite3)
    if ! command -v gcc &> /dev/null; then
        print_info "Installing GCC (required for EvilFeed SQLite3)..."
        apt update && apt install -y build-essential gcc libsqlite3-dev
    fi

    cd "$SCRIPT_DIR/evilfeed"
    if CGO_ENABLED=1 go build -o evilfeed . 2>&1; then
        print_good "evilfeed built successfully"
    else
        print_error "Failed to build evilfeed"
        exit 1
    fi
    cd "$SCRIPT_DIR"

    # Build GoPhish (with CGO for SQLite3) - REQUIRED
    echo -e "${YELLOW}[3/4]${NC} Building GoPhish (with CGO for SQLite3)..."

    # Auto-install CGO dependencies if missing
    if ! command -v gcc &> /dev/null; then
        print_info "Installing GCC (required for GoPhish)..."
        apt update && apt install -y build-essential gcc libsqlite3-dev
    fi

    # Build GoPhish
    cd "$SCRIPT_DIR/gophish"
    if CGO_ENABLED=1 go build -o gophish . 2>&1; then
        print_good "gophish built successfully"
    else
        print_error "Failed to build gophish"
        print_info "Please check the error above and ensure all CGO dependencies are installed"
        exit 1
    fi
    cd "$SCRIPT_DIR"

    # Generate GoPhish SSL certificates
    # Always regenerate GoPhish SSL certificates to ensure they match
    # (prevents "private key type does not match public key type" errors)
    print_info "Generating GoPhish SSL certificates..."
    rm -f "$SCRIPT_DIR/gophish/gophish_admin.crt" "$SCRIPT_DIR/gophish/gophish_admin.key" 2>/dev/null
    rm -f "$SCRIPT_DIR/gophish/gophish_template.crt" "$SCRIPT_DIR/gophish/gophish_template.key" 2>/dev/null
    
    # Generate admin certificates
    openssl req -x509 -newkey rsa:2048 \
        -keyout "$SCRIPT_DIR/gophish/gophish_admin.key" \
        -out "$SCRIPT_DIR/gophish/gophish_admin.crt" \
        -days 365 -nodes -subj "/CN=gophish" 2>/dev/null
    
    # Generate template certificates (for phishing server TLS if needed)
    openssl req -x509 -newkey rsa:2048 \
        -keyout "$SCRIPT_DIR/gophish/gophish_template.key" \
        -out "$SCRIPT_DIR/gophish/gophish_template.crt" \
        -days 365 -nodes -subj "/CN=gophish" 2>/dev/null
    
    print_good "GoPhish SSL certificates generated (admin + template)"

    # Build GMaps Scraper
    echo -e "${YELLOW}[4/4]${NC} Building GMaps Scraper..."
    if [[ -d "$SCRIPT_DIR/gmapscraper" ]]; then
        cd "$SCRIPT_DIR/gmapscraper"
        go mod tidy 2>/dev/null || true
        if go build -o gmapscraper . 2>&1; then
            print_good "gmapscraper built successfully"
        else
            print_warning "Failed to build gmapscraper - will be built on first run"
        fi
        cd "$SCRIPT_DIR"
    else
        print_warning "gmapscraper directory not found, skipping..."
    fi
}

show_status() {
    echo ""
    echo -e "${BLUE}════════════════════════════════════════════════════════════════${NC}"
    echo -e "${CYAN}System Status${NC}"
    echo -e "${BLUE}════════════════════════════════════════════════════════════════${NC}"
    echo ""

    # Check Go
    if command -v go &> /dev/null; then
        print_good "Go: $(go version | awk '{print $3}')"
    else
        print_error "Go: Not installed"
    fi

    # Check tmux
    if command -v tmux &> /dev/null; then
        print_good "tmux: Installed"
    else
        print_error "tmux: Not installed"
    fi

    # Check Chrome (for GoogleBypasser + KasadaBypasser)
    if command -v google-chrome &> /dev/null || command -v google-chrome-stable &> /dev/null; then
        print_good "Chrome: Installed (GoogleBypasser + KasadaBypasser ready)"
    else
        print_warning "Chrome: Not installed (GoogleBypasser + KasadaBypasser will fail)"
    fi

    # Check binaries
    [[ -f "$SCRIPT_DIR/evilginx2" ]] && print_good "evilginx2: Built" || print_error "evilginx2: Not built"
    [[ -f "$SCRIPT_DIR/evilfeed/evilfeed" ]] && print_good "evilfeed: Built" || print_error "evilfeed: Not built"
    [[ -f "$SCRIPT_DIR/gophish/gophish" ]] && print_good "gophish: Built" || print_error "gophish: Not built"
    [[ -f "$SCRIPT_DIR/gmapscraper/gmapscraper" ]] && print_good "gmapscraper: Built" || print_warning "gmapscraper: Not built"
    [[ -d "$SCRIPT_DIR/phishcreator/venv" ]] && print_good "phishcreator: Configured" || print_warning "phishcreator: Not configured"
    [[ -d "$SCRIPT_DIR/domainhunterpro/node_modules" ]] && print_good "domainhunterpro: Configured" || print_warning "domainhunterpro: Not configured"

    # Check DNS
    if ! systemctl is-active --quiet systemd-resolved; then
        print_good "systemd-resolved: Disabled"
    else
        print_warning "systemd-resolved: Still running"
    fi

    # Check ports
    echo ""
    print_info "Port status:"
    for port in 80 443; do
        if ss -tlnp 2>/dev/null | grep -q ":${port} "; then
            echo -e "  ${YELLOW}[!]${NC} Port $port: In use"
        else
            echo -e "  ${GREEN}[+]${NC} Port $port: Available"
        fi
    done
}

show_complete() {
    echo ""
    echo -e "${CYAN}╔══════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║              SETUP COMPLETE!                                 ║${NC}"
    echo -e "${CYAN}╚══════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo -e "${GREEN}ProfGinx V8 is now ready to use!${NC}"
    echo ""
    echo -e "${YELLOW}To start all services:${NC}"
    echo "  sudo ./start.sh all"
    echo ""
    echo -e "${YELLOW}Or start individually:${NC}"
    echo "  sudo ./start.sh run        # Evilginx2 only"
    echo "  ./start.sh evilfeed        # EvilFeed dashboard"
    echo "  ./start.sh gophish         # GoPhish"
    echo ""
    echo -e "${YELLOW}Service URLs:${NC}"
    echo "  Evilginx Webpanel:  http://<server_ip>:9091"
    echo "  EvilFeed Dashboard: http://<server_ip>:1337"
    echo "  GoPhish Admin:      https://<server_ip>:3333"
    echo "  PhishCreator:       http://<server_ip>:5050"
    echo "  GMaps Scraper:      http://<server_ip>:8080"
    echo ""
    echo -e "${YELLOW}Default Credentials:${NC}"
    echo "  Evilginx Webpanel: admin / admin123"
    echo "  EvilFeed/GoPhish:  admin / (auto-generated on first run)"
    echo ""
}

# ============================================
# MAIN SETUP FUNCTION
# ============================================

run_full_setup() {
    local rid="$1"

    echo -e "${GREEN}Starting complete ProfGinx V8 setup...${NC}"
    echo ""

    # Step 1: Install dependencies
    echo -e "${BLUE}════════════════════════════════════════════════════════════════${NC}"
    echo -e "${CYAN}Step 1/13: Installing Dependencies${NC}"
    echo -e "${BLUE}════════════════════════════════════════════════════════════════${NC}"
    echo ""
    install_dependencies
    echo ""

    # Step 2: Configure swap (if RAM < 8GB)
    echo -e "${BLUE}════════════════════════════════════════════════════════════════${NC}"
    echo -e "${CYAN}Step 2/13: Configuring Swap (if needed)${NC}"
    echo -e "${BLUE}════════════════════════════════════════════════════════════════${NC}"
    echo ""
    configure_swap
    echo ""

    # Step 3: Install Chrome (for GoogleBypasser + KasadaBypasser)
    echo -e "${BLUE}════════════════════════════════════════════════════════════════${NC}"
    echo -e "${CYAN}Step 3/13: Installing Chrome (GoogleBypasser + KasadaBypasser)${NC}"
    echo -e "${BLUE}════════════════════════════════════════════════════════════════${NC}"
    echo ""
    install_chrome
    echo ""

    # Step 4: Configure DNS
    echo -e "${BLUE}════════════════════════════════════════════════════════════════${NC}"
    echo -e "${CYAN}Step 4/13: Configuring DNS${NC}"
    echo -e "${BLUE}════════════════════════════════════════════════════════════════${NC}"
    echo ""
    configure_dns
    echo ""

    # Step 5: Install Go
    echo -e "${BLUE}════════════════════════════════════════════════════════════════${NC}"
    echo -e "${CYAN}Step 5/13: Installing Go${NC}"
    echo -e "${BLUE}════════════════════════════════════════════════════════════════${NC}"
    echo ""
    install_go
    echo ""

    # Step 6: Clear ports
    echo -e "${BLUE}════════════════════════════════════════════════════════════════${NC}"
    echo -e "${CYAN}Step 6/13: Clearing Ports${NC}"
    echo -e "${BLUE}════════════════════════════════════════════════════════════════${NC}"
    echo ""
    clear_ports
    echo ""

    # Step 7: Configure firewall
    echo -e "${BLUE}════════════════════════════════════════════════════════════════${NC}"
    echo -e "${CYAN}Step 7/13: Configuring Firewall${NC}"
    echo -e "${BLUE}════════════════════════════════════════════════════════════════${NC}"
    echo ""
    configure_firewall
    echo ""

    # Step 8: Download GeoIP Database
    echo -e "${BLUE}════════════════════════════════════════════════════════════════${NC}"
    echo -e "${CYAN}Step 8/13: Downloading GeoIP Database${NC}"
    echo -e "${BLUE}════════════════════════════════════════════════════════════════${NC}"
    echo ""
    download_geoip
    echo ""

    # Step 9: Replace RID
    echo -e "${BLUE}════════════════════════════════════════════════════════════════${NC}"
    echo -e "${CYAN}Step 9/13: Configuring RID${NC}"
    echo -e "${BLUE}════════════════════════════════════════════════════════════════${NC}"
    echo ""
    replace_rid "$rid"
    echo ""

    # Step 10: Build binaries
    echo -e "${BLUE}════════════════════════════════════════════════════════════════${NC}"
    echo -e "${CYAN}Step 10/13: Building Binaries${NC}"
    echo -e "${BLUE}════════════════════════════════════════════════════════════════${NC}"
    echo ""
    build_binaries
    echo ""

    # Step 11: Setup PhishCreator
    echo -e "${BLUE}════════════════════════════════════════════════════════════════${NC}"
    echo -e "${CYAN}Step 11/13: Setting up PhishCreator${NC}"
    echo -e "${BLUE}════════════════════════════════════════════════════════════════${NC}"
    echo ""
    setup_phishcreator
    echo ""

    # Step 12: Setup GMaps Scraper
    echo -e "${BLUE}════════════════════════════════════════════════════════════════${NC}"
    echo -e "${CYAN}Step 12/13: Setting up GMaps Scraper${NC}"
    echo -e "${BLUE}════════════════════════════════════════════════════════════════${NC}"
    echo ""
    setup_gmapscraper
    echo ""

    # Step 13: Setup DomainHunterPro
    echo -e "${BLUE}════════════════════════════════════════════════════════════════${NC}"
    echo -e "${CYAN}Step 13/13: Setting up DomainHunterPro${NC}"
    echo -e "${BLUE}════════════════════════════════════════════════════════════════${NC}"
    echo ""
    setup_domainhunter
    echo ""

    # Show status
    show_status

    # Show completion message
    show_complete
}

# ============================================
# MAIN ENTRY POINT
# ============================================

# Parse arguments
RID_VALUE=""
COMMAND=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        --rid)
            if [[ -n "$2" ]]; then
                RID_VALUE="$2"
                shift 2
            else
                print_error "--rid requires a value"
                exit 1
            fi
            ;;
        full)
            COMMAND="full"
            shift
            ;;
        help|--help|-h)
            show_usage
            exit 0
            ;;
        *)
            shift
            ;;
    esac
done

# Handle command
case "$COMMAND" in
    full)
        check_root
        run_full_setup "$RID_VALUE"
        ;;
    *)
        show_usage
        ;;
esac
