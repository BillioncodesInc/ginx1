#!/bin/bash

# ProfGinx V8 Complete Cleanup Script
# Stops all services, kills tmux sessions, and removes data

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

# tmux session name (must match start.sh)
TMUX_SESSION="profginx"

clear

echo -e "${CYAN}╔══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${CYAN}║              PROFGINX V8 CLEANUP SCRIPT                      ║${NC}"
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

# ============================================
# STOP SERVICES ONLY (no data removal)
# ============================================

stop_services_only() {
    echo -e "${BLUE}Stopping all ProfGinx V4 services...${NC}"
    echo ""

    # Kill tmux session
    echo -e "${YELLOW}[1/2]${NC} Stopping tmux sessions..."
    if tmux has-session -t "$TMUX_SESSION" 2>/dev/null; then
        tmux kill-session -t "$TMUX_SESSION" 2>/dev/null
        print_good "tmux session '${TMUX_SESSION}' killed"
    else
        print_info "No tmux session '${TMUX_SESSION}' found"
    fi

    # Also kill any other profginx-related tmux sessions
    tmux list-sessions 2>/dev/null | grep -i "profginx\|evilginx\|gophish\|evilfeed" | cut -d: -f1 | while read -r session; do
        tmux kill-session -t "$session" 2>/dev/null
        print_good "tmux session '$session' killed"
    done

    # Kill processes
    echo ""
    echo -e "${YELLOW}[2/2]${NC} Stopping processes..."

    local killed=false

    if pgrep -f "evilginx2" > /dev/null 2>&1; then
        pkill -9 -f "evilginx2" 2>/dev/null
        print_good "evilginx2 stopped"
        killed=true
    fi

    if pgrep -f "evilfeed" > /dev/null 2>&1; then
        pkill -9 -f "evilfeed" 2>/dev/null
        print_good "evilfeed stopped"
        killed=true
    fi

    if pgrep -f "gophish" > /dev/null 2>&1; then
        pkill -9 -f "gophish" 2>/dev/null
        print_good "gophish stopped"
        killed=true
    fi

    if pgrep -f "gmapscraper" > /dev/null 2>&1; then
        pkill -9 -f "gmapscraper" 2>/dev/null
        print_good "gmapscraper stopped"
        killed=true
    fi

    if pgrep -f "phishcreator" > /dev/null 2>&1; then
        pkill -9 -f "phishcreator" 2>/dev/null
        print_good "phishcreator stopped"
        killed=true
    fi

    if pgrep -f "domainhunterpro" > /dev/null 2>&1 || pgrep -f "node.*domainhunterpro" > /dev/null 2>&1; then
        pkill -9 -f "domainhunterpro" 2>/dev/null
        pkill -9 -f "node.*domainhunterpro" 2>/dev/null
        print_good "domainhunter stopped"
        killed=true
    fi

    if [[ "$killed" == "false" ]]; then
        print_info "No running processes found"
    fi

    sleep 1
    echo ""
    echo -e "${GREEN}✅ All services stopped${NC}"
    echo ""
}

# ============================================
# FULL CLEANUP (services + data)
# ============================================

full_cleanup() {
    echo -e "${RED}⚠️  WARNING: This will DELETE ALL ProfGinx V8 data!${NC}"
    echo ""
    echo -e "${YELLOW}This includes:${NC}"
    echo "  - Running services and tmux sessions"
    echo "  - Configuration files (config.json, blacklist.txt)"
    echo "  - Databases (sessions, credentials, campaigns)"
    echo "  - SSL certificates"
    echo "  - Logs"
    echo "  - Phishlet data"
    echo "  - GoPhish data"
    echo "  - GMaps Scraper data (jobs database)"
    echo "  - PhishCreator data"
    echo "  - DomainHunterPro data (databases, dist)"
    echo ""
    read -p "Are you sure you want to continue? (type 'yes' to confirm): " confirm

    if [[ "$confirm" != "yes" ]]; then
        echo -e "${YELLOW}Cleanup cancelled.${NC}"
        exit 0
    fi

    echo ""
    echo -e "${BLUE}Starting full cleanup...${NC}"
    echo ""

    # Check if running as root
    if [[ "$EUID" -ne 0 ]]; then
        print_warning "Not running as root. Some files may require sudo."
        echo "   Run with: sudo ./cleanup.sh full"
        echo ""
    fi

    # Step 1: Stop services and tmux
    echo -e "${BLUE}[1/8]${NC} Stopping all services and tmux sessions..."

    # Kill tmux session
    if tmux has-session -t "$TMUX_SESSION" 2>/dev/null; then
        tmux kill-session -t "$TMUX_SESSION" 2>/dev/null
        print_good "tmux session '${TMUX_SESSION}' killed"
    fi

    # Kill any related tmux sessions
    tmux list-sessions 2>/dev/null | grep -i "profginx\|evilginx\|gophish\|evilfeed" | cut -d: -f1 | while read -r session; do
        tmux kill-session -t "$session" 2>/dev/null
        print_good "tmux session '$session' killed"
    done

    # Kill processes
    pkill -9 -f "evilginx2" 2>/dev/null && print_good "evilginx2 stopped"
    pkill -9 -f "gophish" 2>/dev/null && print_good "gophish stopped"
    pkill -9 -f "evilfeed" 2>/dev/null && print_good "evilfeed stopped"
    pkill -9 -f "gmapscraper" 2>/dev/null && print_good "gmapscraper stopped"
    pkill -9 -f "phishcreator" 2>/dev/null && print_good "phishcreator stopped"
    pkill -9 -f "domainhunterpro" 2>/dev/null && print_good "domainhunter stopped"
    pkill -9 -f "node.*domainhunterpro" 2>/dev/null
    sleep 2
    print_good "Services stopped"
    echo ""

    # Step 2: Remove local .evilginx directory
    echo -e "${BLUE}[2/8]${NC} Removing Evilginx2 local data directory..."
    EVILGINX_LOCAL="$SCRIPT_DIR/.evilginx"
    if [[ -d "$EVILGINX_LOCAL" ]]; then
        rm -rf "$EVILGINX_LOCAL"
        print_good "Removed: $EVILGINX_LOCAL"
    else
        print_info "Not found: $EVILGINX_LOCAL"
    fi

    # Also check home directories
    EVILGINX_HOME="$HOME/.evilginx"
    if [[ -d "$EVILGINX_HOME" ]]; then
        rm -rf "$EVILGINX_HOME"
        print_good "Removed: $EVILGINX_HOME"
    fi

    # Check /root/.evilginx
    if [[ "$EUID" -ne 0 ]] && [[ -d "/root/.evilginx" ]]; then
        sudo rm -rf "/root/.evilginx" 2>/dev/null && print_good "Removed: /root/.evilginx" || print_warning "Could not remove /root/.evilginx (permission denied)"
    elif [[ "$EUID" -eq 0 ]] && [[ -d "/root/.evilginx" ]]; then
        rm -rf "/root/.evilginx"
        print_good "Removed: /root/.evilginx"
    fi
    echo ""

    # Step 3: Clean config directory
    echo -e "${BLUE}[3/8]${NC} Cleaning config directory..."
    CONFIG_DIR="$SCRIPT_DIR/config"
    if [[ -d "$CONFIG_DIR" ]]; then
        # Remove certificates
        if [[ -d "$CONFIG_DIR/crt" ]]; then
            rm -rf "$CONFIG_DIR/crt"/*
            print_good "Cleared: config/crt/"
        fi
        # Remove config.json
        if [[ -f "$CONFIG_DIR/config.json" ]]; then
            rm -f "$CONFIG_DIR/config.json"
            print_good "Removed: config/config.json"
        fi
        # Clear blacklist but keep file
        if [[ -f "$CONFIG_DIR/blacklist.txt" ]]; then
            > "$CONFIG_DIR/blacklist.txt"
            print_good "Cleared: config/blacklist.txt"
        fi
    else
        print_info "Not found: $CONFIG_DIR"
    fi
    echo ""

    # Step 4: Clean data directory
    echo -e "${BLUE}[4/8]${NC} Cleaning data directory..."
    DATA_DIR="$SCRIPT_DIR/data"
    if [[ -d "$DATA_DIR" ]]; then
        # Clear credentials
        if [[ -d "$DATA_DIR/credentials" ]]; then
            rm -rf "$DATA_DIR/credentials"/*
            print_good "Cleared: data/credentials/"
        fi
        # Clear sessions
        if [[ -d "$DATA_DIR/sessions" ]]; then
            rm -rf "$DATA_DIR/sessions"/*
            print_good "Cleared: data/sessions/"
        fi
        # Clear reports
        if [[ -d "$DATA_DIR/reports" ]]; then
            rm -rf "$DATA_DIR/reports"/*
            print_good "Cleared: data/reports/"
        fi
    else
        print_info "Not found: $DATA_DIR"
    fi
    echo ""

    # Step 5: Clean GoPhish data
    echo -e "${BLUE}[5/8]${NC} Cleaning GoPhish data..."
    GOPHISH_DIR="$SCRIPT_DIR/gophish"
    if [[ -d "$GOPHISH_DIR" ]]; then
        # Remove database
        if [[ -f "$GOPHISH_DIR/gophish.db" ]]; then
            rm -f "$GOPHISH_DIR/gophish.db"
            print_good "Removed: gophish/gophish.db"
        fi
        # Remove config
        if [[ -f "$GOPHISH_DIR/config.json" ]]; then
            rm -f "$GOPHISH_DIR/config.json"
            print_good "Removed: gophish/config.json"
        fi
    else
        print_info "Not found: $GOPHISH_DIR"
    fi
    echo ""

    # Step 6: Clean EvilFeed data
    echo -e "${BLUE}[6/10]${NC} Cleaning EvilFeed data..."
    EVILFEED_DIR="$SCRIPT_DIR/evilfeed"
    if [[ -d "$EVILFEED_DIR" ]]; then
        # Remove any database files
        rm -f "$EVILFEED_DIR"/*.db 2>/dev/null && print_good "Cleared: evilfeed databases"
        rm -f "$EVILFEED_DIR"/*.sqlite 2>/dev/null
    fi

    # Also check home directory for evilfeed data
    if [[ -d "$HOME/.evilfeed" ]]; then
        rm -rf "$HOME/.evilfeed"
        print_good "Removed: ~/.evilfeed"
    fi
    if [[ -d "$HOME/.evilgophish" ]]; then
        rm -rf "$HOME/.evilgophish"
        print_good "Removed: ~/.evilgophish"
    fi
    echo ""

    # Step 7: Clean GMaps Scraper data
    echo -e "${BLUE}[7/10]${NC} Cleaning GMaps Scraper data..."
    GMAPSCRAPER_DIR="$SCRIPT_DIR/gmapscraper"
    if [[ -d "$GMAPSCRAPER_DIR" ]]; then
        # Remove webdata folder (jobs database, results)
        if [[ -d "$GMAPSCRAPER_DIR/webdata" ]]; then
            rm -rf "$GMAPSCRAPER_DIR/webdata"
            print_good "Removed: gmapscraper/webdata/"
        fi
        # Remove any database files
        rm -f "$GMAPSCRAPER_DIR"/*.db 2>/dev/null && print_good "Cleared: gmapscraper databases"
        rm -f "$GMAPSCRAPER_DIR"/*.db-shm 2>/dev/null
        rm -f "$GMAPSCRAPER_DIR"/*.db-wal 2>/dev/null
        # Remove results CSVs
        rm -f "$GMAPSCRAPER_DIR"/*.csv 2>/dev/null && print_good "Cleared: gmapscraper CSV results"
    else
        print_info "Not found: $GMAPSCRAPER_DIR"
    fi
    echo ""

    # Step 8: Clean PhishCreator data
    echo -e "${BLUE}[8/11]${NC} Cleaning PhishCreator data..."
    PHISHCREATOR_DIR="$SCRIPT_DIR/phishcreator"
    if [[ -d "$PHISHCREATOR_DIR" ]]; then
        # Remove uploads folder
        if [[ -d "$PHISHCREATOR_DIR/uploads" ]]; then
            rm -rf "$PHISHCREATOR_DIR/uploads"/*
            print_good "Cleared: phishcreator/uploads/"
        fi
        # Remove any temp files
        rm -f "$PHISHCREATOR_DIR"/*.tmp 2>/dev/null
    else
        print_info "Not found: $PHISHCREATOR_DIR"
    fi
    echo ""

    # Step 9: Clean DomainHunterPro data
    echo -e "${BLUE}[9/11]${NC} Cleaning DomainHunterPro data..."
    DOMAINHUNTER_DIR="$SCRIPT_DIR/domainhunterpro"
    if [[ -d "$DOMAINHUNTER_DIR" ]]; then
        # Remove database files
        rm -f "$DOMAINHUNTER_DIR"/*.db 2>/dev/null && print_good "Cleared: domainhunterpro databases"
        rm -f "$DOMAINHUNTER_DIR"/*.sqlite 2>/dev/null
        rm -f "$DOMAINHUNTER_DIR"/*.sqlite3 2>/dev/null
        # Remove data directory if exists
        if [[ -d "$DOMAINHUNTER_DIR/data" ]]; then
            rm -rf "$DOMAINHUNTER_DIR/data"/*
            print_good "Cleared: domainhunterpro/data/"
        fi
        # Remove dist directory (build output)
        if [[ -d "$DOMAINHUNTER_DIR/dist" ]]; then
            rm -rf "$DOMAINHUNTER_DIR/dist"
            print_good "Removed: domainhunterpro/dist/"
        fi
        # Remove node_modules (optional - takes long time to reinstall)
        # Uncomment if you want to do full cleanup:
        # rm -rf "$DOMAINHUNTER_DIR/node_modules" && print_good "Removed: domainhunterpro/node_modules/"
    else
        print_info "Not found: $DOMAINHUNTER_DIR"
    fi
    echo ""

    # Step 10: Remove systemd services
    echo -e "${BLUE}[10/11]${NC} Removing systemd services..."
    SERVICES=("evilginx2" "gophish" "evilfeed" "profginx" "gmapscraper" "phishcreator" "domainhunter")
    FOUND_SERVICES=false
    for service in "${SERVICES[@]}"; do
        if systemctl list-unit-files 2>/dev/null | grep -q "$service.service"; then
            print_info "Found service: $service"
            sudo systemctl stop "$service" 2>/dev/null || true
            sudo systemctl disable "$service" 2>/dev/null || true
            sudo rm -f "/etc/systemd/system/$service.service"
            print_good "Removed: $service.service"
            FOUND_SERVICES=true
        fi
    done

    if [[ "$FOUND_SERVICES" == "true" ]]; then
        sudo systemctl daemon-reload 2>/dev/null || true
        print_good "Systemd reloaded"
    else
        print_info "No systemd services found"
    fi
    echo ""

    # Step 11: Clean logs
    echo -e "${BLUE}[11/11]${NC} Cleaning log files..."
    LOG_DIR="$SCRIPT_DIR/log"
    if [[ -d "$LOG_DIR" ]]; then
        rm -rf "$LOG_DIR"/*
        print_good "Cleared: log/"
    fi

    # Check additional log locations
    ADDITIONAL_LOGS=(
        "/var/log/evilginx2"
        "/var/log/gophish"
        "/var/log/evilfeed"
    )
    for log_dir in "${ADDITIONAL_LOGS[@]}"; do
        if [[ -d "$log_dir" ]]; then
            rm -rf "$log_dir" 2>/dev/null || sudo rm -rf "$log_dir" 2>/dev/null && print_good "Removed: $log_dir" || print_warning "Could not remove $log_dir"
        fi
    done
    echo ""

    # Summary
    echo -e "${CYAN}╔══════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║                    CLEANUP COMPLETE!                         ║${NC}"
    echo -e "${CYAN}╚══════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo -e "${GREEN}Cleaned:${NC}"
    echo "  ✅ tmux sessions (profginx)"
    echo "  ✅ Running processes (evilginx2, gophish, evilfeed, gmapscraper, phishcreator, domainhunter)"
    echo "  ✅ .evilginx/ (local config, certificates)"
    echo "  ✅ ~/.evilginx/ (home directory data)"
    echo "  ✅ config/ (config.json, blacklist.txt, crt/)"
    echo "  ✅ data/ (credentials, sessions, reports)"
    echo "  ✅ gophish/ (database, config)"
    echo "  ✅ evilfeed/ (database)"
    echo "  ✅ gmapscraper/ (webdata, jobs database, CSV results)"
    echo "  ✅ phishcreator/ (uploads, temp files)"
    echo "  ✅ domainhunterpro/ (databases, data, dist)"
    echo "  ✅ log/ (log files)"
    echo "  ✅ Systemd services (if any)"
    echo ""
    echo -e "${BLUE}════════════════════════════════════════════════════════════════${NC}"
    echo ""
    echo -e "${GREEN}Your system is now clean for fresh ProfGinx V8 setup!${NC}"
    echo ""
    echo -e "${CYAN}To restart:${NC}"
    echo "  1. ./setup.sh build           # Rebuild binaries"
    echo "  2. sudo ./start.sh all        # Start all services"
    echo ""
}

# ============================================
# USAGE
# ============================================

show_usage() {
    echo -e "${BLUE}Usage:${NC} ./cleanup.sh [command]"
    echo ""
    echo -e "${YELLOW}Commands:${NC}"
    echo "  stop      - Stop all services and tmux sessions (no data removal)"
    echo "  full      - Full cleanup (stop services + remove all data)"
    echo "  help      - Show this help message"
    echo ""
    echo -e "${YELLOW}Examples:${NC}"
    echo "  ./cleanup.sh stop             # Just stop services"
    echo "  sudo ./cleanup.sh full        # Full cleanup with data removal"
    echo ""
    echo -e "${YELLOW}Notes:${NC}"
    echo "  - 'stop' command does not require root"
    echo "  - 'full' command works best with root for complete cleanup"
    echo ""
}

# ============================================
# MAIN ENTRY POINT
# ============================================

case "${1:-help}" in
    stop)
        stop_services_only
        ;;
    full)
        full_cleanup
        ;;
    help|--help|-h)
        show_usage
        ;;
    *)
        # Default behavior: ask what to do
        echo -e "${YELLOW}What would you like to do?${NC}"
        echo ""
        echo "  1. Stop services only (no data removal)"
        echo "  2. Full cleanup (stop services + remove all data)"
        echo "  3. Cancel"
        echo ""
        read -p "Enter choice [1-3]: " choice

        case "$choice" in
            1)
                echo ""
                stop_services_only
                ;;
            2)
                echo ""
                full_cleanup
                ;;
            *)
                echo -e "${YELLOW}Cleanup cancelled.${NC}"
                exit 0
                ;;
        esac
        ;;
esac
