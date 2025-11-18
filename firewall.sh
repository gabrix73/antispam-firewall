#!/bin/bash

# Anti-SPAM iptables script with Spamhaus integration
# Protects SMTP servers from spam and attacks
# Author: Gabrix73
# Date: 2025-11-18

set -e

# Configuration
SMTP_PORT=25
SUBMISSION_PORT=587
SMTPS_PORT=465

# Rate limiting settings
CONN_LIMIT=10          # Max connections per IP per minute
CONN_BURST=5           # Burst allowance
MAIL_LIMIT=30          # Max emails per IP per hour

# Spamhaus lists
SPAMHAUS_DROP="https://www.spamhaus.org/drop/drop.txt"
SPAMHAUS_EDROP="https://www.spamhaus.org/drop/edrop.txt"

# Directories
BLACKLIST_DIR="/var/lib/spamhaus"
BLACKLIST_FILE="$BLACKLIST_DIR/spamhaus_drop.txt"
IPSET_NAME="spamhaus_drop"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Log file
LOGFILE="/var/log/anti-spam-iptables.log"

log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a "$LOGFILE"
}

error() {
    echo -e "${RED}[ERROR]${NC} $1" | tee -a "$LOGFILE"
    exit 1
}

success() {
    echo -e "${GREEN}[OK]${NC} $1" | tee -a "$LOGFILE"
}

warn() {
    echo -e "${YELLOW}[WARNING]${NC} $1" | tee -a "$LOGFILE"
}

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    error "This script must be run as root"
fi

# Check dependencies
check_dependencies() {
    log "Checking dependencies..."
    
    local deps=("iptables" "ipset" "curl" "wget")
    for dep in "${deps[@]}"; do
        if ! command -v "$dep" &> /dev/null; then
            error "$dep is not installed. Install it with: apt-get install $dep"
        fi
    done
    
    success "All dependencies are installed"
}

# Create necessary directories
setup_directories() {
    mkdir -p "$BLACKLIST_DIR"
    touch "$LOGFILE"
    chmod 640 "$LOGFILE"
}

# Download and update Spamhaus lists
update_spamhaus() {
    log "Updating Spamhaus DROP lists..."
    
    local temp_file=$(mktemp)
    
    # Download DROP list
    if wget -q -O "$temp_file" "$SPAMHAUS_DROP"; then
        grep -E '^[0-9]' "$temp_file" | awk '{print $1}' > "$BLACKLIST_FILE.tmp"
        success "Downloaded Spamhaus DROP list"
    else
        warn "Failed to download DROP list"
    fi
    
    # Download EDROP list
    if wget -q -O "$temp_file" "$SPAMHAUS_EDROP"; then
        grep -E '^[0-9]' "$temp_file" | awk '{print $1}' >> "$BLACKLIST_FILE.tmp"
        success "Downloaded Spamhaus EDROP list"
    else
        warn "Failed to download EDROP list"
    fi
    
    if [ -f "$BLACKLIST_FILE.tmp" ]; then
        mv "$BLACKLIST_FILE.tmp" "$BLACKLIST_FILE"
        local count=$(wc -l < "$BLACKLIST_FILE")
        success "Updated Spamhaus lists: $count networks"
    else
        error "Failed to create blacklist file"
    fi
    
    rm -f "$temp_file"
}

# Create and populate ipset
setup_ipset() {
    log "Setting up ipset for Spamhaus..."
    
    # Remove old ipset if exists
    ipset destroy "$IPSET_NAME" 2>/dev/null || true
    
    # Create new ipset
    ipset create "$IPSET_NAME" hash:net maxelem 100000
    
    # Load blacklist into ipset
    local count=0
    while IFS= read -r network; do
        if [[ "$network" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/[0-9]+ ]]; then
            ipset add "$IPSET_NAME" "$network" 2>/dev/null || true
            ((count++))
        fi
    done < "$BLACKLIST_FILE"
    
    success "Loaded $count networks into ipset"
}

# Setup iptables rules
setup_iptables() {
    log "Setting up iptables rules..."
    
    # Create custom chains
    iptables -N SMTP_FILTER 2>/dev/null || iptables -F SMTP_FILTER
    iptables -N RATE_LIMIT 2>/dev/null || iptables -F RATE_LIMIT
    
    # Block Spamhaus DROP list
    iptables -A INPUT -m set --match-set "$IPSET_NAME" src -j DROP
    success "Blocked Spamhaus DROP list IPs"
    
    # Direct SMTP traffic to custom chain
    iptables -A INPUT -p tcp --dport "$SMTP_PORT" -j SMTP_FILTER
    iptables -A INPUT -p tcp --dport "$SUBMISSION_PORT" -j SMTP_FILTER
    iptables -A INPUT -p tcp --dport "$SMTPS_PORT" -j SMTP_FILTER
    
    # Rate limiting - connection attempts
    iptables -A SMTP_FILTER -m recent --name smtp_conn --set
    iptables -A SMTP_FILTER -m recent --name smtp_conn --update --seconds 60 --hitcount "$CONN_LIMIT" -j LOG --log-prefix "SMTP_RATE_LIMIT: " --log-level 4
    iptables -A SMTP_FILTER -m recent --name smtp_conn --update --seconds 60 --hitcount "$CONN_LIMIT" -j DROP
    success "Configured connection rate limiting: $CONN_LIMIT conn/min"
    
    # Connection limit per IP
    iptables -A SMTP_FILTER -m connlimit --connlimit-above 5 --connlimit-mask 32 -j LOG --log-prefix "SMTP_CONN_LIMIT: " --log-level 4
    iptables -A SMTP_FILTER -m connlimit --connlimit-above 5 --connlimit-mask 32 -j REJECT --reject-with tcp-reset
    success "Configured concurrent connection limit: 5 per IP"
    
    # Block known bad patterns
    # SYN flood protection
    iptables -A SMTP_FILTER -p tcp --syn -m limit --limit 1/s --limit-burst 3 -j ACCEPT
    iptables -A SMTP_FILTER -p tcp --syn -j DROP
    
    # Invalid packets
    iptables -A SMTP_FILTER -m state --state INVALID -j DROP
    
    # Accept established connections
    iptables -A SMTP_FILTER -m state --state ESTABLISHED,RELATED -j ACCEPT
    
    # Accept new connections (after all filters)
    iptables -A SMTP_FILTER -m state --state NEW -j ACCEPT
    
    success "SMTP filtering rules applied"
}

# Advanced protection rules
setup_advanced_protection() {
    log "Setting up advanced protection..."
    
    # Create chain for mail-specific protection
    iptables -N MAIL_PROTECT 2>/dev/null || iptables -F MAIL_PROTECT
    
    # Protect against slowloris attacks
    iptables -A MAIL_PROTECT -p tcp --dport "$SMTP_PORT" -m conntrack --ctstate NEW -m recent --set --name smtp_slow
    iptables -A MAIL_PROTECT -p tcp --dport "$SMTP_PORT" -m conntrack --ctstate NEW -m recent --update --seconds 60 --hitcount 4 --name smtp_slow -j LOG --log-prefix "SMTP_SLOWLORIS: "
    iptables -A MAIL_PROTECT -p tcp --dport "$SMTP_PORT" -m conntrack --ctstate NEW -m recent --update --seconds 60 --hitcount 4 --name smtp_slow -j DROP
    
    # Block common spam source countries (optional - customize as needed)
    # Uncomment and customize based on your needs
    # iptables -A INPUT -p tcp --dport "$SMTP_PORT" -m geoip --src-cc CN,RU,BR -j DROP
    
    success "Advanced protection enabled"
}

# Setup logging
setup_logging() {
    log "Configuring logging..."
    
    # Log dropped packets
    iptables -N LOG_DROP 2>/dev/null || iptables -F LOG_DROP
    iptables -A LOG_DROP -m limit --limit 5/min -j LOG --log-prefix "SMTP_DROPPED: " --log-level 4
    iptables -A LOG_DROP -j DROP
    
    success "Logging configured"
}

# Save iptables rules
save_rules() {
    log "Saving iptables rules..."
    
    if command -v iptables-save &> /dev/null; then
        iptables-save > /etc/iptables/rules.v4 2>/dev/null || \
        iptables-save > /etc/iptables.rules 2>/dev/null || \
        warn "Could not save iptables rules permanently"
        
        success "iptables rules saved"
    fi
}

# Show statistics
show_stats() {
    echo ""
    echo "==================================="
    echo "Anti-SPAM Statistics"
    echo "==================================="
    echo ""
    
    echo "Spamhaus DROP IPs blocked:"
    ipset list "$IPSET_NAME" | grep "Number of entries" || echo "0"
    echo ""
    
    echo "Recent SMTP connections:"
    iptables -L SMTP_FILTER -v -n 2>/dev/null | head -20 || echo "No data"
    echo ""
    
    echo "Rate limited IPs (last hour):"
    grep "SMTP_RATE_LIMIT" /var/log/syslog 2>/dev/null | tail -10 || echo "None"
    echo ""
}

# Cleanup function
cleanup() {
    log "Cleaning up old rules..."
    
    # Flush chains
    iptables -F SMTP_FILTER 2>/dev/null || true
    iptables -F RATE_LIMIT 2>/dev/null || true
    iptables -F MAIL_PROTECT 2>/dev/null || true
    iptables -F LOG_DROP 2>/dev/null || true
    
    success "Cleanup completed"
}

# Uninstall function
uninstall() {
    log "Uninstalling anti-spam rules..."
    
    # Remove ipset
    ipset destroy "$IPSET_NAME" 2>/dev/null || true
    
    # Remove chains
    iptables -D INPUT -m set --match-set "$IPSET_NAME" src -j DROP 2>/dev/null || true
    iptables -D INPUT -p tcp --dport "$SMTP_PORT" -j SMTP_FILTER 2>/dev/null || true
    iptables -D INPUT -p tcp --dport "$SUBMISSION_PORT" -j SMTP_FILTER 2>/dev/null || true
    iptables -D INPUT -p tcp --dport "$SMTPS_PORT" -j SMTP_FILTER 2>/dev/null || true
    
    cleanup
    
    # Delete chains
    iptables -X SMTP_FILTER 2>/dev/null || true
    iptables -X RATE_LIMIT 2>/dev/null || true
    iptables -X MAIL_PROTECT 2>/dev/null || true
    iptables -X LOG_DROP 2>/dev/null || true
    
    success "Anti-spam rules removed"
}

# Main execution
main() {
    case "${1:-install}" in
        install)
            log "Starting anti-spam installation..."
            check_dependencies
            setup_directories
            update_spamhaus
            setup_ipset
            cleanup
            setup_iptables
            setup_advanced_protection
            setup_logging
            save_rules
            success "Anti-spam protection installed successfully"
            show_stats
            ;;
        update)
            log "Updating Spamhaus lists..."
            update_spamhaus
            setup_ipset
            success "Spamhaus lists updated"
            ;;
        stats)
            show_stats
            ;;
        uninstall)
            uninstall
            ;;
        *)
            echo "Usage: $0 {install|update|stats|uninstall}"
            echo ""
            echo "  install    - Install anti-spam protection"
            echo "  update     - Update Spamhaus blacklists"
            echo "  stats      - Show statistics"
            echo "  uninstall  - Remove all anti-spam rules"
            exit 1
            ;;
    esac
}

# Run main function
main "$@"
