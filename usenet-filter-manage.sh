#!/bin/bash
#
# Usenet Advanced Filter Management Script
# Manages peer reputation, SURBL stats, and binary detection
# Version: 1.0
#

set -e

DB_PATH="/var/lib/usenet-filter/reputation.db"
LOG_DIR="/var/log/usenet-filter"
CACHE_DIR="/var/cache/usenet-filter"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# =============================================================================
# PEER REPUTATION FUNCTIONS
# =============================================================================

show_peer_stats() {
    echo -e "${BLUE}=== Peer Reputation Statistics ===${NC}"
    echo ""
    
    sqlite3 "$DB_PATH" <<EOF
.mode column
.headers on
SELECT 
    peer_name,
    total_articles as "Total",
    spam_articles as "Spam",
    ROUND(CAST(spam_articles AS FLOAT) / total_articles * 100, 2) || '%' as "Spam%",
    ROUND(reputation_score, 3) as "Score",
    CASE WHEN blocked = 1 THEN 'BLOCKED' ELSE 'OK' END as "Status"
FROM peer_stats
WHERE total_articles >= 10
ORDER BY spam_articles DESC, total_articles DESC
LIMIT 30;
EOF
}

show_peer_detail() {
    local peer="$1"
    
    echo -e "${BLUE}=== Detailed Stats for $peer ===${NC}"
    echo ""
    
    sqlite3 "$DB_PATH" <<EOF
.mode line
SELECT 
    peer_name as "Peer Name",
    total_articles as "Total Articles",
    spam_articles as "Spam Articles",
    ROUND(CAST(spam_articles AS FLOAT) / total_articles * 100, 2) || '%' as "Spam Rate",
    ROUND(reputation_score, 3) as "Reputation Score",
    datetime(first_seen, 'unixepoch') as "First Seen",
    datetime(last_article, 'unixepoch') as "Last Article",
    CASE WHEN blocked = 1 THEN 'YES' ELSE 'NO' END as "Blocked"
FROM peer_stats
WHERE peer_name = '$peer';
EOF
    
    echo ""
    echo -e "${YELLOW}Recent articles from this peer:${NC}"
    sqlite3 "$DB_PATH" <<EOF
.mode column
.headers on
SELECT 
    datetime(timestamp, 'unixepoch') as "Time",
    CASE WHEN is_spam = 1 THEN 'SPAM' ELSE 'OK' END as "Status",
    spam_reason as "Reason",
    substr(message_id, 1, 40) as "Message-ID"
FROM article_log
WHERE peer_name = '$peer'
ORDER BY timestamp DESC
LIMIT 20;
EOF
}

block_peer() {
    local peer="$1"
    
    sqlite3 "$DB_PATH" "UPDATE peer_stats SET blocked = 1 WHERE peer_name = '$peer';"
    echo -e "${RED}Peer $peer has been BLOCKED${NC}"
}

unblock_peer() {
    local peer="$1"
    
    sqlite3 "$DB_PATH" "UPDATE peer_stats SET blocked = 0 WHERE peer_name = '$peer';"
    echo -e "${GREEN}Peer $peer has been UNBLOCKED${NC}"
}

reset_peer_stats() {
    local peer="$1"
    
    sqlite3 "$DB_PATH" "DELETE FROM peer_stats WHERE peer_name = '$peer';"
    sqlite3 "$DB_PATH" "DELETE FROM article_log WHERE peer_name = '$peer';"
    echo -e "${YELLOW}Stats reset for peer $peer${NC}"
}

# =============================================================================
# SURBL STATISTICS
# =============================================================================

show_surbl_stats() {
    echo -e "${BLUE}=== SURBL Statistics (Last 24h) ===${NC}"
    echo ""
    
    local yesterday=$(date -d '24 hours ago' +%s)
    
    echo "Top blocked domains:"
    sqlite3 "$DB_PATH" <<EOF
.mode column
.headers on
SELECT 
    surbl_hits as "SURBL List",
    COUNT(*) as "Blocks"
FROM article_log
WHERE is_spam = 1 
    AND surbl_hits != ''
    AND timestamp > $yesterday
GROUP BY surbl_hits
ORDER BY COUNT(*) DESC
LIMIT 15;
EOF
    
    echo ""
    echo "SURBL blocks by peer:"
    sqlite3 "$DB_PATH" <<EOF
.mode column
.headers on
SELECT 
    peer_name as "Peer",
    COUNT(*) as "SURBL Blocks"
FROM article_log
WHERE is_spam = 1 
    AND surbl_hits != ''
    AND timestamp > $yesterday
GROUP BY peer_name
ORDER BY COUNT(*) DESC
LIMIT 10;
EOF
}

# =============================================================================
# BINARY DETECTION STATISTICS
# =============================================================================

show_binary_stats() {
    echo -e "${BLUE}=== Binary Detection Statistics (Last 24h) ===${NC}"
    echo ""
    
    local yesterday=$(date -d '24 hours ago' +%s)
    
    echo "Binary blocks by reason:"
    sqlite3 "$DB_PATH" <<EOF
.mode column
.headers on
SELECT 
    spam_reason as "Reason",
    COUNT(*) as "Blocks"
FROM article_log
WHERE binary_detected = 1
    AND timestamp > $yesterday
GROUP BY spam_reason
ORDER BY COUNT(*) DESC;
EOF
    
    echo ""
    echo "Binary blocks by peer:"
    sqlite3 "$DB_PATH" <<EOF
.mode column
.headers on
SELECT 
    peer_name as "Peer",
    COUNT(*) as "Binary Blocks"
FROM article_log
WHERE binary_detected = 1
    AND timestamp > $yesterday
GROUP BY peer_name
ORDER BY COUNT(*) DESC
LIMIT 10;
EOF
}

# =============================================================================
# OVERALL STATISTICS
# =============================================================================

show_overall_stats() {
    echo -e "${BLUE}=== Overall Filter Statistics ===${NC}"
    echo ""
    
    local today=$(date +%s)
    local yesterday=$(date -d '24 hours ago' +%s)
    local week_ago=$(date -d '7 days ago' +%s)
    
    echo -e "${YELLOW}Last 24 hours:${NC}"
    sqlite3 "$DB_PATH" <<EOF
SELECT 
    'Total Articles: ' || COUNT(*) FROM article_log WHERE timestamp > $yesterday
UNION ALL
SELECT 
    'Spam Blocked: ' || COUNT(*) FROM article_log WHERE is_spam = 1 AND timestamp > $yesterday
UNION ALL
SELECT 
    'SURBL Blocks: ' || COUNT(*) FROM article_log WHERE surbl_hits != '' AND timestamp > $yesterday
UNION ALL
SELECT 
    'Binary Blocks: ' || COUNT(*) FROM article_log WHERE binary_detected = 1 AND timestamp > $yesterday
UNION ALL
SELECT 
    'Spam Rate: ' || ROUND(CAST(SUM(is_spam) AS FLOAT) / COUNT(*) * 100, 2) || '%' 
    FROM article_log WHERE timestamp > $yesterday;
EOF
    
    echo ""
    echo -e "${YELLOW}Last 7 days:${NC}"
    sqlite3 "$DB_PATH" <<EOF
SELECT 
    'Total Articles: ' || COUNT(*) FROM article_log WHERE timestamp > $week_ago
UNION ALL
SELECT 
    'Spam Blocked: ' || COUNT(*) FROM article_log WHERE is_spam = 1 AND timestamp > $week_ago
UNION ALL
SELECT 
    'Spam Rate: ' || ROUND(CAST(SUM(is_spam) AS FLOAT) / COUNT(*) * 100, 2) || '%' 
    FROM article_log WHERE timestamp > $week_ago;
EOF
    
    echo ""
    echo -e "${YELLOW}Active peers (last 24h):${NC}"
    sqlite3 "$DB_PATH" "SELECT COUNT(DISTINCT peer_name) FROM article_log WHERE timestamp > $yesterday;"
    
    echo ""
    echo -e "${YELLOW}Blocked peers:${NC}"
    sqlite3 "$DB_PATH" "SELECT COUNT(*) FROM peer_stats WHERE blocked = 1;"
}

# =============================================================================
# MAINTENANCE FUNCTIONS
# =============================================================================

cleanup_old_data() {
    local days="${1:-30}"
    local cutoff=$(date -d "$days days ago" +%s)
    
    echo -e "${YELLOW}Cleaning up data older than $days days...${NC}"
    
    local count=$(sqlite3 "$DB_PATH" "SELECT COUNT(*) FROM article_log WHERE timestamp < $cutoff;")
    
    sqlite3 "$DB_PATH" "DELETE FROM article_log WHERE timestamp < $cutoff;"
    sqlite3 "$DB_PATH" "VACUUM;"
    
    echo -e "${GREEN}Removed $count old article logs${NC}"
}

export_stats() {
    local output="${1:-/tmp/usenet-filter-export.txt}"
    
    echo "Exporting statistics to $output..."
    
    {
        echo "=== USENET ADVANCED FILTER STATISTICS ==="
        echo "Generated: $(date)"
        echo ""
        show_overall_stats
        echo ""
        show_peer_stats
        echo ""
        show_surbl_stats
        echo ""
        show_binary_stats
    } > "$output"
    
    echo -e "${GREEN}Statistics exported to $output${NC}"
}

show_realtime() {
    echo -e "${BLUE}=== Real-time Monitoring (Ctrl+C to stop) ===${NC}"
    echo ""
    
    tail -f "$LOG_DIR/filter.log" | while read line; do
        if echo "$line" | grep -q "Rejected"; then
            echo -e "${RED}$line${NC}"
        elif echo "$line" | grep -q "Accepted"; then
            echo -e "${GREEN}$line${NC}"
        elif echo "$line" | grep -q "BLOCKING"; then
            echo -e "${RED}*** $line ***${NC}"
        else
            echo "$line"
        fi
    done
}

# =============================================================================
# REPORTS
# =============================================================================

generate_daily_report() {
    local yesterday=$(date -d '24 hours ago' +%s)
    local report_file="$LOG_DIR/daily-report-$(date +%Y%m%d).txt"
    
    {
        echo "=============================================="
        echo "USENET FILTER DAILY REPORT"
        echo "Date: $(date)"
        echo "=============================================="
        echo ""
        
        show_overall_stats
        echo ""
        echo "=============================================="
        echo "TOP SPAMMING PEERS"
        echo "=============================================="
        show_peer_stats | head -15
        echo ""
        echo "=============================================="
        echo "SURBL ACTIVITY"
        echo "=============================================="
        show_surbl_stats
        echo ""
        echo "=============================================="
        echo "BINARY DETECTION"
        echo "=============================================="
        show_binary_stats
        
    } > "$report_file"
    
    echo -e "${GREEN}Daily report saved to $report_file${NC}"
    
    # Display on screen
    cat "$report_file"
}

# =============================================================================
# MAIN MENU
# =============================================================================

usage() {
    cat <<EOF
Usage: $0 <command> [options]

PEER REPUTATION:
  peer-stats              Show peer reputation statistics
  peer-detail <peer>      Show detailed stats for specific peer
  block-peer <peer>       Block a peer
  unblock-peer <peer>     Unblock a peer
  reset-peer <peer>       Reset stats for a peer

STATISTICS:
  surbl-stats            Show SURBL blocking statistics
  binary-stats           Show binary detection statistics
  overall-stats          Show overall filter statistics
  realtime               Show real-time filtering activity

REPORTS:
  daily-report           Generate daily report
  export [file]          Export all statistics

MAINTENANCE:
  cleanup [days]         Remove logs older than N days (default: 30)
  
EXAMPLES:
  $0 peer-stats
  $0 peer-detail news.example.com
  $0 block-peer spammer.bad.net
  $0 cleanup 14
  $0 realtime

EOF
}

# =============================================================================
# MAIN EXECUTION
# =============================================================================

# Check if database exists
if [ ! -f "$DB_PATH" ]; then
    echo -e "${RED}Error: Database not found at $DB_PATH${NC}"
    echo "Make sure the filter is running and has processed some articles."
    exit 1
fi

case "${1:-}" in
    peer-stats)
        show_peer_stats
        ;;
    peer-detail)
        [ -z "$2" ] && echo "Usage: $0 peer-detail <peer_name>" && exit 1
        show_peer_detail "$2"
        ;;
    block-peer)
        [ -z "$2" ] && echo "Usage: $0 block-peer <peer_name>" && exit 1
        block_peer "$2"
        ;;
    unblock-peer)
        [ -z "$2" ] && echo "Usage: $0 unblock-peer <peer_name>" && exit 1
        unblock_peer "$2"
        ;;
    reset-peer)
        [ -z "$2" ] && echo "Usage: $0 reset-peer <peer_name>" && exit 1
        reset_peer "$2"
        ;;
    surbl-stats)
        show_surbl_stats
        ;;
    binary-stats)
        show_binary_stats
        ;;
    overall-stats)
        show_overall_stats
        ;;
    daily-report)
        generate_daily_report
        ;;
    export)
        export_stats "$2"
        ;;
    cleanup)
        cleanup_old_data "$2"
        ;;
    realtime)
        show_realtime
        ;;
    *)
        usage
        exit 1
        ;;
esac
