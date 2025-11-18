#!/usr/bin/env python3
"""
Usenet Advanced Filter for INN
Provides: SURBL checking, Peer Reputation, Binary Detection
Complements: SpamAssassin (content) and Cleanfeed (patterns)

Version: 1.0
Date: 2025-11-18
"""

import sys
import sqlite3
import dns.resolver
import re
import time
import hashlib
from urllib.parse import urlparse
from pathlib import Path
from datetime import datetime
import json

# =============================================================================
# CONFIGURATION
# =============================================================================

CONFIG = {
    'db_path': '/var/lib/usenet-filter/reputation.db',
    
    # SURBL lists - only URL blacklists (SpamAssassin handles content)
    'surbl_lists': [
        'multi.surbl.org',
        'dbl.spamhaus.org', 
        'black.uribl.com',
        'multi.uribl.com',
    ],
    
    # Peer reputation thresholds
    'peer_spam_threshold': 0.30,      # 30% = warning
    'peer_block_threshold': 0.60,     # 60% = auto-block
    'peer_reputation_window': 86400,  # 24 hours
    'min_articles_for_stats': 50,
    
    # Binary detection (for text-only servers)
    'max_base64_lines': 15,           # Consecutive base64 lines
    'max_base64_percent': 25,         # % of article
    'max_article_size': 65536,        # 64KB
    
    # Caching
    'cache_dir': '/var/cache/usenet-filter',
    'surbl_cache_time': 3600,         # 1 hour
    
    # Logging
    'log_dir': '/var/log/usenet-filter',
    'log_level': 2,  # 0=none, 1=errors, 2=info, 3=debug
}

# =============================================================================
# GLOBALS
# =============================================================================

surbl_cache = {}
resolver = dns.resolver.Resolver()
resolver.timeout = 2
resolver.lifetime = 2

# =============================================================================
# DATABASE
# =============================================================================

def init_database():
    """Initialize SQLite database for peer reputation"""
    conn = sqlite3.connect(CONFIG['db_path'])
    cursor = conn.cursor()
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS peer_stats (
            peer_name TEXT PRIMARY KEY,
            total_articles INTEGER DEFAULT 0,
            spam_articles INTEGER DEFAULT 0,
            last_article REAL,
            first_seen REAL,
            reputation_score REAL DEFAULT 1.0,
            blocked INTEGER DEFAULT 0
        )
    ''')
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS article_log (
            message_id TEXT PRIMARY KEY,
            peer_name TEXT,
            timestamp REAL,
            is_spam INTEGER,
            spam_reason TEXT,
            surbl_hits TEXT,
            binary_detected INTEGER
        )
    ''')
    
    cursor.execute('''
        CREATE INDEX IF NOT EXISTS idx_peer_timestamp 
        ON article_log(peer_name, timestamp)
    ''')
    
    conn.commit()
    conn.close()
    log_message(2, "Database initialized")

# =============================================================================
# SURBL CHECKING
# =============================================================================

def extract_urls(body):
    """Extract URLs from article body"""
    urls = []
    
    # HTTP/HTTPS URLs
    url_pattern = r'https?://[^\s<>"{}|\\^`\[\]]+'
    urls.extend(re.findall(url_pattern, body, re.IGNORECASE))
    
    # Domain patterns without protocol
    domain_pattern = r'(?:^|\s)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+)'
    for match in re.finditer(domain_pattern, body, re.IGNORECASE | re.MULTILINE):
        domain = match.group(1)
        # Skip local/private IPs
        if domain.startswith(('127.', '10.', '192.168.', 'localhost')):
            continue
        # Skip image extensions
        if domain.endswith(('.jpg', '.png', '.gif', '.txt')):
            continue
        urls.append(f'http://{domain}')
    
    return urls

def extract_domain(url):
    """Extract base domain from URL"""
    try:
        parsed = urlparse(url if '://' in url else f'http://{url}')
        domain = parsed.netloc or parsed.path
        domain = domain.lower().replace('www.', '')
        
        # Get base domain (handle .co.uk, .com.au etc)
        parts = domain.split('.')
        if len(parts) >= 3 and parts[-2] in ['co', 'com', 'org', 'net', 'ac', 'gov']:
            return '.'.join(parts[-3:])
        elif len(parts) >= 2:
            return '.'.join(parts[-2:])
        return domain
    except:
        return None

def check_surbl(url):
    """Check URL against SURBL blacklists"""
    domain = extract_domain(url)
    if not domain:
        return False, []
    
    # Check cache
    cache_key = domain
    if cache_key in surbl_cache:
        cached = surbl_cache[cache_key]
        if time.time() - cached['time'] < CONFIG['surbl_cache_time']:
            return cached['listed'], cached['lists']
    
    hits = []
    listed = False
    
    for surbl_list in CONFIG['surbl_lists']:
        query = f"{domain}.{surbl_list}"
        try:
            result = resolver.resolve(query, 'A')
            if result:
                hits.append(surbl_list)
                listed = True
                log_message(3, f"SURBL hit: {domain} on {surbl_list}")
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.Timeout):
            pass
        except Exception as e:
            log_message(1, f"SURBL error for {domain}: {e}")
    
    # Cache result
    surbl_cache[cache_key] = {
        'time': time.time(),
        'listed': listed,
        'lists': hits
    }
    
    return listed, hits

def scan_article_urls(body):
    """Scan all URLs in article against SURBL"""
    urls = extract_urls(body)
    if not urls:
        return 0, []
    
    log_message(3, f"Found {len(urls)} URLs to check")
    
    all_hits = []
    total_listed = 0
    
    for url in urls:
        listed, hits = check_surbl(url)
        if listed:
            total_listed += 1
            all_hits.append({
                'url': url,
                'lists': hits
            })
    
    return total_listed, all_hits

# =============================================================================
# BINARY DETECTION
# =============================================================================

def detect_binary_content(headers, body):
    """Detect binary content in articles"""
    detection = {
        'is_binary': False,
        'reason': '',
        'confidence': 0
    }
    
    # Check Content-Type header
    content_type_match = re.search(r'Content-Type:\s*(.+)', headers, re.IGNORECASE | re.MULTILINE)
    if content_type_match:
        content_type = content_type_match.group(1).lower()
        if any(t in content_type for t in ['application/', 'image/', 'video/', 'audio/']):
            detection['is_binary'] = True
            detection['reason'] = 'Binary Content-Type'
            detection['confidence'] = 100
            return detection
    
    # Check for UUencode
    if re.search(r'^begin \d{3,4} .+$', body, re.MULTILINE):
        detection['is_binary'] = True
        detection['reason'] = 'UUencoded content'
        detection['confidence'] = 100
        return detection
    
    # Check for yEnc
    if re.search(r'=ybegin|=ypart|=yend', body, re.IGNORECASE):
        detection['is_binary'] = True
        detection['reason'] = 'yEnc encoded content'
        detection['confidence'] = 100
        return detection
    
    # Check for excessive Base64
    lines = body.split('\n')
    base64_lines = 0
    consecutive_base64 = 0
    max_consecutive = 0
    
    for line in lines:
        # Base64 pattern: long lines of A-Za-z0-9+/=
        if re.match(r'^[A-Za-z0-9+/]{60,}={0,2}$', line.strip()):
            base64_lines += 1
            consecutive_base64 += 1
            max_consecutive = max(max_consecutive, consecutive_base64)
        else:
            consecutive_base64 = 0
    
    if max_consecutive > CONFIG['max_base64_lines']:
        detection['is_binary'] = True
        detection['reason'] = f'Consecutive Base64 lines: {max_consecutive}'
        detection['confidence'] = 90
        return detection
    
    if lines:
        base64_percent = (base64_lines / len(lines)) * 100
        if base64_percent > CONFIG['max_base64_percent']:
            detection['is_binary'] = True
            detection['reason'] = f'Base64 content: {base64_percent:.1f}%'
            detection['confidence'] = 80
            return detection
    
    # Check for MIME attachments
    if re.search(r'Content-Disposition:.*attachment', body, re.IGNORECASE | re.MULTILINE):
        detection['is_binary'] = True
        detection['reason'] = 'MIME attachment detected'
        detection['confidence'] = 95
        return detection
    
    # Check for binary filenames
    if re.search(r'\.(?:zip|rar|exe|bin|iso|mp3|avi|mkv|mp4)(?:\s|"|\'|$)', 
                 headers + body, re.IGNORECASE):
        detection['is_binary'] = True
        detection['reason'] = 'Binary filename detected'
        detection['confidence'] = 70
        return detection
    
    return detection

# =============================================================================
# PEER REPUTATION
# =============================================================================

def extract_peer_from_path(headers):
    """Extract originating peer from Path header"""
    path_match = re.search(r'^Path:\s*(.+?)$', headers, re.IGNORECASE | re.MULTILINE)
    if not path_match:
        return 'UNKNOWN'
    
    path = path_match.group(1)
    
    # Skip local injection
    if 'not-for-mail' in path.lower():
        return 'LOCAL'
    
    # Get first real hop (rightmost, closest to origin)
    hops = path.split('!')
    for hop in reversed(hops):
        hop = hop.strip()
        if hop and hop != 'not-for-mail':
            return hop
    
    return 'UNKNOWN'

def update_peer_stats(peer_name, is_spam, reason):
    """Update peer reputation statistics"""
    conn = sqlite3.connect(CONFIG['db_path'])
    cursor = conn.cursor()
    
    now = time.time()
    
    # Get current stats
    cursor.execute('SELECT total_articles, spam_articles, first_seen FROM peer_stats WHERE peer_name = ?', 
                   (peer_name,))
    row = cursor.fetchone()
    
    if row:
        # Update existing
        reputation = calculate_reputation(cursor, peer_name)
        cursor.execute('''
            UPDATE peer_stats 
            SET total_articles = total_articles + 1,
                spam_articles = spam_articles + ?,
                last_article = ?,
                reputation_score = ?
            WHERE peer_name = ?
        ''', (1 if is_spam else 0, now, reputation, peer_name))
    else:
        # New peer
        cursor.execute('''
            INSERT INTO peer_stats 
            (peer_name, total_articles, spam_articles, last_article, first_seen, reputation_score)
            VALUES (?, 1, ?, ?, ?, 1.0)
        ''', (peer_name, 1 if is_spam else 0, now, now))
    
    conn.commit()
    conn.close()

def calculate_reputation(cursor, peer_name):
    """Calculate reputation score for peer"""
    cursor.execute('SELECT total_articles, spam_articles FROM peer_stats WHERE peer_name = ?', 
                   (peer_name,))
    row = cursor.fetchone()
    
    if not row or row[0] < CONFIG['min_articles_for_stats']:
        return 1.0
    
    total, spam = row
    spam_rate = spam / total
    reputation = 1.0 - spam_rate
    
    return reputation

def should_block_peer(peer_name):
    """Check if peer should be blocked based on reputation"""
    conn = sqlite3.connect(CONFIG['db_path'])
    cursor = conn.cursor()
    
    cursor.execute('SELECT total_articles, spam_articles, blocked FROM peer_stats WHERE peer_name = ?',
                   (peer_name,))
    row = cursor.fetchone()
    
    if not row or row[0] < CONFIG['min_articles_for_stats']:
        conn.close()
        return False
    
    total, spam, blocked = row
    spam_rate = spam / total
    
    if spam_rate >= CONFIG['peer_block_threshold']:
        # Mark as blocked
        cursor.execute('UPDATE peer_stats SET blocked = 1 WHERE peer_name = ?', (peer_name,))
        conn.commit()
        log_message(1, f"BLOCKING peer {peer_name} (spam rate: {spam_rate*100:.1f}%)")
        conn.close()
        return True
    
    conn.close()
    return blocked == 1

# =============================================================================
# LOGGING
# =============================================================================

def log_message(level, message):
    """Log message to file"""
    if level > CONFIG['log_level']:
        return
    
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    log_file = Path(CONFIG['log_dir']) / 'filter.log'
    
    try:
        with open(log_file, 'a') as f:
            f.write(f"[{timestamp}] {message}\n")
    except:
        pass

def log_article(message_id, peer_name, is_spam, reason, surbl_hits, binary):
    """Log article processing to database"""
    conn = sqlite3.connect(CONFIG['db_path'])
    cursor = conn.cursor()
    
    cursor.execute('''
        INSERT OR REPLACE INTO article_log
        (message_id, peer_name, timestamp, is_spam, spam_reason, surbl_hits, binary_detected)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    ''', (message_id, peer_name, time.time(), 1 if is_spam else 0, reason, surbl_hits, 1 if binary else 0))
    
    conn.commit()
    conn.close()

# =============================================================================
# MAIN FILTER
# =============================================================================

def filter_article(headers, body):
    """
    Main filter function - complements SpamAssassin and Cleanfeed
    
    Returns: (accept, reason)
    """
    result = {
        'accept': True,
        'reason': '',
        'scores': {}
    }
    
    # Extract metadata
    message_id_match = re.search(r'^Message-ID:\s*(.+?)$', headers, re.IGNORECASE | re.MULTILINE)
    message_id = message_id_match.group(1) if message_id_match else 'UNKNOWN'
    
    peer_name = extract_peer_from_path(headers)
    
    log_message(3, f"Filtering {message_id} from {peer_name}")
    
    # Check peer reputation
    if should_block_peer(peer_name):
        result['accept'] = False
        result['reason'] = 'Peer reputation too low'
        log_article(message_id, peer_name, True, result['reason'], '', False)
        log_message(2, f"Rejected {message_id}: {result['reason']}")
        return result
    
    # Binary detection (for text-only servers)
    binary = detect_binary_content(headers, body)
    if binary['is_binary']:
        result['accept'] = False
        result['reason'] = f"Binary: {binary['reason']}"
        update_peer_stats(peer_name, True, result['reason'])
        log_article(message_id, peer_name, True, result['reason'], '', True)
        log_message(2, f"Rejected {message_id}: {result['reason']}")
        return result
    
    # SURBL checking (URLs not checked by SpamAssassin)
    url_spam_count, surbl_hits = scan_article_urls(body)
    if url_spam_count > 0:
        result['accept'] = False
        result['reason'] = f'Spam URLs detected ({url_spam_count} hits)'
        
        surbl_summary = ';'.join([','.join(hit['lists']) for hit in surbl_hits])
        
        update_peer_stats(peer_name, True, result['reason'])
        log_article(message_id, peer_name, True, result['reason'], surbl_summary, False)
        log_message(2, f"Rejected {message_id}: {result['reason']}")
        return result
    
    # Article passed all checks
    update_peer_stats(peer_name, False, '')
    log_article(message_id, peer_name, False, '', '', False)
    log_message(3, f"Accepted {message_id} from {peer_name}")
    
    return result

# =============================================================================
# INN INTERFACE
# =============================================================================

def process_stdin():
    """Process article from stdin (INN filter mode)"""
    article = sys.stdin.read()
    
    # Split headers and body
    if '\n\n' in article:
        headers, body = article.split('\n\n', 1)
    else:
        headers = article
        body = ''
    
    result = filter_article(headers, body)
    
    if not result['accept']:
        # Reject with reason
        print(result['reason'], file=sys.stderr)
        sys.exit(1)
    
    # Accept
    sys.exit(0)

# =============================================================================
# INITIALIZATION
# =============================================================================

def init():
    """Initialize system"""
    # Create directories
    Path(CONFIG['log_dir']).mkdir(parents=True, exist_ok=True)
    Path(CONFIG['cache_dir']).mkdir(parents=True, exist_ok=True)
    Path(CONFIG['db_path']).parent.mkdir(parents=True, exist_ok=True)
    
    # Initialize database
    init_database()
    
    log_message(2, "Usenet Advanced Filter initialized")

# =============================================================================
# MAIN
# =============================================================================

if __name__ == '__main__':
    init()
    
    if len(sys.argv) > 1 and sys.argv[1] == '--test':
        # Test mode
        print("Running self-test...")
        print("✓ Imports OK")
        print("✓ Database OK")
        print(f"✓ SURBL lists: {', '.join(CONFIG['surbl_lists'])}")
        print("✓ Ready")
    else:
        # Normal INN filter mode
        process_stdin()
