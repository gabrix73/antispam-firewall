# Anti-Spam Suite

Complete anti-spam protection for Usenet (INN) and Mail (SMTP) servers.

## Components

### 1. Usenet Advanced Filter (Python)

**Pure Python implementation** that complements SpamAssassin and Cleanfeed (no Perl required for the core filter):

- **SURBL Checking** - URL spam blacklist verification
- **Peer Reputation** - Track and auto-block problematic peers
- **Binary Detection** - Block binary content on text-only servers

**Language:** Python 3.8+  
**Dependencies:** dnspython, sqlite3  
**Integration:** Can be used directly in INN or via Perl wrapper

### 2. Mail Anti-Spam (Bash/iptables)

Network-level SMTP protection:

- **Spamhaus Integration** - Auto-block known spam IPs
- **Rate Limiting** - Max 10 conn/min per IP
- **Connection Limiting** - Max 5 concurrent per IP
- **SYN Flood Protection** - DDoS mitigation

**Language:** Bash  
**Dependencies:** iptables, ipset, wget

---

## Usenet Filter Installation

### How It Works

The filter is a **standalone Python script** that:

1. Reads article from stdin (headers + body)
2. Checks peer reputation from SQLite database
3. Scans for binary content (UUencode, yEnc, Base64)
4. Queries SURBL blacklists for URLs
5. Updates peer statistics
6. Returns exit code 0 (accept) or 1 (reject)

**Integration options:**
- Direct Python filter in INN (native Python support)
- Perl wrapper calling Python script (via pipe)
- Standalone executable via stdin/stdout

### Prerequisites
```bash
sudo apt install python3-pip python3-dnspython sqlite3
pip3 install dnspython
```

### Install
```bash
# Copy files
sudo cp usenet-advanced-filter.py /usr/local/bin/
sudo cp usenet-filter-manage.sh /usr/local/bin/
sudo chmod +x /usr/local/bin/usenet-*

# Create directories
sudo mkdir -p /var/lib/usenet-filter /var/log/usenet-filter /var/cache/usenet-filter
sudo chown -R news:news /var/lib/usenet-filter /var/log/usenet-filter /var/cache/usenet-filter

# Initialize
sudo -u news python3 /usr/local/bin/usenet-advanced-filter.py --test
```

### INN Integration

> **Note:** The Python script must be named `usenet_advanced_filter.py` (with underscore) for Method 1 to work, or kept as `usenet-advanced-filter.py` (with hyphen) for Method 2.

#### Method 1: Direct Python Filter (Recommended)

First, create a proper Python module:

```bash
# Rename to use underscores (Python module naming)
sudo cp /usr/local/bin/usenet-advanced-filter.py /usr/local/bin/usenet_advanced_filter.py
```

Configure INN to use Python filter directly. Create `/etc/news/filter_innd.py`:

```python
#!/usr/bin/env python3
"""INN Python filter wrapper for advanced filter"""

import sys
sys.path.insert(0, '/usr/local/bin')

# Import the advanced filter
from usenet_advanced_filter import filter_article

def filter_art(article):
    """
    INN filter interface
    Returns: (modified_headers, modified_body, rejection_reason)
    """
    # Split article
    if '\n\n' in article:
        headers, body = article.split('\n\n', 1)
    else:
        headers = article
        body = ''
    
    # Run filter
    result = filter_article(headers, body)
    
    if not result['accept']:
        return ('', '', result['reason'])
    
    return ('', '', '')
```

Make it executable and configure INN:

```bash
sudo chmod +x /etc/news/filter_innd.py
```

Edit `/etc/news/inn.conf` and enable Python filter:

```ini
# Use Python filter
pythonfilter: true
```

Test and reload:

```bash
# Test Python syntax
sudo -u news python3 /etc/news/filter_innd.py

# Reload INN filter
sudo ctlinnd reload filter 'Loading Python advanced filter'
```

#### Method 2: Perl Wrapper (Alternative)

If your INN setup requires Perl, create a wrapper in `/etc/news/filter/filter_innd.pl`:

```perl
#!/usr/bin/perl
use strict;
use warnings;

sub filter_art {
    my ($headers, $body) = @_;
    
    my $article = $headers . "\n\n" . $body;
    
    # Call Python script directly
    open(my $fh, '|-', '/usr/local/bin/usenet-advanced-filter.py') 
        or return ('', '', 'Filter unavailable');
    
    print $fh $article;
    close($fh);
    
    return ('', '', 'Advanced filter rejection') if ($? >> 8) != 0;
    return ('', '', '');
}

1;
```

Reload filter:
```bash
sudo ctlinnd reload filter.perl 'Loading advanced filter'
```

### Usage

```bash
# Monitor real-time
usenet-filter-manage.sh realtime

# Show peer stats
usenet-filter-manage.sh peer-stats

# Block/unblock peer
usenet-filter-manage.sh block-peer news.example.com
usenet-filter-manage.sh unblock-peer news.example.com

# Show statistics
usenet-filter-manage.sh overall-stats
usenet-filter-manage.sh surbl-stats
usenet-filter-manage.sh binary-stats

# Daily report
usenet-filter-manage.sh daily-report

# Cleanup old logs (30 days)
usenet-filter-manage.sh cleanup 30
```

### Configuration

Edit `/usr/local/bin/usenet-advanced-filter.py`:

```python
CONFIG = {
    'peer_spam_threshold': 0.30,      # 30% = warning
    'peer_block_threshold': 0.60,     # 60% = auto-block
    'min_articles_for_stats': 50,
    
    'max_base64_lines': 15,
    'max_base64_percent': 25,
    'max_article_size': 65536,
    
    'surbl_cache_time': 3600,
    'surbl_lists': [
        'multi.surbl.org',
        'dbl.spamhaus.org',
        'black.uribl.com',
        'multi.uribl.com',
    ],
    
    'log_level': 2,
}
```

---

## Mail Anti-Spam Installation

### Install

```bash
sudo cp anti-spam-iptables.sh /usr/local/bin/
sudo chmod +x /usr/local/bin/anti-spam-iptables.sh
sudo /usr/local/bin/anti-spam-iptables.sh install
```

### Usage

```bash
# Install/reinstall
sudo anti-spam-iptables.sh install

# Update Spamhaus lists
sudo anti-spam-iptables.sh update

# Show statistics
sudo anti-spam-iptables.sh stats

# Uninstall
sudo anti-spam-iptables.sh uninstall
```

### Auto-update Spamhaus

```bash
sudo crontab -e
```

Add:
```cron
# Update Spamhaus daily at 3 AM
0 3 * * * /usr/local/bin/anti-spam-iptables.sh update
```

### Configuration

Edit `/usr/local/bin/anti-spam-iptables.sh`:

```bash
# Rate limiting
CONN_LIMIT=10          # Max conn/min per IP
CONN_BURST=5
MAIL_LIMIT=30          # Max emails/hour

# Ports
SMTP_PORT=25
SUBMISSION_PORT=587
SMTPS_PORT=465

# Whitelist trusted IPs
WHITELIST_IPS=(
    "192.0.2.1"
    "198.51.100.5"
)
```

---

## Automation

### Usenet Filter Cron Jobs

```bash
sudo crontab -e -u news
```

Add:
```cron
# Daily report at 6 AM
0 6 * * * /usr/local/bin/usenet-filter-manage.sh daily-report

# Weekly cleanup (30 days)
0 3 * * 0 /usr/local/bin/usenet-filter-manage.sh cleanup 30
```

### Database Maintenance

```cron
# Weekly vacuum (Sunday 2 AM)
0 2 * * 0 sqlite3 /var/lib/usenet-filter/reputation.db "VACUUM; PRAGMA optimize;"
```

---

## Troubleshooting

### Usenet Filter

```bash
# Test filter
echo -e "Message-ID: <test@test>\nPath: test!not-for-mail\n\nTest" | \
  sudo -u news python3 /usr/local/bin/usenet-advanced-filter.py

# Check logs
tail -f /var/log/usenet-filter/filter.log
tail -f /var/log/news/errlog

# Database integrity
sudo sqlite3 /var/lib/usenet-filter/reputation.db "PRAGMA integrity_check;"

# Reset database
sudo rm /var/lib/usenet-filter/reputation.db
sudo -u news python3 /usr/local/bin/usenet-advanced-filter.py --test
```

### Mail Anti-Spam

```bash
# Check iptables rules
sudo iptables -L -v -n | grep -A 10 SMTP

# View Spamhaus blocks
sudo ipset list spamhaus_drop | head -20

# Check rate limits
sudo grep "SMTP_RATE_LIMIT" /var/log/syslog | tail -20

# Whitelist an IP
sudo iptables -I INPUT -s IP_ADDRESS -j ACCEPT
```

---

## Architecture

```
Internet
   │
   ├─── Usenet (119)
   │      ├── iptables (rate limit)
   │      ├── Cleanfeed (patterns)
   │      ├── SpamAssassin (content)
   │      └── Advanced Filter (SURBL+Peer+Binary)
   │             └── INN Server
   │
   └─── Mail (25/587/465)
          ├── iptables + Spamhaus
          └── Mail Server (Postfix/Exim)
```

---

## Files

### Usenet Filter (Python)
- `usenet-advanced-filter.py` - Main Python filter script (standalone)
- `usenet-filter-manage.sh` - Bash management and monitoring tool

### Mail Filter (Bash)
- `anti-spam-iptables.sh` - iptables firewall configuration script

### Documentation
- `README.md` - This file

**Note:** The core filter is pure Python. Perl is only needed if your INN doesn't support native Python filters (Method 2 in integration).
