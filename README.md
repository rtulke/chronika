# Chronika - Forensic Browser History Timeline Tool

A comprehensive tool for analyzing browser history across multiple browsers an platforms with advanced filtering, analytics, and export capabilities. Designed for digital forensics, security analysis, and privacy research.

## ✨ Features

### 🌐 Multi-Browser Support
- **Chrome**: Google Chrome (Chromium-based)
- **Firefox**: Mozilla Firefox
- **Safari**: Apple Safari (macOS only)
- **Brave**: Privacy-focused Chromium browser  
- **Opera**: Feature-rich browser with built-in VPN
- **Edge**: Microsoft Edge (Chromium-based)
- **Vivaldi**: Highly customizable Chromium-based browser
- **Tor Browser**: Anonymous browsing (Firefox-based)
- **Chromium**: Open-source base for Chrome/Edge/Brave
- **LibreWolf**: Privacy-hardened Firefox fork

### 🔍 Advanced Filtering & Search
- **Domain Filtering**: Whitelist/blacklist with regex support
- **Keyword Search**: Search in titles and URLs with regex support
- **Time Range Filtering**: Precise date/time windows or relative periods
- **Visit Frequency**: Filter by visit count (frequently vs rarely visited)
- **Complete Database Search**: Bypass default limits with `--all` and `--no-time-filter`
- **Browser Selection**: Target specific browsers with `--browsers` or exclude with `--exclude-browsers`

### 📊 Analytics & Statistics
- **Comprehensive Statistics**: Total visits, unique domains, browsing patterns
- **Top Domains Analysis**: Most visited sites by frequency and visit count
- **Browser Usage Comparison**: Detailed usage breakdown across browsers  
- **Temporal Patterns**: Browsing patterns by hour, day, weekday, or month
- **Visit Frequency Analysis**: Distribution of site visit frequencies

### 📤 Professional Export Formats
- **Timeline Display**: Visual chronological timeline (default)
- **Data Formats**: JSON, CSV for data analysis
- **SIEM Integration**: Splunk-compatible logs for security analysis
- **ELK Stack**: Logstash-compatible JSON for Elasticsearch
- **Network Analysis**: Gephi-compatible network graphs for visualization
- **Timeline Tools**: TimelineJS-compatible JSON for external timeline tools

### 🔧 Advanced Features
- **Debug Mode**: Detailed database analysis and troubleshooting
- **Privacy Protection**: URL anonymization for safe data sharing
- **Cross-platform**: Linux and macOS support
- **Security Conscious**: Read-only access, temporary file handling
- **Intelligent Filtering**: Automatic database expansion when filters are detected

## 🚀 Quick Start

### Installation

```bash
# Clone repository
git clone https://github.com/user/chronika.git
cd chronika

# Setup virtual environment
python3 -m venv browser_history_env
source browser_history_env/bin/activate

# Install dependencies
pip install -r requirements.txt

# Make executable
chmod +x chronika.py

# Test installation
./chronika.py --help
```

### Basic Usage

```bash
# Display timeline of recent browser history
./chronika.py

# View history from specific browser
./chronika.py --browsers chrome

# Search for security-related content across all browsers
./chronika.py --search "security,hacking,vulnerability" --all

# Generate comprehensive statistics
./chronika.py --format stats --days 30
```

## 📋 Command Line Reference

### Browser Selection
| Parameter | Description | Example |
|-----------|-------------|---------|
| `--browsers` | Select specific browsers | `--browsers chrome,firefox,brave` |
| `--exclude-browsers` | Exclude specific browsers | `--exclude-browsers safari,tor` |

### Output Formats
| Parameter | Description | Use Case |
|-----------|-------------|----------|
| `--format timeline` | Visual chronological display (default) | General browsing overview |
| `--format stats` | Comprehensive statistics | Data analysis, reporting |
| `--format top-domains` | Most visited domains | Site usage analysis |
| `--format browser-usage` | Browser comparison | Browser preference analysis |
| `--format patterns` | Temporal browsing patterns | Behavior analysis |
| `--format json` | Structured data export | Data processing, APIs |
| `--format csv` | Spreadsheet-compatible export | Excel analysis |
| `--format splunk` | SIEM-compatible logs | Security monitoring |
| `--format elk` | Elasticsearch/Logstash format | Log aggregation |
| `--format gephi` | Network graph format | Relationship visualization |
| `--format timeline-json` | External timeline tools | Presentation, reporting |

### Time Filtering
| Parameter | Description | Example |
|-----------|-------------|---------|
| `--days N` | Last N days | `--days 30` |
| `--time-from` | Start time (ISO format) | `--time-from "2025-06-01T09:00:00"` |
| `--time-to` | End time (ISO format) | `--time-to "2025-06-01T17:00:00"` |
| `--no-time-filter` | Search entire database | `--no-time-filter` |

### Content Filtering  
| Parameter | Description | Example |
|-----------|-------------|---------|
| `--search` | Keywords in titles/URLs | `--search "github,python,security"` |
| `--domain-include` | Include only these domains | `--domain-include "github.com,stackoverflow.com"` |
| `--domain-exclude` | Exclude these domains | `--domain-exclude "facebook.com,ads.google.com"` |
| `--min-visits N` | Minimum visit count | `--min-visits 5` |
| `--max-visits N` | Maximum visit count | `--max-visits 50` |
| `--regex` | Enable regex in filters | `--regex --domain-include ".*\.edu"` |

### Database & Display Options
| Parameter | Description | Use Case |
|-----------|-------------|----------|
| `--all` | Search entire database | Finding rare/old entries |
| `--limit N` | Limit displayed results | `--limit 500` |
| `--debug` | Enable debug output | Troubleshooting, analysis |
| `--output FILE` | Specify output filename | `--output analysis.json` |
| `--anonymize` | Anonymize URLs for privacy | Safe data sharing |

### Analytics Options
| Parameter | Description | Example |
|-----------|-------------|---------|
| `--group-by` | Group patterns by time unit | `--group-by hour` / `day` / `weekday` / `month` |

### Configuration
| Parameter | Description |
|-----------|-------------|
| `--config FILE` | Use custom config file |
| `--init-config` | Create default config file |

## 💡 Usage Examples

### Basic Analysis
```bash
# Recent browsing activity
./chronika.py --days 7

# Specific browser analysis  
./chronika.py --browsers chrome --format stats --days 30

# All browsers except problematic Safari
./chronika.py --exclude-browsers safari --format top-domains
```

### Search & Investigation
```bash
# Security research analysis
./chronika.py --search "hack,security,vulnerability,exploit" --all --format timeline

# Development workflow analysis
./chronika.py --domain-include "github.com,stackoverflow.com" --format patterns --group-by hour

# Social media usage
./chronika.py --domain-include "facebook.com,twitter.com,instagram.com" --format browser-usage

# Deep search for rare terms
./chronika.py --search "cryptocurrency,blockchain" --no-time-filter --format top-domains
```

### Professional & Forensic Use
```bash
# Incident response: specific timeframe
./chronika.py --time-from "2025-06-01T14:00:00" --time-to "2025-06-01T16:00:00" --format timeline

# SIEM integration
./chronika.py --browsers chrome --search "login,admin,auth" --format splunk --output security_events.log

# Network analysis for Gephi
./chronika.py --browsers firefox,chrome --format gephi --days 30 --output browsing_network.gexf

# Privacy audit (anonymized)
./chronika.py --anonymize --format json --days 90 --output privacy_audit.json
```

### Data Analysis & Export
```bash
# Comprehensive data export
./chronika.py --format elk --days 30 --output elasticsearch_import.json

# Excel-compatible analysis
./chronika.py --format csv --search "work,project" --output work_analysis.csv

# Statistical reporting
./chronika.py --format stats --days 30 > monthly_report.txt

# Timeline for presentations
./chronika.py --format timeline-json --anonymize --days 7 --output presentation_timeline.json
```

### Advanced Filtering
```bash
# Regex filtering for educational domains
./chronika.py --regex --domain-include ".*\.edu,.*\.gov" --format top-domains

# High-engagement sites only
./chronika.py --min-visits 10 --format browser-usage --days 30

# Exclude tracking/ad domains
./chronika.py --domain-exclude "doubleclick.net,googlesyndication.com,facebook.com" --format patterns

# Complex time-based analysis
./chronika.py --time-from "2025-06-01T09:00:00" --time-to "2025-06-01T17:00:00" --search "work,meeting,calendar" --format stats
```

### Debug & Troubleshooting
```bash
# Debug browser detection issues
./chronika.py --debug --browsers safari

# Debug filtering problems
./chronika.py --search "test" --debug --limit 5

# Database analysis
./chronika.py --debug --no-time-filter --limit 10
```

## 🔧 Configuration

Chronika supports TOML configuration files for persistent settings:

```bash
# Create default configuration
./chronika.py --init-config
```

### Configuration Example (`chronika.toml`)
```toml
[browsers]
chrome = true
firefox = true  
safari = false      # Disabled due to macOS permissions
brave = true
opera = true
edge = true
vivaldi = true
tor = true
chromium = true
librewolf = true

[output]
format = "timeline"
limit = 100
days_back = 7

[display]
show_url = true
show_visit_count = true
date_format = "%Y-%m-%d %H:%M:%S"

[filters]
domain_whitelist = []           # Example: ["github.com", "stackoverflow.com"]
domain_blacklist = []           # Example: ["ads.google.com", "facebook.com"]
keywords = []                   # Example: ["python", "security", "linux"]
min_visit_count = 1
max_visit_count = null
time_from = null               # Example: "2025-06-01T00:00:00"
time_to = null                 # Example: "2025-06-07T23:59:59"
use_regex = false

[analytics]
enable_stats = true
group_patterns_by = "hour"      # hour, day, weekday, month
top_domains_limit = 20
include_subdomains = true

[exports]
include_metadata = true
anonymize_urls = false          # Hash URL paths for privacy
compress_output = false
include_user_agent = false
```

### Preset Configurations

**Security Analysis**
```toml
[filters]
keywords = ["security", "vulnerability", "exploit", "hack", "penetration", "audit"]
[output]
format = "splunk"
days_back = 30
```

**Privacy Research**
```toml
[filters]  
domain_blacklist = ["facebook.com", "google.com", "amazon.com"]
[exports]
anonymize_urls = true
[output]
format = "json"
```

**Development Workflow**
```toml
[filters]
domain_whitelist = ["github.com", "stackoverflow.com", "docs.python.org", "developer.mozilla.org"]
[analytics]
group_patterns_by = "hour"
[output]
format = "patterns"
```

## 📊 Output Formats Explained

### Timeline Display (Default)
```
================================================================================
BROWSER HISTORY TIMELINE (45 entries)
================================================================================

📅 2025-06-09
----------------------------------------
  14:30:15 🌎 [Chrome]
    📄 GitHub - Browser History Tool
    🔗 https://github.com/user/browser-history-tool
    👁️  Visited 3 times

  14:25:42 🦊 [Firefox]
    📄 Python Documentation
    🔗 https://docs.python.org/3/

  14:20:18 🦁 [Brave]
    📄 DuckDuckGo Search Results
    🔗 https://duckduckgo.com/?q=python+sqlite
    👁️  Visited 2 times
```

### Statistics Analysis
```
================================================================================
BROWSER HISTORY STATISTICS
================================================================================

📊 SUMMARY
   Total entries: 1,247
   Total visits: 3,892
   Unique domains: 156
   Unique URLs: 1,089
   Avg visits/URL: 3.1

🌐 BROWSER USAGE
   Chrome: 534 (42.8%)
   Firefox: 312 (25.0%)
   Brave: 231 (18.5%)

🔝 TOP DOMAINS (by frequency)
   github.com: 89 visits
   stackoverflow.com: 67 visits
   docs.python.org: 45 visits
```

### Browsing Patterns
```
================================================================================
BROWSING PATTERNS (grouped by hour)
================================================================================

        08:00 │████████████████████                              67 ( 5.4%)
        09:00 │████████████████████████████████████████████████  124 (10.0%)
        10:00 │██████████████████████████████████████████████    115 ( 9.2%)
        14:00 │████████████████████████████████████████████████  122 ( 9.8%)
        20:00 │████████████████████████                          78 ( 6.3%)
```

### Professional Export Formats

**Splunk Format**
```
timestamp="2025-06-09 14:30:15" browser="Chrome" domain="github.com" url="https://github.com/user/repo" title="GitHub Repository" visit_count=5 source="browser_history" sourcetype="web_history"
```

**ELK/Logstash Format**
```json
{"@timestamp": "2025-06-09T14:30:15", "browser": "Chrome", "domain": "github.com", "url": "https://github.com/user/repo", "title": "GitHub Repository", "visit_count": 5, "event_type": "browser_history"}
```

**Gephi Network Graph**
- Exports GEXF format for network visualization
- Nodes represent unique domains
- Edges show navigation transitions between domains
- Edge weights indicate transition frequency
- Import into Gephi for advanced network analysis

## 🛡️ Security & Privacy Features

### URL Anonymization
```bash
# Anonymize URLs for safe sharing
./chronika.py --format json --anonymize --output safe_export.json
```
URLs are transformed: `https://github.com/user/private-repo` → `https://github.com/path_8472`

### Privacy-Focused Analysis
```bash
# Exclude tracking domains
./chronika.py --domain-exclude "doubleclick.net,googlesyndication.com,facebook.com"

# Focus on work/education domains only
./chronika.py --regex --domain-include ".*\.company\.com,.*\.edu,github\.com"
```

### Security Analysis Examples
```bash
# Security research detection
./chronika.py --search "exploit,vulnerability,malware,phishing" --format splunk --output security_research.log

# Login pattern analysis
./chronika.py --search "login,signin,auth,admin" --format patterns --group-by hour

# Suspicious activity detection
./chronika.py --min-visits 20 --domain-exclude "company.com" --format top-domains --days 7

# Incident timeline reconstruction
./chronika.py --time-from "2025-06-01T13:00:00" --time-to "2025-06-01T15:00:00" --format timeline --debug
```

## 🔍 Troubleshooting

### Debug Mode
```bash
# Enable comprehensive debugging
./chronika.py --debug --browsers chrome --search "test"
```

Debug output includes:
- Database paths and accessibility status
- Total entries in each database
- Table structures and available columns
- Raw SQL query results and sample data
- Filter application step-by-step
- Timestamp conversion details
- Detailed error messages with context

### Common Issues & Solutions

#### No History Found
**Symptoms**: "No browser history found" or very few results
**Solutions**:
```bash
# Check database accessibility
./chronika.py --debug --browsers chrome --limit 5

# Try different time ranges
./chronika.py --no-time-filter --limit 10

# Test specific browser
./chronika.py --browsers firefox --debug
```

#### Safari Permission Issues (macOS)
**Symptoms**: "Operation not permitted" or "Permission denied"
**Solutions**:
1. **Close Safari completely** and retry
2. **Grant Terminal Full Disk Access**:
   - System Preferences → Security & Privacy → Privacy → Full Disk Access
   - Add Terminal and enable
3. **Disable Safari temporarily**:
   ```bash
   ./chronika.py --exclude-browsers safari
   ```

#### Missing Search Results  
**Symptoms**: Expected results not found in search
**Solutions**:
```bash
# Use complete database search
./chronika.py --search "keyword" --no-time-filter --debug

# Check time range
./chronika.py --search "keyword" --days 365 --debug

# Verify search in both titles and URLs
./chronika.py --search "keyword" --all --debug --limit 5
```

#### Database Locked Errors
**Symptoms**: "Database is locked" errors
**Solutions**:
- Close all browser instances completely
- Wait 30 seconds and retry
- Check for crashed browser processes:
  ```bash
  # macOS
  ps aux | grep -i chrome
  killall "Google Chrome"
  
  # Linux  
  pkill chrome
  pkill firefox
  ```

#### Filter Returns No Results
**Symptoms**: "No entries match the specified filters"
**Solutions**:
```bash
# Debug filter application
./chronika.py --search "keyword" --debug --all

# Test without filters first
./chronika.py --browsers chrome --limit 10

# Verify filter syntax
./chronika.py --domain-include "github.com" --debug --limit 5
```

#### Performance Issues
**Symptoms**: Slow processing or timeouts
**Solutions**:
```bash
# Reduce scope
./chronika.py --days 30 --limit 500

# Use time filters
./chronika.py --time-from "2025-06-01T00:00:00" --days 7

# Target specific browsers
./chronika.py --browsers chrome --format stats
```

### Browser-Specific Issues

#### Chrome/Chromium-based
- **Path Issues**: Check if using Chrome Beta/Dev versions
- **Profile Issues**: Tool uses Default profile only
- **Corporate**: May require different paths in managed environments

#### Firefox-based
- **Profile Detection**: Tool searches for "default" in profile name
- **Tor Browser**: Special paths, may have limited history
- **LibreWolf**: Privacy settings may limit history retention

#### Safari (macOS)
- **System Protection**: macOS protects Safari data heavily
- **Database Format**: Changes between macOS versions
- **Container Security**: New Safari versions use sandboxed storage

### Getting Help
```bash
# Generate debug report
./chronika.py --debug --all --limit 1 > debug_report.txt 2>&1

# Test all browsers
./chronika.py --debug --format stats --limit 5 > browser_test.txt 2>&1

# Minimal test case
./chronika.py --browsers chrome --limit 5 --debug
```

## 📈 Use Cases & Examples

### Digital Forensics
```bash
# Timeline reconstruction
./chronika.py --time-from "2025-06-01T08:00:00" --time-to "2025-06-01T18:00:00" --format timeline

# Evidence export
./chronika.py --format elk --no-time-filter --anonymize --output evidence.json

# Network analysis
./chronika.py --format gephi --days 30 --output investigation.gexf
```

### Security Analysis
```bash
# Threat hunting
./chronika.py --search "malware,phishing,suspicious" --format splunk --output threats.log

# Attack pattern analysis  
./chronika.py --domain-include "suspicious.com" --format timeline --no-time-filter

# Login behavior analysis
./chronika.py --search "login,admin,dashboard" --format patterns --group-by hour
```

### Privacy Research
```bash
# Tracking analysis
./chronika.py --search "tracking,analytics,ads" --format top-domains --days 30

# Privacy browser comparison
./chronika.py --browsers brave,firefox,tor --format browser-usage

# Data minimization audit
./chronika.py --anonymize --format csv --days 90 --output privacy_audit.csv
```

### Corporate Monitoring
```bash
# Productivity analysis
./chronika.py --domain-exclude "facebook.com,youtube.com" --format patterns --group-by hour

# Compliance monitoring  
./chronika.py --search "confidential,restricted" --format splunk --output compliance.log

# Bandwidth analysis
./chronika.py --format top-domains --min-visits 50 --days 30
```

### Development & Research
```bash
# Development workflow
./chronika.py --domain-include "github.com,stackoverflow.com" --format patterns

# Research documentation
./chronika.py --search "documentation,tutorial,guide" --format timeline --days 7

# Technology trend analysis
./chronika.py --search "python,javascript,rust" --format stats --days 90
```

### Requirements
- Python 3.6+
- `toml` library
- Linux or macOS
- Read access to browser profile directories

### Development Setup
```bash
git clone https://github.com/user/chronika.git
cd chronika
python3 -m venv dev_env
source dev_env/bin/activate
pip install -r requirements.txt
pip install -r requirements-dev.txt  # If available
```

### Adding New Browsers
1. Implement `get_BROWSER_history_path()` function
2. Determine database format (Chromium-based or Firefox-based)
3. Add to browser configuration in `collect_browser_history()`
4. Update configuration defaults
5. Add documentation and test

### Browser Database Formats
The tool handles three main database timestamp formats:
- **Chromium-based** (Chrome, Brave, Edge, Vivaldi, Opera): Microseconds since 1601-01-01
- **Firefox-based** (Firefox, Tor, LibreWolf): Microseconds since Unix epoch (1970-01-01)  
- **Safari**: Seconds since 2001-01-01 (macOS Core Data reference date)

## 📜 License

This tool is provided for educational, security research, and digital forensics purposes. Users are responsible for compliance with local laws and regulations regarding data privacy and computer access.

**Disclaimer**: Always ensure you have proper authorization before analyzing browser history data, especially in corporate or shared environments.
---

**Chronika** - *Revealing the stories hidden in your browsing history* 🕒
