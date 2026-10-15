#!/usr/bin/env python3
"""
Browser History Timeline Visualization Tool
Reads browser history and displays it in chronological timeline format
"""

import sqlite3
import json
import csv
import os
import re
import sys
from datetime import datetime, timedelta
from pathlib import Path
import argparse
import toml
from typing import List, Dict, Optional
from collections import Counter, defaultdict
from urllib.parse import urlparse, parse_qs

import tempfile
import shutil
import gzip


# Configuration defaults
DEFAULT_CONFIG = {
    "browsers": {
        "chrome": True,
        "firefox": True,
        "safari": True,
        "brave": True,
        "opera": True,
        "edge": True,
        "vivaldi": True,
        "tor": True,
        "chromium": True,
        "librewolf": True
    },
    "output": {
        "format": "timeline",  # timeline, json, csv, stats, top-domains, browser-usage, patterns
        "limit": 100,
        "days_back": 7
    },
    "display": {
        "show_url": True,
        "show_visit_count": True,
        "date_format": "%Y-%m-%d %H:%M:%S",
        "use_emoji": True
    },
    "filters": {
        "domain_whitelist": [],
        "domain_blacklist": [],
        "keywords": [],
        "min_visit_count": 1,
        "max_visit_count": None,
        "time_from": None,
        "time_to": None,
        "use_regex": False
    },
    "analytics": {
        "enable_stats": True,
        "group_patterns_by": "hour",  # hour, day, weekday
        "top_domains_limit": 20,
        "include_subdomains": True
    },
    "exports": {
        "include_metadata": True,
        "anonymize_urls": False,
        "compress_output": False,
        "include_user_agent": False
    }
}


def load_config(config_path: str = "browser_history.toml") -> Dict:
    """Load configuration from TOML file"""
    if os.path.exists(config_path):
        try:
            return toml.load(config_path)
        except Exception as e:
            print(f"Error loading config: {e}")
            return DEFAULT_CONFIG
    return DEFAULT_CONFIG


def create_default_config(config_path: str = "browser_history.toml") -> None:
    """Create default configuration file"""
    with open(config_path, 'w') as f:
        toml.dump(DEFAULT_CONFIG, f)
    print(f"Created default config: {config_path}")


# --- Emoji handling ---------------------------------------------------------
# Decorative icons are printed as literals all over this module. Rather than
# threading a flag through every print call, --no-emoji (or display.use_emoji
# = false) installs a proxy on sys.stdout/stderr that strips emoji sequences,
# plus the spacing that followed them, from everything written to the
# terminal. File exports are unaffected. Box-drawing characters (█ │ ═ ─) and
# plain arrows (→) are deliberately not matched.
_EMOJI_RE = re.compile(
    "(?:"
    "[\U0001F000-\U0001FAFF]"   # pictographs, emoticons, enclosed alnum (SMP)
    "|[\u2300-\u23FF]"          # misc technical: ⌨ ⏰ …
    "|[\u2600-\u27BF]"          # misc symbols & dingbats: ⚙ ✅ ❌ …
    "|[\u2B00-\u2BFF]"          # misc symbols & arrows: ⭐ …
    "|[\u25B6\u25C0]"           # ▶ ◀
    ")"
    "[\uFE0F\u200D\u20E3\U0001F000-\U0001FAFF]*"  # VS16, ZWJ, keycap, joined parts
    "[ \t]*"                     # swallow the spacing that followed the icon
    "|[\uFE0F\u200D\u20E3]"     # stray modifiers
)


def strip_emoji(text: str) -> str:
    """Remove emoji sequences (and the whitespace right after them)."""
    return _EMOJI_RE.sub("", text)


class _EmojiStrippingStream:
    """Thin proxy around a text stream that strips emoji on write()."""

    def __init__(self, stream):
        self._stream = stream

    def write(self, text):
        return self._stream.write(strip_emoji(text))

    def __getattr__(self, name):
        return getattr(self._stream, name)


def disable_emoji_output() -> None:
    """Route stdout and stderr through the emoji-stripping proxy (idempotent)."""
    for name in ("stdout", "stderr"):
        stream = getattr(sys, name)
        if not isinstance(stream, _EmojiStrippingStream):
            setattr(sys, name, _EmojiStrippingStream(stream))


def extract_domain(url: str) -> str:
    """Extract domain from URL"""
    try:
        parsed = urlparse(url)
        return parsed.netloc.lower()
    except:
        return ""


# Known search engines: (domain substring, query parameter, display label).
# Order matters — more specific hosts (e.g. search.brave.com) must precede
# broader ones. If the mapped parameter is missing, "q" is tried as fallback.
SEARCH_ENGINES = [
    ("google.", "q", "Google"),
    ("bing.com", "q", "Bing"),
    ("duckduckgo.com", "q", "DuckDuckGo"),
    ("search.brave.com", "q", "Brave"),
    ("search.yahoo.", "p", "Yahoo"),
    ("ecosia.org", "q", "Ecosia"),
    ("startpage.com", "query", "Startpage"),
    ("qwant.com", "q", "Qwant"),
    ("yandex.", "text", "Yandex"),
    ("baidu.com", "wd", "Baidu"),
    ("youtube.com", "search_query", "YouTube"),
    ("amazon.", "k", "Amazon"),
    ("github.com", "q", "GitHub"),
    ("stackoverflow.com", "q", "Stack Overflow"),
]


def extract_search_query(url: str) -> Optional[Dict]:
    """If the URL is a search-engine results page, return {engine, query}.

    Ebene A: the query is already embedded in the visited URL (e.g. the
    ?q=... parameter), so no extra database access is needed.
    """
    try:
        parsed = urlparse(url)
        domain = parsed.netloc.lower()
        if not domain:
            return None
        params = parse_qs(parsed.query)
        for host_sub, param, label in SEARCH_ENGINES:
            if host_sub in domain:
                # Google's /url? links are outbound redirects, not searches
                if label == "Google" and parsed.path.startswith("/url"):
                    return None
                values = params.get(param) or params.get("q")
                if values and values[0].strip():
                    return {"engine": label, "query": values[0].strip()}
                return None
        return None
    except Exception:
        return None


def anonymize_url(url: str) -> str:
    """Anonymize URL for privacy"""
    try:
        parsed = urlparse(url)
        # Keep scheme and domain, hash the path
        domain = parsed.netloc
        path_hash = hash(parsed.path + parsed.query) % 10000
        return f"{parsed.scheme}://{domain}/path_{path_hash}"
    except:
        return "anonymized_url"


# --- Helper functions for anonymization, metadata, temp DB copy ---
def maybe_anonymize(url: str, config: Dict) -> str:
    """Return anonymized URL if enabled in config."""
    try:
        if config.get("exports", {}).get("anonymize_urls"):
            return anonymize_url(url)
        return url
    except Exception:
        return url

def write_metadata_sidecar(filename: str, config: Dict, count: int) -> None:
    """Write a small sidecar JSON with export metadata if enabled."""
    exports = config.get("exports", {})
    if not exports.get("include_metadata", False):
        return
    meta = {
        "generated_at": datetime.now().isoformat(),
        "entries": count,
        "anonymized": bool(exports.get("anonymize_urls")),
        "compressed": bool(exports.get("compress_output")),
        "tool": "chronika",
        "version": 1
    }
    meta_path = f"{filename}.meta.json"
    try:
        with open(meta_path, "w") as mf:
            json.dump(meta, mf, indent=2)
    except Exception:
        pass

def copy_db_to_temp(db_path: Path, browser_name: str) -> Path:
    """Copy a locked browser DB to a temp file and return the temp path."""
    temp_dir = Path(tempfile.gettempdir())
    temp_db = temp_dir / f"{browser_name.lower()}_history_{os.getpid()}.db"
    try:
        shutil.copy2(db_path, temp_db)
    except Exception:
        # Fallback to basic copy
        shutil.copyfile(db_path, temp_db)
    return temp_db


def get_chrome_history_path() -> Optional[Path]:
    """Get Chrome history database path"""
    system = os.uname().sysname
    home = Path.home()
    
    paths = {
        "Darwin": home / "Library/Application Support/Google/Chrome/Default/History",
        "Linux": home / ".config/google-chrome/Default/History"
    }
    
    path = paths.get(system)
    return path if path and path.exists() else None


def _find_places_databases(profile_dir: Path) -> List[Path]:
    """Return every non-empty places.sqlite under a Mozilla-style profile dir.

    Scans all profiles, not just ones whose folder name contains "default",
    so custom-named profiles (e.g. "Profil 1") are included. Ordered
    largest-first so the profile holding the most history is read first.
    """
    if not profile_dir.exists():
        return []

    def _size(p: Path) -> int:
        try:
            return p.stat().st_size
        except Exception:
            return 0

    dbs = []
    for profile in profile_dir.iterdir():
        try:
            if not profile.is_dir():
                continue
            history_path = profile / "places.sqlite"
            if history_path.exists() and _size(history_path) > 0:
                dbs.append(history_path)
        except Exception:
            continue
    dbs.sort(key=_size, reverse=True)
    return dbs


def get_firefox_history_path() -> List[Path]:
    """Get Firefox history database paths (all profiles with data)"""
    system = os.uname().sysname
    home = Path.home()

    if system == "Darwin":
        profile_dir = home / "Library/Application Support/Firefox/Profiles"
    else:
        profile_dir = home / ".mozilla/firefox"

    return _find_places_databases(profile_dir)


def get_safari_history_path() -> Optional[Path]:
    """Get Safari history database path (macOS only)"""
    if os.uname().sysname != "Darwin":
        return None
    
    home = Path.home()
    
    # Try multiple possible Safari history locations
    safari_paths = [
        home / "Library/Safari/History.db",
        home / "Library/Safari/History.sqlite",
        home / "Library/Safari/UserData/History.db",
        home / "Library/Containers/com.apple.Safari/Data/Library/Safari/History.db"
    ]
    
    for path in safari_paths:
        if path.exists():
            try:
                if os.access(path, os.R_OK):
                    return path
            except Exception:
                pass
    
    return None


def get_brave_history_path() -> Optional[Path]:
    """Get Brave history database path"""
    system = os.uname().sysname
    home = Path.home()
    
    paths = {
        "Darwin": home / "Library/Application Support/BraveSoftware/Brave-Browser/Default/History",
        "Linux": home / ".config/BraveSoftware/Brave-Browser/Default/History"
    }
    
    path = paths.get(system)
    return path if path and path.exists() else None


def get_opera_history_path() -> Optional[Path]:
    """Get Opera history database path"""
    system = os.uname().sysname
    home = Path.home()
    
    paths = {
        "Darwin": home / "Library/Application Support/com.operasoftware.Opera/History",
        "Linux": home / ".config/opera/History"
    }
    
    path = paths.get(system)
    return path if path and path.exists() else None


def get_edge_history_path() -> Optional[Path]:
    """Get Microsoft Edge history database path"""
    system = os.uname().sysname
    home = Path.home()
    
    paths = {
        "Darwin": home / "Library/Application Support/Microsoft Edge/Default/History",
        "Linux": home / ".config/microsoft-edge/Default/History"
    }
    
    path = paths.get(system)
    return path if path and path.exists() else None


def get_vivaldi_history_path() -> Optional[Path]:
    """Get Vivaldi history database path"""
    system = os.uname().sysname
    home = Path.home()
    
    paths = {
        "Darwin": home / "Library/Application Support/Vivaldi/Default/History",
        "Linux": home / ".config/vivaldi/Default/History"
    }
    
    path = paths.get(system)
    return path if path and path.exists() else None


def get_tor_history_path() -> List[Path]:
    """Get Tor Browser history database paths (all profiles with data)"""
    system = os.uname().sysname
    home = Path.home()

    # Tor Browser uses different paths and profile naming
    if system == "Darwin":
        tor_dir = home / "Library/Application Support/TorBrowser-Data/Browser"
    else:
        tor_dir = home / ".tor-browser/app/Browser/TorBrowser/Data/Browser"

    if not tor_dir.exists():
        # Alternative Linux path
        tor_dir = home / "Desktop/tor-browser_en-US/Browser/TorBrowser/Data/Browser"

    return _find_places_databases(tor_dir)


def get_chromium_history_path() -> Optional[Path]:
    """Get Chromium history database path"""
    system = os.uname().sysname
    home = Path.home()
    
    paths = {
        "Darwin": home / "Library/Application Support/Chromium/Default/History",
        "Linux": home / ".config/chromium/Default/History"
    }
    
    path = paths.get(system)
    return path if path and path.exists() else None


def get_librewolf_history_path() -> List[Path]:
    """Get LibreWolf history database paths (all profiles with data)"""
    system = os.uname().sysname
    home = Path.home()

    if system == "Darwin":
        profile_dir = home / "Library/Application Support/LibreWolf/Profiles"
    else:
        profile_dir = home / ".librewolf"

    return _find_places_databases(profile_dir)


def extract_chromium_based_history(db_path: Path, days_back: int, limit: int, browser_name: str, debug: bool = False, no_time_filter: bool = False) -> List[Dict]:
    """Extract history from Chromium-based browsers (Chrome, Brave, Edge, Vivaldi, Chromium, Opera)"""
    history_entries = []
    
    if not no_time_filter:
        cutoff_time = datetime.now() - timedelta(days=days_back)
        # Chromium uses microseconds since 1601-01-01
        chrome_epoch = datetime(1601, 1, 1)
        cutoff_chrome_time = int((cutoff_time - chrome_epoch).total_seconds() * 1000000)
    else:
        cutoff_time = None
        cutoff_chrome_time = 0  # Get all entries
        chrome_epoch = datetime(1601, 1, 1)
    
    if debug:
        print(f"🔍 Debugging {browser_name} database: {db_path}")
        if no_time_filter:
            print(f"   📅 No time filtering - searching entire history")
        else:
            print(f"   📅 Looking for entries newer than: {cutoff_time}")
            print(f"   🕐 Chromium timestamp cutoff: {cutoff_chrome_time}")
    
    try:
        # Copy database to avoid locks
        temp_db = copy_db_to_temp(db_path, browser_name)
        conn = sqlite3.connect(str(temp_db))
        cursor = conn.cursor()
        
        if debug:
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
            tables = [row[0] for row in cursor.fetchall()]
            print(f"   📋 Available tables: {tables}")
            
            # Check total entries in database
            cursor.execute("SELECT COUNT(*) FROM urls")
            total_entries = cursor.fetchone()[0]
            print(f"   📊 Total entries in database: {total_entries:,}")
        
        if no_time_filter:
            query = """
            SELECT url, title, visit_count, last_visit_time
            FROM urls 
            ORDER BY last_visit_time DESC
            LIMIT ?
            """
            cursor.execute(query, (limit,))
        else:
            query = """
            SELECT url, title, visit_count, last_visit_time
            FROM urls 
            WHERE last_visit_time > ?
            ORDER BY last_visit_time DESC
            LIMIT ?
            """
            cursor.execute(query, (cutoff_chrome_time, limit))
        
        rows = cursor.fetchall()
        
        if debug:
            print(f"   📊 Found {len(rows)} raw entries")
            if rows:
                print(f"   📋 Sample row: {rows[0]}")
        
        for row in rows:
            url, title, visit_count, last_visit_time = row
            
            # Convert Chromium time to datetime
            if last_visit_time:
                visit_datetime = chrome_epoch + timedelta(microseconds=last_visit_time)
                history_entries.append({
                    "browser": browser_name,
                    "url": url,
                    "title": title or "No Title",
                    "visit_count": visit_count,
                    "timestamp": visit_datetime,
                    "date_str": visit_datetime.strftime("%Y-%m-%d %H:%M:%S")
                })
        conn.close()
        try:
            if Path(temp_db).exists():
                Path(temp_db).unlink()
        except Exception:
            pass
        if debug:
            print(f"   ✅ Successfully parsed {len(history_entries)} entries")
    except Exception as e:
        if debug:
            print(f"❌ Error reading {browser_name} history: {e}")
        else:
            print(f"Error reading {browser_name} history: {e}")
    
    return history_entries


def extract_chromium_search_terms(db_path: Path, days_back: int, limit: int, browser_name: str, debug: bool = False, no_time_filter: bool = False) -> List[Dict]:
    """Ebene B: read typed search terms from a Chromium keyword_search_terms table."""
    results = []
    chrome_epoch = datetime(1601, 1, 1)
    if not no_time_filter:
        cutoff_time = datetime.now() - timedelta(days=days_back)
        cutoff = int((cutoff_time - chrome_epoch).total_seconds() * 1000000)
    else:
        cutoff = 0

    temp_db = None
    try:
        temp_db = copy_db_to_temp(db_path, browser_name + "_kst")
        conn = sqlite3.connect(str(temp_db))
        cursor = conn.cursor()

        # Table is absent on very old / empty profiles
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='keyword_search_terms'")
        if not cursor.fetchone():
            conn.close()
            return results

        if no_time_filter:
            query = """
            SELECT kst.term, u.url, u.last_visit_time
            FROM keyword_search_terms kst
            JOIN urls u ON u.id = kst.url_id
            ORDER BY u.last_visit_time DESC
            LIMIT ?
            """
            cursor.execute(query, (limit,))
        else:
            query = """
            SELECT kst.term, u.url, u.last_visit_time
            FROM keyword_search_terms kst
            JOIN urls u ON u.id = kst.url_id
            WHERE u.last_visit_time > ?
            ORDER BY u.last_visit_time DESC
            LIMIT ?
            """
            cursor.execute(query, (cutoff, limit))

        rows = cursor.fetchall()
        if debug:
            print(f"   🔎 {browser_name} keyword_search_terms: {len(rows)} rows")

        for term, url, last_visit_time in rows:
            if not term or not last_visit_time:
                continue
            ts = chrome_epoch + timedelta(microseconds=last_visit_time)
            info = extract_search_query(url or "")
            engine = info["engine"] if info else "Search"
            results.append({
                "browser": browser_name,
                "source": "keyword_search_terms",
                "engine": engine,
                "query": term,
                "url": url or "",
                "timestamp": ts,
            })
        conn.close()
    except Exception as e:
        if debug:
            print(f"❌ Error reading {browser_name} search terms: {e}")
    finally:
        try:
            if temp_db and Path(temp_db).exists():
                Path(temp_db).unlink()
        except Exception:
            pass
    return results


def extract_firefox_based_history(db_path: Path, days_back: int, limit: int, browser_name: str, debug: bool = False, no_time_filter: bool = False) -> List[Dict]:
    """Extract history from Firefox-based browsers (Firefox, Tor Browser, LibreWolf)"""
    history_entries = []
    
    if not no_time_filter:
        cutoff_time = datetime.now() - timedelta(days=days_back)
        # Firefox uses microseconds since Unix epoch
        cutoff_firefox_time = int(cutoff_time.timestamp() * 1000000)
    else:
        cutoff_time = None
        cutoff_firefox_time = 0  # Get all entries
    
    if debug:
        print(f"🔍 Debugging {browser_name} database: {db_path}")
        if no_time_filter:
            print(f"   📅 No time filtering - searching entire history")
        else:
            print(f"   📅 Looking for entries newer than: {cutoff_time}")
            print(f"   🕐 Firefox timestamp cutoff: {cutoff_firefox_time}")
    
    try:
        temp_db = copy_db_to_temp(db_path, browser_name)
        conn = sqlite3.connect(str(temp_db))
        cursor = conn.cursor()
        
        if debug:
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
            tables = [row[0] for row in cursor.fetchall()]
            print(f"   📋 Available tables: {tables}")
            
            # Check total entries
            cursor.execute("SELECT COUNT(*) FROM moz_places")
            total_entries = cursor.fetchone()[0]
            print(f"   📊 Total entries in database: {total_entries:,}")
        
        if no_time_filter:
            query = """
            SELECT p.url, p.title, p.visit_count, h.visit_date
            FROM moz_places p
            JOIN moz_historyvisits h ON p.id = h.place_id
            ORDER BY h.visit_date DESC
            LIMIT ?
            """
            cursor.execute(query, (limit,))
        else:
            query = """
            SELECT p.url, p.title, p.visit_count, h.visit_date
            FROM moz_places p
            JOIN moz_historyvisits h ON p.id = h.place_id
            WHERE h.visit_date > ?
            ORDER BY h.visit_date DESC
            LIMIT ?
            """
            cursor.execute(query, (cutoff_firefox_time, limit))
        
        rows = cursor.fetchall()
        
        if debug:
            print(f"   📊 Found {len(rows)} raw entries")
            if rows:
                print(f"   📋 Sample row: {rows[0]}")
        
        for row in rows:
            url, title, visit_count, visit_date = row
            
            if visit_date:
                visit_datetime = datetime.fromtimestamp(visit_date / 1000000)
                history_entries.append({
                    "browser": browser_name,
                    "url": url,
                    "title": title or "No Title",
                    "visit_count": visit_count,
                    "timestamp": visit_datetime,
                    "date_str": visit_datetime.strftime("%Y-%m-%d %H:%M:%S")
                })
        conn.close()
        try:
            if Path(temp_db).exists():
                Path(temp_db).unlink()
        except Exception:
            pass
        if debug:
            print(f"   ✅ Successfully parsed {len(history_entries)} entries")
    except Exception as e:
        if debug:
            print(f"❌ Error reading {browser_name} history: {e}")
        else:
            print(f"Error reading {browser_name} history: {e}")
    
    return history_entries


def extract_firefox_search_terms(places_path: Path, days_back: int, limit: int, browser_name: str, debug: bool = False, no_time_filter: bool = False) -> List[Dict]:
    """Ebene B: read search-bar terms from the sibling formhistory.sqlite.

    Firefox stores search-bar input in formhistory.sqlite (a separate file
    next to places.sqlite), under fieldname 'searchbar-history'.
    """
    results = []
    form_path = Path(places_path).parent / "formhistory.sqlite"
    if not form_path.exists():
        if debug:
            print(f"   🔎 {browser_name}: no formhistory.sqlite next to {places_path.name}")
        return results

    if not no_time_filter:
        cutoff = int((datetime.now() - timedelta(days=days_back)).timestamp() * 1000000)
    else:
        cutoff = 0

    temp_db = None
    try:
        temp_db = copy_db_to_temp(form_path, browser_name + "_form")
        conn = sqlite3.connect(str(temp_db))
        cursor = conn.cursor()

        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='moz_formhistory'")
        if not cursor.fetchone():
            conn.close()
            return results

        if no_time_filter:
            query = """
            SELECT value, lastUsed
            FROM moz_formhistory
            WHERE fieldname = 'searchbar-history'
            ORDER BY lastUsed DESC
            LIMIT ?
            """
            cursor.execute(query, (limit,))
        else:
            query = """
            SELECT value, lastUsed
            FROM moz_formhistory
            WHERE fieldname = 'searchbar-history' AND lastUsed > ?
            ORDER BY lastUsed DESC
            LIMIT ?
            """
            cursor.execute(query, (cutoff, limit))

        rows = cursor.fetchall()
        if debug:
            print(f"   🔎 {browser_name} searchbar-history: {len(rows)} rows")

        for value, last_used in rows:
            if not value or not last_used:
                continue
            ts = datetime.fromtimestamp(last_used / 1000000)
            results.append({
                "browser": browser_name,
                "source": "searchbar",
                "engine": "Searchbar",
                "query": value,
                "url": "",
                "timestamp": ts,
            })
        conn.close()
    except Exception as e:
        if debug:
            print(f"❌ Error reading {browser_name} search terms: {e}")
    finally:
        try:
            if temp_db and Path(temp_db).exists():
                Path(temp_db).unlink()
        except Exception:
            pass
    return results


def extract_safari_history(db_path: Path, days_back: int, limit: int, debug: bool = False) -> List[Dict]:
    """Extract history from Safari database"""
    history_entries = []
    cutoff_time = datetime.now() - timedelta(days=days_back)
    # Safari uses seconds since 2001-01-01
    safari_epoch = datetime(2001, 1, 1)
    cutoff_safari_time = (cutoff_time - safari_epoch).total_seconds()
    
    if debug:
        print(f"🔍 Debugging Safari database: {db_path}")
        print(f"   📅 Looking for entries newer than: {cutoff_time}")
        print(f"   🕐 Safari timestamp cutoff: {cutoff_safari_time}")
    
    try:
        temp_db = copy_db_to_temp(db_path, "safari")
        conn = sqlite3.connect(str(temp_db))
        cursor = conn.cursor()
        
        # Check which tables exist
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
        tables = [row[0] for row in cursor.fetchall()]
        
        if debug:
            print(f"   📋 Available tables: {tables}")
            
            # Check table schemas
            for table in tables:
                if 'history' in table.lower():
                    cursor.execute(f"PRAGMA table_info({table})")
                    columns = cursor.fetchall()
                    print(f"   📋 Table '{table}' columns: {[col[1] for col in columns]}")
        
        # Try different query approaches
        queries_to_try = []
        
        if 'history_visits' in tables and 'history_items' in tables:
            queries_to_try.append((
                "New Safari format (with joins)",
                """
                SELECT hi.url, hv.title, hi.visit_count, hv.visit_time
                FROM history_items hi
                JOIN history_visits hv ON hi.id = hv.history_item
                WHERE hv.visit_time > ?
                ORDER BY hv.visit_time DESC
                LIMIT ?
                """
            ))
        
        if 'history_items' in tables:
            queries_to_try.append((
                "Direct history_items",
                """
                SELECT url, title, visit_count, visit_time
                FROM history_items
                WHERE visit_time > ?
                ORDER BY visit_time DESC
                LIMIT ?
                """
            ))
            
            # Also try without time filter to see if there's any data
            if debug:
                queries_to_try.append((
                    "All history_items (no time filter)",
                    """
                    SELECT url, title, visit_count, visit_time
                    FROM history_items
                    ORDER BY visit_time DESC
                    LIMIT ?
                    """
                ))
        
        for query_name, query in queries_to_try:
            if debug:
                print(f"   🔍 Trying: {query_name}")
            
            try:
                if "no time filter" in query_name:
                    cursor.execute(query, (limit,))
                else:
                    cursor.execute(query, (cutoff_safari_time, limit))
                
                rows = cursor.fetchall()
                
                if debug:
                    print(f"   📊 Found {len(rows)} raw entries")
                    if rows:
                        print(f"   📋 Sample row: {rows[0]}")
                
                if rows:
                    for row in rows:
                        url, title, visit_count, visit_time = row
                        
                        if visit_time and url:
                            # Convert Safari time to datetime
                            try:
                                visit_datetime = safari_epoch + timedelta(seconds=visit_time)
                                
                                # Only add if within time range (for queries without time filter)
                                if "no time filter" not in query_name or visit_datetime >= cutoff_time:
                                    history_entries.append({
                                        "browser": "Safari",
                                        "url": url,
                                        "title": title or "No Title", 
                                        "visit_count": visit_count or 1,
                                        "timestamp": visit_datetime,
                                        "date_str": visit_datetime.strftime("%Y-%m-%d %H:%M:%S")
                                    })
                            except Exception as e:
                                if debug:
                                    print(f"   ❌ Time conversion error: {e}")
                    
                    if debug:
                        print(f"   ✅ Successfully parsed {len(history_entries)} entries")
                    break  # Use first successful query
                else:
                    if debug:
                        print(f"   ❌ No data found with this query")
                    
            except Exception as e:
                if debug:
                    print(f"   ❌ Query failed: {e}")
        
        conn.close()
        try:
            if Path(temp_db).exists():
                Path(temp_db).unlink()
        except Exception:
            pass
        
    except Exception as e:
        if debug:
            print(f"❌ Error reading Safari history: {e}")
        else:
            print(f"Error reading Safari history: {e}")
    
    if debug:
        print(f"📊 Total Safari entries extracted: {len(history_entries)}")
    return history_entries


def apply_filters(history: List[Dict], config: Dict, debug: bool = False) -> List[Dict]:
    """Apply filtering based on configuration"""
    filtered_history = history
    filters = config.get("filters", {})
    
    if debug and filters:
        print(f"🔍 Applying filters to {len(history)} entries...")
    
    # Domain whitelist filter
    domain_whitelist = filters.get("domain_whitelist", [])
    if domain_whitelist:
        initial_count = len(filtered_history)
        if filters.get("use_regex", False):
            whitelist_patterns = [re.compile(pattern, re.IGNORECASE) for pattern in domain_whitelist]
            filtered_history = [
                entry for entry in filtered_history
                if any(pattern.search(extract_domain(entry["url"])) for pattern in whitelist_patterns)
            ]
        else:
            whitelist_domains = [domain.lower() for domain in domain_whitelist]
            filtered_history = [
                entry for entry in filtered_history
                if any(domain in extract_domain(entry["url"]) for domain in whitelist_domains)
            ]
        if debug:
            print(f"   🌐 Domain whitelist: {initial_count} → {len(filtered_history)} entries")
    
    # Domain blacklist filter
    domain_blacklist = filters.get("domain_blacklist", [])
    if domain_blacklist:
        initial_count = len(filtered_history)
        if filters.get("use_regex", False):
            blacklist_patterns = [re.compile(pattern, re.IGNORECASE) for pattern in domain_blacklist]
            filtered_history = [
                entry for entry in filtered_history
                if not any(pattern.search(extract_domain(entry["url"])) for pattern in blacklist_patterns)
            ]
        else:
            blacklist_domains = [domain.lower() for domain in domain_blacklist]
            filtered_history = [
                entry for entry in filtered_history
                if not any(domain in extract_domain(entry["url"]) for domain in blacklist_domains)
            ]
        if debug:
            print(f"   🌐 Domain blacklist: {initial_count} → {len(filtered_history)} entries")
    
    # Keyword filter
    keywords = filters.get("keywords", [])
    if keywords:
        initial_count = len(filtered_history)
        if debug:
            print(f"   🔍 Searching for keywords: {keywords}")
            print(f"   📄 Searching in both titles and URLs...")
        
        matches_found = []
        if filters.get("use_regex", False):
            keyword_patterns = [re.compile(keyword, re.IGNORECASE) for keyword in keywords]
            for entry in filtered_history:
                title_matches = [pattern for pattern in keyword_patterns if pattern.search(entry["title"])]
                url_matches = [pattern for pattern in keyword_patterns if pattern.search(entry["url"])]
                if title_matches or url_matches:
                    matches_found.append(entry)
                    if debug and len(matches_found) <= 3:  # Show first few matches
                        match_info = []
                        if title_matches:
                            match_info.append(f"title: '{entry['title'][:50]}'")
                        if url_matches:
                            match_info.append(f"url: '{entry['url'][:50]}'")
                        print(f"      ✅ Match found in {', '.join(match_info)}")
        else:
            keywords_lower = [keyword.lower() for keyword in keywords]
            for entry in filtered_history:
                title_lower = entry["title"].lower()
                url_lower = entry["url"].lower()
                title_matches = [kw for kw in keywords_lower if kw in title_lower]
                url_matches = [kw for kw in keywords_lower if kw in url_lower]
                if title_matches or url_matches:
                    matches_found.append(entry)
                    if debug and len(matches_found) <= 3:  # Show first few matches
                        match_info = []
                        if title_matches:
                            match_info.append(f"title: '{entry['title'][:50]}' (found: {title_matches})")
                        if url_matches:
                            match_info.append(f"url: '{entry['url'][:50]}' (found: {url_matches})")
                        print(f"      ✅ Match found in {', '.join(match_info)}")
        
        filtered_history = matches_found
        if debug:
            print(f"   🔍 Keyword search: {initial_count} → {len(filtered_history)} entries")
            if len(matches_found) > 3:
                print(f"      ... and {len(matches_found) - 3} more matches")
    
    # Visit count filter
    min_visits = filters.get("min_visit_count", 1)
    max_visits = filters.get("max_visit_count")
    if min_visits > 1:
        initial_count = len(filtered_history)
        filtered_history = [entry for entry in filtered_history if entry["visit_count"] >= min_visits]
        if debug:
            print(f"   👁️  Min visits ({min_visits}): {initial_count} → {len(filtered_history)} entries")
    if max_visits:
        initial_count = len(filtered_history)
        filtered_history = [entry for entry in filtered_history if entry["visit_count"] <= max_visits]
        if debug:
            print(f"   👁️  Max visits ({max_visits}): {initial_count} → {len(filtered_history)} entries")
    
    # Time range filter
    time_from = filters.get("time_from")
    time_to = filters.get("time_to")
    if time_from:
        try:
            from_dt = datetime.fromisoformat(time_from.replace('Z', '+00:00'))
            initial_count = len(filtered_history)
            filtered_history = [entry for entry in filtered_history if entry["timestamp"] >= from_dt]
            if debug:
                print(f"   📅 Time from ({time_from}): {initial_count} → {len(filtered_history)} entries")
        except:
            print(f"Warning: Invalid time_from format: {time_from}")
    
    if time_to:
        try:
            to_dt = datetime.fromisoformat(time_to.replace('Z', '+00:00'))
            initial_count = len(filtered_history)
            filtered_history = [entry for entry in filtered_history if entry["timestamp"] <= to_dt]
            if debug:
                print(f"   📅 Time to ({time_to}): {initial_count} → {len(filtered_history)} entries")
        except:
            print(f"Warning: Invalid time_to format: {time_to}")
    
    return filtered_history


def analyze_browsing_patterns(history: List[Dict], group_by: str) -> Dict:
    """Analyze browsing patterns by time"""
    patterns = defaultdict(int)
    
    for entry in history:
        timestamp = entry["timestamp"]
        
        if group_by == "hour":
            key = timestamp.strftime("%H:00")
        elif group_by == "day":
            key = timestamp.strftime("%Y-%m-%d")
        elif group_by == "weekday":
            key = timestamp.strftime("%A")
        elif group_by == "month":
            key = timestamp.strftime("%Y-%m")
        else:
            key = timestamp.strftime("%H:00")  # Default to hour
        
        patterns[key] += 1
    
    # Sort patterns
    if group_by == "hour":
        sorted_patterns = dict(sorted(patterns.items()))
    elif group_by == "weekday":
        weekday_order = ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday"]
        sorted_patterns = {day: patterns.get(day, 0) for day in weekday_order}
    else:
        sorted_patterns = dict(sorted(patterns.items()))
    
    return sorted_patterns


def has_active_filters(config: Dict) -> bool:
    """Check if any content filters are active that require searching more entries"""
    filters = config.get("filters", {})
    
    # Check if any filtering is active
    if filters.get("domain_whitelist") or filters.get("domain_blacklist"):
        return True
    if filters.get("keywords"):
        return True
    if filters.get("min_visit_count", 1) > 1:
        return True
    if filters.get("max_visit_count"):
        return True
    
    return False


def collect_browser_history(config: Dict, debug: bool = False, search_all: bool = False, no_time_filter: bool = False) -> List[Dict]:
    """Collect history from all enabled browsers"""
    all_history = []
    days_back = config["output"]["days_back"]

    # If a specific time_from is set, ensure we fetch enough days to cover it
    try:
        filt = config.get("filters", {})
        tf = filt.get("time_from")
        if tf:
            from_dt = datetime.fromisoformat(tf.replace('Z', '+00:00'))
            delta_days = max(1, (datetime.now() - from_dt).days + 1)
            if delta_days > days_back:
                if debug:
                    print(f"Extending days_back from {days_back} to {delta_days} based on time_from")
                days_back = delta_days
    except Exception:
        pass
    
    # Determine how many entries to fetch from DB
    if search_all or no_time_filter:
        # Search entire database
        db_limit = 999999  # Effectively unlimited
        if debug:
            if no_time_filter:
                print("🔍 Searching entire database with no time filter")
            else:
                print("🔍 Searching entire database (--all mode)")
    elif has_active_filters(config):
        # If filters are active, fetch more entries to ensure we don't miss matches
        db_limit = config["output"]["limit"] * 10  # 10x more for filtering
        if debug:
            print(f"🔍 Active filters detected, fetching {db_limit} entries for filtering")
    else:
        # Normal mode - use configured limit
        db_limit = config["output"]["limit"]
    
    # Browser configurations: (path_function, extract_function, browser_display_name)
    browsers = {
        "chrome": (get_chrome_history_path, lambda p, d, l: extract_chromium_based_history(p, d, l, "Chrome", debug, no_time_filter)),
        "firefox": (get_firefox_history_path, lambda p, d, l: extract_firefox_based_history(p, d, l, "Firefox", debug, no_time_filter)),
        "safari": (get_safari_history_path, lambda p, d, l: extract_safari_history(p, d, l, debug)),
        "brave": (get_brave_history_path, lambda p, d, l: extract_chromium_based_history(p, d, l, "Brave", debug, no_time_filter)),
        "opera": (get_opera_history_path, lambda p, d, l: extract_chromium_based_history(p, d, l, "Opera", debug, no_time_filter)),
        "edge": (get_edge_history_path, lambda p, d, l: extract_chromium_based_history(p, d, l, "Edge", debug, no_time_filter)),
        "vivaldi": (get_vivaldi_history_path, lambda p, d, l: extract_chromium_based_history(p, d, l, "Vivaldi", debug, no_time_filter)),
        "tor": (get_tor_history_path, lambda p, d, l: extract_firefox_based_history(p, d, l, "Tor Browser", debug, no_time_filter)),
        "chromium": (get_chromium_history_path, lambda p, d, l: extract_chromium_based_history(p, d, l, "Chromium", debug, no_time_filter)),
        "librewolf": (get_librewolf_history_path, lambda p, d, l: extract_firefox_based_history(p, d, l, "LibreWolf", debug, no_time_filter))
    }
    
    for browser_name, (path_func, extract_func) in browsers.items():
        if config["browsers"].get(browser_name, False):
            db_paths = path_func()
            # Normalize to a list so browsers with multiple profiles are merged
            if db_paths is None:
                db_paths = []
            elif isinstance(db_paths, (str, Path)):
                db_paths = [db_paths]
            if db_paths:
                print(f"Reading {browser_name.title()} history...")
                for db_path in db_paths:
                    history = extract_func(db_path, days_back, db_limit)
                    all_history.extend(history)
            else:
                if debug:
                    print(f"🔍 {browser_name.title()} history not found (path detection failed)")
                else:
                    print(f"{browser_name.title()} history not found")
    
    # Annotate each entry with a decoded search query (Ebene A) if the URL
    # is a search-engine results page. None otherwise.
    for entry in all_history:
        info = extract_search_query(entry.get("url", ""))
        if info:
            entry["search_engine"] = info["engine"]
            entry["search_query"] = info["query"]
        else:
            entry["search_engine"] = None
            entry["search_query"] = None

    # Sort by timestamp (newest first)
    return sorted(all_history, key=lambda x: x["timestamp"], reverse=True)


def collect_search_terms(config: Dict, debug: bool = False, search_all: bool = False, no_time_filter: bool = False) -> List[Dict]:
    """Ebene B: collect typed search terms from dedicated browser tables."""
    results = []
    days_back = config["output"]["days_back"]

    if search_all or no_time_filter:
        db_limit = 999999
    else:
        db_limit = max(config["output"]["limit"] * 10, 1000)

    # Chromium path functions return a single path; Firefox family return a list
    chromium_browsers = {
        "chrome": (get_chrome_history_path, "Chrome"),
        "brave": (get_brave_history_path, "Brave"),
        "opera": (get_opera_history_path, "Opera"),
        "edge": (get_edge_history_path, "Edge"),
        "vivaldi": (get_vivaldi_history_path, "Vivaldi"),
        "chromium": (get_chromium_history_path, "Chromium"),
    }
    firefox_browsers = {
        "firefox": (get_firefox_history_path, "Firefox"),
        "tor": (get_tor_history_path, "Tor Browser"),
        "librewolf": (get_librewolf_history_path, "LibreWolf"),
    }

    for name, (path_func, label) in chromium_browsers.items():
        if not config["browsers"].get(name, False):
            continue
        path = path_func()
        if not path:
            continue
        results.extend(extract_chromium_search_terms(path, days_back, db_limit, label, debug, no_time_filter))

    for name, (path_func, label) in firefox_browsers.items():
        if not config["browsers"].get(name, False):
            continue
        paths = path_func()
        if not paths:
            continue
        if isinstance(paths, (str, Path)):
            paths = [paths]
        for p in paths:
            results.extend(extract_firefox_search_terms(p, days_back, db_limit, label, debug, no_time_filter))

    return results


def display_timeline(history: List[Dict], config: Dict) -> None:
    """Display history as timeline"""
    if not history:
        print("No history entries found")
        return
    
    print("\n" + "="*80)
    print(f"BROWSER HISTORY TIMELINE ({len(history)} entries)")
    print("="*80)
    
    current_date = None
    
    for entry in history:
        entry_date = entry["timestamp"].strftime("%Y-%m-%d")
        
        # Print date separator
        if current_date != entry_date:
            current_date = entry_date
            print(f"\n📅 {current_date}")
            print("-" * 40)
        
        # Format entry
        time_str = entry["timestamp"].strftime("%H:%M:%S")
        browser_icons = {
            "Chrome": "🌎",
            "Firefox": "🦊", 
            "Safari": "🧭",
            "Brave": "🦁",
            "Opera": "🎭",
            "Edge": "🌐",
            "Vivaldi": "🎨",
            "Tor Browser": "🧅",
            "Chromium": "⚙️",
            "LibreWolf": "🐺"
        }
        browser_icon = browser_icons.get(entry["browser"], "🌐")
        
        print(f"  {time_str} {browser_icon} [{entry['browser']}]")
        print(f"    📄 {entry['title'][:70]}")
        
        if config["display"]["show_url"]:
            print(f"    🔗 {entry['url'][:70]}")
        
        if config["display"]["show_visit_count"] and entry["visit_count"] > 1:
            print(f"    👁️  Visited {entry['visit_count']} times")
        
        print()


def display_searches(searches: List[Dict], config: Dict, search_all: bool = False) -> None:
    """Display extracted search queries grouped by day."""
    # Deduplicate: same browser + query + url counts once (removes the overlap
    # between Ebene A URL decoding and Ebene B keyword_search_terms).
    seen = set()
    unique = []
    for s in searches:
        key = (s["browser"], s["query"].strip().lower(), s.get("url", ""))
        if key in seen:
            continue
        seen.add(key)
        unique.append(s)

    unique.sort(key=lambda x: x["timestamp"], reverse=True)

    if not unique:
        print("No search queries found")
        return

    display_limit = config["output"]["limit"]
    if not search_all and len(unique) > display_limit:
        print(f"Found {len(unique)} searches, showing {display_limit} (use --all for everything)")
        unique = unique[:display_limit]

    print("\n" + "="*80)
    print(f"SEARCH QUERIES ({len(unique)})")
    print("="*80)

    engine_icons = {
        "Google": "🔍", "Bing": "🔎", "DuckDuckGo": "🦆", "YouTube": "▶️",
        "Yahoo": "🅨", "Yandex": "🔴", "Baidu": "🅱", "Amazon": "📦",
        "Ecosia": "🌱", "Startpage": "🧭", "Qwant": "🐧", "Brave": "🦁",
        "GitHub": "🐙", "Stack Overflow": "📚", "Searchbar": "⌨️", "Search": "🔎",
    }

    current_date = None
    for s in unique:
        day = s["timestamp"].strftime("%Y-%m-%d")
        if current_date != day:
            current_date = day
            print(f"\n📅 {current_date}")
            print("-" * 40)
        t = s["timestamp"].strftime("%H:%M:%S")
        engine = s.get("engine") or s.get("source", "")
        icon = engine_icons.get(engine, "🔎")
        print(f"  {t} {icon} [{engine}] ({s['browser']})")
        print(f"    🔎 {s['query'][:100]}")
    print()


def display_top_domains(history: List[Dict], config: Dict) -> None:
    """Display top domains analysis"""
    analytics = config.get("analytics", {})
    limit = analytics.get("top_domains_limit", 20)
    
    domain_counter = Counter()
    domain_visits = defaultdict(int)
    domain_browsers = defaultdict(set)
    
    for entry in history:
        domain = extract_domain(entry["url"])
        if domain:
            domain_counter[domain] += 1
            domain_visits[domain] += entry["visit_count"]
            domain_browsers[domain].add(entry["browser"])
    
    print("\n" + "="*80)
    print(f"TOP {limit} DOMAINS ANALYSIS")
    print("="*80)
    
    print(f"\n🔝 BY FREQUENCY")
    print("-" * 60)
    for i, (domain, count) in enumerate(domain_counter.most_common(limit), 1):
        visits = domain_visits[domain]
        browsers = ", ".join(sorted(domain_browsers[domain]))
        print(f"{i:2d}. {domain}")
        print(f"    📊 {count:,} entries | 👁️  {visits:,} total visits | 🌐 {browsers}")
        print()


def display_browser_usage(history: List[Dict]) -> None:
    """Display detailed browser usage analysis"""
    browser_stats = defaultdict(lambda: {"count": 0, "visits": 0, "unique_domains": set()})
    
    for entry in history:
        browser = entry["browser"]
        domain = extract_domain(entry["url"])
        
        browser_stats[browser]["count"] += 1
        browser_stats[browser]["visits"] += entry["visit_count"]
        if domain:
            browser_stats[browser]["unique_domains"].add(domain)
    
    print("\n" + "="*80)
    print("BROWSER USAGE ANALYSIS")
    print("="*80)
    
    total_entries = len(history)
    total_visits = sum(entry["visit_count"] for entry in history)
    
    for browser in sorted(browser_stats.keys()):
        stats = browser_stats[browser]
        count = stats["count"]
        visits = stats["visits"]
        unique_domains = len(stats["unique_domains"])
        
        count_pct = (count / total_entries * 100) if total_entries > 0 else 0
        visits_pct = (visits / total_visits * 100) if total_visits > 0 else 0
        
        print(f"\n🌐 {browser}")
        print(f"   📊 Entries: {count:,} ({count_pct:.1f}%)")
        print(f"   👁️  Visits: {visits:,} ({visits_pct:.1f}%)")
        print(f"   🌍 Unique domains: {unique_domains:,}")
        print(f"   📈 Avg visits/entry: {(visits/count):.1f}" if count > 0 else "   📈 Avg visits/entry: 0")


def display_patterns(history: List[Dict], config: Dict) -> None:
    """Display browsing patterns analysis"""
    analytics = config.get("analytics", {})
    group_by = analytics.get("group_patterns_by", "hour")
    
    patterns = analyze_browsing_patterns(history, group_by)
    
    print("\n" + "="*80)
    print(f"BROWSING PATTERNS (grouped by {group_by})")
    print("="*80)
    
    max_count = max(patterns.values()) if patterns else 1
    
    for time_slot, count in patterns.items():
        # Create simple bar chart
        bar_length = int((count / max_count) * 50)
        bar = "█" * bar_length
        percentage = (count / len(history) * 100) if history else 0
        
        print(f"{time_slot:>12} │{bar:<50} {count:>6,} ({percentage:4.1f}%)")


def generate_stats(history: List[Dict], config: Dict) -> Dict:
    """Generate browsing statistics"""
    if not history:
        return {}
    
    analytics = config.get("analytics", {})
    
    # Basic stats
    total_entries = len(history)
    total_visits = sum(entry["visit_count"] for entry in history)
    unique_domains = len(set(extract_domain(entry["url"]) for entry in history))
    unique_urls = len(set(entry["url"] for entry in history))
    
    # Time range
    timestamps = [entry["timestamp"] for entry in history]
    time_range = {
        "earliest": min(timestamps).isoformat(),
        "latest": max(timestamps).isoformat(),
        "span_days": (max(timestamps) - min(timestamps)).days
    }
    
    # Browser usage
    browser_usage = Counter(entry["browser"] for entry in history)
    
    # Top domains
    domain_counter = Counter()
    domain_visits = defaultdict(int)
    
    for entry in history:
        domain = extract_domain(entry["url"])
        if domain:
            domain_counter[domain] += 1
            domain_visits[domain] += entry["visit_count"]
    
    top_domains_limit = analytics.get("top_domains_limit", 20)
    top_domains_by_count = domain_counter.most_common(top_domains_limit)
    top_domains_by_visits = sorted(domain_visits.items(), key=lambda x: x[1], reverse=True)[:top_domains_limit]
    
    # Browsing patterns
    patterns = analyze_browsing_patterns(history, analytics.get("group_patterns_by", "hour"))
    
    # Visit frequency analysis
    visit_freq = Counter(entry["visit_count"] for entry in history)
    
    return {
        "summary": {
            "total_entries": total_entries,
            "total_visits": total_visits,
            "unique_domains": unique_domains,
            "unique_urls": unique_urls,
            "average_visits_per_url": round(total_visits / total_entries, 2) if total_entries > 0 else 0
        },
        "time_range": time_range,
        "browser_usage": dict(browser_usage),
        "top_domains": {
            "by_count": top_domains_by_count,
            "by_visits": top_domains_by_visits
        },
        "browsing_patterns": patterns,
        "visit_frequency": dict(visit_freq)
    }


def display_stats(stats: Dict) -> None:
    """Display statistics in formatted output"""
    print("\n" + "="*80)
    print("BROWSER HISTORY STATISTICS")
    print("="*80)
    
    # Summary
    summary = stats.get("summary", {})
    print(f"\n📊 SUMMARY")
    print(f"   Total entries: {summary.get('total_entries', 0):,}")
    print(f"   Total visits: {summary.get('total_visits', 0):,}")
    print(f"   Unique domains: {summary.get('unique_domains', 0):,}")
    print(f"   Unique URLs: {summary.get('unique_urls', 0):,}")
    print(f"   Avg visits/URL: {summary.get('average_visits_per_url', 0)}")
    
    # Time range
    time_range = stats.get("time_range", {})
    if time_range:
        print(f"\n📅 TIME RANGE")
        print(f"   From: {time_range.get('earliest', 'N/A')}")
        print(f"   To: {time_range.get('latest', 'N/A')}")
        print(f"   Span: {time_range.get('span_days', 0)} days")
    
    # Browser usage
    browser_usage = stats.get("browser_usage", {})
    if browser_usage:
        print(f"\n🌐 BROWSER USAGE")
        total_browser_entries = sum(browser_usage.values())
        for browser, count in sorted(browser_usage.items(), key=lambda x: x[1], reverse=True):
            percentage = (count / total_browser_entries * 100) if total_browser_entries > 0 else 0
            print(f"   {browser}: {count:,} ({percentage:.1f}%)")
    
    # Top domains
    top_domains = stats.get("top_domains", {})
    if top_domains.get("by_count"):
        print(f"\n🔝 TOP DOMAINS (by frequency)")
        for domain, count in top_domains["by_count"][:10]:
            print(f"   {domain}: {count:,} visits")
    
    # Browsing patterns
    patterns = stats.get("browsing_patterns", {})
    if patterns:
        print(f"\n⏰ BROWSING PATTERNS")
        for time_slot, count in list(patterns.items())[:12]:  # Show first 12
            print(f"   {time_slot}: {count:,} visits")



def export_json(history: List[Dict], filename: str = "browser_history.json", config: Optional[Dict] = None) -> None:
    """Export history to JSON (optionally anonymized/compressed)."""
    config = config or {"exports": {}}
    exports = config.get("exports", {})
    export_data = []
    for entry in history:
        e = entry.copy()
        e["timestamp"] = e["timestamp"].isoformat()
        e["url"] = maybe_anonymize(e.get("url", ""), config)
        export_data.append(e)
    use_gzip = bool(exports.get("compress_output"))
    out_path = filename if not use_gzip else (filename if filename.endswith(".gz") else f"{filename}.gz")
    if use_gzip:
        with gzip.open(out_path, 'wt', encoding='utf-8') as f:
            json.dump(export_data, f, indent=2)
    else:
        with open(out_path, 'w') as f:
            json.dump(export_data, f, indent=2)
    print(f"History exported to {out_path}")
    write_metadata_sidecar(filename, config, len(export_data))


def export_csv(history: List[Dict], filename: str = "browser_history.csv", config: Optional[Dict] = None) -> None:
    """Export history to CSV (optionally anonymized/compressed)."""
    if not history:
        return
    config = config or {"exports": {}}
    exports = config.get("exports", {})
    fieldnames = ["browser", "timestamp", "title", "url", "visit_count"]
    use_gzip = bool(exports.get("compress_output"))
    out_path = filename if not use_gzip else (filename if filename.endswith(".gz") else f"{filename}.gz")
    if use_gzip:
        fobj = gzip.open(out_path, 'wt', encoding='utf-8', newline='')
    else:
        fobj = open(out_path, 'w', newline='')
    with fobj as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for entry in history:
            writer.writerow({
                "browser": entry["browser"],
                "timestamp": entry["date_str"],
                "title": entry["title"],
                "url": maybe_anonymize(entry["url"], config),
                "visit_count": entry["visit_count"]
            })
    print(f"History exported to {out_path}")
    write_metadata_sidecar(filename, config, len(history))


# --- Additional exporter functions ---
def export_splunk(history: List[Dict], filename: str, config: Dict) -> None:
    """Export as Splunk-friendly key=value log lines."""
    exports = config.get("exports", {})
    use_gzip = bool(exports.get("compress_output"))
    out_path = filename if not use_gzip else (filename if filename.endswith(".gz") else f"{filename}.gz")
    opener = (lambda p: gzip.open(p, 'wt', encoding='utf-8')) if use_gzip else (lambda p: open(p, 'w'))
    with opener(out_path) as f:
        for e in history:
            line = (
                f"time=\"{e['timestamp'].isoformat()}\" "
                f"browser=\"{e['browser']}\" "
                f"visit_count={e['visit_count']} "
                f"domain=\"{extract_domain(e['url'])}\" "
                f"url=\"{maybe_anonymize(e['url'], config)}\" "
                f"title=\"{e['title'].replace('\"','\'')}\""
            )
            f.write(line + "\n")
    print(f"Splunk log exported to {out_path}")
    write_metadata_sidecar(filename, config, len(history))

def export_elk(history: List[Dict], filename: str, config: Dict) -> None:
    """Export as NDJSON suitable for Elastic/Logstash."""
    exports = config.get("exports", {})
    use_gzip = bool(exports.get("compress_output"))
    out_path = filename if not use_gzip else (filename if filename.endswith(".gz") else f"{filename}.gz")
    opener = (lambda p: gzip.open(p, 'wt', encoding='utf-8')) if use_gzip else (lambda p: open(p, 'w'))
    with opener(out_path) as f:
        for e in history:
            doc = {
                "@timestamp": e['timestamp'].isoformat(),
                "browser": e['browser'],
                "title": e['title'],
                "url": maybe_anonymize(e['url'], config),
                "visit_count": e['visit_count'],
                "domain": extract_domain(e['url'])
            }
            f.write(json.dumps(doc) + "\n")
    print(f"ELK NDJSON exported to {out_path}")
    write_metadata_sidecar(filename, config, len(history))

def export_gephi(history: List[Dict], filename: str, config: Dict) -> None:
    """Export a simple domain-to-domain navigation graph in GEXF."""
    # Build nodes (domains) and edges between consecutive visits
    sorted_hist = sorted(history, key=lambda x: x['timestamp'])  # chronological
    nodes: Dict[str, int] = {}
    edges: Dict[tuple, int] = {}
    node_id = 0
    prev_domain = None
    for e in sorted_hist:
        d = extract_domain(e['url'])
        if not d:
            continue
        if d not in nodes:
            nodes[d] = node_id
            node_id += 1
        if prev_domain is not None and prev_domain != d:
            key = (prev_domain, d)
            edges[key] = edges.get(key, 0) + 1
        prev_domain = d
    # Write minimal GEXF
    with open(filename, 'w') as f:
        f.write('<?xml version="1.0" encoding="UTF-8"?>\n')
        f.write('<gexf xmlns="http://www.gexf.net/1.3" version="1.3">\n')
        f.write('  <graph mode="static" defaultedgetype="directed">\n')
        f.write('    <nodes>\n')
        for d, nid in nodes.items():
            f.write(f'      <node id="{nid}" label="{d}"/>\n')
        f.write('    </nodes>\n')
        f.write('    <edges>\n')
        eid = 0
        for (src, dst), w in edges.items():
            f.write(f'      <edge id="{eid}" source="{nodes[src]}" target="{nodes[dst]}" weight="{w}"/>\n')
            eid += 1
        f.write('    </edges>\n')
        f.write('  </graph>\n')
        f.write('</gexf>\n')
    print(f"Gephi GEXF exported to {filename}")
    write_metadata_sidecar(filename, config, len(history))

def export_timeline_json(history: List[Dict], filename: str, config: Dict) -> None:
    """Export a day-grouped timeline JSON for simple web UIs."""
    grouped: Dict[str, List[Dict]] = defaultdict(list)
    for e in history:
        day = e['timestamp'].strftime('%Y-%m-%d')
        grouped[day].append({
            "time": e['timestamp'].strftime('%H:%M:%S'),
            "browser": e['browser'],
            "title": e['title'],
            "url": maybe_anonymize(e['url'], config),
            "visit_count": e['visit_count']
        })
    obj = {"days": grouped}
    with open(filename, 'w') as f:
        json.dump(obj, f, indent=2)
    print(f"Timeline JSON exported to {filename}")
    write_metadata_sidecar(filename, config, sum(len(v) for v in grouped.values()))


def main():
    """Main function"""
    parser = argparse.ArgumentParser(description="Browser History Timeline Tool with Advanced Analytics")
    parser.add_argument("--config", default="browser_history.toml", help="Config file path")
    parser.add_argument("--init-config", action="store_true", help="Create default config file")
    
    # Output options
    parser.add_argument("--format", choices=[
        "timeline", "json", "csv", "stats", "top-domains", "browser-usage", "patterns",
        "searches", "splunk", "elk", "gephi", "timeline-json"
    ], help="Output format")
    
    # Time options
    parser.add_argument("--days", type=int, help="Days back to search")
    parser.add_argument("--time-from", help="Start time (ISO format: 2025-06-01T10:00:00)")
    parser.add_argument("--time-to", help="End time (ISO format: 2025-06-07T18:00:00)")
    
    # Browser selection
    parser.add_argument("--browsers", help="Comma-separated list of browsers (chrome,firefox,safari,brave,opera,edge,vivaldi,tor,chromium,librewolf)")
    parser.add_argument("--exclude-browsers", help="Comma-separated list of browsers to exclude")
    
    # Filtering options
    parser.add_argument("--domain-include", help="Comma-separated domains to include")
    parser.add_argument("--domain-exclude", help="Comma-separated domains to exclude")
    parser.add_argument("--search", help="Search keywords in titles/URLs")
    parser.add_argument("--min-visits", type=int, help="Minimum visit count")
    parser.add_argument("--max-visits", type=int, help="Maximum visit count")
    parser.add_argument("--regex", action="store_true", help="Use regex for domain/keyword filters")
    
    # Output options
    parser.add_argument("--limit", type=int, help="Max entries to show")
    parser.add_argument("--all", action="store_true", help="Search entire database (ignore limit and time window)")
    parser.add_argument("--no-time-filter", action="store_true", help="Disable time filtering (search all history)")
    parser.add_argument("--output", help="Output filename")
    parser.add_argument("--anonymize", action="store_true", help="Anonymize URLs in output")
    parser.add_argument("--no-emoji", action="store_true", help="Plain text output without emoji icons")
    
    # Analytics options
    parser.add_argument("--group-by", choices=["hour", "day", "weekday", "month"], 
                       help="Group patterns by time unit")
    parser.add_argument("--debug", action="store_true", help="Enable debug output for troubleshooting")
    
    args = parser.parse_args()
    
    if args.init_config:
        create_default_config(args.config)
        return
    
    # Load configuration
    config = load_config(args.config)

    # Emoji toggle: must be installed before the first decorated print
    if args.no_emoji:
        config.setdefault("display", {})["use_emoji"] = False
    if not config.get("display", {}).get("use_emoji", True):
        disable_emoji_output()
    
    # Browser selection override
    if args.browsers:
        # Disable all browsers first
        for browser in config["browsers"]:
            config["browsers"][browser] = False
        
        # Enable specified browsers
        selected_browsers = [b.strip().lower() for b in args.browsers.split(",")]
        valid_browsers = config["browsers"].keys()
        
        for browser in selected_browsers:
            if browser in valid_browsers:
                config["browsers"][browser] = True
            else:
                print(f"Warning: Unknown browser '{browser}'. Valid browsers: {', '.join(valid_browsers)}")
    
    if args.exclude_browsers:
        # Disable specified browsers
        excluded_browsers = [b.strip().lower() for b in args.exclude_browsers.split(",")]
        valid_browsers = config["browsers"].keys()
        
        for browser in excluded_browsers:
            if browser in valid_browsers:
                config["browsers"][browser] = False
            else:
                print(f"Warning: Unknown browser '{browser}'. Valid browsers: {', '.join(valid_browsers)}")
    
    # Override config with other command line arguments
    if args.format:
        config["output"]["format"] = args.format
    if args.days:
        config["output"]["days_back"] = args.days
    if args.limit:
        config["output"]["limit"] = args.limit
    
    # Apply filtering arguments
    if args.domain_include:
        config["filters"]["domain_whitelist"] = [d.strip() for d in args.domain_include.split(",")]
    if args.domain_exclude:
        config["filters"]["domain_blacklist"] = [d.strip() for d in args.domain_exclude.split(",")]
    if args.search:
        config["filters"]["keywords"] = [k.strip() for k in args.search.split(",")]
    if args.min_visits:
        config["filters"]["min_visit_count"] = args.min_visits
    if args.max_visits:
        config["filters"]["max_visit_count"] = args.max_visits
    if args.time_from:
        config["filters"]["time_from"] = args.time_from
    if args.time_to:
        config["filters"]["time_to"] = args.time_to
    if args.regex:
        config["filters"]["use_regex"] = True
    
    # Analytics options
    if args.group_by:
        config["analytics"]["group_patterns_by"] = args.group_by
    
    # Export options
    if args.anonymize:
        config["exports"]["anonymize_urls"] = True
    
    # Debug mode
    debug_mode = args.debug
    if debug_mode:
        print("🔍 Debug mode enabled")
    
    # Search mode
    search_all = args.all
    # --all is meant to show the entire database, so it also disables the
    # time window (not just the row limit).
    no_time_filter = args.no_time_filter or args.all
    
    if search_all:
        print("🔍 Searching entire database")
    if no_time_filter:
        print("🔍 No time filtering - searching all history")
    
    # Collect history
    print("Collecting browser history...")
    history = collect_browser_history(config, debug_mode, search_all, no_time_filter)
    
    if not history:
        print("No browser history found")
        return
    
    # Apply filters
    print(f"Found {len(history)} entries, applying filters...")
    filtered_history = apply_filters(history, config, debug_mode)
    
    if not filtered_history:
        print("No entries match the specified filters")
        return
    
    print(f"Filtered to {len(filtered_history)} entries")
    
    # Apply display limit (post-filtering)
    display_limit = config["output"]["limit"]
    if len(filtered_history) > display_limit and not search_all:
        print(f"Limiting display to {display_limit} entries (use --all to show all)")
        filtered_history = filtered_history[:display_limit]
    
    # Output based on format
    output_format = config["output"]["format"]
    
    if output_format == "timeline":
        display_timeline(filtered_history, config)
    
    elif output_format == "stats":
        stats = generate_stats(filtered_history, config)
        display_stats(stats)
    
    elif output_format == "top-domains":
        display_top_domains(filtered_history, config)
    
    elif output_format == "browser-usage":
        display_browser_usage(filtered_history)
    
    elif output_format == "patterns":
        display_patterns(filtered_history, config)

    elif output_format == "searches":
        # Ebene B: typed search terms from dedicated tables
        searches = collect_search_terms(config, debug_mode, search_all, no_time_filter)
        # Ebene A: searches decoded from the visited URLs already collected
        for entry in history:
            if entry.get("search_query"):
                searches.append({
                    "browser": entry["browser"],
                    "source": "url",
                    "engine": entry.get("search_engine") or "",
                    "query": entry["search_query"],
                    "url": entry.get("url", ""),
                    "timestamp": entry["timestamp"],
                })
        display_searches(searches, config, search_all)
    
    elif output_format == "json":
        filename = args.output or "browser_history.json"
        export_json(filtered_history, filename, config)

    elif output_format == "csv":
        filename = args.output or "browser_history.csv"
        export_csv(filtered_history, filename, config)
    
    elif output_format == "splunk":
        filename = args.output or "browser_history_splunk.log"
        export_splunk(filtered_history, filename, config)
    
    elif output_format == "elk":
        filename = args.output or "browser_history_elk.json"
        export_elk(filtered_history, filename, config)
    
    elif output_format == "gephi":
        filename = args.output or "browser_history_network.gexf"
        export_gephi(filtered_history, filename, config)
    
    elif output_format == "timeline-json":
        filename = args.output or "browser_history_timeline.json"
        export_timeline_json(filtered_history, filename, config)


if __name__ == "__main__":
    main()
