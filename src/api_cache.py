"""api_cache.py — Caching and Rate Limiting for External APIs"""
import sqlite3
import json
import threading
import time
from pathlib import Path

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
CACHE_DB_PATH = _PROJECT_ROOT / "data" / "api_cache.db"

class APICache:
    def __init__(self):
        CACHE_DB_PATH.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self.conn = sqlite3.connect(CACHE_DB_PATH, check_same_thread=False)
        self.conn.execute('''
            CREATE TABLE IF NOT EXISTS api_cache (
                key TEXT PRIMARY KEY,
                value TEXT,
                expires_at REAL
            )
        ''')
        self.conn.execute('''
            CREATE TABLE IF NOT EXISTS rate_limits (
                api_name TEXT,
                timestamp REAL
            )
        ''')
        self.conn.commit()

    def get_cached(self, key: str):
        with self._lock:
            cur = self.conn.cursor()
            cur.execute("SELECT value, expires_at FROM api_cache WHERE key = ?", (key,))
            row = cur.fetchone()
            if row:
                if time.time() < row[1]:
                    return json.loads(row[0])
                else:
                    self.conn.execute("DELETE FROM api_cache WHERE key = ?", (key,))
                    self.conn.commit()
            return None

    def set_cache(self, key: str, value: dict, ttl_seconds: int = 86400):
        with self._lock:
            expires_at = time.time() + ttl_seconds
            self.conn.execute("REPLACE INTO api_cache (key, value, expires_at) VALUES (?, ?, ?)",
                              (key, json.dumps(value), expires_at))
            self.conn.commit()

    def enforce_rate_limit(self, api_name: str, max_per_minute: int):
        with self._lock:
            now = time.time()
            minute_ago = now - 60
            cur = self.conn.cursor()

            # Cleanup old timestamps
            cur.execute("DELETE FROM rate_limits WHERE timestamp < ?", (minute_ago,))
            self.conn.commit()

            # Count recent calls
            cur.execute("SELECT timestamp FROM rate_limits WHERE api_name = ? ORDER BY timestamp ASC", (api_name,))
            calls = cur.fetchall()

            if len(calls) >= max_per_minute:
                oldest = calls[0][0]
                sleep_time = 60 - (now - oldest)
                if sleep_time > 0:
                    print(f"[RATE LIMIT] {api_name.upper()} quota hit. Sleeping {sleep_time:.1f}s to respect limits...")
                    time.sleep(sleep_time)

            # Record this call
            cur.execute("INSERT INTO rate_limits (api_name, timestamp) VALUES (?, ?)", (api_name, time.time()))
            self.conn.commit()

# Singleton instance
api_cache = APICache()
