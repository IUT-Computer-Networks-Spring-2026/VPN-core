"""SQLite user store for the VPN server.

Single table `users`:
    username           TEXT PRIMARY KEY
    password           TEXT NOT NULL            -- SHA-256(username + password) hex
    remaining_quota    INTEGER NOT NULL         -- bytes
    connection_status  TEXT NOT NULL            -- 'connect' | 'disconnect'
    account_status     TEXT NOT NULL            -- 'active' | 'banned' | 'quota_exhausted'
    assigned_ip        TEXT                     -- last assigned IP (nullable)

The hardcoded admin account (admin/admin) is NEVER stored here; the server layer
handles it separately.

All methods are safe to call from multiple threads: every call uses its own
short-lived connection (sqlite3 connections are not shareable across threads)
and writes are serialised by an internal lock so quota updates don't race.
"""

import os
import sqlite3
import threading
from typing import Dict, List, Optional, Tuple

# Account status values.
STATUS_ACTIVE = "active"
STATUS_BANNED = "banned"
STATUS_QUOTA_EXHAUSTED = "quota_exhausted"

# Connection status values.
CONN_CONNECT = "connect"
CONN_DISCONNECT = "disconnect"

# Reserved username that means "applies to every user"; never a real account.
ALL_USERS = "all"

_SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    username           TEXT PRIMARY KEY,
    password           TEXT NOT NULL,
    remaining_quota    INTEGER NOT NULL DEFAULT 0,
    connection_status  TEXT NOT NULL DEFAULT 'disconnect',
    account_status     TEXT NOT NULL DEFAULT 'active',
    assigned_ip        TEXT
);

CREATE TABLE IF NOT EXISTS firewall_domains (
    id       INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL,
    domain   TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS firewall_ips (
    id       INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL,
    ip       TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS traffic_logs (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    username  TEXT NOT NULL,
    dest_ip   TEXT NOT NULL,
    dest_port INTEGER,
    domain    TEXT,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    action    TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_logs_username ON traffic_logs(username);
CREATE INDEX IF NOT EXISTS idx_fw_domains_user ON firewall_domains(username);
CREATE INDEX IF NOT EXISTS idx_fw_ips_user ON firewall_ips(username);
"""


class UserDB:
    """Thread-safe SQLite-backed user store."""

    def __init__(self, path: str = "vpn.db"):
        self.path = path
        self._lock = threading.RLock()
        self._init_schema()

    # -- connection helper ------------------------------------------------ #
    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.path, timeout=30)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA foreign_keys=ON")
        return conn

    def _init_schema(self) -> None:
        with self._lock, self._connect() as conn:
            conn.executescript(_SCHEMA)

    # -- registration / auth --------------------------------------------- #
    def user_exists(self, username: str) -> bool:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT 1 FROM users WHERE username = ?", (username,)
            ).fetchone()
            return row is not None

    def create_user(
        self,
        username: str,
        password_hash: str,
        remaining_quota: int = 0,
    ) -> bool:
        """Insert a new user. Returns False if the username already exists."""
        if username == ALL_USERS:
            return False  # reserved keyword, never a real account
        with self._lock, self._connect() as conn:
            try:
                conn.execute(
                    "INSERT INTO users (username, password, remaining_quota, "
                    "connection_status, account_status, assigned_ip) "
                    "VALUES (?, ?, ?, ?, ?, NULL)",
                    (username, password_hash, int(remaining_quota),
                     CONN_DISCONNECT, STATUS_ACTIVE),
                )
                return True
            except sqlite3.IntegrityError:
                return False

    def get_user(self, username: str) -> Optional[Dict]:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM users WHERE username = ?", (username,)
            ).fetchone()
            return dict(row) if row else None

    def verify_password(self, username: str, password_hash: str) -> bool:
        user = self.get_user(username)
        return bool(user) and user["password"] == password_hash

    # -- connection lifecycle -------------------------------------------- #
    def mark_connected(self, username: str, assigned_ip: str) -> None:
        with self._lock, self._connect() as conn:
            conn.execute(
                "UPDATE users SET connection_status = ?, assigned_ip = ? "
                "WHERE username = ?",
                (CONN_CONNECT, assigned_ip, username),
            )

    def mark_disconnected(self, username: str, remaining_quota: Optional[int] = None) -> None:
        """Set the user offline; optionally persist the final quota."""
        with self._lock, self._connect() as conn:
            if remaining_quota is None:
                conn.execute(
                    "UPDATE users SET connection_status = ?, assigned_ip = NULL "
                    "WHERE username = ?",
                    (CONN_DISCONNECT, username),
                )
            else:
                conn.execute(
                    "UPDATE users SET connection_status = ?, assigned_ip = NULL, "
                    "remaining_quota = ? WHERE username = ?",
                    (CONN_DISCONNECT, max(0, int(remaining_quota)), username),
                )

    # -- quota ------------------------------------------------------------ #
    def get_quota(self, username: str) -> int:
        user = self.get_user(username)
        return int(user["remaining_quota"]) if user else 0

    def set_quota(self, username: str, remaining_quota: int) -> None:
        with self._lock, self._connect() as conn:
            conn.execute(
                "UPDATE users SET remaining_quota = ? WHERE username = ?",
                (max(0, int(remaining_quota)), username),
            )

    def add_quota(self, username: str, extra_bytes: int) -> int:
        """Add quota (admin/portal action). Reactivates a quota-exhausted account.

        Returns the new remaining quota, or -1 if the user does not exist.
        """
        with self._lock, self._connect() as conn:
            row = conn.execute(
                "SELECT remaining_quota, account_status FROM users WHERE username = ?",
                (username,),
            ).fetchone()
            if row is None:
                return -1
            new_quota = max(0, int(row["remaining_quota"]) + int(extra_bytes))
            new_status = row["account_status"]
            if new_status == STATUS_QUOTA_EXHAUSTED and new_quota > 0:
                new_status = STATUS_ACTIVE
            conn.execute(
                "UPDATE users SET remaining_quota = ?, account_status = ? "
                "WHERE username = ?",
                (new_quota, new_status, username),
            )
            return new_quota

    def mark_quota_exhausted(self, username: str) -> None:
        with self._lock, self._connect() as conn:
            conn.execute(
                "UPDATE users SET remaining_quota = 0, account_status = ?, "
                "connection_status = ?, assigned_ip = NULL WHERE username = ?",
                (STATUS_QUOTA_EXHAUSTED, CONN_DISCONNECT, username),
            )

    # -- account status (admin) ------------------------------------------ #
    def set_account_status(self, username: str, status: str) -> bool:
        if status not in (STATUS_ACTIVE, STATUS_BANNED, STATUS_QUOTA_EXHAUSTED):
            raise ValueError(f"invalid account status: {status}")
        with self._lock, self._connect() as conn:
            cur = conn.execute(
                "UPDATE users SET account_status = ? WHERE username = ?",
                (status, username),
            )
            return cur.rowcount > 0

    def ban_user(self, username: str) -> bool:
        return self.set_account_status(username, STATUS_BANNED)

    def unban_user(self, username: str) -> bool:
        return self.set_account_status(username, STATUS_ACTIVE)

    # -- admin queries ---------------------------------------------------- #
    def list_users(self) -> List[Dict]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT username, remaining_quota, connection_status, "
                "account_status, assigned_ip FROM users ORDER BY username"
            ).fetchall()
            return [dict(r) for r in rows]

    def list_online_users(self) -> List[Dict]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT username, remaining_quota, assigned_ip FROM users "
                "WHERE connection_status = ? ORDER BY username",
                (CONN_CONNECT,),
            ).fetchall()
            return [dict(r) for r in rows]

    def reset_all_connections(self) -> None:
        """On server startup, force every user offline (stale flags from a crash)."""
        with self._lock, self._connect() as conn:
            conn.execute(
                "UPDATE users SET connection_status = ?, assigned_ip = NULL",
                (CONN_DISCONNECT,),
            )

    def delete_user(self, username: str) -> bool:
        with self._lock, self._connect() as conn:
            cur = conn.execute("DELETE FROM users WHERE username = ?", (username,))
            return cur.rowcount > 0

    # -- firewall --------------------------------------------------------- #
    def add_firewall_domain(self, username: str, domain: str) -> int:
        """Add a domain-block rule. Returns the new rule id."""
        username = (username or "").strip()
        domain = (domain or "").strip().lower()
        if not username or not domain:
            raise ValueError("username and domain are required")
        with self._lock, self._connect() as conn:
            cur = conn.execute(
                "INSERT INTO firewall_domains (username, domain) VALUES (?, ?)",
                (username, domain),
            )
            return cur.lastrowid

    def add_firewall_ip(self, username: str, ip: str) -> int:
        """Add an IP-block rule. Returns the new rule id."""
        username = (username or "").strip()
        ip = (ip or "").strip()
        if not username or not ip:
            raise ValueError("username and ip are required")
        with self._lock, self._connect() as conn:
            cur = conn.execute(
                "INSERT INTO firewall_ips (username, ip) VALUES (?, ?)",
                (username, ip),
            )
            return cur.lastrowid

    def remove_firewall_rule(self, rule_id: int, rule_type: str) -> bool:
        """Delete a firewall rule. `rule_type` is 'domain' or 'ip'."""
        table = {"domain": "firewall_domains", "ip": "firewall_ips"}.get(rule_type)
        if table is None:
            raise ValueError("rule_type must be 'domain' or 'ip'")
        with self._lock, self._connect() as conn:
            cur = conn.execute(f"DELETE FROM {table} WHERE id = ?", (int(rule_id),))
            return cur.rowcount > 0

    def list_firewall_rules(self) -> Dict[str, List[Dict]]:
        with self._connect() as conn:
            domains = [dict(r) for r in conn.execute(
                "SELECT id, username, domain FROM firewall_domains ORDER BY id"
            ).fetchall()]
            ips = [dict(r) for r in conn.execute(
                "SELECT id, username, ip FROM firewall_ips ORDER BY id"
            ).fetchall()]
        return {"domains": domains, "ips": ips}

    def get_firewall_for_user(self, username: str) -> Tuple[set, set]:
        """Return (blocked_domains, blocked_ips) applying to this user + 'all'."""
        with self._connect() as conn:
            drows = conn.execute(
                "SELECT domain FROM firewall_domains WHERE username = ? OR username = ?",
                (username, ALL_USERS),
            ).fetchall()
            irows = conn.execute(
                "SELECT ip FROM firewall_ips WHERE username = ? OR username = ?",
                (username, ALL_USERS),
            ).fetchall()
        return ({r["domain"].lower() for r in drows}, {r["ip"] for r in irows})

    # -- traffic logs ----------------------------------------------------- #
    def log_traffic(self, username: str, dest_ip: str, dest_port: Optional[int],
                    domain: Optional[str], action: str) -> None:
        with self._lock, self._connect() as conn:
            conn.execute(
                "INSERT INTO traffic_logs (username, dest_ip, dest_port, domain, action) "
                "VALUES (?, ?, ?, ?, ?)",
                (username, dest_ip,
                 int(dest_port) if dest_port is not None else None,
                 domain, action),
            )

    def get_traffic_logs(self, username: Optional[str] = None,
                         limit: int = 500) -> List[Dict]:
        limit = max(1, min(int(limit), 100_000))
        with self._connect() as conn:
            if username:
                rows = conn.execute(
                    "SELECT id, username, dest_ip, dest_port, domain, timestamp, action "
                    "FROM traffic_logs WHERE username = ? ORDER BY id DESC LIMIT ?",
                    (username, limit),
                ).fetchall()
            else:
                rows = conn.execute(
                    "SELECT id, username, dest_ip, dest_port, domain, timestamp, action "
                    "FROM traffic_logs ORDER BY id DESC LIMIT ?",
                    (limit,),
                ).fetchall()
            return [dict(r) for r in rows]

    def clear_traffic_logs(self) -> None:
        with self._lock, self._connect() as conn:
            conn.execute("DELETE FROM traffic_logs")
