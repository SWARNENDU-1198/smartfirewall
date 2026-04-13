import sqlite3
import os
from datetime import datetime, timedelta

DB_FILE = "firewall_data.db"

def get_connection():
    return sqlite3.connect(DB_FILE)

def init_db():
    conn = get_connection()
    c = conn.cursor()
    
    # Connection Logs
    c.execute('''CREATE TABLE IF NOT EXISTS packet_logs (
                 id INTEGER PRIMARY KEY AUTOINCREMENT,
                 timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                 src_ip TEXT,
                 dst_port INTEGER,
                 status TEXT,
                 threat TEXT,
                 process TEXT)''')
                 
    # Rules Tables
    c.execute('''CREATE TABLE IF NOT EXISTS blocked_ips (ip TEXT PRIMARY KEY)''')
    c.execute('''CREATE TABLE IF NOT EXISTS blocked_ports (port INTEGER PRIMARY KEY)''')
    c.execute('''CREATE TABLE IF NOT EXISTS whitelisted_ips (ip TEXT PRIMARY KEY)''')
    
    # Port Scan Events (separate from normal packet logs)
    c.execute('''CREATE TABLE IF NOT EXISTS port_scan_events (
                 id INTEGER PRIMARY KEY AUTOINCREMENT,
                 timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                 src_ip TEXT,
                 ports_count INTEGER,
                 ports_list TEXT)''')
    
    conn.commit()
    conn.close()

# --- RULE MANAGEMENT ---

def load_rules():
    """Returns (blocked_ips, blocked_ports, whitelisted_ips) sets."""
    conn = get_connection()
    c = conn.cursor()
    
    c.execute("SELECT ip FROM blocked_ips")
    b_ips = {row[0] for row in c.fetchall()}
    
    c.execute("SELECT port FROM blocked_ports")
    b_ports = {row[0] for row in c.fetchall()}
    
    c.execute("SELECT ip FROM whitelisted_ips")
    w_ips = {row[0] for row in c.fetchall()}
    
    conn.close()
    return b_ips, b_ports, w_ips

def add_blocked_ip(ip):
    conn = get_connection()
    try:
        conn.execute("INSERT OR IGNORE INTO blocked_ips (ip) VALUES (?)", (ip,))
        conn.commit()
    finally:
        conn.close()

def remove_blocked_ip(ip):
    conn = get_connection()
    conn.execute("DELETE FROM blocked_ips WHERE ip = ?", (ip,))
    conn.commit()
    conn.close()

def add_blocked_port(port):
    conn = get_connection()
    try:
        conn.execute("INSERT OR IGNORE INTO blocked_ports (port) VALUES (?)", (port,))
        conn.commit()
    finally:
        conn.close()

def remove_blocked_port(port):
    conn = get_connection()
    conn.execute("DELETE FROM blocked_ports WHERE port = ?", (port,))
    conn.commit()
    conn.close()

def add_whitelist_ip(ip):
    conn = get_connection()
    try:
        conn.execute("INSERT OR IGNORE INTO whitelisted_ips (ip) VALUES (?)", (ip,))
        conn.commit()
    finally:
        conn.close()

def remove_whitelist_ip(ip):
    conn = get_connection()
    conn.execute("DELETE FROM whitelisted_ips WHERE ip = ?", (ip,))
    conn.commit()
    conn.close()

# --- LOGGING & ANALYTICS ---

def log_packet(src_ip, dst_port, status, threat, process):
    conn = get_connection()
    conn.execute("INSERT INTO packet_logs (src_ip, dst_port, status, threat, process) VALUES (?, ?, ?, ?, ?)",
                 (src_ip, dst_port, status, threat, process))
    conn.commit()
    conn.close()

def get_analytics_data(minutes=10):
    """Returns data for formatting in matplotlib."""
    conn = get_connection()
    c = conn.cursor()
    
    cutoff = datetime.utcnow() - timedelta(minutes=minutes)
    cutoff_str = cutoff.strftime('%Y-%m-%d %H:%M:%S')
    
    # 1. Threats Over Time (grouped by minute)
    c.execute('''SELECT strftime('%H:%M', timestamp), COUNT(*) 
                 FROM packet_logs 
                 WHERE timestamp >= ? AND status = 'BLOCKED'
                 GROUP BY strftime('%H:%M', timestamp)
                 ORDER BY timestamp ASC''', (cutoff_str,))
    threats_over_time = c.fetchall()
    
    # 2. Top Blocked IPs
    c.execute('''SELECT src_ip, COUNT(*) as count 
                 FROM packet_logs 
                 WHERE status = 'BLOCKED' AND src_ip != '127.0.0.1'
                 GROUP BY src_ip 
                 ORDER BY count DESC LIMIT 5''')
    top_ips = c.fetchall()
    
    conn.close()
    return threats_over_time, top_ips

def log_port_scan(src_ip: str, ports_count: int, ports_list: str):
    """Persist a port scan detection event."""
    conn = get_connection()
    conn.execute(
        "INSERT INTO port_scan_events (src_ip, ports_count, ports_list) VALUES (?, ?, ?)",
        (src_ip, ports_count, ports_list)
    )
    conn.commit()
    conn.close()


def get_port_scan_events(limit: int = 50) -> list:
    """Return recent port scan events, newest first."""
    conn = get_connection()
    c = conn.cursor()
    c.execute(
        "SELECT src_ip, ports_count, ports_list, timestamp FROM port_scan_events "
        "ORDER BY timestamp DESC LIMIT ?",
        (limit,)
    )
    rows = c.fetchall()
    conn.close()
    return rows


if __name__ == "__main__":
    init_db()
    print("Database initialized successfully.")
