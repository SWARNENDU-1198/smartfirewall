"""
Smart Firewall v6.0  —  Real-Time Network Monitor
==================================================
Monitors LIVE OS network connections via psutil.
No simulation. No fake packets. No random generation.
All rule logic, OS enforcement, database persistence,
analytics, and UI are fully intact.
"""

import tkinter as tk
from tkinter import messagebox, filedialog
import time
import platform
import subprocess
import psutil
import socket
from collections import defaultdict, deque
from datetime import datetime
import json
import database
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg

PLATFORM = platform.system()   # "Windows", "Linux", "Darwin"

# Valid connection statuses to capture
VALID_STATUSES = {"ESTABLISHED", "SYN_SENT", "SYN_RECV"}

# Localhost / loopback — always skip
SKIP_IPS = {"127.0.0.1", "::1", "0.0.0.0"}


# ═══════════════════════════════════════════════
# COMPONENT 1 · OS Firewall Interface
# ═══════════════════════════════════════════════

# IPs that must never be blocked by auto-enforcement
SAFE_IPS = {"127.0.0.1", "::1", "0.0.0.0"}


class OSFirewall:
    """
    Thin wrapper around OS firewall commands.
    Windows : netsh advfirewall
    Linux   : iptables
    All calls use subprocess.run — never os.system.
    """

    @staticmethod
    def rule_name(ip: str) -> str:
        return f"SmartFW_Block_{ip.replace(':', '_')}"

    @staticmethod
    def rule_exists(ip: str) -> bool:
        """Return True if an OS firewall block rule for this IP already exists."""
        try:
            if PLATFORM == "Windows":
                result = subprocess.run(
                    ["netsh", "advfirewall", "firewall", "show", "rule",
                     f"name={OSFirewall.rule_name(ip)}"],
                    capture_output=True, text=True, timeout=8
                )
                return result.returncode == 0 and "Rule Name" in result.stdout
        except Exception:
            pass
        return False

    @staticmethod
    def block_ip(ip: str) -> tuple[bool, str]:
        """Add an OS-level inbound block rule. Returns (success, message)."""
        if ip in SAFE_IPS or ip.startswith("127."):
            return False, f"Refused: {ip} is a protected address"
        if OSFirewall.rule_exists(ip):
            return True, f"Rule already exists for {ip}"
        try:
            if PLATFORM == "Windows":
                result = subprocess.run(
                    ["netsh", "advfirewall", "firewall", "add", "rule",
                     f"name={OSFirewall.rule_name(ip)}", "dir=in", "action=block",
                     f"remoteip={ip}"],
                    capture_output=True, text=True, timeout=10
                )
            elif PLATFORM == "Linux":
                result = subprocess.run(
                    ["sudo", "iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"],
                    capture_output=True, text=True, timeout=10
                )
            else:
                return False, f"Unsupported OS: {PLATFORM}"

            if result.returncode == 0:
                return True, f"OS rule added: block {ip}"
            else:
                err = result.stderr.strip() or result.stdout.strip()
                return False, f"OS error: {err}"
        except FileNotFoundError:
            return False, "Firewall command not found"
        except subprocess.TimeoutExpired:
            return False, "Command timed out"
        except Exception as e:
            return False, str(e)

    @staticmethod
    def unblock_ip(ip: str) -> tuple[bool, str]:
        """Remove an OS-level inbound block rule. Returns (success, message)."""
        try:
            if PLATFORM == "Windows":
                result = subprocess.run(
                    ["netsh", "advfirewall", "firewall", "delete", "rule",
                     f"name={OSFirewall.rule_name(ip)}"],
                    capture_output=True, text=True, timeout=10
                )
            elif PLATFORM == "Linux":
                result = subprocess.run(
                    ["sudo", "iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"],
                    capture_output=True, text=True, timeout=10
                )
            else:
                return False, f"Unsupported OS: {PLATFORM}"

            if result.returncode == 0:
                return True, f"OS rule removed: unblock {ip}"
            else:
                err = result.stderr.strip() or result.stdout.strip()
                return False, f"OS error: {err}"
        except FileNotFoundError:
            return False, "Firewall command not found"
        except subprocess.TimeoutExpired:
            return False, "Command timed out"
        except Exception as e:
            return False, str(e)

    @staticmethod
    def block_url_dns(url: str):
        try:
            hosts_path = r"C:\Windows\System32\drivers\etc\hosts"
            if PLATFORM != "Windows":
                hosts_path = "/etc/hosts"
            with open(hosts_path, "a") as f:
                f.write(f"\n127.0.0.1 {url} # SmartFW Block")
            return True, f"DNS Blocked: {url}"
        except PermissionError:
            return False, "Access Denied. Run as Admin."
        except Exception as e:
            return False, str(e)


# ═══════════════════════════════════════════════
# COMPONENT 2 · Firewall Engine (pure logic)
# ═══════════════════════════════════════════════

class FirewallEngine:
    # Behaviour detection thresholds
    NORMAL_THRESHOLD = 3     # block after 4 packets from same IP (was 5)
    STRICT_THRESHOLD = 2     # strict: block after 3 (was 3, check is >, so 2 means 3+)
    MAX_TRACKED_IPS  = 200   # prevent unbounded memory, auto-reset when exceeded

    # Raise reset cycle limit — prevents wiping counts during burst attacks
    BEHAVIOUR_RESET_CYCLES = 500

    def __init__(self):
        b_ips, b_ports, w_ips = database.load_rules()
        self.blocked_ips:    set  = b_ips
        self.blocked_ports:  set  = b_ports
        self.whitelisted_ips: set = w_ips
        self.packet_counts:  dict = defaultdict(int)
        self.strict_mode:    bool = False
        self.enforce_tls:    bool = False
        self._cycle:         int  = 0

    # ── Rules ────────────────────────────────────────────
    def add_ip_rule(self, ip):
        if ip and ip not in self.blocked_ips:
            self.blocked_ips.add(ip)
            database.add_blocked_ip(ip)
            return True
        return False

    def add_port_rule(self, port):
        if port not in self.blocked_ports:
            self.blocked_ports.add(port)
            database.add_blocked_port(port)
            return True
        return False

    def add_whitelist(self, ip):
        if ip and ip not in self.whitelisted_ips:
            self.whitelisted_ips.add(ip)
            database.add_whitelist_ip(ip)
            return True
        return False

    def remove_rule(self, rule_text):
        """Remove a rule. Returns (kind, value) for OS-level cleanup."""
        parts = rule_text.split(":", 1)
        if len(parts) < 2:
            return None, None
        kind, val = parts[0].strip(), parts[1].strip()
        if kind == "IP":
            self.blocked_ips.discard(val)
            database.remove_blocked_ip(val)
            return "IP", val
        elif kind == "PORT":
            self.blocked_ports.discard(int(val))
            database.remove_blocked_port(int(val))
            return "PORT", val
        elif kind == "ALLOW":
            self.whitelisted_ips.discard(val)
            database.remove_whitelist_ip(val)
            return "ALLOW", val
        return None, None

    def reset_behaviour(self):
        self.packet_counts.clear()
        self._cycle = 0

    @property
    def threshold(self):
        return self.STRICT_THRESHOLD if self.strict_mode else self.NORMAL_THRESHOLD

    # ── Real-time connection capture via psutil ───────────
    @staticmethod
    def get_real_connections(limit: int = 8) -> list[dict]:
        """
        Fetch live OS network connections.
        Returns up to `limit` filtered connection packets.

        Filters applied:
          • conn.raddr must exist (ignore listening / local-only sockets)
          • conn.status must be ESTABLISHED, SYN_SENT, or SYN_RECV
          • Remote IP must not be a loopback / wildcard address
        """
        packets = []
        try:
            conns = psutil.net_connections(kind="inet")
        except (psutil.AccessDenied, OSError):
            return []

        for conn in conns:
            if len(packets) >= limit:
                break

            # Must have a remote address
            if not conn.raddr:
                continue

            rip = conn.raddr.ip

            # Skip loopback / unset addresses
            if rip in SKIP_IPS or rip.startswith("127."):
                continue

            # Only meaningful connection states
            if conn.status not in VALID_STATUSES:
                continue

            # Resolve process name safely
            proc_name = "—"
            if conn.pid:
                try:
                    proc_name = psutil.Process(conn.pid).name()
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    proc_name = f"PID:{conn.pid}"

            packets.append({
                "src_ip":    rip,
                "dst_port":  conn.raddr.port,
                "timestamp": time.strftime("%H:%M:%S"),
                "process":   proc_name,
            })

        return packets

    # ── Decision pipeline ────────────────────────────────
    def inspect(self, packet: dict) -> dict:
        ip   = packet["src_ip"]
        port = packet["dst_port"]
        proc = packet.get("process", "—")

        # Periodic behaviour-count reset (prevents overflow / stale data)
        self._cycle += 1
        if self._cycle >= self.BEHAVIOUR_RESET_CYCLES:
            self.packet_counts.clear()
            self._cycle = 0

        # 1. Whitelist check
        if ip in self.whitelisted_ips:
            res = {**packet, "status": "ALLOWED", "reason": "Whitelisted", "threat": "LOW"}
            database.log_packet(ip, port, res["status"], res["threat"], proc)
            return res

        # 2. TLS enforcement — block plain HTTP (port 80)
        if self.enforce_tls and port == 80:
            res = {**packet, "status": "BLOCKED", "reason": "Non-TLS Blocked", "threat": "MEDIUM"}
            database.log_packet(ip, port, res["status"], res["threat"], proc)
            return res

        # 3. Blocked IP list
        if ip in self.blocked_ips:
            res = {**packet, "status": "BLOCKED", "reason": "IP Rule", "threat": "MEDIUM"}
            database.log_packet(ip, port, res["status"], res["threat"], proc)
            return res

        # 4. Blocked port list
        if port in self.blocked_ports:
            res = {**packet, "status": "BLOCKED", "reason": "Port Rule", "threat": "MEDIUM"}
            database.log_packet(ip, port, res["status"], res["threat"], proc)
            return res

        # 5. Behaviour detection — repeated connections from same IP
        if len(self.packet_counts) > self.MAX_TRACKED_IPS:
            self.packet_counts.clear()

        self.packet_counts[ip] += 1
        if self.packet_counts[ip] > self.threshold:
            res = {**packet, "status": "BLOCKED", "reason": "Suspicious Activity", "threat": "HIGH"}
            database.log_packet(ip, port, res["status"], res["threat"], proc)
            return res

        # 6. Default allow
        res = {**packet, "status": "ALLOWED", "reason": "No Match", "threat": "LOW"}
        database.log_packet(ip, port, res["status"], res["threat"], proc)
        return res


# ═══════════════════════════════════════════════
# COMPONENT 3 · Port Scan Detector
# ═══════════════════════════════════════════════

class PortScanDetector:
    """
    Stateless, thread-free port-scan detector.
    Tracks (timestamp, port) observations per IP in a rolling time window.
    When unique ports from one IP exceed PORT_THRESHOLD within TIME_WINDOW
    seconds, it raises a detection dict that the GUI can act on.
    No modifications to FirewallEngine are required.
    """

    TIME_WINDOW    = 10     # seconds to look back (was 8)
    PORT_THRESHOLD = 3      # unique ports within window → port scan (was 5)
    MAX_TRACKED    = 150    # cap memory; prune when exceeded

    def __init__(self):
        # ip_str -> list of (epoch_float, port_int)
        self._ip_port_map: dict = {}
        # IPs already alerted this detection cycle (reset when activity drops)
        self._detected_ips: set = set()

    # ── Public API ────────────────────────────────
    def update(self, ip: str, port: int) -> dict | None:
        """
        Record an (ip, port) observation.
        Returns a detection dict if a port scan is newly detected, else None.
        """
        now    = time.time()
        cutoff = now - self.TIME_WINDOW

        # Ensure entry exists; prune map if growing too large
        if ip not in self._ip_port_map:
            if len(self._ip_port_map) >= self.MAX_TRACKED:
                self._cleanup()
            self._ip_port_map[ip] = []

        # Append observation and drop stale entries in one pass
        self._ip_port_map[ip].append((now, port))
        self._ip_port_map[ip] = [
            (t, p) for t, p in self._ip_port_map[ip] if t >= cutoff
        ]

        unique_ports = {p for _, p in self._ip_port_map[ip]}

        if len(unique_ports) >= self.PORT_THRESHOLD:
            if ip not in self._detected_ips:
                # First time we cross the threshold → raise alert
                self._detected_ips.add(ip)
                return {
                    "ip":          ip,
                    "ports_count": len(unique_ports),
                    "ports":       sorted(unique_ports),
                    "timestamp":   time.strftime("%H:%M:%S"),
                    "status":      "BLOCKED",
                    "reason":      "Port Scan Detected",
                    "threat":      "HIGH",
                    "type":        "PORT_SCAN",
                }
        else:
            # Activity dropped back below threshold; allow re-detection later
            self._detected_ips.discard(ip)

        return None

    def reset(self):
        self._ip_port_map.clear()
        self._detected_ips.clear()

    # ── Internal helpers ──────────────────────────
    def _cleanup(self):
        """Evict idle IPs to keep map within MAX_TRACKED."""
        now    = time.time()
        cutoff = now - self.TIME_WINDOW
        idle   = [ip for ip, obs in self._ip_port_map.items()
                  if not any(t >= cutoff for t, _ in obs)]
        for ip in idle:
            del self._ip_port_map[ip]
            self._detected_ips.discard(ip)
        # Hard-cap: drop oldest half if still too large
        if len(self._ip_port_map) >= self.MAX_TRACKED:
            for ip in list(self._ip_port_map)[: self.MAX_TRACKED // 2]:
                del self._ip_port_map[ip]
                self._detected_ips.discard(ip)


# ═══════════════════════════════════════════════
# COMPONENT 4 · Tkinter GUI
# ═══════════════════════════════════════════════

class FirewallGUI:
    # Colour palette
    BG       = "#0d1117"
    PANEL    = "#161b22"
    ACCENT   = "#58a6ff"
    GREEN    = "#3fb950"
    YELLOW   = "#d29922"
    RED      = "#f85149"
    PURPLE   = "#a371f7"
    ORANGE   = "#f0883e"
    TEXT     = "#c9d1d9"
    MUTED    = "#8b949e"
    BORDER   = "#30363d"
    INPUT_BG = "#21262d"

    # Tick interval in milliseconds (1 second)
    TICK_MS = 1000

    def __init__(self, root):
        self.root   = root
        self.engine = FirewallEngine()

        self._running          = False
        self._after_id         = None
        self._total_count      = 0
        self._allowed_count    = 0
        self._blocked_count    = 0
        self._suspicious_count = 0
        self._log_entries      = deque(maxlen=15)
        self._structured_logs  = []      # List of dicts for Analysis Dashboard
        self._enforced_ips     = set()   # IPs currently blocked at OS level

        # ── Enforcement Mode ─────────────────────────
        # "detect"  = Detect Only (default, safe)
        # "enforce" = Detect + Enforce (auto-block HIGH threats at OS level)
        self._enforce_mode    = "detect"   # starts in safe mode
        self._os_blocked_ips  = set()      # IPs blocked at OS level THIS session

        # ── Setup UDP socket for educational attack simulator (port 5555) ──
        self._sim_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            self._sim_sock.bind(("127.0.0.1", 5555))
            self._sim_sock.setblocking(False)
        except OSError:
            pass

        # ── Port Scan Detection state ────────────────
        self._port_scan_detector = PortScanDetector()
        self._port_scan_logs     = []   # [{ip, ports_count, ports, timestamp}]
        self._ps_alert_visible   = False

        # Re-apply OS blocks for any rules loaded from DB
        for ip in self.engine.blocked_ips:
            if ip not in self._enforced_ips:
                OSFirewall.block_ip(ip)
                self._enforced_ips.add(ip)

        self._build_window()
        self._build_ui()
        self._populate_rules_list()

    def _populate_rules_list(self):
        for ip in self.engine.blocked_ips:
            self._rules_lb.insert(tk.END, f"IP   : {ip}")
        for port in self.engine.blocked_ports:
            self._rules_lb.insert(tk.END, f"PORT : {port}")
        for ip in self.engine.whitelisted_ips:
            self._rules_lb.insert(tk.END, f"ALLOW: {ip}")

    # ── Window ────────────────────────────────────────────
    def _build_window(self):
        self.root.title("🛡  Smart Firewall v6.0  —  Real-Time Network Monitor")
        self.root.geometry("1020x880")
        self.root.resizable(True, True)
        self.root.minsize(900, 780)
        self.root.configure(bg=self.BG)
        self.F_H1   = ("Segoe UI", 14, "bold")
        self.F_H2   = ("Segoe UI", 10, "bold")
        self.F_BODY = ("Segoe UI", 10)
        self.F_MONO = ("Consolas",  9)
        self.F_SM   = ("Segoe UI",  9)

    # ── Helpers ───────────────────────────────────────────
    def _section(self, parent, title):
        return tk.LabelFrame(parent, text=f"  {title}  ", font=self.F_H2,
                             fg=self.ACCENT, bg=self.PANEL, bd=1, relief="solid",
                             highlightbackground=self.BORDER)

    def _btn(self, parent, text, cmd, color, **kw):
        b = tk.Button(parent, text=text, command=cmd, bg=color, fg="white",
                      font=self.F_H2, relief="flat", cursor="hand2",
                      activebackground=color, activeforeground="white",
                      padx=10, pady=4, **kw)
        orig = color
        b.bind("<Enter>", lambda e, b=b: b.config(bg=self._lit(orig)))
        b.bind("<Leave>", lambda e, b=b: b.config(bg=orig))
        return b

    @staticmethod
    def _lit(c):
        h = c.lstrip("#")
        return "#{:02x}{:02x}{:02x}".format(
            *[min(255, int(h[i:i+2], 16) + 25) for i in (0, 2, 4)])

    def _lbl(self, parent, text, **kw):
        return tk.Label(parent, text=text, font=self.F_BODY,
                        fg=self.TEXT, bg=self.PANEL, **kw)

    def _entry(self, parent, width=14):
        return tk.Entry(parent, width=width, font=self.F_BODY,
                        bg=self.INPUT_BG, fg=self.TEXT,
                        insertbackground=self.TEXT, relief="flat")

    # ── Build UI ──────────────────────────────────────────
    def _build_ui(self):
        px = dict(padx=10, pady=3)

        # ─── HEADER ──────────────────────────────────────
        hdr = tk.Frame(self.root, bg=self.ACCENT)
        hdr.pack(fill=tk.X)

        tk.Label(hdr, text="🛡  Smart Firewall v6.0",
                 font=self.F_H1, bg=self.ACCENT, fg="white", pady=7
                 ).pack(side=tk.LEFT, padx=14)

        # Real-time monitoring badge
        self._rt_lbl = tk.Label(
            hdr,
            text="🟢 Real-Time Network Monitoring: ACTIVE",
            font=self.F_H2, bg=self.ACCENT, fg="#d2ffb0"
        )
        self._rt_lbl.pack(side=tk.LEFT, padx=18)

        self._status_lbl = tk.Label(hdr, text="● STOPPED", font=self.F_H2,
                                    bg=self.ACCENT, fg=self.RED)
        self._status_lbl.pack(side=tk.RIGHT, padx=14)

        # Connections-per-cycle counter
        self._conn_lbl = tk.Label(hdr, text="Conns: 0", font=self.F_SM,
                                  bg=self.BG, fg=self.GREEN, padx=8)
        self._conn_lbl.pack(side=tk.RIGHT, padx=10)

        # ─── SECTION: RULES ─────────────────────────────
        rules = self._section(self.root, "RULES")
        rules.pack(fill=tk.X, **px)

        r0 = tk.Frame(rules, bg=self.PANEL); r0.pack(fill=tk.X, pady=3, padx=6)
        self._lbl(r0, "Block IP:").pack(side=tk.LEFT)
        self._ip_e = self._entry(r0); self._ip_e.pack(side=tk.LEFT, padx=4, ipady=3)
        self._lbl(r0, "Block Port:").pack(side=tk.LEFT, padx=(10, 0))
        self._port_e = self._entry(r0, 8); self._port_e.pack(side=tk.LEFT, padx=4, ipady=3)
        self._btn(r0, "+ Add Rule", self._add_rule, self.ACCENT).pack(side=tk.LEFT, padx=6)

        r1 = tk.Frame(rules, bg=self.PANEL); r1.pack(fill=tk.X, pady=2, padx=6)
        self._lbl(r1, "Whitelist IP:").pack(side=tk.LEFT)
        self._wl_e = self._entry(r1); self._wl_e.pack(side=tk.LEFT, padx=4, ipady=3)
        self._btn(r1, "+ Whitelist", self._add_whitelist, self.GREEN).pack(side=tk.LEFT, padx=6)

        r_adv = tk.Frame(rules, bg=self.PANEL); r_adv.pack(fill=tk.X, pady=2, padx=6)
        self._lbl(r_adv, "Block URL (DNS):").pack(side=tk.LEFT)
        self._url_e = self._entry(r_adv, 20); self._url_e.pack(side=tk.LEFT, padx=4, ipady=3)
        self._btn(r_adv, "Block", self._add_url_rule, self.PURPLE).pack(side=tk.LEFT, padx=6)

        r2 = tk.Frame(rules, bg=self.PANEL); r2.pack(fill=tk.X, pady=3, padx=6)
        self._lbl(r2, "Active:").pack(side=tk.LEFT)

        lf = tk.Frame(r2, bg=self.PANEL)
        lf.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=4)
        sb = tk.Scrollbar(lf, orient=tk.VERTICAL)
        self._rules_lb = tk.Listbox(lf, height=3, yscrollcommand=sb.set,
                                    font=self.F_MONO, bg=self.INPUT_BG, fg=self.TEXT,
                                    selectbackground=self.ACCENT, relief="flat",
                                    highlightthickness=0)
        sb.config(command=self._rules_lb.yview)
        self._rules_lb.pack(side=tk.LEFT, fill=tk.X, expand=True)
        sb.pack(side=tk.LEFT, fill=tk.Y)
        self._btn(r2, "✕ Remove", self._remove_rule, self.MUTED).pack(side=tk.RIGHT)

        # Enforcement feedback label
        self._enforce_lbl = tk.Label(rules, text="", font=self.F_SM,
                                     bg=self.PANEL, fg=self.MUTED)
        self._enforce_lbl.pack(fill=tk.X, padx=6, pady=(0, 3))

        # ─── SECTION: LIVE CONNECTION MONITOR ──────────
        monitor = self._section(self.root, "LIVE CONNECTION MONITOR")
        monitor.pack(fill=tk.X, **px)

        cols = tk.Frame(monitor, bg=self.PANEL); cols.pack(fill=tk.X, pady=4)

        def _col(parent, label):
            c = tk.Frame(parent, bg=self.BG, padx=8, pady=4)
            c.pack(side=tk.LEFT, expand=True, fill=tk.BOTH, padx=2)
            tk.Label(c, text=label, font=self.F_SM, fg=self.MUTED, bg=self.BG).pack()
            v = tk.Label(c, text="—", font=("Segoe UI", 11, "bold"),
                         fg=self.TEXT, bg=self.BG)
            v.pack()
            return v

        self._v_ip      = _col(cols, "Remote IP")
        self._v_port    = _col(cols, "Remote Port")
        self._v_status  = _col(cols, "Status")
        self._v_threat  = _col(cols, "Threat")
        self._v_reason  = _col(cols, "Reason")
        self._v_process = _col(cols, "Process")

        # ─── SECTION: DASHBOARD ─────────────────────────
        dash = self._section(self.root, "DASHBOARD")
        dash.pack(fill=tk.X, **px)

        ctr = tk.Frame(dash, bg=self.PANEL); ctr.pack(fill=tk.X, pady=3)

        def _ctr(parent, label, color):
            f = tk.Frame(parent, bg=self.BG, padx=10, pady=3)
            f.pack(side=tk.LEFT, expand=True, fill=tk.BOTH, padx=2)
            tk.Label(f, text=label, font=self.F_SM, fg=self.MUTED, bg=self.BG).pack()
            v = tk.Label(f, text="0", font=("Segoe UI", 14, "bold"),
                         fg=color, bg=self.BG)
            v.pack()
            return v

        self._c_total    = _ctr(ctr, "Total",       self.ACCENT)
        self._c_allow    = _ctr(ctr, "Allowed",     self.GREEN)
        self._c_block    = _ctr(ctr, "Blocked",     self.RED)
        self._c_sus      = _ctr(ctr, "Suspicious",  self.YELLOW)
        self._c_pscan    = _ctr(ctr, "Port Scans",  self.ORANGE)

        # ─── SECTION: PORT SCAN ALERT BANNER ────────────
        # Hidden by default; shown only when a scan is detected
        self._ps_banner = tk.Frame(self.root, bg="#3d0000", pady=4)
        # (not packed yet — _handle_port_scan will pack it)

        ps_icon = tk.Label(self._ps_banner,
                           text="🚨  PORT SCAN DETECTED FROM: ",
                           font=("Segoe UI", 10, "bold"),
                           bg="#3d0000", fg=self.RED)
        ps_icon.pack(side=tk.LEFT, padx=(10, 0))

        self._ps_ip_lbl = tk.Label(self._ps_banner,
                                   text="",
                                   font=("Consolas", 10, "bold"),
                                   bg="#3d0000", fg="#ff6b6b")
        self._ps_ip_lbl.pack(side=tk.LEFT)

        self._ps_ports_lbl = tk.Label(self._ps_banner,
                                      text="",
                                      font=("Segoe UI", 9),
                                      bg="#3d0000", fg=self.ORANGE)
        self._ps_ports_lbl.pack(side=tk.LEFT, padx=6)

        self._ps_block_btn = self._btn(
            self._ps_banner,
            "🚫 Block Attacker IP",
            self._block_scan_attacker,
            self.RED
        )
        self._ps_block_btn.pack(side=tk.RIGHT, padx=10)

        tk.Button(
            self._ps_banner, text="✕ Dismiss",
            command=self._dismiss_ps_alert,
            bg="#3d0000", fg=self.MUTED,
            font=self.F_SM, relief="flat", cursor="hand2",
            activebackground="#3d0000", activeforeground=self.TEXT
        ).pack(side=tk.RIGHT, padx=4)

        # ─── SECTION: FIREWALL LOGS ─────────────────────
        logs = self._section(self.root, "FIREWALL LOGS")
        logs.pack(fill=tk.BOTH, expand=True, **px)

        ls = tk.Scrollbar(logs, orient=tk.VERTICAL)
        self._log_text = tk.Text(logs, state=tk.DISABLED, height=7,
                                 yscrollcommand=ls.set, font=self.F_MONO,
                                 bg=self.BG, fg=self.TEXT, relief="flat",
                                 highlightthickness=0, padx=6, pady=4, wrap=tk.NONE)
        ls.config(command=self._log_text.yview)
        self._log_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        ls.pack(side=tk.RIGHT, fill=tk.Y)

        self._log_text.tag_config("low",    foreground=self.GREEN)
        self._log_text.tag_config("medium", foreground=self.YELLOW)
        self._log_text.tag_config("high",   foreground=self.RED)

        # ─── SECTION: OS ENFORCEMENT PANEL ─────────────
        enf_frame = self._section(self.root, "🛡  OS ENFORCEMENT")
        enf_frame.pack(fill=tk.X, **px)

        ef_row1 = tk.Frame(enf_frame, bg=self.PANEL); ef_row1.pack(fill=tk.X, padx=6, pady=(4, 2))

        # Mode label
        tk.Label(ef_row1, text="Mode:", font=self.F_H2, fg=self.TEXT, bg=self.PANEL).pack(side=tk.LEFT)

        self._mode_lbl = tk.Label(
            ef_row1, text="🟡  DETECT ONLY  (Safe)",
            font=("Segoe UI", 10, "bold"), fg=self.YELLOW, bg=self.PANEL, padx=8
        )
        self._mode_lbl.pack(side=tk.LEFT)

        self._enforce_toggle_btn = self._btn(
            ef_row1, "⚡ Enable Detect + Enforce",
            self._toggle_enforce_mode, self.ORANGE
        )
        self._enforce_toggle_btn.pack(side=tk.LEFT, padx=10)

        ef_row2 = tk.Frame(enf_frame, bg=self.PANEL); ef_row2.pack(fill=tk.X, padx=6, pady=(2, 2))

        tk.Label(ef_row2, text="Manual IP:", font=self.F_BODY, fg=self.TEXT, bg=self.PANEL).pack(side=tk.LEFT)
        self._enf_ip_e = self._entry(ef_row2, 16)
        self._enf_ip_e.pack(side=tk.LEFT, padx=6, ipady=3)

        self._btn(ef_row2, "🚫 Block IP",   self._manual_block_ip,   self.RED   ).pack(side=tk.LEFT, padx=3)
        self._btn(ef_row2, "✅ Unblock IP", self._manual_unblock_ip, self.GREEN ).pack(side=tk.LEFT, padx=3)

        ef_row3 = tk.Frame(enf_frame, bg=self.PANEL); ef_row3.pack(fill=tk.X, padx=6, pady=(0, 4))
        tk.Label(ef_row3, text="OS-Blocked IPs:", font=self.F_SM, fg=self.MUTED, bg=self.PANEL).pack(side=tk.LEFT)
        lf2 = tk.Frame(ef_row3, bg=self.PANEL); lf2.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=4)
        sb2 = tk.Scrollbar(lf2, orient=tk.VERTICAL)
        self._enf_lb = tk.Listbox(
            lf2, height=2, yscrollcommand=sb2.set,
            font=self.F_MONO, bg=self.INPUT_BG, fg=self.RED,
            selectbackground=self.ACCENT, relief="flat", highlightthickness=0
        )
        sb2.config(command=self._enf_lb.yview)
        self._enf_lb.pack(side=tk.LEFT, fill=tk.X, expand=True)
        sb2.pack(side=tk.LEFT, fill=tk.Y)

        self._enf_status_lbl = tk.Label(
            enf_frame, text="", font=self.F_SM, bg=self.PANEL, fg=self.MUTED
        )
        self._enf_status_lbl.pack(fill=tk.X, padx=6, pady=(0, 3))

        # ─── FOOTER: Controls ───────────────────────────
        foot = tk.Frame(self.root, bg=self.BG)
        foot.pack(fill=tk.X, padx=10, pady=6)

        self._start_b = self._btn(foot, "▶ Start", self._start, self.GREEN)
        self._start_b.pack(side=tk.LEFT, padx=3)
        self._stop_b = self._btn(foot, "■ Stop", self._stop, self.RED, state=tk.DISABLED)
        self._stop_b.pack(side=tk.LEFT, padx=3)
        self._btn(foot, "📊 Analysis Dashboard", self._show_analysis_dashboard, self.PURPLE).pack(side=tk.LEFT, padx=3)

        # Right side controls
        self._btn(foot, "📄 Export", self._export_logs, self.MUTED).pack(side=tk.RIGHT, padx=3)
        self._btn(foot, "⟳ Clear",  self._clear,       self.MUTED).pack(side=tk.RIGHT, padx=3)

        self._strict_var = tk.BooleanVar(value=False)
        tk.Checkbutton(
            foot, text="Strict Mode (threshold=3)", variable=self._strict_var,
            command=self._toggle_strict, font=self.F_SM,
            bg=self.BG, fg=self.YELLOW, selectcolor=self.INPUT_BG,
            activebackground=self.BG, activeforeground=self.YELLOW,
            cursor="hand2"
        ).pack(side=tk.RIGHT, padx=6)

        self._tls_var = tk.BooleanVar(value=False)
        tk.Checkbutton(
            foot, text="🔒 Enforce TLS (Block HTTP)", variable=self._tls_var,
            command=self._toggle_tls, font=self.F_SM,
            bg=self.BG, fg=self.ACCENT, selectcolor=self.INPUT_BG,
            activebackground=self.BG, activeforeground=self.ACCENT,
            cursor="hand2"
        ).pack(side=tk.RIGHT, padx=6)

        # ─── Status bar ─────────────────────────────────
        self._disc_lbl = tk.Label(
            self.root,
            text="🟡 DETECT ONLY MODE  —  Reads live OS connections via psutil  |  No Auto-Block",
            font=self.F_SM, bg=self.BORDER, fg=self.YELLOW, pady=3)
        self._disc_lbl.pack(fill=tk.X, side=tk.BOTTOM)

    # ═══════════════════════════════════════════════
    # Rule callbacks (with OS enforcement)
    # ═══════════════════════════════════════════════

    def _add_rule(self):
        ip   = self._ip_e.get().strip()
        port = self._port_e.get().strip()
        added = False

        if ip:
            if self.engine.add_ip_rule(ip):
                self._rules_lb.insert(tk.END, f"IP   : {ip}")
                added = True
                ok, msg = OSFirewall.block_ip(ip)
                if ok:
                    self._enforced_ips.add(ip)
                    self._enforce_lbl.config(text=f"✔ OS: {msg}", fg=self.GREEN)
                else:
                    self._enforce_lbl.config(text=f"✘ OS: {msg}", fg=self.RED)
            self._ip_e.delete(0, tk.END)

        if port:
            try:
                p = int(port)
                if self.engine.add_port_rule(p):
                    self._rules_lb.insert(tk.END, f"PORT : {p}")
                    added = True
                self._port_e.delete(0, tk.END)
            except ValueError:
                messagebox.showerror("Error", "Port must be a number")
                return

        if not added and (ip or port):
            messagebox.showinfo("Duplicate", "Rule already exists.")

    def _add_whitelist(self):
        ip = self._wl_e.get().strip()
        if ip:
            if self.engine.add_whitelist(ip):
                self._rules_lb.insert(tk.END, f"ALLOW: {ip}")
                if ip in self._enforced_ips:
                    ok, msg = OSFirewall.unblock_ip(ip)
                    self._enforced_ips.discard(ip)
                    self._enforce_lbl.config(
                        text=f"✔ OS unblocked (whitelisted): {msg}" if ok else f"✘ {msg}",
                        fg=self.GREEN if ok else self.RED)
            else:
                messagebox.showinfo("Duplicate", "IP already whitelisted.")
            self._wl_e.delete(0, tk.END)

    def _add_url_rule(self):
        url = self._url_e.get().strip()
        if url:
            ok, msg = OSFirewall.block_url_dns(url)
            if ok:
                self._rules_lb.insert(tk.END, f"URL  : {url}")
                self._enforce_lbl.config(text=f"✔ {msg}", fg=self.GREEN)
            else:
                self._enforce_lbl.config(text=f"✘ {msg}", fg=self.RED)
            self._url_e.delete(0, tk.END)

    def _toggle_tls(self):
        self.engine.enforce_tls = self._tls_var.get()
        if self.engine.enforce_tls:
            self._enforce_lbl.config(text="🔒 TLS Enforced. Blocking Port 80.", fg=self.ACCENT)
        else:
            self._enforce_lbl.config(text="🔓 TLS Enforcement Disabled.", fg=self.MUTED)

    def _remove_rule(self):
        sel = self._rules_lb.curselection()
        if not sel:
            messagebox.showinfo("Select", "Click a rule first.")
            return
        idx  = sel[0]
        text = self._rules_lb.get(idx)
        kind, val = self.engine.remove_rule(text)
        self._rules_lb.delete(idx)

        if kind == "IP" and val and val in self._enforced_ips:
            ok, msg = OSFirewall.unblock_ip(val)
            self._enforced_ips.discard(val)
            self._enforce_lbl.config(
                text=f"✔ OS: {msg}" if ok else f"✘ OS: {msg}",
                fg=self.GREEN if ok else self.RED)

    def _toggle_strict(self):
        self.engine.strict_mode = self._strict_var.get()
        mode = "STRICT (threshold=3)" if self.engine.strict_mode else "NORMAL (threshold=5)"
        self._enforce_lbl.config(text=f"Behaviour detection: {mode}", fg=self.YELLOW)

    # ═══════════════════════════════════════════════
    # Enforcement Mode
    # ═══════════════════════════════════════════════

    def _toggle_enforce_mode(self):
        """Toggle between Detect Only and Detect+Enforce modes."""
        if self._enforce_mode == "detect":
            # Ask user to confirm before enabling real OS blocking
            confirmed = messagebox.askyesno(
                "⚠ Enable OS Enforcement?",
                "Detect + Enforce mode will automatically block HIGH-threat IPs\n"
                "at the Windows Firewall level using 'netsh advfirewall'.\n\n"
                "• This creates REAL firewall rules on your system.\n"
                "• Localhost and gateway IPs are always protected.\n"
                "• You can unblock IPs at any time.\n\n"
                "This requires Administrator privileges.\n"
                "Enable enforcement?"
            )
            if not confirmed:
                return
            self._enforce_mode = "enforce"
            self._mode_lbl.config(
                text="🔴  DETECT + ENFORCE  (Auto-Blocking ACTIVE)",
                fg=self.RED
            )
            self._enforce_toggle_btn.config(
                text="🟡 Switch to Detect Only", bg=self.YELLOW
            )
            self._disc_lbl.config(
                text="🔴 DETECT + ENFORCE MODE  —  HIGH threats auto-blocked via Windows Firewall",
                fg=self.RED
            )
            self._enf_status_lbl.config(
                text="✔ Enforcement ACTIVE — HIGH threat IPs will be auto-blocked at OS level",
                fg=self.RED
            )
        else:
            self._enforce_mode = "detect"
            self._mode_lbl.config(
                text="🟡  DETECT ONLY  (Safe)",
                fg=self.YELLOW
            )
            self._enforce_toggle_btn.config(
                text="⚡ Enable Detect + Enforce", bg=self.ORANGE
            )
            self._disc_lbl.config(
                text="🟡 DETECT ONLY MODE  —  Reads live OS connections via psutil  |  No Auto-Block",
                fg=self.YELLOW
            )
            self._enf_status_lbl.config(
                text="ℹ Enforcement OFF — switch to Detect+Enforce for auto-blocking",
                fg=self.MUTED
            )

    def _apply_os_block(self, ip: str, reason: str) -> bool:
        """
        Apply an OS-level block for an IP.
        Returns True if successfully blocked.
        Skips safe IPs and already-blocked IPs.
        """
        if ip in SAFE_IPS or ip.startswith("127."):
            return False
        if ip in self._os_blocked_ips:
            return False  # Already blocked this session

        ok, msg = OSFirewall.block_ip(ip)
        if ok:
            self._os_blocked_ips.add(ip)
            self._enforced_ips.add(ip)
            self._enf_lb.insert(tk.END, f"🔴 {ip}")
            # Log the enforcement action in the firewall log
            ts = time.strftime("%H:%M:%S")
            enf_line = f"[{ts}]  🛡 REAL BLOCK APPLIED to {ip:<18} Reason: {reason}\n"
            self._log_entries.appendleft(enf_line)
            self._log_text.config(state=tk.NORMAL)
            self._log_text.delete("1.0", tk.END)
            for entry in self._log_entries:
                t = "high" if "HIGH" in entry or "REAL BLOCK" in entry \
                    else ("medium" if "MEDIUM" in entry else "low")
                self._log_text.insert(tk.END, entry, t)
            self._log_text.config(state=tk.DISABLED)
            self._enf_status_lbl.config(
                text=f"✔ REAL BLOCK APPLIED to {ip}  — {msg}", fg=self.RED
            )
        else:
            self._enf_status_lbl.config(
                text=f"✘ OS block failed for {ip}: {msg}", fg=self.YELLOW
            )
        return ok

    def _manual_block_ip(self):
        """Manually block an IP via the enforcement panel."""
        ip = self._enf_ip_e.get().strip()
        if not ip:
            messagebox.showinfo("Input Required", "Enter an IP address to block.")
            return
        if ip in SAFE_IPS or ip.startswith("127."):
            messagebox.showwarning("Protected IP", f"{ip} is a protected address and cannot be blocked.")
            return
        ok, msg = OSFirewall.block_ip(ip)
        if ok:
            if ip not in self._os_blocked_ips:
                self._os_blocked_ips.add(ip)
                self._enforced_ips.add(ip)
                self._enf_lb.insert(tk.END, f"🔴 {ip}")
            self._enf_status_lbl.config(text=f"✔ {msg}", fg=self.RED)
            ts = time.strftime("%H:%M:%S")
            self._log_entries.appendleft(
                f"[{ts}]  🛡 REAL BLOCK APPLIED to {ip:<18} Reason: Manual Block\n"
            )
        else:
            self._enf_status_lbl.config(text=f"✘ {msg}", fg=self.YELLOW)
        self._enf_ip_e.delete(0, tk.END)

    def _manual_unblock_ip(self):
        """Manually unblock an IP via the enforcement panel."""
        ip = self._enf_ip_e.get().strip()
        if not ip:
            # Try selected from listbox
            sel = self._enf_lb.curselection()
            if sel:
                entry = self._enf_lb.get(sel[0])
                ip = entry.replace("🔴 ", "").strip()
            else:
                messagebox.showinfo("Input Required",
                    "Enter an IP to unblock, or select one from the list.")
                return
        ok, msg = OSFirewall.unblock_ip(ip)
        if ok:
            self._os_blocked_ips.discard(ip)
            self._enforced_ips.discard(ip)
            # Remove from listbox
            for i in range(self._enf_lb.size()):
                if ip in self._enf_lb.get(i):
                    self._enf_lb.delete(i)
                    break
            self._enf_status_lbl.config(text=f"✔ Unblocked: {ip}", fg=self.GREEN)
            ts = time.strftime("%H:%M:%S")
            self._log_entries.appendleft(
                f"[{ts}]  ✅ OS BLOCK REMOVED for {ip:<18} Reason: Manual Unblock\n"
            )
        else:
            self._enf_status_lbl.config(text=f"✘ {msg}", fg=self.YELLOW)
        self._enf_ip_e.delete(0, tk.END)

    # ═══════════════════════════════════════════════
    # Real-time monitoring loop (Tkinter after())
    # ═══════════════════════════════════════════════

    def _start(self):
        self._running = True
        self._start_b.config(state=tk.DISABLED)
        self._stop_b.config(state=tk.NORMAL)
        self._status_lbl.config(text="● ACTIVE", fg=self.GREEN)
        self._rt_lbl.config(text="🟢 Real-Time Network Monitoring: ACTIVE", fg="#d2ffb0")
        self._tick()

    def _stop(self):
        self._running = False
        if self._after_id:
            self.root.after_cancel(self._after_id)
            self._after_id = None
        self._start_b.config(state=tk.NORMAL)
        self._stop_b.config(state=tk.DISABLED)
        self._status_lbl.config(text="● STOPPED", fg=self.RED)
        self._rt_lbl.config(text="⚪ Real-Time Network Monitoring: STOPPED", fg=self.MUTED)

    def _tick(self):
        """Main monitoring loop — called every TICK_MS via Tkinter after()."""
        if not self._running:
            return

        # Pull real OS connections — no simulation, no random data
        conns = self.engine.get_real_connections(limit=8)

        # Merge simulated educational attack packets (from port 5555)
        try:
            while True:
                data, _ = self._sim_sock.recvfrom(2048)
                pkt = json.loads(data.decode())
                if "src_ip" in pkt and "dst_port" in pkt:
                    if "process" not in pkt:
                        pkt["process"] = f"SIM: {pkt.get('attack', 'Attack')}"
                    conns.append(pkt)
        except (BlockingIOError, OSError):
            pass

        self._conn_lbl.config(text=f"Conns: {len(conns)}")

        if conns:
            for pkt in conns:
                res = self.engine.inspect(pkt)
                self._update_ui(res)

                # ── Port scan detection (additional layer, non-invasive) ──
                detection = self._port_scan_detector.update(
                    pkt["src_ip"], pkt["dst_port"]
                )
                if detection:
                    self._handle_port_scan(detection)
        else:
            # No qualifying connections right now — show idle state
            self._v_ip.config(text="Scanning…")
            self._v_port.config(text="—")
            self._v_status.config(text="IDLE", fg=self.MUTED)
            self._v_threat.config(text="—", fg=self.MUTED)
            self._v_reason.config(text="—", fg=self.MUTED)
            self._v_process.config(text="—")

        # Schedule next tick — no threading, pure Tkinter
        self._after_id = self.root.after(self.TICK_MS, self._tick)

    # ═══════════════════════════════════════════════
    # Port Scan Handlers
    # ═══════════════════════════════════════════════

    def _handle_port_scan(self, det: dict):
        """Called when PortScanDetector raises a detection."""
        # 1. Persist to DB (separate table)
        database.log_port_scan(
            det["ip"],
            det["ports_count"],
            ", ".join(str(p) for p in det["ports"])
        )

        # 2. Keep in-memory record for dashboard
        self._port_scan_logs.append(det)
        self._c_pscan.config(text=str(len(self._port_scan_logs)))

        # 3. Also add to structured logs so regular dashboard sees it
        self._structured_logs.append({
            "ip":     det["ip"],
            "port":   det["ports"][0] if det["ports"] else 0,
            "status": "BLOCKED",
            "reason": "Port Scan Detected",
            "threat": "HIGH",
            "type":   "PORT_SCAN",
        })
        self._total_count     += 1
        self._blocked_count   += 1
        self._suspicious_count+= 1
        self._c_total.config(text=str(self._total_count))
        self._c_block.config(text=str(self._blocked_count))
        self._c_sus.config(text=str(self._suspicious_count))

        # 4. Write to live log panel (red, tagged HIGH)
        line = (f"[{det['timestamp']}]  🚨 PORT SCAN DETECTED  "
                f"IP={det['ip']}  Ports={det['ports_count']} unique  "
                f"BLOCKED / HIGH\n")
        self._log_entries.appendleft(line)
        self._log_text.config(state=tk.NORMAL)
        self._log_text.delete("1.0", tk.END)
        for entry in self._log_entries:
            tag = "high" if "HIGH" in entry or "PORT SCAN" in entry \
                  else ("medium" if "MEDIUM" in entry else "low")
            self._log_text.insert(tk.END, entry, tag)
        self._log_text.config(state=tk.DISABLED)

        # 5. Show / update the alert banner
        self._ps_ip_lbl.config(text=det["ip"])
        self._ps_ports_lbl.config(
            text=f"({det['ports_count']} ports:  {', '.join(str(p) for p in det['ports'][:8])}"
                 f"{'…' if len(det['ports']) > 8 else ''})"
        )
        self._ps_block_btn._scan_ip = det["ip"]   # store for block callback
        if not self._ps_alert_visible:
            self._ps_banner.pack(fill=tk.X, padx=10, pady=(4, 0))
            self._ps_alert_visible = True

    def _block_scan_attacker(self):
        """OS-block the IP shown in the panel via netsh (Windows)."""
        ip = getattr(self._ps_block_btn, "_scan_ip", None)
        if not ip:
            return
        if self.engine.add_ip_rule(ip):
            self._rules_lb.insert(tk.END, f"IP   : {ip}")
        ok, msg = OSFirewall.block_ip(ip)
        if ok:
            self._enforced_ips.add(ip)
            self._enforce_lbl.config(
                text=f"🚫 OS BLOCKED scanner: {ip}  — {msg}", fg=self.RED)
        else:
            self._enforce_lbl.config(
                text=f"✘ OS block failed: {msg}", fg=self.YELLOW)
        self._dismiss_ps_alert()

    def _dismiss_ps_alert(self):
        if self._ps_alert_visible:
            self._ps_banner.pack_forget()
            self._ps_alert_visible = False

    # ═══════════════════════════════════════════════
    # Analytics Dashboard
    # ═══════════════════════════════════════════════

    def _show_analysis_dashboard(self):
        if not self._structured_logs:
            messagebox.showinfo("Analysis Dashboard", "No logs to analyze yet. Start monitoring first.")
            return

        win = tk.Toplevel(self.root)
        win.title("Threat Analysis Dashboard")
        win.geometry("850x650")
        win.configure(bg=self.BG)

        # Basic Stats
        total = len(self._structured_logs)
        allowed = sum(1 for x in self._structured_logs if x['status'] == 'ALLOWED')
        blocked = sum(1 for x in self._structured_logs if x['status'] == 'BLOCKED')
        high_threats = sum(1 for x in self._structured_logs if x['threat'] == 'HIGH')
        ratio = f"{(blocked/total)*100:.1f}% vs {(allowed/total)*100:.1f}%" if total > 0 else "N/A"

        # Complex groupings
        ip_blocks = defaultdict(int)
        port_counts = defaultdict(int)
        suspicious_ips = set()

        for log in self._structured_logs:
            port_counts[log['port']] += 1
            if log['status'] == 'BLOCKED':
                ip_blocks[log['ip']] += 1
            if log['threat'] == 'HIGH':
                suspicious_ips.add(log['ip'])

        top_ips = sorted(ip_blocks.items(), key=lambda x: x[1], reverse=True)[:5]
        top_ports = sorted(port_counts.items(), key=lambda x: x[1], reverse=True)[:5]

        # Top Bar
        top_bar = tk.Frame(win, bg=self.PANEL)
        top_bar.pack(fill=tk.X, padx=10, pady=10)
        
        def _refresh():
            win.destroy()
            self._show_analysis_dashboard()

        def _export():
            path = filedialog.asksaveasfilename(defaultextension=".txt", initialfile=f"Analysis_Report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt")
            if path:
                with open(path, "w") as f:
                    f.write("FIREWALL ANALYSIS REPORT\n========================\n\n")
                    f.write(f"Total Packets: {total}\nAllowed: {allowed}\nBlocked: {blocked}\nSuspicious: {high_threats}\n")
                    f.write(f"Blocked vs Allowed Ratio: {ratio}\n\n")
                    f.write("Top Malicious IPs:\n")
                    for ip, count in top_ips: f.write(f" - {ip}: {count} times\n")
                    f.write("\nMost Targeted Ports:\n")
                    for port, count in top_ports: f.write(f" - {port}: {count} times\n")
                    f.write("\nSuspicious IPs (HIGH threat):\n")
                    for ip in suspicious_ips: f.write(f" - {ip}\n")
                messagebox.showinfo("Exported", f"Analysis saved to:\n{path}", parent=win)

        tk.Label(top_bar, text="Analysis Dashboard", font=self.F_H1, fg=self.ACCENT, bg=self.PANEL).pack(side=tk.LEFT, padx=10, pady=5)
        self._btn(top_bar, "⟳ Refresh", _refresh, self.MUTED).pack(side=tk.RIGHT, padx=5)
        self._btn(top_bar, "📄 Export Report", _export, self.PURPLE).pack(side=tk.RIGHT, padx=5)

        content = tk.Frame(win, bg=self.BG)
        content.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)

        # 1. Total Statistics
        f_stats = self._section(content, "Traffic Summary")
        f_stats.grid(row=0, column=0, sticky="nsew", padx=5, pady=5)
        stats_text = f"Total Packets examined: {total}\n\nAllowed Traffic:        {allowed}\nBlocked Traffic:        {blocked}\nHigh Threat Events:     {high_threats}\n\nBlock vs Allow Ratio:   {ratio}"
        tk.Label(f_stats, text=stats_text, font=self.F_MONO, fg=self.TEXT, bg=self.PANEL, justify=tk.LEFT).pack(anchor="w", padx=10, pady=20)

        # 2. Top Malicious IPs
        f_ips = self._section(content, "Top Malicious IPs (Blocked)")
        f_ips.grid(row=0, column=1, sticky="nsew", padx=5, pady=5)
        if top_ips:
            for ip, count in top_ips:
                tk.Label(f_ips, text=f"🔴 {ip}  |  {count} blocks", font=self.F_MONO, fg=self.RED, bg=self.PANEL).pack(anchor="w", padx=10, pady=4)
        else:
            tk.Label(f_ips, text="No blocked IPs found.", fg=self.MUTED, bg=self.PANEL).pack(anchor="w", padx=10, pady=5)

        # 3. Targeted Ports
        f_ports = self._section(content, "Port Activity")
        f_ports.grid(row=1, column=0, sticky="nsew", padx=5, pady=5)
        if top_ports:
            for port, count in top_ports:
                tk.Label(f_ports, text=f"• Port {port:<5} |  {count} requests", font=self.F_MONO, fg=self.YELLOW, bg=self.PANEL).pack(anchor="w", padx=10, pady=4)
        else:
            tk.Label(f_ports, text="No port activity.", fg=self.MUTED, bg=self.PANEL).pack(anchor="w", padx=10, pady=5)

        # 4. Attack Summary
        f_atk = self._section(content, "Suspicious Activity")
        f_atk.grid(row=1, column=1, sticky="nsew", padx=5, pady=5)
        tk.Label(f_atk, text=f"Total HIGH threat events: {high_threats}", font=self.F_BODY, fg=self.RED, bg=self.PANEL).pack(anchor="w", padx=10, pady=5)
        if suspicious_ips:
            tk.Label(f_atk, text="Suspicious IPs:", fg=self.TEXT, bg=self.PANEL).pack(anchor="w", padx=10)
            for ip in list(suspicious_ips)[:5]:
                tk.Label(f_atk, text=f" - {ip}", font=self.F_MONO, fg=self.RED, bg=self.PANEL).pack(anchor="w", padx=10)
            if len(suspicious_ips) > 5:
                tk.Label(f_atk, text=f"   ... and {len(suspicious_ips)-5} more", bg=self.PANEL, fg=self.MUTED).pack(anchor="w", padx=10)
        else:
            tk.Label(f_atk, text="No suspicious IPs detected.", fg=self.GREEN, bg=self.PANEL).pack(anchor="w", padx=10, pady=5)

        content.grid_columnconfigure(0, weight=1)
        content.grid_columnconfigure(1, weight=1)
        content.grid_rowconfigure(0, weight=1)
        content.grid_rowconfigure(1, weight=1)
        content.grid_rowconfigure(2, weight=1)

        # 5. Port Scan Attacks panel (full width, row 2)
        f_ps = self._section(content, "🚨  Port Scan Attacks")
        f_ps.grid(row=2, column=0, columnspan=2, sticky="nsew", padx=5, pady=5)

        ps_logs = self._port_scan_logs  # from memory
        # Also pull persisted ones from DB for completeness
        db_rows = database.get_port_scan_events(limit=30)

        if not ps_logs and not db_rows:
            tk.Label(f_ps, text="No port scan events detected.",
                     fg=self.GREEN, bg=self.PANEL,
                     font=self.F_BODY).pack(anchor="w", padx=10, pady=8)
        else:
            # Header row
            hdr_fr = tk.Frame(f_ps, bg=self.PANEL)
            hdr_fr.pack(fill=tk.X, padx=10, pady=(6, 0))
            def _hdr(text, w):
                tk.Label(hdr_fr, text=text, font=self.F_H2,
                         fg=self.MUTED, bg=self.PANEL, width=w,
                         anchor="w").pack(side=tk.LEFT)
            _hdr("IP Address",        20)
            _hdr("Ports Scanned",      14)
            _hdr("Ports List",         30)
            _hdr("Timestamp",          18)

            # Scrollable list
            ps_frame = tk.Frame(f_ps, bg=self.PANEL)
            ps_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=4)

            ps_sb = tk.Scrollbar(ps_frame, orient=tk.VERTICAL)
            ps_txt = tk.Text(
                ps_frame, height=6, state=tk.DISABLED,
                yscrollcommand=ps_sb.set, font=self.F_MONO,
                bg=self.BG, fg=self.RED, relief="flat",
                highlightthickness=0, padx=6, pady=4, wrap=tk.NONE
            )
            ps_sb.config(command=ps_txt.yview)
            ps_txt.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
            ps_sb.pack(side=tk.LEFT, fill=tk.Y)

            ps_txt.config(state=tk.NORMAL)
            # In-session detections (most recent first)
            for det in reversed(ps_logs):
                ports_str = ", ".join(str(p) for p in det["ports"][:10])
                if len(det["ports"]) > 10:
                    ports_str += " …"
                line = (f"  {det['ip']:<20}  {det['ports_count']:<14}"
                        f"  {ports_str:<32}  {det['timestamp']}\n")
                ps_txt.insert(tk.END, line)
            # DB rows not already shown in memory
            known_ts = {d["timestamp"] for d in ps_logs}
            for ip, cnt, ports_str, ts in db_rows:
                if ts[:8] not in known_ts:   # rough de-dup by HH:MM:SS
                    line = (f"  {ip:<20}  {cnt:<14}"
                            f"  {ports_str[:32]:<32}  {ts}\n")
                    ps_txt.insert(tk.END, line)
            ps_txt.config(state=tk.DISABLED)

            tk.Label(f_ps,
                     text=f"Total port scan events (this session): {len(ps_logs)}",
                     font=self.F_SM, fg=self.ORANGE, bg=self.PANEL
                     ).pack(anchor="w", padx=10, pady=(0, 6))

    # ═══════════════════════════════════════════════
    # UI updaters
    # ═══════════════════════════════════════════════

    def _update_ui(self, r: dict):
        threat = r["threat"]
        color  = {"LOW": self.GREEN, "MEDIUM": self.YELLOW, "HIGH": self.RED}.get(threat, self.TEXT)

        self._v_ip.config(text=r["src_ip"])
        self._v_port.config(text=str(r["dst_port"]))
        self._v_status.config(text=r["status"], fg=color)
        self._v_threat.config(text=threat, fg=color)
        self._v_reason.config(text=r["reason"], fg=color)
        self._v_process.config(text=r.get("process", "—"))

        self._structured_logs.append({
            "ip": r["src_ip"],
            "port": r["dst_port"],
            "status": r["status"],
            "reason": r["reason"],
            "threat": threat
        })

        self._total_count += 1
        self._c_total.config(text=str(self._total_count))

        if r["status"] == "ALLOWED":
            self._allowed_count += 1
            self._c_allow.config(text=str(self._allowed_count))
        else:
            self._blocked_count += 1
            self._c_block.config(text=str(self._blocked_count))
            if threat == "HIGH":
                self._suspicious_count += 1
                self._c_sus.config(text=str(self._suspicious_count))

        # ── Auto-enforce: block HIGH threats when in Detect+Enforce mode ──
        if threat == "HIGH" and self._enforce_mode == "enforce":
            self._apply_os_block(r["src_ip"], r["reason"])

        tag  = {"LOW": "low", "MEDIUM": "medium", "HIGH": "high"}.get(threat, "low")
        proc = r.get("process", "—")
        line = (f"[{r['timestamp']}]  {r['src_ip']:<18} :{r['dst_port']:<5}  "
                f"{r['status']:<9} {threat:<7}  {r['reason']:<22} {proc}\n")
        self._log_entries.appendleft(line)

        self._log_text.config(state=tk.NORMAL)
        self._log_text.delete("1.0", tk.END)
        for entry in self._log_entries:
            t = "high" if "HIGH" in entry else ("medium" if "MEDIUM" in entry else "low")
            self._log_text.insert(tk.END, entry, t)
        self._log_text.config(state=tk.DISABLED)

    # ═══════════════════════════════════════════════
    # Export / Clear
    # ═══════════════════════════════════════════════

    def _export_logs(self):
        if not self._log_entries:
            messagebox.showinfo("Empty", "No logs to export.")
            return
        path = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Text files", "*.txt")],
            initialfile=f"firewall_log_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        )
        if path:
            with open(path, "w") as f:
                f.write("Smart Firewall v6.0  —  Real-Time Network Monitor  |  Log Export\n")
                f.write(f"Exported: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write("=" * 90 + "\n\n")
                for entry in reversed(self._log_entries):
                    f.write(entry)
                f.write(f"\nTotal: {self._total_count}  |  "
                        f"Allowed: {self._allowed_count}  |  "
                        f"Blocked: {self._blocked_count}  |  "
                        f"Suspicious: {self._suspicious_count}\n")
                if self._enforced_ips:
                    f.write(f"\nOS-enforced blocks: {sorted(self._enforced_ips)}\n")
            messagebox.showinfo("Exported", f"Logs saved to:\n{path}")

    def _clear(self):
        self._log_entries.clear()
        self._structured_logs.clear()
        self._log_text.config(state=tk.NORMAL)
        self._log_text.delete("1.0", tk.END)
        self._log_text.config(state=tk.DISABLED)
        self._total_count      = 0
        self._allowed_count    = 0
        self._blocked_count    = 0
        self._suspicious_count = 0
        self._c_total.config(text="0")
        self._c_allow.config(text="0")
        self._c_block.config(text="0")
        self._c_sus.config(text="0")
        self._enforce_lbl.config(text="")
        self.engine.reset_behaviour()
        # Reset port scan detection state
        self._port_scan_logs.clear()
        self._port_scan_detector.reset()
        self._c_pscan.config(text="0")
        self._dismiss_ps_alert()


# ═══════════════════════════════════════════════
# ENTRY POINT
# ═══════════════════════════════════════════════

if __name__ == "__main__":
    database.init_db()  # Ensure database tables exist before GUI starts
    root = tk.Tk()
    app  = FirewallGUI(root)
    root.mainloop()
