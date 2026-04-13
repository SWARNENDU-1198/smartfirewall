"""
Attack Simulator v1.0  (Educational Demo Tool)
================================================
Simulates various cyber-attack patterns to test the Smart Firewall Simulator.
This is NOT real malware — it generates simulated traffic patterns only.

Attack Types:
  1. Port Scan         — rapid probing of many ports from one IP
  2. DDoS Flood        — massive packet burst from multiple IPs
  3. Brute Force       — repeated login attempts on auth ports
  4. IP Spoofing       — randomized source IPs to evade detection
  5. Targeted Attack   — focused attack on a specific IP + port

Usage: Run this alongside the Smart Firewall Simulator to demo detection.

Tech: Python 3 + Tkinter (standalone GUI, no dependencies)
"""

import tkinter as tk
from tkinter import messagebox
import random
import time
import socket
import threading
import json
from datetime import datetime


# ═══════════════════════════════════════════════
# Attack Engine (generates attack packets)
# ═══════════════════════════════════════════════

class AttackEngine:
    """Generates various simulated attack patterns."""

    @staticmethod
    def port_scan(target_ip="192.168.1.100", port_range=(1, 1024)):
        """Simulate a port scan: ONE attacker IP, many ports rapidly."""
        attacker_ip = "10.0.0.66"   # fixed attacker — realistic, triggers PortScanDetector
        packets = []
        for port in range(port_range[0], min(port_range[1], port_range[0] + 50)):
            packets.append({
                "src_ip":    attacker_ip,
                "dst_ip":    target_ip,
                "dst_port":  port,
                "attack":    "PORT SCAN",
                "timestamp": time.strftime("%H:%M:%S"),
            })
        return packets

    @staticmethod
    def ddos_flood(target_ip="192.168.1.100", count=30):
        """Simulate DDoS: one dominant IP floods target to exceed behaviour threshold."""
        packets = []
        flood_ip = "10.0.0.77"   # fixed flood IP — deterministic, always triggers
        for i in range(count):
            # 80% from same IP to reliably exceed threshold
            if i < int(count * 0.8):
                src = flood_ip
            else:
                src = f"192.168.1.{random.randint(2, 254)}"
            packets.append({
                "src_ip":    src,
                "dst_ip":    target_ip,
                "dst_port":  random.choice([80, 443, 8080, 3000]),
                "attack":    "DDoS FLOOD",
                "timestamp": time.strftime("%H:%M:%S"),
            })
        return packets

    @staticmethod
    def brute_force(target_ip="192.168.1.100", attempts=20):
        """Simulate brute force: same IP hitting auth ports repeatedly."""
        attacker_ip = f"192.168.1.13"
        packets = []
        for _ in range(attempts):
            packets.append({
                "src_ip":    attacker_ip,
                "dst_ip":    target_ip,
                "dst_port":  random.choice([22, 3389, 445, 21]),
                "attack":    "BRUTE FORCE",
                "timestamp": time.strftime("%H:%M:%S"),
            })
        return packets

    @staticmethod
    def ip_spoof(target_ip="192.168.1.100", count=15):
        """Simulate IP spoofing: small groups from same spoofed IPs to expose pattern."""
        packets = []
        # Use 3 spoofed IPs, each sending multiple packets — each group hits threshold
        spoofed_ips = ["10.0.1.11", "10.0.2.22", "10.0.3.33"]
        for i in range(count):
            src = spoofed_ips[i % len(spoofed_ips)]  # cycles through 3 IPs
            packets.append({
                "src_ip":    src,
                "dst_ip":    target_ip,
                "dst_port":  random.choice([80, 443, 53, 8443]),
                "attack":    "IP SPOOF",
                "timestamp": time.strftime("%H:%M:%S"),
            })
        return packets

    @staticmethod
    def targeted_attack(target_ip="192.168.1.100", target_port=443, count=25):
        """Simulate targeted attack: one IP hammering one port."""
        attacker = f"192.168.1.45"
        packets = []
        for _ in range(count):
            packets.append({
                "src_ip":    attacker,
                "dst_ip":    target_ip,
                "dst_port":  target_port,
                "attack":    "TARGETED",
                "timestamp": time.strftime("%H:%M:%S"),
            })
        return packets


# ═══════════════════════════════════════════════
# Attack Simulator GUI
# ═══════════════════════════════════════════════

class AttackGUI:
    BG       = "#1a1a2e"
    PANEL    = "#16213e"
    RED      = "#e94560"
    ORANGE   = "#f0883e"
    YELLOW   = "#d29922"
    GREEN    = "#3fb950"
    CYAN     = "#0f3460"
    TEXT     = "#e0e0e0"
    MUTED    = "#8b949e"
    INPUT_BG = "#1a1a2e"
    ACCENT   = "#e94560"

    def __init__(self, root):
        self.root = root
        self.engine = AttackEngine()
        self._attack_running = False
        self._packets_sent = 0
        self._log_lines = []

        self._build_window()
        self._build_ui()

    def _build_window(self):
        self.root.title("⚡ Attack Simulator — Firewall Test Tool")
        self.root.geometry("700x650")
        self.root.resizable(True, True)
        self.root.minsize(650, 550)
        self.root.configure(bg=self.BG)
        self.F_H1   = ("Segoe UI", 14, "bold")
        self.F_H2   = ("Segoe UI", 10, "bold")
        self.F_BODY = ("Segoe UI", 10)
        self.F_MONO = ("Consolas",  9)
        self.F_SM   = ("Segoe UI", 9)

    def _btn(self, parent, text, cmd, color, **kw):
        b = tk.Button(parent, text=text, command=cmd, bg=color, fg="white",
                      font=self.F_H2, relief="flat", cursor="hand2",
                      activebackground=color, activeforeground="white",
                      padx=12, pady=5, **kw)
        orig = color
        b.bind("<Enter>", lambda e, b=b: b.config(bg=self._lit(orig)))
        b.bind("<Leave>", lambda e, b=b: b.config(bg=orig))
        return b

    @staticmethod
    def _lit(c):
        h = c.lstrip("#")
        return "#{:02x}{:02x}{:02x}".format(
            *[min(255, int(h[i:i+2], 16)+25) for i in (0,2,4)])

    def _build_ui(self):
        # ─── HEADER ──────────────────────────────────────
        hdr = tk.Frame(self.root, bg=self.RED)
        hdr.pack(fill=tk.X)

        tk.Label(hdr, text="⚡  Attack Simulator — Firewall Test Tool",
                 font=self.F_H1, bg=self.RED, fg="white", pady=8
                 ).pack(side=tk.LEFT, padx=14)

        self._count_lbl = tk.Label(hdr, text="Packets: 0", font=self.F_H2,
                                   bg=self.RED, fg="white")
        self._count_lbl.pack(side=tk.RIGHT, padx=14)

        # ─── WARNING ─────────────────────────────────────
        warn = tk.Label(self.root,
                        text="⚠  EDUCATIONAL TOOL ONLY — Generates simulated attack patterns for firewall testing",
                        font=self.F_SM, bg=self.ORANGE, fg="white", pady=4)
        warn.pack(fill=tk.X)

        # ─── ATTACK BUTTONS ─────────────────────────────
        atk = tk.LabelFrame(self.root, text="  ATTACK TYPES  ", font=self.F_H2,
                            fg=self.RED, bg=self.PANEL, bd=1, relief="solid")
        atk.pack(fill=tk.X, padx=10, pady=6)

        btn_frame = tk.Frame(atk, bg=self.PANEL)
        btn_frame.pack(fill=tk.X, padx=8, pady=8)

        attacks = [
            ("🔍 Port Scan",       self._run_port_scan,    "#e94560"),
            ("🌊 DDoS Flood",      self._run_ddos,         "#ff6b35"),
            ("🔐 Brute Force",     self._run_brute_force,  "#d29922"),
            ("🎭 IP Spoof",        self._run_ip_spoof,     "#a371f7"),
            ("🎯 Targeted Attack", self._run_targeted,     "#f85149"),
        ]

        for i, (text, cmd, color) in enumerate(attacks):
            b = self._btn(btn_frame, text, cmd, color)
            b.grid(row=i // 3, column=i % 3, padx=4, pady=4, sticky="ew")

        btn_frame.columnconfigure(0, weight=1)
        btn_frame.columnconfigure(1, weight=1)
        btn_frame.columnconfigure(2, weight=1)

        # ─── FULL ASSAULT ────────────────────────────────
        assault_frame = tk.Frame(atk, bg=self.PANEL)
        assault_frame.pack(fill=tk.X, padx=8, pady=(0, 8))

        self._btn(assault_frame, "💀 FULL ASSAULT (All Attacks)",
                  self._run_full_assault, "#8b0000").pack(fill=tk.X)

        # ─── STATUS ─────────────────────────────────────
        self._status_lbl = tk.Label(self.root, text="Ready — Select an attack type",
                                    font=self.F_BODY, bg=self.BG, fg=self.MUTED,
                                    pady=4)
        self._status_lbl.pack(fill=tk.X, padx=10)

        # ─── ATTACK LOG ─────────────────────────────────
        log_frame = tk.LabelFrame(self.root, text="  ATTACK LOG  ", font=self.F_H2,
                                  fg=self.RED, bg=self.PANEL, bd=1, relief="solid")
        log_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=6)

        ls = tk.Scrollbar(log_frame, orient=tk.VERTICAL)
        self._log_text = tk.Text(log_frame, state=tk.DISABLED, height=12,
                                 yscrollcommand=ls.set, font=self.F_MONO,
                                 bg=self.BG, fg=self.TEXT, relief="flat",
                                 highlightthickness=0, padx=6, pady=4, wrap=tk.NONE)
        ls.config(command=self._log_text.yview)
        self._log_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        ls.pack(side=tk.RIGHT, fill=tk.Y)

        self._log_text.tag_config("scan",   foreground="#e94560")
        self._log_text.tag_config("ddos",   foreground="#ff6b35")
        self._log_text.tag_config("brute",  foreground="#d29922")
        self._log_text.tag_config("spoof",  foreground="#a371f7")
        self._log_text.tag_config("target", foreground="#f85149")
        self._log_text.tag_config("info",   foreground="#3fb950")

        # ─── FOOTER ─────────────────────────────────────
        foot = tk.Frame(self.root, bg=self.BG)
        foot.pack(fill=tk.X, padx=10, pady=6)

        self._btn(foot, "⟳ Clear Log", self._clear_log, self.MUTED).pack(side=tk.RIGHT, padx=3)

        disc = tk.Label(self.root,
                        text="🔒  Safe simulation — no real network attacks are performed",
                        font=self.F_SM, bg="#2d2d2d", fg=self.GREEN, pady=3)
        disc.pack(fill=tk.X, side=tk.BOTTOM)

    # ═══════════════════════════════════════════════
    # Attack runners
    # ═══════════════════════════════════════════════

    def _log(self, text, tag="info"):
        self._log_text.config(state=tk.NORMAL)
        self._log_text.insert(tk.END, text + "\n", tag)
        self._log_text.see(tk.END)
        self._log_text.config(state=tk.DISABLED)

    def _process_packets(self, packets, attack_name, tag):
        self._status_lbl.config(text=f"⚡ Executing: {attack_name}...", fg=self.RED)
        self._log(f"\n{'━'*60}", "info")
        self._log(f"  ⚡ {attack_name} STARTED  [{time.strftime('%H:%M:%S')}]", tag)
        self._log(f"  Packets: {len(packets)}", "info")
        self._log(f"{'━'*60}", "info")

        # Network sending
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        for pkt in packets:
            self._packets_sent += 1
            line = (f"  [{pkt['timestamp']}]  {pkt['src_ip']:<18} → "
                    f":{pkt['dst_port']:<5}  {pkt['attack']}")
            self._log(line, tag)
            
            # Send real traffic to Firewall
            try:
                sock.sendto(json.dumps(pkt).encode(), ("127.0.0.1", 5555))
            except: pass

        self._count_lbl.config(text=f"Packets: {self._packets_sent}")
        self._log(f"  ✔ {attack_name} COMPLETE — {len(packets)} packets sent", "info")
        self._status_lbl.config(text=f"✔ {attack_name} complete — "
                                     f"{len(packets)} packets generated", fg=self.GREEN)

    def _run_port_scan(self):
        pkts = self.engine.port_scan()
        self._process_packets(pkts, "PORT SCAN", "scan")

    def _run_ddos(self):
        pkts = self.engine.ddos_flood()
        self._process_packets(pkts, "DDoS FLOOD", "ddos")

    def _run_brute_force(self):
        pkts = self.engine.brute_force()
        self._process_packets(pkts, "BRUTE FORCE", "brute")

    def _run_ip_spoof(self):
        pkts = self.engine.ip_spoof()
        self._process_packets(pkts, "IP SPOOF", "spoof")

    def _run_targeted(self):
        pkts = self.engine.targeted_attack()
        self._process_packets(pkts, "TARGETED ATTACK", "target")

    def _run_full_assault(self):
        confirm = messagebox.askyesno(
            "💀 Full Assault",
            "This will execute ALL attack types simultaneously.\n\n"
            "Total: ~140 simulated packets\n\n"
            "Proceed?")
        if not confirm:
            return

        self._log(f"\n{'═'*60}", "info")
        self._log(f"  💀 FULL ASSAULT INITIATED  [{time.strftime('%H:%M:%S')}]", "info")
        self._log(f"{'═'*60}", "info")

        all_attacks = [
            (self.engine.port_scan(),         "PORT SCAN",       "scan"),
            (self.engine.ddos_flood(),         "DDoS FLOOD",      "ddos"),
            (self.engine.brute_force(),        "BRUTE FORCE",     "brute"),
            (self.engine.ip_spoof(),           "IP SPOOF",        "spoof"),
            (self.engine.targeted_attack(),    "TARGETED ATTACK", "target"),
        ]

        total = 0
        for pkts, name, tag in all_attacks:
            self._process_packets(pkts, name, tag)
            total += len(pkts)

        self._log(f"\n{'═'*60}", "info")
        self._log(f"  💀 FULL ASSAULT COMPLETE — {total} total packets", "info")
        self._log(f"{'═'*60}", "info")
        self._status_lbl.config(text=f"💀 Full Assault complete — {total} packets",
                                fg=self.ORANGE)

    def _clear_log(self):
        self._log_text.config(state=tk.NORMAL)
        self._log_text.delete("1.0", tk.END)
        self._log_text.config(state=tk.DISABLED)
        self._packets_sent = 0
        self._count_lbl.config(text="Packets: 0")
        self._status_lbl.config(text="Ready — Select an attack type", fg=self.MUTED)


# ═══════════════════════════════════════════════
# ENTRY POINT
# ═══════════════════════════════════════════════

if __name__ == "__main__":
    root = tk.Tk()
    app  = AttackGUI(root)
    root.mainloop()
