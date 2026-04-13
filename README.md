# 🔥 Smart Firewall (Real-Time Host-Based Firewall + IDS)

A lightweight, real-time **host-based firewall and intrusion detection system (IDS)** built in Python.
This project monitors **live OS network connections**, detects **suspicious behavior and port scanning**, and can optionally enforce **real blocking using system firewall rules**.

---

## 🚀 Features

### 🛡️ Real-Time Network Monitoring

* Captures **live connections** using `psutil`
* Works on **actual OS traffic** (no simulation)

### ⚡ Rule-Based Filtering

* Block traffic based on:

  * IP address
  * Port number
* Supports **whitelist override**

### 🧠 Behavior-Based Detection

* Detects:

  * Repeated requests (flood-like behavior)
  * Suspicious connection patterns

### 🔍 Port Scan Detection

* Identifies when:

  * Same IP accesses **multiple ports in short time**
* Classifies as:

  * **HIGH threat**
  * “Port Scan Detected”

### 🔐 Optional Real Blocking

* Integrates with **Windows Firewall**
* Can:

  * Block malicious IPs
  * Unblock them safely

### 📊 Analysis Dashboard

* View:

  * Total traffic
  * Blocked vs allowed
  * Top malicious IPs
  * Port activity
* SOC-style insights

### 📱 Multi-Device Attack Detection

* Detects attacks from:

  * Kali Linux
  * Mobile devices
  * Other systems in same network

---

## 🧱 Architecture

```
Real Network (OS)
        ↓
psutil (Connection Capture)
        ↓
Firewall Engine
(Rules + Behavior + Port Scan Detection)
        ↓
Decision Engine
(ALLOW / BLOCK / HIGH THREAT)
        ↓
Optional Enforcement Layer
(Windows Firewall)
        ↓
Logs + Dashboard
```

---

## ⚙️ Tech Stack

* **Python**
* **Tkinter** (GUI)
* **psutil** (network monitoring)
* **subprocess** (OS-level firewall integration)

---

## 📦 Installation

### 1. Clone Repository

```bash
git clone https://github.com/your-username/smart-firewall.git
cd smart-firewall
```

### 2. Install Dependencies

```bash
pip install psutil
```

### 3. Run Application

```bash
python main.py
```

> ⚠️ For real blocking, run as **Administrator**

---

## 🧪 Demo & Testing

### 🔹 Local Attack (Windows PowerShell)

```powershell
1..200 | % { Test-NetConnection YOUR_IP -Port $_ -WarningAction SilentlyContinue }
```

### 🔹 Kali Linux Attack

```bash
nmap YOUR_IP
```

### 🔹 Mobile Attack

* Open browser:

```
http://YOUR_IP:8000
```

* Refresh repeatedly

---

## 🔴 Detection Output Example

```
IP: 192.168.1.10
Status: BLOCKED
Reason: Port Scan Detected
Threat: HIGH
```

---

## 📊 Dashboard Insights

* Total Packets
* Blocked / Allowed Ratio
* Suspicious Events
* Top Attacker IPs
* Port Scan Summary

---

## 🧠 Detection Logic

### Behavior Detection

```
If requests from same IP > threshold → Suspicious
```

### Port Scan Detection

```
If unique ports accessed by same IP > threshold within time window → Port Scan
```

---

## 🔐 Real Blocking (Windows)

### Block IP

```bash
netsh advfirewall firewall add rule name="Block_<IP>" dir=in action=block remoteip=<IP>
```

### Unblock IP

```bash
netsh advfirewall firewall delete rule name="Block_<IP>"
```

---

## ⚠️ Safety Notice

* Use only in **controlled environments**
* Do not test on unauthorized systems
* Avoid blocking:

  * Your own IP
  * Router IP

---

## 🏆 Use Cases

* Cybersecurity demonstrations (NFSU, etc.)
* Learning firewall & IDS concepts
* Network behavior analysis
* Basic intrusion detection research

---

## 🔮 Future Improvements

* Advanced scan detection (SYN, stealth scans)
* Graph-based traffic visualization
* Machine learning-based anomaly detection
* Cross-platform firewall enforcement (Linux/macOS)
* Alert system (email / notifications)

---

## 🤝 Contributing

Pull requests are welcome. For major changes, please open an issue first.

---

## 📜 License

This project is for **educational and research purposes only**.

---

## 👨‍💻 Author

Developed as a **real-time cybersecurity project** demonstrating firewall + IDS concepts for practical environments.

---

## ⭐ Acknowledgment

Inspired by real-world systems like:

* Host-based firewalls
* Intrusion Detection Systems (IDS)
* Security Operations Center (SOC) tools

---

## 🚀 Final Note

> This project bridges the gap between theoretical firewall concepts and real-world implementation by combining **live monitoring, intelligent detection, and optional enforcement** into a single lightweight system.
