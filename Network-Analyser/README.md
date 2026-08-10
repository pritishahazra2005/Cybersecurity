# 🔐 Network Traffic Analyzer

A Python-based network traffic monitoring tool that captures and analyzes live network packets and presents the results through an interactive terminal dashboard.

The project is designed as a practical cybersecurity learning project for understanding **network traffic, packet analysis, protocols, services, traffic statistics, and basic suspicious-activity detection**.

---

## 📌 Overview

Network traffic can provide valuable information about what is happening inside a system or network.

This project provides a lightweight way to observe that activity in real time.

The analyzer captures packets from a network interface, extracts useful information from them, maintains traffic statistics, and presents the results through a terminal-based interface.

It also includes basic security-focused detection logic to highlight traffic patterns that may require further investigation.

---

## ✨ Features

### 📡 Live Packet Capture

The analyzer captures network packets in real time and extracts information such as:

* Source IP address
* Destination IP address
* Protocol
* Source and destination ports
* Common services
* Packet size
* Timestamp

Supported traffic includes common protocols such as:

* TCP
* UDP
* ICMP

---

### 📊 Traffic Statistics

The application maintains useful network telemetry during a capture session, including:

* Total packets captured
* Total traffic volume
* Packets per second
* Average packet size
* Unique hosts observed
* Protocol distribution
* Top network hosts

This provides a quick overview of network activity without requiring a graphical packet-analysis application.

---

### 🚨 Basic Security Monitoring

The analyzer contains lightweight detection heuristics that can highlight potentially interesting traffic patterns.

Examples include:

* TCP SYN probing
* Cleartext HTTP traffic
* FTP traffic
* Telnet traffic
* Unusual destination ports

Detected events are displayed in the dashboard as security alerts.

> **Important:** These alerts are indicators for investigation and are not definitive proof of malicious activity.

---

### 🖥️ Interactive Terminal Dashboard

The project uses **Rich** to provide a continuously updating terminal interface.

The dashboard presents:

```text
┌─────────────────────────────────────────────┐
│             LIVE PACKET MONITOR             │
├─────────────────────────────────────────────┤
│ Source → Destination → Protocol → Service   │
│                                             │
│ 192.168.1.8 → 192.168.1.1 → UDP → DNS      │
│ 192.168.1.8 → xxx.xxx.xxx → TCP → HTTPS    │
├──────────────────────┬──────────────────────┤
│ Network Hosts        │ Telemetry            │
│                      │                      │
│ Packet Counts        │ Packet Rate          │
│ Traffic Volume       │ Protocol Statistics  │
│                      │ Security Alerts      │
└──────────────────────┴──────────────────────┘
```

---

### 💾 CSV & PCAP Export

Captured sessions can be saved for later analysis.

#### CSV

The CSV export contains structured information about observed traffic, making it useful for:

* Reviewing traffic history
* Spreadsheet analysis
* Python-based data processing
* Creating future visualizations

#### PCAP

The analyzer can also save captured packets as a PCAP file.

The resulting file can be opened in **Wireshark** for deeper packet-level investigation.

---

## 🛠️ Technologies Used

| Technology | Purpose                       |
| ---------- | ----------------------------- |
| Python     | Core application              |
| Scapy      | Packet capture and analysis   |
| Rich       | Terminal dashboard            |
| CSV        | Structured traffic export     |
| PCAP       | Packet capture storage        |
| Wireshark  | Optional packet investigation |

---

## 📂 Project Structure

```text
Network-Traffic-Analyzer/
│
├── analyzer.py
├── requirements.txt
├── README.md
├── LICENSE
├── .gitignore
└── demo.gif
```

### `analyzer.py`

The primary application containing packet capture, traffic processing, statistics, security heuristics, dashboard rendering, and session export.

### `requirements.txt`

Contains the Python dependencies required by the application.

### `demo.gif`

A demonstration of the analyzer running and processing network traffic.

### `LICENSE`

Project licensing information.

### `.gitignore`

Specifies files and directories that should not be committed to the repository.

---

## ⚙️ Installation

### 1. Clone the repository

```bash
git clone <your-repository-url>
cd Network-Traffic-Analyzer
```

### 2. Create a virtual environment

#### Windows

```powershell
python -m venv venv
```

Activate it:

```powershell
.\venv\Scripts\Activate.ps1
```

#### Linux / macOS

```bash
python3 -m venv venv
source venv/bin/activate
```

### 3. Install dependencies

```bash
pip install -r requirements.txt
```

---

## 🪟 Windows Setup

If you are running the analyzer on Windows, **Npcap** is required for packet capture.

After installing Npcap, open a new PowerShell window and run the analyzer.

Depending on your system configuration, packet capture may require administrator privileges.

---

## ▶️ Usage

Start the analyzer with:

```bash
python analyzer.py
```

The application may ask for an IP address to monitor:

```text
Monitor specific IP (press Enter for all traffic):
```

### Monitor all available traffic

Press **Enter** without entering an IP address.

### Monitor a specific host

Enter an IP address that you are authorized to monitor:

```text
192.168.1.8
```

The application will then begin displaying captured traffic through the terminal dashboard.

---

## 🧪 Testing

To test the analyzer, run it on a system or network you control.

After starting the application, generate normal network traffic by:

* Opening websites
* Refreshing web pages
* Running DNS queries
* Using normal network applications
* Running a simple connectivity test such as:

```bash
ping google.com
```

As traffic is generated, the dashboard should begin updating with packet information and network statistics.

---

## 📈 Example Traffic

A normal session could display traffic similar to:

<img src="./demo.gif" width="500" alt="App Demo">


## 🚨 Security Alert Example

When traffic matches one of the analyzer's detection heuristics, the dashboard can display an alert such as:

```text
Security Events

[LOW] Unencrypted HTTP traffic detected
[MEDIUM] Cleartext Telnet traffic detected
[HIGH] Possible port scan detected
```

These alerts should be treated as **investigation leads**, not automatic conclusions.

---

## 🔬 PCAP Investigation

One of the useful parts of the project is the ability to move from automated monitoring to manual packet investigation.

The workflow is:

```text
Live Network Traffic
        │
        ▼
   Packet Capture
        │
        ▼
 Network Traffic
   Analyzer
        │
        ├───────────────┐
        ▼               ▼
     CSV Export      PCAP Export
                        │
                        ▼
                    Wireshark
                        │
                        ▼
               Detailed Analysis
```

This makes the project useful for learning how network-monitoring tools and packet-analysis tools can work together.

---

## 🧠 Concepts Demonstrated

This project provides hands-on experience with:

* Network packet capture
* IP addressing
* TCP/IP networking
* TCP and UDP
* ICMP
* Network ports
* Common network services
* DNS traffic
* HTTP/HTTPS traffic
* Network traffic statistics
* Packet analysis
* Basic intrusion-detection concepts
* PCAP files
* Python networking
* Terminal-based security tools

---

## 🚧 Future Improvements

Possible improvements include:

* [ ] More advanced port-scan detection
* [ ] Configurable detection thresholds
* [ ] Network-interface selection
* [ ] Improved filtering options
* [ ] JSON export
* [ ] Persistent event logging
* [ ] More protocol-specific analysis
* [ ] Improved alert correlation
* [ ] Historical traffic visualization
* [ ] Modular detection rules

---

## ⚠️ Disclaimer

This project is intended for **educational, research, and authorized defensive-security purposes**.

Only capture or analyze traffic on networks and systems where you have permission to do so.

The detection mechanisms included in this project are lightweight heuristics and may produce false positives or fail to detect sophisticated attacks. They should not be considered a replacement for a production-grade IDS/IPS.

---

## 👩‍💻 Author

**Pritisha Hazra**

Computer Science & Engineering
Cybersecurity • Cloud Security • Python

---


