# 🌐 Network Traffic Analyzer

A lightweight **real-time network traffic analyzer and mini-NIDS** built with Python, **Scapy**, and **Rich**.

The tool captures live network packets, analyzes basic traffic characteristics, displays network activity through an interactive terminal dashboard, and highlights potentially suspicious traffic patterns.

> ⚠️ **Educational / Defensive Use:** Only capture traffic on networks and systems you own or have explicit permission to monitor.

---

## 📌 Overview

This project provides a simple way to observe network activity directly from the terminal.

It combines:

* **Packet capture** using Scapy
* **Live terminal visualization** using Rich
* **Protocol and service identification**
* **Network host statistics**
* **Traffic telemetry**
* **Basic NIDS-style alerts**
* **CSV and PCAP session export**

The project is intended as a practical introduction to **network monitoring, packet analysis, and defensive security concepts**.

---

## ✨ Features

### 📡 Live Packet Capture

Captures network packets in real time and displays useful information including:

* Source IP
* Destination IP
* Protocol
* Service
* Packet size
* Timestamp

The analyzer supports common traffic types such as:

* TCP
* UDP
* ICMP

---

### 📊 Real-Time Network Dashboard

The Rich-powered terminal interface provides a live view of network activity.

The dashboard includes:

```text
Live Packet Stream
        │
        ├── Source / Destination
        ├── Protocol
        ├── Service
        └── Packet Size

Top Network Hosts
        │
        ├── Packet count
        └── Traffic volume

Telemetry
        │
        ├── Packet rate
        ├── Total packets
        ├── Total bytes
        └── Network activity

Security Watchlist
        │
        └── Suspicious traffic alerts
```

---

## 🚨 Mini-NIDS Detection

The analyzer includes lightweight heuristic rules for identifying potentially suspicious traffic.

It can highlight patterns such as:

### SYN Probes

TCP SYN traffic can be surfaced as a possible probing activity.

### Cleartext Protocols

The analyzer can identify traffic associated with services such as:

* HTTP
* FTP
* Telnet

These protocols may expose information without encryption.

### Unusual Ports

Traffic involving uncommon or high destination ports can be surfaced for investigation.

> These detections are **heuristics**, not definitive indicators of compromise. A flagged packet should be investigated rather than automatically treated as malicious.

---

## 💾 Export Captured Traffic

At the end of a capture session, traffic can be exported into two useful formats.

### CSV

Provides structured traffic information that can be used for analysis in spreadsheet or scripting tools.

Example fields include:

```text
Date
Time
Source IP
Destination IP
Protocol
Service
Size
```

### PCAP

The captured packets can also be saved as a `.pcap` file.

PCAP files can be opened in tools such as **Wireshark** for deeper packet-level investigation.

---

## 🛠️ Technologies

| Technology | Purpose                            |
| ---------- | ---------------------------------- |
| Python     | Core implementation                |
| Scapy      | Packet capture and packet analysis |
| Rich       | Live terminal dashboard            |
| CSV        | Structured traffic export          |
| PCAP       | Raw packet capture export          |
| Wireshark  | Optional packet investigation      |

---

## 📂 Project Structure

```text
Network_Traffic_Analyzer/
│
├── analyzer.py
├── requirements.txt
├── README.md
├── LICENSE
├── .gitignore
└── demo.gif
```

### `analyzer.py`

Main application containing packet capture, traffic analysis, dashboard rendering, detection logic, and export functionality.

### `requirements.txt`

Contains the Python packages required to run the analyzer.

### `demo.gif`

Demonstrates the analyzer running in a live terminal environment.

---

## ⚙️ Installation

### 1. Clone the repository

```bash
git clone <your-repository-url>
cd Network_Traffic_Analyzer
```

### 2. Create a virtual environment

#### Windows

```powershell
python -m venv venv
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

On Windows, Scapy requires a packet-capture driver such as **Npcap**.

Install Npcap before running the analyzer.

After installation, open a new terminal and run:

```powershell
python analyzer.py
```

Depending on your environment, packet capture may require elevated privileges.

---

## ▶️ Running the Analyzer

Start the program with:

```bash
python analyzer.py
```

The application will check the environment and then begin the monitoring workflow.

You can provide an IP address when prompted if you want to focus the analysis on a particular host.

For general testing, leave the field empty and press **Enter** to observe available traffic.

---

## 🧪 Testing

Once the analyzer is running, generate normal network traffic on your own machine.

For example:

```bash
ping google.com
```

You can also:

* Browse websites
* Refresh web pages
* Perform DNS lookups
* Use normal network applications

The dashboard should begin displaying packets and updating its telemetry.

Example:

```text
Source          Destination       Protocol     Service
192.168.1.8     192.168.1.1       UDP          DNS
192.168.1.8     xxx.xxx.xxx.xxx   TCP          HTTPS
192.168.1.1     192.168.1.8       UDP          DNS
```

---

## 🔎 Understanding the Dashboard

### Live Packet Stream

Shows recently captured packets and their basic characteristics.

### Top Network Hosts

Displays hosts generating significant amounts of traffic.

### Telemetry

Provides an overview of the current capture session, including packet activity and traffic statistics.

### Security Watchlist

Displays traffic patterns that match the analyzer's built-in heuristic rules.

---

## 📈 Example Output

A typical session may look similar to:

```text
┌──────────────────── Live Packet Stream ────────────────────┐
│ Time      Source        Destination       Protocol Service │
│                                                            │
│ 11:42:01  192.168.1.8   192.168.1.1       UDP      DNS     │
│ 11:42:02  192.168.1.8   xxx.xxx.xxx.xxx   TCP      HTTPS   │
│ 11:42:03  192.168.1.1   192.168.1.8       UDP      DNS     │
└────────────────────────────────────────────────────────────┘

Top Network Hosts

192.168.1.1       421 packets
192.168.1.8       287 packets

Telemetry

Packets: 708
Traffic: 486 KB
Packet Rate: 32 packets/sec

Security Watchlist

[LOW] Unencrypted HTTP traffic detected
```

*Output varies depending on the network environment and traffic being captured.*

---

## 🔬 PCAP Analysis with Wireshark

The exported PCAP file can be opened in Wireshark for additional investigation.

A typical workflow is:

```text
Network Traffic
      ↓
Network Traffic Analyzer
      ↓
Capture packets
      ↓
Export PCAP
      ↓
Wireshark
      ↓
Detailed packet investigation
```

This makes the project useful as a starting point for learning how automated monitoring and manual packet analysis can complement each other.

---

## 🧠 Concepts Demonstrated

This project provides practical exposure to:

* Network packet capture
* TCP/IP traffic
* TCP and UDP ports
* ICMP traffic
* DNS and HTTP/HTTPS traffic
* Network host identification
* Packet statistics
* Traffic monitoring
* Basic intrusion-detection heuristics
* PCAP analysis
* Python networking
* Terminal-based security tooling

---

## 🚧 Possible Improvements

Some ideas for extending the project include:

* More advanced port-scan detection
* Configurable detection thresholds
* Additional protocol support
* Improved alert correlation
* JSON export
* Persistent logging
* Network-interface selection
* Configurable filtering
* More detailed protocol statistics
* Integration with external security monitoring systems

---

## ⚠️ Disclaimer

This project is intended for **educational and authorized defensive security testing**.

Do not use it to capture, inspect, or analyze network traffic that you do not have permission to monitor.

The included detection rules are basic heuristics and may produce **false positives or false negatives**. They should not be considered a replacement for a production-grade IDS/IPS.

---

## 👩‍💻 Author

**Pritisha Hazra**

Computer Science & Engineering
Cybersecurity | Cloud Security | Python

---

## 📜 License

This project is released under the **MIT License**.

See [`LICENSE`](LICENSE) for details.
