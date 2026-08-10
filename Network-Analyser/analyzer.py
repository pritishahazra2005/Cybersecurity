import csv  # for writing packet logs to a structured CSV file
from collections import Counter  # for tracking packet frequencies, byte totals, and protocol stats
from datetime import datetime  # to generate timestamps for packet capture and export filenames
import os  # for system privilege checks (root/sudo validation)
import re  # for sanitizing user-entered CSV file names
import select  # provides access to operating system I/O multiplexing
import sys  # system platform detection and terminal control
import threading  # background network sniffing and rate calculation
import time  # system delays, rate intervals, and polling rates

from rich.console import Console
from rich.layout import Layout
from rich.live import Live
from rich.panel import Panel
from rich.table import Table
from scapy.all import ICMP, IP, TCP, UDP, sniff, wrpcap  # packet sniffing & PCAP export

# Terminal I/O configuration for Unix platforms
import os

# Add this inside main() before launching anything else:
if sys.platform != "win32" and os.geteuid() != 0:
    print("[!] Privilege Check Failed: Raw packet sniffing requires root permissions.")
    print("    Please run with sudo: 'sudo python3 analyzer.py'\n")
    sys.exit(1)

# GLOBAL STATE & BUFFERS
packet_buffer = []          # Circular queue formatted for terminal UI
all_captured_packets = []   # Structured dictionary list for CSV export
all_raw_packets = []        # Scapy raw packet objects list for PCAP export
total_packets = 0
total_bytes = 0

# TELEMETRY & HOST ANALYTICS COUNTERS
ip_packets = Counter()
ip_bytes = Counter()
protocol_counts = Counter()
unique_hosts = set()

# RATE MEASUREMENT & STATUS
packet_count_last_sec = 0
current_packet_rate = 0
status_message = "Listening for live packets..."

# THREAT DETECTION & CONCURRENCY
flagged_traffic = []
lock = threading.Lock()
TARGET_IP = ""

COMMON_SERVICES = {
    80: "HTTP (Web)",
    443: "HTTPS (Web)",
    53: "DNS (Domain Lookup)",
    22: "SSH (Remote Access)",
    21: "FTP (File Transfer)",
    23: "Telnet",
    123: "NTP (Time Sync)",
    5353: "mDNS (Local Discovery)",
    1900: "SSDP (UPnP)",
    67: "DHCP",
    68: "DHCP",
}


# HELPER FUNCTIONS
def check_privileges():
    """Ensures the script is executing with root privileges required for raw packet sniffing."""
    if sys.platform != "win32":
        if os.geteuid() != 0:
            print("[!] Error: Raw packet sniffing requires administrative/root privileges.")
            print("    Please run this script using sudo: 'sudo python3 analyzer.py'")
            sys.exit(1)


def sanitize_filename(name):
    """Sanitizes user input to construct a clean, valid file base name."""
    name = name.strip()
    if not name:
        return f"traffic_log_{datetime.now().strftime('%Y%m%d_%H%M%S')}"

    # Strip illegal characters for Windows/Unix file systems
    name = re.sub(r'[\\/*?:"<>|]', "_", name)
    
    # Strip explicit extensions if user entered them (we append .csv and .pcap automatically)
    if name.lower().endswith(".csv") or name.lower().endswith(".pcap"):
        name = name.rsplit(".", 1)[0]

    return name


def resolve_service(sport, dport):
    """Translates source/destination port numbers into standard application service names."""
    if dport in COMMON_SERVICES:
        return COMMON_SERVICES[dport]
    if sport in COMMON_SERVICES:
        return COMMON_SERVICES[sport]
    return f"Port {dport}" if dport else "Unknown"


def process_packet(packet):
    """Callback function triggered by Scapy for every sniffed network packet."""
    global total_packets, total_bytes, packet_count_last_sec

    if not packet.haslayer(IP):
        return

    src_ip = packet[IP].src
    dst_ip = packet[IP].dst
    pkt_len = len(packet)

    if TARGET_IP and (TARGET_IP not in (src_ip, dst_ip)):
        return

    date_str = datetime.now().strftime("%Y-%m-%d")
    timestamp = datetime.now().strftime("%H:%M:%S")

    protocol = "Other"
    service = "-"
    dport = None

    if packet.haslayer(TCP):
        protocol = "TCP"
        dport = packet[TCP].dport
        service = resolve_service(packet[TCP].sport, dport)
    elif packet.haslayer(UDP):
        protocol = "UDP"
        dport = packet[UDP].dport
        service = resolve_service(packet[UDP].sport, dport)
    elif packet.haslayer(ICMP):
        protocol = "ICMP"
        service = "Ping / Control"

    size_str = f"{pkt_len} B" if pkt_len < 1024 else f"{pkt_len / 1024:.1f} KB"

    with lock:
        total_packets += 1
        total_bytes += pkt_len
        packet_count_last_sec += 1

        ip_packets[src_ip] += 1
        ip_bytes[src_ip] += pkt_len
        protocol_counts[protocol] += 1
        unique_hosts.add(src_ip)
        unique_hosts.add(dst_ip)

        # MINI-NIDS DETECTION LOGIC
        alert = None

        # Rule 1: Flag TCP SYN Scan / Port Reconnaissance Probe
        if packet.haslayer(TCP) and packet[TCP].flags == "S":
            alert = f"[{timestamp}] SYN Probe: {src_ip} -> {dst_ip}:{dport}"

        # Rule 2: Flag Unencrypted Cleartext Transmissions
        elif dport in [80, 21, 23]:
            proto_name = "HTTP" if dport == 80 else ("FTP" if dport == 21 else "Telnet")
            alert = f"[{timestamp}] Cleartext {proto_name}: {src_ip} -> {dst_ip}"

        # Rule 3: Flag Non-Standard Dynamic High Ports (>1024)
        elif dport and dport not in COMMON_SERVICES and dport > 1024:
            alert = f"[{timestamp}] High Port: {src_ip} -> {dst_ip}:{dport}"

        if alert and alert not in flagged_traffic:
            flagged_traffic.append(alert)
            if len(flagged_traffic) > 5:
                flagged_traffic.pop(0)

        # Append formatted string tuple for UI table display
        packet_buffer.append(
            (date_str, timestamp, src_ip, dst_ip, protocol, service, size_str)
        )
        if len(packet_buffer) > 100:
            packet_buffer.pop(0)

        # Append structured dictionary for CSV export
        packet_log = {
            "Date": date_str,
            "Time": timestamp,
            "Source IP": src_ip,
            "Destination IP": dst_ip,
            "Protocol": protocol,
            "Service": service,
            "Size (Bytes)": pkt_len,
        }
        all_captured_packets.append(packet_log)

        # Retain raw Scapy packet for Wireshark PCAP export
        all_raw_packets.append(packet)


def calculate_rates():
    """Background worker thread function that calculates packet throughput every second."""
    global packet_count_last_sec, current_packet_rate
    while True:
        time.sleep(1)
        with lock:
            current_packet_rate = packet_count_last_sec
            packet_count_last_sec = 0


def start_sniffer():
    """Starts packet capture in non-storing mode to save memory."""
    sniff(prn=process_packet, store=0)


def save_session_data(base_filename):
    """Exports session history to CSV and writes raw packet captures to PCAP for Wireshark."""
    with lock:
        if not all_captured_packets:
            return False, "No packets captured in this session."

        try:
            csv_file = f"{base_filename}.csv"
            pcap_file = f"{base_filename}.pcap"

            # 1. Export CSV Log
            fieldnames = [
                "Date",
                "Time",
                "Source IP",
                "Destination IP",
                "Protocol",
                "Service",
                "Size (Bytes)",
            ]
            with open(csv_file, mode="w", newline="") as file:
                writer = csv.DictWriter(file, fieldnames=fieldnames)
                writer.writeheader()
                writer.writerows(all_captured_packets)

            # 2. Export Wireshark PCAP File
            wrpcap(pcap_file, all_raw_packets)

            return True, f"Saved CSV ('{csv_file}') and PCAP ('{pcap_file}')"
        except Exception as e:
            return False, str(e)


def check_keyboard_input():
    """Non-blocking keyboard reader to capture user key presses interactively."""
    if sys.platform == "win32":
        import msvcrt

        if msvcrt.kbhit():
            return msvcrt.getch().decode("utf-8", errors="ignore").lower()
    else:
        if sys.stdin.isatty():
            dr, _, _ = select.select([sys.stdin], [], [], 0)
            if dr:
                return sys.stdin.read(1).lower()
    return None


def generate_layout(console: Console) -> Layout:
    """Builds and updates the Rich UI layout structure with current telemetry data."""
    layout = Layout()

    term_height = console.height
    usable_height = term_height - 3

    top_panel_height = int(usable_height * (5 / 8))
    bottom_panel_height = usable_height - top_panel_height

    top_max_rows = max(5, top_panel_height - 3)
    bottom_max_rows = max(3, bottom_panel_height - 3)

    layout.split_column(
        Layout(name="top", ratio=5),
        Layout(name="bottom", ratio=3),
        Layout(name="footer", size=3),
    )
    layout["bottom"].split_row(
        Layout(name="top_talkers", ratio=3),
        Layout(name="telemetry", ratio=2),
    )

    with lock:
        mb_transferred = total_bytes / (1024 * 1024)

        # 1. TOP PANEL: Live Packet Stream Table
        top_table = Table(expand=True, show_edge=False)
        top_table.add_column("Date", style="dim green", width=11)
        top_table.add_column("Time", style="dim green", width=9)
        top_table.add_column("Source IP", style="green")
        top_table.add_column("Destination IP", style="green")
        top_table.add_column("Protocol", style="bold green", width=9)
        top_table.add_column("Service / Application", style="bright_green")
        top_table.add_column("Size", style="dim green", justify="right", width=9)

        visible_packets = packet_buffer[-top_max_rows:]
        for pkt in visible_packets:
            top_table.add_row(pkt[0], pkt[1], pkt[2], pkt[3], pkt[4], pkt[5], pkt[6])

        top_panel = Panel(
            top_table,
            title=(
                f"Live Packet Stream | Packets: {total_packets} | Data:"
                f" {mb_transferred:.2f} MB"
            ),
            border_style="green",
        )
        layout["top"].update(top_panel)

        # 2. BOTTOM LEFT PANEL: Top Network Generators
        talkers_table = Table(expand=True, show_edge=False)
        talkers_table.add_column("Active IP Address", style="bright_green")
        talkers_table.add_column("Packets", style="green", justify="right")
        talkers_table.add_column("Data", style="dim green", justify="right")
        talkers_table.add_column("Volume Bar", style="bright_green")

        max_bytes = max(ip_bytes.values()) if ip_bytes else 1

        for ip, p_count in ip_packets.most_common(bottom_max_rows):
            b_count = ip_bytes[ip]
            data_str = (
                f"{b_count / 1024:.1f} KB"
                if b_count < 1048576
                else f"{b_count / 1048576:.2f} MB"
            )

            bar_length = 10
            filled = int((b_count / max_bytes) * bar_length)
            bar = "█" * filled + "░" * (bar_length - filled)

            talkers_table.add_row(ip, str(p_count), data_str, f"[{bar}]")

        talkers_panel = Panel(
            talkers_table, title="Top Network Generators", border_style="green"
        )
        layout["top_talkers"].update(talkers_panel)

        # 3. BOTTOM RIGHT PANEL: Telemetry & NIDS Watchlist
        avg_pkt_size = (total_bytes // total_packets) if total_packets > 0 else 0
        tcp_pct = (
            int((protocol_counts["TCP"] / total_packets) * 100)
            if total_packets > 0
            else 0
        )
        udp_pct = (
            int((protocol_counts["UDP"] / total_packets) * 100)
            if total_packets > 0
            else 0
        )
        icmp_pct = (
            int((protocol_counts["ICMP"] / total_packets) * 100)
            if total_packets > 0
            else 0
        )

        telemetry_text = (
            f"[bold green]Velocity:[/bold green] {current_packet_rate} pkts/sec\n"
        )
        telemetry_text += (
            "[bold green]Status:[/bold green] [bold black on green] ACTIVE CAPTURE"
            " [/bold black on green]\n"
        )
        telemetry_text += (
            f"[bold green]Unique Hosts Detected:[/bold green] {len(unique_hosts)}\n"
        )
        telemetry_text += (
            f"[bold green]Avg Packet Size:[/bold green] {avg_pkt_size} Bytes\n"
        )
        telemetry_text += (
            f"[bold green]Protocol Mix:[/bold green] TCP: {tcp_pct}% | UDP:"
            f" {udp_pct}% | ICMP: {icmp_pct}%\n"
        )
        telemetry_text += (
            f"[bold green]System Alert:[/bold green] [dim green]{status_message}[/dim"
            " green]\n\n"
        )
        telemetry_text += "[bold green]NIDS Threat Watchlist:[/bold green]\n"

        if flagged_traffic:
            for alert in flagged_traffic[-3:]:
                telemetry_text += f"[dim green]• {alert}[/dim green]\n"
        else:
            telemetry_text += "[dim green]No anomalies flagged...[/dim green]\n"

        telemetry_panel = Panel(
            telemetry_text, title="Telemetry & Threat Watchlist", border_style="green"
        )
        layout["telemetry"].update(telemetry_panel)

        # 4. FOOTER PANEL: Interactive Controls
        footer_grid = Table.grid(expand=True)
        footer_grid.add_column(justify="left")
        footer_grid.add_column(justify="right")
        footer_grid.add_row(
            "[bold green]Press [bold bright_green]'q'[/bold bright_green] to stop"
            " capture and exit system[/bold green]",
            "[dim green]All rights reserved to Yannich Thay[/dim green]",
        )
        layout["footer"].update(Panel(footer_grid, border_style="green"))

    return layout


# MAIN ENTRY POINT
def main():
    global TARGET_IP
    
    # 0. Check Root Privileges
    check_privileges()

    console = Console()
    console.clear()
    current_year = datetime.now().year

    print("\n****************************************************************")
    print(r"""
  _  __      _                      _      _____           __  __ _             _                _                    
 | \|  | ___| |___      _____  _ __| | __ |_   _| __ __   / _|/ _(_) ___       / \   _ __   __ _| |_   _ _______ _ __ 
 |  \| |/ _ \ __\ \ /\ / / _ \| '__| |/ /   | || '__/ _`\| |_| |_| |/ __|     / _ \ | '_ \ / _` | | | | |_  / _ \ '__|
 | |\  |  __/ |_ \ V  V / (_) | |  |   <    | || | | (_| |  _|  _| | (__     / ___ \| | | | (_| | | |_| |/ /  __/ |   
 |_| \_|\___|\__| \_/\_/ \___/|_|  |_|\_\___|_||_|  \__,_|_| |_| |_|\___|___/_/   \_\_| |_|\__,_|_|\__, /___\___|_|   
                                        |_____|                         |_____|                     |___/             
    """)
    print("****************************************************************")
    print(
        f"* Copyright © {current_year} Yannich Thay. All rights reserved.       *"
    )
    print(
        "* Network Traffic Analyzer & Mini-NIDS Dashboard               *"
    )
    print("****************************************************************")
    print()

    user_input = input(
        "Please enter an IP address to monitor (or press Enter for all): "
    ).strip()
    TARGET_IP = user_input

    print("\nLaunching interface... (Press 'q' inside dashboard to exit)")
    time.sleep(1.0)
    console.clear()

    threading.Thread(target=start_sniffer, daemon=True).start()
    threading.Thread(target=calculate_rates, daemon=True).start()

    old_settings = None
    if sys.platform != "win32" and sys.stdin.isatty():
        try:
            old_settings = termios.tcgetattr(sys.stdin)
            tty.setcbreak(sys.stdin.fileno())
        except Exception:
            pass

    try:
        with Live(
            generate_layout(console), refresh_per_second=4, console=console
        ) as live:
            while True:
                time.sleep(0.1)
                key = check_keyboard_input()
                if key == "q":
                    break
                live.update(generate_layout(console))
    except KeyboardInterrupt:
        pass
    finally:
        if old_settings and sys.platform != "win32":
            try:
                termios.tcsetattr(sys.stdin, termios.TCSADRAIN, old_settings)
            except Exception:
                pass

        console.clear()
        console.print("[bold green]Capture stopped.[/bold green]\n")

        save_choice = (
            input("Do you want to save session log & PCAP captures? (y/n): ")
            .strip()
            .lower()
        )
        if save_choice in ["y", "yes"]:
            raw_filename = input("Enter file base name (e.g., session_capture): ")
            clean_name = sanitize_filename(raw_filename)

            success, message = save_session_data(clean_name)
            if success:
                console.print(
                    f"\n[bold green][✓] Successfully saved: {message}[/bold green]"
                )
            else:
                console.print(f"\n[bold red][!] Save failed: {message}[/bold red]")
        else:
            console.print("\n[dim green]Session ended without saving.[/dim green]")

        console.print(
            "[bold green][✓] Session ended cleanly. All captures stopped.[/bold green]"
        )


if __name__ == "__main__":
    main()