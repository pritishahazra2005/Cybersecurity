"""
SentinelNet
-----------
Lightweight Network Traffic Monitor & Mini-NIDS

Features:
- Live packet capture using Scapy
- Protocol and host statistics
- Service identification
- Basic suspicious-traffic detection
- Packet-rate monitoring
- CSV and PCAP session export
- Interactive Rich terminal dashboard

Use only on networks and systems you are authorized to monitor.
"""

import csv
import os
import re
import select
import sys
import threading
import time
from collections import Counter, defaultdict
from datetime import datetime

from rich.console import Console
from rich.layout import Layout
from rich.live import Live
from rich.panel import Panel
from rich.table import Table
from scapy.all import ICMP, IP, TCP, UDP, sniff, wrpcap


# ============================================================
# CONFIGURATION
# ============================================================


MAX_VISIBLE_PACKETS = 100
MAX_ALERTS = 6
SCAN_WINDOW_SECONDS = 10
SCAN_PORT_THRESHOLD = 8

COMMON_SERVICES = {
    20: "FTP-Data",
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    67: "DHCP",
    68: "DHCP",
    80: "HTTP",
    110: "POP3",
    123: "NTP",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    587: "SMTP",
    993: "IMAPS",
    995: "POP3S",
    1900: "SSDP",
    3306: "MySQL",
    5353: "mDNS",
    8080: "HTTP-Alt",
}


# ============================================================
# SHARED STATE
# ============================================================

packet_buffer = []
traffic_records = []
raw_packets = []

ip_packet_counts = Counter()
ip_byte_counts = Counter()
protocol_counts = Counter()
unique_hosts = set()

security_alerts = []

# Track destination ports contacted by each source.
scan_tracker = defaultdict(dict)

total_packets = 0
total_bytes = 0
packets_last_second = 0
packets_per_second = 0

target_ip = ""
capture_running = True

lock = threading.Lock()


# ============================================================
# PRIVILEGE CHECK
# ============================================================

def check_privileges():
    """
    Check whether the program has enough privileges for packet capture.

    Linux/macOS generally require root privileges.
    Windows usually relies on Npcap being installed correctly.
    """

    if sys.platform != "win32":
        if os.geteuid() != 0:
            print("[!] SentinelNet requires elevated privileges.")
            print("    Try: sudo python3 analyzer.py")
            sys.exit(1)


# ============================================================
# UTILITY FUNCTIONS
# ============================================================

def sanitize_filename(filename):
    """Create a safe filename from user input."""

    filename = filename.strip()

    if not filename:
        return f"sentinelnet_{datetime.now().strftime('%Y%m%d_%H%M%S')}"

    filename = re.sub(r'[\\/*?:"<>|]', "_", filename)

    for extension in (".csv", ".pcap", ".pcapng"):
        if filename.lower().endswith(extension):
            filename = filename[: -len(extension)]

    return filename


def format_bytes(value):
    """Convert bytes into a readable value."""

    if value < 1024:
        return f"{value} B"

    if value < 1024 * 1024:
        return f"{value / 1024:.1f} KB"

    if value < 1024 * 1024 * 1024:
        return f"{value / (1024 * 1024):.2f} MB"

    return f"{value / (1024 * 1024 * 1024):.2f} GB"


def resolve_service(source_port, destination_port):
    """Identify a common network service from TCP/UDP ports."""

    if destination_port in COMMON_SERVICES:
        return COMMON_SERVICES[destination_port]

    if source_port in COMMON_SERVICES:
        return COMMON_SERVICES[source_port]

    if destination_port:
        return f"Port {destination_port}"

    return "Unknown"


def add_alert(message, severity="LOW"):
    """Add a security alert while avoiding duplicate messages."""

    global security_alerts

    alert = {
        "time": datetime.now().strftime("%H:%M:%S"),
        "severity": severity,
        "message": message,
    }

    with lock:
        duplicate = any(
            item["severity"] == severity
            and item["message"] == message
            for item in security_alerts
        )

        if not duplicate:
            security_alerts.append(alert)

        if len(security_alerts) > MAX_ALERTS:
            security_alerts.pop(0)


# ============================================================
# THREAT DETECTION
# ============================================================

def detect_threats(packet, src_ip, dst_ip, destination_port, timestamp):
    """
    Apply lightweight defensive heuristics to captured packets.

    These are indicators, not proof of malicious activity.
    """

    # --------------------------------------------------------
    # 1. Cleartext services
    # --------------------------------------------------------

    if destination_port == 21:
        add_alert(
            f"Cleartext FTP traffic: {src_ip} -> {dst_ip}",
            "MEDIUM",
        )

    elif destination_port == 23:
        add_alert(
            f"Cleartext Telnet traffic: {src_ip} -> {dst_ip}",
            "MEDIUM",
        )

    elif destination_port == 80:
        add_alert(
            f"Unencrypted HTTP traffic: {src_ip} -> {dst_ip}",
            "LOW",
        )

    # --------------------------------------------------------
    # 2. Suspicious high destination ports
    # --------------------------------------------------------

    if (
        destination_port
        and destination_port > 1024
        and destination_port not in COMMON_SERVICES
    ):
        add_alert(
            f"Unusual destination port {destination_port}: "
            f"{src_ip} -> {dst_ip}",
            "LOW",
        )

    # --------------------------------------------------------
    # 3. TCP SYN monitoring
    # --------------------------------------------------------

    if packet.haslayer(TCP):

        flags = packet[TCP].flags

        # SYN without ACK = connection initiation
        if flags == "S":

            now = time.time()

            with lock:
                source_ports = scan_tracker[src_ip]

                # Remove old observations
                expired = [
                    port
                    for port, seen_at in source_ports.items()
                    if now - seen_at > SCAN_WINDOW_SECONDS
                ]

                for port in expired:
                    del source_ports[port]

                if destination_port:
                    source_ports[destination_port] = now

                unique_ports = len(source_ports)

            if unique_ports >= SCAN_PORT_THRESHOLD:
                add_alert(
                    f"Possible port scan from {src_ip} "
                    f"({unique_ports} ports in {SCAN_WINDOW_SECONDS}s)",
                    "HIGH",
                )


# ============================================================
# PACKET PROCESSING
# ============================================================

def process_packet(packet):
    """Process each packet received from Scapy."""

    global total_packets
    global total_bytes
    global packets_last_second

    if not packet.haslayer(IP):
        return

    src_ip = packet[IP].src
    dst_ip = packet[IP].dst
    packet_size = len(packet)

    # Optional source/destination filter
    if target_ip and target_ip not in (src_ip, dst_ip):
        return

    now = datetime.now()

    date_string = now.strftime("%Y-%m-%d")
    timestamp = now.strftime("%H:%M:%S")

    protocol = "Other"
    service = "-"
    source_port = None
    destination_port = None

    # --------------------------------------------------------
    # TCP
    # --------------------------------------------------------

    if packet.haslayer(TCP):

        protocol = "TCP"

        source_port = packet[TCP].sport
        destination_port = packet[TCP].dport

        service = resolve_service(
            source_port,
            destination_port,
        )

    # --------------------------------------------------------
    # UDP
    # --------------------------------------------------------

    elif packet.haslayer(UDP):

        protocol = "UDP"

        source_port = packet[UDP].sport
        destination_port = packet[UDP].dport

        service = resolve_service(
            source_port,
            destination_port,
        )

    # --------------------------------------------------------
    # ICMP
    # --------------------------------------------------------

    elif packet.haslayer(ICMP):

        protocol = "ICMP"
        service = "Ping / Control"

    # --------------------------------------------------------
    # Update telemetry
    # --------------------------------------------------------

    with lock:

        total_packets += 1
        total_bytes += packet_size
        packets_last_second += 1

        ip_packet_counts[src_ip] += 1
        ip_byte_counts[src_ip] += packet_size

        protocol_counts[protocol] += 1

        unique_hosts.add(src_ip)
        unique_hosts.add(dst_ip)

        # Dashboard packet history
        packet_buffer.append(
            (
                date_string,
                timestamp,
                src_ip,
                dst_ip,
                protocol,
                service,
                format_bytes(packet_size),
            )
        )

        if len(packet_buffer) > MAX_VISIBLE_PACKETS:
            packet_buffer.pop(0)

        # Structured record for CSV export
        traffic_records.append(
            {
                "Date": date_string,
                "Time": timestamp,
                "Source IP": src_ip,
                "Destination IP": dst_ip,
                "Protocol": protocol,
                "Service": service,
                "Size (Bytes)": packet_size,
            }
        )

        # Keep raw Scapy packet for PCAP export
        raw_packets.append(packet)

    # Run detection outside the main statistics lock.
    detect_threats(
        packet,
        src_ip,
        dst_ip,
        destination_port,
        timestamp,
    )


# ============================================================
# PACKET RATE MONITOR
# ============================================================

def calculate_packet_rate():
    """Calculate packets-per-second once every second."""

    global packets_last_second
    global packets_per_second

    while capture_running:

        time.sleep(1)

        with lock:
            packets_per_second = packets_last_second
            packets_last_second = 0


# ============================================================
# SNIFFER
# ============================================================

def start_sniffer():
    """Start live packet capture."""

    try:
        sniff(
            prn=process_packet,
            store=False,
        )

    except PermissionError:
        add_alert(
            "Packet capture permission denied.",
            "HIGH",
        )

    except Exception as error:
        add_alert(
            f"Capture error: {error}",
            "HIGH",
        )


# ============================================================
# SESSION EXPORT
# ============================================================

def save_session(base_filename):
    """Save captured traffic as CSV and PCAP."""

    with lock:

        if not traffic_records:
            return False, "No packets were captured."

        csv_path = f"{base_filename}.csv"
        pcap_path = f"{base_filename}.pcap"

        try:

            fields = [
                "Date",
                "Time",
                "Source IP",
                "Destination IP",
                "Protocol",
                "Service",
                "Size (Bytes)",
            ]

            with open(
                csv_path,
                "w",
                newline="",
                encoding="utf-8",
            ) as file:

                writer = csv.DictWriter(
                    file,
                    fieldnames=fields,
                )

                writer.writeheader()
                writer.writerows(traffic_records)

            wrpcap(
                pcap_path,
                raw_packets,
            )

            return True, (
                f"CSV: {csv_path} | "
                f"PCAP: {pcap_path}"
            )

        except Exception as error:

            return False, str(error)


# ============================================================
# KEYBOARD INPUT
# ============================================================

def get_key():
    """Read a key without blocking the dashboard."""

    if sys.platform == "win32":

        import msvcrt

        if msvcrt.kbhit():
            return msvcrt.getch().decode(
                "utf-8",
                errors="ignore",
            ).lower()

    else:

        if sys.stdin.isatty():

            ready, _, _ = select.select(
                [sys.stdin],
                [],
                [],
                0,
            )

            if ready:
                return sys.stdin.read(1).lower()

    return None


# ============================================================
# DASHBOARD
# ============================================================

def build_dashboard(console):
    """Build the live Rich terminal interface."""

    layout = Layout()

    terminal_height = console.height
    usable_height = max(15, terminal_height - 3)

    top_rows = max(
        5,
        int(usable_height * 0.55),
    )

    bottom_rows = max(
        5,
        usable_height - top_rows,
    )

    layout.split_column(
        Layout(name="packets", size=top_rows),
        Layout(name="bottom", size=bottom_rows),
        Layout(name="footer", size=3),
    )

    layout["bottom"].split_row(
        Layout(name="hosts", ratio=3),
        Layout(name="telemetry", ratio=2),
    )

    with lock:

        # ====================================================
        # TOP: LIVE PACKETS
        # ====================================================

        packet_table = Table(
            expand=True,
            show_edge=False,
        )

        packet_table.add_column(
            "Time",
            width=9,
        )

        packet_table.add_column(
            "Source",
        )

        packet_table.add_column(
            "Destination",
        )

        packet_table.add_column(
            "Protocol",
            width=9,
        )

        packet_table.add_column(
            "Service",
        )

        packet_table.add_column(
            "Size",
            justify="right",
            width=10,
        )

        visible = packet_buffer[-max(5, top_rows - 4):]

        for packet in visible:

            packet_table.add_row(
                packet[1],
                packet[2],
                packet[3],
                packet[4],
                packet[5],
                packet[6],
            )

        packet_panel = Panel(
            packet_table,
            title=(
                f" | LIVE TRAFFIC  "
                f"| Packets: {total_packets:,} "
                f"| Data: {format_bytes(total_bytes)}"
            ),
            border_style="cyan",
        )

        layout["packets"].update(packet_panel)

        # ====================================================
        # BOTTOM LEFT: TOP HOSTS
        # ====================================================

        host_table = Table(
            expand=True,
            show_edge=False,
        )

        host_table.add_column(
            "Host",
        )

        host_table.add_column(
            "Packets",
            justify="right",
        )

        host_table.add_column(
            "Traffic",
            justify="right",
        )

        host_table.add_column(
            "Activity",
        )

        max_host_bytes = (
            max(ip_byte_counts.values())
            if ip_byte_counts
            else 1
        )

        for ip, count in ip_packet_counts.most_common(
            max(3, bottom_rows - 5)
        ):

            byte_count = ip_byte_counts[ip]

            filled = int(
                (byte_count / max_host_bytes) * 10
            )

            bar = (
                "█" * filled
                + "░" * (10 - filled)
            )

            host_table.add_row(
                ip,
                str(count),
                format_bytes(byte_count),
                bar,
            )

        host_panel = Panel(
            host_table,
            title="Top Network Hosts",
            border_style="cyan",
        )

        layout["hosts"].update(host_panel)

        # ====================================================
        # BOTTOM RIGHT: TELEMETRY
        # ====================================================

        avg_packet_size = (
            total_bytes // total_packets
            if total_packets
            else 0
        )

        tcp_percent = (
            int(
                protocol_counts["TCP"]
                / total_packets
                * 100
            )
            if total_packets
            else 0
        )

        udp_percent = (
            int(
                protocol_counts["UDP"]
                / total_packets
                * 100
            )
            if total_packets
            else 0
        )

        icmp_percent = (
            int(
                protocol_counts["ICMP"]
                / total_packets
                * 100
            )
            if total_packets
            else 0
        )

        telemetry = Table.grid(
            expand=True,
        )

        telemetry.add_column()

        telemetry.add_row(
            f"[bold cyan]Status:[/bold cyan] "
            f"[bold green]● CAPTURING[/bold green]"
        )

        telemetry.add_row(
            f"[bold cyan]Rate:[/bold cyan] "
            f"{packets_per_second} packets/sec"
        )

        telemetry.add_row(
            f"[bold cyan]Hosts:[/bold cyan] "
            f"{len(unique_hosts)}"
        )

        telemetry.add_row(
            f"[bold cyan]Avg Packet:[/bold cyan] "
            f"{avg_packet_size} B"
        )

        telemetry.add_row(
            f"[bold cyan]TCP:[/bold cyan] {tcp_percent}%  "
            f"[bold cyan]UDP:[/bold cyan] {udp_percent}%  "
            f"[bold cyan]ICMP:[/bold cyan] {icmp_percent}%"
        )

        telemetry.add_row("")

        telemetry.add_row(
            "[bold cyan]Security Events[/bold cyan]"
        )

        if security_alerts:

            for alert in security_alerts[-3:]:

                severity = alert["severity"]

                if severity == "HIGH":
                    style = "bold red"
                elif severity == "MEDIUM":
                    style = "bold yellow"
                else:
                    style = "dim"

                telemetry.add_row(
                    f"[{style}][{severity}][/{style}] "
                    f"{alert['message']}"
                )

        else:

            telemetry.add_row(
                "[dim]No suspicious activity detected[/dim]"
            )

        telemetry_panel = Panel(
            telemetry,
            title="Telemetry & Threat Watchlist",
            border_style="cyan",
        )

        layout["telemetry"].update(
            telemetry_panel
        )

        # ====================================================
        # FOOTER
        # ====================================================

        footer = Table.grid(
            expand=True,
        )

        footer.add_column(
            justify="left"
        )

        footer.add_column(
            justify="right"
        )

        footer.add_row(
            "[bold cyan]q[/bold cyan] stop capture",
            "[dim]SentinelNet | defensive monitoring[/dim]",
        )

        layout["footer"].update(
            Panel(
                footer,
                border_style="cyan",
            )
        )

    return layout


# ============================================================
# MAIN
# ============================================================

def main():

    global target_ip
    global capture_running

    check_privileges()

    console = Console()

    console.clear()

    print()
    print("=" * 64)
    print("                    NETWORK TRAFFIC MONITOR")
    print("=" * 64)
    print()
    print(" Live packet analysis")
    print(" Lightweight threat detection")
    print(" CSV + PCAP session export")
    print()
    print("=" * 64)
    print()

    target_ip = input(
        "Monitor specific IP "
        "(press Enter for all traffic): "
    ).strip()

    print()
    print("Starting capture...")
    print("Press 'q' inside the dashboard to stop.")
    time.sleep(1)

    console.clear()

    # Start packet capture
    sniffer_thread = threading.Thread(
        target=start_sniffer,
        daemon=True,
    )

    rate_thread = threading.Thread(
        target=calculate_packet_rate,
        daemon=True,
    )

    sniffer_thread.start()
    rate_thread.start()

    try:

        with Live(
            build_dashboard(console),
            refresh_per_second=4,
            console=console,
        ) as live:

            while capture_running:

                time.sleep(0.1)

                key = get_key()

                if key == "q":
                    capture_running = False
                    break

                live.update(
                    build_dashboard(console)
                )

    except KeyboardInterrupt:

        capture_running = False

    finally:

        capture_running = False

        console.clear()

        console.print(
            "\n[bold cyan]Capture stopped.[/bold cyan]\n"
        )

        if total_packets == 0:

            console.print(
                "[yellow]No packets captured.[/yellow]"
            )

            return

        save_choice = input(
            "Save session as CSV + PCAP? (y/n): "
        ).strip().lower()

        if save_choice in ("y", "yes"):

            filename = input(
                "Enter a base filename "
                "(e.g. office_scan): "
            )

            filename = sanitize_filename(
                filename
            )

            success, message = save_session(
                filename
            )

            if success:

                console.print(
                    f"\n[bold green]✓ Saved:[/bold green] "
                    f"{message}"
                )

            else:

                console.print(
                    f"\n[bold red]✗ Export failed:[/bold red] "
                    f"{message}"
                )

        else:

            console.print(
                "[dim]Session data was not exported.[/dim]"
            )

        console.print(
            "\n[bold green]✓ SentinelNet session ended.[/bold green]"
        )


if __name__ == "__main__":
    main()