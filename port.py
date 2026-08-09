#!/usr/bin/python3

import socket
import sys
import time
import threading

GREEN = "\033[92m"
RED = "\033[91m"
CYAN = "\033[96m"
YELLOW = "\033[93m"
RESET = "\033[0m"

usage = "python3 port_scan.py TARGET START_PORT END_PORT"

print("=" * 60)
print("             PYTHON PORT SCANNER")
print("=" * 60)


start_time = time.time()

if len(sys.argv) != 4:
    print(f"{YELLOW}{usage}{RESET}")
    sys.exit(1)

try:
    target = socket.gethostbyname(sys.argv[1])
except socket.gaierror:
    print(f"{RED}[!] Name resolution error{RESET}")
    sys.exit(1)

start_port = int(sys.argv[2])
end_port = int(sys.argv[3])

print(f"{CYAN}Target : {target}{RESET}")
print(f"{CYAN}Ports  : {start_port} - {end_port}{RESET}")
print("-" * 60)

def scan_port(port):
     
     s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
     s.settimeout(2)
     conn=s.connect_ex((target,port))
     if(not conn):
        print(f"{GREEN}[+] Port {port:<5} OPEN{RESET}")
        s.close()

threads = []
for port in range(start_port, end_port+1):

    thread = threading.Thread( 
        target=scan_port, 
        args=(port,)
    ) 
    thread.start() 
    threads.append(thread)

for thread in threads: 
    thread.join()

end_time = time.time()

print("-" * 60)
print(
    f"{GREEN}[✓] Scan completed in "
    f"{end_time - start_time:.2f} seconds{RESET}"
)
print("=" * 60)