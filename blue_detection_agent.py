#!/usr/bin/env python3
"""
blue_detection_agent.py
Monitors syslog for intrusion patterns and notifies controller on detection.
"""

import re
import socket
import time
import subprocess

# === CONFIG ===
CONTROLLER_IP = "192.168.60.2"     # controller VM IP
CONTROLLER_PORT = 50505            # must match orchestrator listening port
PATTERN = re.compile(
    r"(failed password|invalid user|connection closed by authenticating user|brute[- ]?force|intrusion detected|possible attack)",
    re.IGNORECASE
)
CHECK_INTERVAL = 3                 # seconds between log scans
LOG_PATH = "/var/log/syslog"       # path

def notify_controller():
    """Send a UDP ping/alert to controller."""
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.sendto(b"ALERT", (CONTROLLER_IP, CONTROLLER_PORT))
    print("[+] Alert sent to controller")

def main():
    print(f"[Blue IDS] Watching {LOG_PATH} for intrusions...")
    last_size = 0
    while True:
        try:
            result = subprocess.run(["tail", "-n", "50", LOG_PATH], capture_output=True, text=True)
            lines = result.stdout.splitlines()
            for line in lines:
                if PATTERN.search(line):
                    print(f"[!] Intrusion detected: {line}")
                    notify_controller()
                    time.sleep(10)  # avoid flooding controller: needed after attempts
                    break
        except Exception as e:
            print(f"[X] Error: {e}")
        time.sleep(CHECK_INTERVAL)

if __name__ == "__main__":
    main()
