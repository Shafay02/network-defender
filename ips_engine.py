#!/usr/bin/env python3
"""
Automated Intrusion Prevention System (IPS) Engine
Monitors SSH authentication logs and automatically blocks brute-force attackers
using kernel-level firewall rules (iptables/ip6tables).
"""

# 1. What does this program DO in one sentence?
# It watches the SSH auth log, detects brute-force attempts, and blocks attacking IPs.

# 2. What are the 2-3 responsibilities I can separate?
# - A watcher: reads the live log file for new entries
# - A detector: finds failed login attempts and tracks counts per IP
# - An enforcer: blocks and unblocks IPs using iptables

# 3. What data/state do I need to track?
# - counter per IP -> defaultdict(int)
# - ban timestamp per IP -> dict

# 4. What does the main loop look like in plain English?
# open file -> jump to end -> loop forever:
#   if no new line -> check for expired bans -> sleep 1s
#   if new line -> parse it -> increment counter -> ban if over threshold

# 5. What are things that could go wrong?
# - Garbage/binary bytes in log       -> open in 'rb' mode, decode with errors='ignore'
# - Banning the same IP twice         -> check 'if ip not in BANNED_IPS'
# - IPv6 addresses                    -> check ":" in ip to use ip6tables
# - Ctrl+C interrupt                  -> try/except KeyboardInterrupt + cleanup
# - Banning localhost/own IP          -> whitelist check before banning

import re
import subprocess
import time
import logging
from collections import defaultdict

# --- CONFIGURATION ---
LOG_FILE         = "/var/log/auth.log"
FAILED_THRESHOLD = 5      # failed attempts before ban
BAN_TIME         = 300    # ban duration in seconds (5 minutes)
LOG_OUTPUT_FILE  = "/var/log/ips_engine.log"
# ---------------------

# --- WHITELIST: these IPs will never be banned ---
WHITELIST = {"127.0.0.1", "::1"}
# -------------------------------------------------

# --- DATA TRACKING ---
FAILED_ATTEMPTS = defaultdict(int)
BANNED_IPS      = {}
# ---------------------

# --- LOGGING SETUP ---
# Writes events to both the terminal and a log file for persistence
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(message)s",
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler(LOG_OUTPUT_FILE)
    ]
)
# ---------------------

# Regex: captures the IP address from a failed SSH login line
# Example line: "Jun 1 10:23:45 server sshd[1234]: Failed password for root from 192.168.1.50 port 22 ssh2"
failed_regex = re.compile(r"Failed password for .* from (\S+)")


def ban_ip(ip):
    """Blocks an IP by inserting a DROP rule at the top of the INPUT chain."""
    if ip in WHITELIST:
        logging.warning(f"[~] SKIPPED: {ip} is whitelisted, will not ban.")
        return

    if ip not in BANNED_IPS:
        logging.info(f"[!] CRITICAL: IP {ip} exceeded threshold. Executing Kernel Drop...")

        # Use ip6tables for IPv6 addresses (they contain ":"), iptables for IPv4
        cmd = "ip6tables" if ":" in ip else "iptables"
        subprocess.run(["sudo", cmd, "-I", "INPUT", "1", "-s", ip, "-j", "DROP"], check=True)

        BANNED_IPS[ip] = time.time()
        logging.info(f"[+] BANNED: {ip} blocked for {BAN_TIME} seconds.")


def unban_expired_ips():
    """Checks all banned IPs and removes the firewall rule if the ban time has expired."""
    now = time.time()

    # list() creates a copy so we can safely delete from BANNED_IPS inside the loop
    for ip, ban_start in list(BANNED_IPS.items()):
        if now - ban_start > BAN_TIME:
            logging.info(f"[*] INFO: Ban expired for {ip}. Removing kernel restriction...")

            cmd = "ip6tables" if ":" in ip else "iptables"
            subprocess.run(["sudo", cmd, "-D", "INPUT", "-s", ip, "-j", "DROP"], check=True)

            del BANNED_IPS[ip]
            FAILED_ATTEMPTS[ip] = 0
            logging.info(f"[-] UNBANNED: {ip} is now allowed again.")


def cleanup_on_exit():
    """Removes ALL active firewall rules added by this script before shutting down."""
    logging.info("[*] Cleaning up all active firewall rules...")
    for ip in list(BANNED_IPS.keys()):
        cmd = "ip6tables" if ":" in ip else "iptables"
        subprocess.run(["sudo", cmd, "-D", "INPUT", "-s", ip, "-j", "DROP"])
        logging.info(f"[-] Removed rule for {ip}")
    logging.info("[*] Cleanup complete.")


def monitor_logs():
    """Tails the auth log file live, parsing each new line as it arrives."""
    logging.info("[*] Starting Automated Network Defender...")
    logging.info(f"[*] Monitoring {LOG_FILE} for brute-force patterns...")
    logging.info(f"[*] Threshold: {FAILED_THRESHOLD} attempts | Ban time: {BAN_TIME}s")

    subprocess.run(["sudo", "ufw", "--force", "enable"], check=True)

    # Open in binary mode ('rb') to handle any garbage/non-UTF8 bytes without crashing
    with open(LOG_FILE, "rb") as f:

        # Jump to the END of the file so we only process new lines, not old history
        f.seek(0, 2)

        while True:
            line_bytes = f.readline()

            # readline() returns empty bytes b"" when there's no new line yet
            if not line_bytes:
                unban_expired_ips()
                time.sleep(1)
                continue

            # Decode bytes to string, safely ignoring any unreadable binary artifacts
            line = line_bytes.decode("utf-8", errors="ignore")

            match = failed_regex.search(line)
            if match:
                attacker_ip = match.group(1)  # group(1) = first captured group = the IP
                FAILED_ATTEMPTS[attacker_ip] += 1

                logging.info(
                    f"[->] Failed login from {attacker_ip}. "
                    f"Count: {FAILED_ATTEMPTS[attacker_ip]}/{FAILED_THRESHOLD}"
                )

                if FAILED_ATTEMPTS[attacker_ip] >= FAILED_THRESHOLD:
                    ban_ip(attacker_ip)


if __name__ == "__main__":
    try:
        monitor_logs()
    except KeyboardInterrupt:
        print("\n[*] Shutdown signal received.")
        cleanup_on_exit()
        print("[*] Automated Network Defender stopped safely.")
