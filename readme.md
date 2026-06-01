# Automated Intrusion Prevention System (IPS) Engine

A Python-based IPS that monitors SSH authentication logs in real time, detects brute-force login attempts, and automatically blocks attacking IPs using kernel-level firewall rules (`iptables`/`ip6tables`).

---

## What It Does

When an attacker tries to brute-force SSH credentials, Linux logs every failed attempt to `/var/log/auth.log`. This tool watches that file live, counts failures per IP, and fires a kernel-level `DROP` rule the moment an IP crosses the threshold — no human intervention needed.

```
Attacker sends failed SSH logins
        ↓
Linux writes to /var/log/auth.log   ← OS does this automatically
        ↓
IPS Engine detects the pattern      ← this script
        ↓
iptables DROP rule inserted         ← attacker is silently blocked
        ↓
Rule auto-removed after ban expires ← self-cleaning
```

---

## Features

- **Real-time log tailing** — reacts within 1 second of a failed attempt
- **Auto-ban** — blocks IPs that exceed the failed attempt threshold
- **Auto-unban** — removes rules after the configurable ban duration expires
- **IPv4 + IPv6 support** — uses `iptables` or `ip6tables` automatically
- **Whitelist** — localhost and trusted IPs are never banned
- **Persistent logging** — all events written to `/var/log/ips_engine.log`
- **Clean shutdown** — Ctrl+C removes all active firewall rules safely

---

## Sample Output

```
2024-06-01 10:23:46 [*] Starting Automated Network Defender...
2024-06-01 10:23:46 [*] Monitoring /var/log/auth.log for brute-force patterns...
2024-06-01 10:23:47 [->] Failed login from 192.168.1.50. Count: 1/5
2024-06-01 10:23:48 [->] Failed login from 192.168.1.50. Count: 2/5
2024-06-01 10:23:49 [->] Failed login from 192.168.1.50. Count: 3/5
2024-06-01 10:23:50 [->] Failed login from 192.168.1.50. Count: 4/5
2024-06-01 10:23:51 [->] Failed login from 192.168.1.50. Count: 5/5
2024-06-01 10:23:51 [!] CRITICAL: IP 192.168.1.50 exceeded threshold. Executing Kernel Drop...
2024-06-01 10:23:51 [+] BANNED: 192.168.1.50 blocked for 300 seconds.
2024-06-01 10:28:51 [*] INFO: Ban expired for 192.168.1.50. Removing kernel restriction...
2024-06-01 10:28:51 [-] UNBANNED: 192.168.1.50 is now allowed again.
```

---

## Requirements

- Linux (Ubuntu/Debian recommended)
- Python 3.6+
- `iptables` and `ip6tables`
- `ufw`
- Root/sudo privileges

---

## Installation & Usage

**1. Clone the repository**
```bash
git clone https://github.com/YOUR_USERNAME/network-defender.git
cd network-defender
```

**2. Install dependencies**
```bash
pip install -r requirements.txt
```

**3. Run the engine**
```bash
sudo python3 ips_engine.py
```

**4. Stop safely with Ctrl+C** — all firewall rules are cleaned up automatically.

---

## Configuration

Edit the config section at the top of `ips_engine.py`:

```python
LOG_FILE         = "/var/log/auth.log"  # path to SSH auth log
FAILED_THRESHOLD = 5                    # failed attempts before ban
BAN_TIME         = 300                  # ban duration in seconds
```

To whitelist an IP so it can never be banned:
```python
WHITELIST = {"127.0.0.1", "::1", "YOUR_IP_HERE"}
```

---

## How It Works (Technical)

| Component | Implementation |
|---|---|
| Log tailing | `f.seek(0, 2)` jumps to end of file; `readline()` polls for new lines |
| Pattern detection | Regex: `Failed password for .* from (\S+)` |
| Attempt tracking | `defaultdict(int)` — auto-initializes counter for new IPs |
| Ban tracking | `dict` storing IP → ban timestamp |
| Firewall control | `subprocess.run(["sudo", "iptables", "-I", "INPUT", "1", ...])` |
| Safe iteration | `list(BANNED_IPS.items())` prevents RuntimeError on dict mutation |
| Binary safety | File opened in `rb` mode, decoded with `errors='ignore'` |

---

## Known Limitations

- Ban state is in-memory only — if the script restarts, active bans are lost
- Does not persist failed attempt counts across restarts
- Relies on `/var/log/auth.log` — path differs on RedHat/CentOS (`/var/log/secure`)

---

## License

MIT License — free to use, modify, and distribute.
