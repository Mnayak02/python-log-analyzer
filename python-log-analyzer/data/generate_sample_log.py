"""
Generates a realistic sample auth.log file for testing the analyzer.
Run this once to create data/sample_auth.log
"""

import random
from datetime import datetime, timedelta
from pathlib import Path

Path("data").mkdir(exist_ok=True)

HOSTNAME = "ubuntu-server"
ATTACKER_IPS = ["192.168.56.10", "10.0.0.55", "172.16.0.22"]
NORMAL_IPS   = ["192.168.1.101", "192.168.1.105", "10.10.0.50"]
USERNAMES    = ["root", "admin", "ubuntu", "mayur", "deploy", "git", "postgres"]
VALID_USERS  = ["mayur", "ubuntu", "deploy"]

lines = []
base = datetime(2024, 6, 15, 8, 0, 0)


def ts(dt):
    return dt.strftime("%b %d %H:%M:%S")


def sshd(pid=None):
    return f"sshd[{pid or random.randint(10000,99999)}]"


# 1. Normal activity
t = base
for _ in range(40):
    t += timedelta(seconds=random.randint(30, 300))
    ip = random.choice(NORMAL_IPS)
    user = random.choice(VALID_USERS)
    pid = random.randint(10000, 99999)
    if random.random() < 0.8:
        lines.append(f"{ts(t)} {HOSTNAME} {sshd(pid)}: Accepted password for {user} from {ip} port {random.randint(40000,65000)} ssh2")
        lines.append(f"{ts(t + timedelta(minutes=random.randint(5,30)))} {HOSTNAME} {sshd(pid)}: Disconnected from user {user} {ip} port {random.randint(40000,65000)}")
    else:
        lines.append(f"{ts(t)} {HOSTNAME} {sshd(pid)}: Failed password for {user} from {ip} port {random.randint(40000,65000)} ssh2")

# 2. First attacker — heavy brute force (192.168.56.10)
t = base + timedelta(hours=1)
for i in range(147):
    t += timedelta(seconds=random.randint(2, 8))
    user = random.choice(USERNAMES)
    pid = random.randint(10000, 99999)
    if random.random() < 0.3:
        lines.append(f"{ts(t)} {HOSTNAME} {sshd(pid)}: Invalid user {user} from 192.168.56.10 port {random.randint(40000,65000)}")
    else:
        lines.append(f"{ts(t)} {HOSTNAME} {sshd(pid)}: Failed password for {user} from 192.168.56.10 port {random.randint(40000,65000)} ssh2")

# 3. Second attacker — moderate (10.0.0.55)
t = base + timedelta(hours=2)
for i in range(38):
    t += timedelta(seconds=random.randint(5, 20))
    user = random.choice(["root", "admin", "ubuntu"])
    pid = random.randint(10000, 99999)
    lines.append(f"{ts(t)} {HOSTNAME} {sshd(pid)}: Failed password for {user} from 10.0.0.55 port {random.randint(40000,65000)} ssh2")

# 4. Third attacker — low (172.16.0.22)
t = base + timedelta(hours=3)
for i in range(12):
    t += timedelta(seconds=random.randint(30, 90))
    user = random.choice(["root", "admin"])
    pid = random.randint(10000, 99999)
    lines.append(f"{ts(t)} {HOSTNAME} {sshd(pid)}: Failed password for {user} from 172.16.0.22 port {random.randint(40000,65000)} ssh2")

# 5. More normal activity interspersed
t = base + timedelta(hours=4)
for _ in range(20):
    t += timedelta(seconds=random.randint(60, 600))
    ip = random.choice(NORMAL_IPS)
    user = random.choice(VALID_USERS)
    pid = random.randint(10000, 99999)
    lines.append(f"{ts(t)} {HOSTNAME} {sshd(pid)}: Accepted password for {user} from {ip} port {random.randint(40000,65000)} ssh2")

# Sort by timestamp (already roughly sorted but mix in normal activity)
lines.sort()

output_path = "data/sample_auth.log"
with open(output_path, "w") as f:
    f.write("\n".join(lines) + "\n")

print(f"Generated {len(lines)} log lines → {output_path}")
