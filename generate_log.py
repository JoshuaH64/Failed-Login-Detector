"""Generate a fake login log for testing the detector.

Line format:
2026-11-17 09:15:32 | user=alice | ip=192.168.1.10 | status=FAIL
"""
import random
from datetime import datetime, timedelta

LOG_FILE = "sample_login.log"
USERS = ["alice", "bob", "carol", "dave", "erin", "admin", "root", "guest"]
START = datetime(2026, 11, 17, 8, 0, 0)

random.seed(42)  # same output every run; remove for random data

def line(ts, user, ip, status):
    return (ts, f"{ts:%Y-%m-%d %H:%M:%S} | user={user} | ip={ip} | status={status}")

entries = []

# 1. Normal traffic: mostly successes, occasional typo
normal_ips = [f"192.168.1.{i}" for i in range(10, 30)]
for _ in range(300):
    ts = START + timedelta(seconds=random.randint(0, 4 * 3600))
    status = "FAIL" if random.random() < 0.08 else "SUCCESS"
    entries.append(line(ts, random.choice(USERS[:5]), random.choice(normal_ips), status))

# 2. Brute-force attackers: many fails in a short burst
attackers = ["203.0.113.45", "198.51.100.7", "185.220.101.9"]
for ip in attackers:
    burst_start = START + timedelta(minutes=random.randint(10, 200))
    for _ in range(random.randint(8, 20)):
        ts = burst_start + timedelta(seconds=random.randint(0, 240))
        entries.append(line(ts, random.choice(["admin", "root", "guest"]), ip, "FAIL"))

# 3. Slow, spread-out failures: should NOT be flagged
slow_ip = "192.0.2.88"
for i in range(6):
    ts = START + timedelta(minutes=i * 40)
    entries.append(line(ts, "bob", slow_ip, "FAIL"))

entries.sort(key=lambda e: e[0])
with open(LOG_FILE, "w") as f:
    for _, text in entries:
        f.write(text + "\n")

print(f"Wrote {len(entries)} log lines to {LOG_FILE}")
