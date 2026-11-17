"""Detect IPs with many failed logins in a short time window.

Usage:
    python detect_failed_logins.py [logfile] [--threshold N] [--window MINUTES]
"""
import argparse
import csv
import re
from collections import defaultdict, deque
from datetime import datetime, timedelta

LINE_RE = re.compile(
    r"^(?P<ts>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}) \| "
    r"user=(?P<user>\S+) \| ip=(?P<ip>[\d.]+) \| status=(?P<status>SUCCESS|FAIL)$"
)


def parse_log(path):
    """Return a list of (timestamp, user, ip, status), skipping bad lines."""
    events, skipped = [], 0
    with open(path) as f:
        for line in f:
            m = LINE_RE.match(line.strip())
            if not m:
                skipped += 1
                continue
            ts = datetime.strptime(m["ts"], "%Y-%m-%d %H:%M:%S")
            events.append((ts, m["user"], m["ip"], m["status"]))
    return events, skipped


def find_suspicious(events, threshold, window):
    """Sliding-window check: flag IPs with >= threshold failures within `window`."""
    events = sorted(events, key=lambda e: e[0])
    recent = defaultdict(deque)      # ip -> timestamps of failures still in window
    stats = {}                       # ip -> info about flagged IPs
    total_fails = defaultdict(int)
    users_tried = defaultdict(set)

    for ts, user, ip, status in events:
        if status != "FAIL":
            continue
        total_fails[ip] += 1
        users_tried[ip].add(user)

        q = recent[ip]
        q.append(ts)
        while q and ts - q[0] > window:  # drop failures that fell out of the window
            q.popleft()

        if len(q) >= threshold:
            if ip not in stats:
                stats[ip] = {"first_flagged": ts, "peak_in_window": len(q)}
            else:
                stats[ip]["peak_in_window"] = max(stats[ip]["peak_in_window"], len(q))

    return [
        {
            "ip": ip,
            "first_flagged": s["first_flagged"].strftime("%Y-%m-%d %H:%M:%S"),
            "peak_failures_in_window": s["peak_in_window"],
            "total_failures": total_fails[ip],
            "usernames_tried": ";".join(sorted(users_tried[ip])),
        }
        for ip, s in stats.items()
    ]


def write_csv(rows, path):
    fields = ["ip", "first_flagged", "peak_failures_in_window",
              "total_failures", "usernames_tried"]
    with open(path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)


def main():
    p = argparse.ArgumentParser(description="Failed login detector")
    p.add_argument("logfile", nargs="?", default="sample_login.log")
    p.add_argument("--threshold", type=int, default=5, help="failures to flag (default 5)")
    p.add_argument("--window", type=int, default=10, help="window in minutes (default 10)")
    p.add_argument("--output", default="suspicious_ips.csv")
    args = p.parse_args()

    events, skipped = parse_log(args.logfile)
    fails = sum(1 for e in events if e[3] == "FAIL")
    flagged = find_suspicious(events, args.threshold, timedelta(minutes=args.window))
    flagged.sort(key=lambda r: r["peak_failures_in_window"], reverse=True)

    print(f"Parsed {len(events)} events ({fails} failures), skipped {skipped} malformed lines")
    print(f"Rule: {args.threshold}+ failures within {args.window} minutes")
    print(f"Flagged {len(flagged)} IP(s):\n")
    for r in flagged:
        print(f"  {r['ip']:<16} peak={r['peak_failures_in_window']:<3} "
              f"total={r['total_failures']:<3} first flagged {r['first_flagged']}")

    write_csv(flagged, args.output)
    print(f"\nReport saved to {args.output}")


if __name__ == "__main__":
    main()
