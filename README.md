# Failed Login Detector

A Python script that scans a log of login attempts, finds IP addresses with many failed logins in a short time (a common sign of a brute-force attack), and saves a report of suspicious activity to a CSV file.

## Features

- Generates a fake login log for testing, including normal users, brute-force attackers, and a slow "low and slow" IP that should *not* be flagged
- Parses log lines with a regular expression and skips malformed lines instead of crashing
- Detects attacks with a **sliding time window** (default: 5+ failures within 10 minutes)
- Reports the usernames each IP tried, which helps spot guessing of accounts like `admin` and `root`
- Writes results to `suspicious_ips.csv`

## Requirements

Python 3.8+ (standard library only, nothing to install)

## Usage

```bash
# 1. Generate a sample log
python generate_log.py

# 2. Run the detector
python detect_failed_logins.py

# Optional: change the rule
python detect_failed_logins.py sample_login.log --threshold 8 --window 5
```

| Option | Default | Meaning |
|---|---|---|
| `logfile` | `sample_login.log` | Log file to analyze |
| `--threshold` | `5` | Number of failures that triggers a flag |
| `--window` | `10` | Time window in minutes |
| `--output` | `suspicious_ips.csv` | Where to save the report |

## Log format

```
2026-11-17 09:15:32 | user=alice | ip=192.168.1.10 | status=FAIL
```

## Example output

```
Parsed 342 events (59 failures), skipped 0 malformed lines
Rule: 5+ failures within 10 minutes
Flagged 3 IP(s):

  198.51.100.7     peak=15  total=15  first flagged 2026-11-17 09:09:34
  185.220.101.9    peak=13  total=13  first flagged 2026-11-17 10:07:47
  203.0.113.45     peak=8   total=8   first flagged 2026-11-17 09:52:34
```

Full sample files are in the [`examples/`](examples/) folder.

## How detection works

For each IP, the script keeps a queue of its recent failure times. Each time a new failure arrives, timestamps older than the window are removed from the front of the queue. If the queue still holds at least `threshold` entries, the IP is flagged. This means a fast burst of failures is caught, while a few failures spread across hours are not.

## Possible improvements

- Flag successful logins that follow a burst of failures (possible compromised account)
- Detect password spraying (one IP trying many usernames)
- Support real log formats such as Linux `auth.log`
- Add unit tests for the window logic

## Disclaimer

All data is randomly generated for learning purposes. The IP addresses come from reserved documentation ranges.
