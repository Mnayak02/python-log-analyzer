# How It Works — Technical Walkthrough

---

## Pipeline Overview

```
auth.log (raw text)
       │
       ▼
  log_parser.py          ← Regex extracts structured events
       │
       ▼
  failed_logins.csv      ← Cleaned, timestamped event data
       │
       ▼
  brute_force_detector.py ← Sliding window algorithm flags attackers
       │
       ▼
  brute_force_ips.csv    ← Flagged IPs with severity ratings
       │
       ▼
  generate_report.py     ← Plain-English threat summary
       │
       ▼
  threat_summary.txt + Power BI dashboard
```

---

## Step 1 — Log Parsing (log_parser.py)

Linux `auth.log` lines look like this:

```
Jun 15 09:02:11 ubuntu-server sshd[12345]: Failed password for root from 192.168.56.10 port 54823 ssh2
Jun 15 09:02:15 ubuntu-server sshd[12346]: Failed password for invalid user admin from 192.168.56.10 port 54824 ssh2
Jun 15 09:05:33 ubuntu-server sshd[12400]: Accepted password for mayur from 192.168.1.101 port 55000 ssh2
```

The parser uses Python `re` (regular expressions) to extract:
- **Timestamp** — `Jun 15 09:02:11`
- **Event type** — Failed / Accepted / Invalid user
- **Username** — `root`, `admin`, `mayur`
- **Source IP** — `192.168.56.10`
- **Port** — `54823`

Each matched line becomes a row in a Pandas DataFrame.

---

## Step 2 — Brute-Force Detection (brute_force_detector.py)

The detector uses a **sliding window algorithm**:

```
For each source IP:
    Sort its failed login timestamps in order
    For each timestamp T:
        Count how many events fall within [T, T + 10 minutes]
    If max count >= 5:
        FLAG this IP as a brute-force attacker
```

**Why sliding window instead of fixed buckets?**

Fixed buckets (e.g., group by hour) miss attacks that straddle two windows:

```
Fixed 10-min buckets:
  09:00–09:10 → 3 failures   (below threshold, NOT flagged)
  09:10–09:20 → 4 failures   (below threshold, NOT flagged)
  Actual: 7 failures in 20 min window — MISSED

Sliding window:
  09:05–09:15 → 7 failures   (above threshold, FLAGGED ✅)
```

---

## Step 3 — Severity Scoring

| Total Failed Attempts | Severity |
|---|---|
| 50+ | 🔴 CRITICAL |
| 20–49 | 🟠 HIGH |
| 5–19 | 🟡 MEDIUM |
| < 5 | Not flagged |

---

## Step 4 — Report Generation (generate_report.py)

Reads both CSVs and produces:
- Overview statistics
- Per-IP detailed breakdown with timestamps
- ASCII bar charts for top usernames and IPs
- Prioritized remediation recommendations

---

## Sample Log Line Regex Patterns

```python
# Failed login
r'Failed password for (?:invalid user )?(\S+) from (\d+\.\d+\.\d+\.\d+) port (\d+)'

# Successful login
r'Accepted password for (\S+) from (\d+\.\d+\.\d+\.\d+) port (\d+)'

# Invalid user (no password attempt made)
r'Invalid user (\S+) from (\d+\.\d+\.\d+\.\d+)'
```

The `(?:invalid user )?` is a non-capturing group — it optionally matches the phrase "invalid user" so the same pattern handles both `Failed password for root` and `Failed password for invalid user admin`.

---

## Running Against a Real Auth.log

If you have access to a Linux system, you can run this against real logs:

```bash
# Copy the log (requires root/sudo)
sudo cp /var/log/auth.log data/real_auth.log
sudo chown $USER data/real_auth.log

# Run the analyzer
python scripts/run_all.py --log data/real_auth.log
```

⚠️ **Do not commit real auth.log files to GitHub** — they may contain sensitive system information.
