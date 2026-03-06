"""
log_parser.py

Parses Linux auth.log files and extracts structured security events.

Handles these log line formats:
  - Failed password for [user] from [ip] port [port]
  - Failed password for invalid user [user] from [ip] port [port]
  - Accepted password for [user] from [ip] port [port]
  - Invalid user [user] from [ip] port [port]
  - Connection closed / opened events

Usage:
    from scripts.log_parser import parse_auth_log
    events = parse_auth_log("data/sample_auth.log")
"""

import re
import pandas as pd
from datetime import datetime
from pathlib import Path


# ── Regex Patterns ────────────────────────────────────────────────────────────

# Matches: Jun 15 09:02:11 hostname sshd[1234]:
LOG_TIMESTAMP = re.compile(
    r'^(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})'
)

# Matches: Failed password for [invalid user] USERNAME from IP port PORT
FAILED_LOGIN = re.compile(
    r'Failed password for (?:invalid user )?(\S+) from (\d+\.\d+\.\d+\.\d+) port (\d+)'
)

# Matches: Accepted password for USERNAME from IP port PORT
SUCCESS_LOGIN = re.compile(
    r'Accepted password for (\S+) from (\d+\.\d+\.\d+\.\d+) port (\d+)'
)

# Matches: Invalid user USERNAME from IP port PORT
INVALID_USER = re.compile(
    r'Invalid user (\S+) from (\d+\.\d+\.\d+\.\d+)'
)

# Matches: Connection closed / opened
CONNECTION = re.compile(
    r'(Disconnected from|Connection closed|Received disconnect) .*?(\d+\.\d+\.\d+\.\d+)'
)


# ── Parser ────────────────────────────────────────────────────────────────────

def parse_timestamp(raw_ts, year=None):
    """Convert 'Jun 15 09:02:11' to a datetime object."""
    if year is None:
        year = datetime.now().year
    try:
        return datetime.strptime(f"{year} {raw_ts.strip()}", "%Y %b %d %H:%M:%S")
    except ValueError:
        return None


def parse_auth_log(log_path, year=None):
    """
    Parse an auth.log file and return a DataFrame of security events.

    Parameters:
        log_path (str): Path to the auth.log file
        year (int): Year to use for timestamps (defaults to current year)

    Returns:
        pd.DataFrame with columns:
            timestamp, event_type, username, source_ip, port, raw_line
    """
    log_path = Path(log_path)
    if not log_path.exists():
        raise FileNotFoundError(f"Log file not found: {log_path}")

    events = []
    total_lines = 0
    parse_errors = 0

    with open(log_path, "r", errors="replace") as f:
        for line in f:
            total_lines += 1
            line = line.strip()
            if not line:
                continue

            # Extract timestamp
            ts_match = LOG_TIMESTAMP.match(line)
            timestamp = parse_timestamp(ts_match.group(1), year) if ts_match else None

            # Try each pattern
            failed = FAILED_LOGIN.search(line)
            success = SUCCESS_LOGIN.search(line)
            invalid = INVALID_USER.search(line)

            if failed:
                events.append({
                    "timestamp": timestamp,
                    "event_type": "FAILED_LOGIN",
                    "username": failed.group(1),
                    "source_ip": failed.group(2),
                    "port": int(failed.group(3)),
                    "raw_line": line
                })
            elif success:
                events.append({
                    "timestamp": timestamp,
                    "event_type": "SUCCESS_LOGIN",
                    "username": success.group(1),
                    "source_ip": success.group(2),
                    "port": int(success.group(3)),
                    "raw_line": line
                })
            elif invalid:
                events.append({
                    "timestamp": timestamp,
                    "event_type": "INVALID_USER",
                    "username": invalid.group(1),
                    "source_ip": invalid.group(2),
                    "port": 22,
                    "raw_line": line
                })

    df = pd.DataFrame(events)

    if df.empty:
        print(f"  ⚠️  No security events found in {log_path.name}")
        print(f"      Total lines read: {total_lines}")
        return df

    # Sort by timestamp
    df = df.sort_values("timestamp").reset_index(drop=True)

    print(f"  ✅ Parsed {log_path.name}")
    print(f"     Lines read:     {total_lines:,}")
    print(f"     Events found:   {len(df):,}")
    print(f"     Failed logins:  {len(df[df.event_type == 'FAILED_LOGIN']):,}")
    print(f"     Successful:     {len(df[df.event_type == 'SUCCESS_LOGIN']):,}")
    print(f"     Invalid users:  {len(df[df.event_type == 'INVALID_USER']):,}")

    return df


def save_failed_logins(df, output_path):
    """Save failed login events to CSV for Power BI."""
    failed = df[df["event_type"] == "FAILED_LOGIN"].copy()
    failed = failed.drop(columns=["raw_line"])
    Path(output_path).parent.mkdir(parents=True, exist_ok=True)
    failed.to_csv(output_path, index=False)
    print(f"  💾 Saved {len(failed):,} failed login events → {output_path}")
    return failed


if __name__ == "__main__":
    import sys
    log = sys.argv[1] if len(sys.argv) > 1 else "data/sample_auth.log"
    df = parse_auth_log(log)
    if not df.empty:
        save_failed_logins(df, "data/output/failed_logins.csv")
