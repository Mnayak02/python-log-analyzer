"""
generate_report.py

Generates a plain-English threat summary report from parsed log data.
Output is a .txt file readable by anyone — no technical background needed.

Usage:
    python scripts/generate_report.py
    (run after log_parser.py and brute_force_detector.py)
"""

import pandas as pd
from pathlib import Path
from datetime import datetime


OUTPUT_PATH      = "data/output/threat_summary.txt"
FAILED_CSV       = "data/output/failed_logins.csv"
BRUTE_FORCE_CSV  = "data/output/brute_force_ips.csv"


def load_data():
    """Load CSVs produced by previous pipeline steps."""
    failed, brute = pd.DataFrame(), pd.DataFrame()

    if Path(FAILED_CSV).exists():
        failed = pd.read_csv(FAILED_CSV, parse_dates=["timestamp"])

    if Path(BRUTE_FORCE_CSV).exists():
        brute = pd.read_csv(BRUTE_FORCE_CSV, parse_dates=["first_seen", "last_seen"])

    return failed, brute


def build_report(failed, brute, log_file="data/sample_auth.log"):
    """Build the full report as a string."""
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    lines = []

    def add(text=""):
        lines.append(text)

    # ── Header ────────────────────────────────────────────────────────────────
    add("=" * 50)
    add(" SECURITY LOG ANALYSIS REPORT")
    add(f" Generated : {now}")
    add(f" Analyst   : Mayur Prashant Nayak")
    add("=" * 50)
    add()

    # ── Overview ──────────────────────────────────────────────────────────────
    add("OVERVIEW")
    add(f"  Log file analyzed : {log_file}")
    add(f"  Failed logins     : {len(failed):,}")
    add(f"  Unique source IPs : {failed['source_ip'].nunique() if not failed.empty else 0}")
    add(f"  Unique usernames  : {failed['username'].nunique() if not failed.empty else 0}")
    if not failed.empty and "timestamp" in failed.columns:
        first = failed["timestamp"].min()
        last  = failed["timestamp"].max()
        add(f"  Log time range    : {first} → {last}")
    add()

    # ── Brute-Force Detections ────────────────────────────────────────────────
    add("─" * 50)
    if brute.empty:
        add("BRUTE-FORCE DETECTIONS  [None detected]")
        add("  ✅ No IPs exceeded the detection threshold.")
    else:
        add(f"BRUTE-FORCE DETECTIONS  [{len(brute)} IP(s) flagged]")
        add()
        for _, row in brute.iterrows():
            sev_icon = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡"}.get(row["severity"], "⚪")
            add(f"  {sev_icon}  {row['source_ip']}")
            add(f"      Severity         : {row['severity']}")
            add(f"      Total attempts   : {int(row['total_failed']):,}")
            add(f"      Max in 10 min    : {int(row['max_in_10min'])}")
            add(f"      Top target user  : {row['top_username']}")
            add(f"      Unique usernames : {int(row['unique_usernames'])}")
            add(f"      First seen       : {row['first_seen']}")
            add(f"      Last seen        : {row['last_seen']}")
            add(f"      Attack duration  : {row['duration_minutes']} minutes")
            add()
    add()

    # ── Top Targeted Usernames ────────────────────────────────────────────────
    add("─" * 50)
    add("TOP TARGETED USERNAMES")
    add()
    if not failed.empty:
        top_users = failed["username"].value_counts().head(10)
        for username, count in top_users.items():
            bar = "█" * min(int(count / max(top_users) * 30), 30)
            add(f"  {username:<20} {count:>6,}  {bar}")
    else:
        add("  No data available.")
    add()

    # ── Top Attacking IPs ─────────────────────────────────────────────────────
    add("─" * 50)
    add("TOP ATTACKING SOURCE IPs")
    add()
    if not failed.empty:
        top_ips = failed["source_ip"].value_counts().head(10)
        for ip, count in top_ips.items():
            bar = "█" * min(int(count / max(top_ips) * 30), 30)
            flag = " ← FLAGGED" if not brute.empty and ip in brute["source_ip"].values else ""
            add(f"  {ip:<20} {count:>6,}  {bar}{flag}")
    else:
        add("  No data available.")
    add()

    # ── Recommendations ───────────────────────────────────────────────────────
    add("─" * 50)
    add("RECOMMENDED ACTIONS")
    add()
    if not brute.empty:
        critical = brute[brute["severity"] == "CRITICAL"]
        high     = brute[brute["severity"] == "HIGH"]

        add("  IMMEDIATE (within 1 hour):")
        for _, row in pd.concat([critical, high]).iterrows():
            add(f"    • Block IP {row['source_ip']} at the firewall")
        add()
        add("  SHORT-TERM (within 24 hours):")
        add("    • Review all accounts targeted by flagged IPs for unauthorized access")
        add("    • Check for any successful logins from flagged IPs (Event ID 4624)")
        add("    • Reset passwords for all targeted accounts as a precaution")
        add()
        add("  LONG-TERM:")
        add("    • Implement account lockout after 5 failed attempts")
        add("    • Enforce MFA on all accounts with SSH access")
        add("    • Consider moving SSH to a non-standard port (security through obscurity)")
        add("    • Deploy fail2ban to auto-block IPs after threshold is hit")
    else:
        add("  • Continue monitoring — no immediate action required")
        add("  • Review logs regularly for new patterns")
    add()
    add("=" * 50)
    add(" END OF REPORT")
    add("=" * 50)

    return "\n".join(lines)


def save_report(report_text):
    """Save report to file and print to console."""
    Path(OUTPUT_PATH).parent.mkdir(parents=True, exist_ok=True)
    with open(OUTPUT_PATH, "w") as f:
        f.write(report_text)
    print(f"\n  💾 Report saved → {OUTPUT_PATH}")
    print("\n" + "=" * 50)
    print(report_text)


if __name__ == "__main__":
    failed, brute = load_data()
    report = build_report(failed, brute)
    save_report(report)
