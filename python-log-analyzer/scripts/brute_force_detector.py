"""
brute_force_detector.py

Analyzes parsed login events and flags IPs exhibiting brute-force behavior.

Detection logic:
    An IP is flagged if it generates 5+ failed login attempts
    within any rolling 10-minute window.

Usage:
    from scripts.brute_force_detector import detect_brute_force
    flagged = detect_brute_force(failed_logins_df)
"""

import pandas as pd
from pathlib import Path
from datetime import timedelta


# ── Configuration ──────────────────────────────────────────────────────────────
THRESHOLD_ATTEMPTS  = 5       # Min failed attempts to flag
WINDOW_MINUTES      = 10      # Time window in minutes
CRITICAL_THRESHOLD  = 50      # Attempts = CRITICAL severity
HIGH_THRESHOLD      = 20      # Attempts = HIGH severity
MEDIUM_THRESHOLD    = 5       # Attempts = MEDIUM severity


# ── Detection ─────────────────────────────────────────────────────────────────

def get_severity(count):
    """Return severity label based on attempt count."""
    if count >= CRITICAL_THRESHOLD:
        return "CRITICAL"
    elif count >= HIGH_THRESHOLD:
        return "HIGH"
    elif count >= MEDIUM_THRESHOLD:
        return "MEDIUM"
    return "LOW"


def detect_brute_force(df):
    """
    Detect IPs with brute-force patterns using a sliding time window.

    Parameters:
        df (pd.DataFrame): DataFrame from log_parser with event_type, source_ip, timestamp

    Returns:
        pd.DataFrame: Flagged IPs with attempt counts, time ranges, and severity
    """
    failed = df[df["event_type"] == "FAILED_LOGIN"].copy()

    if failed.empty:
        print("  ℹ️  No failed login events to analyze.")
        return pd.DataFrame()

    # Drop rows with missing timestamps
    failed = failed.dropna(subset=["timestamp"])
    failed = failed.sort_values(["source_ip", "timestamp"])

    flagged_ips = []
    window = timedelta(minutes=WINDOW_MINUTES)

    for ip, group in failed.groupby("source_ip"):
        timestamps = group["timestamp"].tolist()
        usernames  = group["username"].tolist()
        max_window_count = 0

        # Sliding window: for each event, count how many fall within next 10 min
        for i, start_ts in enumerate(timestamps):
            count = sum(1 for ts in timestamps[i:] if ts - start_ts <= window)
            max_window_count = max(max_window_count, count)

        if max_window_count >= THRESHOLD_ATTEMPTS:
            total_attempts   = len(group)
            unique_usernames = group["username"].nunique()
            first_seen       = group["timestamp"].min()
            last_seen        = group["timestamp"].max()
            duration_min     = (last_seen - first_seen).total_seconds() / 60

            flagged_ips.append({
                "source_ip":          ip,
                "total_failed":       total_attempts,
                "max_in_10min":       max_window_count,
                "unique_usernames":   unique_usernames,
                "top_username":       group["username"].value_counts().idxmax(),
                "first_seen":         first_seen,
                "last_seen":          last_seen,
                "duration_minutes":   round(duration_min, 1),
                "severity":           get_severity(total_attempts),
            })

    if not flagged_ips:
        print("  ✅ No brute-force patterns detected.")
        return pd.DataFrame()

    result = pd.DataFrame(flagged_ips)
    result = result.sort_values("total_failed", ascending=False).reset_index(drop=True)

    print(f"\n  🚨 BRUTE-FORCE DETECTION RESULTS")
    print(f"  {'─' * 55}")
    print(f"  {'IP Address':<18} {'Attempts':>9} {'Max/10min':>10} {'Severity':<10}")
    print(f"  {'─' * 55}")
    for _, row in result.iterrows():
        sev_icon = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡"}.get(row["severity"], "⚪")
        print(f"  {row['source_ip']:<18} {row['total_failed']:>9,} {row['max_in_10min']:>10,}  {sev_icon} {row['severity']}")
    print(f"  {'─' * 55}")
    print(f"  {len(result)} IP(s) flagged\n")

    return result


def save_brute_force_report(df, output_path):
    """Save flagged IPs to CSV."""
    Path(output_path).parent.mkdir(parents=True, exist_ok=True)
    df.to_csv(output_path, index=False)
    print(f"  💾 Saved brute-force report → {output_path}")


if __name__ == "__main__":
    import sys
    input_csv = sys.argv[1] if len(sys.argv) > 1 else "data/output/failed_logins.csv"

    try:
        df = pd.read_csv(input_csv, parse_dates=["timestamp"])
        df["event_type"] = "FAILED_LOGIN"
        flagged = detect_brute_force(df)
        if not flagged.empty:
            save_brute_force_report(flagged, "data/output/brute_force_ips.csv")
    except FileNotFoundError:
        print(f"Error: {input_csv} not found. Run log_parser.py first.")
