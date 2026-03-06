"""
run_all.py

Runs the full log analysis pipeline in one command:
    Step 1 → Parse auth.log → extract events
    Step 2 → Detect brute-force patterns
    Step 3 → Generate threat summary report

Usage:
    python scripts/run_all.py
    python scripts/run_all.py --log /var/log/auth.log
    python scripts/run_all.py --log data/sample_auth.log --year 2024
"""

import sys
import argparse
from pathlib import Path
from datetime import datetime

# Allow imports from project root
sys.path.insert(0, str(Path(__file__).parent.parent))

from scripts.log_parser        import parse_auth_log, save_failed_logins
from scripts.brute_force_detector import detect_brute_force, save_brute_force_report
from scripts.generate_report   import build_report, save_report


def main():
    parser = argparse.ArgumentParser(description="Security Log Analyzer")
    parser.add_argument("--log",  default="data/sample_auth.log", help="Path to auth.log file")
    parser.add_argument("--year", type=int, default=datetime.now().year, help="Year for log timestamps")
    args = parser.parse_args()

    print("\n" + "=" * 55)
    print("  🔍 SECURITY LOG ANALYZER — FULL PIPELINE")
    print("=" * 55)

    # ── Step 1: Parse ──────────────────────────────────────────
    print("\n[1/3] Parsing log file...")
    df = parse_auth_log(args.log, year=args.year)

    if df.empty:
        print("  ❌ No events parsed. Check the log file path and format.")
        sys.exit(1)

    save_failed_logins(df, "data/output/failed_logins.csv")

    # ── Step 2: Detect ─────────────────────────────────────────
    print("\n[2/3] Running brute-force detection...")
    flagged = detect_brute_force(df)

    if not flagged.empty:
        save_brute_force_report(flagged, "data/output/brute_force_ips.csv")

    # ── Step 3: Report ─────────────────────────────────────────
    print("\n[3/3] Generating threat summary report...")

    import pandas as pd
    failed_df = df[df["event_type"] == "FAILED_LOGIN"]
    report = build_report(failed_df, flagged, log_file=args.log)
    save_report(report)

    # ── Done ───────────────────────────────────────────────────
    print("\n" + "=" * 55)
    print("  ✅ PIPELINE COMPLETE")
    print("=" * 55)
    print("\n  Output files:")
    print("    data/output/failed_logins.csv    ← Import into Power BI")
    print("    data/output/brute_force_ips.csv  ← Import into Power BI")
    print("    data/output/threat_summary.txt   ← Human-readable report")
    print("\n  Next: Open Power BI Desktop and load the CSV files.")
    print("        See dashboards/dashboard-guide.md for instructions.\n")


if __name__ == "__main__":
    main()
