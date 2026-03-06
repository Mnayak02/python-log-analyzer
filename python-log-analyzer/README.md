# 🐍 Python Security Log Analyzer

A Python-based security tool that parses Linux authentication logs, detects brute-force attack patterns, identifies suspicious source IPs, and visualizes findings through Power BI dashboards.

---

## 🎯 What This Does

Raw auth logs are noisy and hard to read manually. This tool automates the process of:
1. Parsing thousands of log lines in seconds
2. Flagging IPs with repeated failed login attempts (brute-force indicators)
3. Exporting clean, structured data for dashboard visualization
4. Producing a plain-English summary of threats detected

---

## 🧰 Tools & Libraries

| Tool | Purpose |
|---|---|
| Python 3 | Core scripting |
| Pandas | Log parsing and data manipulation |
| Regular Expressions (re) | Pattern matching on raw log text |
| Collections | Frequency counting |
| CSV | Export for Power BI |
| Power BI Desktop | Dashboard visualization |

---

## 📁 Repository Structure

```
python-log-analyzer/
├── README.md
├── scripts/
│   ├── log_parser.py          ← Core parser — extracts events from auth.log
│   ├── brute_force_detector.py← Detects brute-force patterns
│   ├── generate_report.py     ← Produces plain-English threat summary
│   └── run_all.py             ← Single script to run the full pipeline
├── data/
│   ├── sample_auth.log        ← Sample log file (safe, no real data)
│   └── output/
│       ├── failed_logins.csv  ← Parsed failed login events
│       ├── brute_force_ips.csv← IPs flagged for brute-force
│       └── threat_summary.txt ← Human-readable report
├── dashboards/
│   └── dashboard-guide.md     ← How to build the Power BI dashboard
├── docs/
│   └── how-it-works.md        ← Technical walkthrough
└── screenshots/
    └── README.md
```

---

## 🚀 Quick Start

```bash
# 1. Clone the repo
git clone https://github.com/YOUR-USERNAME/python-log-analyzer.git
cd python-log-analyzer

# 2. Install dependencies
pip install pandas

# 3. Run the full pipeline against the sample log
python scripts/run_all.py --log data/sample_auth.log

# 4. Check outputs
cat data/output/threat_summary.txt
```

---

## 🔍 Detection Logic

### Brute-Force Detection
An IP is flagged as a brute-force attacker if it generates **5+ failed login attempts within a 10-minute window**.

```
Failed login from 192.168.56.10 at 09:02:11  ─┐
Failed login from 192.168.56.10 at 09:02:15   │  5 failures
Failed login from 192.168.56.10 at 09:02:19   │  in < 10 min
Failed login from 192.168.56.10 at 09:02:24   │  = FLAGGED
Failed login from 192.168.56.10 at 09:02:28  ─┘
```

### What Gets Extracted From Each Log Line
- Timestamp
- Event type (Failed password / Accepted password / Invalid user)
- Username targeted
- Source IP address
- Port

---

## 📊 Sample Output

**threat_summary.txt:**
```
==========================================
 SECURITY LOG ANALYSIS REPORT
 Generated: 2024-06-15 14:30:00
==========================================

OVERVIEW
  Log file analyzed : data/sample_auth.log
  Total log lines   : 2,847
  Failed logins     : 312
  Successful logins : 89
  Unique source IPs : 47

BRUTE-FORCE DETECTIONS  [3 IP(s) flagged]
  192.168.56.10   → 147 failed attempts  CRITICAL
  10.0.0.55       → 38 failed attempts   HIGH
  172.16.0.22     → 12 failed attempts   MEDIUM

TOP TARGETED USERNAMES
  root            → 201 attempts
  admin           → 67 attempts
  ubuntu          → 44 attempts

RECOMMENDATION
  Block the following IPs at the firewall immediately:
    - 192.168.56.10
    - 10.0.0.55
    - 172.16.0.22
==========================================
```

---

## 📈 Power BI Dashboard

The exported CSVs feed directly into a Power BI dashboard with 4 panels:
- Failed login attempts over time (line chart)
- Top attacking IPs (bar chart)
- Top targeted usernames (bar chart)
- Brute-force IP geolocation map

→ Build guide: [`dashboards/dashboard-guide.md`](dashboards/dashboard-guide.md)

---

## 📚 What I Learned

- Parsing unstructured log data with Python regex
- Applying time-window based detection logic (sliding window algorithm)
- Structuring security findings into actionable reports
- Connecting Python-generated CSV data to Power BI for visualization

---

*Built by Mayur Prashant Nayak | [LinkedIn](#) | Part of my cybersecurity portfolio*
