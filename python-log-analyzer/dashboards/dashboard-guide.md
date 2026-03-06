# Power BI Dashboard Guide

This guide walks through building a 4-panel security dashboard in Power BI Desktop using the CSV outputs from the analyzer.

---

## Prerequisites

- [Power BI Desktop](https://powerbi.microsoft.com/desktop) — free download
- Run the analyzer first: `python scripts/run_all.py`
- Output CSVs in `data/output/`:
  - `failed_logins.csv`
  - `brute_force_ips.csv`

---

## Step 1 — Load the Data

1. Open Power BI Desktop
2. Click **Get Data → Text/CSV**
3. Load `data/output/failed_logins.csv`
4. Click **Transform Data** → verify columns look correct → **Close & Apply**
5. Repeat for `data/output/brute_force_ips.csv`

---

## Step 2 — Panel 1: Failed Logins Over Time (Line Chart)

**Shows:** Attack timeline — you'll clearly see the spike during brute-force attacks

1. In the **Visualizations** pane → click **Line chart**
2. Drag fields:
   - X-axis: `timestamp`
   - Y-axis: `timestamp` → change aggregation to **Count**
   - Legend: `source_ip`
3. In the **Filters** pane → filter `event_type` to `FAILED_LOGIN`
4. Format → Title: **"Failed Login Attempts Over Time"**

---

## Step 3 — Panel 2: Top Attacking IPs (Bar Chart)

**Shows:** Which IPs are generating the most failures at a glance

1. Click **Clustered bar chart**
2. Drag fields:
   - Y-axis: `source_ip`
   - X-axis: `source_ip` → Count
3. Sort by Count descending
4. Add conditional formatting: color bars by count (red = highest)
5. Title: **"Top Attacking Source IPs"**

---

## Step 4 — Panel 3: Top Targeted Usernames (Bar Chart)

**Shows:** Which accounts attackers are focusing on — `root` and `admin` will dominate

1. Click **Clustered bar chart**
2. Drag fields:
   - Y-axis: `username`
   - X-axis: `username` → Count
3. Sort by Count descending → show top 10
4. Title: **"Most Targeted Usernames"**

---

## Step 5 — Panel 4: Brute-Force Summary Table

**Shows:** Clean summary of flagged IPs with severity — looks like a real SOC alert table

1. Click **Table** visualization
2. From `brute_force_ips` table, drag all columns:
   - `source_ip`, `total_failed`, `max_in_10min`, `severity`, `top_username`, `duration_minutes`
3. Sort by `total_failed` descending
4. Add conditional formatting on `severity` column:
   - CRITICAL = red background
   - HIGH = orange
   - MEDIUM = yellow
5. Title: **"Brute-Force Detection Results"**

---

## Step 6 — Add a Title Card

1. Insert → **Text box**
2. Type: `Security Log Analysis Dashboard`
3. Subtitle: `Auth.log Threat Detection — Mayur Prashant Nayak`
4. Place at top of the canvas

---

## Step 7 — Final Formatting Tips

- Set canvas background to dark gray (`#1a1a2e`) for a professional SOC look
- Use white or light text on all visuals
- Add a **Card** visual showing total failed login count as a KPI number at the top
- Export as PDF: **File → Export → Export to PDF** — attach this to your resume applications

---

## What the Final Dashboard Shows

A hiring manager looking at your dashboard should immediately see:
1. A clear spike in the timeline when the attack happened
2. Three IPs flagged, with 192.168.56.10 obviously the worst offender
3. Root and admin being hammered — classic automated attack behavior
4. A clean severity table that looks like it came out of a real SOC tool

---

*This dashboard was built from outputs of the Python Security Log Analyzer.*
*→ [Back to main README](../README.md)*
