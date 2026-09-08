# Brute-Force Log Parser

A standalone Python tool that detects brute-force login attempts from a CSV
export of failed-logon events — a Python re-implementation of the SPL
detection built in my Splunk SOC brute-force lab
(https://github.com/david00-sec/splunk-soc-brute-force-lab).

## Why this exists

The Splunk lab detects brute-force SSH attacks using this SPL query:

    sourcetype="WinEventLog:Security" EventCode=4625 Account_Name=LAP1
    | stats count by Account_Name
    | where count >= 3

This project shows the same detection logic implemented outside a SIEM —
useful when log data needs to be analyzed in an environment without Splunk,
or as a lightweight pre-filter before ingestion.

## What it does

- Reads a CSV of failed-logon events (Event ID 4625: source IP, account
  name, timestamp)
- Counts failed attempts per source IP using collections.Counter
- Flags any IP whose count exceeds a configurable threshold
- Reports unique accounts targeted per IP and the first/last-seen timestamps
  for each flagged IP
- Optionally writes flagged results to a CSV report

## Usage

    python3 logon_anomaly_detector.py --input sample_data/dummy_failed_logons.csv --threshold 3
    python3 logon_anomaly_detector.py --input sample_data/dummy_failed_logons.csv --threshold 3 --output flagged_report.csv

## Expected CSV columns

| Canonical field | Accepted header names |
|---|---|
| source_ip | source_ip, src_ip, ip, sourceip, src |
| account_name | account_name, user, username, account, user_name |
| timestamp | timestamp, time, event_time, _time, datetime |
| event_id (optional) | event_id, eventcode, eventid, id |

If an event_id column is present, only rows with value 4625 are counted.
If it's absent, the CSV is assumed to already be pre-filtered to failed
logons (e.g. exported directly from a Splunk search scoped to EventCode=4625).

## Sample data

sample_data/dummy_failed_logons.csv contains synthetic data for testing
without needing a live Splunk export. Running the tool against it with
--threshold 3 flags two IPs as brute-force sources.

## Requirements

Python 3.10+. No external dependencies — standard library only
(csv, collections, argparse, dataclasses, pathlib).# brute-force-log-parser
