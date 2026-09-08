#!/usr/bin/env python3
"""
logon_anomaly_detector.py

Reads a CSV export of failed-logon events (e.g. Windows Event ID 4625 from
Splunk) and flags source IPs whose failed-attempt count exceeds a threshold.

This is a Python re-implementation of a brute-force-detection SPL query:

    index=* EventCode=4625
    | stats count by src_ip
    | where count > <threshold>

Expected CSV columns (case-insensitive, order doesn't matter):
    - source_ip      (or: src_ip, ip)
    - account_name   (or: user, username, account)
    - timestamp      (or: time, event_time, _time)
    - event_id       (optional — if present, non-4625 rows are ignored)

Usage:
    python logon_anomaly_detector.py --input failed_logons.csv --threshold 5
    python logon_anomaly_detector.py --input failed_logons.csv --threshold 5 --output report.csv
"""

from __future__ import annotations

import argparse
import csv
import sys
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path


# ---------------------------------------------------------------------------
# Config: column-name aliases so the script tolerates slightly different
# Splunk export headers without the user having to rename columns by hand.
# ---------------------------------------------------------------------------
COLUMN_ALIASES = {
    "source_ip": {"source_ip", "src_ip", "ip", "sourceip", "src"},
    "account_name": {"account_name", "user", "username", "account", "user_name"},
    "timestamp": {"timestamp", "time", "event_time", "_time", "datetime"},
    "event_id": {"event_id", "eventcode", "eventid", "id"},
}


@dataclass
class IpActivity:
    """Aggregated failed-logon activity for a single source IP."""
    count: int = 0
    accounts: set[str] = field(default_factory=set)
    first_seen: str | None = None
    last_seen: str | None = None


def normalize_headers(fieldnames: list[str]) -> dict[str, str]:
    """
    Map this CSV's actual header names -> our canonical field names
    (source_ip, account_name, timestamp, event_id), based on COLUMN_ALIASES.

    Returns a dict like {"src_ip": "source_ip", "user": "account_name", ...}
    Raises ValueError if a required column can't be found.
    """
    lower_to_actual = {name.strip().lower(): name for name in fieldnames}
    mapping: dict[str, str] = {}

    for canonical, aliases in COLUMN_ALIASES.items():
        found = None
        for alias in aliases:
            if alias in lower_to_actual:
                found = lower_to_actual[alias]
                break
        if found:
            mapping[found] = canonical
        elif canonical in ("source_ip", "account_name", "timestamp"):
            # these three are required; event_id is optional
            raise ValueError(
                f"Could not find a '{canonical}' column in CSV headers {fieldnames}. "
                f"Expected one of: {sorted(aliases)}"
            )

    return mapping


def load_events(csv_path: Path) -> list[dict[str, str]]:
    """Read the CSV and return a list of normalized event dicts."""
    with csv_path.open(newline="", encoding="utf-8-sig") as f:
        reader = csv.DictReader(f)
        if reader.fieldnames is None:
            raise ValueError("CSV file appears to be empty (no header row).")

        header_map = normalize_headers(reader.fieldnames)

        events = []
        for row in reader:
            normalized = {header_map[k]: v for k, v in row.items() if k in header_map}

            # If an event_id column exists, only keep 4625 (failed logon).
            # If it doesn't exist, assume the CSV was pre-filtered in Splunk.
            if "event_id" in normalized:
                event_id = str(normalized["event_id"]).strip()
                if event_id and event_id != "4625":
                    continue

            events.append(normalized)

    return events


def aggregate_by_ip(events: list[dict[str, str]]) -> tuple[Counter, dict[str, IpActivity]]:
    """
    Count failed attempts per source IP, and build a details dict alongside
    the Counter (accounts targeted, first/last seen timestamps).
    """
    counts: Counter = Counter()
    details: dict[str, IpActivity] = defaultdict(IpActivity)

    for event in events:
        ip = event.get("source_ip", "").strip()
        if not ip:
            continue

        account = event.get("account_name", "").strip()
        timestamp = event.get("timestamp", "").strip()

        counts[ip] += 1
        activity = details[ip]
        activity.count += 1
        if account:
            activity.accounts.add(account)

        if timestamp:
            if activity.first_seen is None or timestamp < activity.first_seen:
                activity.first_seen = timestamp
            if activity.last_seen is None or timestamp > activity.last_seen:
                activity.last_seen = timestamp

    return counts, dict(details)


def flag_anomalies(counts: Counter, threshold: int) -> list[tuple[str, int]]:
    """Return (ip, count) pairs where count exceeds the threshold, sorted
    by count descending — mirrors `stats count by src_ip | where count > N`."""
    flagged = [(ip, n) for ip, n in counts.items() if n > threshold]
    flagged.sort(key=lambda pair: pair[1], reverse=True)
    return flagged


def print_report(
    counts: Counter,
    details: dict[str, IpActivity],
    flagged: list[tuple[str, int]],
    threshold: int,
) -> None:
    print(f"\nTotal unique source IPs: {len(counts)}")
    print(f"Total failed-logon events: {sum(counts.values())}")
    print(f"Threshold: > {threshold} failed attempts\n")

    if not flagged:
        print("No IPs exceeded the threshold. No anomalies flagged.")
        return

    print(f"⚠ {len(flagged)} IP(s) flagged as possible brute-force sources:\n")
    print(f"{'Source IP':<18}{'Attempts':<10}{'Accounts Targeted':<20}{'First Seen':<22}{'Last Seen':<22}")
    print("-" * 92)
    for ip, count in flagged:
        activity = details[ip]
        accounts_str = str(len(activity.accounts))
        print(
            f"{ip:<18}{count:<10}{accounts_str:<20}"
            f"{(activity.first_seen or '-'):<22}{(activity.last_seen or '-'):<22}"
        )


def write_report_csv(
    output_path: Path,
    details: dict[str, IpActivity],
    flagged: list[tuple[str, int]],
) -> None:
    """Write the flagged IPs to a CSV for inclusion in a portfolio writeup."""
    with output_path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["source_ip", "failed_attempts", "unique_accounts_targeted", "first_seen", "last_seen"])
        for ip, count in flagged:
            activity = details[ip]
            writer.writerow([
                ip,
                count,
                len(activity.accounts),
                activity.first_seen or "",
                activity.last_seen or "",
            ])


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Detect brute-force login attempts from a failed-logon CSV export."
    )
    parser.add_argument("--input", "-i", required=True, type=Path, help="Path to input CSV file")
    parser.add_argument("--threshold", "-t", type=int, default=5, help="Failed-attempt threshold (default: 5)")
    parser.add_argument("--output", "-o", type=Path, default=None, help="Optional path to write flagged results as CSV")
    return parser.parse_args()


def main() -> int:
    args = parse_args()

    if not args.input.exists():
        print(f"Error: input file not found: {args.input}", file=sys.stderr)
        return 1

    try:
        events = load_events(args.input)
    except ValueError as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1

    if not events:
        print("No matching failed-logon events found in the CSV.")
        return 0

    counts, details = aggregate_by_ip(events)
    flagged = flag_anomalies(counts, args.threshold)
    print_report(counts, details, flagged, args.threshold)

    if args.output:
        write_report_csv(args.output, details, flagged)
        print(f"\nFlagged results written to: {args.output}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
