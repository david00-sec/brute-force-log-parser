"""
Unit tests for logon_anomaly_detector.py

Run with:
    pytest tests/test_logon_anomaly_detector.py -v
"""

import csv
import sys
from collections import Counter
from pathlib import Path

import pytest

# Make the script importable from the tests/ folder
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from logon_anomaly_detector import (
    normalize_headers,
    load_events,
    aggregate_by_ip,
    flag_anomalies,
    IpActivity,
)


# ---------------------------------------------------------------------------
# normalize_headers
# ---------------------------------------------------------------------------

def test_normalize_headers_canonical_names():
    """Standard header names should map straight through."""
    fieldnames = ["source_ip", "account_name", "timestamp", "event_id"]
    mapping = normalize_headers(fieldnames)
    assert mapping == {
        "source_ip": "source_ip",
        "account_name": "account_name",
        "timestamp": "timestamp",
        "event_id": "event_id",
    }


def test_normalize_headers_aliases():
    """Splunk-style alternate header names should also map correctly."""
    fieldnames = ["src_ip", "user", "_time", "EventCode"]
    mapping = normalize_headers(fieldnames)
    assert mapping["src_ip"] == "source_ip"
    assert mapping["user"] == "account_name"
    assert mapping["_time"] == "timestamp"
    assert mapping["EventCode"] == "event_id"


def test_normalize_headers_missing_required_column_raises():
    """Missing a required column (e.g. no IP field at all) should raise."""
    fieldnames = ["account_name", "timestamp"]  # no source_ip / alias
    with pytest.raises(ValueError):
        normalize_headers(fieldnames)


def test_normalize_headers_event_id_optional():
    """event_id is optional — its absence should not raise."""
    fieldnames = ["source_ip", "account_name", "timestamp"]
    mapping = normalize_headers(fieldnames)
    assert "event_id" not in mapping.values()


# ---------------------------------------------------------------------------
# load_events (via a temp CSV file)
# ---------------------------------------------------------------------------

def write_csv(path: Path, rows: list[dict], fieldnames: list[str]) -> None:
    with path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def test_load_events_filters_non_4625(tmp_path):
    csv_path = tmp_path / "events.csv"
    write_csv(
        csv_path,
        rows=[
            {"source_ip": "1.1.1.1", "account_name": "a", "timestamp": "t1", "event_id": "4625"},
            {"source_ip": "1.1.1.1", "account_name": "a", "timestamp": "t2", "event_id": "4624"},
        ],
        fieldnames=["source_ip", "account_name", "timestamp", "event_id"],
    )
    events = load_events(csv_path)
    assert len(events) == 1
    assert events[0]["timestamp"] == "t1"


def test_load_events_no_event_id_column_keeps_all(tmp_path):
    """If there's no event_id column, assume the CSV is pre-filtered."""
    csv_path = tmp_path / "events.csv"
    write_csv(
        csv_path,
        rows=[
            {"source_ip": "1.1.1.1", "account_name": "a", "timestamp": "t1"},
            {"source_ip": "1.1.1.1", "account_name": "b", "timestamp": "t2"},
        ],
        fieldnames=["source_ip", "account_name", "timestamp"],
    )
    events = load_events(csv_path)
    assert len(events) == 2


def test_load_events_empty_file_raises(tmp_path):
    csv_path = tmp_path / "empty.csv"
    csv_path.write_text("", encoding="utf-8")
    with pytest.raises(ValueError):
        load_events(csv_path)


# ---------------------------------------------------------------------------
# aggregate_by_ip
# ---------------------------------------------------------------------------

def test_aggregate_by_ip_counts_correctly():
    events = [
        {"source_ip": "1.1.1.1", "account_name": "admin", "timestamp": "t1"},
        {"source_ip": "1.1.1.1", "account_name": "root", "timestamp": "t2"},
        {"source_ip": "2.2.2.2", "account_name": "admin", "timestamp": "t3"},
    ]
    counts, details = aggregate_by_ip(events)
    assert counts == Counter({"1.1.1.1": 2, "2.2.2.2": 1})
    assert details["1.1.1.1"].accounts == {"admin", "root"}
    assert details["1.1.1.1"].first_seen == "t1"
    assert details["1.1.1.1"].last_seen == "t2"


def test_aggregate_by_ip_skips_blank_ip():
    events = [
        {"source_ip": "", "account_name": "admin", "timestamp": "t1"},
        {"source_ip": "1.1.1.1", "account_name": "admin", "timestamp": "t2"},
    ]
    counts, _ = aggregate_by_ip(events)
    assert counts == Counter({"1.1.1.1": 1})


# ---------------------------------------------------------------------------
# flag_anomalies
# ---------------------------------------------------------------------------

def test_flag_anomalies_respects_threshold():
    counts = Counter({"1.1.1.1": 5, "2.2.2.2": 2, "3.3.3.3": 10})
    flagged = flag_anomalies(counts, threshold=3)
    assert flagged == [("3.3.3.3", 10), ("1.1.1.1", 5)]


def test_flag_anomalies_threshold_is_exclusive():
    """Count exactly equal to the threshold should NOT be flagged
    (mirrors SPL `where count > threshold`)."""
    counts = Counter({"1.1.1.1": 3})
    flagged = flag_anomalies(counts, threshold=3)
    assert flagged == []


def test_flag_anomalies_none_over_threshold_returns_empty():
    counts = Counter({"1.1.1.1": 1, "2.2.2.2": 2})
    flagged = flag_anomalies(counts, threshold=5)
    assert flagged == []
