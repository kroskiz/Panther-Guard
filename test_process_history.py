import unittest

from src.process_history import classify_scan_status


class TestProcessHistory(unittest.TestCase):
    def test_marks_process_instances_using_pid_and_start_time(self):
        records = [
            {"pid": 101, "started_at": "2026-11-27T15:00:00Z"},
            {"pid": 101, "started_at": "2026-11-27T15:01:00Z"},
        ]

        classified = classify_scan_status(records, {(101, "2026-11-27T15:00:00Z")})

        self.assertEqual(
            [record["status"] for record in classified],
            ["Previously Seen", "New"],
        )
        self.assertNotIn("status", records[0])

    def test_empty_snapshot_returns_no_records(self):
        self.assertEqual(classify_scan_status([], {(101, None)}), [])
