def classify_scan_status(
    records: list[dict],
    previously_seen_processes: set[tuple[int, str | None]],
) -> list[dict]:
    """Mark process instances seen before, using start time to guard against PID reuse."""
    # Return updated copies so callers can retain the original scanner records unchanged.
    return [
        {
            **record,
            "status": (
                "Previously Seen"
                if (record["pid"], record.get("started_at")) in previously_seen_processes
                else "New"
            ),
        }
        for record in records
    ]
