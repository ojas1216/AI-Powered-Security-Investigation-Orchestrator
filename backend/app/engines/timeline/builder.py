"""Timeline fusion: merge events from every source into one ordered narrative."""
from __future__ import annotations

from app.schemas.investigation import TimelineEvent


def build_timeline(*event_groups: list[TimelineEvent]) -> list[TimelineEvent]:
    """Flatten and sort heterogeneous event lists by timestamp (stable)."""
    merged: list[TimelineEvent] = []
    for group in event_groups:
        merged.extend(group)
    merged.sort(key=lambda e: e.timestamp)
    return merged
