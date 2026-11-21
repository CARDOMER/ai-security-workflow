import json
from pathlib import Path

from backend.summary import METADATA_FIELDS

CLASSES = ("SECRET", "SCA", "SAST")
METRICS = ("expected", "matched", "missed", "unexpected")


def read_reference(path: Path):
    reference = json.loads(path.read_text(encoding="utf-8-sig"))
    if reference["formatVersion"] != 1 or not reference["findings"]:
        raise ValueError("Unsupported analysis reference")
    return reference


def matches(actual, expected, advisory_ids):
    if actual["category"] != expected["category"]:
        return False
    if actual["category"] == "SCA":
        def canonical(advisory_id):
            return advisory_ids.get((expected["group"], expected["artifact"], advisory_id), advisory_id)

        return (
            all(actual[key] == expected[key] for key in ("path", "group", "artifact", "version"))
            and canonical(actual["advisoryId"]) in map(canonical, expected["advisoryIds"])
        )
    return actual["class"] == expected["class"] and any(
        actual["path"] == location["path"]
        and location["line"] <= actual["line"] <= location.get("endLine", location["line"])
        for location in (expected, *expected.get("alternateLocations", []))
    )


def reference_location(item):
    return {key: value for key, value in item.items() if key in METADATA_FIELDS | {"id", "advisoryIds"}}


def evaluate(reference, actual, advisories=()):
    advisory_ids = {
        (entry["group"], entry["artifact"], alias): entry["id"]
        for entry in advisories
        for alias in entry.get("aliases", [])
    }
    remaining = list(actual)
    metrics = {category: dict.fromkeys(METRICS, 0) for category in CLASSES}
    missed = []
    for expected in reference["findings"]:
        row = metrics[expected["category"]]
        row["expected"] += 1
        position = next((i for i, item in enumerate(remaining) if matches(item, expected, advisory_ids)), None)
        if position is None:
            row["missed"] += 1
            missed.append(reference_location(expected))
        else:
            row["matched"] += 1
            remaining.pop(position)
    for item in remaining:
        metrics[item["category"]]["unexpected"] += 1

    controls = [item for item in reference["controls"] if item["expectedFinding"] is False]
    control_hits = [
        reference_location(item) for item in controls
        if any(matches(hit, item, advisory_ids) for hit in actual)
    ]
    return {
        "byCategory": metrics,
        "total": {key: sum(row[key] for row in metrics.values()) for key in METRICS},
        "missed": missed,
        "unexpected": remaining,
        "controls": {"total": len(controls), "hits": control_hits},
    }
