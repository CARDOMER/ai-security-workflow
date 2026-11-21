import json
import sqlite3
from collections import Counter
from contextlib import closing
from pathlib import Path


class RunHistory:
    def __init__(self, path: Path):
        self.path = path

    def connect(self):
        connection = sqlite3.connect(self.path, timeout=5)
        connection.row_factory = sqlite3.Row
        connection.execute("""
            CREATE TABLE IF NOT EXISTS workflow_runs (
                id TEXT PRIMARY KEY,
                completed_at TEXT NOT NULL,
                payload TEXT NOT NULL
            )
        """)
        return connection

    def save(self, run: dict):
        with closing(self.connect()) as connection, connection:
            connection.execute(
                "INSERT INTO workflow_runs (id, completed_at, payload) VALUES (?, ?, ?)",
                (run["id"], run["completedAt"], json.dumps(run, ensure_ascii=False)),
            )

    def list(self):
        with closing(self.connect()) as connection:
            rows = connection.execute(
                "SELECT payload FROM workflow_runs ORDER BY completed_at DESC, id DESC LIMIT 20"
            ).fetchall()
        return [
            {key: value for key, value in json.loads(row["payload"]).items()
             if key not in {"report", "nodes"}}
            for row in rows
        ]

    def find(self, run_id: str):
        with closing(self.connect()) as connection:
            row = connection.execute(
                "SELECT payload FROM workflow_runs WHERE id = ?", (run_id,),
            ).fetchone()
        return json.loads(row["payload"]) if row else None


def finding_key(item: dict) -> tuple:
    if item["category"] == "SCA":
        return "SCA", item["path"], item["group"], item["artifact"], item["advisoryId"]
    return item["category"], item["path"], item["class"], item["line"]


def exact_finding_key(item: dict) -> tuple:
    key = finding_key(item)
    return (*key, item["version"]) if item["category"] == "SCA" else key


def matched_indices(items, candidates, key):
    shared = Counter(map(key, items)) & Counter(map(key, candidates))
    indices = set()
    for index, item in enumerate(items):
        identity = key(item)
        if shared[identity]:
            indices.add(index)
            shared[identity] -= 1
    return indices


def compare_runs(before: dict, after: dict) -> dict:
    if (not before["comparable"] or not after["comparable"]
            or before["projectKey"] != after["projectKey"]
            or before["analyzers"] != after["analyzers"]):
        raise ValueError("Нужны два полных отчёта одной учебной цели с одинаковым набором анализаторов.")

    older = before["report"]["findings"]
    newer = after["report"]["findings"]
    exact_older = matched_indices(older, newer, exact_finding_key)
    exact_newer = matched_indices(newer, older, exact_finding_key)
    older_remaining = [item for index, item in enumerate(older) if index not in exact_older]
    newer_remaining = [item for index, item in enumerate(newer) if index not in exact_newer]
    shared_older = matched_indices(older_remaining, newer_remaining, finding_key)
    shared_newer = matched_indices(newer_remaining, older_remaining, finding_key)
    added = [item for index, item in enumerate(newer_remaining) if index not in shared_newer]
    removed = [item for index, item in enumerate(older_remaining) if index not in shared_older]
    newer_remaining_indices = [index for index in range(len(newer)) if index not in exact_newer]
    unchanged_indices = exact_newer | {newer_remaining_indices[index] for index in shared_newer}
    unchanged = [item for index, item in enumerate(newer) if index in unchanged_indices]
    return {"added": added, "removed": removed, "unchanged": unchanged}
