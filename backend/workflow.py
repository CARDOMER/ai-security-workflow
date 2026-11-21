from collections import Counter, OrderedDict
from contextlib import nullcontext
from datetime import datetime, timezone
from hashlib import sha256
from os import getenv
from pathlib import Path
from sqlite3 import Error as DatabaseError
from threading import Lock, Thread, Timer
from time import monotonic
from typing import Literal
from uuid import uuid4

import httpx
import regex
from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, ConfigDict, Field
from starlette.concurrency import run_in_threadpool

from backend.archive import MAX_UPLOAD, training_zip
from backend.history import RunHistory, compare_runs
from backend.summary import SEVERITY_ORDER, get_summary_provider, report_metadata, sign_metadata


class Input(BaseModel):
    model_config = ConfigDict(extra="forbid")


Kind = Literal["manual", "schedule", "source", "secret", "sca", "sast", "merge", "condition", "report", "ai", "webhook"]
TRIGGERS = {"manual", "schedule"}
ANALYSIS = {"secret", "sca", "sast"}
DEMO_ARCHIVES = ("check-before.zip", "check-after.zip")
CONNECTIONS = {
    "manual": {"source"}, "schedule": {"source"}, "source": ANALYSIS,
    **{kind: {"merge"} for kind in ANALYSIS},
    "merge": {"report"}, "report": {"condition", "ai", "webhook"},
    "condition": {"ai", "webhook"}, "ai": {"webhook"}, "webhook": set(),
}


class Step(Input):
    id: str = Field(pattern=r"^[a-zA-Z0-9_-]{1,60}$")
    kind: Kind
    metric: Literal["count", "severity", "path"] = "count"
    minimum: int = Field(default=1, ge=0, le=100000)
    severity: Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"] = "HIGH"
    pattern: str = Field(default="", max_length=120)
    at: datetime | None = None


class Link(Input):
    source: str = Field(max_length=60)
    target: str = Field(max_length=60)
    branch: Literal["yes", "no"] | None = None


class Workflow(Input):
    nodes: list[Step] = Field(min_length=1, max_length=24)
    edges: list[Link] = Field(max_length=48)
    uploadId: str | None = Field(default=None, max_length=32)
    projectLabel: str | None = Field(default=None, pattern=r"^[\w][\w .-]{0,59}$")
    trigger: Literal["manual", "schedule"] = "manual"


def scan_graph(upload_id=None, project_label=None):
    analyzers = sorted(ANALYSIS)
    return Workflow(
        nodes=[Step(id=kind, kind=kind) for kind in ("manual", "source", *analyzers, "merge", "report")],
        edges=[
            Link(source="manual", target="source"), Link(source="merge", target="report"),
            *(Link(source="source", target=kind) for kind in analyzers),
            *(Link(source=kind, target="merge") for kind in analyzers),
        ],
        uploadId=upload_id, projectLabel=project_label,
    )


def ordered_steps(graph: Workflow):
    nodes = {node.id: node for node in graph.nodes}
    if len(nodes) != len(graph.nodes):
        raise ValueError("Идентификаторы узлов должны быть уникальны.")
    singleton = Counter(node.kind for node in graph.nodes if node.kind != "webhook")
    if any(count > 1 for count in singleton.values()):
        raise ValueError("Каждый тип узла, кроме webhook, можно добавить один раз.")
    inbound = {node.id: [] for node in graph.nodes}
    links = set()
    for edge in graph.edges:
        source, target = nodes.get(edge.source), nodes.get(edge.target)
        key = (edge.source, edge.target, edge.branch)
        if (source is None or target is None or target.kind not in CONNECTIONS[source.kind]
                or (source.kind == "condition") != (edge.branch is not None) or key in links):
            raise ValueError("Найдена несовместимая или повторяющаяся связь.")
        inbound[edge.target].append(edge)
        links.add(key)
    ordered = []
    pending = dict(nodes)
    while pending:
        ready = [node for node in pending.values() if all(edge.source not in pending for edge in inbound[node.id])]
        if not ready:
            raise ValueError("Граф содержит цикл.")
        ordered.extend(ready)
        for node in ready:
            del pending[node.id]

    active = set()
    for node in ordered:
        if node.kind == graph.trigger or any(edge.source in active for edge in inbound[node.id]):
            active.add(node.id)
    if not any(node.kind == "report" and node.id in active for node in ordered):
        raise ValueError("Соедините триггер, источник, анализатор, объединение и отчёт.")
    for node in ordered:
        if node.kind == "condition" and node.metric == "path":
            if not node.pattern:
                raise ValueError("Укажите регулярное выражение для проверки пути.")
            try:
                regex.compile(node.pattern)
            except regex.error:
                raise ValueError("Некорректное регулярное выражение.") from None
    return ordered, inbound


def condition_matches(node, findings):
    if node.metric == "count":
        return len(findings) >= node.minimum
    if node.metric == "severity":
        return any(SEVERITY_ORDER[item.severity] <= SEVERITY_ORDER[node.severity] for item in findings)
    matcher = regex.compile(node.pattern)
    deadline = monotonic() + 2.5
    for path in dict.fromkeys(item.path for item in findings):
        remaining = deadline - monotonic()
        if remaining <= 0:
            raise TimeoutError
        if matcher.search(path, timeout=min(0.025, remaining)):
            return True
    return False


def make_workflow_router(root, analyzers, summarize, history_path=None):
    router = APIRouter(prefix="/api/workflow")
    lock = Lock()
    runs = OrderedDict()
    uploads = OrderedDict()
    deliveries = OrderedDict()
    scheduled = None
    public_demo = getenv("WORKFLOW_PUBLIC_DEMO") == "1"
    demo_archives = {}
    demo_directory = Path(__file__).resolve().parents[1] / "demo"
    for filename in DEMO_ARCHIVES:
        path = demo_directory / filename
        if path.is_file():
            data = path.read_bytes()
            demo_archives[sha256(data).hexdigest()[:32]] = data
    history = RunHistory(history_path or Path(getenv(
        "WORKFLOW_HISTORY_DB", str(root.parents[1] / "workflow-history.sqlite3"),
    )))

    @router.post("/uploads", status_code=201)
    async def upload(request: Request):
        if request.headers.get("X-Training-Project") != "authorized":
            raise HTTPException(403, "Подтвердите, что ZIP содержит разрешённый учебный проект.")
        data = bytearray()
        async for chunk in request.stream():
            if len(data) + len(chunk) > MAX_UPLOAD:
                raise HTTPException(413, "Допустим ZIP размером до 8 МБ.")
            data.extend(chunk)
        archive = bytes(data)
        if public_demo:
            project = sha256(archive).hexdigest()[:32]
            if demo_archives.get(project) != archive:
                raise HTTPException(422, "В публичном демо доступны только два учебных ZIP из комплекта.")
            return {"uploadId": project}

        def validate():
            with training_zip(archive):
                pass

        try:
            await run_in_threadpool(validate)
        except ValueError as error:
            raise HTTPException(422, str(error)) from None
        project = uuid4().hex
        with lock:
            uploads[project] = archive
            while len(uploads) > 4:
                uploads.popitem(last=False)
        return {"uploadId": project}

    def update(run, **values):
        with lock:
            run.update(values)

    def node_status(run, node, status, detail=""):
        with lock:
            state = {"status": status, "detail": detail}
            run["nodes"][node.id] = state
            run["events"].append({"nodeId": node.id, **state})

    def execute(graph, ordered, inbound, run, archive, provider):
        enabled = {}
        results = {}
        branches = {}
        findings = []
        summary = None
        merge = next(node for node in ordered if node.kind == "merge")
        contributors = {edge.source for edge in inbound[merge.id]}
        failed_analyzers: list[str] = []
        update(run, status="running")
        try:
            if archive is None and not root.is_dir():
                raise ValueError("Учебный проект отсутствует.")
            with (nullcontext(root) if archive is None else training_zip(archive)) as project:
                for node in ordered:
                    active = node.kind == graph.trigger or any(
                        enabled.get(edge.source, False)
                        and (edge.branch is None or branches.get(edge.source) == edge.branch)
                        for edge in inbound[node.id]
                    )
                    if not active:
                        node_status(run, node, "skipped")
                        continue
                    node_status(run, node, "running")
                    detail = ""
                    try:
                        if node.kind == "source":
                            detail = "Repair Desk" if archive is None else "Загруженный ZIP"
                        elif node.kind in ANALYSIS:
                            results[node.id] = list(analyzers[node.kind].scan(project))
                            detail = f"Находок: {len(results[node.id])}"
                        elif node.kind == "merge":
                            findings = [item for edge in inbound[node.id] for item in results.get(edge.source, [])]
                            detail = f"Объединено: {len(findings)}"
                        elif node.kind == "report":
                            report = {"findings": [item.model_dump(by_alias=True, exclude_none=True) for item in findings]}
                            signature = sign_metadata(report_metadata(findings))
                            update(run, report=report, signature=signature)
                            detail = f"Находок: {len(findings)}"
                        elif node.kind == "condition":
                            branches[node.id] = "yes" if condition_matches(node, findings) else "no"
                            detail = "Ветка «Да»" if branches[node.id] == "yes" else "Ветка «Нет»"
                        elif node.kind == "ai":
                            if not findings or len(findings) > 100:
                                node_status(run, node, "skipped", "Разбор доступен для 1–100 находок.")
                                enabled[node.id] = True
                                continue
                            summary = summarize(report_metadata(findings), provider).model_dump(exclude_none=True)
                            update(run, summary=summary)
                            if summary["mode"] == "rules":
                                detail = "Приоритизация по правилам"
                            else:
                                detail = {"gigachat": "GigaChat", "yandex": "YandexGPT"}.get(summary.get("provider"), "ИИ-разбор")
                        elif node.kind == "webhook":
                            payload = {
                                "runId": run["id"],
                                "counts": dict(Counter(item.category for item in findings)),
                                "maxSeverity": min((item.severity for item in findings), key=SEVERITY_ORDER.__getitem__, default=None),
                                "reportComplete": not failed_analyzers,
                                "failedAnalyzers": sorted(failed_analyzers),
                            }
                            if summary is not None:
                                payload["recommendations"] = summary["priorities"]
                            response = httpx.post(
                                getenv("WORKFLOW_WEBHOOK_URL", "http://127.0.0.1:8000/api/workflow/demo-webhook"),
                                json=payload, timeout=5, follow_redirects=False,
                            )
                            response.raise_for_status()
                            detail = f"Доставлено, HTTP {response.status_code}"
                    except Exception as error:
                        if node.id in contributors:
                            failed_analyzers.append(node.kind)
                        detail = "Нода завершилась ошибкой."
                        if node.kind == "webhook":
                            status = error.response.status_code if isinstance(error, httpx.HTTPStatusError) else None
                            detail = f"Ошибка доставки, HTTP {status}" if status else "Ошибка доставки webhook."
                        elif node.kind == "condition" and isinstance(error, TimeoutError):
                            detail = "Превышено время проверки регулярного выражения."
                        node_status(run, node, "error", detail)
                        continue
                    enabled[node.id] = True
                    node_status(run, node, "done", detail)
        except (ValueError, OSError):
            for node in ordered:
                if node.kind == "source":
                    node_status(run, node, "error", "Не удалось открыть учебный проект.")
                else:
                    node_status(run, node, "skipped")
        status = "error" if not run.get("report") or any(
            item["status"] == "error" for item in run["nodes"].values()
        ) else "done"
        selected = sorted(
            node.kind for node in ordered if node.id in contributors
            and run["nodes"][node.id]["status"] in {"done", "error"}
        )
        record = {
            "id": run["id"], "status": status, "completedAt": datetime.now(timezone.utc).isoformat(),
            "source": (graph.projectLabel or "Загруженный ZIP") if archive is not None else "Repair Desk",
            "projectKey": ("upload:" + (graph.projectLabel.strip().casefold() if graph.projectLabel
                                        else graph.uploadId)) if archive is not None else "builtin:repair-desk",
            "analyzers": selected,
            "comparable": bool(run.get("report")) and bool(selected) and not failed_analyzers,
            "nodes": {node.id: {"kind": node.kind, **run["nodes"][node.id]} for node in ordered},
            "report": run.get("report"),
            "count": len(findings) if run.get("report") else None,
        }
        try:
            history.save(record)
        except (DatabaseError, OSError):
            update(run, historyError="Локальная история недоступна. Скачайте отчёт до закрытия страницы.")
        update(run, status=status)

    def start(graph: Workflow, *, wait=False):
        nonlocal scheduled
        if public_demo and graph.uploadId:
            graph = graph.model_copy(update={"projectLabel": "Demo Desk"})
        try:
            ordered, inbound = ordered_steps(graph)
        except ValueError as error:
            raise HTTPException(422, str(error)) from None
        delay = 0.0
        if graph.trigger == "schedule":
            trigger = next(node for node in ordered if node.kind == "schedule")
            if trigger.at is None or trigger.at.utcoffset() is None:
                raise HTTPException(422, "Укажите дату и время со смещением от UTC.")
            delay = (trigger.at - datetime.now(timezone.utc)).total_seconds()
            if not 0 < delay <= 3600:
                raise HTTPException(422, "Выберите время в пределах ближайшего часа.")
        run = {
            "id": uuid4().hex, "status": "scheduled" if delay else "queued",
            "nodes": {node.id: {"status": "waiting", "detail": ""} for node in ordered},
            "events": [{"nodeId": node.id, "status": "waiting", "detail": ""} for node in ordered],
        }
        with lock:
            archive = demo_archives.get(graph.uploadId, uploads.get(graph.uploadId))
            if graph.uploadId and archive is None:
                raise HTTPException(404, "Загрузите ZIP повторно.")
            running = {"queued", "running", "scheduled"}
            if sum(item["status"] in running for item in runs.values()) >= 4:
                raise HTTPException(429, "Слишком много текущих запусков.")
            if delay and scheduled and runs.get(scheduled, {}).get("status") in running:
                raise HTTPException(409, "Уже есть запланированный запуск.")
            if len(runs) >= 24:
                oldest = next(key for key, item in runs.items() if item["status"] not in running)
                del runs[oldest]
                deliveries.pop(oldest, None)
            runs[run["id"]] = run
            if delay:
                scheduled = run["id"]
        provider = None if public_demo else get_summary_provider()
        args = (graph, ordered, inbound, run, archive, provider)
        if wait:
            execute(*args)
            if run["status"] != "done" or run.get("historyError"):
                raise HTTPException(503, "Не удалось сохранить полный отчёт демонстрационного запуска.")
        elif delay:
            worker = Timer(delay, execute, args=args)
            worker.daemon = True
            worker.start()
        else:
            worker = Thread(target=execute, args=args, daemon=True)
            worker.start()
        return {"id": run["id"]}

    @router.post("/runs", status_code=202)
    def start_run(graph: Workflow):
        return start(graph)

    @router.get("/runs/{run_id}")
    def result(run_id: str):
        with lock:
            if run_id not in runs:
                raise HTTPException(404, "Запуск не найден.")
            run = runs[run_id]
            return {**run, "nodes": dict(run["nodes"]), "events": list(run["events"])}

    @router.get("/history")
    def recent():
        try:
            return history.list()
        except (DatabaseError, OSError):
            raise HTTPException(503, "Локальная история недоступна.") from None

    def get_saved(run_id):
        try:
            record = history.find(run_id)
        except (DatabaseError, OSError):
            raise HTTPException(503, "Локальная история недоступна.") from None
        if record is None:
            raise HTTPException(404, "Запуск не найден в истории.")
        return record

    @router.get("/history/{run_id}")
    def saved(run_id: str):
        return get_saved(run_id)

    @router.post("/history/compare")
    def compare(before: str, after: str):
        previous, current = get_saved(before), get_saved(after)
        if previous["completedAt"] >= current["completedAt"]:
            raise HTTPException(422, "Выберите сначала предыдущий запуск, затем новый.")
        try:
            return compare_runs(previous, current)
        except ValueError as error:
            raise HTTPException(422, str(error)) from None

    @router.post("/demo-comparison")
    def compare_demo():
        if len(demo_archives) != len(DEMO_ARCHIVES):
            raise HTTPException(503, "Демонстрационные архивы недоступны.")
        before, after = (
            start(scan_graph(upload_id, "Demo Desk"), wait=True)["id"]
            for upload_id in demo_archives
        )
        return {"before": before, "after": after, "difference": compare(before, after)}

    class Delivery(Input):
        runId: str = Field(pattern=r"^[a-f0-9]{32}$")
        counts: dict[Literal["SECRET", "SCA", "SAST"], int]
        maxSeverity: Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"] | None
        reportComplete: bool = True
        failedAnalyzers: list[Literal["secret", "sca", "sast"]] = Field(default_factory=list, max_length=3)
        recommendations: list[dict] = Field(default_factory=list, max_length=3)

    @router.post("/demo-webhook", status_code=202)
    def receive(payload: Delivery):
        with lock:
            run = runs.get(payload.runId)
            if run is None or run["status"] != "running":
                raise HTTPException(404, "Текущий запуск не найден.")
            deliveries[payload.runId] = payload.model_dump()
            run["delivery"] = deliveries[payload.runId]
        return {"accepted": True}

    return router
