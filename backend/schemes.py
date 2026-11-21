from contextlib import closing
from datetime import datetime, timezone
import json
from os import getenv
from pathlib import Path
import re
import sqlite3
from typing import Literal
from uuid import uuid4

import httpx
from fastapi import APIRouter, HTTPException
from pydantic import ConfigDict, Field

from backend.summary import GigaChatRequestError, get_summary_provider
from backend.workflow import Input, Link, Step, Workflow, ordered_steps


class DraftNode(Step):
    x: float = Field(allow_inf_nan=False, ge=-10000, le=10000)
    y: float = Field(allow_inf_nan=False, ge=-10000, le=10000)


class Draft(Input):
    version: Literal[1]
    nodes: list[DraftNode] = Field(min_length=1, max_length=24)
    edges: list[Link] = Field(max_length=48)

    def validate_graph(self):
        trigger = "manual" if any(node.kind == "manual" for node in self.nodes) else "schedule"
        try:
            ordered_steps(Workflow(nodes=self.nodes, edges=self.edges, trigger=trigger))
        except ValueError as error:
            raise HTTPException(422, str(error)) from None


class Template(Input):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)
    title: str = Field(min_length=1, max_length=80)
    description: str = Field(min_length=1, max_length=300)
    draft: Draft


class Prompt(Input):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)
    prompt: str = Field(min_length=8, max_length=800)


class GeneratedCondition(Input):
    metric: Literal["count", "severity", "path"]
    minimum: int = Field(default=1, ge=0, le=100000)
    severity: Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"] = "HIGH"
    pattern: str = Field(default="", max_length=120)


class GeneratedScenario(Input):
    supported: bool
    trigger: Literal["manual", "schedule"]
    at: datetime | None = None
    analyzers: list[Literal["secret", "sca", "sast"]] = Field(min_length=1, max_length=3)
    condition: GeneratedCondition | None = None
    ai: bool
    webhook: bool

    def draft(self) -> Draft:
        if not self.supported or len(set(self.analyzers)) != len(self.analyzers):
            raise ValueError("Unsupported generated scenario")
        if self.trigger == "schedule" and (
            self.at is None or self.at.utcoffset() is None or
            not 0 < (self.at - datetime.now(timezone.utc)).total_seconds() <= 3600
        ):
            raise ValueError("Unsupported generated schedule")
        if self.condition and not (self.ai or self.webhook):
            raise ValueError("Generated condition has no output")
        nodes = [
            DraftNode(id=self.trigger, kind=self.trigger, x=0, y=100, at=self.at if self.trigger == "schedule" else None),
            DraftNode(id="source", kind="source", x=220, y=100),
            *(DraftNode(id=name, kind=name, x=440, y=index * 100) for index, name in enumerate(self.analyzers)),
            DraftNode(id="merge", kind="merge", x=660, y=100),
            DraftNode(id="report", kind="report", x=880, y=100),
        ]
        edges = [Link(source=self.trigger, target="source"), Link(source="merge", target="report")]
        for analyzer in self.analyzers:
            edges.extend([Link(source="source", target=analyzer), Link(source=analyzer, target="merge")])
        tail = "report"
        branch = None
        if self.condition:
            nodes.append(DraftNode(id="condition", kind="condition", x=1100, y=100, **self.condition.model_dump()))
            edges.append(Link(source=tail, target="condition"))
            tail, branch = "condition", "yes"
        if self.ai:
            nodes.append(DraftNode(id="ai", kind="ai", x=1320, y=100))
            edges.append(Link(source=tail, target="ai", branch=branch))
            tail, branch = "ai", None
        if self.webhook:
            nodes.append(DraftNode(id="webhook", kind="webhook", x=1540 if self.ai else 1320, y=100))
            edges.append(Link(source=tail, target="webhook", branch=branch))
        result = Draft(version=1, nodes=nodes, edges=edges)
        result.validate_graph()
        return result


def explicit_analyzers(prompt: str) -> list[str]:
    # Only resolve an explicit positive scan target, leaving ambiguous requests to the model.
    clause = re.search(r"\bпроверь\w*\b[^.!?;]*?\bна\s+([^.!?;]+)", prompt.casefold())
    if clause is None or re.search(r"\b(?:не|без|кроме|только\s+не)\b", clause[0]):
        return []
    target = clause[1]
    return [
        name for name, pattern in (
            ("secret", r"\b(?:секрет\w*|парол\w*|токен\w*|ключ\w*|secret)\b"),
            ("sca", r"\b(?:зависимост\w*|библиотек\w*|sca)\b"),
            ("sast", r"\b(?:sast|статическ\w*\s+анализ\w*)\b"),
        ) if re.search(pattern, target)
    ]


def make_scheme_router(database: Path):
    router = APIRouter(prefix="/api/workflow")

    def connect():
        connection = sqlite3.connect(database, timeout=5)
        connection.execute("CREATE TABLE IF NOT EXISTS templates (sequence INTEGER PRIMARY KEY, payload TEXT NOT NULL)")
        return connection

    @router.get("/templates")
    def templates():
        try:
            with closing(connect()) as connection:
                return [json.loads(row[0]) for row in connection.execute(
                    "SELECT payload FROM templates ORDER BY sequence DESC LIMIT 30"
                )]
        except sqlite3.Error:
            raise HTTPException(503, "Библиотека шаблонов недоступна.") from None

    @router.post("/templates", status_code=201)
    def publish(template: Template):
        template.draft.validate_graph()
        entry = {"id": uuid4().hex, **template.model_dump(mode="json", exclude_none=True)}
        try:
            with closing(connect()) as connection, connection:
                connection.execute("INSERT INTO templates (payload) VALUES (?)", (json.dumps(entry, ensure_ascii=False),))
                connection.execute(
                    "DELETE FROM templates WHERE sequence NOT IN (SELECT sequence FROM templates ORDER BY sequence DESC LIMIT 30)"
                )
        except sqlite3.Error:
            raise HTTPException(503, "Не удалось сохранить шаблон.") from None
        return entry

    @router.post("/generate")
    def generate(request: Prompt):
        provider = None if getenv("WORKFLOW_PUBLIC_DEMO") == "1" else get_summary_provider()
        if provider is None:
            raise HTTPException(503, "AI-генерация доступна в локальной версии с настроенной LLM.")
        now = datetime.now(timezone.utc)
        requested = explicit_analyzers(request.prompt)
        messages = [
            {"role": "system", "content": (
                "Опиши граф проверки встроенного учебного Repair Desk кратким JSON. "
                "Ручной запуск: trigger=manual. secret ищет секреты и токены, sca проверяет зависимости, "
                "sast проверяет исходный код. "
                "Для порога критичности condition.metric=severity, severity=HIGH или другой уровень. "
                "Если условия нет, condition=null. При наличии условия AI и webhook исполняются только по ветке Да. "
                "Например: {\"supported\":true,\"trigger\":\"manual\",\"at\":null,\"analyzers\":[\"secret\",\"sca\"],"
                "\"condition\":{\"metric\":\"severity\",\"severity\":\"HIGH\"},\"ai\":true,\"webhook\":true}. "
                f"Сейчас {now.isoformat()}. Расписание одноразовое, только следующий час, at с часовым поясом. "
                "Внешние репозитории, Telegram, секреты и URL недопустимы. Доступен HTTP webhook. "
                "Если запрос нельзя выразить этим графом, верни supported=false с остальными допустимыми полями."
            )},
            {"role": "user", "content": request.prompt},
        ]
        try:
            raw = provider.complete(messages, GeneratedScenario.model_json_schema(), "workflow_scenario", 750)
            scenario = GeneratedScenario.model_validate_json(raw)
            if requested:
                scenario = scenario.model_copy(update={"analyzers": requested})
            draft = scenario.draft()
        except (ValueError, HTTPException):
            raise HTTPException(422, "LLM вернула сценарий, который нельзя выполнить. Уточните задачу.") from None
        except (GigaChatRequestError, httpx.HTTPError, OSError, KeyError, TypeError, IndexError):
            raise HTTPException(502, "Не удалось получить сценарий от LLM.") from None
        return draft.model_dump(mode="json", exclude_none=True)

    return router
