from collections.abc import Sequence
from hmac import compare_digest
from os import getenv
from pathlib import Path
import re
from typing import Annotated, Protocol

import httpx
from fastapi import Depends, FastAPI, Header, HTTPException, Response
from pydantic import BaseModel, ConfigDict, Field

from backend.sca_scanner import MavenScaScanner, ScaFinding
from backend.sast_scanner import KotlinSastScanner, SastFinding
from backend.secrets_scanner import SecretFinding, SecretsScanner
from backend.summary import (
    GigaChatProvider, GigaChatRequestError, REPORT_SIGNATURE_HEADER, ReportSummary, SummaryProvider, SummaryResult, YandexProvider,
    get_summary_provider, report_metadata, rules_summary, sign_metadata,
)
from backend.workflow import make_workflow_router


ROOT = Path(__file__).resolve().parents[1] / "test-data" / "training-project"
DATABASE = ROOT.parent / "vulnerability-database" / "vulnerabilities.json"
Finding = Annotated[SecretFinding | ScaFinding | SastFinding, Field(discriminator="category")]


class ScanReport(BaseModel):
    findings: list[Finding]


class ScanRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    analyzers: list[str] = Field(min_length=1)


class Analyzer(Protocol):
    def scan(self, root: Path) -> Sequence[Finding]: ...


ANALYZERS: dict[str, Analyzer] = {
    "secret": SecretsScanner(),
    "sca": MavenScaScanner(DATABASE),
    "sast": KotlinSastScanner(),
}
app = FastAPI(title="AI Security Workflow")


@app.get("/api/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/api/scan", response_model=ScanReport, response_model_exclude_none=True)
def scan(response: Response, request: ScanRequest | None = None) -> ScanReport:
    selected = set(request.analyzers) if request else ANALYZERS.keys()
    if selected - ANALYZERS.keys():
        raise HTTPException(422, "Сценарий содержит неизвестный анализатор.")
    if not ROOT.is_dir():
        raise HTTPException(503, "Учебный проект отсутствует в test-data/training-project.")
    try:
        report = ScanReport(findings=[
            finding for name, analyzer in ANALYZERS.items() if name in selected
            for finding in analyzer.scan(ROOT)
        ])
    except (OSError, ValueError):
        raise HTTPException(500, "Не удалось прочитать файлы проекта или справочник Maven.") from None
    response.headers[REPORT_SIGNATURE_HEADER] = sign_metadata(report_metadata(report.findings))
    return report


@app.post("/api/report/summary", response_model=SummaryResult, response_model_exclude_none=True)
def summarize_report(
    report: ScanReport,
    provider: Annotated[SummaryProvider | None, Depends(get_summary_provider)],
    signature: Annotated[str, Header(alias=REPORT_SIGNATURE_HEADER, pattern=r"^[a-f0-9]{64}$")],
) -> SummaryResult:
    if not 1 <= len(report.findings) <= 100:
        raise HTTPException(422, "Для рекомендаций нужен отчёт с 1–100 находками.")
    metadata = report_metadata(report.findings)
    if not compare_digest(signature, sign_metadata(metadata)):
        raise HTTPException(422, "Отчёт изменился или устарел. Запустите проверку ещё раз.")
    return summarize_metadata(metadata, None if getenv("WORKFLOW_PUBLIC_DEMO") == "1" else provider)


ADVISORY = re.compile(r"\b(?:CVE-\d{4}-\d{4,}|GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4})\b", re.I)


def summarize_metadata(metadata: list[dict], provider: SummaryProvider | None) -> SummaryResult:
    if provider is None:
        return rules_summary(metadata, "Облачный провайдер не настроен или отключён на сервере.")
    try:
        summary = ReportSummary.model_validate_json(provider.summarize(metadata))
        for priority in summary.priorities:
            if max(priority.findingIds) > len(metadata) or len(set(priority.findingIds)) != len(priority.findingIds):
                raise ValueError("Invalid finding references")
        allowed = {item["advisoryId"].upper() for item in metadata if "advisoryId" in item}
        content = [summary.summary, *(text for item in summary.priorities for text in (item.action, item.reason))]
        if any(match.upper() not in allowed for field in content for match in ADVISORY.findall(field)):
            raise ValueError("Unknown advisory reference")
    except (httpx.TimeoutException, TimeoutError):
        return rules_summary(metadata, "Облачный провайдер не ответил вовремя.")
    except GigaChatRequestError as error:
        return rules_summary(metadata, str(error))
    except (httpx.HTTPError, OSError):
        return rules_summary(metadata, "Запрос к облачному провайдеру завершился ошибкой.")
    except (ValueError, KeyError, IndexError, TypeError):
        return rules_summary(metadata, "Рекомендации облачного провайдера не прошли проверку.")
    provider_name = "gigachat" if isinstance(provider, GigaChatProvider) else "yandex" if isinstance(provider, YandexProvider) else None
    return SummaryResult(mode="llm", provider=provider_name, **summary.model_dump())


app.include_router(make_workflow_router(ROOT, ANALYZERS, summarize_metadata))
