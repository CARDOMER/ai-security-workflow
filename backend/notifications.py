import json
from os import getenv
from urllib.parse import urlsplit, urlunsplit

import httpx

DEMO_WEBHOOK_PATH = "/api/workflow/demo-webhook"
DEMO_WEBHOOK_HEADER = "X-Cyber-Garden-Webhook"


def is_local_demo_webhook(address: str) -> bool:
    try:
        url = urlsplit(address)
        return (
            url.scheme in {"http", "https"}
            and url.hostname in {"127.0.0.1", "localhost", "::1"}
            and url.path == DEMO_WEBHOOK_PATH
            and not url.username and not url.password
        )
    except ValueError:
        return False


def report_address(run_id: str):
    address = getenv("WORKFLOW_UI_URL") or getenv("RENDER_EXTERNAL_URL", "")
    try:
        url = urlsplit(address)
        if url.scheme in {"https", "http"} and url.hostname and not url.username and not url.password:
            return urlunsplit((url.scheme, url.netloc, url.path.rstrip("/") + "/", f"run={run_id}", "results"))
    except ValueError:
        pass
    return None


def telegram_configured() -> bool:
    return bool(getenv("TELEGRAM_BOT_TOKEN") and getenv("TELEGRAM_CHAT_ID"))


def send_telegram(payload: dict, *, report: dict | None = None) -> int:
    token = getenv("TELEGRAM_BOT_TOKEN", "")
    chat = getenv("TELEGRAM_CHAT_ID", "")
    if not token or not chat:
        raise ValueError("Учебный чат Telegram не настроен.")
    counts = ", ".join(f"{category}: {count}" for category, count in payload["counts"].items()) or "0"
    lines = [
        "Cyber Garden · итог проверки",
        f"Находки: {counts}",
        f"Максимальная критичность: {payload['maxSeverity'] or 'нет'}",
        "Отчёт полный." if payload["reportComplete"] else "Отчёт неполный.",
        payload.get("reportUrl") or payload.get("reportUrlUnavailable", ""),
    ]
    text = "\n".join(lines)
    method = "sendMessage"
    request = {"json": {"chat_id": chat, "text": text, "link_preview_options": {"is_disabled": True}}}
    if report is not None:
        method = "sendDocument"
        request = {
            "data": {"chat_id": chat, "caption": text},
            "files": {"document": ("repair-desk-report.json",
                                   json.dumps(report, ensure_ascii=False, indent=2).encode("utf-8"),
                                   "application/json")},
        }
    try:
        response = httpx.post(
            f"https://api.telegram.org/bot{token}/{method}",
            timeout=5, follow_redirects=False, **request,
        )
        if response.is_success:
            acknowledgment = response.json()
            if isinstance(acknowledgment, dict) and acknowledgment.get("ok") is True:
                return response.status_code
    except (httpx.HTTPError, ValueError):
        pass
    raise ValueError("Telegram не подтвердил доставку.")
