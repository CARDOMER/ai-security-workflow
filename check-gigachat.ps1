param([switch]$Serve)

$ErrorActionPreference = 'Stop'
Set-Location -LiteralPath $PSScriptRoot

$env:AI_SUMMARY_PROVIDER = 'gigachat'
$env:AI_SUMMARY_MODEL = 'GigaChat-2-Max'
$env:GIGACHAT_CA_FILE = (Read-Host 'PEM certificate path (Enter to use Windows trust)').Trim('"')
$env:GIGACHAT_CREDENTIALS = (Read-Host 'GigaChat Authorization Key (visible input)').Trim()

try {
    if ($Serve) {
        $env:WORKFLOW_WEBHOOK_URL = 'http://127.0.0.1:8001/api/workflow/demo-webhook'
        & .\.venv\Scripts\python.exe -m uvicorn backend.main:app --host 127.0.0.1 --port 8001
        if ($LASTEXITCODE -ne 0) { throw 'GigaChat backend failed.' }
        return
    }

    $check = @'
import json
from pathlib import Path

from fastapi.testclient import TestClient

from backend.main import app

with TestClient(app) as client:
    scan = client.post("/api/scan")
    scan.raise_for_status()
    report = scan.json()
    response = client.post(
        "/api/report/summary",
        json=report,
        headers={"X-Report-Signature": scan.headers["X-Report-Signature"]},
    )
    response.raise_for_status()
    summary = response.json()

result = {
    "findings": len(report["findings"]),
    "mode": summary["mode"],
    "reason": summary.get("fallbackReason"),
}
output = json.dumps(result, ensure_ascii=True)
Path(".gigachat-check-result.json").write_text(output, encoding="utf-8")
print(output)
'@
    $check | & .\.venv\Scripts\python.exe -
    if ($LASTEXITCODE -ne 0) { throw 'GigaChat check failed.' }
}
finally {
    Remove-Item Env:GIGACHAT_CREDENTIALS -ErrorAction SilentlyContinue
}
