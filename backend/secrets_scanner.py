import re
from pathlib import Path

from pydantic import AliasChoices, BaseModel, Field
from typing import Literal

from backend.kotlin_text import strip_comments


class SecretFinding(BaseModel):
    category: Literal["SECRET"] = "SECRET"
    path: str
    kind: str = Field(validation_alias=AliasChoices("class", "kind"), serialization_alias="class")
    line: int = Field(ge=1)
    endLine: int | None = None
    severity: Literal["MEDIUM", "HIGH"]
    description: str
    remediation: str


DESCRIPTIONS = {
    "password": ("HIGH", "Пароль записан в исходном коде."),
    "api-key": ("MEDIUM", "Ключ API записан в исходном коде."),
    "configuration-token": ("HIGH", "Токен записан в файле конфигурации."),
    "secret-fallback": ("HIGH", "Встроенный токен используется при отсутствии переменной окружения."),
    "recoverable-token": ("HIGH", "Токен собирается из строковых литералов перед авторизацией."),
}

TEXT_TYPES = {".kt", ".kts", ".yml", ".yaml", ".properties", ".env"}
IGNORED_DIRS = {".git", ".gradle", "build", "node_modules"}
IDENT = r"[A-Za-z_][A-Za-z0-9_]*"
QUOTED = r'"([^"\\\r\n]+)"'
DECLARATION = re.compile(rf"\b(?:val|var)\s+({IDENT})(?:\s*:\s*String)?\s*=\s*(.+)")
FALLBACK = re.compile(rf'System\s*\.\s*getenv\s*\(\s*"[A-Za-z_][A-Za-z0-9_]*"\s*\)\s*\?:\s*{QUOTED}')
CONCATENATION = re.compile(rf"({IDENT})\s*\+\s*({IDENT})")
BEARER_SINK = re.compile(rf'\bsetBearerAuth\(\s*({IDENT})\s*\)|"Bearer\s+\$(?:\{{({IDENT})\}}|({IDENT}))"')
API_SINK = re.compile(rf'\.header\(\s*"X-Api-Key"\s*,\s*{QUOTED}\s*\)', re.I)
CONFIG = re.compile(r'''^\s*["']?([\w.-]+)["']?\s*[:=]\s*(.+?)\s*$''')


def plausible(value: str) -> bool:
    value = value.strip()
    normalized = re.sub(r"[-_\s]+", "-", value.lower())
    return (
        len(value) >= 6
        and not any(marker in value for marker in ("$", "<", ">", "*", "{{"))
        and not normalized.startswith(("example", "placeholder", "changeme", "replace-me", "your-", "dummy"))
    )


def kotlin_locations(lines: list[str]):
    literals: dict[str, int] = {}
    fallbacks: dict[str, int] = {}
    concatenations: dict[str, int] = {}
    for line, source in enumerate(lines, 1):
        source = source.strip()
        if source.startswith(("//", "/*", "*")):
            continue
        if source == "}":
            literals.clear()
            fallbacks.clear()
            concatenations.clear()
        declaration = DECLARATION.search(source)
        if declaration:
            name, expression = declaration.groups()
            for bindings in (literals, fallbacks, concatenations):
                bindings.pop(name, None)
            literal = re.fullmatch(QUOTED, expression)
            fallback = FALLBACK.fullmatch(expression)
            concat = CONCATENATION.fullmatch(expression)
            if literal and plausible(literal[1]):
                literals[name] = line
                if re.search(r"password$", name, re.I):
                    yield "password", line, None
                elif re.search(r"api_?key$", name, re.I):
                    yield "api-key", line, None
            elif fallback and plausible(fallback[1]):
                fallbacks[name] = line
            elif concat and concat[1] != concat[2] and concat[1] in literals and concat[2] in literals:
                concatenations[name] = min(literals[concat[1]], literals[concat[2]])
        for match in API_SINK.finditer(source):
            if plausible(match[1]):
                yield "api-key", line, None
        for sink in BEARER_SINK.finditer(source):
            name = sink[1] or sink[2] or sink[3]
            if name in fallbacks and line - fallbacks[name] <= 14:
                yield "secret-fallback", fallbacks[name], None
            if name in concatenations and line - concatenations[name] <= 14:
                yield "recoverable-token", concatenations[name], line


def config_locations(lines: list[str]):
    for line, source in enumerate(lines, 1):
        match = CONFIG.match(source)
        if not match:
            continue
        key, value = match.groups()
        key = key.lower().replace("-", "").replace("_", "").rsplit(".", 1)[-1]
        value = re.split(r"\s+#", value, maxsplit=1)[0].strip().strip("'\"")
        bearer = re.fullmatch(r"Bearer\s+(.+)", value, re.I)
        if key == "authorization" and bearer and plausible(bearer[1]):
            yield "configuration-token", line, None
        elif key in {"token", "password", "apikey"} and plausible(value):
            kind = {"password": "password", "apikey": "api-key"}.get(key, "configuration-token")
            yield kind, line, None


class SecretsScanner:
    def scan(self, root: Path) -> list[SecretFinding]:
        findings = []
        for folder, dirs, names in root.walk(follow_symlinks=False):
            dirs[:] = sorted(
                name for name in dirs
                if name not in IGNORED_DIRS and not (folder / name).is_junction()
            )
            for name in sorted(names):
                file = folder / name
                if file.is_symlink() or (file.suffix not in TEXT_TYPES and file.name != ".env"):
                    continue
                source = file.read_text(encoding="utf-8-sig")
                kotlin = file.suffix in {".kt", ".kts"}
                lines = (strip_comments(source) if kotlin else source).splitlines()
                analyze = kotlin_locations if kotlin else config_locations
                for kind, line, end in dict.fromkeys(analyze(lines)):
                    severity, description = DESCRIPTIONS[kind]
                    findings.append(SecretFinding(
                        path=file.relative_to(root).as_posix(), kind=kind, line=line, endLine=end,
                        severity=severity, description=f"{description} Значение: ••••••••",
                        remediation="Вынесите секрет в защищённую конфигурацию и замените его.",
                    ))
        return sorted(findings, key=lambda item: (item.path, item.line, item.kind))
