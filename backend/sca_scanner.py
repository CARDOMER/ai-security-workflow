import json
import re
import tomllib
from collections import defaultdict
from pathlib import Path
from typing import Literal, TypedDict

from pydantic import BaseModel


class ScaFinding(BaseModel):
    category: Literal["SCA"] = "SCA"
    path: str
    group: str
    artifact: str
    version: str
    advisoryId: str
    severity: Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"]
    description: str


class VersionRange(TypedDict):
    lower: str | None
    lowerInclusive: bool
    upper: str
    upperInclusive: bool


NUMERIC = re.compile(r"[0-9]+(?:\.[0-9]+)*")
COORDINATE = re.compile(r"[A-Za-z0-9_.-]+")
VARIABLE = re.compile(r"\$(?:\{([A-Za-z_]\w*)\}|([A-Za-z_]\w*))")
LEXEME = re.compile(r'"""[\s\S]*?"""|"(?:\\.|[^"\\\n])*"|//[^\n]*|/\*[\s\S]*?\*/|[A-Za-z_]\w*|\S')
VALUE = r'"[^"\\\n]*"'
DECLARATION = re.compile(
    rf'\b(?:val|var)\s+(\w+)(?:\s*:\s*String)?\s*=\s*'
    rf'(?:"([^"\\\n]*)"|providers\.gradleProperty\("([^"\\\n]+)"\)\.(?:get\(\)|orNull))\s*$'
)
DEPENDENCY_CALL = (
    rf'(?:add\s+\(\s+{VALUE}\s+,|(?:api|implementation|compileOnly|runtimeOnly|'
    rf'annotationProcessor|[A-Za-z_]\w*(?:Implementation|CompileOnly|RuntimeOnly|AnnotationProcessor))\s+\()'
)
DEPENDENCY = re.compile(DEPENDENCY_CALL + r'\s+"([^"\\\n]+)"\s*,?\s*\)')
CATALOG_DEPENDENCY = re.compile(DEPENDENCY_CALL + r'\s+libs\s+\.\s+([\w]+(?:\s+\.\s+[\w]+)*)\s*,?\s*\)')


def numeric_version(value: str) -> tuple[int, ...]:
    parts = value.split(".")
    while len(parts) > 1 and int(parts[-1]) == 0:
        parts.pop()
    return tuple(map(int, parts))


def in_range(version: str, interval: VersionRange) -> bool:
    if not NUMERIC.fullmatch(version):
        return False
    value = numeric_version(version)
    if interval["lower"] is not None:
        lower = numeric_version(interval["lower"])
        if value < lower or (value == lower and not interval["lowerInclusive"]):
            return False
    upper = numeric_version(interval["upper"])
    return value < upper or (value == upper and interval["upperInclusive"])


def read_optional(path: Path) -> str:
    return path.read_text(encoding="utf-8-sig") if path.is_file() else ""


def variables(source: str, properties_text: str) -> dict[str, str]:
    properties = dict(re.findall(
        r"^[ \t]*([A-Za-z_][\w.-]*)[ \t]*[=:][ \t]*([^\r\n]*)$",
        properties_text, re.M,
    ))
    bindings = {}
    depth = 0
    for token in LEXEME.finditer(source):
        if token[0] == "{":
            depth += 1
        elif token[0] == "}":
            depth -= 1
        elif depth == 0 and token[0] in {"val", "var"}:
            start = source.rfind("\n", 0, token.start()) + 1
            end = source.find("\n", token.end())
            line = source[start:end] if end != -1 else source[start:]
            if match := DECLARATION.fullmatch(line.strip()):
                name, literal, key = match.groups()
                bindings[name] = literal if literal is not None else properties.get(key, "").strip()
    return bindings


def dependency_blocks(source: str):
    tokens = [
        match for match in LEXEME.finditer(source)
        if not match[0].startswith(("//", "/*"))
    ]
    depth = 0
    start = None
    body = []
    for index, match in enumerate(tokens):
        token = match[0]
        if token == "{":
            if depth == 0 and index and tokens[index - 1][0] == "dependencies":
                start = match.end()
            elif start is not None and depth == 1:
                body.append("{")
            depth += 1
        elif token == "}":
            if start is not None and depth == 1:
                yield " ".join(body), source[start:match.start()]
                body.clear()
                start = None
            depth -= 1
        elif start is not None and depth == 1:
            body.append(token)


def catalog_libraries(source: str) -> dict[str, tuple[str, str, str]]:
    catalog = tomllib.loads(source)
    libraries = catalog.get("libraries", {})
    versions = catalog.get("versions", {})
    if not isinstance(libraries, dict) or not isinstance(versions, dict):
        return {}

    aliases = {}
    for alias, item in libraries.items():
        if isinstance(item, str):
            fields = item.split(":")
            if len(fields) != 3:
                continue
            group, artifact, version = fields
        elif isinstance(item, dict):
            module = item.get("module")
            if isinstance(module, str):
                coordinates = module.split(":")
                if len(coordinates) != 2:
                    continue
                group, artifact = coordinates
            else:
                group, artifact = item.get("group"), item.get("name")
            version = item.get("version", "")
            if isinstance(version, dict):
                ref = version.get("ref")
                version = versions.get(ref, "") if isinstance(ref, str) else ""
        else:
            continue
        if all(isinstance(part, str) and COORDINATE.fullmatch(part) for part in (group, artifact)):
            aliases[re.sub(r"[-_.]", ".", alias)] = group, artifact, version if isinstance(version, str) else ""
    return aliases


def declared_versions(build: str, properties: str, locks: str, catalog: str = "") -> set[tuple[str, str, str]]:
    # Replace comments with whitespace while keeping quoted URLs and interpolation intact.
    source = LEXEME.sub(
        lambda match: " " + "\n" * match[0].count("\n")
        if match[0].startswith(("//", "/*")) else match[0],
        build,
    )
    top_level = variables(source, properties)
    locked: dict[tuple[str, str], set[str]] = defaultdict(set)
    for line in locks.splitlines():
        coordinate, separator, _ = line.partition("=")
        fields = coordinate.strip().split(":")
        if separator and len(fields) == 3 and not coordinate.lstrip().startswith("#"):
            group, artifact, version = fields
            locked[group, artifact].add(version)

    declared = set()
    aliases = catalog_libraries(catalog)
    for body, local_source in dependency_blocks(source):
        bindings = top_level | variables(local_source, properties)
        coordinates = []
        for match in DEPENDENCY.finditer(body):
            fields = match[1].split(":")
            if len(fields) in (2, 3):
                coordinates.append((fields[0], fields[1], fields[2] if len(fields) == 3 else ""))
        for match in CATALOG_DEPENDENCY.finditer(body):
            alias = re.sub(r"\s+", "", match[1])
            if alias in aliases:
                coordinates.append(aliases[alias])
        for group, artifact, expression in coordinates:
            if not all(COORDINATE.fullmatch(part) for part in (group, artifact)):
                continue
            versions = locked.get((group, artifact))
            if versions is None:
                refs = VARIABLE.finditer(expression)
                if any(not bindings.get(ref[1] or ref[2]) for ref in refs):
                    continue
                versions = {VARIABLE.sub(lambda ref: bindings[ref[1] or ref[2]], expression)}
            declared.update((group, artifact, item) for item in versions if NUMERIC.fullmatch(item))
    return declared


class MavenScaScanner:
    def __init__(self, database: Path):
        self.database = database

    def scan(self, root: Path) -> list[ScaFinding]:
        build = root / "build.gradle.kts"
        if not build.is_file():
            return []
        dependencies = declared_versions(
            build.read_text(encoding="utf-8-sig"),
            read_optional(root / "gradle.properties"),
            read_optional(root / "gradle.lockfile"),
            read_optional(root / "gradle" / "libs.versions.toml"),
        )
        database = json.loads(self.database.read_text(encoding="utf-8-sig"))
        advisories = defaultdict(list)
        for entry in database["vulnerabilities"]:
            advisories[entry["group"], entry["artifact"]].append(entry)

        findings = []
        seen = set()
        for group, artifact, version in sorted(dependencies):
            for entry in advisories[group, artifact]:
                identity = (group, artifact, version, entry["id"])
                if identity in seen or not any(in_range(version, item) for item in entry["ranges"]):
                    continue
                seen.add(identity)
                findings.append(ScaFinding(
                    path=build.relative_to(root).as_posix(),
                    group=group,
                    artifact=artifact,
                    version=version,
                    advisoryId=entry["id"],
                    severity=entry["severity"],
                    description="Версия зависимости входит в уязвимый диапазон из справочника Maven.",
                ))
        return findings
