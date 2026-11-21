import re
from pathlib import Path
from typing import Literal

from pydantic import AliasChoices, BaseModel, Field

from backend.kotlin_text import STRING, strip_comments


class SastFinding(BaseModel):
    category: Literal["SAST"] = "SAST"
    path: str
    kind: str = Field(validation_alias=AliasChoices("class", "kind"), serialization_alias="class")
    line: int = Field(ge=1)
    endLine: int | None = None
    severity: Literal["MEDIUM", "HIGH"]
    description: str
    remediation: str


RULES = {
    "sql-injection": (
        "HIGH", "HTTP-параметр подставляется непосредственно в текст SQL.",
        "Используйте параметризованный запрос и передавайте значение отдельно.",
    ),
    "tls-verification": (
        "MEDIUM", "HTTPS-клиент принимает любое имя хоста.",
        "Удалите разрешающий проверяющий и используйте стандартную проверку имени хоста.",
    ),
    "credentialed-cors": (
        "MEDIUM", "Одна конфигурация CORS разрешает произвольные источники и передачу учётных данных.",
        "Задайте точный список доверенных источников для запросов с учётными данными.",
    ),
    "route-authorization": (
        "HIGH", "Публичное правило для маршрута с клиентскими данными срабатывает раньше защищённого правила.",
        "Защитите маршрут требуемой ролью до разрешающих правил.",
    ),
    "object-authorization": (
        "HIGH", "Объект выбирается по идентификатору из запроса без ограничения по владельцу.",
        "Получите владельца из доверенного контекста и ограничьте выборку объектами этого владельца.",
    ),
}

IDENT = r"[A-Za-z_]\w*"
FUNCTION = re.compile(rf"\bfun\s+({IDENT})\s*\(((?:[^()]|\([^()]*\))*)\)")
HTTP_INPUT = re.compile(
    rf"@(?:RequestParam|PathVariable)(?:\s*\([^)]*\))?\s+({IDENT})\s*:"
)
JDBC_TYPE = re.compile(rf"\b({IDENT})\s*:\s*JdbcTemplate\b")
JDBC_QUERY = re.compile(rf"\b({IDENT})\s*\.\s*query(?:ForList|ForObject)?\s*\(\s*({STRING})")
INTERPOLATION = re.compile(rf"(?<!\\)\$(?:\{{({IDENT})\}}|({IDENT}))")
TLS_OVERRIDE = re.compile(
    r"\bhostnameVerifier\s*=\s*HostnameVerifier\s*\{\s*\w+\s*,\s*\w+\s*->\s*true\s*}"
)
CORS_BLOCK = re.compile(r"\bCorsConfiguration\s*\(\s*\)\s*\.apply\s*\{([^{}]*)}")
WILDCARD_LIST = re.compile(r'\b(?:allowedOrigins|allowedOriginPatterns)\s*=\s*listOf\s*\(\s*"\*"\s*\)')
ALLOW_CREDENTIALS = re.compile(r"\ballowCredentials\s*=\s*true\b")
CONTROLLER = re.compile(r"@RestController\b")
REPOSITORY = re.compile(rf"@Repository\s+(?:(?:internal|open|public)\s+)?class\s+({IDENT})")
MAPPING = re.compile(r'@(Get|Post|Put|Patch|Delete)Mapping\s*\(\s*"([^"]+)"\s*\)')
PREFIX = re.compile(r'@RequestMapping\s*\(\s*"([^"]+)"\s*\)')
MATCHER = re.compile(
    r'\brequestMatchers\s*\(\s*(?:(?:HttpMethod\.)?(GET|POST|PUT|PATCH|DELETE)\s*,\s*)?'
    r'"([^"]+)"\s*\)\s*\.\s*(permitAll|hasRole|hasAuthority|authenticated)\s*\('
)
OWNER_COLUMN = r"(?:customer|owner|user|account|tenant)_id"
PRIVATE_SELECT = re.compile(rf"\bSELECT\b[^;]*?\b(?:{OWNER_COLUMN}|work_note|counter_note)\b[^;]*?\bFROM\b", re.I)
ID_ONLY = re.compile(r"\bWHERE\s+(?:\w+\.)?[a-z_]\w*_id\s*=\s*\?\s*$", re.I)
OWNER_PREDICATE = re.compile(rf"\b{OWNER_COLUMN}\b", re.I)


def functions(source: str):
    declarations = list(FUNCTION.finditer(source))
    for index, declaration in enumerate(declarations):
        end = declarations[index + 1].start() if index + 1 < len(declarations) else len(source)
        yield declaration, source[declaration.end():end]


def route_prefix(source: str) -> str:
    match = PREFIX.search(source)
    return match[1].rstrip("/") if match else ""


def sql_and_access_locations(sources):
    public_routes = set()
    repository_calls = set()
    for path, source in sources:
        if not CONTROLLER.search(source):
            continue
        receivers = set(JDBC_TYPE.findall(source))
        for declaration, body in functions(source):
            parameters = set(HTTP_INPUT.findall(declaration[2]))
            for query in JDBC_QUERY.finditer(body):
                interpolated = {left or right for left, right in INTERPOLATION.findall(query[2])}
                if query[1] in receivers and parameters & interpolated:
                    yield path, source, "sql-injection", declaration.start(), declaration.end() + query.start(2)
            annotation = source[:declaration.start()].rstrip().splitlines()
            mapping = MAPPING.fullmatch(annotation[-1].strip()) if annotation else None
            if mapping and any(q[1] in receivers and PRIVATE_SELECT.search(q[2]) for q in JDBC_QUERY.finditer(body)):
                public_routes.add((mapping[1].upper(), route_prefix(source) + "/" + mapping[2].lstrip("/")))
            for parameter in parameters:
                calls = re.findall(rf"\b({IDENT})\.({IDENT})\(\s*{re.escape(parameter)}\s*\)", body)
                for receiver, method in calls:
                    target = re.search(rf"\b{re.escape(receiver)}\s*:\s*({IDENT})", source)
                    if target:
                        repository_calls.add((target[1], method))

    for path, source in sources:
        repository = REPOSITORY.search(source)
        if repository:
            jdbc_receivers = set(JDBC_TYPE.findall(source))
            for declaration, body in functions(source):
                if (repository[1], declaration[1]) not in repository_calls:
                    continue
                for query in JDBC_QUERY.finditer(body):
                    sql = query[2].strip('" \n')
                    where = re.search(r"\bWHERE\b.*", sql, re.I | re.S)
                    if (query[1] in jdbc_receivers and where and PRIVATE_SELECT.search(sql)
                            and ID_ONLY.fullmatch(where[0]) and not OWNER_PREDICATE.search(where[0])):
                        yield path, source, "object-authorization", declaration.start(), declaration.end() + query.start(2)
        if not re.search(r"\bHttpSecurity\b", source):
            continue
        matchers = list(MATCHER.finditer(source))
        for index, rule in enumerate(matchers):
            method, route, policy = rule.groups()
            if policy != "permitAll" or not any(
                endpoint == route and (method is None or method == verb)
                for verb, endpoint in public_routes
            ):
                continue
            if any(
                later[3] != "permitAll" and later[2].endswith("/**")
                and route.startswith(later[2][:-2]) and (later[1] is None or later[1] == method)
                for later in matchers[index + 1:]
            ):
                yield path, source, "route-authorization", rule.start(), rule.start()


def configuration_locations(path, source):
    if re.search(r"\bHttpsURLConnection\b", source):
        for match in TLS_OVERRIDE.finditer(source):
            yield path, source, "tls-verification", match.start(), match.end() - 1
    for match in CORS_BLOCK.finditer(source):
        wildcard = WILDCARD_LIST.search(match[1])
        credentials = ALLOW_CREDENTIALS.search(match[1])
        if wildcard and credentials:
            yield (
                path, source, "credentialed-cors",
                match.start(1) + min(wildcard.start(), credentials.start()),
                match.start(1) + max(wildcard.end(), credentials.end()) - 1,
            )


class KotlinSastScanner:
    def scan(self, root: Path) -> list[SastFinding]:
        sources = []
        for folder, directories, names in root.walk(follow_symlinks=False):
            directories[:] = [name for name in directories if name not in {".git", ".gradle", "build"}
                              and not (folder / name).is_junction()]
            for name in names:
                file = folder / name
                if file.suffix == ".kt" and not file.is_symlink():
                    sources.append((file.relative_to(root).as_posix(), strip_comments(file.read_text(encoding="utf-8-sig"))))

        locations = list(sql_and_access_locations(sources))
        for path, source in sources:
            locations.extend(configuration_locations(path, source))
        findings = {}
        for path, source, kind, start, end in locations:
            line = source.count("\n", 0, start) + 1
            last = min(source.count("\n", 0, end) + 1, line + 14)
            severity, description, remediation = RULES[kind]
            findings[path, line, kind] = SastFinding(
                path=path, kind=kind, line=line, endLine=last if last > line else None,
                severity=severity, description=description, remediation=remediation,
            )
        return [findings[key] for key in sorted(findings)]
