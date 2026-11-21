import re


STRING = r'"""[\s\S]*?"""|"(?:\\.|[^"\\\n])*"'
LEXEME = re.compile(rf'{STRING}|//[^\n]*|/\*[\s\S]*?\*/')


def strip_comments(source: str) -> str:
    return LEXEME.sub(
        lambda match: re.sub(r"[^\n]", " ", match[0])
        if match[0].startswith(("//", "/*")) else match[0],
        source,
    )
