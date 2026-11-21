"""Bounded, static import of an authorized training project."""

from contextlib import contextmanager
from io import BytesIO
from pathlib import Path, PurePosixPath
from stat import S_IFDIR, S_IFMT, S_IFREG
from tempfile import TemporaryDirectory
from zipfile import BadZipFile, ZipFile


MAX_UPLOAD = 8 * 1024 * 1024
MAX_EXPANDED = 32 * 1024 * 1024
MAX_ENTRIES = 800
DEVICE = {"CON", "PRN", "AUX", "NUL", *(f"COM{i}" for i in range(1, 10)), *(f"LPT{i}" for i in range(1, 10))}


@contextmanager
def training_zip(data: bytes):
    if not data or len(data) > MAX_UPLOAD:
        raise ValueError("Допустим ZIP размером до 8 МБ.")
    with TemporaryDirectory(prefix="security-workflow-") as directory:
        root = Path(directory)
        try:
            with ZipFile(BytesIO(data)) as archive:
                entries = archive.infolist()
                if len(entries) > MAX_ENTRIES or sum(entry.file_size for entry in entries) > MAX_EXPANDED:
                    raise ValueError("Архив превышает лимит распаковки.")
                seen = set()
                expanded = 0
                for entry in entries:
                    name = entry.orig_filename.rstrip("/")
                    parts = name.split("/")
                    mode = S_IFMT(entry.external_attr >> 16)
                    if (
                        not name or "\\" in name or "\0" in name or mode not in {0, S_IFREG, S_IFDIR}
                        or any(not part or part in {".", ".."} or part[-1] in ". "
                               or any(c in part for c in ':*?"<>|') or any(ord(c) < 32 for c in part)
                               or part.split(".")[0].upper() in DEVICE for part in parts)
                    ):
                        raise ValueError("Архив содержит недопустимый путь или тип файла.")
                    relative = PurePosixPath(*parts)
                    key = relative.as_posix().casefold()
                    if key in seen:
                        raise ValueError("Архив содержит повторяющийся путь.")
                    seen.add(key)
                    destination = root.joinpath(*parts)
                    if entry.is_dir():
                        destination.mkdir(parents=True, exist_ok=True)
                        continue
                    destination.parent.mkdir(parents=True, exist_ok=True)
                    with archive.open(entry) as source, destination.open("xb") as target:
                        while chunk := source.read(65536):
                            expanded += len(chunk)
                            if expanded > MAX_EXPANDED:
                                raise ValueError("Архив превышает лимит распаковки.")
                            target.write(chunk)
        except (BadZipFile, NotImplementedError, RuntimeError, OSError):
            raise ValueError("Не удалось распаковать ZIP учебного проекта.") from None
        children = list(root.iterdir())
        project = children[0] if len(children) == 1 and children[0].is_dir() else root
        if not (project / "build.gradle.kts").is_file():
            raise ValueError("В корне учебного проекта нужен build.gradle.kts.")
        yield project
