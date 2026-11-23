# Shared test helpers. Collector tests replay fixtures through the real code path.

from datetime import datetime, timezone
from pathlib import Path
from typing import Mapping, Sequence

import pytest

from insight_mcp.collectors.base import CollectorError, ErrorCode

FIXTURES = Path(__file__).parent / "fixtures"


def load_fixture(os_name: str, name: str) -> str:
    return (FIXTURES / os_name / name).read_text(encoding="utf-8")


class FakeRunner:
    # Maps an argv prefix (tuple) -> fixture text or a CollectorError to raise.
    # Longest matching prefix wins. Records every call in `.calls`.

    def __init__(self, responses: Mapping[tuple[str, ...], "str | CollectorError"]):
        self.responses = dict(responses)
        self.calls: list[tuple[str, ...]] = []

    def __call__(self, argv: Sequence[str], timeout_s: float = 20.0) -> str:
        argv = tuple(argv)
        self.calls.append(argv)
        best = None
        for prefix in self.responses:
            if argv[: len(prefix)] == prefix and (best is None or len(prefix) > len(best)):
                best = prefix
        if best is None:
            raise CollectorError(ErrorCode.COMMAND_NOT_FOUND, f"no fixture for {argv}")
        resp = self.responses[best]
        if isinstance(resp, CollectorError):
            raise resp
        return resp


class FakeReader:
    # Maps a file path -> text or CollectorError.

    def __init__(self, files: Mapping[str, "str | CollectorError"]):
        self.files = dict(files)
        self.reads: list[str] = []

    def __call__(self, path: str) -> str:
        self.reads.append(path)
        if path not in self.files:
            raise CollectorError(ErrorCode.NO_DATA, f"{path} not found")
        v = self.files[path]
        if isinstance(v, CollectorError):
            raise v
        return v


def utc(*args: int) -> datetime:
    return datetime(*args, tzinfo=timezone.utc)


@pytest.fixture
def fixed_now():
    return lambda: utc(2026, 11, 16, 12, 0, 0)
