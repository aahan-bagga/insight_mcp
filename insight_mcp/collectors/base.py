# The template every OS collector follows (macos.py, windows.py, linux.py).
#
# A collector runs the OS's power tools (e.g. pmset on Mac) and turns their text output
# into PowerEvents etc. It only reports what happened; attribution.py decides the causes.
#
# This file has:
# - Collector: the list of methods each OS must write (collect_events, battery_status, ...)
# - subprocess_runner: runs an OS command with fixed arguments (no shell, so nothing can be injected) and gives up after a time limit
# - file_reader: reads a file like /sys/class/power_supply/...
# - CollectorError: the friendly error a collector raises (e.g. "needs admin, here's how")
# - system_zone: finds your timezone so log times convert to UTC correctly
#
# Commands and files are read through `runner` / `reader`, so tests can swap in saved
# output (fixtures) instead of running real commands.

import os
import subprocess
from abc import ABC, abstractmethod
from datetime import datetime, tzinfo
from enum import Enum
from pathlib import Path
from typing import Callable, Sequence

from ..schema import BatteryHealth, BatteryStatus, Platform, PowerEvent, PowerSetting

DEFAULT_TIMEOUT_S = 20.0


class ErrorCode(str, Enum):
    UNSUPPORTED_PLATFORM = "unsupported_platform"
    COMMAND_NOT_FOUND = "command_not_found"
    PERMISSION_DENIED = "permission_denied"     # source needs admin/group membership; core path must not
    TIMEOUT = "timeout"
    PARSE_ERROR = "parse_error"                 # output did not match any known format
    NO_BATTERY = "no_battery"                   # desktop machine; battery tools only
    NO_DATA = "no_data"                         # source works but has nothing in the window


class CollectorError(Exception):
    # The only exception a collector may raise. server.py turns it into a structured error.

    def __init__(self, code: ErrorCode, message: str, remediation: Sequence[str] = ()):
        super().__init__(message)
        self.code = code
        self.message = message
        self.remediation = list(remediation)   # user-facing steps, plain English


# runner(argv, timeout_s) -> stdout text. Must raise CollectorError (not CalledProcessError etc.).
Runner = Callable[[Sequence[str], float], str]
# reader(path) -> file text. Must raise CollectorError on missing/unreadable file.
Reader = Callable[[str], str]


def subprocess_runner(argv: Sequence[str], timeout_s: float = DEFAULT_TIMEOUT_S) -> str:
    # Default runner: fixed argv, never shell=True, no stdin, decoded as UTF-8 with replacement.
    try:
        proc = subprocess.run(
            list(argv), capture_output=True, timeout=timeout_s, stdin=subprocess.DEVNULL, check=False
        )
    except FileNotFoundError as e:
        raise CollectorError(ErrorCode.COMMAND_NOT_FOUND, f"{argv[0]} not found", [f"Install or enable `{argv[0]}`."]) from e
    except subprocess.TimeoutExpired as e:
        raise CollectorError(ErrorCode.TIMEOUT, f"{argv[0]} timed out after {timeout_s}s", ["Try a shorter time window."]) from e
    out = proc.stdout.decode("utf-8", errors="replace")
    if proc.returncode != 0:
        # Some tools (e.g. powercfg) print errors to stdout, so check both streams.
        err = (proc.stderr.decode("utf-8", errors="replace").strip() or out.strip())
        low = err.lower()
        if any(s in low for s in ("access is denied", "permission denied", "not permitted", "administrator", "privilege")):
            raise CollectorError(ErrorCode.PERMISSION_DENIED, f"{argv[0]}: {err[:200]}")
        raise CollectorError(ErrorCode.PARSE_ERROR, f"{argv[0]} exited {proc.returncode}: {err[:200]}")
    return out


def system_zone() -> tzinfo:
    # The host's IANA zone (DST-aware). Order: $TZ, /etc/localtime symlink, fixed current offset.
    from zoneinfo import ZoneInfo

    name = os.environ.get("TZ", "").lstrip(":")
    if not name:
        try:
            target = os.path.realpath("/etc/localtime")
            if "zoneinfo/" in target:
                name = target.split("zoneinfo/", 1)[1]
        except OSError:
            name = ""
    if name:
        try:
            return ZoneInfo(name)
        except Exception:
            pass
    return datetime.now().astimezone().tzinfo  # last resort: a fixed offset, which gets times wrong by 1h across daylight-saving changes


def file_reader(path: str) -> str:
    try:
        return Path(path).read_text(encoding="utf-8", errors="replace")
    except FileNotFoundError as e:
        raise CollectorError(ErrorCode.NO_DATA, f"{path} not found") from e
    except PermissionError as e:
        raise CollectorError(ErrorCode.PERMISSION_DENIED, f"cannot read {path}") from e


class Collector(ABC):
    platform: Platform

    def __init__(
        self,
        runner: Runner = subprocess_runner,
        reader: Reader = file_reader,
        local_tz: tzinfo | None = None,
        now: Callable[[], datetime] | None = None,
    ) -> None:
        self.runner = runner
        self.reader = reader
        # Zone used to localize naive OS timestamps. Tests pass ZoneInfo("America/Los_Angeles") etc.
        self.local_tz = local_tz or system_zone()
        # Clock (UTC) for live readings like BatteryStatus.sampled_at; injectable for tests.
        from datetime import timezone as _tz
        self.now = now or (lambda: datetime.now(_tz.utc))

    @classmethod
    @abstractmethod
    def is_supported(cls) -> bool:
        # True if this collector can run on the current host (cheap check, no subprocess).
        ...

    @abstractmethod
    def collect_events(self, since: datetime, until: datetime) -> list[PowerEvent]:
        # Historical events with since <= ts < until (both UTC), sorted ascending by ts.
        # Filter by window AS EARLY AS POSSIBLE: ask the OS for the window when it supports it,
        # otherwise skip out-of-window records using a cheap timestamp check BEFORE full parsing.
        # SLEEP_BLOCKER intervals are included if they overlap the window.
        # Raises CollectorError only if NO event source worked; partial failures go in `self.warnings`.
        ...

    @abstractmethod
    def current_blockers(self) -> list[PowerEvent]:
        # SLEEP_BLOCKER events held right now (end=None).
        ...

    @abstractmethod
    def battery_status(self) -> BatteryStatus:
        # Live battery state. Desktop machines return has_battery=False (do not raise).
        ...

    @abstractmethod
    def battery_health(self) -> BatteryHealth:
        # Raises CollectorError(NO_BATTERY) on machines without a battery.
        ...

    @abstractmethod
    def power_settings(self) -> list[PowerSetting]:
        # Current sleep/power settings relevant to drain. Read-only.
        ...

    # Non-fatal problems (e.g. one optional source needed admin) are appended here as
    # plain-English strings; server.py surfaces them as `warnings`.
    @property
    def warnings(self) -> list[str]:
        if not hasattr(self, "_warnings"):
            self._warnings: list[str] = []
        return self._warnings
