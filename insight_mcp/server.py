# MCP server: picks the collector for this OS, runs attribution, returns the CONTRACT.md envelope.
#
# Runs over stdio. Never print to stdout - it carries the MCP protocol. Log to stderr.

import dataclasses
import logging
import statistics
import sys
import time
from datetime import datetime, timedelta, timezone
from typing import Any, Callable

from mcp.server.fastmcp import FastMCP
from mcp.types import ToolAnnotations

from . import attribution
from .collectors.base import Collector, CollectorError, ErrorCode
from .schema import Cause, EventKind, Platform

log = logging.getLogger("insight_mcp")

MAX_HOURS = 720
CACHE_TTL_S = 60.0
TOP_N = 8                 # event-based causes sent to the AI; settings and battery wear are always sent
MIN_BLOCKER_S = 60.0      # blockers that held the laptop awake for less than this in total are noise
MIN_SLOW_SLEEP_S = 10.0   # same for drivers that slowed sleep entry

DEFAULT_REMEDIATION: dict[str, list[str]] = {
    ErrorCode.UNSUPPORTED_PLATFORM.value: ["insight_mcp supports macOS, Windows and Linux laptops."],
    ErrorCode.COMMAND_NOT_FOUND.value: ["A system tool this check needs is missing. Make sure you are on a standard OS install."],
    ErrorCode.PERMISSION_DENIED.value: ["This data source needs extra permissions. The other tools still work without it."],
    ErrorCode.TIMEOUT.value: ["Try a shorter window, e.g. hours=24."],
    ErrorCode.PARSE_ERROR.value: ["Your OS produced output this version doesn't recognise. Please open an issue with the (redacted) output."],
    ErrorCode.NO_BATTERY.value: ["This machine has no battery. Sleep and wake tools still work."],
    ErrorCode.NO_DATA.value: ["No power events were recorded in that window. Try a longer window."],
    "invalid_argument": ["Check the tool arguments."],
    "internal_error": ["Unexpected error. Please open an issue with the message above."],
}

_READ_ONLY = ToolAnnotations(readOnlyHint=True, destructiveHint=False, idempotentHint=True, openWorldHint=False)


# --------------------------------------------------------------------------- collector selection
def _platform() -> Platform | None:
    if sys.platform == "darwin":
        return Platform.MACOS
    if sys.platform.startswith("win"):
        return Platform.WINDOWS
    if sys.platform.startswith("linux"):
        return Platform.LINUX
    return None


def make_collector(platform: Platform | None = None) -> Collector:
    platform = platform or _platform()
    if platform is Platform.MACOS:
        from .collectors.macos import MacOSCollector as C
    elif platform is Platform.WINDOWS:
        from .collectors.windows import WindowsCollector as C
    elif platform is Platform.LINUX:
        from .collectors.linux import LinuxCollector as C
    else:
        raise CollectorError(ErrorCode.UNSUPPORTED_PLATFORM, f"unsupported platform: {sys.platform}")
    if not C.is_supported():
        raise CollectorError(ErrorCode.UNSUPPORTED_PLATFORM, f"{platform.value} collector is not supported on this host")
    return C()


# --------------------------------------------------------------------------- envelope
def _now() -> datetime:
    return datetime.now(timezone.utc)


def _iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


class Service:
    # Tool logic, separated from MCP registration so it can be tested with a fake collector.

    def __init__(self, collector_factory: Callable[[], Collector] = make_collector, clock: Callable[[], datetime] = _now):
        self._factory = collector_factory
        self._collector: Collector | None = None
        self._clock = clock
        self._events_cache: dict[int, tuple[float, list]] = {}

    def _c(self) -> Collector:
        if self._collector is None:
            self._collector = self._factory()
        self._collector.warnings.clear()
        return self._collector

    def _envelope(self, fn: Callable[[Collector], Any]) -> dict[str, Any]:
        platform = _platform()
        out: dict[str, Any] = {"platform": platform.value if platform else sys.platform, "generated_at": _iso(self._clock())}
        try:
            c = self._c()
            out["platform"] = c.platform.value
            data = fn(c)
            out.update(ok=True, data=data, warnings=list(c.warnings))
        except CollectorError as e:
            out.update(ok=False, error=_err(e.code.value, e.message, e.remediation))
        except ValueError as e:
            out.update(ok=False, error=_err("invalid_argument", str(e), []))
        except Exception as e:  # never crash the stdio session
            log.exception("tool failed")
            out.update(ok=False, error=_err("internal_error", f"{type(e).__name__}: {e}"[:300], []))
        return out

    def _window(self, hours: int) -> tuple[datetime, datetime]:
        if not isinstance(hours, int) or not 1 <= hours <= MAX_HOURS:
            raise ValueError(f"hours must be an integer between 1 and {MAX_HOURS}, got {hours!r}")
        until = self._clock()
        return until - timedelta(hours=hours), until

    def _events(self, c: Collector, hours: int):
        since, until = self._window(hours)
        hit = self._events_cache.get(hours)
        if hit and time.monotonic() - hit[0] < CACHE_TTL_S:
            return since, until, hit[1]
        events = [_clip(e, since, until) for e in c.collect_events(since, until)]
        self._events_cache[hours] = (time.monotonic(), events)
        return since, until, events

    @staticmethod
    def _soft(c: Collector, fn: Callable[[], Any], what: str):
        # Optional input for attribution: failure becomes a warning, not an error.
        try:
            return fn()
        except CollectorError as e:
            if e.code is not ErrorCode.NO_BATTERY:
                c.warnings.append(f"{what} unavailable: {e.message}")
            return None

    # ---------------------------------------------------------------- tools
    def battery_status(self) -> dict[str, Any]:
        return self._envelope(lambda c: c.battery_status().to_dict())

    def battery_health(self) -> dict[str, Any]:
        def run(c: Collector):
            h = c.battery_health()
            data = h.to_dict()
            data["attributions"] = [a.to_dict() for a in attribution.attribute([], health=h)]
            return data
        return self._envelope(run)

    def sleep_report(self, hours: int = 24) -> dict[str, Any]:
        def run(c: Collector):
            since, until, events = self._events(c, hours)
            settings = self._soft(c, c.power_settings, "Power settings") or []
            health = self._soft(c, c.battery_health, "health")
            sessions = attribution.build_sessions(events)
            attrs = attribution.attribute(events, settings=settings, health=health, observed_at=self._clock())
            # Lid opens and charger plugs are the user's own actions, not drain causes.
            attrs = [a for a in attrs if a.cause not in (Cause.USER_INPUT, Cause.CHARGER)]
            attrs, omitted = _shortlist(attrs)
            rates = [s.drain_pct_per_hour for s in sessions if s.drain_pct_per_hour is not None]
            totals = {
                "sleep_hours": round(sum((s.end - s.start).total_seconds() for s in sessions) / 3600, 2),
                "dark_wakes": sum(s.dark_wake_count for s in sessions),
                "avg_drain_pct_per_hour": round(statistics.median(rates), 2) if rates else None,
            }
            if not events:
                c.warnings.append("No power events found in this window.")
            return {
                "window": {"since": _iso(since), "until": _iso(until)},
                "sessions": [s.to_dict() for s in sessions],
                "totals": totals,
                "attributions": [a.to_dict() for a in attrs],
                "omitted": omitted,  # smaller causes left out to keep the reply short
            }
        return self._envelope(run)

    def wake_causes(self, hours: int = 168) -> dict[str, Any]:
        wake_kinds = {EventKind.WAKE, EventKind.DARK_WAKE, EventKind.POWER_SOURCE, EventKind.SLEEP}
        def run(c: Collector):
            since, until, events = self._events(c, hours)
            attrs, omitted = _shortlist(attribution.attribute([e for e in events if e.kind in wake_kinds]))
            return {"window": {"since": _iso(since), "until": _iso(until)},
                    "attributions": [a.to_dict() for a in attrs], "omitted": omitted}
        return self._envelope(run)

    def who_is_keeping_me_awake(self) -> dict[str, Any]:
        def run(c: Collector):
            now = self._clock()
            blockers = c.current_blockers()
            return {
                "blockers": [
                    # Linux (systemd-inhibit) can't say when a lock was taken: report unknown, not "0s".
                    {"actor": b.actor,
                     "held_for_s": None if b.extra.get("since_unknown") else round((now - b.ts).total_seconds()),
                     "since": None if b.extra.get("since_unknown") else _iso(b.ts),
                     "raw": b.raw}
                    for b in blockers
                ],
                "attributions": [a.to_dict() for a in attribution.attribute_blockers(blockers)],
            }
        return self._envelope(run)

    def power_settings(self) -> dict[str, Any]:
        def run(c: Collector):
            settings = c.power_settings()
            return {
                "settings": [s.to_dict() for s in settings],
                "attributions": [a.to_dict() for a in attribution.suggest_settings(settings, c.platform, observed_at=self._clock())],
            }
        return self._envelope(run)


def _shortlist(attrs: list) -> tuple[list, int]:
    # Keep the reply small: drop tiny blockers/delays, keep the top TOP_N event-based causes (already ranked),
    # and always keep settings and battery wear. Returns (kept, number omitted).
    always = (Cause.SETTING, Cause.BATTERY_WEAR)
    blockers = (Cause.APP_KEEPING_AWAKE, Cause.SYSTEM_KEEPING_AWAKE)
    def noise(a) -> bool:
        if a.cause in blockers:
            return (a.impact_s or 0.0) < MIN_BLOCKER_S
        if a.cause is Cause.SLOW_SLEEP_ENTRY:
            return (a.impact_s or 0.0) < MIN_SLOW_SLEEP_S
        return False
    ranked = [a for a in attrs if a.cause not in always and not noise(a)]
    kept = ranked[:TOP_N] + [a for a in attrs if a.cause in always]
    return kept, len(attrs) - len(kept)


def _clip(e, since: datetime, until: datetime):
    # Trim SLEEP_BLOCKER intervals to the window so a block that started before `since` isn't fully counted.
    if e.kind is not EventKind.SLEEP_BLOCKER:
        return e
    start = e.ts if e.ts >= since else since
    if e.duration_s is not None and e.end is None:
        end = e.ts + timedelta(seconds=e.duration_s)
    else:
        end = e.end or until
    end = min(end, until)
    if start == e.ts and end == e.end:
        return e
    return dataclasses.replace(e, ts=start, end=end, duration_s=max(0.0, (end - start).total_seconds()))


def _err(code: str, message: str, remediation: list[str]) -> dict[str, Any]:
    return {"code": code, "message": message, "remediation": remediation or DEFAULT_REMEDIATION.get(code, DEFAULT_REMEDIATION["internal_error"])}


# --------------------------------------------------------------------------- MCP wiring
def build_server(service: Service | None = None) -> FastMCP:
    svc = service or Service()
    mcp = FastMCP(
        "insight",
        instructions=(
            "Explains laptop battery drain and sleep problems from local OS power logs. "
            "All tools are read-only. Suggested fixes are commands for the user to run; never claim they were applied."
        ),
    )

    @mcp.tool(annotations=_READ_ONLY)
    def battery_status() -> dict:
        """Current battery level, charging state and time remaining. minutes_remaining is null when the OS has
        no estimate; estimate_kind says whether it is time to empty or to full; settling=true means the charger
        was just plugged/unplugged and values may be stale for ~1 minute."""
        return svc.battery_status()

    @mcp.tool(annotations=_READ_ONLY)
    def battery_health() -> dict:
        """Battery wear: design vs current capacity, health %, cycle count, temperature. Use when the user asks
        if their battery is worn out or why it doesn't last as long as it used to."""
        return svc.battery_health()

    @mcp.tool(annotations=_READ_ONLY)
    def sleep_report(hours: int = 24) -> dict:
        """Explain battery drain while the laptop slept: each sleep session with % lost per hour, how many times
        it woke in the background and why, plus ranked causes with evidence and suggested fixes. Use when the
        user asks why their battery died or drained overnight / while closed. hours: lookback window, 1-720."""
        return svc.sleep_report(hours)

    @mcp.tool(annotations=_READ_ONLY)
    def wake_causes(hours: int = 168) -> dict:
        """Rank what keeps waking the laptop from sleep (Wi-Fi, Bluetooth, scheduled maintenance, USB, lid...)
        with evidence. Use when the user asks why their laptop wakes up by itself. hours: 1-720, default 1 week."""
        return svc.wake_causes(hours)

    @mcp.tool(annotations=_READ_ONLY)
    def who_is_keeping_me_awake() -> dict:
        """Apps and system services preventing sleep right now. Use when the user asks why their laptop won't
        sleep, stays warm in a bag, or the screen/system never idles."""
        return svc.who_is_keeping_me_awake()

    @mcp.tool(annotations=_READ_ONLY)
    def power_settings() -> dict:
        """Current sleep/power settings with plain-English suggestions for ones that increase drain. Fix commands
        are for the user to run themselves (some need admin); this tool never changes settings."""
        return svc.power_settings()

    return mcp


def main() -> None:
    logging.basicConfig(stream=sys.stderr, level=logging.WARNING)
    build_server().run("stdio") # talk to claude through stdin and stdout


if __name__ == "__main__":
    main()
