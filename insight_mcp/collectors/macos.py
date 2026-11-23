# macOS collector: `pmset`, `ioreg` and `system_profiler` output -> schema objects.
#
# Facts only. Reason text from the OS is copied verbatim into `raw_reason`; mapping it to a
# `Cause` is attribution.py's job.
#
# Sources (all read-only, no admin needed):
# - `pmset -g log`         sleep / wake / dark wake / sleep-notification delays / assertions
# - `pmset -g assertions`  live sleep blockers
# - `pmset -g batt`        live battery state
# - `pmset -g custom`      per-power-source settings
# - `ioreg -rn AppleSmartBattery`   capacity, cycles, temperature
# - `system_profiler SPPowerDataType` (optional) battery condition label
#
# `pmset -g log` has no time-range flag and spans days (tens of MB), so `collect_events` walks
# it line by line and drops out-of-window lines with a string comparison on the timestamp
# prefix before any regex runs or any object is built.

import re
import sys
from datetime import datetime, timedelta, timezone
from typing import Iterator

from ..redact import redact
from ..schema import (
    BatteryHealth,
    BatteryStatus,
    ChargeState,
    EstimateKind,
    EventKind,
    Platform,
    PowerEvent,
    PowerSetting,
    PowerSource,
)
from .base import Collector, CollectorError, ErrorCode

PMSET = "/usr/bin/pmset"
IOREG = "/usr/sbin/ioreg"
SYSTEM_PROFILER = "/usr/sbin/system_profiler"

LOG_TIMEOUT_S = 60.0  # `pmset -g log` takes several seconds on a busy machine

# Assertion types that keep the *system* from idle-sleeping (display-only and user-activity
# assertions are excluded). The type is copied to extra["assertion_type"] verbatim.
SLEEP_BLOCKING_ASSERTIONS = frozenset({
    "PreventUserIdleSystemSleep",
    "PreventSystemSleep",
    "NoIdleSleepAssertion",
    "NoSleepAssertion",
    "InternalPreventSleep",
    "SystemIsActive",
    "NetworkClientActive",
    "BackgroundTask",
    "ApplePushServiceTask",
    "SoftwareUpdateTask",
})
# Log actions that end an assertion and carry its total held time.
_RELEASE_ACTIONS = frozenset({"Released", "TimedOut", "ClientDied", "CapExpired"})
_START_ACTIONS = frozenset({"Created"})

# Sleep labels (verbatim pmset text) -> user_initiated. Unlisted labels stay None.
_USER_SLEEP = frozenset({"Clamshell Sleep", "Idle Sleep", "Software Sleep", "Power Button Sleep"})
_AUTO_RESLEEP = frozenset({"Maintenance Sleep", "Sleep Service Back to Sleep", "Notification Wake Back to Sleep"})

# ----------------------------------------------------------------------------- regexes
_TS_SHAPE = re.compile(r"\d{4}-\d\d-\d\d \d\d:\d\d:\d\d [+-]\d{4} ")
_SLEEP_LABEL = re.compile(r"due to '([^']*)'")
_WAKE_REASON = re.compile(r":\s*due to\s+(.*?)\s*(?=\bUsing\s+(?:AC|Batt|BATT)\b|$)")
_USING = re.compile(r"\bUsing\s+(AC|Batt|BATT)\b")
_CHARGE = re.compile(r"\(Charge:\s*(\d+)%\)")
_SECS = re.compile(r"\b(\d+) secs\s*$")
_WAKE_FLAGS = re.compile(r"\[([A-Z]+)\]\s*:")
_FROM_STATE = re.compile(r"\bfrom (.+?) \[")
_ACK_SECTION = re.compile(r"Delays to (\w+) notifications:")
_BRACKET = re.compile(r"\[([^\[\]]*)\]")
_ACK_MS = re.compile(r"\((\d+) ms\)\s*$")
_ACK_ACTOR = re.compile(r"^(.*?)(?: driver)? (?:is slow|timed out|failed)\b")
_ACK_MSG = re.compile(r"\(msg: ([^)]*)\)")
_ASSERTION = re.compile(
    r"PID (-?\d+)\((.*?)\) (\w+) (\w+) \"(.*)\" (\d+:\d\d:\d\d)\s+id:(\S+)"
)
_HELD = re.compile(r"^(\d+):(\d\d):(\d\d)$")
_LIVE_ASSERTION = re.compile(
    r"^\s*pid (-?\d+)\((.*?)\): \[(0x[0-9a-fA-F]+)\] (\d+:\d\d:\d\d) (\w+) named: \"(.*)\"\s*$"
)
_BATT_LINE = re.compile(r"^\s*-(\S+) \(id=\d+\)\s+(\d+)%;\s*([^;]*);\s*(.*?)\s*(?:present:\s*(\w+))?\s*$")
_REMAINING = re.compile(r"(\d+):(\d\d) remaining")
_IOREG_KV = re.compile(r'^\s*"([^"]+)" = (.*?)\s*$')


def _cut(line: str) -> str:
    return line[:200]


def _held_seconds(text: str) -> int | None:
    m = _HELD.match(text)
    if not m:
        return None
    return int(m.group(1)) * 3600 + int(m.group(2)) * 60 + int(m.group(3))


def _iter_lines(text: str) -> Iterator[str]:
    # Yield lines lazily without materializing a list of the whole log.
    start = 0
    n = len(text)
    while start < n:
        end = text.find("\n", start)
        if end == -1:
            end = n
        yield text[start:end].rstrip("\r")
        start = end + 1


class _Window:
    # Cheap timestamp-prefix check. pmset log lines start with
    # 'YYYY-MM-DD HH:MM:SS +ZZZZ'. For each offset seen, the UTC window bounds are rendered
    # once as local 'YYYY-MM-DD HH:MM:SS' strings; every line is then classified with two
    # string comparisons on line[:19] (no datetime, no regex).

    BEFORE, INSIDE, AFTER, NOT_TIMESTAMP = range(4)

    def __init__(self, since: datetime, until: datetime) -> None:
        self.since = since
        self.until = until
        self._bounds: dict[str, tuple[str, str]] = {}

    def classify(self, line: str) -> int:
        # Shape check by character tests only.
        if len(line) < 26 or line[4] != "-" or line[10] != " " or line[19] != " " or line[25] != " ":
            return self.NOT_TIMESTAMP
        if not line[0:4].isdigit():
            return self.NOT_TIMESTAMP
        off = line[20:25]
        b = self._bounds.get(off)
        if b is None:
            b = self._bounds[off] = self._render(off, line)
        key = line[:19]
        if key < b[0]:
            return self.BEFORE
        if key >= b[1]:
            return self.AFTER
        return self.INSIDE

    def _render(self, off: str, line: str) -> tuple[str, str]:
        if off[0] not in "+-" or not off[1:].isdigit():
            raise CollectorError(ErrorCode.PARSE_ERROR, f"pmset log: bad UTC offset in line: {_cut(line)}")
        sign = 1 if off[0] == "+" else -1
        tz = timezone(sign * timedelta(hours=int(off[1:3]), minutes=int(off[3:5])))
        fmt = "%Y-%m-%d %H:%M:%S"
        # since: ceil to whole second so 'key < lo' never drops an in-window second.
        s = self.since.astimezone(tz)
        if s.microsecond:
            s = s.replace(microsecond=0) + timedelta(seconds=1)
        u = self.until.astimezone(tz)
        if u.microsecond:
            u = u.replace(microsecond=0) + timedelta(seconds=1)
        return s.strftime(fmt), u.strftime(fmt)


class MacOSCollector(Collector):
    platform = Platform.MACOS

    @classmethod
    def is_supported(cls) -> bool:
        return sys.platform == "darwin"

    # ======================================================================= events
    def collect_events(self, since: datetime, until: datetime) -> list[PowerEvent]:
        since = _utc(since, "since")
        until = _utc(until, "until")
        if until <= since:
            return []
        text = self.runner([PMSET, "-g", "log"], LOG_TIMEOUT_S)
        try:
            events = self._parse_log(text, since, until)
        except CollectorError:
            raise
        except Exception as e:  # pragma: no cover - defensive wrap (rule 8)
            raise CollectorError(ErrorCode.PARSE_ERROR, f"pmset log: {e}"[:300]) from e
        events.sort(key=lambda ev: ev.ts)
        return events

    def _parse_log(self, text: str, since: datetime, until: datetime) -> list[PowerEvent]:
        win = _Window(since, until)
        out: list[PowerEvent] = []
        pending: dict[str, PowerEvent] = {}  # assertion id -> Created-in-window blocker
        last_acks: dict[str, list[tuple[str, str]]] = {}
        for line in _iter_lines(text):
            where = win.classify(line)
            if where == _Window.NOT_TIMESTAMP or where == _Window.BEFORE:
                continue
            if where == _Window.AFTER:
                # Only an assertion release can still overlap the window (its start is
                # release_ts - held). Cheap literal test before any parsing.
                if line.startswith("Assertions", 26) and _has_release_word(line):
                    self._parse_record(line, since, until, out, pending, last_acks, after=True)
                continue
            self._parse_record(line, since, until, out, pending, last_acks, after=False)
        for ev in pending.values():
            out.append(ev)
        return out

    def _parse_record(self, line, since, until, out, pending, last_acks, *, after: bool) -> None:
        # Full parse of one in-window (or overlapping-release) line. Unknown domains are ignored.
        if not _TS_SHAPE.match(line):
            raise CollectorError(ErrorCode.PARSE_ERROR, f"pmset log: malformed timestamp: {_cut(line)}")
        try:
            ts = datetime.strptime(line[:25], "%Y-%m-%d %H:%M:%S %z").astimezone(timezone.utc)
        except ValueError as e:
            raise CollectorError(ErrorCode.PARSE_ERROR, f"pmset log: bad timestamp: {_cut(line)}") from e
        rest = line[26:]
        tab = rest.find("\t")
        if tab == -1:
            domain, msg = rest.strip(), ""
        else:
            domain, msg = rest[:tab].strip(), rest[tab + 1:].strip()
        try:
            if domain == "Assertions":
                self._assertion(line, ts, msg, since, until, out, pending, after)
                return
            if after:
                return
            if domain == "Sleep":
                out.append(self._sleep(line, ts, msg))
            elif domain == "DarkWake":
                out.append(self._wake(line, ts, msg, EventKind.DARK_WAKE))
            elif domain == "Wake":
                out.append(self._wake(line, ts, msg, EventKind.WAKE))
            elif domain in ("PM Client Acks", "Kernel Client Acks"):
                out.extend(self._acks(line, ts, domain, msg, last_acks))
            elif domain == "Start":
                pending.clear()  # powerd restarted: earlier assertions are gone
                out.append(self._event(line, ts, EventKind.BOOT, raw_reason=msg or None,
                                       extra={"marker": "powerd_start"}))
            elif domain in ("Shutdown", "ShutdownCause"):
                out.append(self._event(line, ts, EventKind.SHUTDOWN, raw_reason=msg or None))
        except CollectorError:
            raise
        except Exception as e:
            raise CollectorError(ErrorCode.PARSE_ERROR, f"pmset log: {type(e).__name__}: {_cut(line)}") from e

    # --------------------------------------------------------------- record kinds
    def _event(self, line: str, ts: datetime, kind: EventKind, **kw) -> PowerEvent:
        return PowerEvent(ts=ts, kind=kind, platform=Platform.MACOS, raw=redact(line.strip()) or "", **kw)

    @staticmethod
    def _source_charge(msg: str) -> tuple[PowerSource, int | None]:
        m = _USING.search(msg)
        src = PowerSource.UNKNOWN
        if m:
            src = PowerSource.AC if m.group(1) == "AC" else PowerSource.BATTERY
        c = _CHARGE.search(msg)
        pct = int(c.group(1)) if c and 0 <= int(c.group(1)) <= 100 else None
        return src, pct

    def _sleep(self, line: str, ts: datetime, msg: str) -> PowerEvent:
        src, pct = self._source_charge(msg)
        m = _SLEEP_LABEL.search(msg)
        label = m.group(1) if m else None
        secs = _SECS.search(msg)
        extra: dict[str, str] = {}
        tail = msg[m.end():] if m else ""
        if tail.startswith(":"):
            flags = tail[1:].split(" Using ", 1)[0].strip()
            if flags:
                extra["flags"] = flags
        if label in _USER_SLEEP:
            ui: bool | None = True
        elif label in _AUTO_RESLEEP:
            ui = False
        else:
            ui = None
        return self._event(
            line, ts, EventKind.SLEEP,
            raw_reason=label if label is not None else msg,
            source=src, charge_pct=pct,
            duration_s=float(secs.group(1)) if secs else None,
            sleep_type=label, user_initiated=ui, extra=extra,
        )

    def _wake(self, line: str, ts: datetime, msg: str, kind: EventKind) -> PowerEvent:
        src, pct = self._source_charge(msg)
        m = _WAKE_REASON.search(msg)
        reason = m.group(1) if m and m.group(1) else msg
        secs = _SECS.search(msg)
        extra: dict[str, str] = {}
        f = _WAKE_FLAGS.search(msg)
        if f:
            extra["flags"] = f.group(1)
        fs = _FROM_STATE.search(msg)
        if fs:
            extra["from_state"] = fs.group(1)
        if msg.startswith("DarkWake to FullWake"):
            extra["transition"] = "darkwake_to_fullwake"
        return self._event(
            line, ts, kind, raw_reason=reason, source=src, charge_pct=pct,
            duration_s=float(secs.group(1)) if secs else None, extra=extra,
        )

    def _acks(self, line, ts, domain, msg, last_acks) -> list[PowerEvent]:
        # 'Delays to Sleep notifications: [X is slow(N ms)] ...' -> one SLEEP_DELAY per item.
        # Kernel lines accumulate earlier items; items repeating the previous line's prefix are
        # dropped so each delay is reported once.
        if not msg:
            last_acks[domain] = []
            return []
        items: list[tuple[str, str]] = []
        sections = list(_ACK_SECTION.finditer(msg))
        for i, sec in enumerate(sections):
            end = sections[i + 1].start() if i + 1 < len(sections) else len(msg)
            for b in _BRACKET.finditer(msg, sec.end(), end):
                items.append((sec.group(1), b.group(1)))
        prev = last_acks.get(domain, [])
        new = items[len(prev):] if prev and items[: len(prev)] == prev else items
        last_acks[domain] = items
        evs: list[PowerEvent] = []
        for section, item in new:
            if section != "Sleep":
                continue
            ms = _ACK_MS.search(item)
            am = _ACK_ACTOR.match(item)
            extra = {"ack_domain": "kernel" if domain.startswith("Kernel") else "pm"}
            mm = _ACK_MSG.search(item)
            if mm:
                extra["msg"] = mm.group(1)
            # raw = record prefix + this item only, so evidence shows the cited delay
            # (the full kernel line can be >3 KB and would be truncated before it).
            excerpt = f"{line[:26]}{domain}\tDelays to Sleep notifications: [{item}]"
            evs.append(self._event(
                excerpt, ts, EventKind.SLEEP_DELAY, raw_reason=item,
                duration_s=int(ms.group(1)) / 1000.0 if ms else None,
                actor=redact(am.group(1)) if am else None, extra=extra,
            ))
        return evs

    def _assertion(self, line, ts, msg, since, until, out, pending, after: bool) -> None:
        m = _ASSERTION.search(msg)
        if not m:
            return  # "Kernel Idle sleep preventers: ..." and other summaries
        pid, proc, action, atype, name, held, aid = m.groups()
        if atype not in SLEEP_BLOCKING_ASSERTIONS:
            return
        if action in _START_ACTIONS:
            if not after:
                pending[aid] = self._event(
                    line, ts, EventKind.SLEEP_BLOCKER, raw_reason=name, actor=redact(proc),
                    extra={"pid": pid, "assertion_type": atype, "action": action,
                           "release_not_logged": "1"},
                )
            return
        if action not in _RELEASE_ACTIONS:
            return  # Summary / TurnedOn / TurnedOff: snapshots, not intervals
        started = pending.pop(aid, None)
        secs = _held_seconds(held)
        if secs is not None:
            start = ts - timedelta(seconds=secs)
        elif started is not None:
            start = started.ts
        else:
            start = ts
        if not (start < until and ts >= since):
            return
        out.append(PowerEvent(
            ts=start, kind=EventKind.SLEEP_BLOCKER, platform=Platform.MACOS,
            raw=redact(line.strip()) or "", raw_reason=name, actor=redact(proc),
            duration_s=float(secs) if secs is not None else None, end=ts,
            extra={"pid": pid, "assertion_type": atype, "action": action},
        ))

    # ======================================================================= live
    def current_blockers(self) -> list[PowerEvent]:
        text = self.runner([PMSET, "-g", "assertions"], 20.0)
        now = _utc(self.now(), "now")
        out: list[PowerEvent] = []
        in_list = False
        cur: dict | None = None

        def flush() -> None:
            nonlocal cur
            if cur is not None and cur["atype"] in SLEEP_BLOCKING_ASSERTIONS:
                out.append(self._live_blocker(cur, now))
            cur = None

        for line in _iter_lines(text):
            if line.startswith("Listed by owning process"):
                in_list = True
                continue
            if not in_list:
                continue
            if line.startswith("\t") and cur is not None:
                cur["details"].append(line.strip())
                continue
            m = _LIVE_ASSERTION.match(line)
            if m:
                flush()
                pid, proc, _aid, held, atype, name = m.groups()
                cur = {"line": line, "pid": pid, "proc": proc, "held": held, "atype": atype,
                       "name": name, "details": []}
            elif line and not line[0].isspace():
                flush()
                in_list = False  # "Kernel Assertions:" or another section
        flush()
        out.sort(key=lambda e: e.ts)
        return out

    def _live_blocker(self, a: dict, now: datetime) -> PowerEvent:
        secs = _held_seconds(a["held"])
        extra = {"pid": a["pid"], "assertion_type": a["atype"]}
        for d in a["details"]:
            if d.startswith("Details:"):
                extra["details"] = redact(d[len("Details:"):].strip()) or ""
            elif d.startswith("Timeout will fire"):
                extra["timeout"] = d
        raw = "\n".join([a["line"].strip(), *a["details"]])
        return PowerEvent(
            ts=now - timedelta(seconds=secs or 0), kind=EventKind.SLEEP_BLOCKER,
            platform=Platform.MACOS, raw=redact(raw) or "", raw_reason=a["name"],
            actor=redact(a["proc"]), duration_s=float(secs) if secs is not None else None,
            end=None, extra=extra,
        )

    def battery_status(self) -> BatteryStatus:
        text = self.runner([PMSET, "-g", "batt"], 20.0)
        now = _utc(self.now(), "now")
        on_ac: bool | None = None
        for line in _iter_lines(text):
            if line.startswith("Now drawing from"):
                if "'AC Power'" in line:
                    on_ac = True
                elif "'Battery Power'" in line:
                    on_ac = False
                continue
            m = _BATT_LINE.match(line)
            if not m or not m.group(1).startswith("InternalBattery"):
                continue
            if m.group(5) is not None and m.group(5).lower() != "true":
                continue
            pct = int(m.group(2))
            word = m.group(3).strip().lower()
            tail = m.group(4)
            if word == "charging" or word == "finishing charge":
                state, kind = ChargeState.CHARGING, EstimateKind.TO_FULL
            elif word == "discharging":
                state, kind = ChargeState.DISCHARGING, EstimateKind.TO_EMPTY
            elif word == "charged":
                state, kind = ChargeState.FULL, None
            elif "not charging" in word or tail.lower().startswith("not charging"):
                state, kind = ChargeState.NOT_CHARGING, None
            else:
                state, kind = ChargeState.UNKNOWN, None
            mins: int | None = None
            r = _REMAINING.search(tail)
            if r and kind is not None and "no estimate" not in tail:
                mins = int(r.group(1)) * 60 + int(r.group(2))
                if mins <= 0 or mins >= 65535:
                    mins = None
            return BatteryStatus(
                has_battery=True, percent=pct if 0 <= pct <= 100 else None, state=state,
                on_ac=on_ac, minutes_remaining=mins,
                estimate_kind=kind if mins is not None else None,
                settling=False,  # pmset exposes no power-source change time
                sampled_at=now,
            )
        return BatteryStatus(
            has_battery=False, percent=None, state=ChargeState.UNKNOWN, on_ac=on_ac,
            minutes_remaining=None, estimate_kind=None, settling=False, sampled_at=now,
        )

    def battery_health(self) -> BatteryHealth:
        text = self.runner([IOREG, "-rn", "AppleSmartBattery"], 20.0)
        now = _utc(self.now(), "now")
        kv: dict[str, str] = {}
        for line in _iter_lines(text):
            m = _IOREG_KV.match(line)
            if m and m.group(1) not in kv and "serial" not in m.group(1).lower():
                kv[m.group(1)] = m.group(2)
        if not kv or kv.get("BatteryInstalled", "Yes") == "No":
            raise CollectorError(ErrorCode.NO_BATTERY, "No internal battery found (AppleSmartBattery absent).",
                                 ["This Mac has no battery; battery health is not available."])

        def num(key: str) -> int | None:
            v = kv.get(key)
            if v is None or not re.fullmatch(r"-?\d+", v):
                return None
            n = int(v)
            if n in (65535, -1) or n < 0:
                return None
            return n

        design = num("DesignCapacity")
        full = num("AppleRawMaxCapacity")
        if full is None:
            mc = num("MaxCapacity")  # Intel: mAh. Apple silicon: percent (<=100), not usable here
            full = mc if mc is not None and mc > 100 else num("NominalChargeCapacity")
        health = round(full / design * 100, 1) if full and design else None
        temp = num("Temperature")
        condition = self._condition()
        return BatteryHealth(
            design_capacity=float(design) if design is not None else None,
            full_charge_capacity=float(full) if full is not None else None,
            capacity_unit="mAh" if (design is not None or full is not None) else None,
            health_pct=health,
            cycle_count=num("CycleCount"),
            condition=condition,
            temperature_c=round(temp / 100.0, 2) if temp is not None else None,
            sampled_at=now,
        )

    def _condition(self) -> str | None:
        try:
            text = self.runner([SYSTEM_PROFILER, "SPPowerDataType"], 30.0)
        except CollectorError as e:
            self.warnings.append(f"Battery condition unavailable (system_profiler: {e.message}).")
            return None
        for line in _iter_lines(text):
            s = line.strip()
            if s.startswith("Condition:"):
                return s[len("Condition:"):].strip() or None
        return None

    def power_settings(self) -> list[PowerSetting]:
        text = self.runner([PMSET, "-g", "custom"], 20.0)
        out: list[PowerSetting] = []
        scope: str | None = None
        for line in _iter_lines(text):
            if not line.strip():
                continue
            if not line[0].isspace():
                head = line.strip().rstrip(":")
                scope = {"Battery Power": "battery", "AC Power": "ac"}.get(head)
                if scope is None:
                    self.warnings.append(f"Skipped pmset settings section {head!r}.")
                continue
            if scope is None:
                continue
            m = re.match(r"^\s*(.*?)\s{2,}(\S.*?)\s*$", line) or re.match(r"^\s*(.*\S)\s+(\S+)\s*$", line)
            if not m:
                continue
            key, value = m.group(1), m.group(2)
            out.append(PowerSetting(
                name=re.sub(r"\s+", "_", key.strip().lower()), value=value, scope=scope,
                native_name=key.strip(), raw=redact(line.strip()) or "",
            ))
        return out


def _has_release_word(line: str) -> bool:
    return any(f") {w} " in line for w in _RELEASE_ACTIONS)


def _utc(dt: datetime, name: str) -> datetime:
    if dt.tzinfo is None or dt.utcoffset() is None:
        raise CollectorError(ErrorCode.PARSE_ERROR, f"{name} must be timezone-aware")
    return dt.astimezone(timezone.utc)
