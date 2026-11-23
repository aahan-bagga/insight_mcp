# Linux collector: systemd journal, sysfs power_supply, upower history, systemd-inhibit.
#
# Facts only. Raw OS text goes into `raw_reason` verbatim; attribution.py assigns causes.
#
# Sources (all read-only, fixed argv, no admin on the core path):
# - `journalctl -o short-iso-precise --since=@<epoch> --until=@<epoch>` restricted to the
#   kernel, systemd-sleep and systemd-logind identifiers -> SLEEP / WAKE / DARK_WAKE /
#   SLEEP_DELAY / BOOT / SHUTDOWN. Reading the system journal needs membership in
#   systemd-journal / adm / wheel; without it this source degrades to a warning.
# - `/var/lib/upower/history-charge-*.dat` (listed with `ls -1`) -> BATTERY_SAMPLE and
#   POWER_SOURCE events, plus charge_pct/source on SLEEP and WAKE (marked in `extra`).
# - `/sys/class/power_supply/*/<attr>` -> battery_status / battery_health. Handles both
#   energy_* (uWh) and charge_* (uAh) batteries. Serial numbers are never read.
# - `systemd-inhibit --list` -> current blockers.
# - `/sys/power/mem_sleep`, `/sys/firmware/acpi/platform_profile`, `/proc/acpi/wakeup`,
#   `/etc/systemd/{logind,sleep}.conf` (+ .conf.d drop-ins) -> power settings.

import math
import re
import sys
from dataclasses import dataclass, field, replace
from datetime import datetime, timedelta, timezone
from typing import Any

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

PS_DIR = "/sys/class/power_supply"
UPOWER_DIR = "/var/lib/upower"
JOURNAL_TIMEOUT_S = 30.0
SHORT_TIMEOUT_S = 5.0

JOURNAL_GROUPS = frozenset({"systemd-journal", "adm", "wheel", "root"})
JOURNAL_REMEDIATION = (
    "Add yourself to the systemd-journal group: `sudo usermod -aG systemd-journal $USER`, "
    "then log out and back in."
)
_FALLBACK_SUPPLIES = ("AC", "AC0", "ACAD", "ADP0", "ADP1", "BAT0", "BAT1", "BAT2", "BATT", "BATC", "CMB0")
_MAINS_TYPES = frozenset({"Mains", "USB", "USB_C", "USB_PD", "USB_PD_DRP"})
_JOURNAL_IDENTS = frozenset({"kernel", "systemd-sleep", "systemd-logind"})
_KERNEL_PREFIXES = ("PM: ", "Linux version ", "Freezing ", "Suspended for ", "Timekeeping suspended", "task:")

# --- journal message patterns (matched only after the cheap ident/prefix/window checks)
_TS_RE = re.compile(r"^(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d)(?:\.(\d{1,9}))?(Z|[+-]\d\d:?\d\d)$")
_LOGIND_TRIGGER_RE = re.compile(r"^(?:Lid closed|Power key pressed|Suspend key pressed|Hibernate key pressed|Sleep key pressed)")
_LOGIND_REQUEST_RE = re.compile(r"^The system will (?:suspend|hibernate|hybrid-sleep|sleep)")
_LOGIND_SHUTDOWN_RE = re.compile(r"^System is (?:powering down|powering off|rebooting|halting)")
_SLEEP_ENTER_RE = re.compile(
    r"^(?:Entering sleep state '([\w-]+)'|Performing sleep operation '([\w-]+)'|(Suspending|Hibernating|Hybrid-sleeping) system)"
)
_OLD_VERB = {"Suspending": "suspend", "Hibernating": "hibernate", "Hybrid-sleeping": "hybrid-sleep"}
_SLEEP_RESUME_RE = re.compile(r"^(?:System returned from sleep|System resumed)")
_SLEEP_FAILED_RE = re.compile(r"^Failed to (?:put system to sleep|suspend system|hibernate system)")
_K_SUSPEND_ENTRY = re.compile(r"^PM: suspend entry \(([\w-]+)\)")
_K_HIBERNATE_ENTRY = re.compile(r"^PM: (?:hibernation: )?hibernation entry")
_K_EXIT = re.compile(r"^PM: (?:suspend exit|(?:hibernation: )?hibernation exit)")
_K_WAKE_REASON = re.compile(
    r"^PM: (?:Triggering wakeup from IRQ|Wakeup pending|last active wakeup source|active wakeup source|"
    r"Some devices failed to suspend|Device .* failed to suspend|dpm_run_callback|Wakeup event detected)"
)
_K_ABORT = re.compile(r"(?i)aborting|failed|early wake")
_K_SLEPT_FOR = re.compile(r"^(?:PM: )?(?:Timekeeping suspended|Suspended) for ([\d.]+) seconds")
_K_FREEZE_FAIL = re.compile(
    r"^Freezing (?:of tasks|user space processes|remaining freezable tasks) failed after ([\d.]+) seconds"
)
_K_TASK = re.compile(r"^task:(\S+)")

_HISTORY_STATE_SOURCE = {
    "discharging": PowerSource.BATTERY,
    "empty": PowerSource.BATTERY,
    "pending-discharge": PowerSource.BATTERY,
    "charging": PowerSource.AC,
    "fully-charged": PowerSource.AC,
    "pending-charge": PowerSource.AC,
}
_STATUS_MAP = {
    "Charging": ChargeState.CHARGING,
    "Discharging": ChargeState.DISCHARGING,
    "Full": ChargeState.FULL,
    "Not charging": ChargeState.NOT_CHARGING,
}

TRIGGER_WINDOW = timedelta(seconds=120)
AUTO_RESLEEP_WINDOW = timedelta(seconds=30)
SLEEP_CHARGE_LOOKBACK = timedelta(minutes=15)
WAKE_CHARGE_LOOKAHEAD = timedelta(minutes=5)


@dataclass
class _Rec:
    ts: datetime
    ident: str
    pid: str | None
    msg: str
    line: str


@dataclass
class _Cycle:
    sleep: _Rec | None = None
    anchor: str = "none"          # "systemd" | "kernel" | "none"
    op: str | None = None         # systemd-sleep operation verbatim ('suspend', 'hibernate'...)
    kernel_mode: str | None = None  # kernel label verbatim ('s2idle', 'deep', 'hibernation')
    kernel_entry: _Rec | None = None
    kernel_exit: _Rec | None = None
    reasons: list[_Rec] = field(default_factory=list)
    failure: _Rec | None = None
    slept_s: float | None = None
    extra: dict[str, str] = field(default_factory=dict)
    user: bool | None = None      # user_initiated for the SLEEP
    trigger: str | None = None    # logind trigger line (lid / key), verbatim


def _parse_ts(s: str) -> datetime | None:
    m = _TS_RE.match(s)
    if not m:
        return None
    base, frac, off = m.groups()
    if off == "Z":
        off = "+00:00"
    elif ":" not in off:
        off = off[:3] + ":" + off[3:]
    frac = ((frac or "") + "000000")[:6]
    return datetime.fromisoformat(f"{base}.{frac}{off}").astimezone(timezone.utc)


def _snake(key: str) -> str:
    return re.sub(r"(?<!^)(?=[A-Z])", "_", key).lower()


def _upower_safe(s: str) -> str:
    # upower builds history ids with g_strdelimit(id, "\\\t\"?' /,.", '_')
    return re.sub(r"[\\\t\"?' /,.]", "_", s)


class LinuxCollector(Collector):
    platform = Platform.LINUX

    @classmethod
    def is_supported(cls) -> bool:
        return sys.platform.startswith("linux")

    # ------------------------------------------------------------------ events
    def collect_events(self, since: datetime, until: datetime) -> list[PowerEvent]:
        since_u = since.astimezone(timezone.utc)
        until_u = until.astimezone(timezone.utc)
        events: list[PowerEvent] = []
        journal_err: CollectorError | None = None
        journal_ok = False

        argv = [
            "journalctl", "--no-pager", "-q", "-o", "short-iso-precise",
            f"--since=@{math.floor(since_u.timestamp())}",
            f"--until=@{math.ceil(until_u.timestamp())}",
            "SYSLOG_IDENTIFIER=kernel", "SYSLOG_IDENTIFIER=systemd-sleep", "SYSLOG_IDENTIFIER=systemd-logind",
        ]
        try:
            text = self.runner(argv, JOURNAL_TIMEOUT_S)
            journal_ok = True
        except CollectorError as e:
            journal_err = e
            self._warn_journal(e)
            text = ""
        if journal_ok:
            jevents, saw_lines = self._parse_journal(text, since_u, until_u)
            events.extend(jevents)
            if not saw_lines:
                self._check_journal_access()

        samples, upower_err = self._upower_samples(since_u, until_u)
        if samples is not None:
            events = self._enrich(events, samples)
            events.extend(self._sample_events(samples, since_u, until_u))

        if not journal_ok and samples is None:
            assert journal_err is not None
            code = journal_err.code if journal_err.code in (ErrorCode.PERMISSION_DENIED, ErrorCode.COMMAND_NOT_FOUND, ErrorCode.TIMEOUT) else ErrorCode.NO_DATA
            raise CollectorError(
                code,
                f"No Linux event source worked: journal ({journal_err.message}); upower history ({upower_err})",
                [
                    JOURNAL_REMEDIATION,
                    "Make sure systemd-journald is running and, for battery history, that UPower (`upower`) is installed.",
                ],
            )
        events.sort(key=lambda e: e.ts)
        return events

    def _warn_journal(self, e: CollectorError) -> None:
        low = e.message.lower()
        if e.code == ErrorCode.COMMAND_NOT_FOUND:
            self.warnings.append(
                "journalctl was not found, so sleep/wake history is unavailable (systemd journal required). "
                "On non-systemd distributions, sleep history is not supported yet."
            )
        elif e.code == ErrorCode.PERMISSION_DENIED or "insufficient permissions" in low or "permission" in low:
            self.warnings.append(
                "Could not read the system journal, so sleep/wake history is missing. " + JOURNAL_REMEDIATION
            )
        elif e.code == ErrorCode.TIMEOUT:
            self.warnings.append("journalctl timed out reading sleep/wake history. Try a shorter time window.")
        else:
            self.warnings.append(f"Could not read sleep/wake history from journalctl: {e.message[:200]}")

    def _check_journal_access(self) -> None:
        try:
            groups = set(self.runner(["id", "-Gn"], SHORT_TIMEOUT_S).split())
        except CollectorError:
            return
        if not groups & JOURNAL_GROUPS:
            self.warnings.append(
                "The journal returned no system entries; your user is probably not allowed to read "
                "system logs (kernel/systemd-sleep), so sleep/wake history may be missing. " + JOURNAL_REMEDIATION
            )

    def _parse_journal(self, text: str, since: datetime, until: datetime) -> tuple[list[PowerEvent], bool]:
        out: list[PowerEvent] = []
        delays: list[dict[str, Any]] = []
        saw = False
        cur: _Cycle | None = None
        last_trigger: _Rec | None = None
        last_request: _Rec | None = None
        last_wake: tuple[datetime, str | None, int] | None = None  # (ts, pid, index in out)

        def emit(ev: PowerEvent) -> int:
            out.append(ev)
            return len(out) - 1

        def in_window(ts: datetime) -> bool:
            return since <= ts < until

        def close(c: _Cycle, wake: _Rec | None) -> None:
            nonlocal last_wake
            if c.sleep is not None and in_window(c.sleep.ts):
                raw = c.sleep.line if c.kernel_entry is None or c.kernel_entry is c.sleep else f"{c.sleep.line} | {c.kernel_entry.line}"
                extra = dict(c.extra)
                if c.op:
                    extra["systemd_sleep_op"] = c.op
                if c.kernel_mode:
                    extra["kernel_sleep_mode"] = c.kernel_mode
                if c.failure is not None or any(_K_ABORT.search(r.msg) for r in c.reasons):
                    extra["aborted"] = "1"
                emit(PowerEvent(
                    ts=c.sleep.ts, kind=EventKind.SLEEP, platform=Platform.LINUX, raw=redact(raw) or "",
                    raw_reason=c.trigger, duration_s=c.slept_s,
                    sleep_type=c.kernel_mode or c.op, user_initiated=c.user, extra=extra,
                ))
            w = wake or c.kernel_exit
            if w is not None and in_window(w.ts):
                parts = [r.msg for r in c.reasons]
                if c.failure is not None:
                    parts.append(c.failure.msg)
                extra = {}
                if c.failure is not None or any(_K_ABORT.search(r.msg) for r in c.reasons):
                    extra["aborted"] = "1"
                if c.kernel_mode or c.op:
                    extra["resumed_from"] = c.kernel_mode or c.op or ""
                lines = [w.line] + [r.line for r in c.reasons]
                idx = emit(PowerEvent(
                    ts=w.ts, kind=EventKind.WAKE, platform=Platform.LINUX, raw=redact(" | ".join(lines)) or "",
                    raw_reason="; ".join(parts) or None, extra=extra,
                ))
                last_wake = (w.ts, w.pid, idx)

        def start(rec: _Rec, anchor: str, op: str | None) -> _Cycle:
            nonlocal cur, last_request, last_trigger
            if cur is not None:
                close(cur, None)
            c = _Cycle(sleep=rec, anchor=anchor, op=op)
            extra: dict[str, str] = {}
            user: bool | None = None
            trigger: str | None = None
            if last_request is not None and timedelta(0) <= rec.ts - last_request.ts <= TRIGGER_WINDOW:
                user = True
                extra["logind_request"] = last_request.msg
                if last_trigger is not None and timedelta(0) <= rec.ts - last_trigger.ts <= TRIGGER_WINDOW:
                    trigger = last_trigger.msg
                last_request = None
                last_trigger = None
            elif (
                last_wake is not None and rec.pid is not None and rec.pid == last_wake[1]
                and timedelta(0) <= rec.ts - last_wake[0] <= AUTO_RESLEEP_WINDOW
            ):
                # same systemd-sleep process went back to sleep with no new logind request
                # (e.g. suspend-then-hibernate): automatic re-sleep, and the wake before it was dark.
                user = False
                extra["auto_resleep"] = "1"
                prev = out[last_wake[2]]
                out[last_wake[2]] = replace(prev, kind=EventKind.DARK_WAKE, extra={**prev.extra, "followed_by_auto_resleep": "1"})
            c.extra, c.user, c.trigger = extra, user, trigger
            cur = c
            return c

        line = ""
        try:
            for line in text.splitlines():
                if not line or line.startswith("-- "):
                    continue
                parts = line.split(" ", 3)
                if len(parts) < 4:
                    continue
                ts_s, _host, identpid, msg = parts
                ident, _, pid = identpid.rstrip(":").partition("[")
                if ident not in _JOURNAL_IDENTS:
                    continue
                saw = True
                if ident == "kernel" and not msg.startswith(_KERNEL_PREFIXES):
                    continue
                ts = _parse_ts(ts_s)
                if ts is None or not (since <= ts < until):
                    continue
                rec = _Rec(ts, ident, pid.rstrip("]") or None, msg, line)

                if ident == "systemd-logind":
                    if _LOGIND_TRIGGER_RE.match(msg):
                        last_trigger = rec
                    elif _LOGIND_REQUEST_RE.match(msg):
                        last_request = rec
                    elif _LOGIND_SHUTDOWN_RE.match(msg):
                        reason = last_trigger.msg if last_trigger and ts - last_trigger.ts <= TRIGGER_WINDOW else None
                        emit(PowerEvent(ts=ts, kind=EventKind.SHUTDOWN, platform=Platform.LINUX,
                                        raw=redact(line) or "", raw_reason=reason or msg))
                        last_trigger = None
                elif ident == "systemd-sleep":
                    m = _SLEEP_ENTER_RE.match(msg)
                    if m:
                        op = m.group(1) or m.group(2) or _OLD_VERB[m.group(3)]
                        start(rec, "systemd", op)
                    elif _SLEEP_RESUME_RE.match(msg) or _SLEEP_FAILED_RE.match(msg):
                        if cur is None:
                            cur = _Cycle()
                        if _SLEEP_FAILED_RE.match(msg):
                            cur.failure = rec
                        close(cur, rec)
                        cur = None
                else:  # kernel
                    m = _K_SUSPEND_ENTRY.match(msg)
                    if m or _K_HIBERNATE_ENTRY.match(msg):
                        mode = m.group(1) if m else "hibernation"
                        if cur is not None and cur.anchor == "systemd" and cur.kernel_mode is None and cur.kernel_exit is None:
                            cur.kernel_mode, cur.kernel_entry = mode, rec
                        else:
                            c = start(rec, "kernel", None)
                            c.kernel_mode, c.kernel_entry = mode, rec
                    elif _K_EXIT.match(msg):
                        if cur is None:
                            cur = _Cycle()
                        cur.kernel_exit = rec
                        if cur.anchor != "systemd":
                            close(cur, rec)
                            cur = None
                    elif _K_WAKE_REASON.match(msg):
                        if cur is None:
                            cur = _Cycle()
                        cur.reasons.append(rec)
                    elif (m := _K_SLEPT_FOR.match(msg)) is not None:
                        if cur is not None:
                            cur.slept_s = float(m.group(1))
                    elif (m := _K_FREEZE_FAIL.match(msg)) is not None:
                        delays.append({"rec": rec, "dur": float(m.group(1)), "actor": None})
                    elif (m := _K_TASK.match(msg)) is not None:
                        if delays and delays[-1]["actor"] is None and ts - delays[-1]["rec"].ts <= timedelta(seconds=5):
                            delays[-1]["actor"] = m.group(1)
                    elif msg.startswith("Linux version "):
                        if cur is not None:
                            close(cur, None)
                            cur = None
                        emit(PowerEvent(ts=ts, kind=EventKind.BOOT, platform=Platform.LINUX,
                                        raw=redact(line) or "", raw_reason=None))
            if cur is not None:
                close(cur, None)
            for d in delays:
                rec = d["rec"]
                emit(PowerEvent(
                    ts=rec.ts, kind=EventKind.SLEEP_DELAY, platform=Platform.LINUX, raw=redact(rec.line) or "",
                    raw_reason=rec.msg, duration_s=d["dur"], actor=redact(d["actor"]),
                ))
        except CollectorError:
            raise
        except Exception as e:  # noqa: BLE001 - contract rule 8
            raise CollectorError(ErrorCode.PARSE_ERROR, f"journalctl parse failed ({e}): {line[:200]}") from e
        return out, saw

    # ------------------------------------------------------------------ upower history
    def _upower_samples(self, since: datetime, until: datetime) -> tuple[list[tuple[datetime, int, PowerSource, str]] | None, str]:
        # Returns (samples incl. a little context around the window, error text). None = unavailable.
        try:
            names = [n.strip() for n in self.runner(["ls", "-1", UPOWER_DIR], SHORT_TIMEOUT_S).splitlines() if n.strip()]
        except CollectorError as e:
            if self._batteries():
                self.warnings.append(
                    "UPower charge history (/var/lib/upower) is unavailable, so battery drain during sleep "
                    "cannot be measured. Install and enable UPower (`upower`) to record it."
                )
            return None, e.message
        files = [n for n in names if n.startswith("history-charge-") and n.endswith(".dat")]
        if not files:
            return None, "no history-charge files"
        bats = self._batteries()
        models = [_upower_safe(b["model"]) for b in bats if b.get("model")]
        matched = [f for f in files if any(f.startswith(f"history-charge-{m}-") for m in models)]
        candidates = matched or files
        lo = int((since - SLEEP_CHARGE_LOOKBACK).timestamp())
        hi = int((until + WAKE_CHARGE_LOOKAHEAD).timestamp())
        best: list[tuple[datetime, int, PowerSource, str]] | None = None
        best_last = -1
        line = ""
        for fname in candidates:
            try:
                text = self.reader(f"{UPOWER_DIR}/{fname}")
            except CollectorError:
                continue
            samples: list[tuple[datetime, int, PowerSource, str]] = []
            last_epoch = -1
            prev: tuple[datetime, int, PowerSource, str] | None = None
            try:
                for line in text.splitlines():
                    head, _, rest = line.partition("\t")
                    if not head.isdigit():
                        continue
                    epoch = int(head)
                    last_epoch = max(last_epoch, epoch)
                    if epoch < lo:
                        # keep only the newest pre-window sample (for source-change detection)
                        prev = (datetime.fromtimestamp(epoch, timezone.utc), 0, PowerSource.UNKNOWN, line)
                        continue
                    if epoch >= hi:
                        continue
                    val_s, _, state = rest.partition("\t")
                    val = float(val_s)
                    pct = max(0, min(100, int(round(val))))
                    state = state.strip()
                    samples.append((datetime.fromtimestamp(epoch, timezone.utc), pct,
                                    _HISTORY_STATE_SOURCE.get(state, PowerSource.UNKNOWN), line))
            except Exception as e:  # noqa: BLE001
                raise CollectorError(ErrorCode.PARSE_ERROR, f"upower history parse failed ({e}): {line[:200]}") from e
            if prev is not None:
                _, _, rest = prev[3].partition("\t")
                st = rest.partition("\t")[2].strip()
                samples.insert(0, (prev[0], -1, _HISTORY_STATE_SOURCE.get(st, PowerSource.UNKNOWN), prev[3]))
            if last_epoch > best_last:
                best, best_last = samples, last_epoch
        if best is None:
            return None, "history files unreadable"
        return best, ""

    def _sample_events(self, samples, since: datetime, until: datetime) -> list[PowerEvent]:
        out: list[PowerEvent] = []
        prev_src: PowerSource | None = None
        for ts, pct, src, line in samples:
            raw = redact(f"upower history-charge: {line}") or ""
            if since <= ts < until and pct >= 0:
                if prev_src is not None and src != PowerSource.UNKNOWN and prev_src != PowerSource.UNKNOWN and src != prev_src:
                    out.append(PowerEvent(ts=ts, kind=EventKind.POWER_SOURCE, platform=Platform.LINUX, raw=raw,
                                          raw_reason=line.split("\t")[-1].strip(), source=src, charge_pct=pct,
                                          extra={"from": "upower_history"}))
                out.append(PowerEvent(ts=ts, kind=EventKind.BATTERY_SAMPLE, platform=Platform.LINUX, raw=raw,
                                      source=src, charge_pct=pct, extra={"from": "upower_history"}))
            if src != PowerSource.UNKNOWN:
                prev_src = src
        return out

    def _enrich(self, events: list[PowerEvent], samples) -> list[PowerEvent]:
        real = [s for s in samples if s[1] >= 0]
        if not real:
            return events
        out = []
        for ev in events:
            pick = None
            if ev.kind == EventKind.SLEEP:
                before = [s for s in real if ev.ts - SLEEP_CHARGE_LOOKBACK <= s[0] <= ev.ts]
                pick = before[-1] if before else None
            elif ev.kind in (EventKind.WAKE, EventKind.DARK_WAKE):
                after = [s for s in real if ev.ts <= s[0] <= ev.ts + WAKE_CHARGE_LOOKAHEAD]
                pick = after[0] if after else None
            if pick is not None:
                ev = replace(ev, charge_pct=pick[1], source=pick[2],
                             extra={**ev.extra, "charge_from": "upower_history",
                                    "charge_sample_ts": pick[0].isoformat().replace("+00:00", "Z")})
            out.append(ev)
        return out

    # ------------------------------------------------------------------ sysfs power_supply
    def _attr(self, name: str, attr: str) -> str | None:
        try:
            v = self.reader(f"{PS_DIR}/{name}/{attr}")
        except CollectorError:
            return None
        v = v.strip()
        return v or None

    def _int_attr(self, name: str, attr: str) -> int | None:
        v = self._attr(name, attr)
        if v is None:
            return None
        try:
            return int(v)
        except ValueError:
            return None

    def _supplies(self) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
        if hasattr(self, "_supply_cache"):
            return self._supply_cache  # type: ignore[has-type]
        try:
            names = [n.strip() for n in self.runner(["ls", "-1", PS_DIR], SHORT_TIMEOUT_S).splitlines() if n.strip()]
        except CollectorError:
            names = list(_FALLBACK_SUPPLIES)
        bats: list[dict[str, Any]] = []
        mains: list[dict[str, Any]] = []
        for n in names:
            t = self._attr(n, "type")
            if t is None or self._attr(n, "scope") == "Device":  # peripheral (mouse, headset) batteries
                continue
            if t == "Battery":
                if self._attr(n, "present") == "0":
                    continue
                bats.append(self._read_battery(n))
            elif t in _MAINS_TYPES:
                mains.append({"name": n, "online": self._int_attr(n, "online")})
        self._supply_cache = (bats, mains)
        return bats, mains

    def _batteries(self) -> list[dict[str, Any]]:
        return self._supplies()[0]

    def _read_battery(self, n: str) -> dict[str, Any]:
        b: dict[str, Any] = {"name": n, "status": self._attr(n, "status"), "capacity": self._int_attr(n, "capacity"),
                             "model": self._attr(n, "model_name"), "cycle_count": self._int_attr(n, "cycle_count"),
                             "health": self._attr(n, "health"), "temp": self._int_attr(n, "temp")}
        e_now, e_full = self._int_attr(n, "energy_now"), self._int_attr(n, "energy_full")
        if e_now is not None or e_full is not None:
            b["unit"] = "mWh"
            b["now"], b["full"], b["design"] = e_now, e_full, self._int_attr(n, "energy_full_design")
            rate = self._int_attr(n, "power_now")
            if rate is None:
                cur, volt = self._int_attr(n, "current_now"), self._int_attr(n, "voltage_now")
                if cur is not None and volt is not None:
                    rate = cur * volt // 1_000_000  # uA * uV -> uW
        else:
            c_now, c_full = self._int_attr(n, "charge_now"), self._int_attr(n, "charge_full")
            b["unit"] = "mAh" if (c_now is not None or c_full is not None) else None
            b["now"], b["full"], b["design"] = c_now, c_full, self._int_attr(n, "charge_full_design")
            rate = self._int_attr(n, "current_now")
        b["rate"] = abs(rate) if rate is not None else None  # some drivers report negative while discharging
        b["tte"] = self._int_attr(n, "time_to_empty_now")
        b["ttf"] = self._int_attr(n, "time_to_full_now")
        return b

    def battery_status(self) -> BatteryStatus:
        bats, mains = self._supplies()
        now = self.now()
        on_ac: bool | None = None
        known = [m["online"] for m in mains if m["online"] is not None]
        if known:
            on_ac = any(v == 1 for v in known)
        if not bats:
            return BatteryStatus(has_battery=False, percent=None, state=ChargeState.UNKNOWN, on_ac=on_ac,
                                 minutes_remaining=None, estimate_kind=None, settling=False, sampled_at=now)
        states = [_STATUS_MAP.get(b["status"] or "", ChargeState.UNKNOWN) for b in bats]
        if ChargeState.CHARGING in states:
            state = ChargeState.CHARGING
        elif ChargeState.DISCHARGING in states:
            state = ChargeState.DISCHARGING
        elif all(s == ChargeState.FULL for s in states):
            state = ChargeState.FULL
        elif ChargeState.NOT_CHARGING in states or ChargeState.FULL in states:
            state = ChargeState.NOT_CHARGING if ChargeState.NOT_CHARGING in states else ChargeState.FULL
        else:
            state = ChargeState.UNKNOWN
        if on_ac is None:
            if state == ChargeState.DISCHARGING:
                on_ac = False
            elif state in (ChargeState.CHARGING, ChargeState.NOT_CHARGING):
                on_ac = True

        same_unit = len({b["unit"] for b in bats}) == 1 and bats[0]["unit"] is not None
        have_energy = same_unit and all(b["now"] is not None and b["full"] for b in bats)
        percent: int | None = None
        if len(bats) == 1 and bats[0]["capacity"] is not None and 0 <= bats[0]["capacity"] <= 100:
            percent = bats[0]["capacity"]
        elif have_energy:
            percent = max(0, min(100, round(sum(b["now"] for b in bats) / sum(b["full"] for b in bats) * 100)))
        else:
            caps = [b["capacity"] for b in bats if b["capacity"] is not None and 0 <= b["capacity"] <= 100]
            percent = round(sum(caps) / len(caps)) if caps else None

        minutes: int | None = None
        kind: EstimateKind | None = None
        if state == ChargeState.DISCHARGING:
            kind = EstimateKind.TO_EMPTY
            if len(bats) == 1 and bats[0]["tte"] and bats[0]["tte"] > 0:
                minutes = round(bats[0]["tte"] / 60)
            elif have_energy:
                rate = sum(b["rate"] or 0 for b in bats)
                if rate > 0:
                    minutes = round(sum(b["now"] for b in bats) / rate * 60)
        elif state == ChargeState.CHARGING:
            kind = EstimateKind.TO_FULL
            if len(bats) == 1 and bats[0]["ttf"] and bats[0]["ttf"] > 0:
                minutes = round(bats[0]["ttf"] / 60)
            elif have_energy:
                rate = sum(b["rate"] or 0 for b in bats)
                if rate > 0:
                    minutes = round(max(0, sum(b["full"] - b["now"] for b in bats)) / rate * 60)
        if minutes is None:
            kind = None
        return BatteryStatus(has_battery=True, percent=percent, state=state, on_ac=on_ac,
                             minutes_remaining=minutes, estimate_kind=kind, settling=False, sampled_at=now)

    def battery_health(self) -> BatteryHealth:
        bats = self._batteries()
        if not bats:
            raise CollectorError(ErrorCode.NO_BATTERY, "No system battery found under /sys/class/power_supply",
                                 ["This machine has no internal battery; battery health is not applicable."])
        units = {b["unit"] for b in bats if b["unit"]}
        use = bats
        if len(units) > 1:
            self.warnings.append("Batteries report different units (energy vs charge); health uses the first battery only.")
            use = [bats[0]]
        unit = use[0]["unit"]
        design = full = None
        if all(b["design"] for b in use):
            design = sum(b["design"] for b in use) / 1000.0
        if all(b["full"] for b in use):
            full = sum(b["full"] for b in use) / 1000.0
        health = round(full / design * 100, 1) if design and full else None
        cycles = [b["cycle_count"] for b in use if b["cycle_count"] is not None and b["cycle_count"] > 0]
        temp = next((b["temp"] for b in use if b["temp"] is not None), None)
        return BatteryHealth(
            design_capacity=design, full_charge_capacity=full, capacity_unit=unit if (design or full) else None,
            health_pct=health, cycle_count=max(cycles) if cycles else None,
            condition=next((b["health"] for b in use if b["health"]), None),
            temperature_c=temp / 10.0 if temp is not None else None, sampled_at=self.now(),
        )

    # ------------------------------------------------------------------ blockers
    def current_blockers(self) -> list[PowerEvent]:
        try:
            text = self.runner(["systemd-inhibit", "--list", "--no-pager"], SHORT_TIMEOUT_S)
        except CollectorError as e:
            self.warnings.append(f"Could not list sleep inhibitors with systemd-inhibit: {e.message[:200]}")
            return []
        try:
            rows = self._parse_inhibit(text)
        except Exception as e:  # noqa: BLE001
            raise CollectorError(ErrorCode.PARSE_ERROR, f"systemd-inhibit parse failed ({e}): {text[:200]}") from e
        now = self.now()
        out = []
        for r in rows:
            what = r.get("what", "")
            if r.get("mode") != "block" or not ({"sleep", "idle", "handle-lid-switch"} & set(what.split(":"))):
                continue
            extra = {k: r[k] for k in ("what", "mode", "comm", "pid") if r.get(k)}
            extra["since_unknown"] = "1"  # systemd-inhibit does not report when the lock was taken
            out.append(PowerEvent(ts=now, kind=EventKind.SLEEP_BLOCKER, platform=Platform.LINUX,
                                  raw=redact(r["raw"]) or "", raw_reason=r.get("why"), actor=redact(r.get("who")),
                                  end=None, extra=extra))
        return out

    @staticmethod
    def _parse_inhibit(text: str) -> list[dict[str, str]]:
        lines = text.splitlines()
        header_i = next((i for i, l in enumerate(lines) if l.startswith("WHO") and "WHAT" in l and "MODE" in l), None)
        rows: list[dict[str, str]] = []
        if header_i is not None:
            header = lines[header_i]
            cols = [(m.group(0).lower(), m.start()) for m in re.finditer(r"\S+", header)]
            for l in lines[header_i + 1:]:
                if not l.strip() or re.match(r"^\d+ inhibitors? listed", l.strip()):
                    continue
                r: dict[str, str] = {}
                for i, (name, start) in enumerate(cols):
                    end = cols[i + 1][1] if i + 1 < len(cols) else None
                    r[name] = l[start:end].strip()
                masked = l
                if r.get("user"):
                    s = cols[[c[0] for c in cols].index("user")][1]
                    e = s + len(r["user"])
                    masked = l[:s] + "<user>".ljust(len(r["user"])) + l[e:]
                r["raw"] = re.sub(r"\s{2,}", "  ", masked.strip())
                rows.append(r)
            return rows
        # legacy (systemd < 240) block format
        block: dict[str, str] = {}
        def flush() -> None:
            if block.get("who") is not None:
                rows.append(dict(block))
            block.clear()
        for l in lines + [""]:
            m = re.match(r"^\s*(Who|What|Why|Mode):\s?(.*)$", l)
            if not m:
                if not l.strip():
                    flush()
                continue
            key, val = m.group(1).lower(), m.group(2).strip()
            if key == "who":
                flush()
                wm = re.match(r"^(.*?) \(UID (\d+)/[^,]*, PID (\d+)/([^)]*)\)$", val)
                if wm:
                    block.update(who=wm.group(1), uid=wm.group(2), pid=wm.group(3), comm=wm.group(4))
                    val = re.sub(r"(UID \d+/)[^,]*", r"\1<user>", val)
                else:
                    block["who"] = val
                block["raw"] = f"Who: {val}"
            else:
                block[key] = val
                block["raw"] = block.get("raw", "") + f" {m.group(1)}: {val}"
        return rows

    # ------------------------------------------------------------------ settings
    def power_settings(self) -> list[PowerSetting]:
        out: list[PowerSetting] = []
        try:
            ms = self.reader("/sys/power/mem_sleep").strip()
            # value is the file as reported ("s2idle [deep]"): the bracket marks the active mode and the
            # other entries are what's available - attribution needs both.
            out.append(PowerSetting(name="mem_sleep", value=ms, scope="all",
                                    native_name="/sys/power/mem_sleep", raw=redact(ms) or ""))
        except CollectorError as e:
            self.warnings.append(f"Could not read /sys/power/mem_sleep: {e.message[:200]}")
        try:
            pp = self.reader("/sys/firmware/acpi/platform_profile").strip()
            if pp:
                out.append(PowerSetting(name="platform_profile", value=pp, scope="all",
                                        native_name="/sys/firmware/acpi/platform_profile", raw=redact(pp) or ""))
        except CollectorError:
            pass  # optional: many machines have no ACPI platform profile
        try:
            out.extend(self._acpi_wakeup(self.reader("/proc/acpi/wakeup")))
        except CollectorError:
            pass  # optional: absent on non-ACPI (e.g. ARM) machines
        for conf, section in (("logind", "Login"), ("sleep", "Sleep")):
            out.extend(self._systemd_conf(conf, section))
        return out

    @staticmethod
    def _acpi_wakeup(text: str) -> list[PowerSetting]:
        out = []
        for l in text.splitlines():
            m = re.match(r"^(\S+)\s+(S\d)\s+\*?(enabled|disabled)\b", l)
            if not m:
                continue
            dev = m.group(1)
            out.append(PowerSetting(name=f"acpi_wakeup_{dev.lower()}", value=m.group(3), scope="all",
                                    native_name=dev, raw=redact(re.sub(r"\s+", " ", l.strip())) or ""))
        return out

    def _systemd_conf(self, conf: str, section: str) -> list[PowerSetting]:
        paths = [f"/etc/systemd/{conf}.conf"]
        try:
            ls = self.runner(["ls", "-1", f"/etc/systemd/{conf}.conf.d"], SHORT_TIMEOUT_S)
            paths += [f"/etc/systemd/{conf}.conf.d/{n.strip()}" for n in sorted(ls.splitlines()) if n.strip().endswith(".conf")]
        except CollectorError:
            pass
        merged: dict[str, tuple[str, str, str]] = {}
        for p in paths:
            try:
                text = self.reader(p)
            except CollectorError:
                continue
            sec = None
            for l in text.splitlines():
                s = l.strip()
                if not s or s[0] in "#;":
                    continue
                if s.startswith("[") and s.endswith("]"):
                    sec = s[1:-1]
                    continue
                if sec != section or "=" not in s:
                    continue
                k, _, v = s.partition("=")
                merged[k.strip()] = (v.strip(), s, p)
        out = []
        for k, (v, raw, p) in merged.items():
            scope = "ac" if k.endswith("ExternalPower") else "all"
            out.append(PowerSetting(name=_snake(k), value=v, scope=scope, native_name=k, raw=redact(f"{p}: {raw}") or ""))
        return out
