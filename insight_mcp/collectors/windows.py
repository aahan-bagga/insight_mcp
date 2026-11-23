# Windows collector.
#
# Sources (all fixed argv, no shell, no network):
#
# core (normal user):
#   wevtutil qe System /q:<XPath with TimeCreated range> /f:RenderedXml   -> sleep/wake/power-source/boot events
#       Kernel-Power 42 (entering sleep), 105 (power source change), 107 (resumed),
#       506/507 (Modern Standby enter/exit); Power-Troubleshooter 1 (wake + wake source);
#       Kernel-General 12/13 (boot/shutdown). The System log is readable by interactive users.
#   powercfg /query SCHEME_CURRENT SUB_SLEEP, powercfg /a                 -> settings
#   powershell Get-CimInstance Win32_Battery (+ root/wmi BatteryStatus)    -> live battery
#   powercfg /batteryreport /xml /output <tempfile>                        -> health
#
# optional / may need elevation:
#   powercfg /requests            (live blockers; elevation required on most builds)
#   powercfg /query ... SUB_NONE CONNECTIVITYINSTANDBY
#   root/wmi battery classes      (health fallback, BatteryStatus flags)
#
# This module reports facts only. OS reason text is copied verbatim into `raw_reason`.

import json
import os
import re
import sys
import tempfile
import xml.etree.ElementTree as ET
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

KP = "Microsoft-Windows-Kernel-Power"
PT = "Microsoft-Windows-Power-Troubleshooter"
KG = "Microsoft-Windows-Kernel-General"

# Power-Troubleshooter 1 is logged after resume completes, sometimes minutes after WakeTime.
_QUERY_SLACK = timedelta(minutes=15)
# Kernel-Power 107 duplicates a Power-Troubleshooter 1 wake; drop 107 if a PT wake is this close.
_DEDUPE_WINDOW_S = 600.0
_RUNTIME_SENTINELS = {71582788, 65535, 0xFFFFFFFF}

_EVENT_RE = re.compile(r"<Event[\s>].*?</Event>", re.S)
_SYSTIME_ATTR_RE = re.compile(r"SystemTime=['\"]([^'\"]+)['\"]")
_ISO_Z_RE = re.compile(r"(\d{4})-(\d\d)-(\d\d)T(\d\d):(\d\d):(\d\d)(?:\.(\d+))?Z")
_SLEEP_REASON_RE = re.compile(r"Sleep Reason:\s*(.+?)\s*$", re.S)
_MS_REASON_RE = re.compile(r"Reason:\s*(.+?)\s*$", re.S)
_WAKE_SOURCE_RE = re.compile(r"Wake Source:\s*(.+?)\s*$", re.S)
_STANDBY_LABEL_RE = re.compile(r"(?:entering|exiting)\s+((?:modern|connected)\s+standby)", re.I)

_TARGET_STATE = {"2": "S1", "3": "S2", "4": "S3", "5": "Hibernate"}

# user_initiated derivation from the verbatim reason text (not a Cause).
_USER_REASONS = ("button or lid", "system idle", "application api", "power button", "lid", "idle timeout")
_AUTO_REASONS = ("hibernate from sleep",)

_EVENTS_XPATH = (
    "*[System[("
    "(Provider[@Name='" + KP + "'] and (EventID=42 or EventID=105 or EventID=107 or EventID=506 or EventID=507))"
    " or (Provider[@Name='" + PT + "'] and EventID=1)"
    " or (Provider[@Name='" + KG + "'] and (EventID=12 or EventID=13))"
    ") and TimeCreated[@SystemTime>='{since}' and @SystemTime<='{until}']]]"
)
_KP105_XPATH = (
    "*[System[Provider[@Name='" + KP + "'] and EventID=105"
    " and TimeCreated[@SystemTime>='{since}' and @SystemTime<='{until}']]]"
)

_PS_BATTERY = (
    "$ErrorActionPreference='SilentlyContinue';"
    "[pscustomobject]@{"
    "Win32Battery=@(Get-CimInstance -ClassName Win32_Battery | "
    "Select-Object BatteryStatus,EstimatedChargeRemaining,EstimatedRunTime,TimeToFullCharge);"
    "BatteryStatus=@(Get-CimInstance -Namespace root/wmi -ClassName BatteryStatus | "
    "Select-Object PowerOnline,Charging,Discharging,ChargeRate,DischargeRate)"
    "} | ConvertTo-Json -Compress -Depth 3"
)
_PS_HEALTH = (
    "$ErrorActionPreference='Stop';"
    "[pscustomobject]@{"
    "Static=@(Get-CimInstance -Namespace root/wmi -ClassName BatteryStaticData | Select-Object DesignedCapacity);"
    "Full=@(Get-CimInstance -Namespace root/wmi -ClassName BatteryFullChargedCapacity | Select-Object FullChargedCapacity);"
    "Cycle=@(Get-CimInstance -Namespace root/wmi -ClassName BatteryCycleCount | Select-Object CycleCount)"
    "} | ConvertTo-Json -Compress -Depth 3"
)
_PS = ("powershell.exe", "-NoProfile", "-NonInteractive", "-Command")

_SETTING_NAMES = {
    "STANDBYIDLE": "sleep_after_s",
    "HIBERNATEIDLE": "hibernate_after_s",
    "HYBRIDSLEEP": "hybrid_sleep",
    "RTCWAKE": "wake_timers",
    "UNATTENDSLEEP": "unattended_sleep_s",
    "AWAYMODE": "away_mode",
    "CONNECTIVITYINSTANDBY": "standby_network_connectivity",
}

_ELEVATE_STEPS = [
    "Open Windows Terminal or PowerShell with 'Run as administrator' and run the tool again.",
    "Or run `powercfg /requests` yourself in an elevated terminal to see what is keeping the PC awake.",
]


def _fmt_xpath_time(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.") + f"{dt.microsecond // 1000:03d}Z"


def _parse_iso_z(text: str | None) -> datetime | None:
    if not text:
        return None
    m = _ISO_Z_RE.search(text)
    if not m:
        return None
    y, mo, d, h, mi, s, frac = m.groups()
    us = int((frac or "0")[:6].ljust(6, "0"))
    try:
        return datetime(int(y), int(mo), int(d), int(h), int(mi), int(s), us, tzinfo=timezone.utc)
    except ValueError:
        return None


def _local(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def _one_line(text: str) -> str:
    return re.sub(r"\s+", " ", text.replace("‎", "").replace("‏", "")).strip()


def _trunc(s: str) -> str:
    return s[:200]


class WindowsCollector(Collector):
    platform = Platform.WINDOWS

    @classmethod
    def is_supported(cls) -> bool:
        return sys.platform == "win32"

    # ------------------------------------------------------------------ helpers
    def _run(self, argv: list[str] | tuple[str, ...], timeout_s: float = 20.0) -> str:
        try:
            return self.runner(argv, timeout_s)
        except CollectorError:
            raise
        except Exception as e:  # runner contract violation; never leak non-CollectorError
            raise CollectorError(ErrorCode.PARSE_ERROR, _trunc(f"{argv[0]} failed: {e}")) from e

    def _query_events(self, xpath: str, extra: tuple[str, ...] = ()) -> str:
        return self._run(["wevtutil", "qe", "System", f"/q:{xpath}", "/f:RenderedXml", "/rd:false", *extra], 60.0)

    def _parse_event_chunk(self, chunk: str) -> dict[str, Any] | None:
        try:
            root = ET.fromstring(chunk)
        except ET.ParseError:
            self.warnings.append(f"Skipped one unreadable event record: {_trunc(chunk)}")
            return None
        rec: dict[str, Any] = {"provider": "", "event_id": None, "time": None, "data": {}, "message": ""}
        for el in root.iter():
            name = _local(el.tag)
            if name == "Provider" and el.get("Name"):
                rec["provider"] = el.get("Name")
            elif name == "EventID" and el.text:
                try:
                    rec["event_id"] = int(el.text.strip())
                except ValueError:
                    pass
            elif name == "TimeCreated":
                rec["time"] = _parse_iso_z(el.get("SystemTime"))
            elif name == "Data" and el.get("Name"):
                rec["data"][el.get("Name")] = (el.text or "").strip()
            elif name == "Message":
                rec["message"] = (el.text or "").replace("‎", "").replace("‏", "")
        if rec["time"] is None or rec["event_id"] is None:
            self.warnings.append(f"Skipped one event without a timestamp or ID: {_trunc(chunk)}")
            return None
        return rec

    def _iter_records(self, text: str, lo: datetime, hi: datetime):
        # Cheap timestamp check before XML parsing (CONTRACT rule 3).
        for m in _EVENT_RE.finditer(text):
            chunk = m.group(0)
            tm = _SYSTIME_ATTR_RE.search(chunk)
            ts = _parse_iso_z(tm.group(1)) if tm else None
            if ts is not None and not (lo <= ts <= hi):
                continue
            rec = self._parse_event_chunk(chunk)
            if rec is not None:
                yield rec

    @staticmethod
    def _raw(rec: dict[str, Any]) -> str:
        short = rec["provider"].replace("Microsoft-Windows-", "")
        ts = rec["time"].isoformat().replace("+00:00", "Z")
        parts = [f"{short} {rec['event_id']} {ts}:"]
        if rec["message"]:
            parts.append(_one_line(rec["message"]))
        data = " ".join(f"{k}={v}" for k, v in rec["data"].items() if v != "")
        if data:
            parts.append(f"| {data}")
        return redact(" ".join(parts)) or ""

    @staticmethod
    def _user_initiated(reason: str | None) -> bool | None:
        if not reason:
            return None
        low = reason.lower()
        if any(a in low for a in _AUTO_REASONS):
            return False
        if any(u in low for u in _USER_REASONS):
            return True
        return None

    # ------------------------------------------------------------------ events
    def _to_event(self, rec: dict[str, Any]) -> PowerEvent | None:
        prov, eid, data, msg = rec["provider"], rec["event_id"], rec["data"], rec["message"]
        raw = self._raw(rec)
        ts = rec["time"]
        extra: dict[str, str] = {"provider": prov, "event_id": str(eid)}

        if prov == KP and eid == 42:
            m = _SLEEP_REASON_RE.search(msg)
            reason = m.group(1).strip() if m else None
            target = data.get("TargetState", "")
            for k in ("TargetState", "EffectiveState", "Reason", "Flags"):
                if data.get(k):
                    extra[k[0].lower() + re.sub(r"(?<!^)([A-Z])", r"_\1", k[1:]).lower()] = data[k]
            return PowerEvent(ts=ts, kind=EventKind.SLEEP, platform=self.platform, raw=raw, raw_reason=reason,
                              sleep_type=_TARGET_STATE.get(target), user_initiated=self._user_initiated(reason),
                              extra=extra)

        if prov == KP and eid == 506:
            m = _MS_REASON_RE.search(msg)
            reason = m.group(1).strip() if m else None
            lm = _STANDBY_LABEL_RE.search(msg)
            label = lm.group(1).title() if lm else "Modern Standby"
            if data.get("Reason"):
                extra["reason_code"] = data["Reason"]
            return PowerEvent(ts=ts, kind=EventKind.SLEEP, platform=self.platform, raw=raw, raw_reason=reason,
                              sleep_type=label, user_initiated=self._user_initiated(reason), extra=extra)

        if prov == KP and eid == 507:
            m = _MS_REASON_RE.search(msg)
            reason = m.group(1).strip() if m else None
            if data.get("Reason"):
                extra["reason_code"] = data["Reason"]
            return PowerEvent(ts=ts, kind=EventKind.WAKE, platform=self.platform, raw=raw, raw_reason=reason, extra=extra)

        if prov == KP and eid == 107:
            return PowerEvent(ts=ts, kind=EventKind.WAKE, platform=self.platform, raw=raw,
                              raw_reason=_one_line(msg) or None, extra=extra)

        if prov == KP and eid == 105:
            ac = data.get("AcOnline", "").lower()
            source = PowerSource.AC if ac in ("true", "1") else PowerSource.BATTERY if ac in ("false", "0") else PowerSource.UNKNOWN
            pct = None
            try:
                rem, full = int(data.get("RemainingCapacity", "")), int(data.get("FullChargeCapacity", ""))
                if full > 0 and rem >= 0:
                    pct = max(0, min(100, round(rem * 100 / full)))
            except ValueError:
                pass
            return PowerEvent(ts=ts, kind=EventKind.POWER_SOURCE, platform=self.platform, raw=raw,
                              raw_reason=_one_line(msg) or None, source=source, charge_pct=pct, extra=extra)

        if prov == PT and eid == 1:
            wake = _parse_iso_z(data.get("WakeTime")) or ts
            sleep = _parse_iso_z(data.get("SleepTime"))
            m = _WAKE_SOURCE_RE.search(msg)
            reason = m.group(1).strip() if m else (data.get("WakeSourceText") or None)
            actor = redact(data.get("WakeTimerOwner") or None)
            if sleep is not None:
                extra["sleep_time"] = sleep.isoformat().replace("+00:00", "Z")
                extra["slept_s"] = f"{max(0.0, (wake - sleep).total_seconds()):.0f}"
            for k, name in (("WakeSourceType", "wake_source_type"), ("TargetState", "target_state")):
                if data.get(k):
                    extra[name] = data[k]
            extra["logged_at"] = ts.isoformat().replace("+00:00", "Z")
            return PowerEvent(ts=wake, kind=EventKind.WAKE, platform=self.platform, raw=raw, raw_reason=reason,
                              actor=actor, extra=extra)

        if prov == KG and eid in (12, 13):
            kind = EventKind.BOOT if eid == 12 else EventKind.SHUTDOWN
            at = _parse_iso_z(data.get("StartTime" if eid == 12 else "StopTime")) or ts
            return PowerEvent(ts=at, kind=kind, platform=self.platform, raw=raw, raw_reason=_one_line(msg) or None,
                              extra=extra)
        return None

    def collect_events(self, since: datetime, until: datetime) -> list[PowerEvent]:
        since, until = since.astimezone(timezone.utc), until.astimezone(timezone.utc)
        hi = until + _QUERY_SLACK
        xpath = _EVENTS_XPATH.replace("{since}", _fmt_xpath_time(since)).replace("{until}", _fmt_xpath_time(hi))
        text = self._query_events(xpath)  # only source: let CollectorError propagate
        events: list[PowerEvent] = []
        try:
            for rec in self._iter_records(text, since, hi):
                ev = self._to_event(rec)
                if ev is not None and since <= ev.ts < until:
                    events.append(ev)
        except CollectorError:
            raise
        except Exception as e:
            raise CollectorError(ErrorCode.PARSE_ERROR, _trunc(f"wevtutil output not understood: {e}")) from e

        pt_wakes = [e.ts for e in events if e.kind == EventKind.WAKE and e.extra.get("provider") == PT]
        events = [
            e for e in events
            if not (e.extra.get("provider") == KP and e.extra.get("event_id") == "107"
                    and any(abs((e.ts - w).total_seconds()) <= _DEDUPE_WINDOW_S for w in pt_wakes))
        ]
        events.sort(key=lambda e: e.ts)
        return events

    # ------------------------------------------------------------------ blockers
    def current_blockers(self) -> list[PowerEvent]:
        try:
            text = self._run(["powercfg", "/requests"])
        except CollectorError as e:
            if e.code in (ErrorCode.PERMISSION_DENIED, ErrorCode.PARSE_ERROR):
                raise CollectorError(
                    e.code,
                    "powercfg /requests could not run; on most Windows builds it needs an elevated (administrator) terminal. "
                    + e.message,
                    list(e.remediation) or _ELEVATE_STEPS,
                ) from e
            raise
        try:
            return self._parse_requests(text)
        except Exception as e:
            raise CollectorError(ErrorCode.PARSE_ERROR, _trunc(f"powercfg /requests output not understood: {e}")) from e

    def _parse_requests(self, text: str) -> list[PowerEvent]:
        now = self.now().astimezone(timezone.utc)
        events: list[PowerEvent] = []
        category: str | None = None
        cur: dict[str, Any] | None = None

        def flush() -> None:
            nonlocal cur
            if cur is None:
                return
            reason = " ".join(cur["reason"]).strip() or None
            raw = f"{cur['category']}: {cur['line']}" + (f" -- {reason}" if reason else "")
            events.append(PowerEvent(
                ts=now, kind=EventKind.SLEEP_BLOCKER, platform=self.platform, raw=redact(raw) or "",
                raw_reason=reason, actor=redact(cur["actor"]), end=None,
                extra={"request_type": cur["category"], "requester_kind": cur["kind"]},
            ))
            cur = None

        for line in text.splitlines():
            s = line.strip()
            if not s:
                flush()
                continue
            hm = re.fullmatch(r"([A-Z][A-Z_]*):", s)
            if hm:
                flush()
                category = hm.group(1)
                continue
            rm = re.match(r"\[([A-Z]+)\]\s*(.+)$", s)
            if rm and category:
                flush()
                kind, name = rm.group(1), rm.group(2).strip()
                cur = {"category": category, "kind": kind, "line": s, "reason": [], "actor": self._actor_name(kind, name)}
                continue
            if s.lower() == "none.":
                continue
            if cur is not None:
                cur["reason"].append(s)
        flush()
        return events

    @staticmethod
    def _actor_name(kind: str, name: str) -> str:
        if kind in ("PROCESS", "SERVICE") and ("\\" in name or "/" in name):
            # "\Device\...\svchost.exe (wuauserv)" -> "svchost.exe (wuauserv)"
            m = re.match(r"(.+?\.exe)\b(.*)$", name, re.I)
            path, rest = (m.group(1), m.group(2)) if m else (name, "")
            base = re.split(r"[\\/]", path)[-1]
            return (base + rest).strip()
        return name

    # ------------------------------------------------------------------ battery
    def _settling(self, now: datetime) -> bool:
        xpath = _KP105_XPATH.replace("{since}", _fmt_xpath_time(now - timedelta(seconds=60))).replace(
            "{until}", _fmt_xpath_time(now))
        try:
            text = self._query_events(xpath, ("/c:5",))
        except CollectorError as e:
            self.warnings.append(f"Could not check for a recent charger change (settling unknown): {e.message}")
            return False
        for m in _SYSTIME_ATTR_RE.finditer(text):
            ts = _parse_iso_z(m.group(1))
            if ts is not None and timedelta(0) <= now - ts <= timedelta(seconds=60):
                return True
        return False

    @staticmethod
    def _load_json(text: str, what: str) -> Any:
        text = text.strip().lstrip("﻿")
        if not text:
            return {}
        try:
            return json.loads(text)
        except json.JSONDecodeError as e:
            raise CollectorError(ErrorCode.PARSE_ERROR, _trunc(f"{what} returned unexpected output: {text}")) from e

    @staticmethod
    def _as_list(v: Any) -> list[dict[str, Any]]:
        if v is None:
            return []
        if isinstance(v, dict):
            v = [v]
        return [x for x in v if isinstance(x, dict)]

    @staticmethod
    def _int(v: Any) -> int | None:
        if isinstance(v, bool) or v is None:
            return None
        try:
            return int(v)
        except (TypeError, ValueError):
            return None

    def battery_status(self) -> BatteryStatus:
        now = self.now().astimezone(timezone.utc)
        data = self._load_json(self._run([*_PS, _PS_BATTERY], 30.0), "Get-CimInstance Win32_Battery")
        if not isinstance(data, dict):
            raise CollectorError(ErrorCode.PARSE_ERROR, _trunc(f"unexpected battery JSON: {data!r}"))
        bats = self._as_list(data.get("Win32Battery"))
        wmi = self._as_list(data.get("BatteryStatus"))
        if not bats:
            return BatteryStatus(has_battery=False, percent=None, state=ChargeState.UNKNOWN, on_ac=None,
                                 minutes_remaining=None, estimate_kind=None, settling=False, sampled_at=now)

        pcts = [p for p in (self._int(b.get("EstimatedChargeRemaining")) for b in bats) if p is not None and 0 <= p <= 100]
        percent = round(sum(pcts) / len(pcts)) if pcts else None
        codes = {self._int(b.get("BatteryStatus")) for b in bats}

        on_ac: bool | None = None
        state = ChargeState.UNKNOWN
        if wmi:
            charging = any(w.get("Charging") is True for w in wmi)
            discharging = any(w.get("Discharging") is True for w in wmi)
            online = any(w.get("PowerOnline") is True for w in wmi)
            on_ac = online if any(isinstance(w.get("PowerOnline"), bool) for w in wmi) else None
            if charging:
                state = ChargeState.CHARGING
            elif discharging:
                state = ChargeState.DISCHARGING
            elif online:
                state = ChargeState.FULL if percent is not None and percent >= 100 else ChargeState.NOT_CHARGING
        else:
            self.warnings.append("Detailed charging flags (root/wmi BatteryStatus) were unavailable; "
                                 "charging state is based on Win32_Battery only.")
        if state == ChargeState.UNKNOWN:
            # Win32_Battery.BatteryStatus codes (documented CIM values).
            if codes & {1, 4, 5}:
                state, on_ac = ChargeState.DISCHARGING, False if on_ac is None else on_ac
            elif codes & {6, 7, 8, 9}:
                state, on_ac = ChargeState.CHARGING, True
            elif 3 in codes:
                state, on_ac = ChargeState.FULL, True
            elif 2 in codes:
                on_ac = True  # "AC power, not discharging": Win32_Battery cannot tell charging from held
        if on_ac is None and state in (ChargeState.CHARGING, ChargeState.FULL, ChargeState.NOT_CHARGING):
            on_ac = True

        minutes: int | None = None
        kind: EstimateKind | None = None
        if state == ChargeState.DISCHARGING:
            vals = [self._int(b.get("EstimatedRunTime")) for b in bats]
            vals = [v for v in vals if v is not None and v > 0 and v not in _RUNTIME_SENTINELS]
            if vals:
                minutes, kind = min(vals), EstimateKind.TO_EMPTY
        elif state == ChargeState.CHARGING:
            vals = [self._int(b.get("TimeToFullCharge")) for b in bats]
            vals = [v for v in vals if v is not None and v > 0 and v not in _RUNTIME_SENTINELS]
            if vals:
                minutes, kind = max(vals), EstimateKind.TO_FULL

        return BatteryStatus(has_battery=True, percent=percent, state=state, on_ac=on_ac,
                             minutes_remaining=minutes, estimate_kind=kind, settling=self._settling(now),
                             sampled_at=now)

    def battery_health(self) -> BatteryHealth:
        now = self.now().astimezone(timezone.utc)
        try:
            return self._health_from_report(now)
        except CollectorError as e:
            if e.code == ErrorCode.NO_BATTERY:
                raise
            first = e
        self.warnings.append(f"powercfg /batteryreport failed ({first.message}); fell back to WMI battery classes.")
        try:
            return self._health_from_wmi(now)
        except CollectorError as e:
            if e.code == ErrorCode.NO_BATTERY:
                raise
            raise CollectorError(
                first.code,
                f"Battery health unavailable: batteryreport: {first.message}; WMI: {e.message}",
                list(first.remediation) or ["Run `powercfg /batteryreport` in a terminal to check that battery reporting works."],
            ) from e

    def _health_from_report(self, now: datetime) -> BatteryHealth:
        with tempfile.TemporaryDirectory(prefix="insight_mcp_") as d:
            path = os.path.join(d, "battery-report.xml")
            self._run(["powercfg", "/batteryreport", "/xml", "/output", path], 30.0)
            text = self.reader(path)
        try:
            root = ET.fromstring(text.lstrip("﻿").encode("utf-8"))
        except ET.ParseError as e:
            raise CollectorError(ErrorCode.PARSE_ERROR, _trunc(f"battery report XML not understood: {text}")) from e
        design = full = 0.0
        cycles: list[int] = []
        n = 0
        for el in root.iter():
            if _local(el.tag) != "Battery":
                continue
            vals = {_local(c.tag): (c.text or "").strip() for c in el}
            # Never read SerialNumber / Id.
            dc, fc = self._int(vals.get("DesignCapacity")), self._int(vals.get("FullChargeCapacity"))
            if dc is None and fc is None:
                continue
            n += 1
            design += dc or 0
            full += fc or 0
            cc = self._int(vals.get("CycleCount"))
            if cc is not None and cc > 0:
                cycles.append(cc)
        if n == 0:
            raise CollectorError(ErrorCode.NO_BATTERY, "No battery found in the Windows battery report.",
                                 ["This PC has no battery, so battery health does not apply."])
        return self._health(design or None, full or None, max(cycles) if cycles else None, now)

    def _health_from_wmi(self, now: datetime) -> BatteryHealth:
        data = self._load_json(self._run([*_PS, _PS_HEALTH], 30.0), "root/wmi battery classes")
        if not isinstance(data, dict):
            raise CollectorError(ErrorCode.PARSE_ERROR, _trunc(f"unexpected battery JSON: {data!r}"))
        design = sum(v for v in (self._int(x.get("DesignedCapacity")) for x in self._as_list(data.get("Static"))) if v)
        full = sum(v for v in (self._int(x.get("FullChargedCapacity")) for x in self._as_list(data.get("Full"))) if v)
        cyc = [v for v in (self._int(x.get("CycleCount")) for x in self._as_list(data.get("Cycle"))) if v]
        if not design and not full:
            raise CollectorError(ErrorCode.NO_BATTERY, "WMI reports no battery.",
                                 ["This PC has no battery, so battery health does not apply."])
        return self._health(float(design) or None, float(full) or None, max(cyc) if cyc else None, now)

    @staticmethod
    def _health(design: float | None, full: float | None, cycles: int | None, now: datetime) -> BatteryHealth:
        pct = round(full / design * 100, 1) if design and full else None
        return BatteryHealth(design_capacity=design, full_charge_capacity=full, capacity_unit="mWh",
                             health_pct=pct, cycle_count=cycles, condition=None, temperature_c=None, sampled_at=now)

    # ------------------------------------------------------------------ settings
    def power_settings(self) -> list[PowerSetting]:
        out: list[PowerSetting] = []
        try:
            out.extend(self._parse_query(self._run(["powercfg", "/query", "SCHEME_CURRENT", "SUB_SLEEP"]), True))
        except CollectorError as e:
            core_err = e
        else:
            core_err = None
        try:
            out.extend(self._parse_query(
                self._run(["powercfg", "/query", "SCHEME_CURRENT", "SUB_NONE", "CONNECTIVITYINSTANDBY"]), False))
        except CollectorError as e:
            self.warnings.append(f"Could not read 'Networking connectivity in Standby' ({e.message}).")
        try:
            s = self._parse_available(self._run(["powercfg", "/a"]))
            if s is not None:
                out.append(s)
        except CollectorError as e:
            self.warnings.append(f"Could not list available sleep states with powercfg /a ({e.message}).")
        if core_err is not None:
            if not out:
                raise core_err
            self.warnings.append(f"Could not read sleep settings with powercfg /query ({core_err.message}).")
        return out

    def _parse_query(self, text: str, include_scheme: bool) -> list[PowerSetting]:
        out: list[PowerSetting] = []
        cur: dict[str, Any] | None = None

        def emit(scope: str, idx_hex: str, line: str) -> None:
            if cur is None:
                return
            try:
                idx = int(idx_hex, 16)
            except ValueError:
                return
            alias = cur.get("alias")
            if cur["options"]:
                value = cur["options"].get(idx, str(idx))
            else:
                value = str(idx)
            name = _SETTING_NAMES.get(alias or "") or re.sub(r"[^a-z0-9]+", "_", (alias or cur["label"]).lower()).strip("_")
            if not cur["options"] and (cur.get("units") or "").lower() == "seconds" and not name.endswith("_s"):
                name += "_s"
            out.append(PowerSetting(name=name, value=value, scope=scope, native_name=alias or cur["guid"],
                                    raw=redact(f"{cur['label']}: {line.strip()}") or ""))

        pending_index: int | None = None
        for line in text.splitlines():
            s = line.strip()
            m = re.match(r"Power Scheme GUID:\s*([0-9a-fA-F-]{36})\s*\((.*)\)", s)
            if m:
                if include_scheme:
                    out.append(PowerSetting(name="power_scheme", value=m.group(2), scope="all",
                                            native_name="SCHEME_CURRENT", raw=redact(s) or ""))
                continue
            m = re.match(r"Power Setting GUID:\s*([0-9a-fA-F-]{36})\s*\((.*)\)", s)
            if m:
                cur = {"guid": m.group(1), "label": m.group(2), "alias": None, "options": {}, "units": None}
                continue
            if cur is None:
                continue
            m = re.match(r"GUID Alias:\s*(\S+)", s)
            if m:
                cur["alias"] = m.group(1)
                continue
            m = re.match(r"Possible Settings units:\s*(.*)", s)
            if m:
                cur["units"] = m.group(1).strip()
                continue
            m = re.match(r"Possible Setting Index:\s*(\d+)", s)
            if m:
                pending_index = int(m.group(1))
                continue
            m = re.match(r"Possible Setting Friendly Name:\s*(.*)", s)
            if m and pending_index is not None:
                cur["options"][pending_index] = m.group(1).strip()
                pending_index = None
                continue
            m = re.match(r"Current (AC|DC) Power Setting Index:\s*0x([0-9a-fA-F]+)", s)
            if m:
                emit("ac" if m.group(1) == "AC" else "battery", m.group(2), s)
        return out

    @staticmethod
    def _parse_available(text: str) -> PowerSetting | None:
        states: list[str] = []
        in_avail = False
        for line in text.splitlines():
            if not line.strip():
                continue
            if not line[:1].isspace():
                in_avail = "are available" in line and "not available" not in line
                continue
            if in_avail and len(line) - len(line.lstrip()) <= 4:
                states.append(line.strip())
        if not states and "available" not in text:
            return None
        return PowerSetting(name="available_sleep_states", value="; ".join(states), scope="all",
                            native_name="powercfg /a", raw=redact(_one_line(text))[:500] or "")
