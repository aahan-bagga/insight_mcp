# Lead-owned: envelope, error policy and argument validation, using a fake collector.

from datetime import datetime, timedelta, timezone

import pytest

from insight_mcp.collectors.base import Collector, CollectorError, ErrorCode
from insight_mcp.schema import (BatteryHealth, BatteryStatus, ChargeState, EventKind, Platform, PowerEvent,
                                PowerSetting, PowerSource)
from insight_mcp.server import Service, build_server

NOW = datetime(2026, 11, 16, 12, tzinfo=timezone.utc)


class Fake(Collector):
    platform = Platform.MACOS

    def __init__(self, events=(), fail=None, blockers=()):
        super().__init__(runner=lambda *a: "", now=lambda: NOW)
        self._events, self._fail, self._blockers = list(events), fail, list(blockers)

    @classmethod
    def is_supported(cls):
        return True

    def collect_events(self, since, until):
        if self._fail:
            raise self._fail
        return [e for e in self._events if since <= e.ts < until]

    def current_blockers(self):
        return self._blockers

    def battery_status(self):
        return BatteryStatus(True, 50, ChargeState.DISCHARGING, False, 120, None, False, NOW)

    def battery_health(self):
        self.warnings.append("health partial")
        return BatteryHealth(8694, 6000, "mAh", 69.0, 900, "Service Recommended", 30.0, NOW)

    def power_settings(self):
        return [PowerSetting("powernap", "1", "battery", "powernap", "powernap 1")]


def svc(**kw):
    return Service(collector_factory=lambda: Fake(**kw), clock=lambda: NOW)


def ev(kind, h, **kw):
    return PowerEvent(ts=NOW - timedelta(hours=h), kind=kind, platform=Platform.MACOS, raw=kind.value, **kw)


def test_ok_envelope_shape():
    r = svc().battery_status()
    assert r["ok"] is True and r["platform"] == "macos" and r["generated_at"] == "2026-11-16T12:00:00Z"
    assert r["data"]["percent"] == 50 and r["warnings"] == []


def test_collector_error_becomes_structured_error_with_remediation():
    r = svc(fail=CollectorError(ErrorCode.PERMISSION_DENIED, "journal denied")).sleep_report(24)
    assert r["ok"] is False and r["error"]["code"] == "permission_denied" and r["error"]["remediation"]


@pytest.mark.parametrize("bad", [0, 721, -5])
def test_hours_validated(bad):
    r = svc().sleep_report(bad)
    assert r["ok"] is False and r["error"]["code"] == "invalid_argument"


def test_sleep_report_end_to_end_and_user_input_filtered():
    events = [
        ev(EventKind.SLEEP, 10, source=PowerSource.BATTERY, charge_pct=80, user_initiated=True, sleep_type="Clamshell Sleep"),
        *[ev(EventKind.DARK_WAKE, 9 - i * 0.01, source=PowerSource.BATTERY, charge_pct=78, raw_reason="wifibt") for i in range(8)],
        ev(EventKind.WAKE, 1, source=PowerSource.BATTERY, charge_pct=60, raw_reason="lid HID Activity"),
    ]
    r = svc(events=events).sleep_report(24)
    assert r["ok"], r
    d = r["data"]
    assert len(d["sessions"]) == 1 and d["sessions"][0]["drain_pct_per_hour"] == pytest.approx(20 / 9, abs=0.05)
    causes = {a["cause"] for a in d["attributions"]}
    assert "user_input" not in causes and "setting" in causes
    assert all(a["evidence"] for a in d["attributions"])
    assert "health partial" in r["warnings"]


def test_since_unknown_blocker_reports_null_duration():
    b = PowerEvent(ts=NOW, kind=EventKind.SLEEP_BLOCKER, platform=Platform.LINUX, raw="x", actor="vlc",
                   extra={"since_unknown": "1"})
    r = svc(blockers=[b]).who_is_keeping_me_awake()
    assert r["data"]["blockers"][0]["held_for_s"] is None and r["data"]["blockers"][0]["since"] is None


def test_all_tools_registered_read_only():
    import asyncio
    tools = asyncio.run(build_server(svc()).list_tools())
    assert {t.name for t in tools} == {"battery_status", "battery_health", "sleep_report", "wake_causes",
                                       "who_is_keeping_me_awake", "power_settings"}
    assert all(t.annotations.readOnlyHint and not t.annotations.destructiveHint for t in tools)


def test_blocker_intervals_clipped_to_window():
    b = PowerEvent(ts=NOW - timedelta(hours=100), end=NOW - timedelta(hours=1), kind=EventKind.SLEEP_BLOCKER,
                   platform=Platform.MACOS, raw="x", actor="coreaudiod", duration_s=99 * 3600)
    class F(Fake):
        def collect_events(self, since, until):
            return [b]
    s = Service(collector_factory=lambda: F(), clock=lambda: NOW)
    _, _, events = s._events(s._c(), 24)
    assert events[0].ts == NOW - timedelta(hours=24) and events[0].end == NOW - timedelta(hours=1)
    assert events[0].duration_s == 23 * 3600
