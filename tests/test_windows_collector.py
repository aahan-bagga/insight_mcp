
import json
from datetime import timezone
from zoneinfo import ZoneInfo

import pytest

from conftest import FIXTURES, FakeReader, FakeRunner, load_fixture, utc
from insight_mcp.collectors.base import CollectorError, ErrorCode
from insight_mcp.collectors.windows import WindowsCollector
from insight_mcp.schema import ChargeState, EstimateKind, EventKind, PowerSource

LA = ZoneInfo("America/Los_Angeles")
WEV = ("wevtutil", "qe", "System")
PS = ("powershell.exe",)


def fx(name: str) -> str:
    return load_fixture("windows", name)


def make(responses, reader=None, now=None):
    runner = FakeRunner(responses)
    c = WindowsCollector(runner=runner, reader=reader or FakeReader({}), local_tz=LA,
                         now=now or (lambda: utc(2026, 11, 16, 12, 0, 0)))
    return c, runner


class SuffixReader:
    # powercfg writes the report to a random temp path; serve the fixture for any *.xml path.

    def __init__(self, text):
        self.text, self.reads = text, []

    def __call__(self, path):
        self.reads.append(path)
        if isinstance(self.text, CollectorError):
            raise self.text
        return self.text


# ---------------------------------------------------------------------------- events
def test_events_s3_laptop_window_and_kinds():
    c, runner = make({WEV: fx("wevtutil_system__s3_laptop.xml")})
    since, until = utc(2026, 11, 15, 12), utc(2026, 11, 16, 12)
    evs = c.collect_events(since, until)

    # time range is pushed into the XPath query (rule 3)
    q = runner.calls[0][3]
    assert q.startswith("/q:") and "@SystemTime>='2026-11-15T12:00:00.000Z'" in q
    assert "@SystemTime<='2026-11-16T12:15:00.000Z'" in q  # slack for late-logged Power-Troubleshooter 1
    assert "/f:RenderedXml" in runner.calls[0]

    assert all(since <= e.ts < until for e in evs)
    assert [e.ts for e in evs] == sorted(e.ts for e in evs)
    assert all(e.ts.tzinfo == timezone.utc for e in evs)
    kinds = [e.kind for e in evs]
    assert kinds == [
        EventKind.POWER_SOURCE, EventKind.SLEEP, EventKind.WAKE, EventKind.SLEEP, EventKind.SLEEP,
        EventKind.WAKE, EventKind.POWER_SOURCE, EventKind.SLEEP, EventKind.WAKE, EventKind.SHUTDOWN,
        EventKind.BOOT, EventKind.SLEEP,
    ]
    # 107 was deduplicated against the Power-Troubleshooter wake
    assert not any(e.extra.get("event_id") == "107" for e in evs)


def test_events_s3_facts_verbatim():
    c, _ = make({WEV: fx("wevtutil_system__s3_laptop.xml")})
    evs = c.collect_events(utc(2026, 11, 15, 12), utc(2026, 11, 16, 12))
    sleeps = [e for e in evs if e.kind == EventKind.SLEEP]
    assert sleeps[0].raw_reason == "System Idle" and sleeps[0].sleep_type == "S3" and sleeps[0].user_initiated is True
    hib = sleeps[2]
    assert hib.raw_reason == "Hibernate from Sleep - Fixed Timeout"
    assert hib.sleep_type == "Hibernate" and hib.user_initiated is False
    assert sleeps[3].raw_reason == "Button or Lid" and sleeps[3].user_initiated is True

    wakes = [e for e in evs if e.kind == EventKind.WAKE]
    timer = wakes[0]
    assert timer.ts == utc(2026, 11, 15, 19, 2, 8, 471985)  # WakeTime, not TimeCreated
    assert timer.raw_reason.startswith("Timer - Windows will execute 'NT TASK\\Microsoft\\Windows\\UpdateOrchestrator")
    assert timer.actor.endswith("svchost.exe (UsoSvc)")
    assert timer.extra["wake_source_type"] == "3"
    assert timer.extra["slept_s"] == str(round((utc(2026, 11, 15, 19, 2, 8) - utc(2026, 11, 15, 17, 20, 35)).total_seconds()))
    assert wakes[1].raw_reason == "Power Button" and wakes[1].extra["target_state"] == "5"
    assert wakes[2].raw_reason == "Device -Intel(R) Wi-Fi 6 AX201 160MHz"

    ps = [e for e in evs if e.kind == EventKind.POWER_SOURCE]
    assert (ps[0].source, ps[0].charge_pct) == (PowerSource.BATTERY, 85)
    assert (ps[1].source, ps[1].charge_pct) == (PowerSource.AC, 42)

    for e in evs:
        assert "LAPTOP-7Q2M4KD" not in e.raw  # hostname never copied into raw
        assert "‎" not in e.raw
        assert len(e.raw) <= 500


def test_events_wake_logged_after_until_is_excluded_but_wake_before_until_kept():
    c, _ = make({WEV: fx("wevtutil_system__s3_laptop.xml")})
    evs = c.collect_events(utc(2026, 11, 16, 9), utc(2026, 11, 16, 12, 4, 58))
    assert evs[-1].kind == EventKind.SLEEP and evs[-1].raw_reason == "Application API"
    evs2 = c.collect_events(utc(2026, 11, 16, 9), utc(2026, 11, 16, 12, 4, 59))
    assert evs2[-1].kind == EventKind.WAKE and evs2[-1].ts == utc(2026, 11, 16, 12, 4, 58)


def test_modern_standby_literal_crlf_messages():
    raw = (FIXTURES / "windows" / "wevtutil_system__modern_standby.xml").read_bytes().decode("utf-8")
    assert "\r\n\r\nReason:" in raw  # literal CRLF inside <Message>
    c, _ = make({WEV: raw})
    evs = c.collect_events(utc(2026, 11, 15, 12), utc(2026, 11, 16, 12))
    assert [e.kind for e in evs] == [EventKind.SLEEP, EventKind.WAKE, EventKind.POWER_SOURCE, EventKind.SLEEP, EventKind.WAKE]
    assert evs[0].sleep_type == "Modern Standby" and evs[0].raw_reason == "Idle Timeout."
    assert evs[0].user_initiated is True
    assert evs[1].raw_reason == "Input Keyboard."
    assert evs[3].raw_reason == "Power Button." and evs[3].user_initiated is True
    # unknown reason text is not an error; emitted verbatim
    assert evs[4].raw_reason == "Fingerprint Sensor Contact." and evs[4].extra["reason_code"] == "99"


def test_events_empty_output_and_malformed_record():
    c, _ = make({WEV: ""})
    assert c.collect_events(utc(2026, 11, 15), utc(2026, 11, 16)) == []
    bad = "<Event xmlns='x'><System><TimeCreated SystemTime='2026-11-15T13:00:00.0Z'/><EventID>42</Event>\r\n"
    good = fx("wevtutil_kp105__recent.xml")
    c, _ = make({WEV: bad + good})
    evs = c.collect_events(utc(2026, 11, 15), utc(2026, 11, 17))
    assert len(evs) == 1 and evs[0].kind == EventKind.POWER_SOURCE
    assert any("unreadable event" in w for w in c.warnings)


def test_events_source_failure_raises_collector_error():
    err = CollectorError(ErrorCode.COMMAND_NOT_FOUND, "wevtutil not found")
    c, _ = make({WEV: err})
    with pytest.raises(CollectorError) as ei:
        c.collect_events(utc(2026, 11, 15), utc(2026, 11, 16))
    assert ei.value.code == ErrorCode.COMMAND_NOT_FOUND


# ---------------------------------------------------------------------------- blockers
def test_current_blockers_parse():
    c, _ = make({("powercfg", "/requests"): fx("powercfg_requests__active.txt")})
    bl = c.current_blockers()
    assert [(b.extra["request_type"], b.extra["requester_kind"]) for b in bl] == [
        ("DISPLAY", "PROCESS"), ("SYSTEM", "DRIVER"), ("SYSTEM", "PROCESS"), ("EXECUTION", "SERVICE")]
    assert all(b.kind == EventKind.SLEEP_BLOCKER and b.end is None for b in bl)
    assert bl[0].actor == "firefox.exe" and bl[0].raw_reason == "Video Wake Lock"
    assert bl[1].raw_reason == "An audio stream is currently in use."
    assert bl[2].actor == "Discord.exe" and bl[2].raw_reason == "WebRTC has active PeerConnections"
    assert bl[3].actor == "svchost.exe (wuauserv)"
    assert all(b.ts == utc(2026, 11, 16, 12) for b in bl)


def test_current_blockers_none():
    c, _ = make({("powercfg", "/requests"): fx("powercfg_requests__none.txt")})
    assert c.current_blockers() == []


def test_current_blockers_needs_admin():
    c, _ = make({("powercfg", "/requests"): CollectorError(ErrorCode.PERMISSION_DENIED, "powercfg: Access is denied.")})
    with pytest.raises(CollectorError) as ei:
        c.current_blockers()
    assert ei.value.code == ErrorCode.PERMISSION_DENIED and ei.value.remediation


def test_blocker_raw_redacts_user_profile_path():
    c, _ = make({("powercfg", "/requests"): fx("powercfg_requests__active.txt")})
    assert all("jdoe" not in b.raw for b in c.current_blockers())


# ---------------------------------------------------------------------------- battery status
def test_battery_status_discharging():
    c, runner = make({PS: fx("cim_battery__discharging.json"), WEV: ""})
    s = c.battery_status()
    assert (s.has_battery, s.percent, s.state, s.on_ac) == (True, 62, ChargeState.DISCHARGING, False)
    assert (s.minutes_remaining, s.estimate_kind, s.settling) == (187, EstimateKind.TO_EMPTY, False)
    assert s.sampled_at == utc(2026, 11, 16, 12)
    # settling check uses an absolute window derived from the injected clock
    q = [a for a in runner.calls if a[0] == "wevtutil"][0][3]
    assert "EventID=105" in q and "'2026-11-16T11:59:00.000Z'" in q


def test_battery_status_ac_held_sentinel_and_settling():
    c, _ = make({PS: fx("cim_battery__ac_held.json"), WEV: fx("wevtutil_kp105__recent.xml")})
    s = c.battery_status()
    assert s.state == ChargeState.NOT_CHARGING and s.on_ac is True and s.percent == 80
    assert s.minutes_remaining is None and s.estimate_kind is None  # 71582788 is a sentinel
    assert s.settling is True


def test_battery_status_without_root_wmi():
    c, _ = make({PS: fx("cim_battery__charging_no_wmi.json"), WEV: ""})
    s = c.battery_status()
    assert s.on_ac is True and s.state == ChargeState.UNKNOWN and s.minutes_remaining is None
    assert any("root/wmi" in w for w in c.warnings)


def test_battery_status_desktop():
    c, _ = make({PS: fx("cim_battery__desktop.json")})
    s = c.battery_status()
    assert s.has_battery is False and s.percent is None and s.on_ac is None


def test_battery_status_settling_check_failure_is_warning():
    c, _ = make({PS: fx("cim_battery__discharging.json"),
                 WEV: CollectorError(ErrorCode.TIMEOUT, "wevtutil timed out")})
    assert c.battery_status().settling is False
    assert c.warnings


# ---------------------------------------------------------------------------- battery health
def test_battery_health_from_report():
    reader = SuffixReader(fx("batteryreport__worn.xml"))
    c, runner = make({("powercfg", "/batteryreport"): ""}, reader=reader)
    h = c.battery_health()
    assert (h.design_capacity, h.full_charge_capacity, h.capacity_unit) == (52000.0, 39520.0, "mWh")
    assert h.health_pct == 76.0 and h.cycle_count == 412
    assert h.condition is None
    argv = runner.calls[0]
    assert argv[:4] == ("powercfg", "/batteryreport", "/xml", "/output")
    assert reader.reads == [argv[4]]
    assert "4821" not in json.dumps(h.to_dict())  # serial never emitted


def test_battery_health_desktop_raises_no_battery():
    c, _ = make({("powercfg", "/batteryreport"): ""}, reader=SuffixReader(fx("batteryreport__desktop.xml")))
    with pytest.raises(CollectorError) as ei:
        c.battery_health()
    assert ei.value.code == ErrorCode.NO_BATTERY


def test_battery_health_falls_back_to_wmi():
    c, _ = make({("powercfg", "/batteryreport"): CollectorError(ErrorCode.PARSE_ERROR, "powercfg exited 1"),
                 PS: fx("cim_battery_health__wmi.json")})
    h = c.battery_health()
    assert h.health_pct == 90.0 and h.cycle_count == 88
    assert any("batteryreport" in w for w in c.warnings)


def test_battery_health_all_sources_fail():
    c, _ = make({("powercfg", "/batteryreport"): CollectorError(ErrorCode.PARSE_ERROR, "x"),
                 PS: CollectorError(ErrorCode.PERMISSION_DENIED, "Access denied")})
    with pytest.raises(CollectorError) as ei:
        c.battery_health()
    assert ei.value.remediation


# ---------------------------------------------------------------------------- settings
def _settings_responses(over=None):
    r = {
        ("powercfg", "/query", "SCHEME_CURRENT", "SUB_SLEEP"): fx("powercfg_query__sub_sleep.txt"),
        ("powercfg", "/query", "SCHEME_CURRENT", "SUB_NONE"): fx("powercfg_query__connectivity_in_standby.txt"),
        ("powercfg", "/a"): fx("powercfg_a__modern_standby.txt"),
    }
    r.update(over or {})
    return r


def test_power_settings():
    c, _ = make(_settings_responses())
    by = {(s.name, s.scope): s for s in c.power_settings()}
    assert by[("power_scheme", "all")].value == "Balanced"
    assert by[("sleep_after_s", "ac")].value == "0"
    assert by[("sleep_after_s", "battery")].value == "900"
    assert by[("hibernate_after_s", "battery")].value == "10800"
    assert by[("hybrid_sleep", "ac")].value == "Off"
    assert by[("wake_timers", "ac")].value == "Enable"
    assert by[("wake_timers", "battery")].value == "Important Wake Timers Only"
    assert by[("wake_timers", "battery")].native_name == "RTCWAKE"
    assert by[("standby_network_connectivity", "battery")].value == "Managed by Windows"
    assert by[("available_sleep_states", "all")].value == \
        "Standby (S0 Low Power Idle) Network Connected; Hibernate; Fast Startup"
    assert c.warnings == []


def test_power_settings_optional_source_failure_is_warning():
    c, _ = make(_settings_responses({
        ("powercfg", "/query", "SCHEME_CURRENT", "SUB_NONE"): CollectorError(ErrorCode.PARSE_ERROR, "Invalid Parameters")}))
    names = {s.name for s in c.power_settings()}
    assert "standby_network_connectivity" not in names and "wake_timers" in names
    assert len(c.warnings) == 1


def test_power_settings_all_fail_raises():
    e = CollectorError(ErrorCode.COMMAND_NOT_FOUND, "powercfg not found")
    c, _ = make({("powercfg",): e})
    with pytest.raises(CollectorError):
        c.power_settings()


def test_no_shell_strings_in_argv():
    c, runner = make({WEV: "", ("powercfg",): "", PS: fx("cim_battery__desktop.json")})
    c.collect_events(utc(2026, 11, 15), utc(2026, 11, 16))
    c.battery_status()
    for argv in runner.calls:
        assert isinstance(argv, tuple) and all(isinstance(a, str) for a in argv)
