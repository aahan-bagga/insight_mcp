# MacOSCollector tests. Every OS call goes through FakeRunner with real (redacted) fixtures.

from datetime import datetime, timedelta
from zoneinfo import ZoneInfo

import pytest

from conftest import FIXTURES, FakeRunner, load_fixture, utc
from insight_mcp.collectors import macos as macos_mod
from insight_mcp.collectors.base import CollectorError, ErrorCode
from insight_mcp.collectors.macos import IOREG, PMSET, SYSTEM_PROFILER, MacOSCollector
from insight_mcp.redact import redact
from insight_mcp.schema import ChargeState, EstimateKind, EventKind, PowerSource

LA = ZoneInfo("America/Los_Angeles")
NOW = utc(2026, 11, 18, 21, 15, 42)


def make(responses, now=NOW) -> MacOSCollector:
    return MacOSCollector(runner=FakeRunner(responses), local_tz=LA, now=lambda: now)


def log_collector(text: str) -> MacOSCollector:
    return make({(PMSET, "-g", "log"): text})


def of(events, kind):
    return [e for e in events if e.kind == kind]


def assert_window(events, since, until):
    assert events == sorted(events, key=lambda e: e.ts)
    for e in events:
        assert e.ts.tzinfo is not None and e.ts.utcoffset() == timedelta(0)
        if e.kind == EventKind.SLEEP_BLOCKER:
            assert e.ts < until and (e.end is None or e.end >= since)
        else:
            assert since <= e.ts < until


# ----------------------------------------------------------------------------- pmset -g log
def test_wake_storm_fixture():
    since, until = utc(2026, 11, 11, 22, 55), utc(2026, 11, 11, 23, 40)
    ev = log_collector(load_fixture("macos", "pmset_log__wake_storm.txt")).collect_events(since, until)
    assert_window(ev, since, until)

    sleeps = of(ev, EventKind.SLEEP)
    first = sleeps[0]
    assert first.ts == utc(2026, 11, 11, 22, 57, 23)  # 14:57:23 -0800
    assert first.sleep_type == "Clamshell Sleep" and first.raw_reason == "Clamshell Sleep"
    assert first.user_initiated is True
    assert first.source == PowerSource.BATTERY and first.charge_pct == 50
    assert first.duration_s == 1021.0
    assert first.extra["flags"] == "TCPKeepAlive=active"
    assert {s.sleep_type for s in sleeps[1:]} == {"Sleep Service Back to Sleep", "Maintenance Sleep"}
    assert all(s.user_initiated is False for s in sleeps[1:])

    dark = of(ev, EventKind.DARK_WAKE)
    assert len(dark) == 8
    assert dark[0].raw_reason == "NUB.SPMISw3IRQ nub-spmi0.0x02 rtc/SleepService"
    wifibt = [d for d in dark if d.raw_reason == "smc.sysState.Wake(0x70070000) wifibt SMC.OutboxNotEmpty/"]
    assert len(wifibt) == 7
    assert all(d.extra["flags"] == "CDNP" and d.extra["from_state"] == "Deep Idle" for d in dark)
    assert not of(ev, EventKind.WAKE)


def test_sleep_delays_pm_and_kernel():
    since, until = utc(2026, 11, 11, 22, 57), utc(2026, 11, 11, 22, 58)
    ev = log_collector(load_fixture("macos", "pmset_log__wake_storm.txt")).collect_events(since, until)
    delays = of(ev, EventKind.SLEEP_DELAY)
    assert [(d.actor, d.duration_s) for d in delays] == [
        ("com.apple.audio.ParrotAudioPlugin", 0.435),
        ("com.apple.bluetooth.sleep", 1.558),
    ]
    assert delays[1].raw_reason == "com.apple.bluetooth.sleep is slow(1558 ms)"
    assert delays[1].extra["ack_domain"] == "pm"
    assert "com.apple.bluetooth.sleep is slow(1558 ms)" in delays[1].raw


def test_kernel_acks_only_sleep_section_and_dedup_accumulated_items():
    head = "2026-11-11 15:00:00 -0800 Kernel Client Acks  \t"
    line1 = head + "Delays to Wake notifications: [A driver is slow(msg: SetState to 1)(76 ms)] " \
                   "Delays to Sleep notifications: [AppleAVE2Driver driver is slow(msg: SetState to 0)(2031 ms)] "
    line2 = line1.replace("15:00:00", "15:05:00") + "[RTBuddy(GFX) driver is slow(msg: SetState to 2)(102 ms)] "
    ev = log_collector(f"{line1}\n{line2}\n").collect_events(utc(2026, 11, 11, 22), utc(2026, 11, 12))
    delays = of(ev, EventKind.SLEEP_DELAY)
    assert [(d.actor, d.duration_s, d.extra["msg"]) for d in delays] == [
        ("AppleAVE2Driver", 2.031, "SetState to 0"),
        ("RTBuddy(GFX)", 0.102, "SetState to 2"),
    ]
    assert all(d.extra["ack_domain"] == "kernel" for d in delays)


def test_idle_sleep_on_ac_then_full_wake():
    since, until = utc(2026, 11, 12, 19, 0), utc(2026, 11, 12, 19, 30)
    ev = log_collector(load_fixture("macos", "pmset_log__idle_sleep_ac.txt")).collect_events(since, until)
    assert_window(ev, since, until)
    first = of(ev, EventKind.SLEEP)[0]
    assert (first.sleep_type, first.user_initiated, first.source, first.charge_pct) == ("Idle Sleep", True, PowerSource.AC, 45)
    wake = of(ev, EventKind.WAKE)
    assert len(wake) == 1
    w = wake[0]
    assert w.ts == utc(2026, 11, 12, 19, 28, 43)
    assert w.raw_reason == "HID Activity"
    assert w.source == PowerSource.AC and w.charge_pct == 64
    assert w.extra["transition"] == "darkwake_to_fullwake"
    assert "AOP.OutboxNotEmpty voice_trigger/" in {d.raw_reason for d in of(ev, EventKind.DARK_WAKE)}


def test_lid_wake_fixture():
    since, until = utc(2026, 11, 13, 4, 10), utc(2026, 11, 13, 4, 25)
    ev = log_collector(load_fixture("macos", "pmset_log__lid_wake.txt")).collect_events(since, until)
    assert_window(ev, since, until)
    wakes = of(ev, EventKind.WAKE)
    assert wakes[0].raw_reason == "smc.sysState.Wake(0x70070000) lid SMC.OutboxNotEmpty/HID Activity"
    assert wakes[0].duration_s == 68.0 and wakes[0].charge_pct == 100
    assert "transition" not in wakes[0].extra
    assert wakes[1].raw_reason == "smc.sysState.Wake(0x70070000) trackpadkeyboard SMC.OutboxNotEmpty/UserActivity Assertion"
    assert wakes[1].duration_s is None


def test_window_bounds_inclusive_exclusive():
    text = load_fixture("macos", "pmset_log__wake_storm.txt")
    # 15:14:24 -0800 dark wake == 23:14:24Z
    ev = log_collector(text).collect_events(utc(2026, 11, 11, 23, 14, 24), utc(2026, 11, 11, 23, 16, 34))
    dark = of(ev, EventKind.DARK_WAKE)
    assert [d.ts for d in dark] == [utc(2026, 11, 11, 23, 14, 24)]  # since included, until (23:16:34) excluded


def test_explicit_offsets_are_honored_across_dst():
    lines = [
        "2026-11-01 01:30:00 -0700 Sleep               \tEntering Sleep state due to 'Idle Sleep': Using AC (Charge:100%) 10 secs",
        "2026-11-01 01:30:00 -0800 Sleep               \tEntering Sleep state due to 'Idle Sleep': Using AC (Charge:100%) 10 secs",
    ]
    ev = log_collector("\n".join(lines)).collect_events(utc(2026, 11, 1), utc(2026, 11, 2))
    assert [e.ts for e in ev] == [utc(2026, 11, 1, 8, 30), utc(2026, 11, 1, 9, 30)]
    assert all(e.extra.get("tz_ambiguous") is None for e in ev)


def test_unknown_sleep_label_and_reason_kept_verbatim():
    lines = [
        "2026-11-11 15:00:00 -0800 Sleep               \tEntering Sleep state due to 'Thermal Emergency Sleep': Using Batt (Charge:3%) 9 secs",
        "2026-11-11 15:01:00 -0800 DarkWake            \tsomething new and unexpected",
    ]
    ev = log_collector("\n".join(lines)).collect_events(utc(2026, 11, 11, 22), utc(2026, 11, 12))
    assert ev[0].sleep_type == "Thermal Emergency Sleep" and ev[0].user_initiated is None
    assert ev[1].kind == EventKind.DARK_WAKE and ev[1].raw_reason == "something new and unexpected"
    assert ev[1].source == PowerSource.UNKNOWN and ev[1].charge_pct is None


# --------------------------------------------------------------------- early window filter
MALFORMED_OLD = "2026-11-01 25:61:99 -0800 Sleep               \tEntering Sleep state due to 'Clamshell Sleep' garbage"
MALFORMED_NEW = "2026-11-30 25:61:99 -0800 DarkWake            \tgarbage"


def test_malformed_out_of_window_lines_are_never_parsed():
    text = MALFORMED_OLD + "\n" + load_fixture("macos", "pmset_log__wake_storm.txt") + MALFORMED_NEW + "\n"
    ev = log_collector(text).collect_events(utc(2026, 11, 11, 22, 55), utc(2026, 11, 11, 23, 40))
    assert len(of(ev, EventKind.SLEEP)) == 9


def test_malformed_in_window_line_raises_parse_error():
    with pytest.raises(CollectorError) as ei:
        log_collector(MALFORMED_OLD).collect_events(utc(2026, 10, 31), utc(2026, 11, 3))
    assert ei.value.code == ErrorCode.PARSE_ERROR
    assert "25:61:99" in ei.value.message


def test_out_of_window_lines_skip_full_parse(monkeypatch):
    text = load_fixture("macos", "pmset_log__wake_storm.txt")
    calls: list[str] = []
    real = MacOSCollector._parse_record

    def counting(self, line, *a, **kw):
        calls.append(line)
        return real(self, line, *a, **kw)

    monkeypatch.setattr(MacOSCollector, "_parse_record", counting)
    # Count regex calls too: none of the out-of-window lines may reach a regex.
    seen_by_regex: list[str] = []
    real_match = macos_mod._TS_SHAPE

    class Spy:
        def match(self, s, *a):
            seen_by_regex.append(s)
            return real_match.match(s, *a)

    monkeypatch.setattr(macos_mod, "_TS_SHAPE", Spy())

    since, until = utc(2026, 11, 11, 23, 17), utc(2026, 11, 11, 23, 18)  # 15:17:00..15:18:00 -0800
    log_collector(text).collect_events(since, until)

    in_window = [l for l in text.splitlines() if "2026-11-11 15:17:00" <= l[:19] < "2026-11-11 15:18:00"]
    after_releases = [
        l for l in text.splitlines()
        if l[:19] >= "2026-11-11 15:18:00" and l[26:36] == "Assertions"
        and any(f") {w} " in l for w in ("Released", "TimedOut", "ClientDied", "CapExpired"))
    ]
    assert in_window and len(text.splitlines()) > 5 * len(in_window)
    assert sorted(calls) == sorted(in_window + after_releases)
    assert sorted(seen_by_regex) == sorted(calls)
    assert not any(l[:19] < "2026-11-11 15:17:00" for l in calls)


# ------------------------------------------------------------------------------ blockers
ASSERT = "{ts} -0800 Assertions          \tPID {pid}({proc}) {action} {atype} \"{name}\" {held}  id:0x0x{aid} [System: PrevIdle]"


def a_line(ts, action, held, aid, atype="PreventUserIdleSystemSleep", proc="Brave Browser", name="Playing audio", pid=688):
    return ASSERT.format(ts=ts, pid=pid, proc=proc, action=action, atype=atype, name=name, held=held, aid=aid)


def test_blocker_intervals_overlap_window():
    since, until = utc(2026, 11, 11, 23, 0), utc(2026, 11, 11, 23, 30)  # 15:00..15:30 -0800
    lines = [
        a_line("2026-11-11 14:50:00", "Released", "00:05:00", "1"),          # ended before since: out
        a_line("2026-11-11 15:10:00", "Released", "00:20:00", "2"),          # started before since: in
        a_line("2026-11-11 15:20:00", "Created", "00:00:00", "3"),           # never released: in, end None
        a_line("2026-11-11 15:25:00", "Created", "00:00:00", "4"),
        a_line("2026-11-11 16:00:00", "Released", "00:35:00", "4"),          # released after until: in
        a_line("2026-11-11 16:10:00", "TimedOut", "00:05:00", "5"),          # wholly after: out
        a_line("2026-11-11 15:12:00", "Released", "00:01:00", "6", atype="PreventUserIdleDisplaySleep"),  # display only
        a_line("2026-11-11 15:12:00", "Summary", "00:01:00", "7"),           # snapshot only
        "2026-11-11 15:13:00 -0800 Assertions          \tKernel Idle sleep preventers: IOPMrootDomain",
    ]
    ev = log_collector("\n".join(lines)).collect_events(since, until)
    assert all(e.kind == EventKind.SLEEP_BLOCKER for e in ev)
    by_id = {e.raw.split("id:0x0x")[1].split()[0]: e for e in ev}
    assert set(by_id) == {"2", "3", "4"}
    assert by_id["2"].ts == utc(2026, 11, 11, 22, 50) and by_id["2"].end == utc(2026, 11, 11, 23, 10)
    assert by_id["2"].duration_s == 1200.0 and by_id["2"].actor == "Brave Browser"
    assert by_id["2"].raw_reason == "Playing audio"
    assert by_id["2"].extra == {"pid": "688", "assertion_type": "PreventUserIdleSystemSleep", "action": "Released"}
    assert by_id["3"].end is None and by_id["3"].extra["release_not_logged"] == "1"
    assert by_id["4"].ts == utc(2026, 11, 11, 23, 25) and by_id["4"].end == utc(2026, 11, 12, 0, 0)
    assert ev == sorted(ev, key=lambda e: e.ts)


def test_blocker_raw_and_actor_are_redacted():
    line = a_line("2026-11-11 15:10:00", "Released", "00:01:00", "9", proc="sharingd",
                  name="Handoff to a1:b2:c3:d4:e5:f6 /Users/jane/x")
    ev = log_collector(line).collect_events(utc(2026, 11, 11, 23), utc(2026, 11, 12))
    assert "a1:b2" not in ev[0].raw and "<mac>" in ev[0].raw and "jane" not in ev[0].raw


def test_current_blockers_fixture():
    c = make({(PMSET, "-g", "assertions"): load_fixture("macos", "pmset_assertions__caffeinate.txt")})
    bl = c.current_blockers()
    assert [b.actor for b in bl] == ["powerd", "caffeinate"]  # sorted by start; display/user-activity excluded
    caf = bl[1]
    assert caf.kind == EventKind.SLEEP_BLOCKER and caf.end is None
    assert caf.raw_reason == "caffeinate command-line tool"
    assert caf.duration_s == 131.0 and caf.ts == NOW - timedelta(seconds=131)
    assert caf.extra["assertion_type"] == "PreventUserIdleSystemSleep"
    assert caf.extra["details"] == "caffeinate asserting for 300 secs"
    assert bl[0].raw_reason == "Powerd - Prevent sleep while display is on"


# -------------------------------------------------------------------------- battery
def test_battery_status_fixture_charging():
    st = make({(PMSET, "-g", "batt"): load_fixture("macos", "pmset_batt__charging.txt")}).battery_status()
    assert st.has_battery and st.percent == 43 and st.on_ac is True
    assert st.state == ChargeState.CHARGING
    assert st.minutes_remaining == 97 and st.estimate_kind == EstimateKind.TO_FULL
    assert st.settling is False and st.sampled_at == NOW


@pytest.mark.parametrize(
    "body,state,mins,kind,on_ac",
    [
        ("Now drawing from 'Battery Power'\n -InternalBattery-0 (id=1)\t85%; discharging; 5:12 remaining present: true",
         ChargeState.DISCHARGING, 312, EstimateKind.TO_EMPTY, False),
        ("Now drawing from 'Battery Power'\n -InternalBattery-0 (id=1)\t85%; discharging; (no estimate) present: true",
         ChargeState.DISCHARGING, None, None, False),
        ("Now drawing from 'AC Power'\n -InternalBattery-0 (id=1)\t100%; charged; 0:00 remaining present: true",
         ChargeState.FULL, None, None, True),
        ("Now drawing from 'AC Power'\n -InternalBattery-0 (id=1)\t80%; AC attached; not charging present: true",
         ChargeState.NOT_CHARGING, None, None, True),
        ("Now drawing from 'AC Power'\n -InternalBattery-0 (id=1)\t5%; charging; 1092:15 remaining present: true",
         ChargeState.CHARGING, None, None, True),  # 65535-minute style sentinel
    ],
)
def test_battery_status_variants(body, state, mins, kind, on_ac):
    st = make({(PMSET, "-g", "batt"): body}).battery_status()
    assert (st.state, st.minutes_remaining, st.estimate_kind, st.on_ac) == (state, mins, kind, on_ac)


def test_battery_status_desktop():
    st = make({(PMSET, "-g", "batt"): "Now drawing from 'AC Power'\n"}).battery_status()
    assert st.has_battery is False and st.percent is None and st.on_ac is True


def test_battery_health_fixture():
    c = make({
        (IOREG, "-rn", "AppleSmartBattery"): load_fixture("macos", "ioreg_battery__apple_silicon.txt"),
        (SYSTEM_PROFILER, "SPPowerDataType"): load_fixture("macos", "system_profiler_power__normal.txt"),
    })
    h = c.battery_health()
    assert (h.design_capacity, h.full_charge_capacity, h.capacity_unit) == (8694.0, 7442.0, "mAh")
    assert h.health_pct == 85.6 and h.cycle_count == 431 and h.condition == "Normal"
    assert h.temperature_c == 30.55
    assert "serial" not in str(h.to_dict()).lower()
    assert c.warnings == []


def test_battery_health_condition_optional():
    c = make({
        (IOREG, "-rn", "AppleSmartBattery"): load_fixture("macos", "ioreg_battery__apple_silicon.txt"),
        (SYSTEM_PROFILER, "SPPowerDataType"): CollectorError(ErrorCode.TIMEOUT, "system_profiler timed out"),
    })
    h = c.battery_health()
    assert h.condition is None and h.health_pct == 85.6
    assert len(c.warnings) == 1 and "condition" in c.warnings[0].lower()


def test_battery_health_intel_style_and_sentinels():
    body = '\n'.join([
        '+-o AppleSmartBattery  <class AppleSmartBattery>', '    {',
        '      "MaxCapacity" = 4000', '      "DesignCapacity" = 5000', '      "CycleCount" = 65535',
        '      "Temperature" = 65535', '    }',
    ])
    h = make({(IOREG, "-rn", "AppleSmartBattery"): body, (SYSTEM_PROFILER,): ""}).battery_health()
    assert h.full_charge_capacity == 4000.0 and h.health_pct == 80.0
    assert h.cycle_count is None and h.temperature_c is None


def test_battery_health_no_battery():
    with pytest.raises(CollectorError) as ei:
        make({(IOREG, "-rn", "AppleSmartBattery"): ""}).battery_health()
    assert ei.value.code == ErrorCode.NO_BATTERY and ei.value.remediation


# -------------------------------------------------------------------------- settings
def test_power_settings_fixture():
    s = make({(PMSET, "-g", "custom"): load_fixture("macos", "pmset_custom__default.txt")}).power_settings()
    d = {(x.scope, x.name): x for x in s}
    assert {x.scope for x in s} == {"battery", "ac"}
    assert d[("battery", "powernap")].value == "1"
    assert d[("ac", "womp")].value == "1" and d[("battery", "womp")].value == "0"
    assert d[("battery", "tcpkeepalive")].native_name == "tcpkeepalive"
    sob = d[("ac", "sleep_on_power_button")]
    assert sob.native_name == "Sleep On Power Button" and sob.value == "1"
    assert d[("ac", "hibernatefile")].value == "/var/vm/sleepimage"
    assert ("battery", "lessbright") in d and ("ac", "lessbright") not in d


# -------------------------------------------------------------------------- errors / hygiene
def test_runner_error_propagates_as_collector_error():
    c = make({(PMSET, "-g", "log"): CollectorError(ErrorCode.TIMEOUT, "pmset timed out")})
    with pytest.raises(CollectorError) as ei:
        c.collect_events(utc(2026, 11, 11), utc(2026, 11, 12))
    assert ei.value.code == ErrorCode.TIMEOUT


def test_naive_window_rejected():
    with pytest.raises(CollectorError):
        log_collector("").collect_events(datetime(2026, 11, 11), utc(2026, 11, 12))


def test_no_live_commands_run():
    r = FakeRunner({(PMSET, "-g", "log"): load_fixture("macos", "pmset_log__lid_wake.txt")})
    MacOSCollector(runner=r, local_tz=LA, now=lambda: NOW).collect_events(utc(2026, 11, 13), utc(2026, 11, 14))
    assert r.calls == [(PMSET, "-g", "log")]


@pytest.mark.parametrize("path", sorted((FIXTURES / "macos").glob("*.txt")), ids=lambda p: p.name)
def test_fixture_hygiene(path):
    text = path.read_text(encoding="utf-8")
    assert len(text.encode()) < 200 * 1024
    assert redact(text) == text  # already redacted
    for line in text.splitlines():
        if '"Serial"' in line:
            assert '"Serial"="<serial>"' in line and line.count('"Serial"') == line.count('"Serial"="<serial>"')
        assert "Serial Number" not in line
