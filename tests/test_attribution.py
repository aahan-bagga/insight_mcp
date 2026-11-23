# Tests for insight_mcp.attribution using hand-written events (no collectors, no I/O).

from datetime import datetime, timedelta

import pytest

from conftest import utc
from insight_mcp import attribution as A
from insight_mcp.attribution import RULES, attribute, attribute_blockers, build_sessions, classify_event, suggest_settings
from insight_mcp.schema import (
    BatteryHealth,
    Cause,
    Confidence,
    EventKind,
    Platform,
    PowerEvent,
    PowerSetting,
    PowerSource,
)

M, W, L = Platform.MACOS, Platform.WINDOWS, Platform.LINUX
T0 = utc(2026, 11, 16, 0, 0, 0)


def ev(kind: EventKind, platform: Platform, *, ts: datetime = T0, reason: str | None = None,
       raw: str | None = None, actor: str | None = None, **kw) -> PowerEvent:
    return PowerEvent(ts=ts, kind=kind, platform=platform, raw=raw if raw is not None else (reason or actor or ""),
                      raw_reason=reason, actor=actor, **kw)


def mac_dark(reason: str, ts: datetime = T0, pct: int | None = None) -> PowerEvent:
    raw = (f"2026-11-16 00:00:00 -0800 DarkWake  \tDarkWake from Deep Idle [CDNP] : due to {reason} "
           f"Using BATT (Charge:{pct if pct is not None else 80}%) 45 secs")
    return ev(EventKind.DARK_WAKE, M, ts=ts, reason=reason, raw=raw, charge_pct=pct, source=PowerSource.BATTERY)


# =========================================================================== RULES table
def test_rule_ids_unique_and_well_formed():
    ids = [r.id for r in RULES]
    assert len(ids) == len(set(ids))
    for r in RULES:
        assert r.platforms and r.kinds


CASES = [
    # --- macOS (pmset -g log "due to ..." text)
    (M, EventKind.WAKE, "EC.LidOpen/Lid Open", None, Cause.USER_INPUT, "macos.wake.lid"),
    (M, EventKind.WAKE, "EC.PowerButton/User", None, Cause.USER_INPUT, "macos.wake.power_button"),
    (M, EventKind.WAKE, "HID Activity", None, Cause.USER_INPUT, "macos.wake.hid"),
    (M, EventKind.WAKE, "UserActivity Assertion", None, Cause.USER_INPUT, "macos.wake.useractivity"),
    (M, EventKind.DARK_WAKE, "smc.70070000 wifibt SMC.OutboxNotEmpty", None, Cause.WIRELESS_UNSPECIFIED,
     "macos.darkwake.wifibt"),
    (M, EventKind.DARK_WAKE, "EC.ACAttach/", None, Cause.CHARGER, "macos.wake.charger"),
    (M, EventKind.DARK_WAKE, "NUB.SPMI0.SW3 RTC/Maintenance", None, Cause.SCHEDULED_MAINTENANCE, "macos.darkwake.rtc"),
    (M, EventKind.DARK_WAKE, "RTC/SleepService", None, Cause.SCHEDULED_MAINTENANCE, "macos.darkwake.rtc"),
    (M, EventKind.DARK_WAKE, "ARPT/Network", None, Cause.NETWORK, "macos.darkwake.network"),
    (M, EventKind.DARK_WAKE, "en0/MagicPacket", None, Cause.NETWORK, "macos.darkwake.network"),
    (M, EventKind.DARK_WAKE, "BT.OutboxNotEmpty", None, Cause.BLUETOOTH, "macos.darkwake.bluetooth"),
    (M, EventKind.WAKE, "XHC1/USB", None, Cause.USB_DEVICE, "macos.wake.usb"),
    # --- Windows (Power-Troubleshooter Event 1 "Wake Source", Modern Standby exit reasons)
    (W, EventKind.WAKE, "Wake Source: Power Button", None, Cause.USER_INPUT, "windows.wake.power_button"),
    (W, EventKind.WAKE, "Exit Reason: Lid", None, Cause.USER_INPUT, "windows.wake.lid"),
    (W, EventKind.WAKE, "Wake Source: Device -HID Keyboard Device", None, Cause.USER_INPUT, "windows.wake.hid"),
    (W, EventKind.WAKE, "Exit Reason: Input Keyboard", None, Cause.USER_INPUT, "windows.wake.hid"),
    (W, EventKind.WAKE, "Wake Source: Device -Microsoft AC Adapter", None, Cause.CHARGER, "windows.wake.charger"),
    (W, EventKind.DARK_WAKE, "Exit Reason: ACDC Power Source", None, Cause.CHARGER, "windows.wake.charger"),
    (W, EventKind.WAKE, "Wake Source: Timer - Windows will execute 'NT TASK\\Microsoft\\Windows\\UpdateOrchestrator\\"
                        "Reboot' scheduled task that requested waking the computer.", None,
     Cause.SCHEDULED_MAINTENANCE, "windows.wake.timer"),
    (W, EventKind.DARK_WAKE, "Exit Reason: PDC Task Clock", None, Cause.SCHEDULED_MAINTENANCE, "windows.wake.timer"),
    (W, EventKind.WAKE, "Wake Source: Device -Intel(R) Wireless Bluetooth(R)", None, Cause.BLUETOOTH,
     "windows.wake.bluetooth"),
    (W, EventKind.WAKE, "Wake Source: Device -Intel(R) Wi-Fi 6 AX201 160MHz", None, Cause.NETWORK,
     "windows.wake.network"),
    (W, EventKind.WAKE, "Wake Source: Device -Realtek PCIe GbE Family Controller", None, Cause.NETWORK,
     "windows.wake.network"),
    (W, EventKind.WAKE, "Wake Source: Device -USB Root Hub (USB 3.0)", None, Cause.USB_DEVICE, "windows.wake.usb"),
    # --- Linux (wakeup_sources names, ACPI ids, logind messages)
    (L, EventKind.WAKE, "Lid opened.", None, Cause.USER_INPUT, "linux.wake.lid"),
    (L, EventKind.WAKE, "PNP0C0C:00", None, Cause.USER_INPUT, "linux.wake.power_button"),
    (L, EventKind.WAKE, "i8042", None, Cause.USER_INPUT, "linux.wake.hid"),
    (L, EventKind.WAKE, "ACPI0003:00", None, Cause.CHARGER, "linux.wake.charger"),
    (L, EventKind.DARK_WAKE, "rtc0", None, Cause.SCHEDULED_MAINTENANCE, "linux.wake.rtc"),
    (L, EventKind.WAKE, "alarmtimer.0.auto", None, Cause.SCHEDULED_MAINTENANCE, "linux.wake.rtc"),
    (L, EventKind.WAKE, "hci0", None, Cause.BLUETOOTH, "linux.wake.bluetooth"),
    (L, EventKind.WAKE, "btusb", None, Cause.BLUETOOTH, "linux.wake.bluetooth"),
    (L, EventKind.WAKE, "iwlwifi", None, Cause.NETWORK, "linux.wake.network"),
    (L, EventKind.WAKE, "enp0s31f6", None, Cause.NETWORK, "linux.wake.network"),
    (L, EventKind.WAKE, "xhci_hcd", None, Cause.USB_DEVICE, "linux.wake.usb"),
    (L, EventKind.WAKE, "XHC", None, Cause.USB_DEVICE, "linux.wake.usb"),
]


@pytest.mark.parametrize("platform,kind,reason,actor,cause,rule_id", CASES)
def test_classify_wake_reasons(platform, kind, reason, actor, cause, rule_id):
    c, conf, rid = classify_event(ev(kind, platform, reason=reason, actor=actor))
    assert (c, rid) == (cause, rule_id)
    assert conf in (Confidence.HIGH, Confidence.MEDIUM)


BLOCKER_CASES = [
    (M, "coreaudiod", 'pid 412(coreaudiod): [0x000a0000000197d0] 00:10:23 PreventUserIdleSystemSleep named: '
                      '"com.apple.audio.context123.preventuseridlesleep"', Cause.SYSTEM_KEEPING_AWAKE,
     "macos.blocker.system"),
    (M, "backupd", 'pid 288(backupd): [0x0001] 00:20:00 PreventUserIdleSystemSleep named: "Time Machine"',
     Cause.SYSTEM_KEEPING_AWAKE, "macos.blocker.system"),
    (M, "Google Chrome", 'pid 911(Google Chrome): [0x0002] 01:02:03 PreventUserIdleSystemSleep named: "Playing audio"',
     Cause.APP_KEEPING_AWAKE, "any.blocker.app"),
    (W, "Realtek High Definition Audio(SST)",
     "[DRIVER] Realtek High Definition Audio(SST) (HDAUDIO\\FUNC_01&VEN_10EC)\nAn audio stream is currently in use.",
     Cause.SYSTEM_KEEPING_AWAKE, "windows.blocker.system"),
    (W, "Legacy Kernel Caller", "[DRIVER] Legacy Kernel Caller", Cause.SYSTEM_KEEPING_AWAKE, "windows.blocker.system"),
    (W, "\\Device\\HarddiskVolume3\\Program Files\\Google\\Chrome\\Application\\chrome.exe",
     "[PROCESS] \\Device\\HarddiskVolume3\\Program Files\\Google\\Chrome\\Application\\chrome.exe\nVideo Wake Lock",
     Cause.APP_KEEPING_AWAKE, "windows.blocker.process"),
    (L, "NetworkManager", "NetworkManager  0  root  1234  NetworkManager  sleep  NetworkManager needs to turn off networks  delay",
     Cause.SYSTEM_KEEPING_AWAKE, "linux.blocker.system"),
    (L, "firefox", "firefox  1000  user  4321  firefox  idle  audio-playing  block",
     Cause.APP_KEEPING_AWAKE, "any.blocker.app"),
]


@pytest.mark.parametrize("platform,actor,raw,cause,rule_id", BLOCKER_CASES)
def test_classify_blockers(platform, actor, raw, cause, rule_id):
    # raw_reason that mentions audio must not make an app look like the system service
    e = ev(EventKind.SLEEP_BLOCKER, platform, actor=actor, raw=raw, reason="Playing audio")
    c, _, rid = classify_event(e)
    assert (c, rid) == (cause, rule_id)


def test_power_source_is_charger_and_sleep_delay_is_slow_entry():
    ps = ev(EventKind.POWER_SOURCE, M, raw="Summary- [System: DeclUser kDisp] Using AC(Charge: 54)",
            source=PowerSource.AC)
    assert classify_event(ps)[:2] == (Cause.CHARGER, Confidence.HIGH)
    sd = ev(EventKind.SLEEP_DELAY, W, actor="nvlddmkm", raw="Event 42: driver nvlddmkm delayed sleep", duration_s=12.0)
    assert classify_event(sd)[0] is Cause.SLOW_SLEEP_ENTRY


@pytest.mark.parametrize("platform,reason,raw", [
    (M, "NUB.SPMI0.SW3 SMC.OutboxNotEmpty", "DarkWake from Deep Idle [CDNP] : due to NUB.SPMI0.SW3 SMC.OutboxNotEmpty "
                                            "Using AC (Charge:80%) 45 secs"),
    (W, "Wake Source: Unknown", "The system has returned from a low power state. Wake Source: Unknown"),
    (L, "PM: Triggering wakeup from IRQ 9", "kernel: PM: Triggering wakeup from IRQ 9"),
])
def test_unmatched_reason_falls_back_to_unknown(platform, reason, raw):
    assert classify_event(ev(EventKind.WAKE, platform, reason=reason, raw=raw)) == (
        Cause.UNKNOWN, Confidence.LOW, "fallback.unknown")


def test_rules_are_platform_scoped():
    # "rtc0" is a Linux wake source; on Windows it should not match the Linux RTC rule
    assert classify_event(ev(EventKind.WAKE, W, reason="rtc0"))[0] is Cause.UNKNOWN
    # SLEEP events have no rules
    assert classify_event(ev(EventKind.SLEEP, M, reason="Clamshell Sleep"))[0] is Cause.UNKNOWN


def test_unknown_wakes_produce_low_confidence_attribution_with_inspect_fix():
    atts = attribute([ev(EventKind.WAKE, W, reason="Wake Source: Unknown")])
    assert len(atts) == 1
    a = atts[0]
    assert a.cause is Cause.UNKNOWN and a.confidence is Confidence.LOW
    assert "best guess" in a.explanation
    assert a.suggested_fix and "powercfg" in (a.suggested_fix.command or "")


# =========================================================================== sessions
def _sleep(ts, pct, source=PowerSource.BATTERY, user=True, platform=M):
    return ev(EventKind.SLEEP, platform, ts=ts, raw=f"Sleep Entering Sleep state due to 'Clamshell Sleep' (Charge:{pct}%)",
              charge_pct=pct, source=source, user_initiated=user, sleep_type="Clamshell Sleep")


def _wake(ts, pct, reason="EC.LidOpen/Lid Open", platform=M, source=PowerSource.BATTERY):
    return ev(EventKind.WAKE, platform, ts=ts, reason=reason, raw=f"Wake from Deep Idle : due to {reason} (Charge:{pct}%)",
              charge_pct=pct, source=source)


def test_basic_session_drain_and_dark_wakes():
    events = [
        _sleep(T0, 90),
        mac_dark("ARPT/Network", T0 + timedelta(hours=1), 88),
        ev(EventKind.SLEEP, M, ts=T0 + timedelta(hours=1, seconds=40), raw="Maintenance Sleep",
           user_initiated=False, sleep_type="Maintenance Sleep"),
        mac_dark("NUB.SPMI0.SW3 RTC/Maintenance", T0 + timedelta(hours=2), 86),
        _wake(T0 + timedelta(hours=4), 82),
    ]
    [s] = build_sessions(events)
    assert s.start == T0 and s.end == T0 + timedelta(hours=4)
    assert (s.start_pct, s.end_pct) == (90, 82)
    assert s.drain_pct_per_hour == 2.0
    assert s.dark_wake_count == 2
    assert s.wake_causes == {"network": 1, "scheduled_maintenance": 1}
    assert s.woke_by is Cause.USER_INPUT


def test_maintenance_sleep_does_not_start_session():
    events = [ev(EventKind.SLEEP, M, raw="Maintenance Sleep", user_initiated=False),
              _wake(T0 + timedelta(hours=1), 80)]
    assert build_sessions(events) == []


def test_session_split_on_power_source_change():
    events = [
        _sleep(T0, 50),
        ev(EventKind.POWER_SOURCE, M, ts=T0 + timedelta(hours=2), raw="Using AC (Charge:46%)",
           source=PowerSource.AC, charge_pct=46),
        _wake(T0 + timedelta(hours=5), 100, source=PowerSource.AC),
    ]
    s1, s2 = build_sessions(events)
    assert s1.source is PowerSource.BATTERY and s2.source is PowerSource.AC
    assert s1.end == s2.start == T0 + timedelta(hours=2)
    assert s1.woke_by is Cause.CHARGER and s2.woke_by is Cause.USER_INPUT
    assert s1.drain_pct_per_hour == 2.0
    assert s2.drain_pct_per_hour is None  # on AC


def test_short_or_unknown_charge_session_has_no_drain():
    short = [_sleep(T0, 90), _wake(T0 + timedelta(minutes=20), 89)]
    assert build_sessions(short)[0].drain_pct_per_hour is None
    unknown = [ev(EventKind.SLEEP, M, raw="Sleep", user_initiated=None, source=PowerSource.BATTERY),
               ev(EventKind.WAKE, M, ts=T0 + timedelta(hours=3), reason="EC.LidOpen")]
    s = build_sessions(unknown)[0]
    assert s.drain_pct_per_hour is None and s.start_pct is None


def test_session_discarded_on_boot_without_wake():
    events = [_sleep(T0, 5), ev(EventKind.BOOT, M, ts=T0 + timedelta(hours=8), raw="boot"),
              _wake(T0 + timedelta(hours=9), 50)]
    assert build_sessions(events) == []


# =========================================================================== heuristics
def test_wake_storm_detected():
    storm = [mac_dark("ARPT/Network", T0 + timedelta(minutes=i)) for i in range(7)]
    lone = [mac_dark("ARPT/Network", T0 + timedelta(hours=3 + i)) for i in range(2)]
    atts = attribute(storm + lone)
    storms = [a for a in atts if a.explanation.startswith("Wake storm")]
    assert len(storms) == 1
    assert storms[0].cause is Cause.NETWORK and storms[0].event_count == 7
    assert storms[0].confidence is Confidence.MEDIUM
    assert 1 <= len(storms[0].evidence) <= 5


def test_no_wake_storm_below_threshold():
    sparse = [mac_dark("ARPT/Network", T0 + timedelta(minutes=2 * i)) for i in range(6)]  # 6 within exactly 10 min (inclusive)
    assert any(a.explanation.startswith("Wake storm") for a in attribute(sparse))
    sparser = [mac_dark("ARPT/Network", T0 + timedelta(minutes=3 * i)) for i in range(6)]  # spans 15 min
    assert not any(a.explanation.startswith("Wake storm") for a in attribute(sparser))


def _blocker(start_min, end_min, actor="Google Chrome", platform=M):
    return ev(EventKind.SLEEP_BLOCKER, platform, ts=T0 + timedelta(minutes=start_min),
              end=T0 + timedelta(minutes=end_min), actor=actor,
              raw=f'pid 911({actor}): PreventUserIdleSystemSleep named: "Playing audio"')


def test_overlapping_blocker_intervals_counted_once():
    blockers = [_blocker(0, 60), _blocker(30, 90), _blocker(120, 150), _blocker(0, 600, actor="coreaudiod")]
    held = A._held_by_actor(blockers, T0)
    assert held["Google Chrome"] == 120 * 60  # [0,90] + [120,150], not 60+60+30
    assert held["coreaudiod"] == 600 * 60
    atts = attribute(blockers)
    chrome = next(a for a in atts if a.subject == "Google Chrome")
    assert chrome.cause is Cause.APP_KEEPING_AWAKE and chrome.event_count == 3
    assert "2.0 h" in chrome.explanation and "counted once" in chrome.explanation
    core = next(a for a in atts if a.subject == "coreaudiod")
    assert core.cause is Cause.SYSTEM_KEEPING_AWAKE


def test_blockers_ranked_by_time_held_not_record_count():
    # 50 one-minute records (50 min) vs one 10-hour record: the 10-hour blocker must rank first.
    chatty = [_blocker(i * 2, i * 2 + 1, actor="nsurlsessiond") for i in range(50)]
    long_one = [_blocker(0, 600, actor="caffeinate")]
    atts = attribute(chatty + long_one)
    assert [a.subject for a in atts[:2]] == ["caffeinate", "nsurlsessiond"]
    assert atts[0].impact_s == 600 * 60 and atts[1].impact_s == 50 * 60

def test_open_blocker_uses_duration_then_input_horizon():
    open_with_dur = ev(EventKind.SLEEP_BLOCKER, M, actor="zoom.us", raw="pid 1(zoom.us)", duration_s=600.0)
    open_no_dur = ev(EventKind.SLEEP_BLOCKER, M, actor="Spotify", raw="pid 2(Spotify)")
    held = A._held_by_actor([open_with_dur, open_no_dur], T0 + timedelta(hours=1))
    assert held == {"zoom.us": 600.0, "Spotify": 3600.0}


def test_attribute_blockers_live_one_per_actor():
    live = [
        ev(EventKind.SLEEP_BLOCKER, W, actor="\\Device\\HarddiskVolume3\\Program Files\\Mozilla Firefox\\firefox.exe",
           raw="[PROCESS] \\Device\\HarddiskVolume3\\Program Files\\Mozilla Firefox\\firefox.exe\nPlaying audio",
           duration_s=300.0),
        ev(EventKind.SLEEP_BLOCKER, W, ts=T0 + timedelta(seconds=5),
           actor="\\Device\\HarddiskVolume3\\Program Files\\Mozilla Firefox\\firefox.exe",
           raw="[PROCESS] \\Device\\HarddiskVolume3\\Program Files\\Mozilla Firefox\\firefox.exe\nVideo Wake Lock",
           duration_s=295.0),
        ev(EventKind.SLEEP_BLOCKER, W, actor="Realtek High Definition Audio(SST)",
           raw="[DRIVER] Realtek High Definition Audio(SST)\nAn audio stream is currently in use."),
    ]
    atts = attribute_blockers(live)
    assert len(atts) == 2
    ff = atts[0]
    assert ff.cause is Cause.APP_KEEPING_AWAKE and ff.event_count == 2
    assert "firefox.exe" in ff.suggested_fix.command and ff.suggested_fix.requires_admin
    assert ff.suggested_fix.tradeoff
    drv = atts[1]
    assert drv.cause is Cause.SYSTEM_KEEPING_AWAKE and "unknown time" in drv.explanation


def test_high_drain_session_flagged():
    events = []
    t = T0
    for i, drain in enumerate([1, 1, 1, 5]):  # 3 normal nights, then one at 5%/h
        events.append(_sleep(t, 90))
        if i == 3:
            for k in range(3):
                events.append(mac_dark("smc.70070000 wifibt SMC.OutboxNotEmpty", t + timedelta(hours=1 + k)))
        events.append(_wake(t + timedelta(hours=4), 90 - 4 * drain))
        t += timedelta(days=1)
    atts = attribute(events)
    hi = [a for a in atts if "the median" in a.explanation]
    assert len(hi) == 1
    assert hi[0].cause is Cause.WIRELESS_UNSPECIFIED and hi[0].confidence is Confidence.LOW
    assert "5.0%/h" in hi[0].explanation and "5.0x" in hi[0].explanation
    assert 1 <= len(hi[0].evidence) <= 5


def test_battery_wear():
    h = BatteryHealth(design_capacity=5000, full_charge_capacity=3800, capacity_unit="mAh", health_pct=76.0,
                      cycle_count=812, condition="Service Recommended", temperature_c=30.1, sampled_at=T0)
    [a] = attribute([], health=h)
    assert a.cause is Cause.BATTERY_WEAR and a.evidence[0].ts == T0
    assert "76.0%" in a.explanation and "812 cycles" in a.explanation
    good = BatteryHealth(5000, 4500, "mAh", 90.0, 100, "Normal", None, T0)
    assert attribute([], health=good) == []


def test_slow_sleep_entry_attribution():
    d = [ev(EventKind.SLEEP_DELAY, L, ts=T0 + timedelta(hours=i), actor="nvidia",
            raw="PM: suspend of devices took 12.000 seconds", duration_s=12.0) for i in range(2)]
    [a] = attribute(d)
    assert a.cause is Cause.SLOW_SLEEP_ENTRY and a.subject == "nvidia" and "24 s" in a.explanation


# =========================================================================== settings
def _set(name, value, scope="battery", native=None, raw=None):
    return PowerSetting(name=name, value=value, scope=scope, native_name=native or name, raw=raw or f" {name} {value}")


@pytest.mark.parametrize("platform,setting,rule_id,admin", [
    (M, _set("powernap", "1"), "macos.setting.powernap", True),
    (M, _set("tcpkeepalive", "1", scope="all"), "macos.setting.tcpkeepalive", True),
    (M, _set("standby", "0"), "macos.setting.standby_off", True),
    (W, _set("wake_timers", "0x00000001", native="bd3b718a-0680-4d9d-8ab2-e1d2b4ac806d"),
     "windows.setting.wake_timers", False),
    (W, _set("connectivity_in_standby", "1"), "windows.setting.connectivity_in_standby", False),
    (W, _set("standby_timeout_s", "0"), "windows.setting.never_sleep", False),
    (L, _set("mem_sleep", "[s2idle] deep", scope="all"), "linux.setting.mem_sleep_s2idle", True),
    (L, _set("handle_lid_switch", "ignore", scope="all"), "linux.setting.lid_ignored", True),
])
def test_drain_relevant_settings_detected(platform, setting, rule_id, admin):
    [(s, rule)] = A._setting_findings([setting], platform)
    assert rule.id == rule_id
    att = A._setting_attribution(s, rule, T0)
    assert att.cause is Cause.SETTING and att.evidence[0].raw == setting.raw
    assert att.suggested_fix.requires_admin is admin
    assert att.suggested_fix.tradeoff


def test_harmless_settings_ignored():
    harmless = [_set("powernap", "1", scope="ac"), _set("powernap", "0"), _set("standby_timeout_s", "900"),
                _set("mem_sleep", "s2idle [deep]", scope="all")]
    for p in Platform:
        assert A._setting_findings(harmless, p) == []
    assert suggest_settings(harmless, M, observed_at=T0) == []


def test_suggest_settings_end_to_end():
    atts = suggest_settings([_set("powernap", "1")], M, observed_at=T0)
    assert atts[0].cause is Cause.SETTING
    assert atts[0].evidence[0].ts == T0
    assert atts[0].suggested_fix and atts[0].suggested_fix.requires_admin


def test_session_splits_on_source_field_without_power_source_event():
    # macOS logs no POWER_SOURCE events: a dark wake carrying a different source must split the session.
    start = ev(EventKind.SLEEP, M, ts=T0, raw="Sleep", source=PowerSource.AC, charge_pct=80, user_initiated=True)
    dw = ev(EventKind.DARK_WAKE, M, ts=T0 + timedelta(hours=2), reason="wifibt", raw="DarkWake",
            source=PowerSource.BATTERY, charge_pct=80)
    end = ev(EventKind.WAKE, M, ts=T0 + timedelta(hours=8), reason="lid", raw="Wake",
             source=PowerSource.BATTERY, charge_pct=70)
    sessions = build_sessions([start, dw, end])
    assert [s.source for s in sessions] == [PowerSource.AC, PowerSource.BATTERY]
    assert sessions[1].drain_pct_per_hour is not None


# =========================================================================== attribute() general
def test_ranking_and_evidence_bounds():
    events = [mac_dark("ARPT/Network", T0 + timedelta(hours=i)) for i in range(10)]
    events += [_wake(T0 + timedelta(hours=20), 50)]
    events += [ev(EventKind.WAKE, M, ts=T0 + timedelta(hours=21), reason="Mystery", raw="Wake due to Mystery")]
    atts = attribute(events)
    assert atts[0].cause is Cause.NETWORK and atts[0].event_count == 10
    assert "per hour" in atts[0].explanation
    keys = [(a.impact_s or 0.0, a.event_count * A._WEIGHT[a.confidence]) for a in atts]
    assert keys == sorted(keys, reverse=True)
    for a in atts:
        assert 1 <= len(a.evidence) <= 5
        for e in a.evidence:
            assert e.ts.utcoffset() == timedelta(0)


def test_attribute_is_pure_and_order_independent():
    events = [mac_dark("ARPT/Network", T0 + timedelta(minutes=i)) for i in range(8)]
    a1 = attribute(events)
    a2 = attribute(list(reversed(events)))
    assert [x.to_dict() for x in a1] == [x.to_dict() for x in a2]
