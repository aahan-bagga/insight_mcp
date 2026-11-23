# LinuxCollector tests. Fixtures replay real Linux output formats through the real code path.

import json
import re
from datetime import timezone
from zoneinfo import ZoneInfo

import pytest

from insight_mcp.collectors.base import CollectorError, ErrorCode
from insight_mcp.collectors.linux import LinuxCollector
from insight_mcp.schema import ChargeState, EstimateKind, EventKind, Platform, PowerSource
from tests.conftest import FakeReader, FakeRunner, load_fixture, utc

SINCE = utc(2026, 11, 15, 12, 0, 0)
UNTIL = utc(2026, 11, 16, 12, 0, 0)
UPOWER_LS = "history-charge-5B10W13930-57.dat\nhistory-rate-5B10W13930-57.dat\nhistory-time-empty-5B10W13930-57.dat\n"


def sysfs(name: str) -> tuple[dict[str, str], str]:
    # Expand a `grep . /sys/class/power_supply/*/*` capture into {path: contents} and an `ls -1` listing.
    files: dict[str, list[str]] = {}
    for line in load_fixture("linux", name).splitlines():
        m = re.match(r"^(/sys/class/power_supply/[^/]+/[^/:]+):(.*)$", line)
        assert m, line
        files.setdefault(m.group(1), []).append(m.group(2))
    dirs = sorted({p.split("/")[4] for p in files})
    return {p: "\n".join(v) + "\n" for p, v in files.items()}, "\n".join(dirs) + "\n"


def make(runner_map=None, files=None, sysfs_fixture="sysfs_power_supply__thinkpad_energy_uwh.txt", fixed_now=None):
    ps_files, ps_ls = sysfs(sysfs_fixture) if sysfs_fixture else ({}, "")
    rmap = {("ls", "-1", "/sys/class/power_supply"): ps_ls}
    rmap.update(runner_map or {})
    fmap = dict(ps_files)
    fmap.update(files or {})
    runner, reader = FakeRunner(rmap), FakeReader(fmap)
    c = LinuxCollector(runner=runner, reader=reader, local_tz=ZoneInfo("America/Los_Angeles"),
                       now=fixed_now or (lambda: utc(2026, 11, 16, 12, 0, 0)))
    return c, runner, reader


def journal_only(fixture: str):
    return make({("journalctl",): load_fixture("linux", fixture),
                 ("ls", "-1", "/var/lib/upower"): CollectorError(ErrorCode.PARSE_ERROR, "ls: cannot access")})


def of(events, kind):
    return [e for e in events if e.kind == kind]


def assert_invariants(events):
    assert events == sorted(events, key=lambda e: e.ts)
    for e in events:
        assert e.platform == Platform.LINUX
        assert e.ts.tzinfo is not None and e.ts.utcoffset().total_seconds() == 0
        assert SINCE <= e.ts < UNTIL
        assert all(isinstance(v, str) for v in e.extra.values())
        json.dumps(e.to_dict())


# ------------------------------------------------------------------ journal: systemd 252 style (-0800 offsets)
def test_journal_lid_s2idle_cycle():
    c, runner, _ = journal_only("journalctl__lid_s2idle_idle_shutdown.txt")
    ev = c.collect_events(SINCE, UNTIL)
    assert_invariants(ev)

    argv = runner.calls[0]
    assert argv[:2] == ("journalctl", "--no-pager")
    assert f"--since=@{int(SINCE.timestamp())}" in argv and f"--until=@{int(UNTIL.timestamp())}" in argv
    assert "SYSLOG_IDENTIFIER=systemd-sleep" in argv

    sleeps, wakes = of(ev, EventKind.SLEEP), of(ev, EventKind.WAKE)
    assert len(sleeps) == 2 and len(wakes) == 2
    s1, w1 = sleeps[0], wakes[0]
    # 13:58:41.402117 PST == 21:58:41.402117Z (anchored on systemd-sleep, not the kernel line)
    assert s1.ts == utc(2026, 11, 15, 21, 58, 41).replace(microsecond=402117)
    assert s1.sleep_type == "s2idle"
    assert s1.raw_reason == "Lid closed."
    assert s1.user_initiated is True
    assert s1.extra["systemd_sleep_op"] == "suspend"
    assert s1.extra["logind_request"] == "The system will suspend now!"
    assert w1.ts == utc(2026, 11, 16, 3, 47, 13).replace(microsecond=51877)
    assert w1.raw_reason == "PM: Triggering wakeup from IRQ 9"

    # idle suspend: logind request but no lid/key line -> raw_reason None, still user/idle initiated
    s2, w2 = sleeps[1], wakes[1]
    assert s2.raw_reason is None and s2.user_initiated is True
    assert w2.raw_reason is None

    boots, downs = of(ev, EventKind.BOOT), of(ev, EventKind.SHUTDOWN)
    assert len(boots) == 2 and len(downs) == 1
    assert downs[0].raw_reason == "Power key pressed short."
    # out-of-window line (03:59:58 PST == 11:59:58Z) was skipped by the cheap check
    assert all(e.ts >= SINCE for e in ev)
    # no cause assignment anywhere
    assert not hasattr(ev[0], "cause")


# ------------------------------------------------------------------ journal: systemd 256 style (-08:00 offsets)
def test_journal_systemd256_aborted_deep_and_suspend_then_hibernate():
    c, _, _ = journal_only("journalctl__systemd256_deep_aborted_sth.txt")
    ev = c.collect_events(SINCE, UNTIL)
    assert_invariants(ev)

    delays = of(ev, EventKind.SLEEP_DELAY)
    assert len(delays) == 1
    assert delays[0].duration_s == pytest.approx(20.004)
    assert delays[0].actor == "mount.cifs"
    assert delays[0].raw_reason.startswith("Freezing user space processes failed after 20.004 seconds")

    sleeps = of(ev, EventKind.SLEEP)
    assert [s.sleep_type for s in sleeps] == ["deep", "deep", "s2idle", "hibernation"]
    aborted = sleeps[0]
    assert aborted.extra.get("aborted") == "1" and aborted.raw_reason == "Power key pressed short."
    wakes = of(ev, EventKind.WAKE)
    assert "Failed to put system to sleep. System resumed again: Device or resource busy" in wakes[0].raw_reason
    assert wakes[0].extra["aborted"] == "1"

    assert sleeps[1].duration_s == pytest.approx(3021.551)
    assert sleeps[1].raw_reason == "Lid closed."

    # suspend-then-hibernate: the RTC wake that is followed by an automatic hibernate is a dark wake
    sth_suspend, sth_hibernate = sleeps[2], sleeps[3]
    assert sth_suspend.user_initiated is True
    assert sth_suspend.extra["logind_request"] == "The system will suspend and later hibernate now!"
    assert sth_hibernate.user_initiated is False and sth_hibernate.extra["auto_resleep"] == "1"
    dark = of(ev, EventKind.DARK_WAKE)
    assert len(dark) == 1 and dark[0].ts == utc(2026, 11, 16, 4, 5, 45).replace(microsecond=44318)
    assert wakes[-1].ts == utc(2026, 11, 16, 10, 12, 10).replace(microsecond=210554)
    assert wakes[-1].extra["resumed_from"] == "hibernation"


def test_journal_window_excludes_events_outside():
    c, _, _ = journal_only("journalctl__systemd256_deep_aborted_sth.txt")
    since, until = utc(2026, 11, 15, 20, 0, 0), utc(2026, 11, 15, 22, 0, 0)
    ev = c.collect_events(since, until)
    # only the lid-close deep sleep (20:40:00Z) and its wake (21:30:22Z) fall in this window
    assert [e.kind for e in ev] == [EventKind.SLEEP, EventKind.WAKE]
    assert all(since <= e.ts < until for e in ev)


def test_garbage_journal_is_not_an_error():
    c, _, _ = make({("journalctl",): "garbage\n\x00\x01 nonsense line here\n2026-99-99T00:00 host kernel: PM: suspend exit\n",
                    ("ls", "-1", "/var/lib/upower"): CollectorError(ErrorCode.PARSE_ERROR, "no dir"),
                    ("id", "-Gn"): "alex adm sudo\n"})
    assert c.collect_events(SINCE, UNTIL) == []


# ------------------------------------------------------------------ upower history + enrichment
def test_upower_history_samples_and_enrichment():
    c, _, reader = make(
        {("journalctl",): load_fixture("linux", "journalctl__lid_s2idle_idle_shutdown.txt"),
         ("ls", "-1", "/var/lib/upower"): UPOWER_LS},
        {"/var/lib/upower/history-charge-5B10W13930-57.dat": load_fixture("linux", "upower_history_charge__thinkpad.dat")},
    )
    ev = c.collect_events(SINCE, UNTIL)
    assert_invariants(ev)
    assert not any("rate" in p for p in reader.reads)

    s1, s2 = of(ev, EventKind.SLEEP)
    w1, w2 = of(ev, EventKind.WAKE)
    assert (s1.charge_pct, s1.source, s1.extra["charge_from"]) == (78, PowerSource.BATTERY, "upower_history")
    assert (w1.charge_pct, w1.source) == (71, PowerSource.BATTERY)
    assert (s2.charge_pct, w2.charge_pct, w2.source) == (60, 59, PowerSource.AC)

    samples = of(ev, EventKind.BATTERY_SAMPLE)
    assert len(samples) == 10  # 11:50Z..08:00Z; 10:00Z and 13:00Z are outside the window
    src = of(ev, EventKind.POWER_SOURCE)
    assert [(e.source, e.raw_reason) for e in src] == [(PowerSource.BATTERY, "discharging"), (PowerSource.AC, "charging")]


# ------------------------------------------------------------------ degradation (CONTRACT rule 4)
def test_journal_permission_denied_degrades_to_warning():
    c, _, _ = make(
        {("journalctl",): CollectorError(ErrorCode.PARSE_ERROR,
                                         "journalctl exited 1: No journal files were opened due to insufficient permissions."),
         ("ls", "-1", "/var/lib/upower"): UPOWER_LS},
        {"/var/lib/upower/history-charge-5B10W13930-57.dat": load_fixture("linux", "upower_history_charge__thinkpad.dat")},
    )
    ev = c.collect_events(SINCE, UNTIL)
    assert ev and not of(ev, EventKind.SLEEP)
    assert any("usermod -aG systemd-journal" in w for w in c.warnings)


def test_empty_journal_without_group_warns():
    c, _, _ = make({("journalctl",): "", ("id", "-Gn"): "alex sudo\n",
                    ("ls", "-1", "/var/lib/upower"): CollectorError(ErrorCode.PARSE_ERROR, "no dir")})
    assert c.collect_events(SINCE, UNTIL) == []
    assert any("systemd-journal" in w for w in c.warnings)
    assert any("UPower" in w for w in c.warnings)


def test_empty_journal_with_group_does_not_warn_about_journal():
    c, _, _ = make({("journalctl",): "", ("id", "-Gn"): "alex adm systemd-journal\n",
                    ("ls", "-1", "/var/lib/upower"): CollectorError(ErrorCode.PARSE_ERROR, "no dir")},
                   sysfs_fixture="sysfs_power_supply__desktop_no_battery.txt")
    assert c.collect_events(SINCE, UNTIL) == []
    assert c.warnings == []


def test_no_source_works_raises_collector_error():
    c, _, _ = make({("journalctl",): CollectorError(ErrorCode.PERMISSION_DENIED, "journalctl: permission denied"),
                    ("ls", "-1", "/var/lib/upower"): CollectorError(ErrorCode.PARSE_ERROR, "no dir")})
    with pytest.raises(CollectorError) as ei:
        c.collect_events(SINCE, UNTIL)
    assert ei.value.code == ErrorCode.PERMISSION_DENIED
    assert ei.value.remediation and "systemd-journal" in ei.value.remediation[0]


# ------------------------------------------------------------------ battery
def test_battery_status_energy_uwh_discharging():
    c, _, reader = make()
    st = c.battery_status()
    assert st.has_battery and st.percent == 73
    assert st.state == ChargeState.DISCHARGING and st.on_ac is False
    assert st.minutes_remaining == 229  # 32.21 Wh / 8.455 W
    assert st.estimate_kind == EstimateKind.TO_EMPTY
    assert st.settling is False and st.sampled_at == utc(2026, 11, 16, 12, 0, 0)
    assert not any("serial" in p for p in reader.reads)
    assert not any("hidpp" in p and not p.endswith(("/type", "/scope")) for p in reader.reads)


def test_battery_health_energy_uwh():
    c, _, _ = make()
    h = c.battery_health()
    assert h.capacity_unit == "mWh"
    assert h.design_capacity == 57000.0 and h.full_charge_capacity == 44120.0
    assert h.health_pct == 77.4 and h.cycle_count == 412
    assert "831" not in json.dumps(h.to_dict())


def test_battery_charge_uah_charging():
    c, _, _ = make(sysfs_fixture="sysfs_power_supply__charge_uah_charging.txt")
    st = c.battery_status()
    assert st.state == ChargeState.CHARGING and st.on_ac is True and st.percent == 41
    assert st.minutes_remaining == 74 and st.estimate_kind == EstimateKind.TO_FULL
    h = c.battery_health()
    assert h.capacity_unit == "mAh" and h.design_capacity == 4210.0 and h.full_charge_capacity == 3804.0
    assert h.health_pct == 90.4
    assert h.cycle_count is None  # 0 = firmware does not report cycles
    assert "A1B2C3D4E5F6G7" not in json.dumps(h.to_dict())


def test_desktop_no_battery():
    c, _, _ = make(sysfs_fixture="sysfs_power_supply__desktop_no_battery.txt")
    st = c.battery_status()
    assert st.has_battery is False and st.percent is None and st.minutes_remaining is None
    with pytest.raises(CollectorError) as ei:
        c.battery_health()
    assert ei.value.code == ErrorCode.NO_BATTERY and ei.value.remediation


def test_ls_unavailable_falls_back_to_common_names():
    files, _ = sysfs("sysfs_power_supply__thinkpad_energy_uwh.txt")
    c = LinuxCollector(runner=FakeRunner({}), reader=FakeReader(files), local_tz=timezone.utc,
                       now=lambda: utc(2026, 11, 16, 12, 0, 0))
    assert c.battery_status().percent == 73


# ------------------------------------------------------------------ blockers
def test_current_blockers_table_format():
    c, runner, _ = make({("systemd-inhibit",): load_fixture("linux", "systemd_inhibit__table.txt")})
    bl = c.current_blockers()
    assert [b.actor for b in bl] == ["alex", "Firefox", "caffeine"]
    lid, ff, caf = bl
    assert lid.extra["what"] == "handle-lid-switch" and lid.extra["comm"] == "gsd-power"
    assert ff.raw_reason == "audio-playing" and ff.extra["mode"] == "block"
    assert caf.raw_reason == "Caffeine is active" and caf.extra["what"] == "idle:sleep"
    for b in bl:
        assert b.kind == EventKind.SLEEP_BLOCKER and b.end is None
        assert b.ts == utc(2026, 11, 16, 12, 0, 0) and b.extra["since_unknown"] == "1"
        assert " alex " not in b.raw and "<user>" in b.raw
    assert runner.calls[-1] == ("systemd-inhibit", "--list", "--no-pager")


def test_current_blockers_legacy_format():
    c, _, _ = make({("systemd-inhibit",): load_fixture("linux", "systemd_inhibit__legacy_blocks.txt")})
    (b,) = c.current_blockers()
    assert b.actor == "Totem" and b.raw_reason == "Playing a video"
    assert b.extra == {"what": "idle:sleep", "mode": "block", "comm": "totem", "pid": "4410", "since_unknown": "1"}
    assert "alex" not in b.raw


def test_current_blockers_missing_tool_warns():
    c, _, _ = make()
    assert c.current_blockers() == []
    assert c.warnings


# ------------------------------------------------------------------ settings
def test_power_settings():
    c, _, _ = make(
        {("ls", "-1", "/etc/systemd/logind.conf.d"): "10-idle.conf\nREADME\n"},
        {"/sys/power/mem_sleep": load_fixture("linux", "sys_power_mem_sleep__deep.txt"),
         "/sys/firmware/acpi/platform_profile": "low-power\n",
         "/proc/acpi/wakeup": load_fixture("linux", "proc_acpi_wakeup__thinkpad.txt"),
         "/etc/systemd/logind.conf": load_fixture("linux", "logind_conf__lid_ignore_on_ac.conf"),
         "/etc/systemd/logind.conf.d/10-idle.conf": "[Login]\nIdleActionSec=15min\n"},
    )
    s = {x.name: x for x in c.power_settings()}
    assert s["mem_sleep"].value == "s2idle [deep]" and s["mem_sleep"].raw == "s2idle [deep]"
    assert s["platform_profile"].value == "low-power"
    assert s["acpi_wakeup_xhci"].value == "enabled" and s["acpi_wakeup_xdci"].value == "disabled"
    assert s["acpi_wakeup_lid"].native_name == "LID"
    assert s["handle_lid_switch"].value == "suspend" and s["handle_lid_switch"].scope == "all"
    assert s["handle_lid_switch_external_power"].value == "ignore" and s["handle_lid_switch_external_power"].scope == "ac"
    assert s["idle_action_sec"].value == "15min"  # drop-in overrides main file
    assert "handle_power_key" not in s  # commented defaults are not reported
    assert not any(k.startswith("n_auto") for k in s)
