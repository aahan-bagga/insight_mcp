# Lead-owned: collector output feeds attribution end to end (names/values agree across modules).

from datetime import datetime, timezone

from insight_mcp.attribution import suggest_settings
from insight_mcp.collectors.linux import LinuxCollector
from insight_mcp.schema import Cause, Platform, PowerSetting

from conftest import FakeReader, FakeRunner, load_fixture

T = datetime(2026, 11, 16, tzinfo=timezone.utc)


def _subjects(settings, platform):
    return {a.subject for a in suggest_settings(settings, platform, observed_at=T) if a.cause is Cause.SETTING}


def test_macos_settings_fixture_produces_advice():
    from insight_mcp.collectors.macos import MacOSCollector
    c = MacOSCollector(runner=FakeRunner({("/usr/bin/pmset", "-g", "custom"): load_fixture("macos", "pmset_custom__default.txt")}),
                       now=lambda: T)
    assert {"powernap", "tcpkeepalive"} <= _subjects(c.power_settings(), Platform.MACOS)


def test_linux_s2idle_with_deep_available_is_flagged():
    c = LinuxCollector(runner=FakeRunner({}),
                       reader=FakeReader({"/sys/power/mem_sleep": "[s2idle] deep\n"}), now=lambda: T)
    settings = [s for s in c.power_settings() if s.name == "mem_sleep"]
    assert _subjects(settings, Platform.LINUX) == {"mem_sleep"}


def test_windows_settings_match_by_native_name():
    ss = [PowerSetting("standby_network_connectivity", "Enable", "battery", "CONNECTIVITYINSTANDBY", "x"),
          PowerSetting("wake_timers", "Enable", "battery", "RTCWAKE", "x")]
    assert _subjects(ss, Platform.WINDOWS) == {"standby_network_connectivity", "wake_timers"}
