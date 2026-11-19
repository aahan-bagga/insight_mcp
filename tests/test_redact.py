#testing for redaction, vital info leaving your computer

import pytest

from insight_mcp.redact import redact


@pytest.mark.parametrize("text, expected", [
    # hardware identifiers
    ("bt 3c:22:fb:01:02:03 up", "bt <mac> up"),
    ("eth 3C-22-FB-01-02-03", "eth <mac>"),
    ('"Serial"="F5D2303ASAB0VC5BH"', '"Serial"=\"<serial>"'),
    ("SerialNumber: ABC12345", "SerialNumber: <serial>"),
    ("dev 26C9F08B-2572-4BAE-A354-0123456789AB on", "dev <uuid> on"),
    ("id F5D2303ASAB0VC5BH", "id <id>"),
    # owner names in device names
    ("Jane Doe's AirPods Pro connected", "AirPods Pro connected"),
    ("Aahan\u2019s MacBook Pro", "MacBook Pro"),
    # usernames in paths
    ("/Users/jdoe/Library/x", "/Users/<user>/Library/x"),
    ("/home/jdoe/.config", "/home/<user>/.config"),
    (r"C:\Users\jdoe\AppData", r"C:\Users\<user>\AppData"),
    (r"\Device\HarddiskVolume3\Users\jdoe\app.exe", r"\Device\HarddiskVolume3\Users\<user>\app.exe"),
    # network addresses
    ("peer 192.168.1.4 port", "peer <ip> port"),
    ("v6 fe80:0:0:0:1c2b:3d4e:5f60:7a8b", "v6 <ip>"),
])
def test_patterns(text, expected):
    assert redact(text) == expected


@pytest.mark.parametrize("text", [
    # evidence that must survive: wake reasons, process names, short product codes, percentages, times
    "DarkWake due to smc.sysState.Wake wifibt SMC.OutboxNotEmpty/ Using BATT (Charge:12%)",
    "PID 425(WindowServer) product:TMKB-M1 eventType:17",
    "com.apple.audio.context107.preventuserid",
    "rtc/SleepService 1057 secs 2026-11-15 16:37:00 -0800",
    "Wake Source: Device -USB Root Hub (USB 3.0)",
    "The battery\u2019s charge is low",
])

def test_evidence_is_preserved(text):
    assert redact(text) == text #if nothing is redacted, then text should be the same before and after


def test_idempotent():
    once = redact("Jane's iPhone 3c:22:fb:01:02:03 /Users/jdoe 10.0.0.1")
    assert redact(once) == once


def test_none_passthrough():
    assert redact(None) is None
