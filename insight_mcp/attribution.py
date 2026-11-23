# Pure analysis: map collector facts (PowerEvent / PowerSetting / BatteryHealth) to Causes.
#
# No I/O, no clock, no global mutation. Collectors copy OS reason text verbatim into
# `raw_reason`; this module is the only place that turns that text into a `Cause`.
#
# Rule matching: RULES are tried in order and the first rule whose platform and kind match,
# and whose pattern matches `raw_reason`, then `actor`, then `raw`, wins.
# Unmatched events fall back to (UNKNOWN, LOW, "fallback.unknown").

import re
import statistics
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Callable, Iterable, Sequence

from .schema import (
    Attribution,
    BatteryHealth,
    Cause,
    Confidence,
    EventKind,
    Evidence,
    Platform,
    PowerEvent,
    PowerSetting,
    PowerSource,
    SleepSession,
    SuggestedFix,
)

__all__ = [
    "Rule",
    "RULES",
    "classify_event",
    "build_sessions",
    "attribute",
    "attribute_blockers",
    "suggest_settings",
]


# =========================================================================== rules
@dataclass(frozen=True)
class Rule:
    id: str
    platforms: frozenset[Platform]
    kinds: frozenset[EventKind]
    pattern: re.Pattern[str]
    cause: Cause
    confidence: Confidence


_M = frozenset({Platform.MACOS})
_W = frozenset({Platform.WINDOWS})
_L = frozenset({Platform.LINUX})
_ALL = frozenset(Platform)
_WAKES = frozenset({EventKind.WAKE, EventKind.DARK_WAKE})
_BLOCK = frozenset({EventKind.SLEEP_BLOCKER})
_ANY = re.compile(r"^")  # matches every string, including ""

H, MED, LO = Confidence.HIGH, Confidence.MEDIUM, Confidence.LOW


def _r(id_: str, plats: frozenset[Platform], kinds: frozenset[EventKind], pat: str | re.Pattern[str],
       cause: Cause, conf: Confidence) -> Rule:
    p = pat if isinstance(pat, re.Pattern) else re.compile(pat, re.IGNORECASE)
    return Rule(id_, plats, kinds, p, cause, conf)


def _names(*names: str) -> str:
    return "(?:" + "|".join(names) + ")"


_MAC_SYS = _names(
    "coreaudiod", "powerd", r"backupd(?:-helper)?", "sharingd", "bluetoothd", r"mds(?:_stores)?",
    r"mdworker\w*", "WindowServer", "useractivityd", "cloudd", "softwareupdated", "kernel_task",
    "apsd", "airportd", "mDNSResponder", "configd", "locationd", "nsurlsessiond", "launchd",
    "loginwindow", "hidd", "symptomsd", "photoanalysisd", "bird", "rapportd", "AirPlayXPCHelper",
    r"com\.apple\.[\w.-]+",
)
_WIN_SYS = _names(
    r"svchost\.exe", "System", "Legacy Kernel Caller", r"audiodg\.exe", r"SearchIndexer\.exe",
    r"MoUsoCoreWorker\.exe", r"TiWorker\.exe", "wuauserv", r"msiexec\.exe", r"TrustedInstaller\.exe",
)
_LINUX_SYS = _names(
    "NetworkManager", "ModemManager", "UPower", "upowerd", "gnome-settings-daemon",
    "GNOME Settings Daemon", "GNOME Shell", r"gsd-[\w-]+", "systemd-logind", "logind", "packagekitd",
    "PackageKit", "fwupd", "fwupdmgr", r"unattended-upgrades?", "Unattended Upgrades Shutdown",
    "snapd", "kded5", "ksmserver", "org_kde_powerdevil", "PowerDevil", "powerdevil",
    "xfce4-power-manager", "cupsd", "udisksd", "accounts-daemon",
)

RULES: tuple[Rule, ...] = (
    # ---- cross-platform, kind-defined -------------------------------------------------
    _r("any.power_source", _ALL, frozenset({EventKind.POWER_SOURCE}), _ANY, Cause.CHARGER, H),
    _r("any.sleep_delay", _ALL, frozenset({EventKind.SLEEP_DELAY}), _ANY, Cause.SLOW_SLEEP_ENTRY, H),

    # ---- macOS wakes (pmset -g log "due to ..." text) ---------------------------------
    _r("macos.wake.lid", _M, _WAKES, r"EC\.LidOpen|\bLid ?Open\b", Cause.USER_INPUT, H),
    _r("macos.wake.power_button", _M, _WAKES, r"PowerButton|Power Button|\bPWRB\b", Cause.USER_INPUT, H),
    _r("macos.wake.hid", _M, _WAKES, r"\bHID\b|HID Activity|Keyboard|Trackpad", Cause.USER_INPUT, H),
    _r("macos.wake.useractivity", _M, _WAKES, r"UserActivity", Cause.USER_INPUT, MED),
    _r("macos.darkwake.wifibt", _M, _WAKES, r"wifibt", Cause.WIRELESS_UNSPECIFIED, MED),
    _r("macos.wake.charger", _M, _WAKES, r"\bEC\.AC(?:Attach|Detach)\b|\bAC ?(?:Attach|Detach)\b|AC Adapter|ACPowerChange",
       Cause.CHARGER, H),
    _r("macos.darkwake.rtc", _M, _WAKES, r"\bRTC\b|Maintenance|SleepService|PowerNap|\bScheduled\b",
       Cause.SCHEDULED_MAINTENANCE, H),
    _r("macos.darkwake.network", _M, _WAKES,
       r"\bARPT\b|\ben\d\b|\bWi-?Fi\b|\bWLAN\b|TCPKeepAlive|\bwomp\b|MagicPacket|\bNetwork\b|\bapsd\b|Push ?Notification",
       Cause.NETWORK, H),
    _r("macos.darkwake.bluetooth", _M, _WAKES, r"\bBT\b|Bluetooth|\bBTLE\b|bluetoothd", Cause.BLUETOOTH, H),
    _r("macos.wake.usb", _M, _WAKES, r"\bXHC\d*\b|\bEHC\d*\b|\bUSB|usb-drd", Cause.USB_DEVICE, H),

    # ---- Windows wakes (Power-Troubleshooter "Wake Source", Modern Standby exit reasons) --
    _r("windows.wake.power_button", _W, _WAKES, r"Power ?Button", Cause.USER_INPUT, H),
    _r("windows.wake.lid", _W, _WAKES, r"\bLid\b", Cause.USER_INPUT, H),
    _r("windows.wake.hid", _W, _WAKES, r"\bHID\b|Keyboard|\bMouse\b|Touchpad|Precision Touch|Input (?:Touch|Pen)",
       Cause.USER_INPUT, H),
    _r("windows.wake.charger", _W, _WAKES, r"AC Adapter|\bACDC\b|AC/DC|Power Source|Battery Charger",
       Cause.CHARGER, H),
    _r("windows.wake.timer", _W, _WAKES,
       r"\bTimer\b|Wake Timer|PDC Task Clock|\bScheduled\b|UpdateOrchestrator|\bNT TASK\b|Maintenance",
       Cause.SCHEDULED_MAINTENANCE, H),
    _r("windows.wake.bluetooth", _W, _WAKES, r"Bluetooth", Cause.BLUETOOTH, H),
    _r("windows.wake.network", _W, _WAKES,
       r"Wi-?Fi|Wireless|\bWLAN\b|802\.11|Ethernet|\bGbE\b|Network|\bLAN\b|\bNIC\b|Killer",
       Cause.NETWORK, H),
    _r("windows.wake.usb", _W, _WAKES, r"\bUSB|xHCI|Host Controller", Cause.USB_DEVICE, H),

    # ---- Linux wakes (wakeup_sources / ACPI device IDs / logind messages) ---------------
    _r("linux.wake.lid", _L, _WAKES, r"\bLid\b|PNP0C0D", Cause.USER_INPUT, H),
    _r("linux.wake.power_button", _L, _WAKES, r"Power (?:key|button)|PNP0C0C|LNXPWRBN|\bPWRB\b",
       Cause.USER_INPUT, H),
    _r("linux.wake.hid", _L, _WAKES, r"\bi8042\b|\batkbd\b|\bserio\d*\b|keyboard|touchpad|\bmouse\b|\bhid\b|i2c_hid",
       Cause.USER_INPUT, H),
    _r("linux.wake.charger", _L, _WAKES, r"ACPI0003|AC adapter|\bADP\d\b|\bucsi", Cause.CHARGER, H),
    _r("linux.wake.rtc", _L, _WAKES, r"\brtc\d*\b|alarmtimer|WakeSystem|\.timer\b", Cause.SCHEDULED_MAINTENANCE, H),
    _r("linux.wake.bluetooth", _L, _WAKES, r"\bhci\d\b|btusb|bluetooth|btintel|btrtl", Cause.BLUETOOTH, H),
    _r("linux.wake.network", _L, _WAKES,
       r"iwlwifi|\bath\d+k|\bmt7\d+|\brtw\d*|brcmfmac|\bwlan\d*\b|\bwlp\w+|\benp\w+|\beth\d\b|\be1000e\b|\br8169\b|\bigc\b|wake-?on-?lan|\bWoL\b",
       Cause.NETWORK, H),
    _r("linux.wake.usb", _L, _WAKES, r"\bxhci|\bXHC\d?\b|\busb\d*\b|\bEHC\d\b|PNP0D10", Cause.USB_DEVICE, H),

    # ---- sleep blockers: OS services first, anything else is an app ------------------
    _r("macos.blocker.system", _M, _BLOCK, rf"^{_MAC_SYS}$|\bpid \d+\({_MAC_SYS}\)", Cause.SYSTEM_KEEPING_AWAKE, H),
    _r("windows.blocker.system", _W, _BLOCK,
       rf"(?m)^\[(?:DRIVER|SERVICE|SYSTEM)\]|^{_WIN_SYS}$|\\Windows\\(?:System32|SysWOW64)\\",
       Cause.SYSTEM_KEEPING_AWAKE, H),
    _r("windows.blocker.process", _W, _BLOCK, r"(?m)^\[PROCESS\]", Cause.APP_KEEPING_AWAKE, H),
    _r("linux.blocker.system", _L, _BLOCK, rf"^{_LINUX_SYS}$", Cause.SYSTEM_KEEPING_AWAKE, H),
    _r("any.blocker.app", _ALL, _BLOCK, _ANY, Cause.APP_KEEPING_AWAKE, MED),
)

_FALLBACK = (Cause.UNKNOWN, Confidence.LOW, "fallback.unknown")


def classify_event(event: PowerEvent) -> tuple[Cause, Confidence, str]:
    # (cause, confidence, rule_id). Unmatched -> (UNKNOWN, LOW, "fallback.unknown").
    fields = (event.raw_reason, event.actor, event.raw)
    for rule in RULES:
        if event.platform not in rule.platforms or event.kind not in rule.kinds:
            continue
        for text in fields:
            if text is not None and rule.pattern.search(text):
                return rule.cause, rule.confidence, rule.id
    return _FALLBACK


# =========================================================================== helpers
_WEIGHT = {Confidence.HIGH: 1.0, Confidence.MEDIUM: 0.6, Confidence.LOW: 0.3}
_CONF_ORDER = [Confidence.LOW, Confidence.MEDIUM, Confidence.HIGH]
_CAUSE_ORDER = {c: i for i, c in enumerate(Cause)}
_MIN_DRAIN_SESSION = timedelta(minutes=30)
_STORM_WINDOW = timedelta(minutes=10)
_STORM_MIN = 6
_DEFAULT_WAKE_S = 30.0  # assumed length of a wake when the OS doesn't log one


def _iso(dt: datetime) -> str:
    return dt.isoformat().replace("+00:00", "Z")


def _dur(seconds: float) -> str:
    if seconds < 60:
        return f"{seconds:.0f} s"
    if seconds < 3600:
        return f"{seconds / 60:.0f} min"
    return f"{seconds / 3600:.1f} h"


def _pick(items: Sequence[PowerEvent], k: int = 5) -> list[PowerEvent]:
    # Up to k items spread evenly (first and last always included).
    n = len(items)
    if n <= k:
        return list(items)
    idx = sorted({round(i * (n - 1) / (k - 1)) for i in range(k)})
    return [items[i] for i in idx]


def _evidence(events: Sequence[PowerEvent], note: str) -> tuple[Evidence, ...]:
    return tuple(Evidence(ts=e.ts, raw=e.raw, note=note) for e in _pick(events))


def _low_note(conf: Confidence) -> str:
    return " (Low confidence: this is a best guess.)" if conf is Confidence.LOW else ""


def _majority_conf(confs: Iterable[Confidence]) -> Confidence:
    c = Counter(confs)
    best = max(c.values())
    # ties resolve to the lower confidence
    return next(x for x in _CONF_ORDER if c.get(x) == best)


def _plural(n: int, word: str) -> str:
    return f"{n} {word}{'' if n == 1 else 's'}"


# --------------------------------------------------------------------------- fixes
_INSPECT_WAKE = {
    Platform.MACOS: SuggestedFix("Review recent wake reasons.", 'pmset -g log | grep -iE "wake (from|reason)|DarkWake"',
                                 False, None),
    Platform.WINDOWS: SuggestedFix("Review the last wake source and armed wake devices.",
                                   "powercfg /lastwake && powercfg /devicequery wake_armed", False, None),
    Platform.LINUX: SuggestedFix("Review kernel wake messages from this boot.",
                                 'journalctl -b -k | grep -iE "wake|PM:"', False, None),
}


def _wake_fix(cause: Cause, platform: Platform, subject: str | None) -> SuggestedFix | None:
    P = platform
    if cause in (Cause.USER_INPUT, Cause.CHARGER):
        return None
    if cause is Cause.NETWORK:
        if P is Platform.MACOS:
            return SuggestedFix("Turn off TCP keepalive and wake-for-network-access on battery.",
                                "sudo pmset -b tcpkeepalive 0 && sudo pmset -b womp 0", True,
                                "Find My Mac and network wake (remote file sharing) stop working while asleep on battery.")
        if P is Platform.WINDOWS:
            return SuggestedFix("Disable network connectivity in Modern Standby on battery.",
                                "powercfg /setdcvalueindex SCHEME_CURRENT SUB_NONE CONNECTIVITYINSTANDBY 0 && powercfg /setactive SCHEME_CURRENT",
                                False, "Email, calls and notifications are not delivered while the PC is in standby.")
        return SuggestedFix("Disable wake-on-LAN / Wi-Fi wake (WoWLAN) on the network interface.",
                            "nmcli connection modify <connection> 802-3-ethernet.wake-on-lan ignore", True,
                            "The machine can no longer be woken remotely over the network.")
    if cause is Cause.WIRELESS_UNSPECIFIED:
        return SuggestedFix("Wi-Fi or Bluetooth woke the Mac. Turn off TCP keepalive on battery, and disconnect or unpair "
                            "Bluetooth accessories that are not in use.",
                            "sudo pmset -b tcpkeepalive 0", True,
                            "Find My Mac stops updating while asleep on battery.")
    if cause is Cause.BLUETOOTH:
        if P is Platform.WINDOWS:
            cmd = f'powercfg /devicedisablewake "{subject}"' if subject else "powercfg /devicequery wake_armed"
            return SuggestedFix("Stop the Bluetooth device from waking the PC.", cmd, bool(subject),
                                "Bluetooth keyboards/mice can no longer wake the PC.")
        return SuggestedFix("Turn off Bluetooth or disconnect idle Bluetooth accessories before sleeping.", None, False,
                            "Bluetooth keyboards/mice can no longer wake the machine.")
    if cause is Cause.SCHEDULED_MAINTENANCE:
        if P is Platform.MACOS:
            return SuggestedFix("Turn off Power Nap on battery.", "sudo pmset -b powernap 0", True,
                                "Mail, iCloud and Time Machine stop updating while the Mac sleeps on battery.")
        if P is Platform.WINDOWS:
            return SuggestedFix("Disable wake timers on battery.",
                                "powercfg /setdcvalueindex SCHEME_CURRENT SUB_SLEEP RTCWAKE 0 && powercfg /setactive SCHEME_CURRENT",
                                False, "Scheduled tasks (e.g. Windows Update restarts) no longer wake the PC on battery.")
        return SuggestedFix("Find systemd timers with WakeSystem=true and disable the ones you do not need.",
                            "systemctl list-timers --all", False, "Disabled timers will no longer wake the machine.")
    if cause is Cause.USB_DEVICE:
        if P is Platform.WINDOWS:
            cmd = f'powercfg /devicedisablewake "{subject}"' if subject else "powercfg /devicequery wake_armed"
            return SuggestedFix("Stop the USB device from waking the PC.", cmd, bool(subject),
                                "That device can no longer wake the PC.")
        if P is Platform.LINUX:
            return SuggestedFix("Check which devices are allowed to wake the machine (/proc/acpi/wakeup).",
                                "cat /proc/acpi/wakeup", False, None)
        return SuggestedFix("Unplug USB accessories or hubs before sleeping.", None, False, None)
    if cause is Cause.UNKNOWN:
        return _INSPECT_WAKE[P]
    return None


def _blocker_fix(cause: Cause, platform: Platform, actor: str) -> SuggestedFix:
    if platform is Platform.WINDOWS:
        if cause is Cause.APP_KEEPING_AWAKE:
            exe = re.split(r"[\\/]", actor)[-1]
            return SuggestedFix(f"Quit or pause {exe}, or tell Windows to ignore its sleep requests.",
                                f'powercfg /requestsoverride PROCESS "{exe}" SYSTEM', True,
                                f"The PC may sleep while {exe} is playing media or downloading.")
        return SuggestedFix(f"Stop the activity behind {actor} (e.g. audio playback, file sharing) and re-check.",
                            "powercfg /requests", True, None)
    if platform is Platform.MACOS:
        verb = "Quit or pause" if cause is Cause.APP_KEEPING_AWAKE else "Stop the activity behind"
        return SuggestedFix(f"{verb} {actor} (e.g. playback, sharing, backup), then confirm with the command.",
                            "pmset -g assertions", False,
                            f"Whatever {actor} is doing stops or no longer prevents sleep.")
    verb = "Quit or pause" if cause is Cause.APP_KEEPING_AWAKE else "Stop the activity behind"
    return SuggestedFix(f"{verb} {actor}, then confirm the inhibitor is gone.", "systemd-inhibit --list", False,
                        f"Whatever {actor} is doing stops or no longer prevents sleep.")


# =========================================================================== sessions
@dataclass
class _Open:
    start_ev: PowerEvent
    source: PowerSource
    readings: list[tuple[datetime, int]] = field(default_factory=list)
    dark: list[PowerEvent] = field(default_factory=list)


@dataclass(frozen=True)
class _SessionRec:
    session: SleepSession
    start_ev: PowerEvent
    end_ev: PowerEvent
    dark: tuple[PowerEvent, ...]


def _close(o: _Open, end_ev: PowerEvent, woke_by: Cause) -> _SessionRec:
    readings = list(o.readings)
    if end_ev.charge_pct is not None:
        readings.append((end_ev.ts, end_ev.charge_pct))
    start_r = readings[0] if readings else None
    end_r = readings[-1] if len(readings) >= 2 else None
    start, end = o.start_ev.ts, end_ev.ts
    drain: float | None = None
    if (o.source is not PowerSource.AC and start_r and end_r and end - start >= _MIN_DRAIN_SESSION
            and end_r[0] > start_r[0]):
        hours = (end_r[0] - start_r[0]).total_seconds() / 3600
        delta = start_r[1] - end_r[1]
        if delta >= 0:
            drain = round(delta / hours, 2)
    causes = Counter(classify_event(d)[0].value for d in o.dark)
    s = SleepSession(
        start=start, end=end, source=o.source,
        start_pct=start_r[1] if start_r else None,
        end_pct=end_r[1] if end_r else None,
        drain_pct_per_hour=drain,
        dark_wake_count=len(o.dark),
        wake_causes=dict(causes),
        woke_by=woke_by,
    )
    return _SessionRec(s, o.start_ev, end_ev, tuple(o.dark))


def _sessions(events: Sequence[PowerEvent]) -> list[_SessionRec]:
    out: list[_SessionRec] = []
    cur: _Open | None = None
    for ev in sorted(events, key=lambda e: e.ts):
        k = ev.kind
        if cur is None:
            if k is EventKind.SLEEP and ev.user_initiated is not False:
                cur = _Open(ev, ev.source)
                if ev.charge_pct is not None:
                    cur.readings.append((ev.ts, ev.charge_pct))
            continue
        if k is EventKind.WAKE:
            out.append(_close(cur, ev, classify_event(ev)[0]))
            cur = None
        elif cur.source is PowerSource.UNKNOWN and ev.source is not PowerSource.UNKNOWN and k is not EventKind.SLEEP_BLOCKER:
            cur.source = ev.source  # adopt the first known source
            if k is EventKind.DARK_WAKE:
                cur.dark.append(ev)
            if ev.charge_pct is not None:
                cur.readings.append((ev.ts, ev.charge_pct))
        elif (ev.source is not cur.source and ev.source is not PowerSource.UNKNOWN
              and k in (EventKind.POWER_SOURCE, EventKind.DARK_WAKE, EventKind.SLEEP, EventKind.BATTERY_SAMPLE)):
            # Power source changed mid-sleep. macOS never logs POWER_SOURCE events, so any event that
            # carries a different known source is a split point.
            out.append(_close(cur, ev, Cause.CHARGER))
            cur = _Open(ev, ev.source)
            if ev.charge_pct is not None:
                cur.readings.append((ev.ts, ev.charge_pct))
        elif k is EventKind.DARK_WAKE:
            cur.dark.append(ev)
            if ev.charge_pct is not None:
                cur.readings.append((ev.ts, ev.charge_pct))
        elif k is EventKind.BATTERY_SAMPLE and ev.charge_pct is not None:
            cur.readings.append((ev.ts, ev.charge_pct))
        elif k in (EventKind.BOOT, EventKind.SHUTDOWN):
            cur = None  # no clean wake (shutdown / battery died): discard the open session
        # SLEEP while in a session (maintenance re-sleep or duplicate) does not start a new one.
    return out


def build_sessions(events: Sequence[PowerEvent]) -> list[SleepSession]:
    # Sessions run from a SLEEP with user_initiated != False to the next WAKE. Split when POWER_SOURCE changes.
    # drain_pct_per_hour is None on AC, if charge is unknown, or if the session is shorter than 30 min.
    return [r.session for r in _sessions(events)]


# =========================================================================== blockers
def _blocker_end(ev: PowerEvent, horizon: datetime) -> datetime:
    if ev.end is not None:
        return ev.end
    if ev.duration_s is not None:
        return ev.ts + timedelta(seconds=ev.duration_s)
    return max(ev.ts, horizon)


def _merge(intervals: Iterable[tuple[datetime, datetime]]) -> list[tuple[datetime, datetime]]:
    merged: list[tuple[datetime, datetime]] = []
    for s, e in sorted(intervals):
        if merged and s <= merged[-1][1]:
            if e > merged[-1][1]:
                merged[-1] = (merged[-1][0], e)
        else:
            merged.append((s, e))
    return merged


def _held_by_actor(blockers: Sequence[PowerEvent], horizon: datetime) -> dict[str, float]:
    # Total seconds each actor held sleep off, with overlapping intervals counted once.
    by: dict[str, list[tuple[datetime, datetime]]] = defaultdict(list)
    for b in blockers:
        by[b.actor or "unknown process"].append((b.ts, _blocker_end(b, horizon)))
    return {a: sum((e - s).total_seconds() for s, e in _merge(iv)) for a, iv in by.items()}


def _blocker_cause(evs: Sequence[PowerEvent]) -> tuple[Cause, Confidence]:
    classified = [classify_event(e)[:2] for e in evs]
    causes = Counter(c for c, _ in classified)
    if causes.get(Cause.SYSTEM_KEEPING_AWAKE):
        cause = Cause.SYSTEM_KEEPING_AWAKE
    elif causes.get(Cause.APP_KEEPING_AWAKE):
        cause = Cause.APP_KEEPING_AWAKE
    else:  # only reachable if a blocker has no text at all
        return Cause.APP_KEEPING_AWAKE, Confidence.LOW
    return cause, _majority_conf(cf for c, cf in classified if c is cause)


def _blocker_attributions(blockers: Sequence[PowerEvent], horizon: datetime) -> list[Attribution]:
    groups: dict[str, list[PowerEvent]] = defaultdict(list)
    for b in sorted(blockers, key=lambda e: e.ts):
        groups[b.actor or "unknown process"].append(b)
    held = _held_by_actor(blockers, horizon)
    out = []
    for actor, evs in groups.items():
        cause, conf = _blocker_cause(evs)
        kind = "an OS service" if cause is Cause.SYSTEM_KEEPING_AWAKE else "an app"
        out.append(Attribution(
            cause=cause, confidence=conf,
            evidence=_evidence(evs, f"{actor} held a sleep-prevention request"),
            explanation=(f"{actor} ({kind}) kept the system awake for {_dur(held[actor])} in total across "
                         f"{_plural(len(evs), 'sleep-blocker record')} (overlapping intervals counted once)."
                         + _low_note(conf)),
            suggested_fix=_blocker_fix(cause, evs[0].platform, actor),
            event_count=len(evs), subject=actor, impact_s=held[actor],
        ))
    return out


def attribute_blockers(blockers: Sequence[PowerEvent]) -> list[Attribution]:
    # For live blockers: one Attribution per actor (APP_ or SYSTEM_KEEPING_AWAKE).
    groups: dict[str, list[PowerEvent]] = defaultdict(list)
    for b in sorted(blockers, key=lambda e: e.ts):
        groups[b.actor or "unknown process"].append(b)
    out = []
    for actor, evs in groups.items():
        cause, conf = _blocker_cause(evs)
        durs = [e.duration_s for e in evs if e.duration_s is not None]
        held = f"held for {_dur(max(durs))}" if durs else "held for an unknown time"
        kind = "an OS service" if cause is Cause.SYSTEM_KEEPING_AWAKE else "an app"
        out.append(Attribution(
            cause=cause, confidence=conf,
            evidence=_evidence(evs, f"{actor} is currently preventing sleep"),
            explanation=(f"{actor} ({kind}) is preventing sleep right now with "
                         f"{_plural(len(evs), 'active request')}, {held}." + _low_note(conf)),
            suggested_fix=_blocker_fix(cause, evs[0].platform, actor),
            event_count=len(evs), subject=actor, impact_s=max(durs) if durs else None,
        ))
    return _rank(out)


# =========================================================================== settings
def _on(v: str) -> bool:
    s = v.strip().lower()
    if s in ("true", "yes", "on", "enable", "enabled"):
        return True
    try:
        return int(s, 0) != 0
    except ValueError:
        return False


def _zero(v: str) -> bool:
    s = v.strip().lower()
    if s == "never":
        return True
    try:
        return int(s, 0) == 0
    except ValueError:
        return False


_WIN_APPLY = " && powercfg /setactive SCHEME_CURRENT"


@dataclass(frozen=True)
class _SettingRule:
    id: str
    platforms: frozenset[Platform]
    name: re.Pattern[str]                       # matched against PowerSetting.name, then native_name
    bad: Callable[[str], bool]                  # True if the value increases drain
    explain: str                                # "{value}" placeholder allowed
    fix: Callable[[PowerSetting], SuggestedFix]


def _rx(p: str) -> re.Pattern[str]:
    return re.compile(p, re.IGNORECASE)


def _gnome_or_none(s: PowerSetting) -> str | None:
    if "sleep-inactive-battery-timeout" in s.native_name:
        return "gsettings set org.gnome.settings-daemon.plugins.power sleep-inactive-battery-timeout 900"
    return None


_SETTING_RULES: tuple[_SettingRule, ...] = (
    # macOS (pmset)
    _SettingRule("macos.setting.powernap", _M, _rx(r"^powernap$"), _on,
                 "Power Nap is on, so the Mac wakes periodically during sleep to sync mail, iCloud and backups.",
                 lambda s: SuggestedFix("Turn off Power Nap on battery.", "sudo pmset -b powernap 0", True,
                                        "Mail, iCloud and Time Machine stop updating while the Mac sleeps on battery.")),
    _SettingRule("macos.setting.tcpkeepalive", _M, _rx(r"^tcpkeepalive$"), _on,
                 "TCP keepalive is on, so network connections are maintained (with dark wakes) during sleep.",
                 lambda s: SuggestedFix("Turn off TCP keepalive on battery.", "sudo pmset -b tcpkeepalive 0", True,
                                        "Find My Mac and push services stop updating while asleep on battery.")),
    _SettingRule("macos.setting.womp", _M, _rx(r"^womp$"), _on,
                 "Wake for network access is on, so network traffic can wake the Mac.",
                 lambda s: SuggestedFix("Turn off wake for network access on battery.", "sudo pmset -b womp 0", True,
                                        "Remote file/screen sharing can no longer wake the Mac.")),
    _SettingRule("macos.setting.ttyskeepawake", _M, _rx(r"^ttyskeepawake$"), _on,
                 "Open remote terminal sessions keep the Mac from sleeping.",
                 lambda s: SuggestedFix("Let the Mac sleep even with open SSH sessions.",
                                        "sudo pmset -b ttyskeepawake 0", True,
                                        "Idle SSH sessions no longer keep the Mac awake.")),
    _SettingRule("macos.setting.proximitywake", _M, _rx(r"^proximitywake$"), _on,
                 "Proximity wake is on, so the Mac wakes when your iPhone or Apple Watch is nearby.",
                 lambda s: SuggestedFix("Turn off proximity wake on battery.", "sudo pmset -b proximitywake 0", True,
                                        "The Mac no longer wakes when your devices are nearby.")),
    _SettingRule("macos.setting.standby_off", _M, _rx(r"^standby$"), _zero,
                 "Standby is off, so the Mac never moves into its low-power deep sleep state.",
                 lambda s: SuggestedFix("Turn standby back on.", "sudo pmset -b standby 1", True,
                                        "Waking after a long sleep takes a few seconds longer.")),
    _SettingRule("macos.setting.never_sleep", _M, _rx(r"^sleep(?:_timeout)?(?:_s|_min)?$"), _zero,
                 "System sleep is disabled ({value}), so the Mac never sleeps when idle.",
                 lambda s: SuggestedFix("Let the Mac sleep after 10 idle minutes on battery.",
                                        "sudo pmset -b sleep 10", True, "The Mac sleeps after 10 idle minutes.")),
    # Windows (powercfg)
    _SettingRule("windows.setting.wake_timers", _W,
                 _rx(r"wake_?timers?|rtcwake|bd3b718a-0680-4d9d-8ab2-e1d2b4ac806d"), _on,
                 "Wake timers are allowed on battery, so scheduled tasks can wake the PC.",
                 lambda s: SuggestedFix("Disable wake timers on battery.",
                                        "powercfg /setdcvalueindex SCHEME_CURRENT SUB_SLEEP RTCWAKE 0" + _WIN_APPLY,
                                        False, "Scheduled tasks (e.g. update restarts) no longer wake the PC on battery.")),
    _SettingRule("windows.setting.connectivity_in_standby", _W,
                 _rx(r"connectivity_?in_?standby|f15576e8-98b7-4186-b944-eafa664402d9"), _on,
                 "Network connectivity stays on in Modern Standby, which keeps the radio and background sync active.",
                 lambda s: SuggestedFix("Disable network connectivity in standby on battery.",
                                        "powercfg /setdcvalueindex SCHEME_CURRENT SUB_NONE CONNECTIVITYINSTANDBY 0" + _WIN_APPLY,
                                        False, "Email, calls and notifications are not delivered during standby.")),
    _SettingRule("windows.setting.never_sleep", _W,
                 _rx(r"^standby_timeout|standbyidle|29f6c1db-86da-48c5-9fdb-f2b67b1f44da"), _zero,
                 "Sleep after idle is set to never on battery.",
                 lambda s: SuggestedFix("Sleep after 15 idle minutes on battery.",
                                        "powercfg /change standby-timeout-dc 15", False,
                                        "The PC sleeps after 15 idle minutes on battery.")),
    _SettingRule("windows.setting.never_hibernate", _W,
                 _rx(r"^hibernate_timeout|hibernateidle|9d7815a6-7ee4-497e-8888-515a05f02364"), _zero,
                 "Hibernate is never used on battery, so standby keeps draining until the battery is empty.",
                 lambda s: SuggestedFix("Hibernate after 3 hours of sleep on battery.",
                                        "powercfg /change hibernate-timeout-dc 180", False,
                                        "Resuming after a long sleep takes longer.")),
    # Linux
    _SettingRule("linux.setting.mem_sleep_s2idle", _L, _rx(r"^mem_sleep$"),
                 lambda v: "[s2idle]" in v and "deep" in v,
                 "Suspend uses s2idle ({value}) even though deep (S3) sleep is available; s2idle usually drains faster.",
                 lambda s: SuggestedFix("Switch suspend to deep sleep for this boot (persist with the kernel parameter "
                                        "mem_sleep_default=deep).", "echo deep | sudo tee /sys/power/mem_sleep", True,
                                        "Resume is slower, and some laptops' deep sleep is unreliable.")),
    _SettingRule("linux.setting.never_sleep", _L, _rx(r"sleep.*(?:battery|timeout)|^standby_timeout"), _zero,
                 "Automatic suspend on battery is disabled ({value}).",
                 lambda s: SuggestedFix("Enable automatic suspend on battery (e.g. after 15 idle minutes).",
                                        _gnome_or_none(s), False, "The machine suspends when idle on battery.")),
    _SettingRule("linux.setting.lid_ignored", _L, _rx(r"handle_?lid_?switch"),
                 lambda v: v.strip().lower() in ("ignore", "lock"),
                 "Closing the lid does not suspend (HandleLidSwitch={value}).",
                 lambda s: SuggestedFix("Set HandleLidSwitch=suspend in /etc/systemd/logind.conf, then restart "
                                        "systemd-logind or reboot.", None, True,
                                        "Closing the lid always suspends.")),
)


def _setting_findings(settings: Sequence[PowerSetting], platform: Platform | None
                      ) -> list[tuple[PowerSetting, _SettingRule]]:
    # Drain-relevant (setting, rule) pairs. platform=None checks every platform's rules.
    out = []
    for s in settings:
        if s.scope not in ("battery", "all"):
            continue
        for rule in _SETTING_RULES:
            if platform is not None and platform not in rule.platforms:
                continue
            if (rule.name.search(s.name) or rule.name.search(s.native_name)) and rule.bad(s.value):
                out.append((s, rule))
                break
    return out


def _setting_attribution(s: PowerSetting, rule: _SettingRule, ts: datetime) -> Attribution:
    return Attribution(
        cause=Cause.SETTING, confidence=Confidence.MEDIUM,
        evidence=(Evidence(ts=ts, raw=s.raw, note=f"{s.native_name} = {s.value} ({s.scope})"),),
        explanation=rule.explain.format(value=s.value),
        suggested_fix=rule.fix(s), event_count=1, subject=s.name,
    )


def _suggest(settings: Sequence[PowerSetting], platform: Platform | None, observed_at: datetime) -> list[Attribution]:
    return [_setting_attribution(s, r, observed_at) for s, r in _setting_findings(settings, platform)]


def suggest_settings(settings: Sequence[PowerSetting], platform: Platform, *, observed_at: datetime) -> list[Attribution]:
    # cause=SETTING for drain-relevant settings. Fix commands are for the user to run. Mark requires_admin and tradeoff.
    # observed_at: UTC time the settings were read (supplied by the caller; this module never reads the clock).
    return _rank(_suggest(settings, platform, observed_at))


# =========================================================================== attribute
def _rank(atts: list[Attribution]) -> list[Attribution]:
    # Biggest battery impact first (seconds awake), then by how many records support it.
    return sorted(atts, key=lambda a: (-(a.impact_s or 0.0), -a.event_count * _WEIGHT[a.confidence],
                                       _CAUSE_ORDER[a.cause], a.subject or ""))


def _wake_attributions(wakes: Sequence[PowerEvent]) -> list[Attribution]:
    groups: dict[tuple[Cause, str | None], list[tuple[PowerEvent, Confidence, str]]] = defaultdict(list)
    for ev in wakes:
        cause, conf, rid = classify_event(ev)
        groups[(cause, ev.actor)].append((ev, conf, rid))
    out = []
    for (cause, subject), items in groups.items():
        evs = [e for e, _, _ in items]
        conf = _majority_conf(c for _, c, _ in items)
        n_dark = sum(1 for e in evs if e.kind is EventKind.DARK_WAKE)
        span_h = (evs[-1].ts - evs[0].ts).total_seconds() / 3600
        rate = f", about {len(evs) / span_h:.1f} per hour" if span_h >= 1 and len(evs) > 1 else ""
        who = f" ({subject})" if subject else ""
        label = cause.value.replace("_", " ")
        if cause is Cause.SLOW_SLEEP_ENTRY:
            total = sum(e.duration_s or 0 for e in evs)
            expl = (f"{subject or 'A process or driver'} delayed sleep entry {_plural(len(evs), 'time')}, "
                    f"{_dur(total)} in total.")
            fix = SuggestedFix(f"Update or remove {subject or 'the delaying driver/process'}.", None, False, None)
            note = "sleep entry was delayed"
        else:
            expl = (f"{_plural(len(evs), 'wake')} ({n_dark} dark) attributed to {label}{who}"
                    f" between {_iso(evs[0].ts)} and {_iso(evs[-1].ts)}{rate}.")
            if cause is Cause.UNKNOWN:
                expl = (f"{_plural(len(evs), 'wake')} ({n_dark} dark) had a reason no rule recognises, "
                        f"e.g. \"{(evs[0].raw_reason or evs[0].raw)[:80]}\".")
            fix = _wake_fix(cause, evs[0].platform, subject)
            note = f"wake reason matched {items[0][2]}"
        if cause is Cause.SLOW_SLEEP_ENTRY:
            impact = sum(e.duration_s or 0 for e in evs)
        else:
            impact = sum(e.duration_s if e.duration_s is not None else _DEFAULT_WAKE_S for e in evs)
        out.append(Attribution(cause=cause, confidence=conf, evidence=_evidence(evs, note),
                               explanation=expl + _low_note(conf), suggested_fix=fix,
                               event_count=len(evs), subject=subject, impact_s=impact))
    return out


def _storms(dark: Sequence[PowerEvent]) -> list[list[PowerEvent]]:
    # Maximal clusters where some 10-minute window holds >= 6 dark wakes.
    n = len(dark)
    spans: list[tuple[int, int]] = []
    j = 0
    for i in range(n):
        j = max(j, i)
        while j + 1 < n and dark[j + 1].ts - dark[i].ts <= _STORM_WINDOW:
            j += 1
        if j - i + 1 >= _STORM_MIN:
            if spans and i <= spans[-1][1]:
                spans[-1] = (spans[-1][0], j)
            else:
                spans.append((i, j))
    return [list(dark[a:b + 1]) for a, b in spans]


def _storm_attributions(dark: Sequence[PowerEvent]) -> list[Attribution]:
    out = []
    for cluster in _storms(dark):
        classified = [classify_event(e) for e in cluster]
        counts = Counter(c for c, _, _ in classified)
        cause = min(counts, key=lambda c: (-counts[c], _CAUSE_ORDER[c]))
        conf = min(Confidence.MEDIUM, _majority_conf(cf for c, cf, _ in classified if c is cause),
                   key=_CONF_ORDER.index)
        minutes = (cluster[-1].ts - cluster[0].ts).total_seconds() / 60
        out.append(Attribution(
            cause=cause, confidence=conf,
            evidence=_evidence(cluster, "dark wake inside a wake storm"),
            explanation=(f"Wake storm: {len(cluster)} dark wakes in {minutes:.0f} min "
                         f"({_iso(cluster[0].ts)} to {_iso(cluster[-1].ts)}), "
                         f"{counts[cause]} of them {cause.value.replace('_', ' ')}." + _low_note(conf)),
            suggested_fix=_wake_fix(cause, cluster[0].platform, None),
            event_count=len(cluster), subject=None,
            impact_s=sum(e.duration_s if e.duration_s is not None else _DEFAULT_WAKE_S for e in cluster),
        ))
    return out


def _drain_attributions(recs: Sequence[_SessionRec]) -> list[Attribution]:
    rated = [r for r in recs if r.session.drain_pct_per_hour is not None]
    if len(rated) < 2:
        return []
    med = statistics.median(r.session.drain_pct_per_hour for r in rated)  # type: ignore[misc]
    if med <= 0:
        return []
    out = []
    for r in rated:
        s = r.session
        d = s.drain_pct_per_hour
        assert d is not None
        if d < 2 * med:
            continue
        if s.wake_causes:
            top = max(s.wake_causes, key=lambda c: (s.wake_causes[c], -_CAUSE_ORDER[Cause(c)]))
            cause = Cause(top)
            why = f"{s.dark_wake_count} dark wakes, mostly {top.replace('_', ' ')}"
        else:
            cause = Cause.UNKNOWN
            why = "no dark wakes were recorded"
        evs = [r.start_ev, *r.dark, r.end_ev]
        out.append(Attribution(
            cause=cause, confidence=Confidence.LOW,
            evidence=_evidence(evs, "boundary or dark wake of a high-drain sleep session"),
            explanation=(f"Sleep from {_iso(s.start)} to {_iso(s.end)} drained {d:.1f}%/h, "
                         f"{d / med:.1f}x the median {med:.1f}%/h; {why}." + _low_note(Confidence.LOW)),
            suggested_fix=_wake_fix(cause, r.start_ev.platform, None) if cause is not Cause.UNKNOWN
            else _INSPECT_WAKE[r.start_ev.platform],
            event_count=1 + len(r.dark), subject=None,
            impact_s=(s.end - s.start).total_seconds(),
        ))
    return out


def _wear_attribution(h: BatteryHealth) -> Attribution | None:
    if h.health_pct is None or h.health_pct >= 80:
        return None
    unit = h.capacity_unit or ""
    raw = (f"health_pct={h.health_pct} full_charge_capacity={h.full_charge_capacity}{unit} "
           f"design_capacity={h.design_capacity}{unit} cycle_count={h.cycle_count} condition={h.condition}")
    cycles = f" after {h.cycle_count} cycles" if h.cycle_count is not None else ""
    return Attribution(
        cause=Cause.BATTERY_WEAR, confidence=Confidence.HIGH,
        evidence=(Evidence(ts=h.sampled_at, raw=raw, note="full-charge capacity is below 80% of design"),),
        explanation=(f"The battery holds {h.health_pct:.1f}% of its design capacity{cycles}, so each charge "
                     f"lasts about {100 - h.health_pct:.0f}% less than when new."),
        suggested_fix=SuggestedFix("Have the battery serviced or replaced.", None, False,
                                   "Costs money and time without the machine."),
        event_count=1, subject=None,
    )


def attribute(events: Sequence[PowerEvent], *, settings: Sequence[PowerSetting] = (),
              health: BatteryHealth | None = None, observed_at: datetime | None = None) -> list[Attribution]:
    # Ranked by impact_s (seconds of impact), then record count. Includes cross-event heuristics:
    # wake storms (>=6 dark wakes in 10 min), merged blocker intervals per actor (overlap counted once),
    # sessions with drain >= 2x the median, and wear when health_pct < 80.
    evs = sorted(events, key=lambda e: e.ts)
    out: list[Attribution] = []

    wakeish = [e for e in evs if e.kind in (EventKind.WAKE, EventKind.DARK_WAKE, EventKind.SLEEP_DELAY)]
    out += _wake_attributions(wakeish)
    out += _storm_attributions([e for e in evs if e.kind is EventKind.DARK_WAKE])

    blockers = [e for e in evs if e.kind is EventKind.SLEEP_BLOCKER]
    if blockers:
        horizon = max(max((e.end or e.ts) for e in evs), max(e.ts for e in evs))
        out += _blocker_attributions(blockers, horizon)

    out += _drain_attributions(_sessions(evs))

    if health is not None and (w := _wear_attribution(health)) is not None:
        out.append(w)

    if settings:
        ts = observed_at or (evs[-1].ts if evs else None)
        if ts is None:
            raise ValueError("attribute(settings=...) needs observed_at when there are no events")
        platforms = {e.platform for e in evs}
        out += _suggest(settings, platforms.pop() if len(platforms) == 1 else None, ts)

    return _rank(out)
