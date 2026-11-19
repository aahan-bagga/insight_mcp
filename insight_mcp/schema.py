#Shared data model. Every collector emits these types; attribution consumes them.

#CONTRACT RULES (see CONTRACT.md for the full list):
#- Every datetime is timezone-aware UTC. Use `to_utc()` to convert.
#- Collectors emit facts only (`raw_reason` verbatim). Only attribution.py assigns a `Cause`.
#- These dataclasses are frozen; build new instances instead of mutating them.

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any


# --------------------------------------------------------------------------- enums
class Platform(str, Enum):
    MACOS = "macos"
    WINDOWS = "windows"
    LINUX = "linux"


class EventKind(str, Enum):
    SLEEP = "sleep"                  # system entered sleep / suspend / modern standby
    WAKE = "wake"                    # full, user-visible wake (display on)
    DARK_WAKE = "dark_wake"          # background wake with the display off (macOS DarkWake, Windows standby activity)
    POWER_SOURCE = "power_source"    # charger attached or detached; `source` holds the NEW state
    BATTERY_SAMPLE = "battery_sample"  # a charge reading with no sleep/wake meaning
    SLEEP_BLOCKER = "sleep_blocker"  # a process/service prevented idle sleep over [ts, end]
    SLEEP_DELAY = "sleep_delay"      # a process/driver slowed entry into sleep by `duration_s`
    BOOT = "boot"
    SHUTDOWN = "shutdown"


class PowerSource(str, Enum):
    AC = "ac"
    BATTERY = "battery"
    UNKNOWN = "unknown"


class Cause(str, Enum):
    """Only attribution.py may produce these."""
    USER_INPUT = "user_input"                    # lid, keyboard, trackpad, power button
    CHARGER = "charger"                          # power source change
    NETWORK = "network"                          # Wi-Fi / Ethernet / wake-on-LAN / TCP keepalive / push
    BLUETOOTH = "bluetooth"
    WIRELESS_UNSPECIFIED = "wireless_unspecified"  # OS reports Wi-Fi OR Bluetooth without saying which
    SCHEDULED_MAINTENANCE = "scheduled_maintenance"  # RTC/wake timers, Power Nap, OS maintenance tasks
    USB_DEVICE = "usb_device"
    APP_KEEPING_AWAKE = "app_keeping_awake"      # third-party process blocking sleep
    SYSTEM_KEEPING_AWAKE = "system_keeping_awake"  # OS service blocking sleep (audio, sharing, backup...)
    SLOW_SLEEP_ENTRY = "slow_sleep_entry"        # process/driver delaying sleep
    SETTING = "setting"                          # a power setting that increases drain
    BATTERY_WEAR = "battery_wear"                # drain explained by degraded capacity
    UNKNOWN = "unknown"


class Confidence(str, Enum):
    HIGH = "high"      # the OS named the cause unambiguously
    MEDIUM = "medium"  # strong pattern / heuristic match
    LOW = "low"        # best guess; explanation must say so


class ChargeState(str, Enum):
    CHARGING = "charging"
    DISCHARGING = "discharging"
    FULL = "full"
    NOT_CHARGING = "not_charging"  # on AC but held (e.g. optimized charging at 80%)
    UNKNOWN = "unknown"


class EstimateKind(str, Enum):
    TO_EMPTY = "to_empty"
    TO_FULL = "to_full"


# --------------------------------------------------------------------------- helpers
def to_utc(dt: datetime) -> datetime:
    #Return a tz-aware UTC datetime. Naive input is REJECTED: collectors must
    #localize naive OS timestamps themselves (see CONTRACT.md 'Timestamps')."""
    if dt.tzinfo is None or dt.utcoffset() is None:
        raise ValueError(f"naive datetime not allowed: {dt!r}")
    return dt.astimezone(timezone.utc)


def _require_utc(dt: datetime | None, name: str) -> None:
    if dt is None:
        return
    if dt.tzinfo is None or dt.utcoffset() != timezone.utc.utcoffset(None):
        raise ValueError(f"{name} must be tz-aware UTC, got {dt!r}")


def _jsonable(v: Any) -> Any:
    if isinstance(v, Enum):
        return v.value
    if isinstance(v, datetime):
        return v.isoformat().replace("+00:00", "Z")
    if isinstance(v, dict):
        return {k: _jsonable(x) for k, x in v.items()}
    if isinstance(v, (list, tuple)):
        return [_jsonable(x) for x in v]
    return v


class _Serializable:
    def to_dict(self) -> dict[str, Any]:
        return _jsonable(asdict(self))  # type: ignore[arg-type]


# --------------------------------------------------------------------------- events
RAW_MAX = 500  # characters of original log text kept on each event


@dataclass(frozen=True)
class PowerEvent(_Serializable):
    ts: datetime                         # UTC; for SLEEP_BLOCKER the interval start
    kind: EventKind
    platform: Platform
    raw: str                             # original record text (redacted, <= RAW_MAX chars) - used as evidence
    raw_reason: str | None = None        # verbatim OS reason substring, e.g. "wifibt SMC.OutboxNotEmpty"
    source: PowerSource = PowerSource.UNKNOWN  # power source at this moment
    charge_pct: int | None = None        # 0..100
    duration_s: float | None = None      # SLEEP/DARK_WAKE: reported time in state; SLEEP_DELAY: delay; BLOCKER: held time
    end: datetime | None = None          # SLEEP_BLOCKER interval end (UTC); None if still held
    actor: str | None = None             # process / driver / device name (redacted)
    sleep_type: str | None = None        # SLEEP only, verbatim OS label: "Clamshell Sleep", "Maintenance Sleep", "s2idle", "Modern Standby"...
    user_initiated: bool | None = None   # SLEEP: True if user/idle sleep, False if maintenance re-sleep, None unknown
    extra: dict[str, str] = field(default_factory=dict)  # collector-specific facts; string values only

    def __post_init__(self) -> None:
        _require_utc(self.ts, "ts")
        _require_utc(self.end, "end")
        if self.charge_pct is not None and not 0 <= self.charge_pct <= 100:
            raise ValueError(f"charge_pct out of range: {self.charge_pct}")
        from .redact import redact  # central safety net; collectors redact too (idempotent)
        object.__setattr__(self, "raw", (redact(self.raw) or "")[:RAW_MAX])
        object.__setattr__(self, "raw_reason", redact(self.raw_reason))
        object.__setattr__(self, "actor", redact(self.actor))


# --------------------------------------------------------------------------- live state
@dataclass(frozen=True)
class BatteryStatus(_Serializable):
    has_battery: bool
    percent: int | None
    state: ChargeState
    on_ac: bool | None
    minutes_remaining: int | None        # None = OS has no estimate (never a sentinel like 65535)
    estimate_kind: EstimateKind | None   # what minutes_remaining means
    settling: bool                       # True if power source changed < 60s ago: state/estimate may be stale
    sampled_at: datetime                 # UTC

    def __post_init__(self) -> None:
        _require_utc(self.sampled_at, "sampled_at")


@dataclass(frozen=True)
class BatteryHealth(_Serializable):
    design_capacity: float | None
    full_charge_capacity: float | None
    capacity_unit: str | None            # "mAh" | "mWh" - as reported; never mix units
    health_pct: float | None             # full_charge / design * 100, rounded to 1 decimal
    cycle_count: int | None
    condition: str | None                # OS label verbatim if any ("Normal", "Service Recommended")
    temperature_c: float | None
    sampled_at: datetime

    def __post_init__(self) -> None:
        _require_utc(self.sampled_at, "sampled_at")


@dataclass(frozen=True)
class PowerSetting(_Serializable):
    name: str                            # normalized snake_case: "powernap", "tcpkeepalive", "standby_timeout_s", "mem_sleep"
    value: str                           # as reported, stringified
    scope: str                           # "battery" | "ac" | "all"
    native_name: str                     # OS name/command key, e.g. "powernap" or GUID alias
    raw: str                             # source line (redacted)

    def __post_init__(self) -> None:
        from .redact import redact
        object.__setattr__(self, "raw", redact(self.raw) or "")


# --------------------------------------------------------------------------- analysis output
@dataclass(frozen=True)
class Evidence(_Serializable):
    ts: datetime                         # UTC of the cited event
    raw: str                             # verbatim excerpt from PowerEvent.raw
    note: str                            # why this line supports the cause

    def __post_init__(self) -> None:
        _require_utc(self.ts, "ts")


@dataclass(frozen=True)
class SuggestedFix(_Serializable):
    description: str                     # plain English
    command: str | None                  # shell command for the USER to run; the server never executes it
    requires_admin: bool
    tradeoff: str | None                 # what the user gives up (e.g. "Find My stops updating while asleep")


@dataclass(frozen=True)
class Attribution(_Serializable):
    cause: Cause
    confidence: Confidence
    evidence: tuple[Evidence, ...]       # NON-EMPTY, at most 5 items, most representative first
    explanation: str                     # plain English, 1-2 sentences, mentions counts/rates
    suggested_fix: SuggestedFix | None
    event_count: int                     # number of events this attribution covers
    subject: str | None = None           # process / device / setting name if applicable

    def __post_init__(self) -> None:
        if not self.evidence:
            raise ValueError("Attribution requires at least one Evidence")


@dataclass(frozen=True)
class SleepSession(_Serializable):
    #One stretch from a user/idle sleep to the next full WAKE.
    #Split into a new session whenever the power source changes mid-sleep."""
    start: datetime
    end: datetime
    source: PowerSource                  # constant within a session (sessions split on change)
    start_pct: int | None
    end_pct: int | None
    drain_pct_per_hour: float | None     # None if on AC, unknown charge, or session < 30 min
    dark_wake_count: int
    wake_causes: dict[str, int]          # Cause.value -> count
    woke_by: Cause                       # cause of the terminating full WAKE

    def __post_init__(self) -> None:
        _require_utc(self.start, "start")
        _require_utc(self.end, "end")
