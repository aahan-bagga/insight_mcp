#redaction removes private info like mac addresses, serial numbers / hardware IDS, or any names involved('Jane's Airpods'), user home paths
#and IPv4 / IPv6 addresses
#so this sensitive info doesn't go to anthropic's servers upon tool calling
# each os has separate formats for their respective power diagnostics tools, but this redaction tests only the private data, which is the same
# per each os

import re #regex

#regex redaction per above schema

_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"\b(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}\b"), "<mac>"),
    (re.compile(r"(?i)(\"?serial(?:number)?\"?\s*[=:]\s*\"?)[A-Za-z0-9-]{6,}"), r"\1<serial>"),
    (re.compile(r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b"), "<uuid>"),
    (re.compile(r"\b(?=[A-Z0-9]*\d)(?=[A-Z0-9]*[A-Z])[A-Z0-9]{12,}\b"), "<id>"),
    (re.compile(r"\b[\w .-]{1,40}?['’]s (?=(?:AirPods|iPhone|iPad|MacBook|Mac|Apple Watch|Watch|Magic|Beats|Galaxy|Pixel|Surface|Phone|Laptop|PC|Headphones|Keyboard|Mouse|Trackpad)\b)"), ""),
    (re.compile(r"(?i)(/Users/|/home/|[A-Za-z]:\\Users\\|\\Device\\HarddiskVolume\d+\\Users\\)[^/\\\s\"']+"), r"\1<user>"),
    (re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"), "<ip>"),
    (re.compile(r"\b(?:[0-9a-fA-F]{1,4}:){4,7}[0-9a-fA-F]{1,4}\b"), "<ip>"),
]


def redact(text: str | None) -> str | None: # input could be string or nothing and output could be string or nothing
    if text is None:
        return None
    for pat, repl in _PATTERNS:
        text = pat.sub(repl, text)
    return text
