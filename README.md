# insight-mcp

An MCP server that tells your AI assistant why your laptop's battery drained. It reads the power logs your OS already keeps (sleep and wake history, what's blocking sleep, battery health, power settings) and turns them into ranked causes. Each cause comes with evidence and a suggested fix.

> **You:** Why did my battery die overnight?
> **Claude:** *(calls `sleep_report`)* Your Mac woke up 155 times while it was asleep, mostly for Wi-Fi/Bluetooth. That works out to 1.5%/h, 2.3× your usual rate. Power Nap is on while on battery, and turning it off would reduce those wakes: `sudo pmset -b powernap 0`.

It works on **macOS, Windows and Linux**, runs entirely on your machine, and never changes anything.

## Tools

| Tool | What it answers |
|---|---|
| `battery_status` | Current charge, charging state, time to empty or full (`null` when the OS has no estimate) |
| `battery_health` | Design vs. current capacity, health %, cycle count, temperature |
| `sleep_report(hours=24)` | Every sleep session, % lost per hour, background wakes, and ranked causes with evidence |
| `wake_causes(hours=168)` | What keeps waking the laptop: Wi-Fi, Bluetooth, scheduled maintenance, USB, and so on |
| `who_is_keeping_me_awake` | Apps and services preventing sleep right now |
| `power_settings` | Power settings that increase drain, with fix commands for **you** to run |

Every response has the shape `{"ok", "platform", "generated_at", "data" | "error", "warnings"}`. Each error includes plain-English steps to fix it.

## Install

You need Python 3.10+ and [uv](https://docs.astral.sh/uv/).

**Claude Code**
```bash
claude mcp add insight -s user -- uvx --from git+https://github.com/aahan-bagga/insight_mcp insight-mcp
```

**Claude Desktop, Cursor, VS Code and other MCP clients**: add this to the client's MCP config (for Claude Desktop that's `claude_desktop_config.json`):
```json
{
  "mcpServers": {
    "insight": {
      "command": "uvx",
      "args": ["--from", "git+https://github.com/aahan-bagga/insight_mcp", "insight-mcp"]
    }
  }
}
```

**From source**
```bash
git clone https://github.com/aahan-bagga/insight_mcp && cd insight_mcp
pip install -e ".[dev]" && python -m pytest -q
claude mcp add insight -- python -m insight_mcp.server
```

## Privacy and safety
- **Read-only.** It never changes settings. Fix commands are returned as text for you to run yourself.
- **No network calls and no telemetry.** It only runs local OS tools (`pmset`, `ioreg`, `wevtutil`, `powercfg`, `journalctl`, `/sys`), with fixed arguments and no shell.
- **Redacted output.** Serial numbers, MAC/IP addresses, owner names ("Jane's AirPods" becomes "AirPods") and usernames in paths are removed before anything is returned.
- **What does leave your machine:** the summaries the tools return go to your AI assistant like any other message, so they reach your AI provider. Raw logs are never sent.
- **No admin needed** for the core features, with one exception: on Windows, `who_is_keeping_me_awake` needs an elevated terminal because `powercfg /requests` requires it.

## Platform support

| | Sleep/wake history | Live blockers | Battery | Settings | Notes |
|---|---|---|---|---|---|
| **macOS** | `pmset -g log` | `pmset -g assertions` | `ioreg` | `pmset -g custom` | Tested on real hardware (Apple Silicon) |
| **Windows** | Event Log (Kernel-Power, Power-Troubleshooter) | `powercfg /requests` (admin) | CIM / battery report | `powercfg /query` | Parsers built from documented formats; Modern Standby event wording partly reconstructed. English-language Windows only for now |
| **Linux** | `journalctl` + UPower history | `systemd-inhibit` | `/sys/class/power_supply` | `mem_sleep`, logind, ACPI wakeup | systemd distros. Reading the journal may require the `systemd-journal` group |

The Windows and Linux parsers haven't run on real machines yet. If you hit a wake reason the tool doesn't recognise, please open an issue with the redacted output.

## Development
```bash
python -m pytest -q        # all tests replay saved fixtures; no live commands run
```
Layout: `insight_mcp/schema.py` (data model), `collectors/{macos,windows,linux}.py` (OS output → events, no interpretation), `attribution.py` (pure rules + heuristics → causes), `server.py` (MCP tools).

## License
MIT
