# insight-mcp

An MCP server that tells your AI assistant why your laptop's battery drained. It reads the power logs your OS already keeps (sleep and wake history, what's blocking sleep, battery health, power settings) and turns them into ranked causes. Each cause comes with evidence and a suggested fix.

> **You:** Why did my battery die overnight?
> **Claude:** *(calls `sleep_report`)* Your Mac woke up 155 times while it was asleep, mostly for Wi-Fi/Bluetooth. That works out to 1.5%/h, 2.3× your usual rate. Power Nap is on while on battery, and turning it off would reduce those wakes: `sudo pmset -b powernap 0`.

It works on **macOS, Windows and Linux**, runs entirely on your machine, and never changes anything.

## Why not just ask Claude Code?

Claude Code has a terminal, so it can run `pmset`, `powercfg` or `journalctl` itself. insight has no special access: it reads the same logs. The difference is what happens after the command runs:

- **The logs are too big.** `pmset -g log` holds weeks of history, often tens of thousands of lines. That's more than an AI can usefully read in one go, and tool output gets cut off long before then. insight reads the whole log on your machine and sends back a short summary.
- **The maths is easy to get wrong.** Finding the cause means pairing every sleep with its wake, working out % lost per hour, and adding up how long each app blocked sleep with overlapping periods counted once. An AI doing this by reading text makes mistakes. insight does it in tested code, and gives the same answer every time.
- **The wake reasons are cryptic.** The logs say things like `wifibt SMC.OutboxNotEmpty` or `rtc/Maintenance`. insight has a tested rule for each one, so the AI isn't guessing.
- **Raw logs contain private data.** They include serial numbers, MAC addresses, device names like "Jane's AirPods" and your username. When Claude Code runs the command, all of that output is sent to your AI provider. insight removes it first.
- **Every OS is different.** Claude Code would need to know the right commands, flags and output format for macOS, Windows and Linux. insight gives the same answer format on all three.
- **It can't change anything.** Claude Code can run any command, including ones that change your power settings (`sudo pmset ...`). insight is read-only: it only suggests fixes, and you decide whether to run them.
- **It's cheaper.** Raw log output uses up a lot of Claude Code's context and tokens. insight's summary is a small fraction of that.

In short, Claude Code is good at explaining and advising. insight gives it accurate, compact, private data to work from.

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
