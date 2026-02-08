<div align="center">

<img src="assets/pentestagent-logo.png" alt="PentestAgent Logo" width="220" style="margin-bottom: 20px;"/>

# PentestAgent
### AI Penetration Testing

[![Python](https://img.shields.io/badge/Python-3.10%2B-blue.svg)](https://www.python.org/) [![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE.txt) [![Version](https://img.shields.io/badge/Version-0.2.0-orange.svg)](https://github.com/GH05TCREW/pentestagent/releases) [![Security](https://img.shields.io/badge/Security-Penetration%20Testing-red.svg)](https://github.com/GH05TCREW/pentestagent) [![MCP](https://img.shields.io/badge/MCP-Compatible-purple.svg)](https://github.com/GH05TCREW/pentestagent)

</div>

https://github.com/user-attachments/assets/a67db2b5-672a-43df-b709-149c8eaee975

## Requirements

- Python 3.10+
- API key for OpenAI, Anthropic, or other LiteLLM-supported provider

## Install

```bash
# Clone
git clone https://github.com/GH05TCREW/pentestagent.git
cd pentestagent

# Setup (creates venv, installs deps)
.\scripts\setup.ps1   # Windows
./scripts/setup.sh    # Linux/macOS

# Or manual
python -m venv venv
.\venv\Scripts\Activate.ps1  # Windows
source venv/bin/activate     # Linux/macOS
pip install -e ".[all]"
playwright install chromium  # Required for browser tool
```

## Configure

Create `.env` in the project root:

```
ANTHROPIC_API_KEY=sk-ant-...
PENTESTAGENT_MODEL=claude-sonnet-4-20250514
```

Or for OpenAI:

```
OPENAI_API_KEY=sk-...
PENTESTAGENT_MODEL=gpt-5
```

Any [LiteLLM-supported model](https://docs.litellm.ai/docs/providers) works.

## Run

```bash
pentestagent                    # Launch TUI
pentestagent -t 192.168.1.1     # Launch with target
pentestagent --docker           # Run tools in Docker container
```

## Docker

Run tools inside a Docker container for isolation and pre-installed pentesting tools.

### Option 1: Pull pre-built image (fastest)

```bash
# Base image with nmap, netcat, curl
docker run -it --rm \
  -e ANTHROPIC_API_KEY=your-key \
  -e PENTESTAGENT_MODEL=claude-sonnet-4-20250514 \
  ghcr.io/gh05tcrew/pentestagent:latest

# Kali image with metasploit, sqlmap, hydra, etc.
docker run -it --rm \
  -e ANTHROPIC_API_KEY=your-key \
  ghcr.io/gh05tcrew/pentestagent:kali
```

### Option 2: Build locally

```bash
# Build
docker compose build

# Run
docker compose run --rm pentestagent

# Or with Kali
docker compose --profile kali build
docker compose --profile kali run --rm pentestagent-kali
```

The container runs PentestAgent with access to Linux pentesting tools. The agent can use `nmap`, `msfconsole`, `sqlmap`, etc. directly via the terminal tool.

Requires Docker to be installed and running.

## Modes

PentestAgent has three modes, accessible via commands in the TUI:

| Mode | Command | Description |
|------|---------|-------------|
| Assist | (default) | Chat with the agent. You control the flow. |
| Agent | `/agent <task>` | Autonomous execution of a single task. |
| Crew | `/crew <task>` | Multi-agent mode. Orchestrator spawns specialized workers. |

### TUI Commands

```
/agent <task>    Run autonomous agent on task
/crew <task>     Run multi-agent crew on task
/target <host>   Set target
/tools           List available tools
/notes           Show saved notes
/report          Generate report from session
/memory          Show token/memory usage
/prompt          Show system prompt
/clear           Clear chat and history
/quit            Exit (also /exit, /q)
/help            Show help (also /h, /?)
```

Press `Esc` to stop a running agent. `Ctrl+Q` to quit.

## Unified CTF/RE Solver

BinAgent includes a unified solver (`binagent solve`) that routes CTF/RE challenges to the appropriate existing components:

- **ctf_nc**: Netcat challenges → CTFRunner (banner-first approach)
- **apk_re**: APK reverse engineering → APKAnalyzer/Solver (deterministic)
- **binary_re**: Binary analysis → BinaryAnalystAgent (requires IDA)

### Architecture

```
┌─────────────────┐     ┌──────────────┐     ┌─────────────────┐
│  binagent solve │ ──▶ │ RouterPlanner│ ──▶ │    Executor     │
│   (CLI entry)   │     │ (JSON plan)  │     │ (deterministic) │
└─────────────────┘     └──────────────┘     └─────────────────┘
                              │                      │
                              ▼                      ▼
                        LLM (optional)         Existing tools:
                        for complex routing    - CTFRunner
                                               - APKAnalyzer/Solver
                                               - BinaryAnalystAgent
```

The LLM is used **only for planning** (producing a JSON plan), not for step-by-step solving.
Execution is deterministic using existing components.

### Usage

```bash
# Netcat challenge (auto-detects host:port)
binagent solve "nc example.com 12345"

# APK reverse engineering
binagent solve --file ./challenge.apk

# Binary with description
binagent solve --file ./binary --desc "Buffer overflow"

# Explicit target
binagent solve --connect example.com:12345
```

### Output

Results are saved to `runs/<run-id>/`:
- `plan.json` - Routing plan (JSON)
- `transcript.txt` - Execution log
- `summary.json` - Results with flags
- `run.json` - Run metadata

## APK CTF Solver (Deterministic)

BinAgent also includes a deterministic APK solver (no LLM) for faster CTF solving:
- Extracts APKs using apktool
- Decompiles using jadx
- Scans for flag patterns and encoded tokens
- Tries common decoders (Base64, Base32, hex, ROT13, XOR)

### Usage

```bash
# Solve an APK CTF challenge (deterministic)
binagent apk ./challenge.apk --mode solve

# With custom flag pattern
binagent apk ./challenge.apk --mode solve --flag-regex "myctf\{[^}]+\}"

# Analysis only (no solving)
binagent apk ./challenge.apk
```

### Output

Results are saved to `runs/<run-id>/`:

| File | Description |
|------|-------------|
| `summary.json` | Solver results with flags and evidence |
| `run.json` | Run metadata (tools, timings, config) |
| `transcript.txt` | Detailed solver action log |
| `manifest_info.json` | Package, components, permissions |
| `apktool_out/` | Extracted APK contents |
| `jadx_out/` | Decompiled Java sources |

### Interpreting Results

```bash
# Check if solver found a flag
cat runs/<run-id>/summary.json | jq '.success, .flags'

# PASS: success=true, flags=[{flag: "...", evidence: {...}}]
# FAIL: success=false, flags=[], check stop_reason
```

### Requirements

```bash
# Install required tools
sudo apt install apktool default-jdk

# Install jadx (not in apt)
wget https://github.com/skylot/jadx/releases/download/v1.5.0/jadx-1.5.0.zip
unzip jadx-1.5.0.zip -d /opt/jadx
sudo ln -s /opt/jadx/bin/jadx /usr/local/bin/jadx
```

## Playbooks

PentestAgent includes prebuilt **attack playbooks** for black-box security testing. Playbooks define a structured approach to specific security assessments.

**Run a playbook:**

```bash
pentestagent run -t example.com --playbook thp3_web
```

![Playbook Demo](assets/playbook.gif)

## Tools

PentestAgent includes built-in tools and supports MCP (Model Context Protocol) for extensibility.

**Built-in tools:** `terminal`, `browser`, `notes`, `web_search` (requires `TAVILY_API_KEY`)

### MCP Integration

Add external tools via MCP servers in `pentestagent/mcp/mcp_servers.json`:

```json
{
  "mcpServers": {
    "nmap": {
      "command": "npx",
      "args": ["-y", "gc-nmap-mcp"],
      "env": {
        "NMAP_PATH": "/usr/bin/nmap"
      }
    }
  }
}
```

### IDA MCP (Windows-hosted SSE)

If you run WSL and have IDA Pro on Windows, you can host the IDA MCP server on Windows and connect via SSE from WSL.

**1) Start the server on Windows (PowerShell):**

```powershell
$env:IDA_PATH="C:\Users\ChemistryKing\Desktop\IDA Professional 9.0\idat64.exe"
$env:IDA_WSL_DISTRO="Ubuntu"
python \\wsl.localhost\Ubuntu\home\a347908610\binagent\third_party\ida_mcp\ida_server.py --transport sse --host 0.0.0.0 --port 6666
```

**2) Set the Windows host IP in WSL**

From WSL, get the Windows host IP:

```bash
cat /proc/net/route | awk '$2=="00000000"{print $3; exit}' | \
python3 - <<'PY'
import struct, sys
val = int(sys.stdin.read().strip(), 16)
print(".".join(map(str, struct.pack("<L", val))))
PY
```

Then update the `ida-local` server entry in `pentestagent/mcp/mcp_servers.json` to use that IP:

```json
{
  "command": "python3",
  "args": [
    "third_party/ida_mcp/ida_server.py",
    "--transport",
    "sse",
    "--host",
    "172.27.0.1",
    "--port",
    "6666"
  ]
}
```

**3) Test the connection from WSL**

```bash
binagent mcp test ida-local
```

### CLI Tool Management

```bash
pentestagent tools list         # List all tools
pentestagent tools info <name>  # Show tool details
pentestagent mcp list           # List MCP servers
pentestagent mcp add <name> <command> [args...]  # Add MCP server
pentestagent mcp test <name>    # Test MCP connection
```

## Knowledge

- **RAG:** Place methodologies, CVEs, or wordlists in `pentestagent/knowledge/sources/` for automatic context injection.
- **Notes:** Agents save findings to `loot/notes.json` with categories (`credential`, `vulnerability`, `finding`, `artifact`). Notes persist across sessions and are injected into agent context.
- **Shadow Graph:** In Crew mode, the orchestrator builds a knowledge graph from notes to derive strategic insights (e.g., "We have credentials for host X").

## Project Structure

```
pentestagent/
  agents/         # Agent implementations
  config/         # Settings and constants
  interface/      # TUI and CLI
  knowledge/      # RAG system and shadow graph
  llm/            # LiteLLM wrapper
  mcp/            # MCP client and server configs
  playbooks/      # Attack playbooks
  runtime/        # Execution environment
  tools/          # Built-in tools
```

## Development

```bash
pip install -e ".[dev]"
pytest                       # Run tests
pytest --cov=pentestagent    # With coverage
black pentestagent           # Format
ruff check pentestagent      # Lint
```

## Legal

Only use against systems you have explicit authorization to test. Unauthorized access is illegal.

## License

MIT

## HexStrike Integration & Thanks

This branch vendors an optional integration with HexStrike (a powerful MCP-enabled scoring and tooling framework). HexStrike acts as a force-multiplier for PentestAgent by exposing a rich set of automated pentesting tools and workflows that the agent can call via MCP — greatly expanding available capabilities with minimal setup.

Special thanks and credit to the HexStrike project and its author: https://github.com/0x4m4/hexstrike-ai

Notes:
- HexStrike is vendored under `third_party/hexstrike` and is opt-in; follow `scripts/install_hexstrike_deps.sh` to install its Python dependencies.
- Auto-start of the vendored HexStrike adapter is controlled via the `.env` flag `LAUNCH_HEXTRIKE` and can be enabled per-user.
- This update also includes several TUI fixes (improved background worker handling and safer task cancellation) to stabilize the terminal UI while using long-running MCP tools.
