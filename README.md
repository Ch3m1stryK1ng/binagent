<div align="center">

# BinAgent

### LLM-Driven Binary Analysis Agent with MCP Tool Orchestration

[![Python](https://img.shields.io/badge/Python-3.10%2B-blue.svg)](https://www.python.org/)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE.txt)
[![MCP](https://img.shields.io/badge/MCP-Compatible-purple.svg)](https://modelcontextprotocol.io)

</div>

## Overview

BinAgent is an LLM-based agent that performs automated vulnerability detection and CTF-style challenge solving on compiled binaries. The agent operates through a **Plan → Act → Observe → Re-plan** loop: given a binary, it formulates a multi-step analysis plan, executes tool calls to gather evidence (decompiled code, cross-references, string artifacts), observes the results, and iteratively refines its plan until it reaches a conclusion. Findings are grounded in concrete evidence — every reported vulnerability is tied to a function address, a decompiled snippet, and a CWE label.

The key architectural decision in BinAgent is the use of the **Model Context Protocol (MCP)** to decouple LLM reasoning from tool execution. Rather than embedding analysis logic directly in the agent, BinAgent connects to external analysis backends — primarily **Ghidra** via [pyghidra-mcp](https://github.com/DarkMatter-999/pyghidra-mcp) — through a standardized tool protocol. The LLM plans and reasons; Ghidra provides ground-truth static analysis (decompilation, cross-references, symbol resolution). This separation allows the agent to leverage the full power of a production reverse-engineering platform without coupling the LLM to any particular tool's API.

BinAgent supports two operating modes: **ANALYZE** for vulnerability detection with CWE-labeled output, and **SOLVE** for CTF flag recovery across binary RE, network service, and APK challenges. Both modes enforce a mandatory planning phase (3–7 steps) before any tool execution, with bounded tool budgets and tactical replanning when the agent gets stuck.

The design draws on established agent patterns — ReAct (Yao et al., 2023), Plan-and-Solve (Wang et al., 2023), CRITIC (Gou et al., 2024), and Reflexion (Shinn et al., 2023) — and positions itself alongside recent work on LLM-assisted binary analysis such as VulBinLLM and LLM4Decompile.

## Architecture

```
┌─────────────────────────────────────────────────────────────────────────┐
│                              User Task                                  │
│           binagent analyze ./binary   or   binagent solve "nc ..."      │
└────────────────────────────────┬────────────────────────────────────────┘
                                 │
                                 ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                      CLI  (interface/main.py)                           │
│                  parse args → select mode → launch agent                │
└────────────────────────────────┬────────────────────────────────────────┘
                                 │
                                 ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                     GeneralAgent  (core agent loop)                     │
│                                                                         │
│   ┌───────────┐    ┌────────────────────────────────────────────────┐   │
│   │ PREFLIGHT │───▶│  PLAN → ACT → OBSERVE → RE-PLAN  (bounded)   │   │
│   │ (auto)    │    │                                                │   │
│   │ • import  │    │  1. LLM generates numbered plan (3-7 steps)   │   │
│   │ • strings │    │  2. Execute tool calls per step                │   │
│   │ • xrefs   │    │  3. Observe results, link to evidence         │   │
│   │ • decompile    │  4. Re-plan if stuck or new info emerges      │   │
│   └───────────┘    └──────────────────┬─────────────────────────────┘   │
│                                       │                                 │
└───────────────────────────────────────┼─────────────────────────────────┘
                                        │
              ┌─────────────────────────┼─────────────────────────┐
              │                         │                         │
              ▼                         ▼                         ▼
┌───────────────────┐   ┌───────────────────┐   ┌───────────────────────┐
│   MCP Manager     │   │       LLM         │   │    Tool Registry      │
│  mcp/manager.py   │   │    llm/llm.py     │   │   tools/registry.py   │
│                   │   │                   │   │                       │
│ • connect_all()   │   │ • LiteLLM wrapper │   │ • Built-in tools      │
│ • tool discovery  │   │ • Any provider    │   │ • MCP tools           │
└────────┬──────────┘   └───────────────────┘   └───────────────────────┘
         │
         │  MCP Protocol (stdio / SSE)
         │
    ┌────┴────────────────────────────────────────────┐
    │                                                  │
    ▼                    ▼                    ▼        │
┌──────────┐   ┌──────────────┐   ┌──────────────┐   │
│  Ghidra  │   │  HexStrike   │   │  Metasploit  │   │
│ (pyghidra│   │  (vendored)  │   │  (vendored)  │   │
│  -mcp)   │   │              │   │              │   │
└──────────┘   └──────────────┘   └──────────────┘   │
                                                      │
```

## Key Design Principles

- **Mandatory planning phase** — The agent must output a numbered plan (3–7 steps) before executing any tool calls. Plans are validated programmatically; execution is blocked until the plan passes.
- **Evidence-linked observations** — Every finding must be tied to a `function:address:snippet` triple. Natural-language claims without supporting evidence are rejected during re-planning.
- **Fail-fast bootstrap** — Before analysis begins, the agent verifies that required tools (e.g., Ghidra MCP) are reachable and the binary is loadable. Missing tools trigger an immediate error rather than silent degradation.
- **Bounded tool budgets** — Preflight consumes ~30 tool calls for Ghidra workflows. The main loop operates within a configurable iteration limit to prevent runaway execution.
- **Tactical replanning** — When the agent detects it is stuck (e.g., tool failures, unexpected binary structure), it pauses execution, states what went wrong, and proposes an alternative plan.
- **CWE-labeled output** — Vulnerability findings in ANALYZE mode are tagged with CWE identifiers, function addresses, and decompiled evidence snippets.

## MCP Integration

BinAgent uses the [Model Context Protocol (MCP)](https://modelcontextprotocol.io) to connect to external analysis tools. MCP provides a standardized interface for tool discovery and invocation — the agent discovers available tools at startup, and the LLM selects which tools to call based on their schemas. This makes the system modular: new analysis backends can be added without modifying the agent core.

### Configured MCP Backends

| Server | Description | Transport |
|--------|-------------|-----------|
| `ghidra-local` | Ghidra headless analysis via pyghidra-mcp | stdio |
| `hexstrike-local` | HexStrike AI pentesting toolkit | stdio |
| `metasploit-local` | Metasploit Framework integration | stdio |

### Configuration

MCP servers are configured in `pentestagent/mcp/mcp_servers.json`:

```json
{
  "mcpServers": {
    "ghidra-local": {
      "command": "pyghidra-mcp",
      "args": [],
      "env": {
        "GHIDRA_INSTALL_DIR": "/path/to/ghidra",
        "JAVA_HOME": "/path/to/jdk"
      },
      "enabled": true
    }
  }
}
```

### Managing MCP Servers

```bash
binagent mcp list                          # List configured servers
binagent mcp add <name> <command> [args]   # Register new server
binagent mcp remove <name>                 # Remove a server
binagent mcp enable <name>                 # Enable a server
binagent mcp disable <name>                # Disable a server
binagent mcp test <name>                   # Test connectivity
```

### Tool Discovery Flow

1. On startup, `MCPManager.connect_all()` connects to each enabled MCP server.
2. Available tools are discovered via the MCP `tools/list` method.
3. Each tool is registered in the `ToolRegistry` with its schema.
4. The LLM receives tool schemas in its context and can invoke them by name.

## Ghidra Integration

BinAgent's primary analysis backend is [pyghidra-mcp](https://github.com/DarkMatter-999/pyghidra-mcp), which exposes Ghidra's analysis engine over the MCP protocol.

### Available Operations

| Operation | Description |
|-----------|-------------|
| `import_binary` | Load a binary into a Ghidra project for analysis |
| `decompile_function` | Decompile a function to C-like pseudocode |
| `search_strings` | Extract strings from the binary |
| `list_cross_references` | Find callers/callees of a given address |
| `search_symbols_by_name` | Resolve symbol names to addresses |
| `list_functions` | Enumerate functions in the binary |
| `list_imports` | List imported library functions |
| `list_exports` | List exported symbols |

### Preflight Phase

When a binary is provided, the agent runs an automated preflight sequence before LLM planning begins:

1. **File identification** — `file` command to determine binary type
2. **Security metadata** — `checksec` and `readelf` for headers, segments, protections
3. **Ghidra import** — Load the binary into Ghidra headless
4. **String extraction** — Search for interesting strings
5. **Risky symbol scan** — Search for dangerous functions (`gets`, `strcpy`, `sprintf`, `system`, `free`, etc.)
6. **Cross-reference resolution** — For each risky import, find call sites in user code
7. **Caller decompilation** — Decompile functions that call risky APIs
8. **Full decompilation** — For small binaries, decompile all user functions

The preflight results are injected into the conversation context so the LLM can plan with concrete evidence rather than guessing.

### Environment Setup

```bash
# Required environment variables
export GHIDRA_INSTALL_DIR=/path/to/ghidra_11.x
export JAVA_HOME=/path/to/jdk-21

# Install pyghidra-mcp
pip install pyghidra-mcp

# Verify the connection
binagent mcp test ghidra-local
```

## Operating Modes

### Analyze Mode

Vulnerability detection with CWE-labeled findings.

```bash
binagent analyze ./binary
binagent analyze ./binary --task "Find buffer overflow vulnerabilities"
binagent analyze ./binary --offline    # Without Ghidra (limited analysis)
```

**Workflow:** Bootstrap → Preflight → Plan → Analysis Loop → CWE Report

The agent identifies dangerous API call sites, decompiles surrounding code, reasons about exploitability, and produces structured findings:

```json
{
  "cwe": "CWE-121",
  "function": "handle_input",
  "address": "0x00401234",
  "evidence": "gets(buf) with stack buffer of 64 bytes, no bounds checking",
  "severity": "HIGH"
}
```

When Ghidra is unavailable, the `--offline` flag enables fallback analysis using `file`, `strings`, and `readelf`.

### Solve Mode (CTF)

CTF-style flag recovery across multiple challenge types.

```bash
# Netcat challenge (auto-detects host:port)
binagent solve "nc example.com 12345"

# Binary reverse engineering
binagent solve --file ./challenge --desc "Buffer overflow"

# APK reverse engineering
binagent solve --file ./challenge.apk

# Explicit network target
binagent solve --connect example.com:12345
```

**Workflow:** Parse challenge → Plan → Execute (binary analysis + network + decoding) → Flag extraction

**Supported challenge types:**
- **Network services** — Banner parsing, protocol interaction, exploit delivery
- **Binary RE** — Static analysis via Ghidra, flag extraction from logic
- **APK RE** — Decompilation, pattern matching, decoder chains
- **Crypto/encoding** — Base64, XOR, ROT13, custom encodings

**Built-in solve tools:** `run_command`, `python_eval`, `solve_script`, `netcat`

### Interactive TUI

BinAgent also provides a terminal UI for interactive pentesting workflows:

```bash
binagent                        # Launch TUI
binagent -t 192.168.1.1        # Launch with target
binagent --docker               # Run tools in Docker container
```

| Mode | Command | Description |
|------|---------|-------------|
| Assist | (default) | Chat with the agent — you control the flow |
| Agent | `/agent <task>` | Autonomous execution of a single task |
| Crew | `/crew <task>` | Multi-agent mode with orchestrator and workers |

<details>
<summary>TUI command reference</summary>

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

</details>

## APK Analysis

BinAgent includes a deterministic APK solver (no LLM required) for fast CTF challenge solving:

- Extracts APKs using `apktool`
- Decompiles Java sources using `jadx`
- Scans for flag patterns and encoded tokens
- Tries common decoders (Base64, Base32, hex, ROT13, XOR)

```bash
binagent apk ./challenge.apk --mode solve                          # Solve APK challenge
binagent apk ./challenge.apk --mode solve --flag-regex "myctf\{[^}]+\}"  # Custom flag pattern
binagent apk ./challenge.apk                                       # Analysis only
```

**Requirements:** `apktool`, `jadx`, `default-jdk`

## Installation

### Requirements

- Python 3.10+
- API key for an LLM provider (Anthropic, OpenAI, or any [LiteLLM-supported provider](https://docs.litellm.ai/docs/providers))

### Setup

```bash
git clone https://github.com/GH05TCREW/pentestagent.git
cd pentestagent

# Option A: Setup script
./scripts/setup.sh          # Linux/macOS
.\scripts\setup.ps1         # Windows

# Option B: Manual
python -m venv venv
source venv/bin/activate    # Linux/macOS
pip install -e ".[all]"
```

### Configuration

Create a `.env` file in the project root:

```bash
# LLM provider (pick one)
ANTHROPIC_API_KEY=sk-ant-...
# OPENAI_API_KEY=sk-...

# Model selection (any LiteLLM-supported model)
PENTESTAGENT_MODEL=claude-sonnet-4-20250514

# Ghidra integration (optional)
GHIDRA_INSTALL_DIR=/path/to/ghidra_11.x
JAVA_HOME=/path/to/jdk-21
```

### Makefile Targets

```bash
make install          # Install dependencies
make test             # Run test suite
make solve DESC="..."       # Unified solver
make solve FILE=./chall     # Solve file-based challenge
make ctf-apk APK=./app.apk # APK solver
make clean            # Clean build artifacts
```

## Docker

Run BinAgent in a Docker container with pre-installed tools:

```bash
# Base image
docker run -it --rm \
  -e ANTHROPIC_API_KEY=your-key \
  -e PENTESTAGENT_MODEL=claude-sonnet-4-20250514 \
  ghcr.io/gh05tcrew/pentestagent:latest

# Kali image (metasploit, sqlmap, hydra, etc.)
docker run -it --rm \
  -e ANTHROPIC_API_KEY=your-key \
  ghcr.io/gh05tcrew/pentestagent:kali

# Build locally
docker compose build
docker compose run --rm pentestagent
```

## Project Structure

```
pentestagent/
  agents/              # Agent implementations
    general_agent.py   #   GeneralAgent (analyze/solve — primary agent)
    base_agent.py      #   BaseAgent ABC with plan-act-observe loop
    binary_agent/      #   BinaryAnalystAgent (alternative implementation)
    crew/              #   Multi-agent orchestration
  apk/                 # Deterministic APK analyzer and solver
  config/              # Settings and constants
  ctf/                 # CTF parser, runner, solver
  interface/           # CLI entry points and TUI
  knowledge/           # RAG system and shadow graph
  llm/                 # LiteLLM wrapper (any provider)
  mcp/                 # MCP client, server configs, adapters
  playbooks/           # Attack playbooks
  runtime/             # Local and Docker execution environments
  tools/               # Built-in tools (terminal, browser, notes, etc.)
third_party/           # Vendored MCP servers (HexStrike, Metasploit)
docs/                  # Architecture docs and related papers
```

## Research Context

BinAgent is positioned as a **control-layer contribution** to the LLM-assisted binary analysis space. Rather than building new static or dynamic analysis primitives, it orchestrates existing tools (Ghidra, Metasploit) through a structured agent loop with mandatory planning, bounded execution, and evidence-linked findings. The architecture is informed by both agent reliability research (ReAct, Plan-and-Solve, CRITIC, Reflexion) and binary analysis literature (VulBinLLM, LLM4Decompile), applying agent decomposition patterns to the specific constraints of reverse engineering workflows — large context, expensive tool calls, and the need for verifiable evidence.

For detailed architecture documentation and design rationale, see [`docs/binary_agent_architecture.md`](docs/binary_agent_architecture.md). For a curated survey of related work, see [`docs/binary_agent_related_papers.md`](docs/binary_agent_related_papers.md).

### References

- Yao et al. **ReAct: Synergizing Reasoning and Acting in Language Models.** ICLR 2023. [arXiv:2210.03629](https://arxiv.org/abs/2210.03629)
- Wang et al. **Plan-and-Solve Prompting.** ACL 2023. [arXiv:2305.04091](https://arxiv.org/abs/2305.04091)
- Gou et al. **CRITIC: Large Language Models Can Self-Correct with Tool-Interactive Critiquing.** ICLR 2024. [arXiv:2305.11738](https://arxiv.org/abs/2305.11738)
- Shinn et al. **Reflexion: Language Agents with Verbal Reinforcement Learning.** NeurIPS 2023. [arXiv:2303.11366](https://arxiv.org/abs/2303.11366)
- Ye et al. **VulBinLLM: LLM-powered Vulnerability Detection for Stripped Binaries.** 2025. [arXiv:2505.22010](https://arxiv.org/abs/2505.22010)
- Tan et al. **LLM4Decompile: Decompiling Binary Code with Large Language Models.** EMNLP 2024. [arXiv:2403.05286](https://arxiv.org/abs/2403.05286)
- Yang et al. **SWE-agent: Agent-Computer Interfaces Enable Automated Software Engineering.** 2024. [arXiv:2405.15793](https://arxiv.org/abs/2405.15793)
- Deng et al. **PentestGPT: An LLM-Empowered Automatic Penetration Testing Tool.** 2024. [arXiv:2308.06782](https://arxiv.org/abs/2308.06782)

## Acknowledgments

BinAgent builds on [PentestAgent](https://github.com/GH05TCREW/pentestagent) by GH05TCREW. Additional integrations:

- [HexStrike AI](https://github.com/0x4m4/hexstrike-ai) — MCP-enabled pentesting toolkit (vendored under `third_party/hexstrike`)
- [pyghidra-mcp](https://github.com/DarkMatter-999/pyghidra-mcp) — Ghidra analysis via Model Context Protocol

## Legal

Only use against systems you have explicit authorization to test. Unauthorized access is illegal.

## License

MIT — see [LICENSE.txt](LICENSE.txt).
