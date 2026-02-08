# BinaryAnalystAgent Architecture

This document provides an audit-grade confirmation of the MCP + LLM + Agent architecture for the BinaryAnalystAgent.

## Architecture Diagram

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                              User Task                                       │
│              "Analyze binary for buffer overflows"                           │
│                         pentestagent analyze ./binary                        │
└─────────────────────────────────────────────────────────────────────────────┘
                                      │
                                      ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                          CLI Entry Point                                     │
│                    interface/main.py → interface/cli.py                      │
│                       run_binary_analysis()                                  │
└─────────────────────────────────────────────────────────────────────────────┘
                                      │
            ┌─────────────────────────┼─────────────────────────┐
            │                         │                         │
            ▼                         ▼                         ▼
┌───────────────────┐   ┌───────────────────┐   ┌───────────────────────────┐
│   MCP Manager     │   │       LLM         │   │    Tool Registry          │
│  mcp/manager.py   │   │    llm/llm.py     │   │   tools/registry.py       │
│                   │   │                   │   │                           │
│ • connect_all()   │   │ • generate()      │   │ • get_all_tools()         │
│ • IDA adapter     │   │ • LiteLLM wrapper │   │ • register_tool_instance()│
└───────────────────┘   └───────────────────┘   └───────────────────────────┘
            │                         │                         │
            └─────────────────────────┼─────────────────────────┘
                                      │
                                      ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                        BinaryAnalystAgent                                    │
│              agents/binary_agent/binary_agent.py                             │
│                                                                              │
│  ┌─────────────────────────────────────────────────────────────────────┐    │
│  │                    BOOTSTRAP PHASE (NEW)                            │    │
│  │  1. verify_ida_tools() - Check required IDA tools exist             │    │
│  │  2. load_binary() - Auto-load binary into IDA                       │    │
│  │  3. Fail fast if tools missing (unless offline_mode=True)           │    │
│  └─────────────────────────────────────────────────────────────────────┘    │
│                                      │                                       │
│                                      ▼                                       │
│  ┌─────────────────────────────────────────────────────────────────────┐    │
│  │                     AGENT LOOP (BaseAgent)                          │    │
│  │                    agents/base_agent.py                             │    │
│  │                                                                      │    │
│  │  while iteration < max_iterations:                                   │    │
│  │      response = await self.llm.generate(                            │    │
│  │          system_prompt=self.get_system_prompt(),  ←─┐               │    │
│  │          messages=self._format_messages_for_llm(),  │               │    │
│  │          tools=self.tools,                          │ LLM CALL      │    │
│  │      )                                            ──┘               │    │
│  │                                                                      │    │
│  │      if response.tool_calls:                                        │    │
│  │          tool_results = await self._execute_tools(tool_calls)       │    │
│  │                                      │                               │    │
│  └──────────────────────────────────────┼───────────────────────────────┘    │
└─────────────────────────────────────────┼───────────────────────────────────┘
                                          │
                                          ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                         Tool Execution                                       │
│                      tools/registry.py → Tool.execute()                      │
│                                                                              │
│  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────────────────┐  │
│  │  MCP IDA Tools  │  │  Built-in Tools │  │     Other MCP Tools         │  │
│  │                 │  │                 │  │                             │  │
│  │ • load_binary   │  │ • terminal      │  │ • hexstrike_*               │  │
│  │ • get_functions │  │ • notes         │  │ • metasploit_*              │  │
│  │ • disassemble   │  │ • browser       │  │                             │  │
│  │ • get_strings   │  │ • web_search    │  │                             │  │
│  │ • find_xrefs    │  │ • finish        │  │                             │  │
│  └────────┬────────┘  └─────────────────┘  └─────────────────────────────┘  │
└───────────┼─────────────────────────────────────────────────────────────────┘
            │
            ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                          MCP Protocol                                        │
│                         mcp/tools.py                                         │
│                      create_mcp_tool()                                       │
│                                                                              │
│  Tool call: mcp_ida-local_load_binary                                        │
│      → manager.call_tool("ida-local", "load_binary", args)                   │
│      → server.transport.send({method: "tools/call", params: {...}})          │
└─────────────────────────────────────────────────────────────────────────────┘
            │
            ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                        IDA MCP Server                                        │
│               third_party/ida_mcp/ida_server.py                              │
│                                                                              │
│  FastMCP server exposing IDA Pro functionality:                              │
│  • load_binary(file_path) → Binary metadata                                  │
│  • get_functions(filter) → Function list                                     │
│  • disassemble_function(address) → Assembly + dangerous call detection       │
│  • get_strings(min_length) → String extraction                               │
│  • find_xrefs(address, direction) → Cross-references                         │
└─────────────────────────────────────────────────────────────────────────────┘
            │
            ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                           IDA Pro                                            │
│                    (External application)                                    │
│                                                                              │
│  IDA batch mode execution:                                                   │
│  idat64 -A -S"script.py" binary                                              │
│                                                                              │
│  IDAPython script runs analysis and returns JSON results                     │
└─────────────────────────────────────────────────────────────────────────────┘
```

## Code Path Proof: LLM is Invoked

### 1. Entry Point
**File:** `interface/main.py:381-390`
```python
from .cli import run_binary_analysis
asyncio.run(
    run_binary_analysis(
        binary_path=args.binary,
        model=args.model,
        ...
    )
)
```

### 2. LLM Creation
**File:** `interface/cli.py:868-870`
```python
llm = LLM(model=model)
logger.info(f"[LLM] Initialized with model: {model}")
```

### 3. Agent Creation with LLM
**File:** `interface/cli.py:1035-1042`
```python
agent = BinaryAnalystAgent(
    llm=llm,           # ← LLM instance passed here
    tools=tools,
    runtime=runtime,
    binary_path=binary_path,
    offline_mode=offline_mode,
)
```

### 4. Agent Loop Invocation
**File:** `interface/cli.py:1079`
```python
async for response in agent.agent_loop(task_msg):
```

### 5. LLM.generate() Called in Loop
**File:** `agents/base_agent.py:234-238`
```python
response = await self.llm.generate(
    system_prompt=self.get_system_prompt(),
    messages=self._format_messages_for_llm(),
    tools=self.tools,
)
```

### 6. Actual LiteLLM API Call
**File:** `llm/llm.py:181-185`
```python
async def _call():
    return await self._litellm.acompletion(**call_kwargs)

response = await self._retry_with_backoff(_call)
```

## Tool Registration Flow

### 1. Built-in Tools Auto-loaded
**File:** `tools/__init__.py:20`
```python
_loaded = load_all_tools()  # Loads terminal, notes, browser, etc.
```

### 2. MCP Tools Connected
**File:** `interface/cli.py:845-858`
```python
mcp_tools = await mcp_manager.connect_all()
for tool in mcp_tools:
    register_tool_instance(tool)  # Registers mcp_ida-local_* tools
```

### 3. Tools Passed to Agent
**File:** `interface/cli.py:872`
```python
tools = get_all_tools()  # Returns all registered tools
```

### 4. Tools Converted for LLM
**File:** `llm/llm.py:156-157`
```python
if tools:
    llm_tools = [tool.to_llm_format() for tool in tools if tool.enabled]
```

### 5. Tool Schema Format
**File:** `tools/registry.py:62-75`
```python
def to_llm_format(self) -> dict:
    return {
        "type": "function",
        "function": {
            "name": self.name,
            "description": self.description,
            "parameters": {
                "type": self.schema.type,
                "properties": self.schema.properties or {},
                "required": self.schema.required or [],
            },
        },
    }
```

## Runtime Guards (New)

### Required IDA Tools
**File:** `agents/binary_agent/binary_agent.py:22-28`
```python
REQUIRED_IDA_TOOLS = [
    "load_binary",
    "get_functions",
    "disassemble_function",
    "get_strings",
    "find_xrefs",
]
```

### Bootstrap Verification
**File:** `agents/binary_agent/binary_agent.py:85-150`
```python
async def bootstrap(self) -> Dict[str, Any]:
    # 1. Verify binary file exists
    # 2. Verify IDA tools (fail fast if missing)
    # 3. Auto-load binary into IDA
    # Returns status dict or raises exception
```

### Fail-Fast Exceptions
- `IDAToolsNotAvailableError`: Required IDA tools not connected
- `BinaryNotLoadedError`: Failed to load binary into IDA

## Observability Logging

Log prefixes and their meanings:
- `[BINARY_AGENT]` - Agent lifecycle events
- `[LLM]` - LLM initialization and calls
- `[MCP]` - MCP connection events
- `[TOOLS]` - Tool registration

Example log output:
```
12:34:56 [MCP] Initializing MCP connections...
12:34:56 [MCP] Config path: /path/to/mcp_servers.json
12:34:57 [MCP] Connected. Total tools: 8
12:34:57 [TOOLS] Registered MCP tools: ['mcp_ida-local_load_binary', ...]
12:34:57 [MCP] IDA tools found: ['mcp_ida-local_load_binary', ...]
12:34:57 [LLM] Initialized with model: gpt-4
12:34:57 [BINARY_AGENT] === INITIALIZATION START ===
12:34:57 [BINARY_AGENT] Starting bootstrap...
12:34:58 [BINARY_AGENT] load_binary() called for: /path/to/binary
12:34:59 [BINARY_AGENT] load_binary SUCCESS
12:34:59 [BINARY_AGENT] Bootstrap SUCCESS - mode=ida
12:34:59 [BINARY_AGENT] === ANALYSIS PHASE START ===
```

## Verification Commands

### Test with IDA MCP Available
```bash
# Ensure IDA MCP is running
LAUNCH_IDA=1 pentestagent analyze ./test_binary --task "Find buffer overflows"

# Check logs for:
# - [MCP] IDA tools found: [...]
# - [BINARY_AGENT] load_binary SUCCESS
# - [LLM] Response received
```

### Test Failure Mode (No IDA)
```bash
# Without IDA MCP
LAUNCH_IDA=0 pentestagent analyze ./test_binary

# Should fail with:
# ERROR: IDA MCP tools not available
# Missing: ['load_binary', 'get_functions', ...]
```

### Test Offline Mode
```bash
# Explicit offline mode (limited analysis)
pentestagent analyze ./test_binary --offline

# Should show:
# Running in OFFLINE MODE - IDA tools not available
```

## Paper-Grounded Design Mapping

This architecture can be positioned as a control-layer contribution informed by prior work:

1. **Firmware-scale feasibility baseline**
- FIRMADYNE (NDSS 2016), FirmAE (ACSAC 2020), FirmSolo (USENIX Security 2023), Pandawan (USENIX Security 2024), and FFXE (USENIX Security 2024) establish firmware analysis/rehosting and CFG recovery at scale.
- Our distinction: instead of building a new emulator/rehoster, we optimize planner behavior under constrained tool budgets and incomplete context.

2. **Selective deep analysis over brute force**
- Driller (NDSS 2016) and QSYM (USENIX Security 2018) show that hybrid/selective expensive analysis outperforms naive exhaustive strategies.
- Our analogue: prioritize risky functions/callsites first, then perform bounded deep dives with explicit evidence requirements.

3. **LLM + binary analysis integration**
- VulBinLLM (arXiv 2505.22010) and LLM4Decompile (EMNLP 2024) support the viability of LLM-enhanced binary workflows.
- Our distinction: mandatory `plan -> act -> observe -> re-plan` loop and machine-checkable evidence objects as first-class outputs.

4. **Agent reliability patterns**
- ReAct, Plan-and-Solve, Reflexion, CRITIC, and MemGPT motivate decomposition, critique loops, and memory control.
- Our implementation choice: bounded iterations, fail-fast bootstrap checks, and evidence-linked observations before re-planning.

## Recommended Paper-Focused Evaluation Additions

To align this architecture with the literature above, add these ablations:

1. **Planning policy ablation**
- Compare: direct tool-use (no explicit plan) vs single upfront plan vs iterative re-plan.
- Metrics: success rate, wall-clock time, tool calls, token cost.

2. **Prioritization policy ablation**
- Compare: random traversal vs heuristic risky-API ranking vs evidence-aware ranking.
- Metrics: time-to-first-valid finding, findings/tool-call, false positive rate.

3. **Context/memory policy ablation**
- Compare: full transcript context vs compressed summaries vs structured evidence store.
- Metrics: latency, token usage, regression in finding quality.

4. **Scalability characterization**
- Plot outcomes against binary scale indicators: number of functions, xrefs, and disassembly size.
- Report degradation points and dominant failure modes from logs.

## Reference Index (Suggested)

- ReAct: https://arxiv.org/abs/2210.03629
- Plan-and-Solve: https://arxiv.org/abs/2305.04091
- Reflexion: https://arxiv.org/abs/2303.11366
- CRITIC: https://arxiv.org/abs/2305.11738
- MemGPT: https://arxiv.org/abs/2310.08560
- VulBinLLM: https://arxiv.org/abs/2505.22010
- LLM4Decompile: https://arxiv.org/abs/2403.05286
- FIRMADYNE: https://www.ndss-symposium.org/wp-content/uploads/2017/09/towards-automated-dynamic-analysis-linux-based-embedded-firmware.pdf
- Driller: https://www.ndss-symposium.org/wp-content/uploads/2017/09/driller-augmenting-fuzzing-through-selective-symbolic-execution.pdf
- QSYM: https://www.usenix.org/conference/usenixsecurity18/presentation/yun
- FirmSolo: https://www.usenix.org/conference/usenixsecurity23/presentation/angelakopoulos
- Pandawan: https://www.usenix.org/conference/usenixsecurity24/presentation/angelakopoulos
