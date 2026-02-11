# BinAgent Analyze Mode: Logic and Pipeline

## 1) High-Level Control Logic

```mermaid
flowchart TD
    A[CLI: binagent analyze <binary>] --> B[Initialize GeneralAgent + Runtime + Tools]
    B --> C[Connect MCP servers]
    
    *C --> D[Preflight Evidence Collection]
    
    D --> E[Generate Initial Plan]
    E --> F[Execute Loop: Think -> Tool Calls -> Observe]
    F --> G{Progress?}
    G -- Yes --> H[Update Findings + Evidence + Plan State]
    H --> I{Plan Complete?}
    I -- No --> F
    I -- Yes --> J[Finalize Summary]
    G -- No --> K{Stagnation/Max Iteration?}
    K -- No --> F
    K -- Yes --> L[Early Stop or Safety Stop]
    J --> M[Write Artifacts]
    L --> M
    M --> N[outcome.json / evidence.json / tool_log.json / transcript.txt / conversation.md / plan.json]
```

## 2) *Analyze Mode Dataflow (Evidence-Centric)

```mermaid
flowchart LR
    T[Tool Outputs\nrun_command / ghidra tools] --> X[Evidence Extractor]
    U[LLM Text Output] --> Y[Content Finding Extractor]
    X --> F[Raw Findings Buffer]
    Y --> F
    F --> Z[Normalize Findings]
    Z --> D[Evidence-Aware Dedup]
    D --> O[Final Findings in outcome.json]
```

## 3) Sequence View (One Typical Run)

```mermaid
sequenceDiagram
    participant User
    participant CLI as binagent CLI
    participant Agent as GeneralAgent(analyze)
    participant LLM
    participant Tools
    participant Ghidra as ghidra-local MCP

    User->>CLI: binagent analyze <elf>
    CLI->>Agent: solve(mode=analyze)
    Agent->>Tools: preflight run_command(file/readelf)
    Agent->>Ghidra: import_binary + list/search/xref/decompile
    Agent->>LLM: planning prompt (short analyze plan)
    LLM-->>Agent: plan steps
    loop Plan-Act-Observe
      Agent->>LLM: next-step context + evidence
      LLM-->>Agent: tool calls / reasoning
      Agent->>Tools: execute calls
      Tools-->>Agent: results
      Agent->>Agent: extract evidence + findings
    end
    Agent->>Agent: normalize + deduplicate findings
    Agent->>CLI: print summary
    Agent->>Agent: save artifacts
```

## 4) Key Mechanisms

- Planning first, but now phrased as guidance (not hard-blocking) to reduce tool-use resistance.
- Preflight front-loads static evidence so later LLM steps can focus on triage and mapping to CWE.
- Findings are extracted from:
  - structured tool outputs (especially decompile/xref),
  - model outputs (only non-plan content).
- Dedup is evidence-aware, not exact-string-only:
  - compares CWE + location + evidence similarity,
  - merges duplicates while keeping stronger evidence/confidence.
- Safety guards:
  - protocol sanitization for tool-call message format,
  - LLM API retry/stop behavior,
  - stagnation early-stop to avoid wasting loops.

## 5) Artifact Contract

- `plan.json`: the planned steps for this run.
- `tool_log.json`: all tool calls/results (audit trail).
- `evidence.json`: extracted evidence snippets.
- `outcome.json`: final normalized + deduplicated findings.
- `transcript.txt`: chronological runtime events.
- `conversation.md`: full conversation/tool exchange history.

## 6) One-Line Summary

`binagent analyze` is an evidence-driven control loop: collect static signals, plan actions, execute selectively, convert outputs to CWE findings, deduplicate by evidence similarity, and emit reproducible artifacts.

