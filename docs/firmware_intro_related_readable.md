# Introduction
Firmware remains a high-impact and persistent attack surface: it is widely deployed, tightly coupled to device-critical functionality, and often updated less frequently than user-space software. Auditing firmware binaries is hard because source code is usually unavailable, architectures/toolchains are heterogeneous, and the analysis space becomes too large for exhaustive exploration under realistic time and compute limits. This creates a recurring gap between theoretically analyzable and operationally auditable.

This project studies whether an LLM-driven security agent can reduce that gap via structured planning plus tool-grounded binary analysis. The focus is vulnerability detection in stripped or partially symbolized binaries, where the agent must infer structure, prioritize risky regions, and justify findings with explicit evidence. Instead of brute-force tool invocation, the agent uses a `plan -> act -> observe -> replan` loop with bounded iterations, evidence-aware prioritization (dangerous APIs, cross-references, data-flow hints), and scalable decomposition (coarse triage plus selective deep dives). The objective is to improve both effectiveness (real vulnerabilities found) and efficiency (latency and tool/token cost), while preserving auditability via machine-checkable evidence trails.

Research question:
How can a security agent expand the range of binary vulnerability tasks it can solve from minimal task descriptions, while remaining fast and reliable on large firmware inputs, using principled planning and evidence-guided decomposition?

To answer this, the project develops **BinAgent**, built on top of the open-source **PentestAgent** framework, and evaluates it on progressively harder reverse-engineering and vulnerability-analysis tasks. The intended contribution is a practical control-layer architecture for firmware-scale binary auditing that is measurable, reproducible, and extensible across analysis backends.

## Planned Contributions
1. A planner-centric agent architecture for firmware binary auditing that integrates LLM reasoning with static-analysis/decompiler tooling, and requires evidence-linked outputs.
2. An evidence-aware prioritization policy for large binaries that ranks risky functions/callsites before deep inspection, reducing unnecessary exploration.
3. A scalable decomposition workflow (coarse-to-fine analysis, selective deep dives, caching/memory control) designed for latency and cost constraints.
4. An artifact-driven evaluation protocol (plans, tool logs, evidence traces, outcomes) to study speed-quality tradeoffs and failure modes.

# Related Work
## Firmware Binary Analysis
Foundational firmware work established scalable pipelines for extraction, rehosting, and dynamic analysis. Large-scale studies surfaced ecosystem-wide weaknesses (Costin et al., 2014). FIRMADYNE (NDSS 2016) and FirmAE (ACSAC 2020) improved automated firmware emulation and practical rehosting success. More recent systems broaden coverage across user/kernel boundaries and device behavior, including FirmSolo (USENIX Security 2023), Pandawan (USENIX Security 2024), and work on peripheral modeling and CFG recovery (e.g., Laelaps, FFXE). These systems are essential for execution coverage, but they do not directly solve planner-level prioritization under strict latency budgets. This project complements them by optimizing what to analyze next when full emulation context is unavailable or too expensive.

## Binary Vulnerability Discovery and Program Analysis
Classical binary vulnerability discovery combines symbolic execution, concolic execution, and fuzzing. Driller (NDSS 2016) showed that selective symbolic execution can amplify fuzzing efficiency; QSYM (USENIX Security 2018) emphasized practical performance in hybrid concolic workflows. Cross-architecture bug-discovery systems and SoK analyses reinforce a central lesson: selective expensive reasoning generally beats exhaustive search. This project applies that lesson at the agent-control layer: use cheap global scans to rank hypotheses, then spend expensive tool calls only on evidence-supported regions.

## LLMs for Binary Analysis
Recent work shows that LLMs can contribute directly to binary workflows. LLM4Decompile (EMNLP 2024) demonstrates strong LLM-assisted decompilation and highlights functional/executability-oriented evaluation. VulBinLLM (arXiv 2025) targets stripped-binary vulnerability detection and introduces decompilation optimization plus long-context memory strategies. These works motivate feasibility, but they leave open a systems question central to this project: how to keep tool use bounded, evidence-linked, and robust as binary scale increases.

## LLM Tool-Using Agents for Security Tasks
Tool-using LLM agents are stronger when reasoning is interleaved with external actions (ReAct, Toolformer). Planning-centric variants (Plan-and-Solve, Tree-of-Thoughts), critique/reflection loops (Reflexion, CRITIC), and memory hierarchies (MemGPT) provide concrete patterns for long-horizon reliability. In security, PentestGPT and autonomous web-hacking studies show promise but also expose reproducibility and robustness limits on complex tasks. This project operationalizes these lessons with mandatory planning, bounded loops, and strict evidence linkage (e.g., CWE + function/address + snippet + tool provenance).

## Positioning of This Work
This project sits at the intersection of firmware reverse engineering, binary analysis, and LLM agent orchestration. The novelty is not a new decompiler, emulator, or symbolic engine; it is a control-layer design that:
1. Adapts analysis depth to observed evidence.
2. Prioritizes dangerous regions before broad exploration.
3. Manages context/cost via scalable decomposition and memory control.
4. Produces machine-checkable artifacts suitable for regression testing.

This makes the system a practical research vehicle for studying scalability and reliability in firmware-oriented binary auditing.
