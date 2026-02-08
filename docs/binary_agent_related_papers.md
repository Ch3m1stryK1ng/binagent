# Related Papers for LLM-Driven Binary/Firmware Vulnerability Agent

This note curates papers most relevant to your current direction:
- `Track A`: firmware-focused vulnerability detection from binaries.
- `Track B`: scalable/reliable agent design (planning, decomposition, evidence loops).

## 1) Closest Binary/LLM Papers

1. **VulBinLLM: LLM-powered Vulnerability Detection for Stripped Binaries (arXiv 2025)**
Link: https://arxiv.org/abs/2505.22010
Why it matters:
- Directly aligned with your core problem (stripped binaries + vuln reasoning).
- Uses decompilation optimization + memory/extended-context workflow.
What to borrow:
- Treat decompilation quality and memory policy as first-class components in the pipeline.
- Keep detection output tied to explicit evidence objects, not only natural-language claims.

2. **LLM4Decompile: Decompiling Binary Code with Large Language Models (EMNLP 2024)**
Links:
- https://arxiv.org/abs/2403.05286
- https://aclanthology.org/2024.emnlp-main.203/
Why it matters:
- Strong recent baseline for LLM-assisted binary decompilation.
- Emphasizes re-executability/recompilability style evaluation, not just text similarity.
What to borrow:
- Evaluate upstream decompilation quality separately from downstream vulnerability reasoning.
- Track executability-oriented metrics as an early predictor of reasoning quality.

## 2) Firmware Analysis Foundations (Track A)

1. **FIRMADYNE: Towards Automated Dynamic Analysis for Linux-based Embedded Firmware (NDSS 2016)**
Links:
- https://www.ndss-symposium.org/ndss2016/ndss-2016-programme/
- https://www.ndss-symposium.org/wp-content/uploads/2017/09/towards-automated-dynamic-analysis-linux-based-embedded-firmware.pdf
Relevance:
- Foundational scalable firmware emulation pipeline and vulnerability validation framing.

2. **FirmAE: Towards Large-Scale Emulation of IoT Firmware for Dynamic Analysis (ACSAC 2020)**
Link: https://www.acsac.org/2020/program/final/s313.html
Relevance:
- Focuses on raising rehosting success rate (important for coverage before deep analysis).

3. **Device-agnostic Firmware Execution is Possible (Laelaps, ACSAC 2020)**
Link: https://www.acsac.org/2020/program/final/s254.html
Relevance:
- Peripheral emulation with concolic assistance; useful when binaries depend on unknown device behavior.

4. **FirmSolo: Enabling dynamic analysis of binary Linux-based IoT kernel modules (USENIX Security 2023)**
Link: https://www.usenix.org/conference/usenixsecurity23/presentation/angelakopoulos
Relevance:
- Extends analysis into kernel modules; good reference if your firmware track expands beyond user space.

5. **Pandawan: Quantifying Progress in Linux-based Firmware Rehosting (USENIX Security 2024)**
Link: https://www.usenix.org/conference/usenixsecurity24/presentation/angelakopoulos
Relevance:
- Useful for benchmarking rehosting quality and holistic user+kernel analysis at scale.

6. **FFXE: Dynamic Control Flow Graph Recovery for Embedded Firmware Binaries (USENIX Security 2024)**
Link: https://www.usenix.org/conference/usenixsecurity24/presentation/tsang
Relevance:
- CFG recovery improves downstream triage/ranking quality for evidence-guided deep dives.

## 3) Binary Vulnerability Discovery at Scale (Pre-LLM but Still Critical)

1. **Driller: Augmenting Fuzzing Through Selective Symbolic Execution (NDSS 2016)**
Links:
- https://www.ndss-symposium.org/ndss2016/ndss-2016-programme/
- https://www.ndss-symposium.org/wp-content/uploads/2017/09/driller-augmenting-fuzzing-through-selective-symbolic-execution.pdf
Relevance:
- Classic coarse-to-fine hybridization pattern: cheap exploration first, expensive reasoning only where needed.

2. **QSYM: A Practical Concolic Execution Engine Tailored for Hybrid Fuzzing (USENIX Security 2018)**
Link: https://www.usenix.org/conference/usenixsecurity18/presentation/yun
Relevance:
- Practical performance-minded concolic design. Strong inspiration for selective deep analysis policies.

3. **discovRE: Efficient Cross-Architecture Identification of Bugs in Binary Code (NDSS 2016)**
Link: https://www.ndss-symposium.org/ndss2016/ndss-2016-programme/
Relevance:
- Efficient pre-filter + expensive semantic compare workflow mirrors your evidence-aware prioritization idea.

4. **SoK: (State of) The Art of War: Offensive Techniques in Binary Analysis (IEEE S&P 2016)**
Link: https://ieeexplore.ieee.org/document/7546500/
Relevance:
- Still useful as a taxonomy anchor for positioning your contribution as control-layer orchestration, not a new static/dynamic primitive.

## 4) Agent Planning / Reliability / Decomposition (Track B)

1. **ReAct (ICLR 2023)**
Link: https://arxiv.org/abs/2210.03629
Relevance:
- Canonical plan-act-observe style reasoning+action loop.

2. **Toolformer (2023)**
Link: https://arxiv.org/abs/2302.04761
Relevance:
- Tool-use as a learned decision problem; motivates explicit tool-call governance.

3. **Plan-and-Solve Prompting (ACL 2023)**
Link: https://arxiv.org/abs/2305.04091
Relevance:
- Explicit planning stage improves difficult task reliability from minimal prompts.

4. **Tree of Thoughts (NeurIPS 2023)**
Link: https://arxiv.org/abs/2305.10601
Relevance:
- Search over reasoning branches; useful for bounded alternative hypothesis testing.

5. **Reflexion (2023)**
Link: https://arxiv.org/abs/2303.11366
Relevance:
- Verbal feedback memory for iterative improvement without fine-tuning.

6. **CRITIC (ICLR 2024)**
Link: https://arxiv.org/abs/2305.11738
Relevance:
- Tool-interactive critique loop; aligns with your evidence-linked verification stage.

7. **Voyager (2023)**
Link: https://arxiv.org/abs/2305.16291
Relevance:
- Skill library/curriculum concepts map to caching reusable binary-analysis procedures.

8. **MemGPT (2024)**
Link: https://arxiv.org/abs/2310.08560
Relevance:
- Hierarchical memory management ideas for long-context binaries and long sessions.

9. **SWE-agent (2024)**
Link: https://arxiv.org/abs/2405.15793
Relevance:
- A practical example of interface-constrained agent loops with benchmark-driven evaluation.

## 5) Security-Agent Benchmarks / Reality Check

1. **PentestGPT (2023/2024)**
Link: https://arxiv.org/abs/2308.06782
Relevance:
- Good reference for decomposition into sub-modules and scenario-level evaluation.

2. **LLM Agents can Autonomously Hack Websites (2024)**
Link: https://arxiv.org/abs/2402.06664
Relevance:
- Demonstrates frontier agent capability and highlights safety/evaluation implications for offensive workflows.

## 6) Suggested Positioning Statements for Your Writeups

Use these in intro/related-work sections (adapt as needed):

1. Prior firmware systems (FIRMADYNE/FirmAE/FirmSolo/Pandawan) improve execution and coverage, but do not directly solve planner-level prioritization under strict latency budgets.
2. Prior binary analysis systems (Driller/QSYM/discovRE) show that selective deep analysis beats exhaustive search; your agent applies this principle at the control layer with LLM planning and evidence constraints.
3. Recent LLM-binary works (VulBinLLM, LLM4Decompile) validate feasibility, but your emphasis is operational reliability on larger inputs through bounded planning, decomposition, and explicit evidence trails.
4. Agent papers (ReAct/Plan-and-Solve/CRITIC/Reflexion/MemGPT) motivate architecture choices; your contribution is a security-specific instantiation with measurable speed/quality tradeoffs.

## 7) High-Value Experiments to Add Next

1. **Ablate planning depth**: no-plan vs single-plan vs re-plan under same tool budget.
2. **Ablate prioritization**: random function order vs heuristic risk ranking vs evidence-aware ranking.
3. **Ablate memory policy**: full transcript vs compressed memory vs structured evidence store.
4. **Scalability curves**: runtime/cost/success against binary size (#functions, #xrefs, code bytes).
5. **Evidence quality**: rate of findings with reproducible function+address+snippet+CWE linkage.

These experiments make your work more comparable to both the firmware and agent literature.
