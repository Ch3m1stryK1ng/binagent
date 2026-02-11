# BinAgent Firmware Benchmark Manifest (Readable)

Machine-readable file:
- `docs/benchmark_manifest.json`

## Purpose
This benchmark is designed for **effectiveness-first** evaluation of BinAgent on firmware binary analysis.

It is split into three groups:
1. `positive_cve`: weak ground-truth samples with CVE labels.
2. `negative_no_cve`: no-CVE controls to estimate false positives.
3. `unknown_real_world`: real-world firmware where full ground truth is unavailable.

## Dataset Summary
- Total samples: **24**
- Positive (`CVE-*`): **10**
- Negative (`CVE-no-CVE-*`): **2**
- Unknown real-world: **12**

## Why This Is Better Than the Demo List
- Adds weak-ground-truth CVE-labeled cases for measurable recall/hit-rate.
- Adds explicit no-CVE controls for false-positive measurement.
- Keeps realistic unlabeled firmware for external validity.
- Includes both ELF and raw blobs to stress analysis robustness.

## Group Details

### 1) positive_cve (10)
Source:
- `monolithic-firmware-collection/ARMCortex-M/D_FUZZWARE/new-targets/zephyr-os/prebuilt_samples/`

Examples:
- `.../CVE-2021-3321/zephyr-CVE-2021-3321.elf`
- `.../CVE-2021-3330/zephyr-CVE-2021-3330.elf`

Use for:
- `cve_hit_rate_on_positive`

### 2) negative_no_cve (2)
Examples:
- `.../CVE-no-CVE-false-positive-rf-size-check/zephyr-CVE-no-CVE-false-positive-rf-size-check.elf`
- `.../CVE-no-CVE-false-positive-watchdog-callback/zephyr-CVE-no-CVE-false-positive-watchdog-callback.elf`

Use for:
- `false_positive_rate_on_negative`

### 3) unknown_real_world (12)
Examples:
- `monolithic-firmware-collection/ARMCortex-M/p2im_console/p2im_console.elf`
- `monolithic-firmware-collection/ARMCortex-M/st-plc/st-plc.elf`
- `monolithic-firmware-collection/ARMCortex-M/D_POLYPUS/BCM4345C0.bin`
- `monolithic-firmware-collection/ARMCortex-R/ShannonBaseband/modem.bin`

Use for:
- analyst validation quality and generalization checks

## Recommended Metrics
- `cve_hit_rate_on_positive`
- `false_positive_rate_on_negative`
- `evidence_completeness_rate`
- `time_to_first_actionable_finding`
- `analyst_validation_pass_rate`

## Minimal Batch-Run Example
```bash
jq -r '.groups[].samples[].path' docs/benchmark_manifest.json | while read -r fw; do
  echo "[RUN] $fw"
  binagent analyze "$fw" --task "Find likely vulnerabilities with evidence"
done
```

## Notes
- Treat `positive_cve` as weak ground truth (good for relative comparison, not absolute completeness).
- Treat `unknown_real_world` as realism/generalization set, not a strict precision/recall set.
- Keep run artifacts (`plan.json`, `evidence.json`, `outcome.json`) for later ablation and error analysis.
