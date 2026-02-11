# Firmware Demo Test List

This is a starter test list for BinAgent from `monolithic-firmware-collection`, ordered from easier ELF-based targets to harder raw binaries.

## Tier 1: Quick Sanity (ELF, small/medium)
1. `monolithic-firmware-collection/ARMCortex-M/p2im_console/p2im_console.elf` (~1.10 MB)
2. `monolithic-firmware-collection/ARMCortex-M/p2im_gateway/p2im_gateway.elf` (~0.88 MB)
3. `monolithic-firmware-collection/ARMCortex-M/st-plc/st-plc.elf` (~1.04 MB)

## Tier 2: Network Service Style (ELF)
4. `monolithic-firmware-collection/ARMCortex-M/stm32_tcp_echo_server/stm32_tcp_echo_server.elf` (~2.04 MB)
5. `monolithic-firmware-collection/ARMCortex-M/stm32_udp_echo_server/stm32_udp_echo_server.elf` (~2.04 MB)

## Tier 3: CVE-Labeled Zephyr Samples (ELF)
6. `monolithic-firmware-collection/ARMCortex-M/D_FUZZWARE/new-targets/zephyr-os/prebuilt_samples/CVE-2021-3321/zephyr-CVE-2021-3321.elf` (~1.78 MB)
7. `monolithic-firmware-collection/ARMCortex-M/D_FUZZWARE/new-targets/zephyr-os/prebuilt_samples/CVE-2021-3322/zephyr-CVE-2021-3322.elf` (~1.78 MB)
8. `monolithic-firmware-collection/ARMCortex-M/D_FUZZWARE/new-targets/zephyr-os/prebuilt_samples/CVE-2021-3330/zephyr-CVE-2021-3330.elf` (~1.77 MB)

## Tier 4: Harder Raw Binary Targets
9. `monolithic-firmware-collection/ARMCortex-M/D_POLYPUS/BCM4345C0.bin` (~0.78 MB)
10. `monolithic-firmware-collection/ARMCortex-R/ShannonBaseband/modem.bin` (~40.89 MB)

## Suggested Run Commands
```bash
# single target
binagent analyze ./monolithic-firmware-collection/ARMCortex-M/p2im_console/p2im_console.elf

# example with explicit task
binagent analyze ./monolithic-firmware-collection/ARMCortex-M/st-plc/st-plc.elf \
  --task "Find memory corruption and unsafe copy patterns with evidence"
```

## Notes
- Prefer `.elf` first for better symbols/structure and easier debugging.
- Use Tier 4 only after you validate the workflow on Tier 1-3.
- Keep per-target run artifacts under `runs/<id>/` for later benchmark comparison.
