# Aegis on Real APT Telemetry: Audit (v2 baseline vs v2.1)

_Dataset: MITRE ATT&CK Evals APT29 emulation, published by OTRF (SpecterOps). Real Sysmon + Windows Security telemetry that the author did NOT write. This is the honest counterpart to the synthetic benchmark._

> Run it yourself: `python -m aegis_sim.apt_audit --file <mordor_json>`  (datasets from github.com/OTRF/Security-Datasets)

## The headline: v2 -> v2.1 on APT29 Day 1

| Metric | v2 | v2.1 | Delta |
|--------|---:|-----:|:-----:|
| Events processed | 195,903 | 195,903 | same dataset |
| **Schema coverage** (events mapped to a detectable type) | 11.5% | **73.4%** | +61.9 |
| Detections raised | 123 | 158 | +35 |
| Incidents formed | 1 | 2 | +1 |
| **ATT&CK technique recall** | 30.0% (9/29) | **43.3%** (13/29) | +13.3 |

**Newly detected in v2.1:** T1003.001 (LSASS Memory), T1018 (Remote System Discovery), T1082 (System Info Discovery), T1087.002 (Domain Account Discovery)

### Why v2 was blind (the real gap Vo Khanh asked about)

v2 only mapped a narrow slice of real EDR telemetry. On this dataset the biggest dropped EventIDs were:

| EventID | Meaning | v2 handling |
|--------:|---------|-------------|
| 10 | Sysmon ProcessAccess (LSASS memory read = credential dumping) | dropped (39,286 events) |
| 12 | Sysmon registry key create/delete | dropped (61,152 events) |
| 5156 | Windows Filtering Platform network connection | dropped (3,163 events) |
| 800/4103/4104 | PowerShell pipeline / script-block content | dropped (5,113 events) |
| 4663 | Object access (NTDS.dit / SAM handle) | dropped (5,337 events) |

### What v2.1 changed

- **Normalizer** now maps Sysmon 10 (process access), 5156/5158 (WFP network), 800/4103/4104 (PowerShell script blocks, so the payload reaches the execution rules), Sysmon 12 (registry), and 4663 (object access). Schema coverage went from 11.5% to 73.4%.
- **New rule CRED-003**: LSASS memory access via Sysmon 10 -> T1003.001 (the single most important APT signal, invisible to v2). Fired 8x on real events.
- **New rule EXEC-007**: malicious PowerShell *script block* content (encoding, download cradle, AMSI bypass, reflective load). Fired 2x.
- **Broadened discovery (DISC-001)** to catch PowerShell recon cmdlets, still burst-gated to keep false positives near zero (synthetic benchmark stayed at 100% detection / 0% FPR).

### Where Aegis still lags on APT29 Day 1 (honest miss list -> v2.2 roadmap)

Still missed: T1003.003 (NTDS), T1005 (Data from Local System), T1021.001 (RDP), T1027 (Obfuscated Files), T1041 (Exfil over C2), T1048 (Exfil Alternative Protocol), T1053.005 (Scheduled Task), T1055 (Process Injection), T1057 (Process Discovery), T1059.003 (Windows Command Shell), T1070.001 (Clear Event Logs), T1074.001 (Local Data Staging), T1083 (File and Directory Discovery), T1113 (Screen Capture), T1136.001 (Create Account), T1140 (Deobfuscate), T1552.001 (Credentials In Files)

These need more than schema mapping:
- **T1055 (process injection)** needs Sysmon 8 (CreateRemoteThread) and access-pattern analysis.
- **Discovery via native APIs / Seatbelt** (T1082/T1083/T1057/T1087) bypasses command-line rules.
- **T1041/T1048 (exfiltration)** needs byte volume from netflow; WFP events do not carry it.
- **T1003.003 (NTDS) / T1552 (creds in files)** need DCSync DCERPC parsing and richer file-read context.
- **T1140 (deobfuscation) / T1027** need script-block de-obfuscation, not just pattern match.

## The messier run: APT29 Day 2 (v2.1)

- Events processed: **586,668** (larger, noisier real capture)
- Schema coverage: **87.9%**  |  detections: 157  |  incidents: 1
- ATT&CK technique recall: **36.7%** (11/29)
- Detected: T1003.001 (LSASS Memory), T1003.003 (NTDS), T1018 (Remote System Discovery), T1021.002 (SMB/Admin Shares), T1059.001 (PowerShell), T1071.001 (Web Protocols), T1082 (System Info Discovery), T1087.002 (Domain Account Discovery), T1105 (Ingress Tool Transfer), T1136.001 (Create Account), T1547.001 (Registry Run Key)
- Missed: T1005 (Data from Local System), T1021.001 (RDP), T1027 (Obfuscated Files), T1041 (Exfil over C2), T1048 (Exfil Alternative Protocol), T1053.005 (Scheduled Task), T1055 (Process Injection), T1057 (Process Discovery), T1059.003 (Windows Command Shell), T1070.001 (Clear Event Logs), T1074.001 (Local Data Staging), T1078 (Valid Accounts), T1083 (File and Directory Discovery), T1113 (Screen Capture), T1140 (Deobfuscate), T1204.002 (Malicious File), T1543.003 (Windows Service), T1552.001 (Credentials In Files), T1560.001 (Archive via Utility)

Top reconstructed incidents:
- `SEC-0001` [critical] risk 100.0 on NASHUA.dmevals.local, NEWYORK.dmevals.local - Lateral movement by - across 4 host(s)

## Honest takeaways

1. **The connector/schema layer was the real bottleneck, not the detection logic.** v2 looked strong on synthetic data because the synthetic data used the exact event shapes the rules expected. Real EDR emits a much wider set, and 88% of it was invisible until v2.1.
2. **Coverage != recall.** v2.1 lifted schema coverage ~6x and recovered the crown-jewel technique (LSASS dumping), but full APT recall needs deeper detection content (injection, native-API discovery, exfil volume). That is real work, not a wording fix.
3. **This is the only benchmark that counts.** Nobody tuned these logs to Aegis. The miss list is the roadmap.

---

Copyright (c) 2026 Raunit Thakur. All rights reserved.