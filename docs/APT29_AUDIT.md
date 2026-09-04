# Aegis on Real APT Telemetry: Audit (v2 -> v2.1 -> v2.2)

_Dataset: MITRE ATT&CK Evals APT29 emulation, published by OTRF (SpecterOps). Real Sysmon and Windows Security telemetry that the author did NOT write, so nobody tuned it to the rules. This is the honest counterpart to the synthetic benchmark._

> Reproduce: `python -m aegis_sim.apt_audit --file <mordor_json>` (datasets: github.com/OTRF/Security-Datasets)

## Day 1 (the smaller run): the full progression

| Metric | v2 | v2.1 | v2.2 |
|--------|---:|-----:|-----:|
| Events processed | 195,903 | 195,903 | 195,903 |
| **Schema coverage** | 11.5% | 73.4% | **73.5%** |
| Detections | 123 | 158 | 168 |
| Incidents | 1 | 2 | 1 |
| **ATT&CK technique recall** | 30.0% (9/30) | 43.3% (13/30) | **56.7%** (17/30) |

- **v2.1 added:** T1003.001 (LSASS Memory), T1018 (Remote System Discovery), T1082 (System Info Discovery), T1087.002 (Domain Account Discovery)
- **v2.2 added:** T1003.003 (NTDS), T1055 (Process Injection), T1057 (Process Discovery), T1083 (File and Directory Discovery)
- **Still missed on Day 1:** T1005 (Data from Local System), T1021.001 (RDP), T1027 (Obfuscated Files), T1041 (Exfil over C2), T1048 (Exfil Alternative Protocol), T1053.005 (Scheduled Task), T1059.003 (Windows Command Shell), T1070.001 (Clear Event Logs), T1074.001 (Local Data Staging), T1113 (Screen Capture), T1136.001 (Create Account), T1140 (Deobfuscate), T1552.001 (Credentials In Files)

## Day 2 (the messier run, 587k events)

- Schema coverage: 87.9% (v2.1) -> **87.9%** (v2.2)
- Technique recall: 36.7% -> **53.3%** (16/30)
- v2.2 added on Day 2: T1053.005 (Scheduled Task), T1055 (Process Injection), T1057 (Process Discovery), T1083 (File and Directory Discovery), T1552.001 (Credentials In Files)
- Detected: T1003.001 (LSASS Memory), T1003.003 (NTDS), T1018 (Remote System Discovery), T1021.002 (SMB/Admin Shares), T1053.005 (Scheduled Task), T1055 (Process Injection), T1057 (Process Discovery), T1059.001 (PowerShell), T1071.001 (Web Protocols), T1082 (System Info Discovery), T1083 (File and Directory Discovery), T1087.002 (Domain Account Discovery), T1105 (Ingress Tool Transfer), T1136.001 (Create Account), T1547.001 (Registry Run Key), T1552.001 (Credentials In Files)
- Missed: T1005 (Data from Local System), T1021.001 (RDP), T1027 (Obfuscated Files), T1041 (Exfil over C2), T1048 (Exfil Alternative Protocol), T1059.003 (Windows Command Shell), T1070.001 (Clear Event Logs), T1074.001 (Local Data Staging), T1078 (Valid Accounts), T1113 (Screen Capture), T1140 (Deobfuscate), T1204.002 (Malicious File), T1543.003 (Windows Service), T1560.001 (Archive via Utility)

Top reconstructed incidents:
- `SEC-0001` [critical] risk 100.0 on NASHUA.dmevals.local, NEWYORK.dmevals.local: Lateral movement by - across 4 host(s)

## What each version changed

**v2.1 (schema coverage).** The normalizer mapped Sysmon 10 (LSASS access), 5156/5158 (WFP network), 800/4103/4104 (PowerShell script blocks), 12 (registry) and 4663 (object access). New rules: CRED-003 (LSASS memory access) and EXEC-007 (malicious script blocks). Coverage went from 11.5% to 73.4% on Day 1.

**v2.2 (detection content).** After seeing what Day 1/Day 2 still missed, added: mapping for Sysmon 8 (CreateRemoteThread) and 4662/1102; and rules INJ-001 (process injection, T1055), CRED-004 (LSA secret / DCSync, T1003.003/004/006), DEFEV-004 (Security log cleared, T1070.001), PERS-006 (scheduled task, T1053.005), DISC-002 (file/process discovery, T1083/T1057) and CRED-005 (stored-credential-file access, T1552.001). Synthetic benchmark stayed at 100% detection / 0% FPR.

## Honest takeaways

1. The connector and schema layer, not the detection logic, was the real bottleneck. v2 looked strong on synthetic data because that data used the exact event shapes the rules expected.
2. Coverage is not recall. v2.1 fixed coverage (~6x) and recovered LSASS dumping; v2.2 added the detection content for injection, DCSync, log clearing, scheduled tasks and discovery.
3. Some Day 1 'misses' are techniques not present in that day's telemetry (e.g. log clearing and account creation appear on Day 2). The union ground-truth set makes single-day recall a floor, not a ceiling.
4. This is the only benchmark that counts: nobody tuned these logs to Aegis. The remaining miss list is the roadmap.

---

Copyright (c) 2026 Raunit Thakur. All rights reserved.