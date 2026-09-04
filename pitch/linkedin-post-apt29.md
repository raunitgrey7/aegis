Last week a few people here asked the fair question: what does your detection platform do on REAL attack telemetry, not your own simulator? So I ran it, audited it honestly, then spent two releases fixing what the audit exposed. Here is the whole arc, wins and misses.

The test: I pointed Aegis at the MITRE ATT&CK Evals APT29 emulation (published by OTRF and SpecterOps). Real Sysmon and Windows Security logs that I did not write. 196,000 events on day 1, 587,000 on day 2.

The uncomfortable baseline (v2):
> It could actually see only 12% of the events, and it caught 30% of the emulated ATT&CK techniques.
> It missed the single most important APT signal outright: LSASS memory access for credential theft.

Why? Real EDR does not look like a tidy simulator. It emits Sysmon 10 (process access), Sysmon 8 (remote thread injection), WFP 5156 (network), PowerShell script blocks, and directory-object access. My rules were written for a narrower set of event shapes, so most of the real telemetry was invisible. That connector and schema gap, not the detection logic, was the real bottleneck.

So I did two audit-driven releases:

v2.1 fixed schema coverage. I mapped the missing event types and added rules for LSASS memory access and malicious PowerShell script blocks. Coverage went from 12% to 73%. Recall went from 30% to 43%. Credential dumping went from MISSED to DETECTED.

v2.2 fixed detection content. After seeing what was still missed, I added process injection (Sysmon 8), LSA secret and DCSync access, Security-log clearing, scheduled tasks, file and process discovery, and stored-credential-file reads.

The result on the same real logs:
> Day 1 technique recall: 30% to 43% to 57%. Nearly doubled from the baseline.
> Day 2 (587k events): 53% of techniques, and it reconstructed a critical lateral-movement incident across 4 real domain hosts.
> The synthetic benchmark stayed at 100% detection and 0% false positives the whole time.

The part I will not dress up: 57% is not 95%. The remaining misses are exfiltration volume, obfuscation and deobfuscation, RDP, and screen capture. Some need netflow byte counts, some need script deobfuscation. That list is the v2.3 roadmap, written into the repo, not hidden.

On the connector question directly: Aegis normalizes everything to one schema and ingests over a REST endpoint, so any shipper (Winlogbeat, NXLog, Vector, Fluent Bit) feeds it. CrowdStrike, Defender, SentinelOne, Splunk, Sentinel and Elastic all work by forwarding today. Native connectors are roadmap.

Full before-and-after audit with the honest miss list: github.com/raunitgrey7/aegis, docs/APT29_AUDIT.md

Detection engineers: what would you prioritize next, more schema coverage or more detection content?

#CyberSecurity #DetectionEngineering #ThreatDetection #SOC #MITREATTACK #IncidentResponse #BlueTeam #DFIR #InfoSec #Sysmon #EDR #ThreatIntelligence #SecurityEngineering #APT29 #PurpleTeam #OpenSource #AI
