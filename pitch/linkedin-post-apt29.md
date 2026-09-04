A few people here pushed back on my last post with the same fair question: what does it do on REAL telemetry, not your own simulator?

So I ran it. Here is the honest result, wins and misses.

I pointed Aegis at the MITRE ATT&CK Evals APT29 emulation (published by OTRF / SpecterOps). Real Sysmon and Windows Security telemetry that I did not write: 196,000 events on day 1, 587,000 on day 2.

The uncomfortable baseline (v2):
> It mapped only 11.5% of the events and caught 30% of the emulated ATT&CK techniques.
> It missed the single most important APT signal entirely: LSASS memory access for credential theft.

Why? Real EDR does not look like a tidy simulator. It emits Sysmon 10 (process access), WFP 5156 (network), PowerShell script-block logs (4104), registry 12, object access 4663. My rules were written for a narrower set of event shapes, so 88% of real telemetry was invisible. That is the connector and schema gap, and it was the real bottleneck, not the detection logic.

What I changed in v2.1:
> Mapped those event types. Schema coverage went 11.5% to 73.4% on day 1, and 87.9% on the 587k-event day 2.
> Added a rule for LSASS memory access (Sysmon 10). It fired on real events. Credential dumping went from MISSED to DETECTED.
> Added a PowerShell script-block rule and broadened discovery, while keeping the synthetic benchmark at 100% detection and 0% false positives.
> ATT&CK technique recall went 30% to 43% on day 1. Day 2 additionally caught NTDS dumping and account creation.

The part I will not dress up:
43% recall is not 90%. Coverage is not recall. Catching a real APT fully needs deeper detection content: process injection (Sysmon 8), discovery through native APIs, exfiltration volume from netflow. That miss list is the v2.2 roadmap, and it is in the repo, not hidden.

On the connector question directly: Aegis normalizes everything to one schema and ingests over a REST endpoint, so anything that ships logs (Winlogbeat, NXLog, Vector, Fluent Bit, Filebeat) feeds it. CrowdStrike FDR, Defender, SentinelOne, Splunk, Sentinel and Elastic all work by forwarding today. Native one-click connectors are roadmap, not shipped.

Full audit (before and after, with the honest miss list): github.com/raunitgrey7/aegis -> docs/APT29_AUDIT.md

If you do detection engineering: what would you have prioritized first, the schema coverage or the detection content?

#CyberSecurity #DetectionEngineering #ThreatDetection #SOC #MITREATTACK #IncidentResponse #BlueTeam #DFIR #InfoSec #Sysmon #EDR #ThreatIntelligence #SecurityEngineering #APT29 #PurpleTeam #OpenSource #AI
