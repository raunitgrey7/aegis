# Aegis Competitive Analysis

**Audience:** founders, investors, senior security engineers
**Scope:** Aegis (open-source, self-hosted AI security investigation and threat-intelligence platform) versus the commercial SIEM/XDR/UEBA market, the AI-SOC startup cohort, and open-source baselines.
**Method note:** competitor descriptions rely on publicly documented, widely known capabilities. Where a specific figure is not publicly established, this document describes the capability qualitatively rather than inventing a number. No market-share, pricing, or vendor benchmark figures are asserted.

---

## 1. Executive summary

Aegis is not a Splunk or Sentinel replacement and should not be pitched as one. It is a small, self-hosted detection-and-investigation engine whose distinguishing design decision is that a deterministic core (YAML rules, statistical baselines, threat-intel matching, graph correlation) decides what is malicious, and a local LLM is confined to *explaining* those decisions, with its narrative fact-checked against the detection record before it is shown to an analyst. Every large vendor now markets "grounded" or "evidence-backed" AI summaries; Aegis's differentiation is not grounding per se but the combination of verification depth (entity- and technique-level claim checking, not citation presence), zero data egress and zero API cost, an attack graph as the primary artifact rather than an alert list, and a rule DSL, benchmark, and evaluation methodology that are fully open. Against the giants, Aegis loses on almost every operational axis that matters to a Fortune-500 SOC: ingestion scale, connector breadth, detection-content velocity, SOAR, certifications, global telemetry, and support. Its original 100/100 synthetic benchmark is a regression harness written by the rule author and must not be presented as an efficacy result; v2's external-dataset validation and per-million-event false-incident metrics exist precisely to replace that number with something defensible. The realistic near-term wedge is analyst-hour reduction for MSSP/MDR teams, mid-market organisations that cannot or will not send telemetry to a vendor cloud, air-gapped and regulated environments, and OEM licensing of the verification layer to vendors who already have ingestion and content. Winning any of those requires closing specific engineering gaps (streaming ingestion, collectors, playbooks, multi-tenancy) that are enumerated in Section 7.

---

## 2. Market map

| Group | Who decides malice | Deployment | Data residency | Pricing model (qualitative) | AI role | Evidence / explainability | Prompt-injection posture | Aegis stronger | Aegis weaker |
|---|---|---|---|---|---|---|---|---|---|
| **Cloud-scale SIEM / data platforms** (Splunk ES, Microsoft Sentinel + Security Copilot, Google SecOps/Chronicle + Gemini, Elastic Security, Cortex XSIAM, QRadar) | Vendor and community rules, vendor ML/analytics; analyst confirms | Cloud-first; Splunk, Elastic, QRadar also on-prem; XSIAM cloud | Vendor cloud regions; on-prem options for some | Per-GB/TB ingest or workload-based; per-user/per-SCU add-ons for AI assistants | Assistant: query generation, alert summarisation, guided investigation; increasingly agentic triage | Rule matched plus assistant summary; Microsoft and Google publicly emphasise evidence-linked summaries | Rarely a documented, first-class control; assistants operate over trusted-tenant data | Verification depth, self-hosting, zero AI cost, open rule DSL, attack-graph artifact | Scale, connectors, content library, SOAR, compliance, UEBA maturity, support |
| **EDR/XDR with AI analysts** (CrowdStrike Falcon + Charlotte AI, SentinelOne + Purple AI, Microsoft Defender XDR) | Vendor kernel-level sensor plus cloud ML; vendor decides for endpoint | Cloud console, vendor agent on endpoints | Vendor cloud | Per-endpoint / per-module subscription | Natural-language investigation, summarisation, guided response; CrowdStrike publicly stresses Charlotte AI is bounded by Falcon data | Strong on endpoint: process trees, detection rationale; vendor-defined | Not a published control for hostile telemetry against the assistant | Cross-source graph (endpoint + network + DNS + cloud) under one schema; no vendor lock-in; local reasoning | Sensor quality, prevention/response on the endpoint, global threat telemetry, response automation |
| **UEBA / next-gen SIEM** (Exabeam, Securonix, Hunters, Anvilogic, Panther) | Vendor behavioural models plus rules; Panther/Anvilogic detection-as-code | Cloud/SaaS; Panther and Anvilogic sit on the customer's data lake (Snowflake, Databricks, etc.) | Vendor SaaS or customer warehouse | Ingest-, identity-, or seat-based subscriptions | Increasingly LLM-assisted triage and rule authoring | Behavioural timelines, risk scores; models mostly opaque | Not prominent in public docs | Transparent baselines and rule DSL; explainable risk scoring; self-hosted | Depth and maturity of behavioural models, identity analytics, detection-as-code CI/CD tooling, enterprise integrations |
| **AI-SOC / autonomous investigation** (Dropzone AI, Prophet Security, Exaforce, Torq HyperSOC, Simbian, Command Zero, Intezer) | Upstream SIEM/EDR raises the alert; LLM agents triage, enrich, and recommend a verdict per alert | Cloud/SaaS, integrated on top of existing stacks | Vendor cloud (alert context and pulled evidence leave the customer) | Per-alert, per-analyst-seat, or platform subscription | Central: LLM-driven per-alert investigation, enrichment, and reporting | Investigation write-ups with citations to pulled evidence; quality of verification varies and is mostly not externally auditable | Little public detail; risk is real because agents read attacker-controlled fields | AI does not decide malice; claims are checked against a deterministic record; runs local; open; graph correlation across alerts rather than per-alert | Integration breadth with existing SIEM/EDR/ticketing, polish, enterprise sales, per-alert automation depth |
| **Open-source baselines** (Wazuh, Security Onion, Elastic self-hosted, Sigma ecosystem, TheHive/Cortex) | Community rules (Sigma, Wazuh rulesets, Suricata/Zeek signatures); analyst | Self-hosted | Full customer control | Open-source with optional vendor cloud/enterprise tiers | Little to none natively (Elastic AI Assistant in the paid tiers) | Rule-level; no narrative layer | Not applicable (no LLM) | Verified LLM narrative, attack graph, risk ledger, baselines, benchmark discipline layered on the same self-hosted premise | Community size, collectors/agents, hardened deployments, Sigma content volume, case management maturity |

---

## 3. Where the giants are genuinely better

This section is deliberately unflattering. Any pitch that omits it will be discounted by a competent buyer.

- **Ingestion scale.** Splunk, Sentinel, Chronicle, Elastic, and XSIAM are engineered for terabytes to petabytes per day with distributed indexing, tiered storage, and query engines tuned over a decade. Aegis ingests through a Python pipeline into a single normalised store with a NetworkX graph in process. It has not been tested at anything approaching enterprise volume, and NetworkX in particular is an in-memory library, not a graph database.
- **Connector breadth.** The major platforms ship hundreds of maintained integrations (cloud providers, identity, SaaS, network, endpoint, ticketing). Aegis has a handful of parsers for the telemetry families listed in its documentation. Every missing connector is a deployment blocker for someone.
- **Detection content.** Vendors employ dedicated research teams who publish and maintain thousands of rules and analytics, update them against new tradecraft within days, and tune them against telemetry from thousands of tenants. Aegis has 58 rules and ATT&CK coverage of 69/80 techniques *within its own evaluated scope*, written by one author. Coverage breadth and freshness are not comparable.
- **SOAR and response.** Cortex XSOAR, Splunk SOAR, Sentinel playbooks, Torq, and the EDR vendors' native response (isolate host, kill process, revoke token) are mature. Aegis produces investigations; it does not act.
- **Compliance and assurance.** SOC 2, ISO 27001, FedRAMP, and similar attestations are table stakes for regulated buyers of hosted products. Aegis, being self-hosted, sidesteps some of this, but it has no third-party audit of its own code, and a buyer inherits the burden of operating it securely.
- **Threat intelligence.** CrowdStrike, Microsoft, Google, and Palo Alto derive intelligence from very large sensor networks and human intelligence teams. Aegis matches against public feeds (abuse.ch, Spamhaus). Public feeds are useful and free; they are also what every attacker checks against.
- **UEBA maturity.** Exabeam and Securonix have spent years on identity-centric behavioural models, peer grouping, and session stitching. Aegis's baselines (login-hour, first-seen geo, robust z-score egress, process rarity, DNS entropy) are sound but narrow.
- **Multi-tenancy and MSSP tooling.** The commercial platforms offer tenant isolation, cross-tenant content management, and consolidated billing. Aegis is single-tenant.
- **Support, SLAs, and ecosystem.** Certified engineers, 24x7 support, training programmes, partner networks, and hiring pools. An open-source project maintained by one person has none of these.

Aegis has none of the above at scale. That is a statement of fact about a small project, not a criticism of its design; it defines which buyers are out of reach.

---

## 4. Where Aegis's design choices are differentiated

Grounding is no longer a differentiator on its own. Microsoft (Security Copilot), Google (Gemini in SecOps), and CrowdStrike (Charlotte AI) all publicly emphasise that their assistants answer from tenant data and cite evidence. The AI-SOC startups build their product around cited investigations. The credible claim is narrower and is a combination of four properties that, taken together, none of the groups above currently offers:

1. **Deterministic core, verified AI.** The LLM never produces a verdict. Rules, baselines, threat-intel matches, and graph correlation produce the incident; the model writes a narrative; the v2 Claim Verifier then checks every entity, technique, and causal claim in that narrative against the detection record and flags or removes anything unsupported. Most competitors check that citations exist. Aegis checks that the cited thing actually supports the claim. This is a stronger guarantee and it is auditable because the record is a plain data structure, not a vendor index.
2. **Self-hosted, zero egress, zero API cost.** Telemetry, graph, and model inference stay on the operator's hardware (Ollama). No per-token bill, no vendor tenant, no cloud region to negotiate. This matters concretely to defence, healthcare, critical infrastructure, sovereign-cloud mandates, and air-gapped networks, where the cloud-native AI-SOC startups and Copilot-class assistants are simply not deployable.
3. **Attack graph as the primary artifact.** Aegis reconstructs a layered attack graph over a persistent knowledge graph and presents the campaign, not a list of alerts. SIEMs present alerts and, in the better cases, incident groupings; the graph is a secondary view. Making the graph primary shapes the whole investigation experience and is the substrate for the low-and-slow correlation in v2.
4. **Openness as a verification property.** The rule DSL, the risk scoring, the benchmark harness, the evaluation methodology, and the audit log format are readable and reproducible. A buyer can inspect why something fired. With vendor ML this is generally impossible, and with AI-SOC products the investigation logic is proprietary.

Secondary properties worth stating but not overselling: JWT/RBAC, hash-chained audit log, and an explicit prompt-injection defence for hostile telemetry (attacker-controlled strings in process arguments, DNS labels, user-agent fields, and similar are treated as untrusted before reaching the model). The last one is more unusual than it should be; few vendors document how their assistant is protected from adversarial content in the very logs it summarises.

---

## 5. The critique-driven gaps v2 closes

Four critiques of v1 are valid and each maps to a v2 feature. The right-hand column is what remains open even after v2.

| Critique of v1 | Why it is valid | v2 response | What remains open |
|---|---|---|---|
| **No base-rate-honest false-positive metric.** Precision on a synthetic set says nothing about how many false incidents an analyst would see on real volume. | Real SOC volume is millions of events per day; a small per-event false-positive rate is a large per-day analyst burden. | Report false incidents per million events and per analyst-day, computed on external telemetry, alongside precision/recall. | Numbers will be dataset-specific; a true operational rate requires a production deployment with an honest ground-truth process. |
| **Benchmark authored by the rule author.** The 100/100 result on the synthetic scenarios is a reproducibility and regression harness, not an independent efficacy measurement. The same person wrote the attacks and the rules that catch them. | Author-written benchmarks measure self-consistency, not detection power. | Validate against OTRF Security-Datasets / Mordor, public attack telemetry the author did not generate, with results published including misses. | These datasets are also public and known to the community; rules could still be tuned to them. Independent red-team evaluation on unseen telemetry is the only fully credible next step. |
| **Grounding is not truth.** Checking that a narrative cites evidence does not check that the evidence supports the claim. An LLM can cite a real event and misdescribe it. | Citation presence is a weak filter; hallucinated causality and mislabelled techniques pass through it. | Claim Verifier: every entity, technique, and relationship the narrative names is checked against the deterministic detection record; unsupported claims are flagged or stripped. | Verification is bounded by what the deterministic layer recorded. A claim about something the rules never observed is unverifiable, not false. Narrative omissions are not caught. |
| **Fixed-window correlation misses low-and-slow attacks.** Sequence rules and time-boxed correlation cannot see a campaign spread over weeks using living-off-the-land binaries. | This is exactly how patient adversaries operate. | Risk Ledger: per-entity risk accumulation with time-decay, plus graph-path correlation so weak signals on related entities compound across the knowledge graph rather than expiring. | Decay parameters and path weights are tunable and therefore gameable; evaluation on real long-duration intrusions is needed, and public datasets rarely contain them. |

The honest summary is that v2 converts four unverifiable claims into four measurable ones. It does not yet produce a number that an outsider should trust without running the harness themselves, which is the point of shipping the harness.

---

## 6. Realistic go-to-market wedge

**Who Aegis can plausibly win against today**

- **MSSP / MDR analyst-hour reduction.** Service providers are paid per tenant and pay per analyst-hour. A tool that turns a cluster of alerts into a verified narrative and a graph, and can be run on the provider's own infrastructure without a per-token bill, has a direct cost argument. The missing piece is multi-tenancy (Section 7).
- **Mid-market self-hosted SOC.** Organisations already running Wazuh, Security Onion, or self-hosted Elastic, who want an investigation layer without sending data to a vendor cloud. Aegis competes here against "nothing" or against an engineer's scripts, not against Splunk.
- **Regulated and air-gapped environments.** Defence, government, industrial control, and sovereign-cloud contexts where cloud AI assistants are contractually or physically excluded. Local-LLM investigation with an audit trail is a real capability gap in that market, and the competitors in Group 4 cannot follow.
- **OEM of the verification layer.** Vendors who already have ingestion, content, and customers but whose AI assistant is a thin wrapper could license the Claim Verifier and evidence-linking model. This is the most capital-efficient path and the one most sensitive to how well the verifier is documented and tested.

**Who Aegis cannot win against today**

- Any Fortune-500 or large-government buyer replacing Splunk, Sentinel, or Chronicle. The evaluation criteria (scale, connectors, certifications, support, content velocity) are all in Section 3.
- Any buyer whose primary need is endpoint prevention and response; that is the EDR vendors' domain and requires a sensor Aegis does not have.
- Any buyer who wants a managed service with a contractual SLA.

---

## 7. What it would take to compete at scale

Ordered roughly by dependency, not by ease.

1. **Streaming ingestion.** Replace the batch/Python pipeline with a Kafka (or equivalent) backbone, stateless parsers, and a graph store that is not in-process (Neo4j, Memgraph, or a property-graph layer over Postgres). Without this, nothing else scales.
2. **Collectors and agents.** A supported way to ship Sysmon, auditd, Zeek, and cloud logs to Aegis without hand-built forwarding: OpenTelemetry-style collectors, Fluent Bit / Vector configs, and eventually a lightweight agent.
3. **Connector ecosystem.** A documented parser/normaliser interface with a contribution path, and a target of the top few dozen sources by SOC prevalence (identity providers, cloud audit logs, major firewalls, EDR exports).
4. **SOAR playbooks.** Even a minimal YAML playbook runner (enrich, notify, open ticket, isolate via EDR API) changes Aegis from "investigation" to "operations" in a buyer's mind.
5. **Multi-tenancy.** Tenant isolation in schema, graph, RBAC, and model context. Required for the MSSP wedge.
6. **Certifications and hardening.** Third-party code audit, SBOM, signed releases, a published security response process; SOC 2 if a hosted offering ever exists.
7. **Detection-content programme.** Sigma import, a rule contribution and review process, versioned rule packs, and a public changelog tied to ATT&CK updates.
8. **Real-telemetry evaluation with red team.** A standing evaluation programme on unseen telemetry, adversary emulation exercises not designed by the rule author, and publication of misses as well as hits. This is the only thing that will ever make the detection numbers credible to a sceptical buyer.

None of these is a research problem; all are engineering and organisational effort that a single maintainer cannot absorb. That is the honest investment thesis: the differentiating ideas exist and are implemented; the platform around them does not.

---

Copyright © 2026 Raunit Thakur. All rights reserved.
