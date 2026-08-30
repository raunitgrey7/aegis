# Aegis Evaluation Report

_Generated 2026-08-30T14:38:53.881941+00:00 · seed 1337 · deterministic & reproducible_

Ran **100 attack** and **100 benign** scenarios against a synthetic 60-user enterprise after a **23,047-event** benign training baseline (**30,496** events total).

## Headline metrics

| Metric | Result |
|--------|-------:|
| Detection Rate (recall) | **100.0%** |
| False Positive Rate | **2.0%** |
| Precision | 98.0% |
| F1 score | 99.0% |
| Attack-chain reconstruction | 89.5% |
| MITRE technique recall | 86.7% |
| MITRE technique precision | 62.2% |
| IOC correlation accuracy | 82.9% |
| Evidence coverage | 73.4% |
| Mean detection latency | 766.84 ms |
| p95 detection latency | 2269.16 ms |
| Throughput | 199 events/s |

Confusion matrix — TP 100, FP 2, TN 98, FN 0.

## Per-scenario breakdown

| ID | Scenario | Runs | Det. rate | Chain recon. | Technique recall | Evidence cov. | Mean risk |
|----|----------|-----:|----------:|-------------:|-----------------:|--------------:|----------:|
| A | Brute-force authentication | 13 | 100.0% | 100.0% | 100.0% | 55.5% | 93.5 |
| B | Suspicious off-hours login | 13 | 100.0% | 50.0% | 66.7% | 100.0% | 66.6 |
| C | Malicious document execution | 13 | 100.0% | 100.0% | 100.0% | 75.0% | 100.0 |
| D | Privilege escalation & backdoor account | 13 | 100.0% | 100.0% | 100.0% | 80.0% | 100.0 |
| E | Hands-on-keyboard lateral movement | 12 | 100.0% | 66.7% | 75.0% | 29.9% | 100.0 |
| F | Ransomware detonation | 12 | 100.0% | 100.0% | 100.0% | 71.7% | 100.0 |
| G | DNS tunnelling / exfiltration channel | 12 | 100.0% | 100.0% | 100.0% | 98.9% | 100.0 |
| H | Data collection & exfiltration | 12 | 100.0% | 100.0% | 50.0% | 75.0% | 100.0 |

_Detection is fully deterministic; the LLM is not involved in any number above._
