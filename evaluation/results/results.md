# Aegis Evaluation Report

_Generated 2026-09-04T09:11:53.309018+00:00 · seed 1337 · deterministic & reproducible_

Ran **108 attack** and **108 benign** scenarios against a synthetic 60-user enterprise after a **23,047-event** benign training baseline (**30,407** events total).

## Headline metrics

| Metric | Result |
|--------|-------:|
| Detection Rate (recall) | **100.0%** |
| False Positive Rate | **1.9%** |
| Precision | 98.2% |
| F1 score | 99.1% |
| Attack-chain reconstruction | 88.0% |
| MITRE technique recall | 84.3% |
| MITRE technique precision | 58.4% |
| IOC correlation accuracy | 80.0% |
| Evidence coverage | 74.5% |
| Mean detection latency | 1211.42 ms |
| p95 detection latency | 3745.19 ms |
| Throughput | 116 events/s |

Confusion matrix — TP 108, FP 2, TN 106, FN 0.

## Base-rate-honest false-positive load

A percentage FPR on a balanced set is cosmetic. What reaches an analyst is a false *incident*, and what matters is how many arrive against real event volume:

| Metric | Result |
|--------|-------:|
| Benign events processed | 26,343 |
| False incidents raised | 2 |
| **False incidents per million events** | **75.92** |
| Projected false incidents/day @ 50M events/day | 3796.0 |

> This is still on synthetic benign traffic. The projection assumes the synthetic base rate holds on real telemetry, which is exactly the assumption an external evaluation has to test.

## Per-scenario breakdown

| ID | Scenario | Runs | Det. rate | Chain recon. | Technique recall | Evidence cov. | Mean risk |
|----|----------|-----:|----------:|-------------:|-----------------:|--------------:|----------:|
| A | Brute-force authentication | 12 | 100.0% | 100.0% | 100.0% | 57.9% | 93.6 |
| B | Suspicious off-hours login | 12 | 100.0% | 50.0% | 66.7% | 100.0% | 67.4 |
| C | Malicious document execution | 12 | 100.0% | 100.0% | 100.0% | 75.0% | 100.0 |
| D | Privilege escalation & backdoor account | 12 | 100.0% | 100.0% | 100.0% | 80.0% | 100.0 |
| E | Hands-on-keyboard lateral movement | 12 | 100.0% | 66.7% | 75.0% | 30.6% | 100.0 |
| F | Ransomware detonation | 12 | 100.0% | 100.0% | 100.0% | 69.7% | 100.0 |
| G | DNS tunnelling / exfiltration channel | 12 | 100.0% | 100.0% | 100.0% | 98.8% | 100.0 |
| H | Data collection & exfiltration | 12 | 100.0% | 100.0% | 50.0% | 75.0% | 100.0 |
| I | Low-and-slow campaign | 12 | 100.0% | 75.0% | 66.7% | 83.3% | 100.0 |

_Detection is fully deterministic; the LLM is not involved in any number above._

## What this benchmark is — and is not

This is a **reproducibility / regression harness**: the same author wrote the attack scenarios, the benign look-alikes, and the detection rules. A high score here proves the pipeline behaves as designed and stays stable across changes. It is **not** an independent detection-efficacy result — it says nothing about attacks the author did not script. Credible detection numbers require external telemetry the author did not generate and a red team the author does not control; that is the `aegis_sim.external` evaluation and the design-partner phase, not this file.
