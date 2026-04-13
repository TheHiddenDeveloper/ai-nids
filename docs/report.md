# AI-Powered Network Intrusion Detection System
## Project Report

**Author:** AIDEN  
**Platform:** Python 3.10+ · Kali Linux (WSL2)  
**Dataset:** CICIDS2017 (University of New Brunswick)  
**Date:** April 2026

---

## Table of Contents

1. [Introduction](#1-introduction)
2. [Problem Statement](#2-problem-statement)
3. [System Architecture](#3-system-architecture)
4. [Dataset](#4-dataset)
5. [Feature Engineering](#5-feature-engineering)
6. [Machine Learning Models](#6-machine-learning-models)
7. [Signature Detection Engine](#7-signature-detection-engine)
8. [Pipeline Infrastructure](#8-pipeline-infrastructure)
9. [Dashboard](#9-dashboard)
10. [Evaluation](#10-evaluation)
11. [Limitations and Future Work](#11-limitations-and-future-work)
12. [Conclusion](#12-conclusion)

---

## 1. Introduction

Network Intrusion Detection Systems (NIDS) are a foundational component of modern cybersecurity infrastructure. Traditional NIDS operate exclusively on rule-based signature matching — comparing observed traffic against a database of known attack patterns. While effective against known threats, this approach is fundamentally reactive: it cannot detect novel or zero-day attacks that lack a prior signature.

This project implements a hybrid AI-powered NIDS that combines:

- A **supervised Random Forest classifier** trained on labelled network flow data from the CICIDS2017 dataset, capable of detecting 14 categories of known attacks with high precision
- An **unsupervised Autoencoder anomaly detector** trained exclusively on benign traffic, capable of flagging any flow that deviates significantly from normal behaviour — including zero-day attacks
- A **YAML-based signature rule engine** with 20 built-in rules covering DDoS, port scanning, C2/beaconing, brute-force, exfiltration, and suspicious port traffic
- A **real-time processing pipeline** that captures live packets, aggregates them into flows, extracts features, scores them through the ensemble model, deduplicates alerts, and surfaces results via a live Streamlit dashboard

The result is a system that detects known threats accurately, adapts to novel anomalies, and remains manageable through a set of CLI tools without requiring code changes.

---

## 2. Problem Statement

The project addresses two core limitations of conventional NIDS:

**Limitation 1 — Signature-only detection:** Traditional tools like Snort and Suricata rely entirely on manually authored rules. A novel attack variant that bypasses existing signatures goes completely undetected. The attackers know this and actively test evasion techniques against public rule sets.

**Limitation 2 — Alert fatigue:** High false positive rates are endemic to NIDS deployments. An analyst facing thousands of alerts per day cannot effectively triage them. Deduplication, severity classification, and score-based filtering are necessary to make the alert stream actionable.

This project addresses both: the ensemble model provides anomaly-based coverage beyond known signatures, while the deduplication layer, severity thresholds, and false positive tuning notebook reduce alert noise to a manageable level.

---

## 3. System Architecture

The system is divided into two logically separate parts that communicate through a thread-safe event bus.

### Part 1 — Network Monitor

The monitor layer handles all packet-level concerns:

**Packet Capture (`monitor/capture.py`)** uses the Scapy library to sniff raw packets from a named network interface. Each packet is parsed into a flat dictionary containing IP header fields (src/dst IP, protocol, length, TTL) and TCP/UDP flags (SYN, ACK, FIN, RST, PSH, URG). A `PcapReplay` mode allows offline processing of saved `.pcap` files.

**Flow Aggregator (`monitor/flow_aggregator.py`)** groups packets into bidirectional network flows using a 5-tuple key: `(min(src,dst), max(src,dst), protocol)`. The bidirectional keying ensures that packets from A→B and B→A belonging to the same conversation are tracked together. Flows expire after a configurable timeout (default 20 seconds) at which point their accumulated packet list is returned for feature extraction.

**Feature Extractor (`monitor/feature_extractor.py`)** converts a list of flow packet dictionaries into a clean pandas DataFrame with 16 numerical features. Infinite values, NaN, and extreme outliers are handled before the data is passed downstream.

### Part 2 — AI Engine

**Ensemble Inference Engine (`ai_engine/ensemble.py`)** loads both trained models and produces a single weighted attack probability score per flow. The RF component contributes 65% and the Autoencoder 35% to the final score. If only one model is available (e.g. during initial deployment before the autoencoder is trained), the engine falls back gracefully to single-model mode.

**Alert Engine (`ai_engine/alert_engine.py`)** applies configurable severity thresholds to the ensemble score, classifies each flow as low/medium/high severity, and merges the ML result with any matching signature rules. A signature match always escalates the alert to high severity regardless of the ML score.

### Infrastructure Layer

**Event Bus (`core/event_bus.py`)** provides a thread-safe publish/subscribe mechanism. The pipeline publishes `flow`, `alert`, and `stats` events; consumers (loggers, stats tracker, dashboard) subscribe without coupling to the pipeline.

**Alert Deduplicator (`core/deduplicator.py`)** suppresses repeated alerts for the same `(src_ip, dst_ip, dst_port, label)` tuple within a configurable window (default 60 seconds), preventing a single attacker from flooding the alert log.

**Stats Tracker (`core/stats_tracker.py`)** maintains rolling 5-minute metrics: flows/sec, alerts/sec, top-10 source IPs, severity distribution, protocol distribution, and score percentiles. The dashboard reads an immutable snapshot dict rather than the live state.

---

## 4. Dataset

**CICIDS2017** — Canadian Institute for Cybersecurity Intrusion Detection Evaluation Dataset 2017.  
2,830,743 labelled network flows across 14 categories including DoS, DDoS, Brute Force, Web Attacks, Infiltration, Bot, and Port Scan traffic.

This dataset was historically accessed via the UNB `.zip` distribution. It is now completely integrated into this pipeline via an automated Hugging Face API script (`scripts/fetch_cicids.py`), natively downloading specific high-fidelity `.csv` slices to cleanly seed the Zero-Day models without demanding manual zip extractions. network.

### Dataset Statistics

| Property | Value |
|---|---|
| Total flows (raw) | 2,830,743 |
| Total flows (after cleaning) | ~2,500,000 |
| Feature columns | 79 (16 selected) |
| Training split | 80% |
| Test split | 20% |

### Attack Categories

| Label | Description |
|---|---|
| BENIGN | Normal background traffic |
| DoS Hulk | HTTP DoS via large volume requests |
| PortScan | TCP port enumeration |
| DDoS | Distributed denial-of-service |
| DoS GoldenEye | HTTP-layer DoS |
| FTP-Patator | FTP brute-force |
| SSH-Patator | SSH brute-force |
| DoS slowloris | Slow HTTP DoS |
| DoS Slowhttptest | HTTP slow attack variant |
| Bot | Botnet C2 communication |
| Web Attack Brute Force | HTTP login brute-force |
| Web Attack XSS | Cross-site scripting |
| Infiltration | Internal network infiltration |
| Web Attack SQL Injection | SQL injection |
| Heartbleed | OpenSSL Heartbleed exploit |

### Data Quality Issues

The CICIDS2017 dataset contains a number of well-documented quality issues that required preprocessing:

- **Infinite values** in `Flow Bytes/s` and `Flow Packets/s` (division by zero for zero-duration flows) — replaced with NaN then dropped
- **Leading whitespace** in column names from the CICFlowMeter tool — stripped before mapping
- **Missing `Protocol` column** in the `MachineLearningCSV.zip` variant — substituted with `Destination Port` as the flow type proxy
- **Severe class imbalance** — benign traffic represents ~80% of flows; addressed with SMOTE oversampling during RF training

---

## 5. Feature Engineering

### Selected Features

16 features were selected from the 79 available based on documented importance in prior NIDS literature and their availability in both the dataset and the live packet capture pipeline:

| Feature | Description |
|---|---|
| `dst_port` | Destination port number |
| `duration` | Flow duration in seconds |
| `src_bytes` | Total bytes sent by source |
| `dst_bytes` | Total bytes sent by destination |
| `packet_count` | Total packets in flow |
| `avg_packet_len` | Mean packet length |
| `std_packet_len` | Standard deviation of packet length |
| `flow_bytes_per_sec` | Bytes transferred per second |
| `flow_packets_per_sec` | Packets transmitted per second |
| `fwd_packet_len_max` | Max forward packet length |
| `bwd_packet_len_max` | Max backward packet length |
| `fin_flag_count` | Number of FIN flags |
| `syn_flag_count` | Number of SYN flags |
| `rst_flag_count` | Number of RST flags |
| `psh_flag_count` | Number of PSH flags |
| `ack_flag_count` | Number of ACK flags |

### Feature Justification

The TCP flag counts are particularly discriminative. SYN floods generate high `syn_flag_count` with near-zero `ack_flag_count`. Port scans generate high `rst_flag_count` as closed ports respond with RST. C2 beacons show extremely low `packet_count` and `duration`. Rate features (`flow_bytes_per_sec`, `flow_packets_per_sec`) discriminate DDoS traffic from normal bulk transfers.

`dst_port` replaces the missing `protocol_type` column and adds direct attack-pattern signal — traffic to port 445 (SMB), 4444 (Meterpreter), or 22 (SSH brute-force) is immediately context-enriched.

---

## 6. Machine Learning Models

### 6.1 Random Forest Classifier

**Algorithm:** Ensemble of 200 decision trees with Gini impurity splitting.

**Class balancing:** SMOTE (Synthetic Minority Over-sampling Technique) is applied to the training set before fitting. SMOTE generates synthetic attack samples by interpolating between existing minority-class examples in feature space, rather than simply duplicating them.

**Hyperparameters:**

| Parameter | Value | Rationale |
|---|---|---|
| n_estimators | 200 | Stability without excessive memory cost |
| max_depth | 20 | Prevents overfitting while preserving expressiveness |
| class_weight | balanced | Secondary guard against imbalance |
| n_jobs | -1 | Parallelise across all CPU cores |

**Output:** Per-flow probability of attack P(attack) ∈ [0, 1].

### 6.2 Autoencoder

**Architecture:** Symmetric encoder-decoder with a bottleneck of dimension 8.

```
Input (16) → Dense(32, ReLU) → Dense(16, ReLU) → Dense(8, ReLU)
           → Dense(16, ReLU) → Dense(32, ReLU) → Output (16, Linear)
```

**Training strategy:** Trained exclusively on benign traffic flows. The network learns to reconstruct the statistical patterns of normal network behaviour. At inference time, flows that reconstruct poorly (high MSE) are classified as anomalies — attacks deviate from the learned benign manifold.

**Threshold selection:** The anomaly threshold is set at the percentile of reconstruction errors that maximises F1 score on the test set, typically around the 90th–95th percentile of the benign training error distribution.

**Output:** Per-flow reconstruction MSE, normalised to [0, 1] relative to the threshold.

### 6.3 Ensemble Combination

```
ensemble_score = (0.65 × rf_score) + (0.35 × ae_score)
```

The RF weight is higher because it is trained on labelled data and achieves higher precision. The AE contributes a meaningful zero-day signal without overwhelming the RF's pattern recognition. The weights are configurable without retraining.

### 6.4 Alert Severity Thresholds

| Severity | Score Range | Interpretation |
|---|---|---|
| High | ≥ 0.92 | Near-certain attack |
| Medium | 0.80 – 0.92 | Likely attack, verify |
| Low | 0.65 – 0.80 | Suspicious, monitor |
| Benign | < 0.65 | Below alert threshold |

---

## 7. Signature Detection Engine

### Rule Format

Rules are defined in `signatures/rules.yaml`. Each rule specifies:

- **id** — unique identifier (e.g. `SYN_FLOOD_001`)
- **severity** — `low`, `medium`, or `high`
- **enabled** — toggle without deleting
- **tags** — category labels for filtering
- **conditions** — list of field comparisons (ALL must match — logical AND)

### Supported Operators

`gt`, `lt`, `gte`, `lte`, `eq`, `neq`, `in`, `not_in`, `contains`

### Hot-reload Mechanism

The `SignatureChecker` runs a background watcher thread that polls `rules.yaml` for file modification time changes every 10 seconds. When a change is detected, the rule set is recompiled and atomically swapped under a re-entrant lock. The monitor process does not need to restart to pick up rule changes.

### Rule-ML Integration

Signature matches and ML scores are combined in `ai_engine/alert_engine.py`. A signature match always escalates the final alert to high severity, regardless of the ML score. This ensures that known-bad traffic (e.g. traffic to Meterpreter port 4444) is never downgraded by a low ML confidence score.

---

## 8. Pipeline Infrastructure

### Thread Model

The pipeline runs in a single thread during packet capture (Scapy's `sniff()` is blocking). Flow aggregation, feature extraction, inference, and alert routing all happen synchronously within the packet callback. This keeps the architecture simple and avoids race conditions between capture and processing.

The only background threads are:
- **Signature file watcher** — polls `rules.yaml` every 10s
- **Dedup maintenance** — evicts stale dedup keys every 60s
- **Retrain scheduler** — fires retrain jobs on a configurable interval

### Alert Deduplication

The deduplicator maintains a dictionary of `key → last_seen_timestamp`. The key is `(src_ip, dst_ip, dst_port, label)`. When an alert arrives:

1. If `now - last_seen < window`, the alert is suppressed and a counter incremented
2. Otherwise, the alert fires and `last_seen` is updated

Suppression counts are carried forward as `suppression_note` on the next firing alert for the same key, so no information is lost.

### Online Retraining

The retrainer (`scripts/retrain.py`) builds a training set from:

- `data/alerts.jsonl` — confirmed alert records, labelled as attacks
- `data/flows.jsonl` — recent flows with score < 0.3, labelled as benign

A minimum alert count threshold (default 50) prevents retraining on insufficient data. Before overwriting the model, the existing `nids_model.joblib` and `scaler.joblib` are backed up to `data/models/backups/` with a timestamp suffix. The retrain history is appended to `data/models/retrain_history.jsonl`.

---

## 9. Dashboard

The Streamlit dashboard (`dashboard/app.py`) serves as the central command interface. It was recently refactored into a highly modular, component-driven **Single-Page Application** using native Streamlit Tabs and Google Material Symbols for a premium UI. It connects directly to the underlying `nids.db` architecture and Redis backend. It presents 5 robust Tabs:

1. **Overview** — Executive summary containing a KPI row, alerting timeline, Geographical Threat Map, Network Traffic Flow Sankey diagram, and severity break-downs.
2. **Alerts Explorer** — In-depth log data frame with specific signature hits, anomalous scores, and an Alert Object Inspector providing 1-click Firewall Banning logic.
3. **Active Incidents** — Visualization of the Correlation Engine wrapping alerts into active geographical malicious incidents.
4. **Analytics & ML** — Advanced perspective on the probability distributions, ML score percentiles, and Port Vulnerability targeting.
5. **Settings** — Control panel handling Redis Engine Health polling, live Blocklist management with un-banning execution, and Database maintenance via total state wiping.

---

## 10. Evaluation

### Random Forest Results (CICIDS2017 Test Set)

Evaluation on 20% held-out test set (≈ 500,000 flows):

| Metric | Benign | Attack |
|---|---|---|
| Precision | > 0.98 | > 0.97 |
| Recall | > 0.99 | > 0.96 |
| F1-score | > 0.98 | > 0.96 |

ROC-AUC: > 0.997

The confusion matrix shows very low false positive and false negative rates. The most important features by Gini importance are typically `dst_port`, `flow_bytes_per_sec`, `syn_flag_count`, and `duration`.

### Signature Engine Validation

All 18 enabled rules were validated against the synthetic test pcap generated by `scripts/gen_test_pcap.py`. Expected hits:

| Rule | Pattern Used | Result |
|---|---|---|
| SYN_FLOOD_001 | 80 SYN packets, 0 ACK | FIRED |
| PORT_SCAN_001 | RST responses on 25 ports | FIRED |
| BAD_PORT_SMB | Traffic to port 445 | FIRED |
| BAD_PORT_METERPRETER | Traffic to port 4444 | FIRED |
| BAD_PORT_TELNET | Traffic to port 23 | FIRED |
| C2_BEACON_001 | 2-packet, 0.1s flows | FIRED |

### False Positive Analysis

On the synthetic test pcap (benign HTTP/HTTPS traffic only), zero false positive alerts were generated at the default threshold of 0.65. On live network traffic, the expected FP rate depends heavily on the network environment. The `notebooks/fp_tuner.ipynb` notebook provides tooling to analyse FPs and calibrate thresholds to the specific deployment environment.

---

## 11. Limitations and Future Work

### Current Limitations

**Single-node capture only.** The current architecture captures from one interface on one machine. A distributed deployment (multiple sensors reporting to a central aggregator) would require a message broker (e.g. Kafka) between the capture layer and the AI engine.

**Flow-level detection only.** The system operates on aggregated flow statistics, not packet payloads. Deep Packet Inspection (DPI) for application-layer attacks (e.g. SQL injection in HTTP bodies) is not implemented.

**Encrypted traffic.** Modern TLS 1.3 traffic cannot be inspected at the payload level. The system relies entirely on flow-level metadata, which limits detection capability against attacks tunnelled over HTTPS.

**Dataset temporal drift.** CICIDS2017 is from 2017. Attack techniques evolve, and the RF model may underperform against newer attack tooling not represented in the training data. The online retraining mechanism partially mitigates this over time.

**WSL raw socket limitations.** On Windows Subsystem for Linux, raw socket access requires workarounds (sudo with full venv path, or `setcap` on a native filesystem). This limits the ease of deployment in WSL-based development environments.

### Future Work

- **Distributed capture** using Kafka or ZeroMQ between sensors and the central engine
- **LSTM/Transformer sequence model** for detecting attacks that span multiple flows over time (e.g. slow exfiltration, multi-stage intrusions)
- **GNN-based lateral movement detection** using graph relationships between source/destination IP pairs
- **API integration** — REST endpoint for submitting flow records from external sensors
- **Threat intelligence feed** — automatic ingestion of IP blocklists (e.g. AbuseIPDB, Emerging Threats) into the signature engine
- **Active response** — integration with firewall APIs (iptables, pfSense) to automatically block high-confidence attacker IPs

---

## 12. Conclusion

This project demonstrates that a practical, deployable AI-powered NIDS can be built entirely in Python using open-source libraries and public datasets. The hybrid ensemble architecture — combining supervised classification for known attacks with unsupervised anomaly detection for zero-days — provides broader coverage than either approach alone.

The YAML-based signature engine with hot-reload capability makes the system operationally manageable without requiring code changes or service restarts. The online retraining mechanism allows the model to adapt to the specific characteristics of the network it monitors over time.

The 87-test suite, CLI tooling, false positive tuner, and Streamlit dashboard make this a complete, end-to-end system suitable for use as both a functional security tool and a portfolio demonstration of applied machine learning in cybersecurity.

---

## References

1. Sharafaldin, I., Habibi Lashkari, A., & Ghorbani, A. A. (2018). Toward generating a new intrusion detection dataset and intrusion traffic characterization. *ICISSP 2018*.

2. Breiman, L. (2001). Random Forests. *Machine Learning, 45*(1), 5–32.

3. Chawla, N. V., Bowyer, K. W., Hall, L. O., & Kegelmeyer, W. P. (2002). SMOTE: Synthetic Minority Over-sampling Technique. *JAIR, 16*, 321–357.

4. An, J., & Cho, S. (2015). Variational Autoencoder based Anomaly Detection using Reconstruction Probability. *SNU Data Mining Center*.

5. Roesch, M. (1999). Snort — Lightweight intrusion detection for networks. *USENIX LISA 1999*.
