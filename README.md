# AI-NIDS — AI-Powered Network Intrusion Detection System

![Python](https://img.shields.io/badge/Python-3.10%2B-3776AB?logo=python&logoColor=white)
![scikit-learn](https://img.shields.io/badge/scikit--learn-RF%20%2B%20SMOTE-F7931E?logo=scikitlearn&logoColor=white)
![TensorFlow](https://img.shields.io/badge/TensorFlow-Autoencoder-FF6F00?logo=tensorflow&logoColor=white)
![Streamlit](https://img.shields.io/badge/Dashboard-Streamlit-FF4B4B?logo=streamlit&logoColor=white)
![Tests](https://img.shields.io/badge/Tests-87%20passing-22c55e)
![License](https://img.shields.io/badge/License-MIT-6366f1)

A production-grade, Python-based NIDS that combines a supervised **Random Forest** classifier, an unsupervised **Autoencoder** anomaly detector, and a hot-reloadable **YAML signature engine** into a single real-time detection pipeline.

---

## Key Features

- **Dual-model ensemble** — RF (known attacks) + Autoencoder (zero-days) with configurable weighting
- **20 built-in signature rules** across 7 categories: DDoS, port scan, C2/beaconing, brute-force, exfiltration, suspicious ports
- **Hot-reload signatures** — edit `rules.yaml` while the monitor runs; changes apply within 10 seconds
- **Alert deduplication** — suppresses repeated alerts from the same source within a configurable window
- **Online retraining** — periodically retrains on confirmed alerts + recent benign flows
- **Live Streamlit dashboard** — 8-panel real-time view with timeline, score histogram, top IPs, and signature hit chart
- **87 unit tests** covering every layer of the pipeline
- **Trained on CICIDS2017** — 2.8M labelled network flows across 14 attack categories

---

## Architecture

```
Live network traffic  ──or──  pcap replay
          │
          ▼
  ┌───────────────────────────────────────┐
  │         Part 1 — Network Monitor      │
  │                                       │
  │   PacketCapture  (scapy / pyshark)    │
  │         │                             │
  │   FlowAggregator  (5-tuple, 20s TTL)  │
  │         │                             │
  │   FeatureExtractor  (20 features)     │
  └──────────────┬────────────────────────┘
                 │  flow feature vectors
                 ▼
  ┌───────────────────────────────────────┐
  │          Part 2 — AI Engine           │
  │                                       │
  │   EnsembleInferenceEngine             │
  │     ├── RandomForest  (65%)           │◄── Trained on CICIDS2017
  │     └── Autoencoder   (35%)           │◄── Benign-traffic baseline
  │         │                             │
  │   AlertDeduplicator  (60s window)     │
  │         │                             │
  │   AlertEngine  (low/medium/high)      │
  │         │                             │
  │   SignatureChecker  (YAML rules)  ────┤◄── signatures/rules.yaml
  └──────────────┬────────────────────────┘
                 │
          ┌──────┴──────┐
          │  EventBus   │  (thread-safe pub/sub)
          └──────┬──────┘
     ┌───────────┼───────────┐
     ▼           ▼           ▼
 FlowLogger  AlertLogger  StatsTracker
 (JSONL)     (JSONL)      (rolling 5min)
                               │
                               ▼
                     Streamlit Dashboard
                     (http://localhost:8501)
```

---

## Quickstart

### 1. Install

```bash
# Clone / extract project
cd ai_nids/

# Create virtual environment
python3 -m venv ai-venv
source ai-venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

### 2. Download CICIDS2017

Download **MachineLearningCSV.zip** from https://www.unb.ca/cic/datasets/ids-2017.html  
Extract the CSV files into `data/raw/cicids2017/`:

```bash
unzip MachineLearningCSV.zip -d data/raw/cicids2017/
```

### 3. Train the model

```bash
# Random Forest only (fast — ~15 min on full dataset)
python scripts/train.py --model rf

# Both RF + Autoencoder (recommended for full ensemble)
python scripts/train.py --model both
```

Evaluation plots are saved to `data/models/`.

### 4. Demo mode (no root needed)

Generate a synthetic attack pcap and run the full pipeline against it:

```bash
python scripts/demo.py
```

This generates attack traffic, runs detection, and shows a live terminal report. No root, no live interface needed.

### 5. Live monitoring

```bash
# Find your interface
ip a

# Run monitor (requires root for raw socket capture)
sudo -E env PATH="$PATH" python scripts/run_monitor.py --interface eth0

# Or grant cap_net_raw to avoid sudo
sudo setcap cap_net_raw+eip ai-venv/bin/python3
python scripts/run_monitor.py --interface eth0

# Or run with sudo with venv preserved via -E flag
sudo -E env PATH="$PATH" python scripts/run_monitor.py --interface eth0
```


### 6. Dashboard

```bash
# In a separate terminal
streamlit run dashboard/app.py
# → http://localhost:8501
```

### 7. Autonomous Systemd Setup

To convert the NIDS and Dashboard into robust background daemons that start on boot and automatically handle logging limits:
```bash
# This will link systemd files and start rotating logs
bash scripts/deploy.sh

# You can then safely close the terminal
```

---

## Project Structure

```
ai_nids/
│
├── monitor/                    # Part 1: capture + feature pipeline
│   ├── capture.py              #   scapy live capture & pcap replay
│   ├── flow_aggregator.py      #   bidirectional 5-tuple flow tracking
│   ├── feature_extractor.py    #   raw flows → 20-feature DataFrame
│   └── logger.py               #   Numpy-safe JSONL Rolling Logger
│
├── ai_engine/                  # Part 2: models & training
│   ├── dataset.py              #   CICIDS2017 loader + column mapping
│   ├── trainer.py              #   RF (SMOTE) + Autoencoder training
│   ├── ensemble.py             #   weighted RF + AE inference engine
│   ├── inference.py            #   standalone RF inference (legacy)
│   └── alert_engine.py         #   severity thresholds + result filtering
│
├── core/                       # Infrastructure
│   ├── pipeline.py             #   central orchestrator (Step 4)
│   ├── event_bus.py            #   thread-safe pub/sub
│   ├── deduplicator.py         #   alert storm suppression
│   └── stats_tracker.py        #   rolling 5-min metrics
│
├── signatures/
│   ├── rules.yaml              #   20 YAML signature rules
│   ├── loader.py               #   YAML → Rule objects compiler
│   └── checker.py              #   hot-reloading rule evaluator
│
├── dashboard/
│   └── app.py                  #   Streamlit real-time dashboard
│
├── scripts/
│   ├── train.py                #   CLI: train RF / AE / both
│   ├── run_monitor.py          #   CLI: live capture + inference
│   ├── capture_dataset.py      #   CLI: build canonical local CSV data
│   ├── train_local_model.py    #   CLI: retrain models natively
│   ├── deploy.sh               #   CLI: installs Systemd autonomy layer
│   ├── demo.py                 #   CLI: self-contained demo mode
│   ├── retrain.py              #   CLI: online retraining scheduler
│   ├── sig_manager.py          #   CLI: rule management tool
│   └── gen_test_pcap.py        #   CLI: synthetic attack pcap generator
│
├── scripts/systemd/            #   Systemd `.service` configs
│
├── notebooks/
│   ├── train_explore.ipynb     #   step-by-step training exploration
│   └── fp_tuner.ipynb          #   false positive analysis + calibration
│
├── tests/                      #   87 unit tests (pytest)
├── docs/
│   └── SETUP.md                #   full installation guide
│
├── config.yaml                 #   all tuneable parameters
└── requirements.txt
```

---

## Detection Capabilities

### Machine Learning

| Model | Type | Training data | Strength |
|---|---|---|---|
| Random Forest | Supervised | CICIDS2017 (2.8M flows) | Known attack patterns |
| Autoencoder | Unsupervised | Benign traffic only | Zero-day anomalies |
| Ensemble | Weighted (65/35) | Both above | Combined coverage |

### Signature Rules

| Category | Rules | Examples |
|---|---|---|
| DDoS / Flood | 3 | SYN flood, UDP flood, high-volume flow |
| Port scanning | 3 | RST-based, FIN stealth, NULL scan |
| C2 / Beaconing | 2 | Tiny periodic flows, low-and-slow |
| Suspicious ports | 7 | 23, 445, 3389, 5900, 6667, 4444, 31337 |
| Brute force | 2 | SSH, FTP repeated connection attempts |
| Exfiltration | 1 | Large asymmetric outbound upload |

Add custom rules by editing `signatures/rules.yaml` — no code changes needed.

---

## Management Tools

```bash
# Signature management
python scripts/sig_manager.py list
python scripts/sig_manager.py list --tag c2
python scripts/sig_manager.py show SYN_FLOOD_001
python scripts/sig_manager.py test SYN_FLOOD_001
python scripts/sig_manager.py enable  DNS_EXFIL_001
python scripts/sig_manager.py disable BAD_PORT_VNC
python scripts/sig_manager.py stats

# Online retraining
python scripts/retrain.py --once
python scripts/retrain.py --interval 3600 --min-new-alerts 50

# False positive tuning
jupyter notebook notebooks/fp_tuner.ipynb
```

---

## Running Tests

```bash
pytest tests/ -v
# 87 tests across 5 test files
```

---

## Dataset

**CICIDS2017** — Canadian Institute for Cybersecurity Intrusion Detection Evaluation Dataset 2017.  
2,830,743 labelled network flows across 14 categories including DoS, DDoS, Brute Force, Web Attacks, Infiltration, Bot, and Port Scan traffic.

Download: https://www.unb.ca/cic/datasets/ids-2017.html  
Use: `MachineLearningCSV.zip` (not `GeneratedLabelledFlows.zip`)

---

## WSL / Kali Notes

Raw packet capture requires root or `cap_net_raw`. On WSL, the venv is dropped when using `sudo`:

```bash
# Recommended — use full venv path with sudo
sudo /path/to/ai-venv/bin/python scripts/run_monitor.py --interface eth0

# Or use sudo -E to preserve venv environment
sudo -E env PATH="$PATH" python scripts/run_monitor.py --interface eth0
```

---

## License

MIT — see LICENSE file.
