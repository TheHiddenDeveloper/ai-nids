# AI-Powered Network Intrusion Detection System

A Python-based NIDS combining ML-driven anomaly detection with signature-based rules.

## Architecture

```
Live traffic
    │
    ▼
Packet Capture (scapy)
    │
    ▼
Flow Aggregator (5-tuple)
    │
    ▼
Feature Extractor (16 features)
    │
    ├──► Signature Checker (rule-based)
    │
    ▼
Inference Engine (Random Forest / Autoencoder)
    │
    ▼
Alert Engine (severity classification)
    │
    ▼
Dashboard (Streamlit) + Alert Log (JSONL)
```

## Quick Start

See `docs/SETUP.md` for full setup instructions.

```bash
# 1. Install
pip install -r requirements.txt

# 2. Train (after downloading CICIDS2017)
python scripts/train.py --model rf

# 3. Monitor
sudo python scripts/run_monitor.py --interface eth0

# 4. Dashboard
streamlit run dashboard/app.py
```

## Project Structure

```
ai_nids/
├── monitor/            # Packet capture, flow aggregation, feature extraction
├── ai_engine/          # Dataset loader, model training, inference
├── dashboard/          # Streamlit web UI
├── signatures/         # Rule-based detection layer
├── scripts/            # CLI entry points (train, monitor)
├── data/               # Raw data, models, logs (git-ignored)
├── tests/              # Unit tests
├── docs/               # Setup guide
├── config.yaml         # All tuneable parameters
└── requirements.txt
```
