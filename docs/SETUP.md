# AI-NIDS Setup Guide (Kali / Ubuntu)

## 1. System Prerequisites

```bash
sudo apt update
sudo apt install -y python3-pip python3-venv libpcap-dev wireshark-common tcpdump
```

## 2. Project Setup

```bash
# Clone or extract the project
cd ai_nids/

# Create and activate a virtual environment
python3 -m venv venv
source venv/bin/activate

# Install all Python dependencies
pip install -r requirements.txt
```

## 3. Download the CICIDS2017 Dataset

1. Visit: https://www.unb.ca/cic/datasets/ids-2017.html
2. Download the **CSV** files (not the pcap files — CSVs are pre-processed flows)
3. Place them in `data/raw/cicids2017/`

Expected file structure:
```
data/raw/cicids2017/
├── Monday-WorkingHours.pcap_ISCX.csv
├── Tuesday-WorkingHours.pcap_ISCX.csv
├── Wednesday-workingHours.pcap_ISCX.csv
├── Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv
├── Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv
├── Friday-WorkingHours-Morning.pcap_ISCX.csv
├── Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv
└── Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv
```

> **Tip:** You can start with just one or two CSV files to verify the pipeline
> works before loading the full 2.8 GB dataset.

## 4. Train the Model

```bash
# Train the Random Forest (recommended first — fast and accurate)
python scripts/train.py --model rf

# Train the Autoencoder (unsupervised, for zero-day detection)
python scripts/train.py --model autoencoder

# Train both at once
python scripts/train.py --model both

# Use a specific data directory or model output path
python scripts/train.py --model rf \
  --data-dir /path/to/cicids2017 \
  --model-dir data/models
```

Training output (Random Forest on full dataset):
- Expected time: ~5–15 minutes depending on CPU
- Expected accuracy: >97% on CICIDS2017 binary classification
- Saved files: `data/models/nids_model.joblib`, `data/models/scaler.joblib`

## 5. Find Your Network Interface

```bash
ip a
# or
ifconfig

# Common interface names:
#   eth0, ens33, enp3s0  — wired
#   wlan0, wlp2s0        — wireless
#   lo                   — loopback (for local testing only)
```

Update `config.yaml` → `network.interface` to match.

## 6. Run the Live Monitor

```bash
# Live capture (requires root for raw socket access)
sudo python scripts/run_monitor.py --interface eth0

# Longer capture windows (useful on busy networks)
sudo python scripts/run_monitor.py --interface eth0 --timeout 60

# Offline mode — replay a saved .pcap file (no root needed)
python scripts/run_monitor.py --pcap data/raw/sample.pcap

# Signature-only mode (no AI model required)
sudo python scripts/run_monitor.py --interface eth0 --no-model
```

### Root / Capability Options

Raw packet capture requires root privileges OR a capability grant:

```bash
# Option 1: Run with sudo (easiest)
sudo python scripts/run_monitor.py --interface eth0

# Option 2: Grant cap_net_raw to your Python binary (persistent, no sudo needed)
sudo setcap cap_net_raw+eip $(which python3)
python scripts/run_monitor.py --interface eth0
```

## 7. Launch the Dashboard

```bash
# From the project root (not the dashboard/ folder)
streamlit run dashboard/app.py

# Custom host/port
streamlit run dashboard/app.py --server.address 0.0.0.0 --server.port 8501
```

Open your browser at: http://localhost:8501

The dashboard auto-refreshes every 3 seconds and shows:
- Live alert table with severity colour-coding
- Severity breakdown pie chart
- ML score histogram with threshold markers
- Top alert source IP bar chart

## 8. Run the Test Suite

```bash
# Run all tests
pytest tests/ -v

# Run a specific test file
pytest tests/test_flow_aggregator.py -v

# Run with coverage
pip install pytest-cov
pytest tests/ --cov=monitor --cov=ai_engine --cov=signatures --cov-report=term-missing
```

## 9. Configuration Reference

All tuneable parameters live in `config.yaml`:

| Key | Default | Description |
|-----|---------|-------------|
| `network.interface` | `eth0` | NIC for live capture |
| `network.capture_timeout` | `10` | Seconds per capture window |
| `features.flow_timeout` | `60` | Seconds before a flow expires |
| `model.type` | `random_forest` | Model to use for inference |
| `model.anomaly_threshold` | `0.65` | Minimum score to trigger an alert |
| `alerts.severity_levels.low` | `0.65` | Low severity threshold |
| `alerts.severity_levels.medium` | `0.80` | Medium severity threshold |
| `alerts.severity_levels.high` | `0.92` | High severity threshold |
| `dashboard.refresh_interval` | `3` | Dashboard auto-refresh in seconds |

## 10. Data Files Generated

| File | Description |
|------|-------------|
| `data/flows.jsonl` | All scored flows (one JSON per line) |
| `data/alerts.jsonl` | Alert records only |
| `data/nids.log` | Application log |
| `data/models/nids_model.joblib` | Trained RF model |
| `data/models/scaler.joblib` | Feature scaler |
| `data/models/autoencoder.keras` | Trained autoencoder (if used) |

## Troubleshooting

**`PermissionError: [Errno 1] Operation not permitted`**
→ Run with `sudo` or grant `cap_net_raw` as above.

**`FileNotFoundError: No CSV files found`**
→ Check that CICIDS2017 CSV files are in `data/raw/cicids2017/`.

**`Model not found`**
→ Run `python scripts/train.py --model rf` first.

**Dashboard shows "No alerts yet"**
→ The monitor needs to be running in a separate terminal. Start it with `sudo python scripts/run_monitor.py`.

**`ModuleNotFoundError`**
→ Ensure your venv is activated: `source venv/bin/activate`
