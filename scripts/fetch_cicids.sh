#!/bin/bash
# scripts/fetch_cicids.sh
# Downloads actual CICIDS2017 research data for high-precision training.

set -e

PROJECT_ROOT="/home/thehiddendeveloper/Dev Work/ai-nids"
DATA_DIR="$PROJECT_ROOT/data/raw/cicids2017"
mkdir -p "$DATA_DIR"

echo "+++ Research Data Ingestion: CICIDS2017 +++"

# Ensure huggingface_hub is ready
"$PROJECT_ROOT/ai-venv/bin/pip" install -q huggingface_hub

# Download specific subsets: Friday (DDoS and PortScan)
echo "Downloading DDoS research data..."
"$PROJECT_ROOT/ai-venv/bin/huggingface-cli" download c01dsnap/CIC-IDS2017 \
    "Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv" \
    --local-dir "$DATA_DIR" --local-dir-use-symlinks False

echo "Downloading PortScan research data..."
"$PROJECT_ROOT/ai-venv/bin/huggingface-cli" download c01dsnap/CIC-IDS2017 \
    "Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv" \
    --local-dir "$DATA_DIR" --local-dir-use-symlinks False

echo "+++ Research Data Ingested Successfully → $DATA_DIR +++"
