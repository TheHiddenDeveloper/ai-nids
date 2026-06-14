"""
Research Data Fetcher (Python)
-------------------------------
Uses huggingface_hub API to download CICIDS2017 subsets.
"""

import os
from huggingface_hub import hf_hub_download
from pathlib import Path
from loguru import logger

PROJECT_ROOT = Path("/home/thehiddendeveloper/Dev/ai-nids")
DATA_DIR = PROJECT_ROOT / "data/raw/cicids2017"
REPO_ID = "c01dsnap/CIC-IDS2017"

FILES = [
    "Monday-WorkingHours.pcap_ISCX.csv",
    "Tuesday-WorkingHours.pcap_ISCX.csv",
    "Wednesday-workingHours.pcap_ISCX.csv",
    "Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv",
    "Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv",
    "Friday-WorkingHours-Morning.pcap_ISCX.csv",
    "Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv",
    "Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv",
]

def fetch():
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    logger.info("+++ Research Data Ingestion: CICIDS2017 (Python API) +++")
    
    for filename in FILES:
        logger.info(f"Downloading {filename}...")
        try:
            # Download file to local directory
            path = hf_hub_download(
                repo_id=REPO_ID,
                repo_type="dataset",
                filename=filename,
                local_dir=DATA_DIR,
                local_dir_use_symlinks=False
            )
            logger.success(f"Downloaded: {path}")
        except Exception as e:
            logger.error(f"Failed to download {filename}: {e}")

if __name__ == "__main__":
    fetch()
