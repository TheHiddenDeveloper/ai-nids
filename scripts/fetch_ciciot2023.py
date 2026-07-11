"""
================================================================================
FETCH CICIoT2023 — IoT Attack Dataset Downloader
================================================================================
Purpose:
  Downloads CICIoT2023 research dataset CSV files into data/raw/ciciot2023/.

  The full dataset is ~46M records across many partitioned CSV files (~13GB).
  By default, downloads a representative subset (first N partitions) to keep
  disk usage manageable while providing enough diversity for training.

  NOTE: The CIC server may block automated downloads (returning HTML pages
  instead of CSVs). If the direct download fails, this script provides
  manual download instructions.

  Alternative: Kaggle mirror
    1. Install: pip install kaggle
    2. Set up credentials: https://www.kaggle.com/docs/api#authentication
    3. Download: kaggle datasets download -d himadri07/ciciot2023 --unzip -p data/raw/ciciot2023

  Dataset: https://www.unb.ca/cic/datasets/iotdataset-2023.html
  Paper:   Neto et al., "CICIoT2023: A real-time dataset and benchmark for
           large-scale attacks in IoT environment", Sensors (2023)

Usage:
  python scripts/fetch_ciciot2023.py                  # download default subset
  python scripts/fetch_ciciot2023.py --partitions 20  # download more data
  python scripts/fetch_ciciot2023.py --all            # download everything (~13GB)
================================================================================
"""

import argparse
import urllib.request
import sys
from pathlib import Path
from loguru import logger

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DATA_DIR = PROJECT_ROOT / "data/raw/ciciot2023"

# CICIoT2023 CSV files are partitioned. Each partition is a separate CSV.
# The dataset is hosted at the CIC research server.
BASE_URL = "https://cicresearch.ca/IOTDataset/CIC_IOT_Dataset2023/CSV"

# Default: download partitions 0-9 (representative subset)
DEFAULT_PARTITIONS = list(range(10))
MAX_PARTITIONS = 49  # Total partitions (0-48)


def _is_valid_csv(filepath: Path) -> bool:
    """Check that a downloaded file is actually a CSV, not an HTML error page."""
    try:
        with open(filepath, "rb") as f:
            header = f.read(256)
        # HTML pages start with <!DOCTYPE, <html, <HTML, or <?xml
        lower = header.lower().strip()
        if lower.startswith((b"<!doctype", b"<html", b"<html", b"<?xml", b"<head")):
            return False
        # Valid CSV should have comma or header-like content
        return b"," in header or b"flow" in lower or b"label" in lower
    except Exception:
        return False


def fetch_partition(partition_idx: int, out_dir: Path) -> bool:
    """Download a single CSV partition."""
    filename = f"part-{partition_idx:05d}.csv"
    url = f"{BASE_URL}/{filename}"
    out_path = out_dir / filename

    if out_path.exists() and _is_valid_csv(out_path):
        logger.info(f"  {filename} already exists, skipping")
        return True
    elif out_path.exists():
        logger.warning(f"  {filename} exists but is not a valid CSV (likely HTML page), re-downloading")
        out_path.unlink()

    logger.info(f"  Downloading {filename}...")
    try:
        urllib.request.urlretrieve(url, out_path)
        size_mb = out_path.stat().st_size / (1024 * 1024)

        if not _is_valid_csv(out_path):
            logger.error(f"  {filename}: server returned HTML instead of CSV (anti-bot protection)")
            out_path.unlink()
            return False

        logger.success(f"  Downloaded {filename} ({size_mb:.1f} MB)")
        return True
    except Exception as e:
        logger.error(f"  Failed to download {filename}: {e}")
        if out_path.exists():
            out_path.unlink()
        return False


def fetch(partitions: list = None):
    """Download CICIoT2023 CSV partitions."""
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    logger.info("+++ Research Data Ingestion: CICIoT2023 +++")

    if partitions is None:
        partitions = DEFAULT_PARTITIONS

    logger.info(f"Downloading {len(partitions)} partition(s) to {DATA_DIR}")
    success = 0
    for idx in partitions:
        if fetch_partition(idx, DATA_DIR):
            success += 1

    if success == 0:
        logger.error("=" * 60)
        logger.error("CICIoT2023 download failed — the CIC server is blocking automated requests.")
        logger.error("")
        logger.error("MANUAL DOWNLOAD OPTIONS:")
        logger.error("")
        logger.error("  Option A — Kaggle mirror (recommended):")
        logger.error("    1. pip install kaggle")
        logger.error("    2. Set up API key: https://www.kaggle.com/docs/api#authentication")
        logger.error("    3. Run:")
        logger.error(f"       kaggle datasets download -d himadri07/ciciot2023 --unzip -p {DATA_DIR}")
        logger.error("")
        logger.error("  Option B — Manual download:")
        logger.error("    1. Visit: https://www.unb.ca/cic/datasets/iotdataset-2023.html")
        logger.error("    2. Click 'Download the dataset'")
        logger.error(f"    3. Extract CSV files into: {DATA_DIR}/")
        logger.error("")
        logger.error("  Option C — Kaggle web:")
        logger.error("    1. Visit: https://www.kaggle.com/datasets/himadri07/ciciot2023")
        logger.error("    2. Click 'Download' (requires free Kaggle account)")
        logger.error(f"    3. Extract CSV files into: {DATA_DIR}/")
        logger.error("=" * 60)
        sys.exit(1)
    else:
        logger.success(f"Downloaded {success}/{len(partitions)} partitions → {DATA_DIR}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Download CICIoT2023 dataset")
    parser.add_argument("--partitions", type=int, default=10,
                        help=f"Number of CSV partitions to download (1-{MAX_PARTITIONS+1}, default: 10)")
    parser.add_argument("--all", action="store_true",
                        help="Download all partitions (~13GB)")
    args = parser.parse_args()

    if args.all:
        partitions = list(range(MAX_PARTITIONS + 1))
    else:
        n = min(args.partitions, MAX_PARTITIONS + 1)
        partitions = list(range(n))

    fetch(partitions)
