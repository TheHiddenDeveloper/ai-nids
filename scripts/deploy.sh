#!/usr/bin/env bash
# ==============================================================================
# DEPLOY — Systemd Service Installer
# ==============================================================================
# Purpose:
#   Installs AI-NIDS as systemd services for production deployment. Dynamically
#   detects the project root, current user, virtualenv, and network interface
#   to set up services correctly regardless of deployment path.
#
# Services:
#   ai-nids-monitor.service — continuous packet capture + inference pipeline
#   ai-nids-api.service     — FastAPI backend serving the dashboard + REST API
#
# Steps:
#   1. Detect project root, user, virtualenv, node/npm
#   2. Build Next.js frontend (static export for FastAPI to serve)
#   3. Detect active network interface (excludes lo/docker/bridge)
#   4. Process systemd service templates (replace {{variables}})
#   5. Copy to /etc/systemd/system/, daemon-reload, enable, restart
#
# Usage:
#   sudo bash scripts/deploy.sh
#
# Design:
#   - No separate dashboard service — FastAPI serves frontend at / on port 8000
#   - ai-nids-dashboard.service was removed as redundant
#   - Uses sed for template variable substitution
#   - After deploy, check: sudo systemctl status ai-nids-monitor.service
# ==============================================================================

set -e

echo "🛡️  Deploying AI-NIDS Services..."

# 1. Resolve absolute project directory (ensure we are in the root)
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

if [ ! -d "$PROJECT_ROOT/scripts/systemd" ]; then
  echo "❌ Error: Could not find systemd templates in $PROJECT_ROOT/scripts/systemd"
  exit 1
fi

echo "Project Root: $PROJECT_ROOT"
# When run with sudo, $USER is "root" — use $SUDO_USER for the real user
REAL_USER="${SUDO_USER:-$USER}"
echo "Current User: $REAL_USER"

# 2. Check for virtual environment
VENV_DIR="$PROJECT_ROOT/ai-venv"
if [ ! -d "$VENV_DIR" ]; then
  echo "❌ Error: Virtual environment not found at $VENV_DIR"
  echo "Please create a virtual environment named 'ai-venv' in the project root."
  exit 1
fi

# 2b. Check for Node.js and npm (needed for frontend)
if ! command -v node &> /dev/null; then
  echo "❌ Error: Node.js is required for the Next.js frontend but not found."
  echo "Please install Node.js and npm."
  exit 1
fi

if ! command -v npm &> /dev/null; then
  echo "❌ Error: npm is required for the Next.js frontend but not found."
  echo "Please install npm."
  exit 1
fi

echo "Node.js version: $(node --version)"
echo "npm version: $(npm --version)"

# 2c. Build the Next.js frontend (static export served by FastAPI on port 8000)
echo ""
echo "Building Next.js frontend..."
cd "$PROJECT_ROOT/frontend"
npm install
npm run build
cd "$PROJECT_ROOT"
echo "✅ Frontend build complete"

# 3. Dynamically detect a valid network interface
# Priority: Ethernet (UP) > Wireless (UP) > First available (not lo/docker)
INTERFACE=""
if ip link show eth0 >/dev/null 2>&1; then
  INTERFACE="eth0"
else
  # Find an active Ethernet or WiFi interface (UP)
  # Exclude loopback, docker, and bridges
  INTERFACE=$(ip addr show | grep 'state UP' | awk '{print $2}' | sed 's/://' | grep -vE '^(lo|docker|br-|veth)' | head -n 1)
  
  if [ -z "$INTERFACE" ]; then
    # Fallback: Just get the first non-loopback device that isn't docker
    INTERFACE=$(ip link show | awk -F': ' '/^[0-9]+: / {print $2}' | grep -vE '^(lo|docker|br-|veth)' | head -n 1)
  fi
fi

if [ -z "$INTERFACE" ]; then
  echo "⚠️ Warning: Could not detect a valid network interface. Defaulting to 'lo'."
  INTERFACE="lo"
else
  echo "Detected Interface: $INTERFACE"
fi

# 4. Define target service files (frontend is served by FastAPI at port 8000, no separate dashboard service)
MONITOR_SVC="ai-nids-monitor.service"
API_SVC="ai-nids-api.service"

# 5. Process and copy service files
echo "Processing and copying service files to /etc/systemd/system/..."

process_service() {
  local svc_name=$1
  local src="$PROJECT_ROOT/scripts/systemd/$svc_name"
  local dest="/etc/systemd/system/$svc_name"
  
  # Create a temporary processed file
  local tmp_file=$(mktemp)
  
  # Perform replacements while preserving absolute paths and handling spaces via {{PROJECT_ROOT}}
  sed "s|{{PROJECT_ROOT}}|$PROJECT_ROOT|g" "$src" | \
  sed "s|{{USER}}|$REAL_USER|g" | \
  sed "s|{{INTERFACE}}|$INTERFACE|g" > "$tmp_file"
  
  # Copy to final destination with sudo
  sudo cp "$tmp_file" "$dest"
  rm "$tmp_file"
}

process_service "$MONITOR_SVC"
process_service "$API_SVC"

# 6. Reload and restart
echo "Reloading systemd daemon..."
sudo systemctl daemon-reload

echo "Enabling services..."
sudo systemctl enable "$MONITOR_SVC"
sudo systemctl enable "$API_SVC"

echo "Restarting services..."
sudo systemctl restart "$MONITOR_SVC"
sudo systemctl restart "$API_SVC"

echo "✅ Deployment Complete!"
echo ""
echo "Check status:"
echo "  sudo systemctl status $MONITOR_SVC"
echo "  sudo systemctl status $API_SVC"
echo ""
echo "Frontend is served by the API at http://localhost:8000 (no separate dashboard service needed)"
