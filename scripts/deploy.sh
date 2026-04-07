#!/usr/bin/env bash
# Deploy AI-NIDS Systemd Services Dynamically
# This script intelligently finds the project root, current user, and virtualenv
# to set up systemd services correctly regardless of deployment path.

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
echo "Current User: $USER"

# 2. Check for virtual environment
VENV_DIR="$PROJECT_ROOT/ai-venv"
if [ ! -d "$VENV_DIR" ]; then
  echo "❌ Error: Virtual environment not found at $VENV_DIR"
  echo "Please create a virtual environment named 'ai-venv' in the project root."
  exit 1
fi

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

# 4. Define target service files
MONITOR_SVC="ai-nids-monitor.service"
DASHBOARD_SVC="ai-nids-dashboard.service"

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
  sed "s|{{USER}}|$USER|g" | \
  sed "s|{{INTERFACE}}|$INTERFACE|g" > "$tmp_file"
  
  # Copy to final destination with sudo
  sudo cp "$tmp_file" "$dest"
  rm "$tmp_file"
}

process_service "$MONITOR_SVC"
process_service "$DASHBOARD_SVC"

# 6. Reload and restart
echo "Reloading systemd daemon..."
sudo systemctl daemon-reload

echo "Enabling services..."
sudo systemctl enable "$MONITOR_SVC"
sudo systemctl enable "$DASHBOARD_SVC"

echo "Restarting services..."
sudo systemctl restart "$MONITOR_SVC"
sudo systemctl restart "$DASHBOARD_SVC"

echo "✅ Deployment Complete!"
echo ""
echo "Check status:"
echo "  sudo systemctl status $MONITOR_SVC"
echo "  sudo systemctl status $DASHBOARD_SVC"
