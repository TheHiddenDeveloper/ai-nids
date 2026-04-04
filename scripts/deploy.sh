#!/usr/bin/env bash
# Deploy AI-NIDS Systemd Services

set -e

echo "🛡️  Deploying AI-NIDS Services..."

# Determine absolute path to the project to dynamically update the service files
PROJECT_DIR=$(pwd)
echo "Setting WorkingDirectory to: $PROJECT_DIR"

if [ ! -d "scripts/systemd" ]; then
  echo "❌ Error: MUST be run from the root of the ai_nids project directory."
  exit 1
fi

# We use sudo directly to copy to systemd
echo "Copying service files to /etc/systemd/system/..."
sudo cp scripts/systemd/ai-nids-monitor.service /etc/systemd/system/
sudo cp scripts/systemd/ai-nids-dashboard.service /etc/systemd/system/

# Fix paths dynamically in the copied systemd files
sudo sed -i "s|/home/dev/Projects/ai_nids|$PROJECT_DIR|g" /etc/systemd/system/ai-nids-monitor.service
sudo sed -i "s|/home/dev/Projects/ai_nids|$PROJECT_DIR|g" /etc/systemd/system/ai-nids-dashboard.service

echo "Reloading systemd daemon..."
sudo systemctl daemon-reload

echo "Enabling services to start on boot..."
sudo systemctl enable ai-nids-monitor.service
sudo systemctl enable ai-nids-dashboard.service

echo "Starting services..."
sudo systemctl restart ai-nids-monitor.service
sudo systemctl restart ai-nids-dashboard.service

echo "✅ Deployment Complete!"
echo ""
echo "You can check their status using:"
echo "  sudo systemctl status ai-nids-monitor"
echo "  sudo systemctl status ai-nids-dashboard"
echo ""
echo "To view live logs:"
echo "  sudo journalctl -u ai-nids-monitor.service -f"
