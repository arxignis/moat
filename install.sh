#!/bin/sh

VERSION=0.0.6

# Install dependencies
echo "Installing dependencies..."
apt-get update -qq
apt-get install -yqq curl sed

# Install moat
echo "Installing moat ${VERSION} for $(arch)..."
curl -fSL https://github.com/arxignis/moat/releases/download/v${VERSION}/moat-$(arch)-unknown-linux-gnu.tar.gz -o /tmp/moat-$(arch)-unknown-linux-gnu.tar.gz
tar -C /usr/local/bin -xzf /tmp/moat-$(arch)-unknown-linux-gnu.tar.gz

# Install service
echo "Installing service..."
curl -fSL https://raw.githubusercontent.com/arxignis/moat/refs/heads/main/others/systemd/moat.service -o /etc/systemd/system/moat.service
systemctl daemon-reload

# Create directories
echo "Creating directories..."
mkdir -p /var/log/moat /var/run/moat /var/lib/moat /etc/moat

# Prompt for API key
echo ""
echo "Please enter your Arxignis API key:"
read -r API_KEY

# Create config file
echo "Creating config file..."
curl -fSL https://raw.githubusercontent.com/arxignis/moat/refs/heads/main/config_example.yaml -o /etc/moat/config.yaml
sed -i "s/api_key: \"\"/api_key: \"${API_KEY}\"/" /etc/moat/config.yaml
chmod 644 /etc/moat/config.yaml

# Enable and start service
echo "Enabling and starting service..."
systemctl enable moat
systemctl start moat

# Check status
echo "Checking status..."
systemctl status moat
