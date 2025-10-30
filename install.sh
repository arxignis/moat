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

# Create config file
echo "Creating config file..."
curl -fSL https://raw.githubusercontent.com/arxignis/moat/refs/heads/main/config_example.yaml -o /etc/moat/config.yaml
chmod 644 /etc/moat/config.yaml

# Enable and start service
echo "Enabling and starting service..."
systemctl enable moat

echo "Before starting the service, you need to add your API key to the config file /etc/moat/config.yaml."
echo "You can get your API key from https://dash.arxignis.com/settings/api-keys."
echo "Then run 'systemctl start moat' to start the service."
