#!/bin/sh

VERSION=0.1.1
BRANCH=main

# Install dependencies
echo "Installing dependencies..."
apt-get update -qq
apt-get install -yqq curl sed clamav-daemon redis-server

# Setup ClamAV

echo "Setting up ClamAV..."
curl -fSL https://raw.githubusercontent.com/arxignis/moat/refs/heads/${BRANCH}/others/clamd/clamd.conf -o /etc/clamav/clamd.conf
mkdir -p /etc/systemd/system/clamav-daemon.socket.d
curl -fSL https://raw.githubusercontent.com/arxignis/moat/refs/heads/${BRANCH}/others/systemd/clamd/override.conf -o /etc/systemd/system/clamav-daemon.socket.d/override.conf
systemctl daemon-reload
systemctl enable clamav-daemon
systemctl restart clamav-daemon
systemctl status clamav-daemon

echo "ClamAV setup complete."
sleep 1

# Install moat
echo "Installing moat ${VERSION} for $(arch)..."
curl -fSL https://github.com/arxignis/moat/releases/download/v${VERSION}/moat-$(arch)-unknown-linux-gnu.tar.gz -o /tmp/moat-$(arch)-unknown-linux-gnu.tar.gz
tar -C /usr/local/bin -xzf /tmp/moat-$(arch)-unknown-linux-gnu.tar.gz

# Install service
echo "Installing service..."
curl -fSL https://raw.githubusercontent.com/arxignis/moat/refs/heads/${BRANCH}/others/systemd/moat.service -o /etc/systemd/system/moat.service
systemctl daemon-reload

# Create directories
echo "Creating directories..."
mkdir -p /var/log/moat /var/run/moat /var/lib/moat /etc/moat

# Create config file
echo "Creating config file..."
curl -fSL https://raw.githubusercontent.com/arxignis/moat/refs/heads/${BRANCH}/config_example.yaml -o /etc/moat/config.yaml
chmod 644 /etc/moat/config.yaml

# Enable and start service
echo "Enabling and starting service..."
systemctl enable moat

echo "Before starting the service, you need to add your API key to the config file /etc/moat/config.yaml."
sleep 1
echo "You can get your API key from https://dash.arxignis.com/settings/api-keys."
sleep 1
echo "Then run 'systemctl start moat' to start the service."
