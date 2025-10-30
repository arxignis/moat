#!/bin/sh

VERSION=0.0.6

# Install dependencies
apt-get update -qq
apt-get install -yqq curl

# Install moat
curl -fSL https://github.com/arxignis/moat/releases/download/v${VERSION}/moat-$(arch)-unknown-linux-gnu.tar.gz -o /tmp/moat-$(arch)-unknown-linux-gnu.tar.gz
tar -C /usr/local/bin -xzf /tmp/moat-$(arch)-unknown-linux-gnu.tar.gz

# Install service
curl -fSL https://raw.githubusercontent.com/arxignis/moat/refs/heads/main/others/systemd/moat.service -o /etc/systemd/system/moat.service
systemctl daemon-reload

# Create directories
mkdir -p /var/log/moat /var/run/moat /var/lib/moat

# Enable and start service
systemctl enable moat
systemctl start moat

# Check status
systemctl status moat
