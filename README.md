<div align="center">
  <img height=100 weight=100 src="images/logo.svg" alt="arxgnis logo" />
</div>

<p align="center">
  <a href="https://github.com/arxignis/moat/blob/main/LICENSE"><img src="https://img.shields.io/badge/License-ELv2-green" alt="License - Elastic 2.0"></a> &nbsp;
  <a href="https://github.com/arxignis/moat/actions?query=branch%3Amain"><img src="https://github.com/arxignis/moat/actions/workflows/build.yml/badge.svg" alt="CI Build"></a> &nbsp;
  <a href="https://github.com/arxignis/moat/releases"><img src="https://img.shields.io/github/release/arxignis/moat.svg?label=Release" alt="Release"></a> &nbsp;
  <img alt="GitHub Downloads (all assets, all releases)" src="https://img.shields.io/github/downloads/arxignis/moat/total"> &nbsp;
  <a href="https://docs.arxignis.com/"><img alt="Static Badge" src="https://img.shields.io/badge/arxignis-documentation-page?style=flat&link=https%3A%2F%2Fdocs.arxignis.com%2F"></a> &nbsp;
  <a href="https://discord.gg/jzsW5Q6s9q"><img src="https://img.shields.io/discord/1377189913849757726?label=Discord" alt="Discord"></a> &nbsp;
  <a href="https://x.com/arxignis"><img src="https://img.shields.io/twitter/follow/arxignis?style=flat" alt="X (formerly Twitter) Follow" /> </a>
</p>

# Community
[![Join us on Discord](https://img.shields.io/badge/Join%20Us%20on-Discord-5865F2?logo=discord&logoColor=white)](https://discord.gg/jzsW5Q6s9q)
[![Substack](https://img.shields.io/badge/Substack-FF6719?logo=substack&logoColor=fff)](https://arxignis.substack.com/)

## What is moat ancient story?
You can read [here](./STORY.md).

# Core features
- [x] SSL termination
- [x] ACME support
- [x] Firewall with eBPF
- [x] Threat detection by IP and JA4+ hashes
- [x] WAF by Wirefilter
- [x] Content scanning by ClamAV
- [x] Metrics
- [x] Access Logs

## Alpha features
- Anomaly detection

## Docker build
```
docker build -t moat .
```

## Docker run
```
docker run --cap-add=SYS_ADMIN --cap-add=BPF \
--cap-add=NET_ADMIN moat --iface eth0 \
--arxignis-api-key="" --arxignis-rule-id="" \
--upstream "http://127.0.0.1:8081"
```

## CLI Options

This section describes all available command-line options for the Moat firewall and reverse proxy.

### Basic Usage

```bash
moat [OPTIONS]
```

### Required Options

#### Arxignis Integration
- `--arxignis-api-key <KEY>` - API key for Arxignis service
- `--arxignis-rule-id <ID>` - Rule ID for Arxignis integration

### Network Configuration

#### Interface Configuration
- `--iface <INTERFACE>`, `-i <INTERFACE>` - Network interface to attach XDP program to (default: `eth0`)

#### Server Addresses
- `--control-addr <ADDRESS>` - HTTP control-plane bind address (default: `0.0.0.0:8080`)
- `--http-addr <ADDRESS>` - HTTP server bind address for ACME HTTP-01 challenges and regular HTTP traffic (default: `0.0.0.0:80`)
- `--tls-addr <ADDRESS>` - HTTPS reverse-proxy bind address (default: `0.0.0.0:443`)

### TLS Configuration

#### TLS Mode
- `--tls-mode <MODE>` - TLS operating mode (default: `disabled`)
  - `disabled` - No TLS, HTTP only
  - `custom` - Use custom certificates
  - `acme` - Automatic certificate management with Let's Encrypt
- `--tls-only` - Reject non-SSL requests (except ACME challenges) when TLS mode is disabled

#### Upstream Configuration
- `--upstream <URL>` - Upstream origin URL (always required)
  - Must be absolute URI (e.g., `http://127.0.0.1:8081`)
  - Used for forwarding requests in all TLS modes

#### Custom TLS Certificates
- `--tls-cert-path <PATH>` - Path to custom certificate (PEM) when using custom TLS mode
- `--tls-key-path <PATH>` - Path to custom private key (PEM) when using custom TLS mode

### ACME Configuration (Let's Encrypt)

#### Domain Management
- `--acme-domains <DOMAINS>` - Domains for ACME certificate issuance (comma separated or repeated)
- `--acme-contacts <CONTACTS>` - ACME contact addresses (mailto: optional, comma separated or repeated)

#### ACME Settings
- `--acme-use-prod` - Use Let's Encrypt production directory instead of staging
- `--acme-directory <URL>` - Override ACME directory URL (useful for Pebble or other test CAs)
- `--acme-accept-tos` - Explicitly accept the ACME Terms of Service (default: `false`)
- `--acme-ca-root <PATH>` - Custom CA bundle for the ACME directory (PEM file)

### Redis Configuration

- `--redis-url <URL>` - Redis connection URL for ACME cache storage (default: `redis://127.0.0.1/0`)
- `--redis-prefix <PREFIX>` - Namespace prefix for Redis ACME cache entries (default: `arxignis:acme`)

### Domain Filtering

#### Whitelist Configuration
- `--domain-whitelist <DOMAINS>` - Domain whitelist (exact matches, comma separated or repeated)
  - If specified, only requests to these domains will be allowed

#### Wildcard Patterns
- `--domain-wildcards <PATTERNS>` - Domain wildcard patterns (comma separated or repeated)
  - Supports wildcards: `*.example.com`, `api.*.example.com`
  - If specified along with whitelist, both are checked (OR logic)

### Arxignis Configuration

- `--arxignis-base-url <URL>` - Base URL for Arxignis API (default: `https://api.arxignis.com/v1`)

### Usage Examples

#### Basic HTTP Proxy
```bash
moat --iface eth0 --arxignis-api-key "your-key" --arxignis-rule-id "your-rule-id" --upstream "http://127.0.0.1:8081"
```

#### Custom TLS Proxy
```bash
moat --iface eth0 --tls-mode custom --tls-cert-path /path/to/cert.pem --tls-key-path /path/to/key.pem --upstream "http://127.0.0.1:8081" --arxignis-api-key "your-key" --arxignis-rule-id "your-rule-id"
```

#### ACME TLS Proxy
```bash
moat --iface eth0 --tls-mode acme --acme-domains "example.com,www.example.com" --acme-contacts "admin@example.com" --upstream "http://127.0.0.1:8081" --arxignis-api-key "your-key" --arxignis-rule-id "your-rule-id"
```

#### With Domain Filtering
```bash
moat --iface eth0 --domain-whitelist "trusted.com,secure.example.com" --domain-wildcards "*.api.example.com" --upstream "http://127.0.0.1:8081" --arxignis-api-key "your-key" --arxignis-rule-id "your-rule-id"
```

#### TLS-Only Mode (HTTP with TLS enforcement)
```bash
moat --iface eth0 --tls-only --upstream "http://127.0.0.1:8081" --arxignis-api-key "your-key" --arxignis-rule-id "your-rule-id"
```

### Notes

- The `--upstream` option is always required for request forwarding
- When TLS mode is `disabled`, Moat runs as an HTTP proxy + firewall
- When TLS mode is `custom` or `acme`, Moat runs as an HTTPS proxy + firewall
- `--tls-only` mode enforces TLS requirements: non-SSL requests return 426 Upgrade Required (except ACME challenges)
- For custom TLS mode, both `--tls-cert-path` and `--tls-key-path` are required
- Domain filtering supports both exact matches (whitelist) and wildcard patterns
- When using Docker, ensure the required capabilities (`SYS_ADMIN`, `BPF`, `NET_ADMIN`) are added
- The XDP program attaches to the specified network interface for packet filtering

### License

This repository includes proprietary software components. Our company holds a license for JA4+, which is only available to users with valid Arxignis subscriptions.

[JA4+ License](https://github.com/FoxIO-LLC/ja4/blob/main/LICENSE-JA4)
[JA4+ License FAQ](https://github.com/FoxIO-LLC/ja4/blob/main/License%20FAQ.md)

