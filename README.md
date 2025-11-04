![Arxignis logo](./images/logo.png)

<p align="center">
  <a href="https://github.com/arxignis/moat/blob/main/LICENSE"><img src="https://img.shields.io/badge/License-ELv2-green" alt="License - Elastic 2.0"></a> &nbsp;
  <a href="https://github.com/arxignis/moat/actions?query=branch%3Amain"><img src="https://github.com/arxignis/moat/actions/workflows/release.yaml/badge.svg" alt="CI Build"></a> &nbsp;
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
You can read [here](./docs/STORY.md).

## Overview

Moat is a high-performance reverse proxy and firewall built with Rust, featuring:

- **XDP-based packet filtering** for ultra-low latency protection at kernel level
- **Dynamic access rules** with automatic updates from Arxignis API
- **BPF statistics collection** for packet processing and dropped IP monitoring
- **TCP fingerprinting** for behavioral analysis and threat detection
- **TLS fingerprinting** with JA4 support for client identification
- **JA4+ fingerprinting** with complete suite: JA4H (HTTP headers), JA4T (TCP options), JA4L (latency), JA4S (TLS server), and JA4X (X.509 certificates)
- **Automatic TLS certificate management** with ACME/Let's Encrypt integration
- **Threat intelligence integration** with Arxignis API for real-time protection
- **CAPTCHA protection** with support for hCaptcha, reCAPTCHA, and Cloudflare Turnstile
- **Content scanning** with ClamAV integration for malware detection
- **PROXY protocol support** for preserving client IP addresses through load balancers
- **Health check endpoints** for monitoring and load balancer integration
- **Redis-backed caching** for certificates, threat intelligence, and validation results
- **Domain filtering** with whitelist support
- **Wirefilter expressions** for advanced request filtering
- **Unified event queue** with batched processing for logs, statistics, and events
- **Flexible configuration** via YAML files, command line arguments, or environment variables

## Configuration Methods

Moat supports three configuration methods with the following priority (highest to lowest):

1. **YAML Configuration File** - Comprehensive configuration via `config.yaml`
2. **Command Line Arguments** - Override specific settings via CLI flags
3. **Environment Variables** - Set configuration via `AX_*` prefixed environment variables

Configuration from higher priority sources overrides lower priority sources. For example, a YAML file setting will override the same setting from an environment variable.

## Quick Start

> 🚧 **Important:** This application only runs on Linux.

## Requirements

### System Requirements

- **Linux kernel** 4.18+ (for XDP support)
- **BPF support** - Required for packet filtering
- **Network capabilities** - SYS_ADMIN, BPF, NET_ADMIN for Docker deployments
- **Redis** - For caching and certificate store
- **ClamAV** - For content scanning (optional, when content scanning is enabled)

### Dependencies

- **libbpf** - For eBPF program loading
- **Redis** - Caching backend
- **ClamAV** - Antivirus engine for content scanning

### Ubuntu install
```bash
curl -fSL https://raw.githubusercontent.com/arxignis/moat/refs/heads/main/install.sh | sh
```
✅ Tested with Ubuntu 24.04

### Kubernetes install
```bash
helm repo add arxignis https://helm.arxignis.com
helm install moat-stack
```

[More details here.](./docs/OPERATOR_README.md)

### Killercoda playground
```bash
curl -sSL https://raw.githubusercontent.com/arxignis/moat/main/scenarios/moat-operator/moat.sh | bash -s -- --api-key <YOUR_API_KEY>
```

## Configuration
You have 3 options can configure moat.
- config file
- environment variables
- cli parameters

### Configuration File

[Moat supports configuration via YAML files.](./config_example.yaml)

### Environment Variables

All configuration options can be overridden using environment variables with the `AX_` prefix:

```bash
# Server configuration
export AX_SERVER_UPSTREAM="http://localhost:8080"
export AX_SERVER_HTTP_ADDR="0.0.0.0:80"
export AX_SERVER_TLS_ADDR="0.0.0.0:443"
```
[You can find more here.](./docs/ENVIRONMNET_VARS.md)
## Command Line Options

### Basic Usage

```bash
moat --help
```

### Configuration Options

- `--config <PATH>`, `-c <PATH>` - Path to configuration file (YAML format)

## Features

### Threat Intelligence Integration

Moat integrates with Arxignis API to provide real-time threat intelligence:

- **IP reputation scoring** - Automatic scoring of incoming IP addresses
- **Bot detection** - Advanced bot detection and mitigation
- **Geolocation filtering** - Block or allow traffic based on geographic location
- **Threat context** - Rich context about detected threats
- **Caching** - Redis-backed caching for improved performance
- **Dynamic access rules** - Automatic updates of access rules (allow/block lists) from Arxignis API
- **JA4/JA4+ fingerprinting** - Complete JA4+ suite implementation:
  - **JA4**: TLS client fingerprinting from ClientHello
  - **JA4H**: HTTP header fingerprinting from request headers
  - **JA4T**: TCP fingerprinting from SYN packet options
  - **JA4L**: Latency fingerprinting from packet timing
  - **JA4S**: TLS server fingerprinting from ServerHello
  - **JA4X**: X.509 certificate fingerprinting

### Dynamic Access Rules

Kernel-level IP filtering with automatic updates:

- **Allow/Block lists** - Configure IP addresses, ASNs, and countries for allow/block rules
- **Automatic updates** - Rules are fetched from Arxignis API and updated periodically
- **BPF map integration** - Rules are enforced at kernel level via XDP for maximum performance
- **IPv4 and IPv6 support** - Both IP versions are supported with separate rule sets
- **Recently banned tracking** - Track recently banned IPs for UDP, ICMP, and TCP FIN/RST packets
- **Zero downtime updates** - Rules are updated without interrupting traffic

### Wirefilter Expression Engine

Advanced request filtering with powerful expression language:

- **Flexible expressions** - Use wirefilter expressions for complex filtering rules
- **HTTP field matching** - Filter based on request method, path, headers, and more
- **Content scanning triggers** - Define when to scan content based on request characteristics
- **WAF integration** - Wirefilter expressions are fetched from Arxignis API for centralized management
- **Action support** - Configure actions (allow, block, challenge) based on expression matches

### ⚠️ Degraded Features When Access Logs Disabled

When access log sending is disabled (`AX_ARXIGNIS_LOG_SENDING_ENABLED=false` or `--arxignis-log-sending-enabled=false`), the following features are degraded:

- **Threat Intelligence (Degraded)** - Basic threat intelligence still works for real-time blocking, but detailed threat analysis and historical data collection is limited
- **Anomaly Detection** - Advanced anomaly detection capabilities are not available without access log data
- **Metrics & Analytics** - Comprehensive metrics and analytics are not available without access log aggregation
- **BPF Statistics** - Statistics can still be collected locally but won't be sent to Arxignis API for centralized analysis
- **TCP Fingerprinting** - Fingerprints can still be collected locally but won't be sent to Arxignis API for behavioral analysis

### CAPTCHA Protection

Moat supports multiple CAPTCHA providers for additional security:

- **hCaptcha** - Privacy-focused CAPTCHA service
- **reCAPTCHA** - Google's CAPTCHA service
- **Cloudflare Turnstile** - Privacy-preserving alternative to traditional CAPTCHAs

Features:
- **Token-based validation** - JWT-signed tokens for secure validation
- **Configurable TTL** - Customizable token and cache expiration times
- **Redis caching** - Efficient caching of validation results

### Content Scanning

Moat provides comprehensive content scanning capabilities:

- **ClamAV integration** - Real-time malware detection using ClamAV engine
- **Multipart form scanning** - Scans individual parts of multipart uploads
- **Form data scanning** - Scans URL-encoded form data for malicious content
- **Configurable content types** - Specify which content types to scan
- **File size limits** - Configurable maximum file size for scanning
- **Wirefilter expressions** - Advanced filtering rules for when to scan content
- **Extension filtering** - Skip scanning for specific file extensions

### PROXY Protocol Support

Moat supports [PROXY protocol](./docs/PROXY_PROTOCOL.md) for preserving client information:

- **TCP PROXY protocol** - Preserves original client IP addresses through load balancers
- **Configurable timeout** - Customizable timeout for PROXY protocol parsing
- **Load balancer integration** - Works with HAProxy, AWS ALB, and other load balancers

### Health Check Endpoints

Moat provides comprehensive health monitoring capabilities with a dedicated health check server:

#### Features
- **Separate port** - Health checks run on a dedicated port independent of main proxy traffic
- **Configurable endpoint** - Customizable health check path (default: `/health`)
- **Multiple HTTP methods** - Support for GET, HEAD, and other HTTP methods
- **CIDR filtering** - Restrict health check access to specific IP ranges for security
- **JSON response** - Structured health status with timestamp and service information
- **Environment variable configuration** - Full runtime configuration via environment variables

#### Configuration

**YAML Configuration:**
```yaml
server:
  health_check:
    enabled: true                    # Enable/disable health check server
    endpoint: "/health"              # Health check endpoint path
    port: "0.0.0.0:8080"            # Health check server bind address
    methods: ["GET", "HEAD"]         # Allowed HTTP methods
    allowed_cidrs: []                # CIDR restrictions (empty = allow all)
```

**Environment Variables:**
```bash
AX_SERVER_HEALTH_CHECK_ENABLED=true
AX_SERVER_HEALTH_CHECK_ENDPOINT=/health
AX_SERVER_HEALTH_CHECK_PORT=0.0.0.0:8080
AX_SERVER_HEALTH_CHECK_METHODS=GET,HEAD
AX_SERVER_HEALTH_CHECK_ALLOWED_CIDRS=127.0.0.0/8,::1/128
```

#### Usage Examples

**Basic health check:**
```bash
curl http://localhost:8080/health
```

**Response format:**
```json
{
  "status": "healthy",
  "timestamp": "2024-01-01T12:00:00Z",
  "service": "moat"
}
```

**HEAD request (for load balancers):**
```bash
curl -I http://localhost:8080/health
```

**Restricted access (only localhost):**
```yaml
server:
  health_check:
    allowed_cidrs: ["127.0.0.0/8", "::1/128"]
```

#### Load Balancer Integration

Health checks are designed for seamless integration with load balancers:

- **Kubernetes** - Use for liveness and readiness probes
- **Docker Swarm** - Health check endpoint for service discovery
- **AWS ALB/NLB** - Target group health checks
- **HAProxy** - Backend server health monitoring
- **Nginx** - Upstream health checks

### XDP Packet Filtering

Moat uses eXpress Data Path (XDP) for ultra-low latency packet filtering:

- **Kernel-space filtering** - Packet filtering happens in kernel space for maximum performance
- **BPF programs** - Custom Berkeley Packet Filter programs for advanced filtering
- **Multiple interfaces** - Support for attaching to multiple network interfaces
- **Fallback mode** - Can run without XDP for environments that don't support it

### BPF Statistics and Monitoring

Comprehensive kernel-level statistics collection:

- **Packet counters** - Total packets processed and dropped
- **Access rule statistics** - IPv4/IPv6 banned and recently banned hit counts
- **Dropped IP tracking** - Detailed tracking of dropped IP addresses with drop counts
- **Drop reason classification** - Categorize drops by access rules, UDP, ICMP, or TCP FIN/RST
- **Periodic logging** - Configurable intervals for statistics and event logging
- **Event streaming** - Send statistics to Arxignis API for analysis

### TCP Fingerprinting

Advanced TCP-level fingerprinting capabilities:

- **TCP SYN fingerprinting** - Extract unique fingerprints from TCP SYN packets
- **Connection tracking** - Track TTL, MSS, window size, window scale, and TCP options
- **Pattern analysis** - Identify unique fingerprint patterns and track by IP address
- **Configurable thresholds** - Filter by minimum packet count and connection duration
- **Periodic collection** - Configurable intervals for fingerprint collection and logging
- **Event streaming** - Send fingerprint data to Arxignis API for behavioral analysis

### Event Processing and Batching

Efficient event handling with unified queue:

- **Unified event queue** - Single queue for access logs, BPF statistics, and TCP fingerprints
- **Batch processing** - Events are batched with configurable limits (5000 logs per batch, 5MB size limit)
- **Timeout-based flushing** - Batches are sent every 10 seconds regardless of size
- **Automatic retries** - Failed requests are retried with exponential backoff
- **Memory efficient** - Events are processed in batches to minimize memory overhead
- **Non-blocking** - Event processing happens in background tasks without blocking main proxy

### TLS Management

Comprehensive TLS support with multiple modes:

- **ACME integration** - Automatic certificate management with Let's Encrypt
- **Custom certificates** - Support for your own TLS certificates
- **HTTP-only mode** - Run without TLS for internal networks
- **TLS enforcement** - Force HTTPS with HTTP upgrade responses

## Architecture

### Components

- **XDP Filter** - Kernel-space packet filtering using eBPF
- **HTTP Server** - Handles ACME challenges, HTTP traffic, and health checks
- **TLS Server** - Manages HTTPS connections and certificate handling
- **Reverse Proxy** - Forwards requests to upstream services
- **Threat Intelligence** - Integrates with Arxignis API for real-time threat data
- **Access Rules Engine** - Dynamic IP allow/block lists with periodic updates from Arxignis API
- **BPF Statistics Collector** - Tracks packet processing, drops, and banned IP hits at kernel level
- **TCP Fingerprint Collector** - Extracts and analyzes TCP SYN fingerprints for behavioral analysis
- **Fingerprint Engine** - Complete JA4+ suite:
  - **JA4** TLS fingerprinting from ClientHello
  - **JA4H** HTTP header fingerprinting
  - **JA4T** TCP options fingerprinting
  - **JA4L** Latency measurement framework
  - **JA4S** TLS server response fingerprinting
  - **JA4X** X.509 certificate fingerprinting
- **CAPTCHA Engine** - Validates CAPTCHA responses from multiple providers
- **Content Scanner** - ClamAV integration for malware detection
- **PROXY Protocol Handler** - Preserves client IP addresses through load balancers
- **Event Queue** - Unified batch processing for logs, statistics, and events
- **Redis Cache** - Stores certificates, threat intelligence, CAPTCHA validation results, and content scan results

### Performance

- **Ultra-low latency** - XDP filtering operates in kernel space
- **High throughput** - Rust-based implementation with async I/O
- **Memory efficient** - Minimal memory footprint with efficient caching
- **Scalable** - Supports multiple network interfaces and concurrent connections


## Notes

- The `--upstream` option is always required for request forwarding
- When TLS mode is `disabled`, Moat runs as an HTTP proxy + firewall
- When TLS mode is `custom` or `acme`, Moat runs as an HTTPS proxy + firewall
- `--tls-only` mode enforces TLS requirements: non-SSL requests return 426 Upgrade Required (except ACME challenges)
- For custom TLS mode, both `--tls-cert-path` and `--tls-key-path` are required
- Domain filtering supports exact matches (whitelist)
- When using Docker, ensure the required capabilities (`SYS_ADMIN`, `BPF`, `NET_ADMIN`) are added
- The XDP program attaches to the specified network interface for packet filtering
- BPF statistics and TCP fingerprinting require XDP to be enabled (not available with `--disable-xdp`)
- Access rules are automatically updated from Arxignis API at regular intervals
- BPF statistics track packet processing metrics and dropped IPs at kernel level
- TCP fingerprinting collects SYN packet characteristics for behavioral analysis
- Fingerprinting supports the complete JA4+ suite:
  - JA4 generates fingerprints from TLS ClientHello messages
  - JA4H generates fingerprints from HTTP request headers
  - JA4T generates fingerprints from TCP SYN packet options
  - JA4L measures packet latencies for network distance estimation
  - JA4S generates fingerprints from TLS ServerHello responses
  - JA4X generates fingerprints from X.509 certificates
- CAPTCHA tokens are JWT-signed for security and can be cached for performance
- Threat intelligence data is cached in Redis to minimize API calls
- Multiple network interfaces can be configured for high availability setups
- Content scanning requires a running ClamAV server and is disabled by default
- PROXY protocol support enables proper client IP preservation through load balancers
- Health check endpoints can be configured for monitoring and load balancer integration
- Access logs, statistics, and events are batched and sent to Arxignis API for analysis
- Configuration priority: YAML file > Command line arguments > Environment variables
