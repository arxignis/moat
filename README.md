![Gen0Sec logo](./images/logo.svg)

<p align="center">
  <a href="https://github.com/gen0sec/synapse/blob/main/LICENSE"><img src="https://img.shields.io/badge/License-ELv2-green" alt="License - Elastic 2.0"></a> &nbsp;
  <a href="https://github.com/gen0sec/synapse/actions?query=branch%3Amain"><img src="https://github.com/gen0sec/synapse/actions/workflows/release.yaml/badge.svg" alt="CI Build"></a> &nbsp;
  <a href="https://github.com/gen0sec/synapse/releases"><img src="https://img.shields.io/github/release/gen0sec/synapse.svg?label=Release" alt="Release"></a> &nbsp;
  <img alt="GitHub Downloads (all assets, all releases)" src="https://img.shields.io/github/downloads/gen0sec/synapse/total"> &nbsp;
  <a href="https://docs.gen0sec.com/"><img alt="Static Badge" src="https://img.shields.io/badge/arxignis-documentation-page?style=flat&link=https%3A%2F%2Fdocs.gen0sec.com%2F"></a> &nbsp;
  <a href="https://discord.gg/jzsW5Q6s9q"><img src="https://img.shields.io/discord/1377189913849757726?label=Discord" alt="Discord"></a> &nbsp;
  <a href="https://x.com/arxignis"><img src="https://img.shields.io/twitter/follow/arxignis?style=flat" alt="X (formerly Twitter) Follow" /> </a>
</p>

# Community
[![Join us on Discord](https://img.shields.io/badge/Join%20Us%20on-Discord-5865F2?logo=discord&logoColor=white)](https://discord.gg/jzsW5Q6s9q)
[![Substack](https://img.shields.io/badge/Substack-FF6719?logo=substack&logoColor=fff)](https://arxignis.substack.com/)

## Overview

Synapse is a high-performance reverse proxy and firewall built with Rust, featuring:

- **XDP-based packet filtering** for ultra-low latency protection at kernel level
- **Dynamic access rules** with automatic updates from Gen0Sec API
- **BPF statistics collection** for packet processing and dropped IP monitoring
- **TCP fingerprinting** for behavioral analysis and threat detection
- **TLS fingerprinting** with JA4 support for client identification
- **JA4+ fingerprinting** with complete suite: JA4H (HTTP headers), JA4T (TCP options), JA4L (latency), JA4S (TLS server), and JA4X (X.509 certificates)
- **Automatic TLS certificate management** with ACME/Let's Encrypt integration
- **Threat intelligence integration** with Gen0Sec API for real-time protection
- **CAPTCHA protection** with support for hCaptcha, reCAPTCHA, and Cloudflare Turnstile
- **Content scanning** with ClamAV integration for malware detection
<!-- - **PROXY protocol support** for preserving client IP addresses through load balancers -->
- **Health check endpoints** for monitoring and load balancer integration
- **Redis-backed caching** for certificates, threat intelligence, and validation results
- **Domain filtering** with whitelist support
- **Wirefilter expressions** for advanced request filtering
- **Unified event queue** with batched processing for logs, statistics, and events
- **Flexible configuration** via YAML files, command line arguments, or environment variables
- **Advanced upstream routing** with service discovery support (file, Consul, Kubernetes)
- **Hot-reloadable upstreams configuration** for zero-downtime updates

## Modes

Synapse can run in two modes:

### Reverse Proxy Mode (Default)

Synapse runs as a full-featured reverse proxy with HTTP/HTTPS support, forwarding requests to upstream servers while applying access rules and threat intelligence at the kernel level.

**Features:**
- HTTP/HTTPS reverse proxy
- TLS certificate management (ACME or custom)
- Request forwarding to upstream servers
- Access rules enforcement
- Threat intelligence integration
- Content scanning and CAPTCHA protection

**Configuration:**
```yaml
server:
  disable_http_server: false  # Default: HTTP server enabled
  http_addr: "0.0.0.0:80"
  tls_addr: "0.0.0.0:443"
  upstream: "http://localhost:8080"
```

**CLI:**
```bash
synapse --upstream http://localhost:8080 --arxignis-api-key "your-key"
```

### Agent Mode

Synapse runs as a standalone agent focused on access rules enforcement without HTTP/HTTPS proxy functionality. This mode is ideal for network-level protection where you don't need request proxying.

**Features:**
- XDP-based packet filtering at kernel level
- Dynamic access rules with automatic updates from Gen0Sec API
- BPF statistics collection
- TCP fingerprinting
- No HTTP/HTTPS proxy servers (no upstream required)
- Health check server still available (if enabled)

**Configuration:**
```yaml
server:
  disable_http_server: true  # Disable HTTP server, run as agent
```

**CLI:**
```bash
synapse --disable-http-server --arxignis-api-key "your-key"
```

**Environment Variable:**
```bash
export AX_SERVER_DISABLE_HTTP_SERVER=true
```

**Use Cases:**
- Network-level firewall protection without proxying
- Access rules enforcement at the edge
- Kernel-level IP blocking without HTTP overhead
- Integration with existing reverse proxies or load balancers

## Configuration Methods

Synapse supports three configuration methods with the following priority (highest to lowest):

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
curl -fSL https://raw.githubusercontent.com/gen0sec/synapse/refs/heads/main/install.sh | sh
```
✅ Tested with Ubuntu 24.04

### Kubernetes install
```bash
helm repo add arxignis https://helm.gen0sec.com
helm install synapse-stack
```

[More details here.](./docs/OPERATOR_README.md)

### Killercoda playground
```bash
curl -sSL https://raw.githubusercontent.com/gen0sec/synapse/main/scenarios/synapse-operator/synapse.sh | bash -s -- --api-key <YOUR_API_KEY>
```

## Configuration
You have 3 options can configure synapse.
- config file
- environment variables
- cli parameters

### Configuration File

[Synapse supports configuration via YAML files.](./config_example.yaml)

### Environment Variables

All configuration options can be overridden using environment variables with the `AX_` prefix:

```bash
# Server configuration
export AX_SERVER_UPSTREAM="http://localhost:8080"
export AX_SERVER_HTTP_ADDR="0.0.0.0:80"
export AX_SERVER_TLS_ADDR="0.0.0.0:443"
export AX_SERVER_DISABLE_HTTP_SERVER="false"

# TLS configuration
export AX_TLS_MODE="acme"
export AX_TLS_ONLY="false"

# ACME configuration
export AX_ACME_DOMAINS="example.com,www.example.com"
export AX_ACME_CONTACTS="admin@example.com"
export AX_ACME_USE_PROD="true"

# Redis configuration
export AX_REDIS_URL="redis://127.0.0.1/0"
export AX_REDIS_PREFIX="ax:synapse"

# Network configuration
export AX_NETWORK_IFACE="eth0"
export AX_NETWORK_DISABLE_XDP="false"

# Gen0Sec configuration
export AX_ARXIGNIS_API_KEY="your-api-key"
export AX_ARXIGNIS_BASE_URL="https://api.gen0sec.com/v1"
export AX_ARXIGNIS_LOG_SENDING_ENABLED="true"
export AX_ARXIGNIS_INCLUDE_RESPONSE_BODY="true"
export AX_ARXIGNIS_MAX_BODY_SIZE="1048576"

# CAPTCHA configuration
export AX_CAPTCHA_SITE_KEY="your-site-key"
export AX_CAPTCHA_SECRET_KEY="your-secret-key"
export AX_CAPTCHA_JWT_SECRET="your-jwt-secret"
export AX_CAPTCHA_PROVIDER="turnstile"

# Content scanning
export AX_CONTENT_SCANNING_ENABLED="true"
export AX_CLAMAV_SERVER="localhost:3310"
export AX_CONTENT_MAX_FILE_SIZE="10485760"
export AX_CONTENT_SCAN_CONTENT_TYPES="text/html,application/x-www-form-urlencoded,multipart/form-data"
export AX_CONTENT_SKIP_EXTENSIONS=".jpg,.png,.gif"

# Domain filtering
export AX_DOMAINS_WHITELIST="trusted.com,secure.example.com"

# Health check configuration
export AX_SERVER_HEALTH_CHECK_ENABLED="true"
export AX_SERVER_HEALTH_CHECK_ENDPOINT="/health"
export AX_SERVER_HEALTH_CHECK_PORT="0.0.0.0:8080"
export AX_SERVER_HEALTH_CHECK_METHODS="GET,HEAD"
export AX_SERVER_HEALTH_CHECK_ALLOWED_CIDRS="127.0.0.0/8,::1/128"

# BPF Statistics
export AX_BPF_STATS_ENABLED="true"
export AX_BPF_STATS_LOG_INTERVAL="60"
export AX_BPF_STATS_ENABLE_DROPPED_IP_EVENTS="true"
export AX_BPF_STATS_DROPPED_IP_EVENTS_INTERVAL="30"

# TCP Fingerprinting
export AX_TCP_FINGERPRINT_ENABLED="true"
export AX_TCP_FINGERPRINT_LOG_INTERVAL="60"
export AX_TCP_FINGERPRINT_ENABLE_FINGERPRINT_EVENTS="true"
export AX_TCP_FINGERPRINT_EVENTS_INTERVAL="30"
export AX_TCP_FINGERPRINT_MIN_PACKET_COUNT="3"
export AX_TCP_FINGERPRINT_MIN_CONNECTION_DURATION="1"

# Daemon mode
export AX_DAEMON_ENABLED="false"
export AX_DAEMON_PID_FILE="/var/run/synapse.pid"
export AX_DAEMON_WORKING_DIRECTORY="/"
export AX_DAEMON_STDOUT="/var/log/synapse/access.log"
export AX_DAEMON_STDERR="/var/log/synapse/error.log"

# Logging
export AX_LOGGING_LEVEL="info"
```

For a complete list of all available environment variables, see [ENVIRONMNET_VARS.md](./docs/ENVIRONMNET_VARS.md).

### Upstreams Configuration

Synapse supports advanced upstream routing via a separate upstreams configuration file. This file supports hot-reloading - changes are applied immediately without restarting the service.

**Features:**
- **Multiple service discovery providers** - File-based, Consul, and Kubernetes service discovery
- **Global configuration** - Sticky sessions, rate limits, and headers applied globally
- **Gen0Sec paths** - Global paths that work across all hostnames (evaluated before hostname-specific routing)
- **Per-path configuration** - Rate limits, headers, and HTTPS redirects per path
- **Hot-reloading** - Configuration changes apply immediately without service restart

**Configuration File:**

The upstreams configuration file is specified in the main config file or via the Pingora configuration section. See [UPSTREAMS_CONFIG.md](./UPSTREAMS_CONFIG.md) for complete documentation.

**Basic Example (File Provider):**

```yaml
provider: "file"
config:
  https_proxy_enabled: false
  sticky_sessions: true
  global_rate_limit: 100
  global_headers:
    - "Access-Control-Allow-Origin:*"
    - "X-Proxy-From:Synapse"

arxignis_paths:
  "/cgi-bin/captcha/verify":
    rate_limit: 200
    servers:
      - "127.0.0.1:3001"

upstreams:
  example.com:
    certificate: "example.com"
    paths:
      "/":
        rate_limit: 200
        servers:
          - "127.0.0.1:8000"
          - "127.0.0.1:8001"
```

**Kubernetes Service Discovery:**

```yaml
provider: "kubernetes"
config:
  sticky_sessions: true
  global_rate_limit: 300

kubernetes:
  servers:
    - "https://k8s-api.example.com:6443"
  tokenpath: "/var/run/secrets/kubernetes.io/serviceaccount/token"
  services:
    - upstream: "http://my-service.default.svc.cluster.local:8080"
      hostname: "api.example.com"
      path: "/"
      rate_limit: 500
```

**Consul Service Discovery:**

```yaml
provider: "consul"
config:
  sticky_sessions: true
  global_rate_limit: 200

consul:
  servers:
    - "consul1.example.com:8500"
    - "consul2.example.com:8500"
  token: "your-consul-token"
  services:
    - upstream: "http://service-name.service.consul:8080"
      hostname: "api.example.com"
      path: "/"
      rate_limit: 500
```

**Example Files:**
- [upstreams_example.yaml](./upstreams_example.yaml) - File provider with all options
- [upstreams_example_kubernetes.yaml](./upstreams_example_kubernetes.yaml) - Kubernetes service discovery
- [upstreams_example_consul.yaml](./upstreams_example_consul.yaml) - Consul service discovery

## Command Line Options

### Basic Usage

```bash
synapse --help
```

### Configuration Options

- `--config <PATH>`, `-c <PATH>` - Path to configuration file (YAML format)

## Features

### Threat Intelligence Integration

Synapse integrates with Gen0Sec API to provide real-time threat intelligence:

- **IP reputation scoring** - Automatic scoring of incoming IP addresses
- **Bot detection** - Advanced bot detection and mitigation
- **Geolocation filtering** - Block or allow traffic based on geographic location
- **Threat context** - Rich context about detected threats
- **Caching** - Redis-backed caching for improved performance
- **Dynamic access rules** - Automatic updates of access rules (allow/block lists) from Gen0Sec API
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
- **Automatic updates** - Rules are fetched from Gen0Sec API and updated periodically
- **BPF map integration** - Rules are enforced at kernel level via XDP for maximum performance
- **IPv4 and IPv6 support** - Both IP versions are supported with separate rule sets
- **Recently banned tracking** - Track recently banned IPs for UDP, ICMP, and TCP FIN/RST packets
- **Zero downtime updates** - Rules are updated without interrupting traffic

### Wirefilter Expression Engine

Advanced request filtering with powerful expression language:

- **Flexible expressions** - Use wirefilter expressions for complex filtering rules
- **HTTP field matching** - Filter based on request method, path, headers, and more
- **Content scanning triggers** - Define when to scan content based on request characteristics
- **WAF integration** - Wirefilter expressions are fetched from Gen0Sec API for centralized management
- **Action support** - Configure actions (allow, block, challenge) based on expression matches

### ⚠️ Degraded Features When Access Logs Disabled

When access log sending is disabled (`AX_ARXIGNIS_LOG_SENDING_ENABLED=false` or `--arxignis-log-sending-enabled=false`), the following features are degraded:

- **Threat Intelligence (Degraded)** - Basic threat intelligence still works for real-time blocking, but detailed threat analysis and historical data collection is limited
- **Anomaly Detection** - Advanced anomaly detection capabilities are not available without access log data
- **Metrics & Analytics** - Comprehensive metrics and analytics are not available without access log aggregation
- **BPF Statistics** - Statistics can still be collected locally but won't be sent to Gen0Sec API for centralized analysis
- **TCP Fingerprinting** - Fingerprints can still be collected locally but won't be sent to Gen0Sec API for behavioral analysis

### CAPTCHA Protection

Synapse supports multiple CAPTCHA providers for additional security:

- **hCaptcha** - Privacy-focused CAPTCHA service
- **reCAPTCHA** - Google's CAPTCHA service
- **Cloudflare Turnstile** - Privacy-preserving alternative to traditional CAPTCHAs

Features:
- **Token-based validation** - JWT-signed tokens for secure validation
- **Configurable TTL** - Customizable token and cache expiration times
- **Redis caching** - Efficient caching of validation results

### Content Scanning

Synapse provides comprehensive content scanning capabilities:

- **ClamAV integration** - Real-time malware detection using ClamAV engine
- **Multipart form scanning** - Scans individual parts of multipart uploads
- **Form data scanning** - Scans URL-encoded form data for malicious content
- **Configurable content types** - Specify which content types to scan
- **File size limits** - Configurable maximum file size for scanning
- **Wirefilter expressions** - Advanced filtering rules for when to scan content
- **Extension filtering** - Skip scanning for specific file extensions

### PROXY Protocol Support

Synapse supports [PROXY protocol](./docs/PROXY_PROTOCOL.md) for preserving client information:

- **TCP PROXY protocol** - Preserves original client IP addresses through load balancers
- **Configurable timeout** - Customizable timeout for PROXY protocol parsing
- **Load balancer integration** - Works with HAProxy, AWS ALB, and other load balancers

### Health Check Endpoints

Synapse provides comprehensive health monitoring capabilities with a dedicated health check server:

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
  "service": "synapse"
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

Synapse uses eXpress Data Path (XDP) for ultra-low latency packet filtering:

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
- **Event streaming** - Send statistics to Gen0Sec API for analysis

### TCP Fingerprinting

Advanced TCP-level fingerprinting capabilities:

- **TCP SYN fingerprinting** - Extract unique fingerprints from TCP SYN packets
- **Connection tracking** - Track TTL, MSS, window size, window scale, and TCP options
- **Pattern analysis** - Identify unique fingerprint patterns and track by IP address
- **Configurable thresholds** - Filter by minimum packet count and connection duration
- **Periodic collection** - Configurable intervals for fingerprint collection and logging
- **Event streaming** - Send fingerprint data to Gen0Sec API for behavioral analysis

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
- **Upstreams Manager** - Advanced routing with service discovery and hot-reloading
- **Threat Intelligence** - Integrates with Gen0Sec API for real-time threat data
- **Access Rules Engine** - Dynamic IP allow/block lists with periodic updates from Gen0Sec API
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
<!-- - **PROXY Protocol Handler** - Preserves client IP addresses through load balancers -->
- **Event Queue** - Unified batch processing for logs, statistics, and events
- **Redis Cache** - Stores certificates, threat intelligence, CAPTCHA validation results, and content scan results

### Performance

- **Ultra-low latency** - XDP filtering operates in kernel space
- **High throughput** - Rust-based implementation with async I/O
- **Memory efficient** - Minimal memory footprint with efficient caching
- **Scalable** - Supports multiple network interfaces and concurrent connections


## Notes

- The `--upstream` option is always required for request forwarding
- When TLS mode is `disabled`, Synapse runs as an HTTP proxy + firewall
- When TLS mode is `custom` or `acme`, Synapse runs as an HTTPS proxy + firewall
- `--tls-only` mode enforces TLS requirements: non-SSL requests return 426 Upgrade Required (except ACME challenges)
- For custom TLS mode, both `--tls-cert-path` and `--tls-key-path` are required
- Domain filtering supports exact matches (whitelist)
- When using Docker, ensure the required capabilities (`SYS_ADMIN`, `BPF`, `NET_ADMIN`) are added
- The XDP program attaches to the specified network interface for packet filtering
- BPF statistics and TCP fingerprinting require XDP to be enabled (not available with `--disable-xdp`)
- Access rules are automatically updated from Gen0Sec API at regular intervals
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
- Access logs, statistics, and events are batched and sent to Gen0Sec API for analysis
- Configuration priority: YAML file > Command line arguments > Environment variables
- Upstreams configuration supports hot-reloading - changes apply immediately without restart
- Service discovery providers: file (static), Consul, and Kubernetes
- Gen0Sec paths are global paths that work across all hostnames and are evaluated before hostname-specific routing

## Thank you!
[Cloudflare](https://github.com/cloudflare) for Pingora and Wirefilter
[Aralaz](https://github.com/sadoyan/aralez) for Aralez
