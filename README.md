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

## Overview

Moat is a high-performance reverse proxy and firewall built with Rust, featuring:

- **XDP-based packet filtering** for ultra-low latency protection
- **Automatic TLS certificate management** with ACME/Let's Encrypt integration
- **Threat intelligence integration** with Arxignis API
- **CAPTCHA protection** with support for hCaptcha, reCAPTCHA, and Cloudflare Turnstile
- **Content scanning** with ClamAV integration for malware detection
- **PROXY protocol support** for preserving client IP addresses
- **Health check endpoints** for monitoring and load balancer integration
- **Redis-backed caching** for certificates, threat intelligence, and CAPTCHA validation
- **Domain filtering** with whitelist support
- **Wirefilter expressions** for advanced request filtering
- **Environment variable configuration** for containerized deployments

## Quick Start

### Docker Build
```bash
docker build -t moat .
```

### Docker Run
```bash
docker run --cap-add=SYS_ADMIN --cap-add=BPF \
--cap-add=NET_ADMIN moat --iface eth0 \
--arxignis-api-key="your-key" --upstream "http://127.0.0.1:8081"
```

### Docker with Health Checks
```bash
# Run with health check configuration via environment variables
docker run --cap-add=SYS_ADMIN --cap-add=BPF --cap-add=NET_ADMIN \
-e AX_SERVER_HEALTH_CHECK_ENABLED=true \
-e AX_SERVER_HEALTH_CHECK_PORT=0.0.0.0:8080 \
-e AX_SERVER_HEALTH_CHECK_ENDPOINT=/health \
-p 8080:8080 \
moat --iface eth0 --arxignis-api-key="your-key" --upstream "http://127.0.0.1:8081"
```

### Docker Compose Example
```yaml
services:
  moat:
    build: .
    cap_add:
      - SYS_ADMIN
      - BPF
      - NET_ADMIN
    ports:
      - "80:80"
      - "443:443"
      - "127.0.0.1:8080:8080"  # Health check port
    environment:
      - AX_SERVER_HEALTH_CHECK_ENABLED=true
      - AX_SERVER_HEALTH_CHECK_PORT=0.0.0.0:8080
      - AX_SERVER_HEALTH_CHECK_ENDPOINT=/health
      - AX_SERVER_HEALTH_CHECK_ALLOWED_CIDRS=127.0.0.0/8,::1/128
    command: ["--iface", "eth0", "--arxignis-api-key", "your-key", "--upstream", "http://backend:8081"]
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:8080/health"]
      interval: 30s
      timeout: 10s
      retries: 3
      start_period: 40s
```

### Kubernetes Deployment Example
```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: moat
spec:
  replicas: 3
  selector:
    matchLabels:
      app: moat
  template:
    metadata:
      labels:
        app: moat
    spec:
      containers:
      - name: moat
        image: moat:latest
        ports:
        - containerPort: 80
          name: http
        - containerPort: 443
          name: https
        - containerPort: 8080
          name: health
        env:
        - name: AX_SERVER_HEALTH_CHECK_ENABLED
          value: "true"
        - name: AX_SERVER_HEALTH_CHECK_PORT
          value: "0.0.0.0:8080"
        - name: AX_SERVER_HEALTH_CHECK_ENDPOINT
          value: "/health"
        - name: AX_ARXIGNIS_API_KEY
          valueFrom:
            secretKeyRef:
              name: moat-secrets
              key: arxignis-api-key
        args:
        - "--iface"
        - "eth0"
        - "--upstream"
        - "http://backend-service:8081"
        livenessProbe:
          httpGet:
            path: /health
            port: 8080
          initialDelaySeconds: 30
          periodSeconds: 10
        readinessProbe:
          httpGet:
            path: /health
            port: 8080
          initialDelaySeconds: 5
          periodSeconds: 5
        securityContext:
          capabilities:
            add:
            - SYS_ADMIN
            - BPF
            - NET_ADMIN
---
apiVersion: v1
kind: Service
metadata:
  name: moat-service
spec:
  selector:
    app: moat
  ports:
  - name: http
    port: 80
    targetPort: 80
  - name: https
    port: 443
    targetPort: 443
  - name: health
    port: 8080
    targetPort: 8080
  type: LoadBalancer
```

### Configuration File

Moat supports configuration via YAML files. Copy `config_example.yaml` to `config.yaml` and customize:

```bash
cp config_example.yaml config.yaml
```

The configuration file supports all features including:
- Server bind addresses and upstream configuration
- PROXY protocol support for load balancer integration
- Health check endpoint configuration
- TLS modes (disabled, custom, ACME)
- ACME certificate management with Let's Encrypt
- Redis caching configuration
- Network interface and XDP settings
- Arxignis API integration
- CAPTCHA protection settings
- Content scanning with ClamAV integration
- Domain filtering rules
- Logging configuration

### Environment Variables

All configuration options can be overridden using environment variables with the `AX_` prefix:

```bash
# Server configuration
export AX_SERVER_UPSTREAM="http://localhost:8080"
export AX_SERVER_HTTP_ADDR="0.0.0.0:80"
export AX_SERVER_TLS_ADDR="0.0.0.0:443"

# TLS configuration
export AX_TLS_MODE="acme"
export AX_TLS_ONLY="false"

# ACME configuration
export AX_ACME_DOMAINS="example.com,www.example.com"
export AX_ACME_CONTACTS="admin@example.com"
export AX_ACME_USE_PROD="true"

# Redis configuration
export AX_REDIS_URL="redis://127.0.0.1/0"
export AX_REDIS_PREFIX="ax:moat"

# Network configuration
export AX_NETWORK_IFACE="eth0"
export AX_NETWORK_DISABLE_XDP="false"

# Arxignis configuration
export AX_ARXIGNIS_API_KEY="your-api-key"
export AX_ARXIGNIS_BASE_URL="https://api.arxignis.com/v1"

# CAPTCHA configuration
export AX_CAPTCHA_SITE_KEY="your-site-key"
export AX_CAPTCHA_SECRET_KEY="your-secret-key"
export AX_CAPTCHA_JWT_SECRET="your-jwt-secret"
export AX_CAPTCHA_PROVIDER="turnstile"

# Domain filtering
export AX_DOMAINS_WHITELIST="trusted.com,secure.example.com"

# Content scanning
export AX_CONTENT_SCANNING_ENABLED="true"
export AX_CLAMAV_SERVER="localhost:3310"
export AX_CONTENT_MAX_FILE_SIZE="10485760"
export AX_CONTENT_SCAN_CONTENT_TYPES="text/html,application/x-www-form-urlencoded,multipart/form-data"
export AX_CONTENT_SKIP_EXTENSIONS=".jpg,.png,.gif"
export AX_CONTENT_SCAN_EXPRESSION="http.request.method eq \"POST\" or http.request.method eq \"PUT\""

# PROXY protocol
export AX_PROXY_PROTOCOL_ENABLED="true"
export AX_PROXY_PROTOCOL_TIMEOUT="1000"

# Logging
export AX_LOGGING_LEVEL="info"
```

## Command Line Options

### Basic Usage

```bash
moat [OPTIONS]
```

### Configuration Options

- `--config <PATH>`, `-c <PATH>` - Path to configuration file (YAML format)

### Required Options

#### Arxignis Integration
- `--arxignis-api-key <KEY>` - API key for Arxignis service

### Network Configuration

#### Interface Configuration
- `--iface <INTERFACE>`, `-i <INTERFACE>` - Network interface to attach XDP program to (default: `eth0`)
- `--ifaces <INTERFACES>` - Multiple network interfaces for XDP attach (comma-separated)
- `--disable-xdp` - Disable XDP packet filtering (run without BPF/XDP)

#### Server Addresses
- `--control-addr <ADDRESS>` - HTTP control-plane bind address (default: `0.0.0.0:8080`)
- `--http-addr <ADDRESS>` - HTTP server bind address for ACME HTTP-01 challenges and regular HTTP traffic (default: `0.0.0.0:80`)
- `--http-bind <ADDRESSES>` - Additional HTTP bind addresses (comma-separated)
- `--tls-addr <ADDRESS>` - HTTPS reverse-proxy bind address (default: `0.0.0.0:443`)
- `--tls-bind <ADDRESSES>` - Additional HTTPS bind addresses (comma-separated)

**Note:** Health check configuration is available via YAML configuration file and environment variables only. See [Health Check Endpoints](#health-check-endpoints) section for details.

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
- `--redis-prefix <PREFIX>` - Namespace prefix for Redis ACME cache entries (default: `ax:moat`)

### Domain Filtering

#### Whitelist Configuration
- `--domain-whitelist <DOMAINS>` - Domain whitelist (exact matches, comma separated or repeated)
  - If specified, only requests to these domains will be allowed

### Arxignis Configuration

- `--arxignis-base-url <URL>` - Base URL for Arxignis API (default: `https://api.arxignis.com/v1`)

### CAPTCHA Configuration

- `--captcha-site-key <KEY>` - CAPTCHA site key for security verification
- `--captcha-secret-key <KEY>` - CAPTCHA secret key for security verification
- `--captcha-jwt-secret <SECRET>` - JWT secret key for CAPTCHA token signing
- `--captcha-provider <PROVIDER>` - CAPTCHA provider: `hcaptcha`, `recaptcha`, `turnstile` (default: `hcaptcha`)
- `--captcha-token-ttl <SECONDS>` - CAPTCHA token TTL in seconds (default: `7200`)
- `--captcha-cache-ttl <SECONDS>` - CAPTCHA validation cache TTL in seconds (default: `300`)

### PROXY Protocol Configuration

- `--proxy-protocol-enabled` - Enable PROXY protocol support for TCP connections
- `--proxy-protocol-timeout <MILLISECONDS>` - PROXY protocol timeout in milliseconds (default: `1000`)

### Logging Configuration

- `--log-level <LEVEL>` - Log level: `error`, `warn`, `info`, `debug`, `trace` (default: `info`)

### Usage Examples

#### Basic HTTP Proxy
```bash
moat --iface eth0 --arxignis-api-key "your-key" --upstream "http://127.0.0.1:8081"
```

#### Custom TLS Proxy
```bash
moat --iface eth0 --tls-mode custom --tls-cert-path /path/to/cert.pem --tls-key-path /path/to/key.pem --upstream "http://127.0.0.1:8081" --arxignis-api-key "your-key"
```

#### ACME TLS Proxy
```bash
moat --iface eth0 --tls-mode acme --acme-domains "example.com,www.example.com" --acme-contacts "admin@example.com" --upstream "http://127.0.0.1:8081" --arxignis-api-key "your-key"
```

#### With Domain Filtering
```bash
moat --iface eth0 --domain-whitelist "trusted.com,secure.example.com" --upstream "http://127.0.0.1:8081" --arxignis-api-key "your-key"
```

#### With CAPTCHA Protection
```bash
moat --iface eth0 --captcha-site-key "your-site-key" --captcha-secret-key "your-secret-key" --captcha-jwt-secret "your-jwt-secret" --captcha-provider "turnstile" --upstream "http://127.0.0.1:8081" --arxignis-api-key "your-key"
```

#### TLS-Only Mode (HTTP with TLS enforcement)
```bash
moat --iface eth0 --tls-only --upstream "http://127.0.0.1:8081" --arxignis-api-key "your-key"
```

#### Multiple Network Interfaces
```bash
moat --ifaces "eth0,eth1" --upstream "http://127.0.0.1:8081" --arxignis-api-key "your-key"
```

#### Disable XDP (Software-only Mode)
```bash
moat --disable-xdp --upstream "http://127.0.0.1:8081" --arxignis-api-key "your-key"
```

#### With Content Scanning
```bash
moat --iface eth0 --upstream "http://127.0.0.1:8081" --arxignis-api-key "your-key" --config config.yaml
```

#### With PROXY Protocol Support
```bash
moat --iface eth0 --proxy-protocol-enabled --proxy-protocol-timeout 2000 --upstream "http://127.0.0.1:8081" --arxignis-api-key "your-key"
```

#### Using Configuration File
```bash
moat --config /path/to/config.yaml
```

## Features

### Threat Intelligence Integration

Moat integrates with Arxignis API to provide real-time threat intelligence:

- **IP reputation scoring** - Automatic scoring of incoming IP addresses
- **Bot detection** - Advanced bot detection and mitigation
- **Geolocation filtering** - Block or allow traffic based on geographic location
- **Threat context** - Rich context about detected threats
- **Caching** - Redis-backed caching for improved performance
- **JA4+** - SSL and TCP fingerpriting

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

Moat supports PROXY protocol for preserving client information:

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
- **CAPTCHA Engine** - Validates CAPTCHA responses from multiple providers
- **Content Scanner** - ClamAV integration for malware detection
- **PROXY Protocol Handler** - Preserves client IP addresses through load balancers
- **Redis Cache** - Stores certificates, threat intelligence, CAPTCHA validation results, and content scan results

### Performance

- **Ultra-low latency** - XDP filtering operates in kernel space
- **High throughput** - Rust-based implementation with async I/O
- **Memory efficient** - Minimal memory footprint with efficient caching
- **Scalable** - Supports multiple network interfaces and concurrent connections

## Requirements

### System Requirements

- **Linux kernel** 4.18+ (for XDP support)
- **BPF support** - Required for packet filtering
- **Network capabilities** - SYS_ADMIN, BPF, NET_ADMIN for Docker deployments
- **Redis** - For caching and certificate store
- **ClamAV** - For content scanning (optional, when content scanning is enabled)

### Dependencies

- **libbpf** - For eBPF program loading
- **Tokio** - Async runtime
- **Hyper** - HTTP server implementation
- **Rustls** - TLS implementation
- **Redis** - Caching backend
- **ClamAV** - Antivirus engine for content scanning

## Notes

- The `--upstream` option is always required for request forwarding
- When TLS mode is `disabled`, Moat runs as an HTTP proxy + firewall
- When TLS mode is `custom` or `acme`, Moat runs as an HTTPS proxy + firewall
- `--tls-only` mode enforces TLS requirements: non-SSL requests return 426 Upgrade Required (except ACME challenges)
- For custom TLS mode, both `--tls-cert-path` and `--tls-key-path` are required
- Domain filtering supports exact matches (whitelist)
- When using Docker, ensure the required capabilities (`SYS_ADMIN`, `BPF`, `NET_ADMIN`) are added
- The XDP program attaches to the specified network interface for packet filtering
- CAPTCHA tokens are JWT-signed for security and can be cached for performance
- Threat intelligence data is cached in Redis to minimize API calls
- Multiple network interfaces can be configured for high availability setups
- Content scanning requires a running ClamAV server and is disabled by default
- PROXY protocol support enables proper client IP preservation through load balancers
- Health check endpoints can be configured for monitoring and load balancer integration
- Configuration files take precedence over command line arguments, which override environment variables
