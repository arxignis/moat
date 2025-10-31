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

# Daemon mode
export AX_DAEMON_ENABLED="false"
export AX_DAEMON_PID_FILE="/var/run/moat.pid"
export AX_DAEMON_WORKING_DIRECTORY="/"
export AX_DAEMON_STDOUT="/var/log/moat.out"
export AX_DAEMON_STDERR="/var/log/moat.err"
export AX_DAEMON_USER="nobody"
export AX_DAEMON_GROUP="daemon"
export AX_DAEMON_CHOWN_PID_FILE="true"

# Logging
export AX_LOGGING_LEVEL="info"

# BPF Statistics configuration
export AX_BPF_STATS_ENABLED="true"
export AX_BPF_STATS_LOG_INTERVAL="60"
export AX_BPF_STATS_ENABLE_DROPPED_IP_EVENTS="true"
export AX_BPF_STATS_DROPPED_IP_EVENTS_INTERVAL="30"

# TCP Fingerprinting configuration
export AX_TCP_FINGERPRINT_ENABLED="true"
export AX_TCP_FINGERPRINT_LOG_INTERVAL="60"
export AX_TCP_FINGERPRINT_ENABLE_FINGERPRINT_EVENTS="true"
export AX_TCP_FINGERPRINT_EVENTS_INTERVAL="30"
export AX_TCP_FINGERPRINT_MIN_PACKET_COUNT="3"
export AX_TCP_FINGERPRINT_MIN_CONNECTION_DURATION="1"

# Arxignis log sending configuration
export AX_ARXIGNIS_LOG_SENDING_ENABLED="true"
export AX_ARXIGNIS_INCLUDE_RESPONSE_BODY="true"
export AX_ARXIGNIS_MAX_BODY_SIZE="1048576"
```
