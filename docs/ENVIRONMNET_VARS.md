```bash
# Application mode
export AX_MODE="proxy"

# Redis configuration
export AX_REDIS_URL="redis://127.0.0.1/0"
export AX_REDIS_PREFIX="ax:synapse"

# Network configuration
export AX_NETWORK_IFACE="eth0"
export AX_NETWORK_IFACES="eth0,eth1"
export AX_NETWORK_DISABLE_XDP="false"

# Gen0Sec configuration
export AX_ARXIGNIS_API_KEY="your-api-key"
export AX_ARXIGNIS_BASE_URL="https://api.gen0sec.com/v1"

# CAPTCHA configuration
export AX_CAPTCHA_SITE_KEY="your-site-key"
export AX_CAPTCHA_SECRET_KEY="your-secret-key"
export AX_CAPTCHA_JWT_SECRET="your-jwt-secret"
export AX_CAPTCHA_PROVIDER="turnstile"
export AX_CAPTCHA_TOKEN_TTL="7200"
export AX_CAPTCHA_CACHE_TTL="300"

# Content scanning
export AX_CONTENT_SCANNING_ENABLED="true"
export AX_CLAMAV_SERVER="localhost:3310"
export AX_CONTENT_MAX_FILE_SIZE="10485760"
export AX_CONTENT_SCAN_CONTENT_TYPES="text/html,application/x-www-form-urlencoded,multipart/form-data"
export AX_CONTENT_SKIP_EXTENSIONS=".jpg,.png,.gif"
export AX_CONTENT_SCAN_EXPRESSION="http.request.method eq \"POST\" or http.request.method eq \"PUT\""

# Daemon mode
export AX_DAEMON_ENABLED="false"
export AX_DAEMON_PID_FILE="/var/run/synapse.pid"
export AX_DAEMON_WORKING_DIRECTORY="/"
export AX_DAEMON_STDOUT="/var/log/synapse/access.log"
export AX_DAEMON_STDERR="/var/log/synapse/error.log"
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

# Gen0Sec log sending configuration
export AX_ARXIGNIS_LOG_SENDING_ENABLED="true"
export AX_ARXIGNIS_INCLUDE_RESPONSE_BODY="true"
export AX_ARXIGNIS_MAX_BODY_SIZE="1048576"
```
