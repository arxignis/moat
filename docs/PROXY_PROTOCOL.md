# PROXY Protocol Support

This document describes the PROXY protocol implementation in moat.

## Overview

The PROXY protocol is used when running moat behind a Layer 4 load balancer (like AWS NLB, HAProxy, nginx stream module) to preserve the original client IP address and port information. Without the PROXY protocol, moat would only see the load balancer's IP address, making it impossible to apply proper security policies based on the true client IP.

## Specification

The implementation follows the PROXY protocol specification:
- [HAProxy PROXY Protocol Specification v1 and v2](https://www.haproxy.org/download/1.8/doc/proxy-protocol.txt)

Both PROXY protocol v1 (text-based) and v2 (binary) are supported.

## Features

- **PROXY v1 Support**: Text-based format for IPv4 and IPv6
- **PROXY v2 Support**: Binary format with support for:
  - IPv4 (AF_INET)
  - IPv6 (AF_INET6)
  - LOCAL command (for health checks)
  - PROXY command (for proxied connections)
- **HTTP Forwarded Header**: Automatically adds the `Forwarded` header with the real client IP to upstream requests
- **Transparent Integration**: Works seamlessly with TLS fingerprinting and security features

## Compilation

The PROXY protocol support is behind a feature flag and must be enabled at compile time:

```bash
cargo build --release --features proxy_protocol
```

## Configuration

### Via Config File (config.yaml)

```yaml
server:
  http_addr: "0.0.0.0:80"
  tls_addr: "0.0.0.0:443"
  upstream: "http://localhost:8080"
  enable_proxy_protocol: true  # Enable PROXY protocol
```

### Via Command Line

```bash
./moat --enable-proxy-protocol --upstream http://localhost:8080
```

### Via Environment Variable

```bash
export AX_SERVER_ENABLE_PROXY_PROTOCOL=true
./moat --upstream http://localhost:8080
```

## How It Works

### Connection Flow

1. **Load Balancer** receives connection from client (1.2.3.4:56789)
2. **Load Balancer** establishes connection to moat and sends PROXY protocol header:
   ```
   PROXY TCP4 1.2.3.4 10.0.0.5 56789 443\r\n
   ```
3. **moat** parses the PROXY protocol header, extracts client IP (1.2.3.4)
4. **moat** uses the real client IP for:
   - Security policies and threat intelligence
   - WAF rules and access control
   - Logging and analytics
5. **moat** adds `Forwarded: for=1.2.3.4` header to upstream request
6. **Upstream server** receives request with original client IP information

### PROXY Protocol v1 Format

Text-based format:
```
PROXY TCP4 192.168.1.1 10.0.0.1 56324 443\r\n
```

Or for unknown connections (health checks):
```
PROXY UNKNOWN\r\n
```

### PROXY Protocol v2 Format

Binary format with 16-byte header followed by address information:
```
\x0D\x0A\x0D\x0A\x00\x0D\x0A\x51\x55\x49\x54\x0A  (signature)
[version_cmd] [family_protocol] [length_hi] [length_lo]
[address data...]
```

## Load Balancer Configuration Examples

### AWS Network Load Balancer (NLB)

Enable PROXY protocol v2 on the target group:

```bash
aws elbv2 modify-target-group-attributes \
  --target-group-arn <target-group-arn> \
  --attributes Key=proxy_protocol_v2.enabled,Value=true
```

### HAProxy

```haproxy
frontend https_frontend
    bind *:443
    mode tcp
    default_backend moat_backend

backend moat_backend
    mode tcp
    balance roundrobin
    server moat1 10.0.1.10:443 send-proxy-v2 check
    server moat2 10.0.1.11:443 send-proxy-v2 check
```

### nginx (stream module)

```nginx
stream {
    upstream moat_backend {
        server 10.0.1.10:443;
        server 10.0.1.11:443;
    }

    server {
        listen 443;
        proxy_pass moat_backend;
        proxy_protocol on;
    }
}
```

## Security Considerations

### Important: Trusted Networks Only

**WARNING**: Only enable PROXY protocol when moat is deployed behind a trusted load balancer in a secure network. If PROXY protocol is enabled and moat is directly exposed to the internet, attackers can spoof arbitrary source IP addresses by sending crafted PROXY protocol headers.

### Best Practices

1. **Network Isolation**: Deploy moat in a private network, only accessible from the load balancer
2. **Firewall Rules**: Configure firewall to only allow connections from the load balancer IPs
3. **TLS Termination**: Consider whether TLS should be terminated at the load balancer or at moat
4. **Health Checks**: Use PROXY protocol v2 LOCAL command for health checks

## Troubleshooting

### Error: "Invalid PROXY protocol header"

This occurs when:
- The load balancer is not configured to send PROXY protocol headers
- The load balancer is sending the wrong version (v1 vs v2)
- Non-load-balanced traffic reaches moat with PROXY protocol enabled

**Solution**: Verify load balancer configuration and ensure only proxied traffic reaches moat.

### Client IP Still Shows Load Balancer IP

Check that:
1. PROXY protocol is enabled in moat configuration
2. moat was compiled with `--features proxy_protocol`
3. Load balancer is configured to send PROXY protocol headers
4. Check logs for "PROXY protocol enabled" message on startup

### Health Checks Failing

Some load balancers send health checks without PROXY protocol headers. Use:
- PROXY protocol v2 LOCAL command
- Separate health check endpoint not behind load balancer
- TCP health checks instead of HTTP

## API and Implementation Details

### ProxyProtocolStream

The `ProxyProtocolStream` wrapper reads and parses the PROXY protocol header transparently:

```rust
use moat::http::proxy_protocol::ProxyProtocolStream;

// Wrap a TCP stream
let proxy_stream = ProxyProtocolStream::new(tcp_stream).await?;

// Get real client address
if let Some(info) = proxy_stream.proxy_info() {
    println!("Real client: {}", info.src_addr);
    println!("Proxy address: {}", info.dst_addr);
}

// Use the stream normally (header is already consumed)
// The stream can now be used for TLS, HTTP, etc.
```

### Forwarded Header

When PROXY protocol is enabled and client information is available, moat automatically adds the `Forwarded` HTTP header as specified in [RFC 7239](https://tools.ietf.org/html/rfc7239):

```
Forwarded: for=192.168.1.1
```

This allows upstream applications to access the real client IP address.

## Performance

The PROXY protocol adds minimal overhead:
- **v1**: ~50 bytes text header, simple string parsing
- **v2**: 16-28 bytes binary header (IPv4) or 16-52 bytes (IPv6), fast binary parsing
- **Latency**: < 1ms additional latency for header parsing

## Compatibility

- **PROXY v1**: Compatible with HAProxy, AWS NLB, nginx
- **PROXY v2**: Compatible with HAProxy 1.5+, AWS NLB, nginx 1.13.11+
- **IP Versions**: IPv4 and IPv6 fully supported
- **Protocols**: Works with both HTTP and HTTPS (TLS)

## Example Deployment Architecture

```
┌─────────────┐
│   Client    │
│  1.2.3.4    │
└──────┬──────┘
       │
       │ TCP + TLS
       │
       ▼
┌─────────────────────────┐
│   AWS Network LB        │
│   (PROXY v2 enabled)    │
└─────────┬───────────────┘
          │
          │ PROXY TCP4 1.2.3.4 10.0.0.5 56789 443\r\n
          │ + TLS handshake
          │
          ▼
     ┌────────────────┐
     │  moat instance │
     │  10.0.1.10     │
     │  (proxy proto) │
     └────────┬───────┘
              │
              │ HTTP + Forwarded: for=1.2.3.4
              │
              ▼
        ┌─────────────┐
        │  Upstream   │
        │   Server    │
        └─────────────┘
```

## Testing

To test PROXY protocol locally, you can use HAProxy or send manual PROXY headers:

### Using netcat to send PROXY v1

```bash
# Start moat with proxy protocol
./moat --enable-proxy-protocol --upstream http://localhost:8080 &

# Send PROXY v1 header followed by HTTP request
(echo -ne "PROXY TCP4 1.2.3.4 127.0.0.1 56789 443\r\n"; \
 echo -ne "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n") | \
 nc localhost 443
```

### Using HAProxy locally

```haproxy
# haproxy.cfg
frontend test_fe
    bind *:8443
    mode tcp
    default_backend moat_be

backend moat_be
    mode tcp
    server moat 127.0.0.1:443 send-proxy-v2
```

```bash
haproxy -f haproxy.cfg
curl -k https://localhost:8443/
```

## References

- [HAProxy PROXY Protocol Specification](https://www.haproxy.org/download/1.8/doc/proxy-protocol.txt)
- [RFC 7239 - Forwarded HTTP Header](https://tools.ietf.org/html/rfc7239)
- [AWS NLB PROXY Protocol](https://docs.aws.amazon.com/elasticloadbalancing/latest/network/load-balancer-target-groups.html#proxy-protocol)

