# Synapse BPF Firewall - Quick Start


### Terminal 1: Start Docker
```bash
docker-compose up
```


### Terminal 2: Run Firewall

#### Custom TLS
```bash
# Generate cert
openssl req -x509 -nodes -newkey rsa:2048 \
    -keyout server.key -out server.crt -days 365 \
    -subj "/CN=localhost"

# Build & run
cargo build --release
sudo bash -c 'ulimit -l unlimited && target/release/bpf-firewall \
    --iface lo \
    --tls-addr 0.0.0.0:8443 \
    --tls-mode custom \
    --tls-cert-path server.crt \
    --tls-key-path server.key \
    --upstream http://127.0.0.1:8081'

# Test
curl -vk https://localhost:8443/
```

#### ACME/Let's Encrypt
```bash
# Build & run
cargo build --release
sudo bash -c 'ulimit -l unlimited && target/release/bpf-firewall \
    --iface eth0 \
    --tls-addr 0.0.0.0:443 \
    --tls-mode acme \
    --acme-domains your-domain.com \
    --acme-contacts admin@your-domain.com \
    --redis-url redis://127.0.0.1:6379/0 \
    --redis-prefix synapse:acme \
    --acme-accept-tos \
    --acme-use-prod \
    --upstream http://127.0.0.1:8081'

# Test
curl -v https://your-domain.com/
```

---


