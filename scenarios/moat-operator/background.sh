#!/bin/bash
set -euo pipefail

echo "[startup] preparing base image"
service docker start >/dev/null 2>&1 || true

apt-get update -qq
apt-get install -yqq curl git jq >/dev/null

GO_VERSION=1.22.6
curl -sSL "https://go.dev/dl/go${GO_VERSION}.linux-amd64.tar.gz" -o /tmp/go.tar.gz
rm -rf /usr/local/go
tar -C /usr/local -xzf /tmp/go.tar.gz
echo 'export PATH=$PATH:/usr/local/go/bin:/root/go/bin' >> /root/.bashrc
export PATH=$PATH:/usr/local/go/bin:/root/go/bin

curl -sSL https://kind.sigs.k8s.io/dl/v0.23.0/kind-linux-amd64 -o /usr/local/bin/kind
chmod +x /usr/local/bin/kind
curl -sSL https://raw.githubusercontent.com/helm/helm/main/scripts/get-helm-3 | bash >/dev/null

if ! command -v kubectl >/dev/null 2>&1; then
  KUBECTL_VERSION="$(curl -Ls https://dl.k8s.io/release/stable.txt)"
  curl -sSL "https://dl.k8s.io/release/${KUBECTL_VERSION}/bin/linux/amd64/kubectl" -o /usr/local/bin/kubectl
  chmod +x /usr/local/bin/kubectl
fi

mkdir -p /root/workspace
cd /root/workspace

if [ ! -d moat ]; then
  git clone --branch controller --single-branch https://github.com/arxignis/moat.git moat >/dev/null
else
  (
    cd moat
    git fetch origin controller >/dev/null
    git checkout controller >/dev/null 2>&1
    git pull --ff-only origin controller >/dev/null
  )
fi

git config --global --add safe.directory /root/workspace/moat

if [ ! -e moat-operator ]; then
  ln -s /root/workspace/moat/moat-operator /root/workspace/moat-operator
fi

cd /root/workspace/moat-operator

# Fix operator manager image
if grep -q 'ghcr.io/example/moat-operator:latest' config/manager.yaml; then
  sed -i 's|ghcr.io/example/moat-operator:latest|moat-operator:local|g' config/manager.yaml
fi

# Add events RBAC
if ! grep -q 'events' config/rbac.yaml; then
  cat <<'RBAC_PATCH' >> config/rbac.yaml
  - apiGroups:
      - ""
    resources:
      - events
    verbs:
      - create
      - patch
      - update
RBAC_PATCH
fi

echo "[startup] environment ready. open the terminal and run step 1."
