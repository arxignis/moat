install the tooling 
```bash
# Base packages
apt-get update -qq
apt-get install -yqq curl git jq

# Go 1.22.6
GO_VERSION=1.22.6
curl -sSL "https://go.dev/dl/go${GO_VERSION}.linux-amd64.tar.gz" -o /tmp/go.tar.gz
rm -rf /usr/local/go
tar -C /usr/local -xzf /tmp/go.tar.gz
echo 'export PATH=$PATH:/usr/local/go/bin:/root/go/bin' >> ~/.bashrc
export PATH=$PATH:/usr/local/go/bin:/root/go/bin

# kind + Helm + kubectl 
curl -sSL https://kind.sigs.k8s.io/dl/v0.23.0/kind-linux-amd64 -o /usr/local/bin/kind
chmod +x /usr/local/bin/kind
curl -sSL https://raw.githubusercontent.com/helm/helm/main/scripts/get-helm-3 | bash >/dev/null
if ! command -v kubectl >/dev/null 2>&1; then
  KUBECTL_VERSION="$(curl -Ls https://dl.k8s.io/release/stable.txt)"
  curl -sSL "https://dl.k8s.io/release/${KUBECTL_VERSION}/bin/linux/amd64/kubectl" -o /usr/local/bin/kubectl
  chmod +x /usr/local/bin/kubectl
fi

# Workspace checkout
mkdir -p /root/workspace
cd /root/workspace
if [ ! -d moat ]; then
  git clone --branch controller --single-branch https://github.com/arxignis/moat.git moat
else
  cd moat
  git fetch origin controller
  git checkout controller
  git pull --ff-only origin controller
  cd ..
fi
git config --global --add safe.directory /root/workspace/moat
[ -e /root/workspace/moat-operator ] || ln -s /root/workspace/moat/moat-operator /root/workspace/moat-operator

```
