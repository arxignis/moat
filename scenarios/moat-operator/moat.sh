#!/usr/bin/env sh
set -eu

# --- fixed variables ---
CLUSTER_NAME="moat"
WORKSPACE_DIR="/root/workspace"
MOAT_REPO="https://github.com/arxignis/moat.git"
MOAT_BRANCH="main"
MOAT_NAMESPACE="moat"
MOAT_OPERATOR_NAMESPACE="moat-system"

MOAT_IMAGE_REPO="ghcr.io/arxignis/moat"
MOAT_IMAGE_TAG="latest"

MOAT_OPERATOR_DIR_NAME="moat-operator"
MOAT_OPERATOR_IMAGE_REMOTE="ghcr.io/arxignis/moat-operator:latest"
MOAT_OPERATOR_IMAGE_LOCAL="moat-operator:local"

GO_VERSION="1.22.6"
KIND_VERSION="v0.23.0"

# --- prompt for API key ---
printf "Enter ArxIgnis API key: "
if command -v stty >/dev/null 2>&1; then
  stty -echo
  # ensure echo is restored on exit/interrupt
  trap 'stty echo 2>/dev/null || true' EXIT INT TERM
fi
IFS= read -r MOAT_API_KEY
# restore echo and print a newline so the prompt looks clean
if command -v stty >/dev/null 2>&1; then
  stty echo 2>/dev/null || true
  trap - EXIT INT TERM
fi
echo
if [ -z "$MOAT_API_KEY" ]; then
  echo "API key is required." >&2
  exit 1
fi

# --- base packages ---
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -yqq ca-certificates curl git jq tar

# --- Go ---
curl -fsSL "https://go.dev/dl/go${GO_VERSION}.linux-amd64.tar.gz" -o /tmp/go.tar.gz
rm -rf /usr/local/go
tar -C /usr/local -xzf /tmp/go.tar.gz
if ! grep -q '/usr/local/go/bin' /root/.bashrc 2>/dev/null; then
  echo 'export PATH=$PATH:/usr/local/go/bin:/root/go/bin' >> /root/.bashrc
fi
export PATH=$PATH:/usr/local/go/bin:/root/go/bin

# --- kind + helm + kubectl ---
curl -fsSL "https://kind.sigs.k8s.io/dl/${KIND_VERSION}/kind-linux-amd64" -o /usr/local/bin/kind
chmod +x /usr/local/bin/kind

curl -fsSL https://raw.githubusercontent.com/helm/helm/main/scripts/get-helm-3 | bash >/dev/null

if ! command -v kubectl >/dev/null 2>&1; then
  KUBECTL_VERSION="$(curl -fsSL https://dl.k8s.io/release/stable.txt)"
  curl -fsSL "https://dl.k8s.io/release/${KUBECTL_VERSION}/bin/linux/amd64/kubectl" -o /usr/local/bin/kubectl
  chmod +x /usr/local/bin/kubectl
fi

# --- workspace + clone (main) ---
mkdir -p "$WORKSPACE_DIR"
cd "$WORKSPACE_DIR"
if [ ! -d moat ]; then
  git clone --branch "$MOAT_BRANCH" --single-branch "$MOAT_REPO" moat
else
  cd moat
  git fetch origin "$MOAT_BRANCH"
  git checkout "$MOAT_BRANCH"
  git pull --ff-only origin "$MOAT_BRANCH"
  cd ..
fi
git config --global --add safe.directory "$WORKSPACE_DIR/moat"
[ -e "$WORKSPACE_DIR/$MOAT_OPERATOR_DIR_NAME" ] || ln -s "$WORKSPACE_DIR/moat/$MOAT_OPERATOR_DIR_NAME" "$WORKSPACE_DIR/$MOAT_OPERATOR_DIR_NAME"

# --- kind cluster ---
if ! kind get clusters 2>/dev/null | grep -q "^${CLUSTER_NAME}\$"; then
  kind create cluster --name "$CLUSTER_NAME"
fi
kubectl config use-context "kind-${CLUSTER_NAME}"

# --- preload operator image (remote -> local tag) ---
docker pull "$MOAT_OPERATOR_IMAGE_REMOTE"
docker tag  "$MOAT_OPERATOR_IMAGE_REMOTE" "$MOAT_OPERATOR_IMAGE_LOCAL"
kind load docker-image "$MOAT_OPERATOR_IMAGE_REMOTE" --name "$CLUSTER_NAME"
kind load docker-image "$MOAT_OPERATOR_IMAGE_LOCAL"  --name "$CLUSTER_NAME"

# --- install Moat via Helm ---
cd "$WORKSPACE_DIR/moat/helm"
cat <<VALUES >/tmp/moat-values.yaml
moat:
  server:
    upstream: "http://example.com"
  network:
    disableXdp: true
  arxignis:
    apiKey: "$MOAT_API_KEY"
  redis:
    url: ""
  contentScanning:
    scanExpression: 'http.request.method eq "POST" or http.request.method eq "PUT"'
image:
  repository: $MOAT_IMAGE_REPO
  tag: $MOAT_IMAGE_TAG
  pullPolicy: IfNotPresent
VALUES

helm upgrade --install moat . \
  --namespace "$MOAT_NAMESPACE" \
  --create-namespace \
  -f /tmp/moat-values.yaml

kubectl -n "$MOAT_NAMESPACE" rollout status deployment/moat
kubectl -n "$MOAT_NAMESPACE" get pods -o wide

# --- deploy operator ---
cd "$WORKSPACE_DIR/$MOAT_OPERATOR_DIR_NAME"
# keep repo's kustomization; just ensure RBAC file exists/overridden
mkdir -p config
cat <<'RBAC' > config/rbac.yaml
apiVersion: v1
kind: ServiceAccount
metadata:
  name: moat-operator
  namespace: moat-system
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: moat-operator
rules:
  - apiGroups: ['']
    resources: ['configmaps']
    verbs: ['get', 'list', 'watch']
  - apiGroups: ['apps']
    resources: ['deployments']
    verbs: ['get', 'list', 'watch', 'patch', 'update']
  - apiGroups: ['']
    resources: ['events']
    verbs: ['create', 'patch', 'update']
  - apiGroups: ['coordination.k8s.io']
    resources: ['leases']
    verbs: ['get', 'list', 'watch', 'create', 'update', 'patch', 'delete']
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: moat-operator
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: moat-operator
subjects:
  - kind: ServiceAccount
    name: moat-operator
    namespace: moat-system
RBAC

kubectl get ns "$MOAT_OPERATOR_NAMESPACE" >/dev/null 2>&1 || kubectl create ns "$MOAT_OPERATOR_NAMESPACE"
kubectl apply -k config

kubectl -n "$MOAT_OPERATOR_NAMESPACE" set resources deploy/moat-operator \
  --requests=cpu=5m,memory=32Mi \
  --limits=cpu=200m,memory=128Mi

kubectl -n "$MOAT_OPERATOR_NAMESPACE" rollout status deployment/moat-operator
kubectl -n "$MOAT_OPERATOR_NAMESPACE" get pods -o wide

# --- install user-driven toggle (info <-> debug) ---
cat >/usr/local/bin/moat-toggle-config <<'TSH'
#!/usr/bin/env sh
set -eu
NS="moat"
TMP="/tmp/moat-config.yaml"
kubectl -n "$NS" get configmap moat -o jsonpath='{.data.config\.yaml}' > "$TMP"
if grep -q 'level: "info"' "$TMP"; then
  sed -i '0,/level: "info"/s//level: "debug"/' "$TMP"
else
  sed -i '0,/level: "debug"/s//level: "info"/' "$TMP"
fi
kubectl -n "$NS" create configmap moat --from-file=config.yaml="$TMP" -o yaml --dry-run=client | kubectl apply -f -
TSH
chmod +x /usr/local/bin/moat-toggle-config

echo
echo "[moat-install] ✅ Install complete."
echo
echo "Demo restart:"
echo "  # Terminal 1 (watch):"
echo "  kubectl -n $MOAT_NAMESPACE get pods -w"
echo
echo "  # Terminal 2 (toggle config):"
echo "  moat-toggle-config"
echo
echo "Run 'moat-toggle-config' repeatedly to flip info↔debug and watch the pod restart each time."
