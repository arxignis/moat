#!/usr/bin/env bash
set -euo pipefail

# --- settings---
CLUSTER_NAME="moat"
WORKSPACE_DIR="/root/workspace"
REPO_URL="https://github.com/arxignis/moat.git"
REPO_BRANCH="killercoda"

MOAT_NS="moat"
OP_NS="moat-system"
CHART_STACK_DIR="$WORKSPACE_DIR/moat/helm/moat-controller"

# resources created by the umbrella chart
DP_DEPLOY="moat-stack"     # Moat dataplane Deployment
CM_NAME="moat-stack"       # Moat ConfigMap holding config.yaml
OP_DEPLOY="moat-operator"  # Operator Deployment

# --- prompt for API key ---
read -rs -p "Enter ArxIgnis API key: " MOAT_API_KEY; echo
[ -z "${MOAT_API_KEY:-}" ] && echo "API key is required." >&2 && exit 1

as_root() { if [ "$(id -u)" -eq 0 ]; then "$@"; else sudo "$@"; fi; }

echo "[deps] Installing base tools (kind/helm/kubectl/jq)..."
as_root apt-get update -qq
as_root apt-get install -yqq ca-certificates curl git jq tar

if ! command -v kind >/dev/null 2>&1; then
  as_root curl -sSL "https://kind.sigs.k8s.io/dl/v0.23.0/kind-linux-amd64" -o /usr/local/bin/kind
  as_root chmod +x /usr/local/bin/kind
fi
if ! command -v helm >/dev/null 2>&1; then
  as_root bash -c 'curl -sSL https://raw.githubusercontent.com/helm/helm/main/scripts/get-helm-3 | bash >/dev/null'
fi
if ! command -v kubectl >/dev/null 2>&1; then
  KVER="$(curl -Ls https://dl.k8s.io/release/stable.txt)"
  as_root curl -sSL "https://dl.k8s.io/release/${KVER}/bin/linux/amd64/kubectl" -o /usr/local/bin/kubectl
  as_root chmod +x /usr/local/bin/kubectl
fi

echo "[git] Cloning arxignis/moat @ ${REPO_BRANCH}..."
mkdir -p "$WORKSPACE_DIR" && cd "$WORKSPACE_DIR"
if [ -d moat ]; then
  cd moat && git fetch origin "$REPO_BRANCH" && git checkout "$REPO_BRANCH" && git pull --ff-only origin "$REPO_BRANCH"
else
  git clone --branch "$REPO_BRANCH" --single-branch "$REPO_URL" moat && cd moat
fi
git config --global --add safe.directory "$WORKSPACE_DIR/moat"

echo "[kind] Ensuring cluster '${CLUSTER_NAME}'..."
if ! kind get clusters 2>/dev/null | grep -qx "$CLUSTER_NAME"; then
  kind create cluster --name "$CLUSTER_NAME"
fi
kubectl config use-context "kind-${CLUSTER_NAME}" >/dev/null

# --- install umbrella chart ---
[ -f "$CHART_STACK_DIR/Chart.yaml" ] || { echo "[err] Missing chart at: $CHART_STACK_DIR" >&2; exit 1; }

echo "[helm] Building chart dependencies..."
helm dependency build "$CHART_STACK_DIR" >/dev/null

echo "[helm] Installing/Upgrading release 'moat-stack'..."
helm upgrade --install moat-stack "$CHART_STACK_DIR" \
  -n "$MOAT_NS" --create-namespace \
  --set global.namespaces.moat="$MOAT_NS" \
  --set global.namespaces.operator="$OP_NS" \
  --set moat.image.repository="ghcr.io/arxignis/moat" \
  --set moat.image.tag="latest" \
  --set moat.moat.server.upstream="http://example.com" \
  --set moat.moat.network.disableXdp=true \
  --set moat.moat.arxignis.apiKey="$MOAT_API_KEY" \
  --set moat.moat.contentScanning.scanExpression='http.request.method eq "POST" or http.request.method eq "PUT"' \
  --set operator.enabled=true \
  --set operator.createNamespace=true \
  --set operator.image.repository="ghcr.io/arxignis/moat-operator" \
  --set operator.image.tag="latest"

echo "[wait] Waiting for dataplane Deployment/${DP_DEPLOY}..."
kubectl -n "$MOAT_NS" rollout status "deploy/${DP_DEPLOY}"

echo "[wait] Waiting for operator Deployment/${OP_DEPLOY}..."
kubectl -n "$OP_NS" rollout status "deploy/${OP_DEPLOY}"

# --- helpers (hardcoded names, no discovery) ---
echo "[helpers] Installing helper commands..."

# stream dataplane logs
as_root bash -c "cat >/usr/local/bin/moat-logs" <<'H1'
#!/usr/bin/env bash
set -euo pipefail
kubectl -n moat logs deploy/moat-stack -f --tail=200
H1
as_root chmod +x /usr/local/bin/moat-logs

# port-forward dataplane 80 -> localhost:8080
as_root bash -c "cat >/usr/local/bin/moat-pf" <<'H2'
#!/usr/bin/env bash
set -euo pipefail
kubectl -n moat port-forward deploy/moat-stack 8080:80
H2
as_root chmod +x /usr/local/bin/moat-pf

# toggle logging level info<->debug inside the umbrella ConfigMap and apply it back
as_root bash -c "cat >/usr/local/bin/moat-toggle-config" <<'H3'
#!/usr/bin/env bash
set -euo pipefail
NS="moat"
CM="moat-stack"
TMP="$(mktemp)"

# extract config.yaml from the known key name (contains a dot)
DATA="$(kubectl -n "$NS" get cm "$CM" -o json | jq -r '.data["config.yaml"] // empty')"
if [ -z "$DATA" ]; then
  echo "[error] Key 'config.yaml' missing in ConfigMap '$CM' in ns '$NS'." >&2
  exit 1
fi
printf "%s" "$DATA" > "$TMP"

# flip the logging level (create section if missing)
if grep -q 'level: "info"' "$TMP"; then
  sed -i '0,/level: "info"/s//level: "debug"/' "$TMP"
elif grep -q 'level: "debug"' "$TMP"; then
  sed -i '0,/level: "debug"/s//level: "info"/' "$TMP"
else
  printf "\nlogging:\n  level: \"debug\"\n" >> "$TMP"
fi

# apply back to the SAME ConfigMap name
kubectl -n "$NS" create cm "$CM" --from-file=config.yaml="$TMP" -o yaml --dry-run=client | kubectl apply -f -
rm -f "$TMP"

echo "[toggle] Updated $CM in $NS. In another terminal, run: kubectl -n $NS get pods -w"
H3
as_root chmod +x /usr/local/bin/moat-toggle-config

echo
echo "[moat] ✅ Install complete."

cat <<EONEXT

To WATCH a restart (use two terminals):

  Terminal A)
    kubectl -n ${MOAT_NS} get pods -w

  Terminal B)
    moat-toggle-config    # flips logging level info↔debug and should trigger a rollout

Handy shortcuts:
  moat-logs              # stream dataplane logs
  moat-pf                # port-forward dataplane 80 -> localhost:8080
EONEXT
