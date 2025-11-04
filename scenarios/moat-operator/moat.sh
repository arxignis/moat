#!/usr/bin/env bash
set -eu
[ -n "${BASH_VERSION:-}" ] && set -o pipefail

# ===== settings =====
CLUSTER_NAME="ax"
MOAT_NS="ax"
OP_NS="ax-system"

# hardcoded resource names (created by the umbrella chart)
DP_DEPLOY="moat-stack"     # dataplane Deployment
CM_NAME="moat-stack"       # ConfigMap holding config.yaml
OP_DEPLOY="moat-operator"  # operator Deployment

# public Helm repo + chart version to install
HELM_REPO_NAME="arxignis"
HELM_REPO_URL="https://helm.arxignis.com"
CHART="${HELM_REPO_NAME}/moat-stack"
CHART_VER="0.1.2"

# ===== parse CLI arguments =====
show_help() {
  cat <<EOF
Usage: $0 [OPTIONS]

Options:
  -k, --api-key KEY    ArxIgnis API key (or use MOAT_API_KEY env var)
  -h, --help           Show this help message

Examples:
  $0 --api-key your-api-key-here
  MOAT_API_KEY=your-key $0
  curl -sSL https://raw.githubusercontent.com/arxignis/moat/main/scenarios/moat-operator/moat.sh | bash -s -- --api-key your-key
EOF
  exit 0
}

# Parse arguments
while [ $# -gt 0 ]; do
  case "$1" in
    -k|--api-key)
      if [ -z "${2:-}" ]; then
        echo "Error: --api-key requires a value" >&2
        exit 1
      fi
      MOAT_API_KEY="$2"
      shift 2
      ;;
    -h|--help)
      show_help
      ;;
    *)
      echo "Unknown option: $1" >&2
      echo "Use --help for usage information" >&2
      exit 1
      ;;
  esac
done

# ===== prompt for API key =====
if [ -z "${MOAT_API_KEY:-}" ]; then
  if [ -n "${BASH_VERSION:-}" ]; then
    if [ -t 0 ]; then
      # Bash with terminal: use silent read
      read -rs -p "Enter Arxignis API key: " MOAT_API_KEY; echo
    else
      # Bash without terminal (piped): read without hiding
      printf "Enter Arxignis API key: "
      read MOAT_API_KEY
      echo
    fi
  else
    # POSIX-compatible fallback for sh
    printf "Enter Arxignis API key: "
    if [ -t 0 ]; then
      # Terminal available: hide input
      stty -echo 2>/dev/null || true
      read MOAT_API_KEY
      stty echo 2>/dev/null || true
    else
      # No terminal (piped): read without hiding
      read MOAT_API_KEY
    fi
    echo
  fi
fi
[ -z "${MOAT_API_KEY:-}" ] && echo "API key is required." >&2 && exit 1

as_root() { if [ "$(id -u)" -eq 0 ]; then "$@"; else sudo "$@"; fi; }

echo "[deps] Installing base tools (kind/helm/kubectl/jq/curl/git/tar)..."
export DEBIAN_FRONTEND=noninteractive
as_root apt-get update -qq
as_root apt-get install -yqq ca-certificates curl git jq tar

# kind
if ! command -v kind >/dev/null 2>&1; then
  echo "[deps] Installing kind..."
  as_root curl -sSL "https://kind.sigs.k8s.io/dl/v0.23.0/kind-linux-amd64" -o /usr/local/bin/kind
  as_root chmod +x /usr/local/bin/kind
fi

# helm
if ! command -v helm >/dev/null 2>&1; then
  echo "[deps] Installing Helm..."
  as_root bash -c 'curl -sSL https://raw.githubusercontent.com/helm/helm/main/scripts/get-helm-3 | bash >/dev/null'
fi

# kubectl
if ! command -v kubectl >/dev/null 2>&1; then
  echo "[deps] Installing kubectl..."
  KVER="$(curl -Ls https://dl.k8s.io/release/stable.txt)"
  as_root curl -sSL "https://dl.k8s.io/release/${KVER}/bin/linux/amd64/kubectl" -o /usr/local/bin/kubectl
  as_root chmod +x /usr/local/bin/kubectl
fi

# ===== cluster =====
echo "[kind] Ensuring cluster '${CLUSTER_NAME}'..."
if ! kind get clusters 2>/dev/null | grep -qx "$CLUSTER_NAME"; then
  kind create cluster --name "$CLUSTER_NAME"
fi
kubectl config use-context "kind-${CLUSTER_NAME}" >/dev/null

# ===== helm repo + install =====
echo "[helm] Adding repo '${HELM_REPO_NAME}' and updating index..."
helm repo add "${HELM_REPO_NAME}" "${HELM_REPO_URL}" --force-update >/dev/null
helm repo update >/dev/null

echo "[helm] Installing/Upgrading ${CHART} (version ${CHART_VER})..."
helm upgrade --install moat-stack "$CHART" \
  --version "$CHART_VER" \
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

# ===== wait for rollouts =====
echo "[wait] Waiting for dataplane Deployment/${DP_DEPLOY}..."
kubectl -n "$MOAT_NS" rollout status "deploy/${DP_DEPLOY}"

echo "[wait] Waiting for operator Deployment/${OP_DEPLOY}..."
kubectl -n "$OP_NS" rollout status "deploy/${OP_DEPLOY}"

# ===== helpers =====
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

# extract config.yaml from the known key name
DATA="$(kubectl -n "$NS" get cm "$CM" -o json | jq -r '.data["config.yaml"] // empty')"
if [ -z "$DATA" ]; then
  echo "[error] Key 'config.yaml' missing in ConfigMap '$CM' (ns '$NS')." >&2
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
    kubectl -n "${MOAT_NS}" get pods -w

  Terminal B)
    moat-toggle-config    # flips logging level info<->debug and should trigger a rollout

Handy shortcuts:
  moat-logs              # stream dataplane logs
  moat-pf                # port-forward dataplane 80 -> localhost:8080
EONEXT
