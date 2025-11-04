

## Add the Helm repo

```sh
helm repo add arxignis https://helm.arxignis.com
helm repo update
helm search repo arxignis
# arxignis/moat
# arxignis/moat-stack
```

## Install

```sh
# set your API key
export ARX_KEY="REPLACE_ME"

# pick a chart version (see `helm search repo arxignis` for latest)
export MOAT_STACK_VER="0.1.2"

helm upgrade --install moat-stack arxignis/moat-stack \
  --version "$MOAT_STACK_VER" \
  -n moat --create-namespace \
  --set global.namespaces.moat="moat" \
  --set global.namespaces.operator="moat-system" \
  --set moat.image.repository="ghcr.io/arxignis/moat" \
  --set moat.image.tag="latest" \
  --set moat.moat.server.upstream="http://example.com" \
  --set moat.moat.network.disableXdp=true \
  --set moat.moat.arxignis.apiKey="$ARX_KEY" \
  --set moat.moat.contentScanning.scanExpression='http.request.method eq "POST" or http.request.method eq "PUT"' \
  --set operator.enabled=true \
  --set operator.createNamespace=true \
  --set operator.image.repository="ghcr.io/arxignis/moat-operator" \
  --set operator.image.tag="latest"
```

Wait for rollouts:

```sh
kubectl -n moat rollout status deploy/moat-stack
kubectl -n moat-system rollout status deploy/moat-operator
```

## Configure via `values.yaml`

```yaml
global:
  namespaces:
    moat: moat
    operator: moat-system

moat:
  replicaCount: 1
  image:
    repository: ghcr.io/arxignis/moat
    tag: latest
    pullPolicy: IfNotPresent

  moat:
    server:
      # Where Moat proxies to by default (change to your origin)
      upstream: "http://example.com"
    network:
      # Disable XDP for environments without eBPF/XDP
      disableXdp: true
    arxignis:
      # Prefer to set via --set or Secrets in production
      apiKey: "REPLACE_ME"
    contentScanning:
      # Only scan bodies on POST/PUT in this example
      scanExpression: 'http.request.method eq "POST" or http.request.method eq "PUT"'

operator:
  enabled: true
  createNamespace: true
  image:
    repository: ghcr.io/arxignis/moat-operator
    tag: latest
    pullPolicy: IfNotPresent
  replicaCount: 1
  leaderElect: true
  serviceAccount:
    create: true
    name: ""
  rbac:
    create: true
  resources:
    requests:
      cpu: 5m
      memory: 32Mi
    limits:
      cpu: 200m
      memory: 128Mi
```

Install with:

```sh
helm upgrade --install moat-stack arxignis/moat-stack \
  --version "$MOAT_STACK_VER" \
  -n moat --create-namespace \
  -f values.yaml
```
