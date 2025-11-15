Create a config for the chart, install it, and make sure the pods run.

```bash
cat <<'EOF' >/tmp/synapse-values.yaml
synapse:
  server:
    upstream: "http://example.com"
  network:
    disableXdp: true
  arxignis:
    apiKey: "INSERT API KEY HERE"
  redis:
    url: ""
  contentScanning:
    scanExpression: 'http.request.method eq "POST" or http.request.method eq "PUT"'
image:
  repository: ghcr.io/gen0sec/synapse
  tag: latest
  pullPolicy: IfNotPresent
EOF

cd ~/workspace/synapse/helm
kubectl delete namespace synapse --ignore-not-found
helm upgrade --install synapse . \
  --namespace synapse \
  --create-namespace \
  -f /tmp/synapse-values.yaml

kubectl -n synapse rollout status deployment/synapse
kubectl -n synapse get pods -o wide
kubectl -n synapse get configmap synapse -o yaml | sed -n '1,40p'
```

