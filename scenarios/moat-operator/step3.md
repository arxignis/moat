Lay down sane defaults for the chart, install it, and make sure the pods settle.

```bash
cat <<'EOF' >/tmp/moat-values.yaml
moat:
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
  repository: ghcr.io/arxignis/moat
  tag: latest
  pullPolicy: IfNotPresent
EOF

cd ~/workspace/moat/helm
kubectl delete namespace moat --ignore-not-found
helm upgrade --install moat . \
  --namespace moat \
  --create-namespace \
  -f /tmp/moat-values.yaml

kubectl -n moat rollout status deployment/moat
kubectl -n moat get pods -o wide
kubectl -n moat get configmap moat -o yaml | sed -n '1,40p'
```

