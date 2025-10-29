1. Lay down fresh RBAC, deploy the operator, and trim its resource requests so it schedules on kind.

```bash
cd ~/workspace/moat-operator
cat <<'EOF' > config/rbac.yaml
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
EOF
kubectl apply -k config
kubectl -n moat-system set resources deploy/moat-operator \
  --requests=cpu=5m,memory=32Mi \
  --limits=cpu=200m,memory=128Mi
kubectl -n moat-system rollout status deployment/moat-operator
kubectl -n moat-system get pods
```

2. Change the configmap to another valid config.

```bash
cd ~/workspace/moat/helm
helm template moat . \
  --namespace moat \
  --show-only templates/configmap.yaml \
  -f /tmp/moat-values.yaml \
  | kubectl apply -f -

kubectl -n moat describe deployment moat | grep moat.arxignis.com/config-hash

kubectl -n moat get configmap moat -o jsonpath='{.data.config\.yaml}' > /tmp/moat-config.yaml
if grep -q 'level: "info"' /tmp/moat-config.yaml; then
  sed -i '0,/level: "info"/s//level: "debug"/' /tmp/moat-config.yaml
else
  sed -i '0,/level: "debug"/s//level: "info"/' /tmp/moat-config.yaml
fi
printf '\n# touched %s\n' "$(date --utc +'%Y-%m-%dT%H:%M:%SZ')" >> /tmp/moat-config.yaml
kubectl -n moat create configmap moat \
  --from-file=config.yaml=/tmp/moat-config.yaml \
  -o yaml --dry-run=client | kubectl apply -f -
kubectl -n moat get pods -o wide
```

