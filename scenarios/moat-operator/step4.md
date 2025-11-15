1. Lay down fresh RBAC, deploy the operator, and trim its resource requests so it schedules on kind.

```bash
cd ~/workspace/synapse-operator
cat <<'EOF' > config/rbac.yaml
apiVersion: v1
kind: ServiceAccount
metadata:
  name: synapse-operator
  namespace: synapse-system
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: synapse-operator
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
  name: synapse-operator
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: synapse-operator
subjects:
  - kind: ServiceAccount
    name: synapse-operator
    namespace: synapse-system
EOF
kubectl apply -k config
kubectl -n synapse-system set resources deploy/synapse-operator \
  --requests=cpu=5m,memory=32Mi \
  --limits=cpu=200m,memory=128Mi
kubectl -n synapse-system rollout status deployment/synapse-operator
kubectl -n synapse-system get pods
```

2. Change the configmap to another valid config.

```bash
cd ~/workspace/synapse/helm
helm template synapse . \
  --namespace synapse \
  --show-only templates/configmap.yaml \
  -f /tmp/synapse-values.yaml \
  | kubectl apply -f -

kubectl -n synapse describe deployment synapse | grep synapse.gen0sec.com/config-hash

kubectl -n synapse get configmap synapse -o jsonpath='{.data.config\.yaml}' > /tmp/synapse-config.yaml
if grep -q 'level: "info"' /tmp/synapse-config.yaml; then
  sed -i '0,/level: "info"/s//level: "debug"/' /tmp/synapse-config.yaml
else
  sed -i '0,/level: "debug"/s//level: "info"/' /tmp/synapse-config.yaml
fi
printf '\n# touched %s\n' "$(date --utc +'%Y-%m-%dT%H:%M:%SZ')" >> /tmp/synapse-config.yaml
kubectl -n synapse create configmap synapse \
  --from-file=config.yaml=/tmp/synapse-config.yaml \
  -o yaml --dry-run=client | kubectl apply -f -
kubectl -n synapse get pods -o wide
```

