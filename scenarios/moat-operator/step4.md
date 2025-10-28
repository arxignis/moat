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
# optional: watch progress, then Ctrl+C once Running
kubectl -n moat-system get pods -w
```

2. Capture the current config hash, then edit the ConfigMap to trigger a reconcile.

```bash
kubectl -n moat describe deployment moat | grep moat.arxignis.com/config-hash

kubectl -n moat get configmap moat -o jsonpath='{.data.config.yaml}' > /tmp/moat-config.yaml
printf '\n# touched %s\n' "$(date --utc)" >> /tmp/moat-config.yaml
kubectl -n moat create configmap moat \
  --from-file=config.yaml=/tmp/moat-config.yaml \
  -o yaml --dry-run=client | kubectl apply -f -
```

3. Verify the rollout and peek at the operator logs (run the log command in another terminal with `--follow`).

```bash
kubectl -n moat rollout status deployment/moat
kubectl -n moat describe deployment moat | grep moat.arxignis.com/config-hash
kubectl -n moat-system logs deployment/moat-operator --tail=20
```
