set up kind and load the operator image
```bash
kind create cluster --name moat || true
kubectl config use-context kind-moat
docker pull ghcr.io/arxignis/moat-operator:latest
kind load docker-image ghcr.io/arxignis/moat-operator:latest --name moat

