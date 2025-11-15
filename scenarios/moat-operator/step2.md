set up kind and load the operator image
```bash
kind create cluster --name synapse || true
kubectl config use-context kind-synapse
docker pull ghcr.io/gen0sec/synapse-operator:latest
kind load docker-image ghcr.io/gen0sec/synapse-operator:latest --name synapse

