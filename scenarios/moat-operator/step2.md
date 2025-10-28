Build the Go operator image locally and load it into kind so we can deploy it later.

```bash
cd ~/workspace/moat-operator
go mod tidy
mkdir -p bin
GOOS=linux GOARCH=amd64 go build -o bin/moat-operator .
docker build -t moat-operator:local .

kind create cluster --name moat || true
kubectl config use-context kind-moat
kind load docker-image moat-operator:local --name moat
```
