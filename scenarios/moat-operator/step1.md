Start by confirming the tooling the environment prepared.

```bash
source ~/.bashrc
go version
docker --version
kind version
helm version
kubectl version --client 2>/dev/null || echo "kubectl not found"
ls -1 /root/workspace
```
