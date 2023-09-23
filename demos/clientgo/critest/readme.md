```
go mod edit -require k8s.io/cri-api@v0.25.7
go mod edit -require github.com/opencontainers/runc@v1.1.4
go mod tidy
```