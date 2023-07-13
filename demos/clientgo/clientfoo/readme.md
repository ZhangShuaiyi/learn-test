## build
```
CGO_ENABLED=0 go build
docker build -t localhost:5000/local/clientfoo:v1 .
docker push localhost:5000/local/clientfoo:v1
```