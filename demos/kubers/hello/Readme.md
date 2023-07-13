## build
```
cargo build --target x86_64-unknown-linux-musl --release
docker build -t localhost:5000/local/hello:v1 .
docker push localhost:5000/local/hello:v1
```
