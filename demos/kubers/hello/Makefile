IMG ?= localhost:5000/local/hello:v1

.PHONY: all
all: build

.PHONY: build
build: ## Build binary.
	cargo build --target x86_64-unknown-linux-musl --release

.PHONY: docker-build
docker-build: build ## Build docker image with the manager.
	docker build -t ${IMG} .

.PHONY: docker-push
docker-push: docker-build ## Push docker image with the manager.
	docker push ${IMG}