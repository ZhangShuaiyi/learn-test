IMG ?= localhost:5000/local/clientfoo:v1

.PHONY: all
all: build

.PHONY: build
build: ## Build binary.
	CGO_ENABLED=0 go build -o clientfoo

.PHONY: docker-build
docker-build: build ## Build docker image with the manager.
	docker build -t ${IMG} .

.PHONY: docker-push
docker-push: docker-build ## Push docker image with the manager.
	docker push ${IMG}

