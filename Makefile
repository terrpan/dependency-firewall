.PHONY: help build build-worker push mtls-certs up down restart logs logs-control-plane logs-proxy logs-dependency-graph-worker ps clean status test test-integration test-all test-coverage fmt lint lint-fix lefthook hooks-install vet tidy all

LEFTHOOK_VERSION ?= v1.13.6

help: ## Show this help message
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-22s\033[0m %s\n", $$1, $$2}'

build: ## Build the firewall image using ko and load it into Docker
	@echo "Building firewall with ko..."
	@KO_DOCKER_REPO=ko.local ko build --bare ./cmd/firewall
	@docker tag ko.local:latest dependency-firewall:latest
	@echo "Tagged as dependency-firewall:latest"

build-worker: ## Build the isolated npm dependency graph worker image
	@echo "Building dependency graph worker image..."
	@docker build -f Dockerfile.dependency-graph-worker -t dependency-firewall-graph-worker:latest .

push: ## Push the firewall image using ko
	ko build ./cmd/firewall

mtls-certs: ## Generate local mTLS certificates for split-mode Docker Compose
	@if [ ! -f examples/mtls/certs/ca.pem ] || [ ! -f examples/mtls/certs/control-plane.pem ] || [ ! -f examples/mtls/certs/proxy-a.pem ] || [ ! -f examples/mtls/certs/dependency-graph-worker.pem ] || ! openssl x509 -checkend 0 -noout -in examples/mtls/certs/ca.pem >/dev/null 2>&1 || ! openssl x509 -checkend 0 -noout -in examples/mtls/certs/control-plane.pem >/dev/null 2>&1 || ! openssl x509 -checkend 0 -noout -in examples/mtls/certs/proxy-a.pem >/dev/null 2>&1 || ! openssl x509 -checkend 0 -noout -in examples/mtls/certs/dependency-graph-worker.pem >/dev/null 2>&1; then ./examples/mtls/generate-certs.sh; fi

up: mtls-certs build build-worker ## Build and start docker compose
	docker compose up -d --force-recreate

down: ## Stop docker compose
	docker compose down

restart: down up ## Restart docker compose (rebuilds image)

logs: ## Show docker compose logs
	docker compose logs -f

logs-control-plane: ## Show control-plane logs only
	docker compose logs -f control-plane

logs-proxy: ## Show proxy logs only
	docker compose logs -f proxy

logs-dependency-graph-worker: ## Show dependency graph worker logs only
	docker compose logs -f dependency-graph-worker

ps: ## Show docker compose containers
	docker compose ps

clean: ## Clean up docker images and volumes
	docker compose down -v
	docker rmi -f dependency-firewall:latest 2>/dev/null || true
	docker rmi -f dependency-firewall-graph-worker:latest 2>/dev/null || true

status: ## Show service status
	@echo "Docker Compose Status:"
	@docker compose ps
	@echo ""
	@echo "Control Plane Health:"
	@curl -s http://localhost:8080/healthz | jq . || echo "(Service may not be running)"
	@echo ""
	@echo "Proxy Health:"
	@curl -s http://localhost:8081/healthz | jq . || echo "(Service may not be running)"

test: ## Run tests
	go test ./...

test-integration: ## Run tests including integration-tagged tests
	go test ./... -tags integration

test-all: ## Run all tests with race detector and integration tag
	go test ./... -race -tags integration

test-coverage: ## Run tests with coverage
	go test ./... -cover

fmt: ## Format Go code with the configured golangci-lint formatters
	golangci-lint fmt ./...

lint: ## Run all configured Go linters
	golangci-lint run ./...

lint-fix: ## Apply safe automatic fixes, then report remaining lint findings
	golangci-lint run --fix ./...

lefthook: ## Ensure the lefthook binary is installed
	@command -v lefthook >/dev/null 2>&1 || go install github.com/evilmartians/lefthook@$(LEFTHOOK_VERSION)

hooks-install: lefthook ## Install lefthook git hooks
	@lefthook install

vet: ## Run go vet
	go vet ./...

tidy: ## Tidy dependencies
	go mod tidy

all: clean build build-worker test ## Clean, build, and test
