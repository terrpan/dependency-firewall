.PHONY: help build push up down restart logs logs-control-plane logs-proxy ps clean status test test-integration test-all test-coverage fmt lint vet tidy all

help: ## Show this help message
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-22s\033[0m %s\n", $$1, $$2}'

build: ## Build the firewall image using ko and load it into Docker
	@echo "Building firewall with ko..."
	@KO_DOCKER_REPO=ko.local ko build --bare ./cmd/firewall
	@docker tag ko.local:latest dependency-firewall:latest
	@echo "Tagged as dependency-firewall:latest"

push: ## Push the firewall image using ko
	ko build ./cmd/firewall

up: build ## Build and start docker compose
	docker compose up -d

down: ## Stop docker compose
	docker compose down

restart: down up ## Restart docker compose (rebuilds image)

logs: ## Show docker compose logs
	docker compose logs -f

logs-control-plane: ## Show control-plane logs only
	docker compose logs -f control-plane

logs-proxy: ## Show proxy logs only
	docker compose logs -f proxy

ps: ## Show docker compose containers
	docker compose ps

clean: ## Clean up docker images and volumes
	docker compose down -v
	docker rmi -f dependency-firewall:latest 2>/dev/null || true

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

fmt: ## Format code
	go fmt ./...

lint: ## Run linters
	golangci-lint run

vet: ## Run go vet
	go vet ./...

tidy: ## Tidy dependencies
	go mod tidy

all: clean build test ## Clean, build, and test
