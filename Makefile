.PHONY: help build push up down logs clean

# Build configuration
KO_REPO ?= docker://dependency-firewall
VERSION ?= $(shell git describe --tags --always 2>/dev/null || echo "latest")
COMMIT ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
BUILD_TIME ?= $(shell git log -1 --format=%aI 2>/dev/null || echo "unknown")

help: ## Show this help message
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-15s\033[0m %s\n", $$1, $$2}'

build: ## Build firewall image using ko
	@echo "Building v$(VERSION) (commit: $(COMMIT), time: $(BUILD_TIME))"
	KO_DOCKER_REPO=$(KO_REPO) VERSION=$(VERSION) COMMIT=$(COMMIT) BUILD_TIME=$(BUILD_TIME) ko build --push=false -t $(VERSION) ./cmd/firewall

rebuild: ## Force rebuild (no cache) using ko
	@echo "Force rebuilding v$(VERSION) (commit: $(COMMIT), time: $(BUILD_TIME))"
	KO_DOCKER_REPO=$(KO_REPO) VERSION=$(VERSION) COMMIT=$(COMMIT) BUILD_TIME=$(BUILD_TIME) ko build --push=false -t $(VERSION) ./cmd/firewall

push: ## Push firewall image using ko
	KO_DOCKER_REPO=$(KO_REPO) VERSION=$(VERSION) COMMIT=$(COMMIT) BUILD_TIME=$(BUILD_TIME) ko build -t $(VERSION) ./cmd/firewall

up: build ## Build with ko and start docker-compose
	docker-compose up -d

down: ## Stop docker-compose
	docker-compose down

restart: down up ## Restart docker-compose (rebuilds image)

logs: ## Show docker-compose logs
	docker-compose logs -f

logs-firewall: ## Show firewall logs only
	docker-compose logs -f firewall

logs-postgres: ## Show postgres logs only
	docker-compose logs -f postgres

logs-valkey: ## Show valkey logs only
	docker-compose logs -f valkey

ps: ## Show docker-compose containers
	docker-compose ps

shell: ## Open shell in firewall container
	docker-compose exec firewall sh

clean: ## Clean up docker images and volumes
	docker-compose down -v
	docker rmi -f dependency-firewall:latest 2>/dev/null || true

status: ## Show service status
	@echo "Docker Compose Status:"
	@docker-compose ps
	@echo ""
	@echo "Firewall Health:"
	@curl -s http://localhost:8080/healthz | jq . || echo "(Service may not be running)"

test: ## Run tests
	go test ./...

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




