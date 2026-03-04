.PHONY: build build-coordinator build-mockapi build-helper run run-coordinator test clean fmt lint proto \
	test-e2e test-e2e-down docker-build run-dev-dropin run-secure-local

APP_NAME := csar
COORD_NAME := csar-coordinator
BUILD_DIR := bin
VERSION ?= dev
COMPOSE_E2E := docker compose -f docker-compose.e2e.yaml

build:
	go build -ldflags "-X main.Version=$(VERSION)" -o $(BUILD_DIR)/$(APP_NAME) ./cmd/csar

build-coordinator:
	go build -ldflags "-X main.version=$(VERSION)" -o $(BUILD_DIR)/$(COORD_NAME) ./cmd/csar-coordinator

build-mockapi:
	go build -o $(BUILD_DIR)/mockapi ./cmd/mockapi

build-helper:
	go build -o $(BUILD_DIR)/csar-helper ./cmd/csar-helper

build-all: build build-coordinator build-mockapi build-helper

run: build
	./$(BUILD_DIR)/$(APP_NAME) -config config.example.yaml

run-coordinator: build-coordinator
	./$(BUILD_DIR)/$(COORD_NAME) -listen :9090

test:
	go test ./... -count=1

test-unit:
	go test $$(go list ./... | grep -v tests/) -count=1

test-integration:
	go test ./tests/integration/ -v -count=1

test-verbose:
	go test ./... -v -count=1

test-race:
	go test ./... -race -count=1

# Docker-based E2E tests (mockapi + csar + test runner)
test-e2e:
	$(COMPOSE_E2E) up --build --abort-on-container-exit --exit-code-from e2e
	$(COMPOSE_E2E) down -v

test-e2e-down:
	$(COMPOSE_E2E) down -v --remove-orphans

docker-build:
	docker build -t csar:latest -f Dockerfile .
	docker build -t csar-coordinator:latest -f Dockerfile.coordinator .
	docker build -t csar-mockapi:latest -f Dockerfile.mockapi .

clean:
	rm -rf $(BUILD_DIR)

fmt:
	go fmt ./...

lint:
	golangci-lint run ./...

# Security-focused static analysis (audit §2.2: SAST).
lint-security:
	@echo "==> Running gosec (SAST)..."
	gosec -fmt=json -out=gosec-report.json ./... || true
	gosec ./...

# Run golangci-lint with strict config (.golangci.yml).
lint-strict:
	golangci-lint run --config .golangci.yml ./...

run-dev-dropin: build
	./$(BUILD_DIR)/$(APP_NAME) -config config.dev-local.yaml

run-secure-local: build
	./$(BUILD_DIR)/$(APP_NAME) -config config.prod-single.yaml \
		-kms-provider local -kms-local-keys "dev-key=dev-passphrase" \
		-token-file tokens.yaml

proto:
	protoc --go_out=. --go_opt=paths=source_relative \
		--go-grpc_out=. --go-grpc_opt=paths=source_relative \
		proto/csar/v1/auth.proto \
		proto/csar/v1/coordinator.proto
