# ────────────────────────────────────────────────────────────────────────────
SHELL := /usr/bin/env bash
.SHELLFLAGS := -eu -o pipefail -c
# ────────────────────────────────────────────────────────────────────────────
BINARY := flow
CMD_PATH := ./cmd/flow

# Auto-discover flow files
INTEGRATION_FLOWS := $(shell find flows/integration -name "*.flow.yaml" 2>/dev/null)
E2E_FLOWS := $(shell find flows/e2e -name "*.flow.yaml" 2>/dev/null)

# ────────────────────────────────────────────────────────────────────────────
.PHONY: all clean build build-static install test test-race coverage e2e integration test-all check fmt vet lint tidy fix release

all: clean test build install

clean:
	git clean -dfx -e .env

build:
	go build -o $(BINARY) $(CMD_PATH)

build-static:
	CGO_ENABLED=0 go build -a -ldflags '-extldflags "-static"' -o $(BINARY) $(CMD_PATH)

install: build
	go install $(CMD_PATH)

serve:
	go run $(CMD_PATH) serve

# ────────────────────────────────────────────────────────────────────────────
# Release
# ────────────────────────────────────────────────────────────────────────────

release:
	@if [ -z "$(TAG)" ]; then echo "Usage: make release TAG=v0.1.1"; exit 1; fi
	@echo "Creating and pushing tag $(TAG)..."
	git tag $(TAG)
	git push origin $(TAG)
	@echo "✅ Tag $(TAG) pushed! Check GitHub Actions for release progress."

# ────────────────────────────────────────────────────────────────────────────
# Tests
# ────────────────────────────────────────────────────────────────────────────

test:
	go test -v ./...

test-race:
	go test -race -v ./...

coverage:
	go test ./... -coverprofile=coverage.out
	go tool cover -func=coverage.out

# ────────────────────────────────────────────────────────────────────────────
# Integration (auto-discovers all flows)
# ────────────────────────────────────────────────────────────────────────────

e2e:
	@for flow in $(E2E_FLOWS); do go run $(CMD_PATH) run $$flow; done

integration:
	go test -tags=integration ./...
	@for flow in $(INTEGRATION_FLOWS); do go run $(CMD_PATH) run $$flow; done

# Full test suite
test-all: test-race integration e2e

# ────────────────────────────────────────────────────────────────────────────
# Code quality
# ────────────────────────────────────────────────────────────────────────────

check: fmt vet lint tidy

fmt:
	go fmt ./...

vet:
	go vet ./...

lint:
	golangci-lint run -c .golangci.yml ./...

tidy:
	go mod tidy
	go mod verify

fix:
	golangci-lint run --fix -c .golangci.yml ./...
	go fmt ./... 