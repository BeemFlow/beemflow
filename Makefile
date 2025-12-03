# BeemFlow Rust - Makefile
# Build, test, and development automation for BeemFlow

BINARY := flow
RELEASE_BINARY := target/release/$(BINARY)

# Auto-discover flow files
INTEGRATION_FLOWS := $(shell find flows/integration -name "*.flow.yaml" 2>/dev/null)
E2E_FLOWS := $(shell find flows/e2e -name "*.flow.yaml" 2>/dev/null)
EXAMPLE_FLOWS := $(shell find flows/examples -name "*.flow.yaml" 2>/dev/null)

.PHONY: all clean build build-frontend build-static install test test-verbose test-race coverage integration e2e test-all check fmt fmt-check lint fix release

all: clean test build install

clean:
	cargo clean
	rm -rf frontend/dist
	rm -f test_all_flows.sh test_registry test_registry.rs flows/test_fetch.flow.yaml

build-frontend:
	cd frontend && npm install && npm run build

build: build-frontend
	cargo build --release

build-static: build-frontend
	cargo build --release --target x86_64-unknown-linux-musl

install: build
	cargo install --path .

serve:
	cargo run --release -- serve

# ────────────────────────────────────────────────────────────────────────────
# Tests
# ────────────────────────────────────────────────────────────────────────────

# Run unit + integration tests
test:
	cargo test --lib
	cargo test --test integration_test

# Integration tests only
integration:
	cargo test --test integration_test

# E2E tests via CLI
e2e: build
	@test_dir="/tmp/beemflow-e2e-$$$$"; \
	export BEEMFLOW_HOME="$$test_dir"; \
	mkdir -p "$$test_dir"; \
	failed=0; \
	for flow in $(INTEGRATION_FLOWS) $(E2E_FLOWS); do \
		flow_name=$$(basename $$flow .flow.yaml); \
		if ! $(RELEASE_BINARY) flows save $$flow_name --file "$$flow"; then \
			echo "Save failed: $$flow_name"; \
			failed=$$((failed + 1)); \
			continue; \
		fi; \
		if ! $(RELEASE_BINARY) runs start $$flow_name --draft; then \
			echo "Execution failed: $$flow_name"; \
			failed=$$((failed + 1)); \
		fi; \
	done; \
	rm -rf "$$test_dir"; \
	if [ $$failed -gt 0 ]; then \
		echo "E2E tests failed: $$failed flow(s)"; \
		exit 1; \
	fi

# Full test suite (unit + integration + e2e)
test-all: test e2e

# Testing variants
test-verbose:
	cargo test -- --nocapture

test-race:
	cargo test -- --test-threads=1

coverage:
	cargo tarpaulin --out Html --output-dir coverage

# ────────────────────────────────────────────────────────────────────────────
# Code quality
# ────────────────────────────────────────────────────────────────────────────

# Static analysis (formatting + linting)
check: build-frontend fmt-check lint

fmt:
	cargo fmt

fmt-check:
	cargo fmt -- --check

lint:
	cargo clippy --lib --all-features -- \
		-D warnings \
		-D clippy::unwrap_used \
		-D clippy::expect_used \
		-D clippy::panic \
		-D clippy::indexing_slicing \
		-D clippy::unwrap_in_result
	cargo clippy --bins --all-features -- -D warnings

# Auto-fix all issues (format + clippy --fix)
fix:
	cargo fix --allow-dirty --allow-staged
	cargo clippy --fix --allow-dirty --allow-staged --lib --all-features -- \
		-D warnings \
		-D clippy::unwrap_used \
		-D clippy::expect_used \
		-D clippy::panic \
		-D clippy::indexing_slicing \
		-D clippy::unwrap_in_result
	cargo clippy --fix --allow-dirty --allow-staged --bins --all-features -- -D warnings
	$(MAKE) fmt

# ────────────────────────────────────────────────────────────────────────────
# Release
# ────────────────────────────────────────────────────────────────────────────

release:
	@if [ -z "$(TAG)" ]; then echo "Usage: make release TAG=v0.2.1"; exit 1; fi
	git tag $(TAG)
	git push origin $(TAG)

# ────────────────────────────────────────────────────────────────────────────
# Development helpers
# ────────────────────────────────────────────────────────────────────────────

# Run a specific flow
run:
	@if [ -z "$(FLOW)" ]; then echo "Usage: make run FLOW=path/to/flow.yaml"; exit 1; fi
	@flow_name=$$(basename $(FLOW) .flow.yaml); \
	flow_content=$$(cat $(FLOW)); \
	cargo run --release -- flows save $$flow_name --content "$$flow_content" > /dev/null; \
	cargo run --release -- runs start $$flow_name --draft

# Run with debug logging
debug:
	@if [ -z "$(FLOW)" ]; then echo "Usage: make debug FLOW=path/to/flow.yaml"; exit 1; fi
	@flow_name=$$(basename $(FLOW) .flow.yaml); \
	flow_content=$$(cat $(FLOW)); \
	cargo run --release -- flows save $$flow_name --content "$$flow_content" > /dev/null; \
	RUST_LOG=debug cargo run --release -- runs start $$flow_name --draft

# List all available tools
tools:
	@echo "Registered tools:"
	@cat src/registry/default.json | jq -r '.[] | select(.type == "tool") | "  - " + .name' | head -20
	@echo "  ..."

# Show test results summary
test-summary:
	@./test_all_flows.sh 2>/dev/null || echo "Run 'make build' first"

# Watch mode for development
watch:
	cargo watch -x 'build' -x 'test'

# Generate documentation
docs:
	cargo doc --no-deps --open

# Benchmark
bench:
	cargo bench

# Security audit
audit:
	cargo audit

