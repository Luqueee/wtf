.DEFAULT_GOAL := help

CARGO ?= cargo
E2E_FILTER ?=

.PHONY: help build check test calibration report-eval fmt fmt-check lint e2e e2e-docker e2e-all

help:
	@printf '%s\n' \
		'make build       Build the Rust workspace' \
		'make check       Check all targets' \
		'make test        Run the Rust test suite (Docker E2E stays ignored)' \
		'make calibration Run isolated diagnostic matrices and print observed metrics' \
		'make report-eval Execute isolated report acceptance corpus with measured metrics' \
		'make fmt         Format Rust sources' \
		'make fmt-check   Check Rust formatting' \
		'make lint        Run Clippy with warnings denied' \
		'make e2e         Run Cargo, Git, curl, and isolated systemd/Docker E2E' \
		'make e2e-docker  Opt in to shared-daemon Docker E2E' \
		'make e2e-all     Run both E2E groups (includes Docker)' \
		'Filter quick or Docker E2E: make e2e E2E_FILTER=cargo_build_failure'

build:
	$(CARGO) build --locked --workspace

check:
	$(CARGO) check --locked --workspace --all-targets

test:
	$(CARGO) test --locked --workspace

calibration:
	$(CARGO) test --locked -p wtf --test diagnostic_benchmark --test shell_calibration --test dns_calibration --test service_container_calibration -- --nocapture
	$(CARGO) test --locked -p wtf-core --test calibration_matrix --test dns_investigation -- --nocapture

report-eval:
	$(CARGO) test --locked -p wtf --test report_evaluation -- --nocapture

fmt:
	$(CARGO) fmt --all

fmt-check:
	$(CARGO) fmt --all -- --check

lint:
	$(CARGO) clippy --locked --workspace --all-targets --all-features -- -D warnings

e2e:
	bash scripts/e2e.sh quick "$(E2E_FILTER)"

e2e-docker:
	bash scripts/e2e.sh docker "$(E2E_FILTER)"

e2e-all:
	bash scripts/e2e.sh all
