# Arkhon: one command per job. Run `make` for the list.
.DEFAULT_GOAL := help
DB ?= postgresql://arkhon@127.0.0.1:5433/postgres

help: ## Show this list
	@grep -hE '^[a-z-]+:.*## ' $(MAKEFILE_LIST) | awk -F':.*## ' '{printf "  make %-16s %s\n", $$1, $$2}'

setup: ## Install dev tools (pre-commit hooks, Python test deps)
	pipx install pre-commit || pip install pre-commit
	pre-commit install
	pip install "pyyaml>=6" "jsonschema>=4.20" "pytest>=8" "ruff>=0.12"

check: ## Format, lint and test everything (what CI runs)
	cargo fmt --all --check
	cargo clippy --workspace --all-targets -- -D warnings
	ARKHON_TEST_DATABASE_URL=$(DB) cargo test --workspace
	ruff check . && ruff format --check . && pytest -q

fmt: ## Format Rust and Python
	cargo fmt --all && ruff format .

suite: ## Customer app prototype on the real engine: http://127.0.0.1:4317/dashboard.html
	cargo run -p arkhon-suite-dev

suite-reset: ## Same, starting over with the example company
	cargo run -p arkhon-suite-dev -- --reset

license-server: ## License Manager + Operator Console: http://127.0.0.1:8443/console (env: server/README.md)
	cargo run --release -p arkhon-license-server -- serve

admin: ## Create an operator: make admin EMAIL=you@arkhonindustries.com PASSWORD='...'
	cargo run --release -p arkhon-license-server -- create-admin --email "$(EMAIL)" --password "$(PASSWORD)"

keys-root: ## OFFLINE ONLY: make keys-root OUT=/secure/root.key
	cargo run --release -p arkhon-keygen -- root --out "$(OUT)"

keys-issuing: ## make keys-issuing ROOT=root.key OUT=issuing.key CERT=issuing.cert SERIAL=1
	cargo run --release -p arkhon-keygen -- issuing --root "$(ROOT)" --out "$(OUT)" --cert "$(CERT)" --serial "$(SERIAL)" --days 365

env-check: ## Report this computer's hardware tier (GPU, RAM, TPM)
	cd tools/env-check && python3 -m arkhon_envcheck.check

fuzz: ## Fuzz every parser for 5 minutes each (nightly + cargo-fuzz)
	cd fuzz && for t in $$(cargo +nightly fuzz list); do cargo +nightly fuzz run -O $$t -- -max_total_time=300 || exit 1; done

coverage: ## Line coverage of the security crates
	cargo llvm-cov -p arkhon-crypto -p arkhon-tpm -p arkhon-license --summary-only

.PHONY: help setup check fmt suite suite-reset license-server admin keys-root keys-issuing env-check fuzz coverage
