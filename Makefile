.PHONY: build-native build-wasm fmt fmt-ci lint

BOLD_CYAN := \033[1;36m
RESET := \033[0m

define log
	@printf '$(BOLD_CYAN)[%s]$(RESET)\n' "$(1)"
endef

all: build-native build-wasm

build-native:
	$(call log,Building native binary)
	@cargo build --release --bin tiber

build-wasm:
	$(call log,Building WebAssembly module)
	@command -v wasm-pack >/dev/null 2>&1 || { \
		printf '\033[1;31m[ERROR]\033[0m wasm-pack not found. Please run: cargo install wasm-pack\n' ; \
		exit 1 ; \
	}
	@cd wasm && wasm-pack --log-level warn build --release --target web

fmt:
	$(call log,Formatting code)
	@cargo fmt --all

fmt-ci:
	$(call log,Checking code formatting)
	@cargo fmt --all -- --check

lint:
	$(call log,Running clippy linter)
	@cargo clippy --all-targets --all-features -- -D warnings
