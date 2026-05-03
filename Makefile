.PHONY: build-native build-wasm fmt fmt-ci lint fuzz-build fuzz-encrypt fuzz-decrypt fuzz-roundtrip

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
	@wasm-pack --log-level warn build --release --target web wasm

fmt:
	$(call log,Formatting code)
	@cargo fmt --all

fmt-ci:
	$(call log,Checking code formatting)
	@cargo fmt --all -- --check

lint:
	$(call log,Running clippy linter)
	@cargo clippy --all-targets --all-features -- -D warnings

FUZZ_CORPUS := fuzz/corpus
FUZZ_OUT    := fuzz/findings

fuzz-build:
	$(call log,Building fuzz targets with AFL++ instrumentation)
	@cargo afl --version >/dev/null 2>&1 || { \
		printf '\033[1;31m[ERROR]\033[0m cargo-afl not found. Please run: cargo install afl\n' ; \
		exit 1 ; \
	}
	@cargo afl build --features fuzzing

fuzz: fuzz-build
	$(call log,Fuzzing roundtrip)
	@mkdir -p $(FUZZ_CORPUS)/roundtrip $(FUZZ_OUT)/roundtrip
	@[ -n "$$(ls -A $(FUZZ_CORPUS)/roundtrip 2>/dev/null)" ] || \
		dd if=/dev/urandom bs=32 count=1 2>/dev/null > $(FUZZ_CORPUS)/roundtrip/seed1
	@cargo afl fuzz -i $(FUZZ_CORPUS)/roundtrip -o $(FUZZ_OUT)/roundtrip -- ./target/debug/fuzz_roundtrip
