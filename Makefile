.PHONY: build-native build-wasm fmt fmt-ci lint fuzz-corpus fuzz-build fuzz

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

fuzz-corpus:
	$(call log,Generating NIST AES-128 seed corpus)
	@mkdir -p $(FUZZ_CORPUS)/roundtrip
	@python3 -c "open('$(FUZZ_CORPUS)/roundtrip/seed01','wb').write(bytes.fromhex('0'*64))"
	@python3 -c "open('$(FUZZ_CORPUS)/roundtrip/seed02','wb').write(bytes.fromhex('2b7e151628aed2a6abf7158809cf4f3c3243f6a8885a308d313198a2e0370734'))"
	@python3 -c "open('$(FUZZ_CORPUS)/roundtrip/seed03','wb').write(bytes.fromhex('000102030405060708090a0b0c0d0e0f00112233445566778899aabbccddeeff'))"
	@python3 -c "open('$(FUZZ_CORPUS)/roundtrip/seed04','wb').write(bytes.fromhex('2b7e151628aed2a6abf7158809cf4f3c6bc1bee22e409f96e93d7e117393172a'))"
	@python3 -c "open('$(FUZZ_CORPUS)/roundtrip/seed05','wb').write(bytes.fromhex('2b7e151628aed2a6abf7158809cf4f3cae2d8a571e03ac9c9eb76fac45af8e51'))"
	@python3 -c "open('$(FUZZ_CORPUS)/roundtrip/seed06','wb').write(bytes.fromhex('2b7e151628aed2a6abf7158809cf4f3c30c81c46a35ce411e5fbc1191a0a52ef'))"
	@python3 -c "open('$(FUZZ_CORPUS)/roundtrip/seed07','wb').write(bytes.fromhex('2b7e151628aed2a6abf7158809cf4f3cf69f2445df4f9b17ad2b417be66c3710'))"
	@python3 -c "open('$(FUZZ_CORPUS)/roundtrip/seed08','wb').write(bytes.fromhex('f'*64))"
	@python3 -c "open('$(FUZZ_CORPUS)/roundtrip/seed09','wb').write(bytes.fromhex('000102030405060708090a0b0c0d0e0f0f1e2d3c4b5a69788796a5b4c3d2e1f0'))"

fuzz-build:
	$(call log,Building fuzz target with libfuzzer instrumentation)
	@cargo fuzz --version >/dev/null 2>&1 || { \
		printf '\033[1;31m[ERROR]\033[0m cargo-fuzz not found. Please run: cargo install cargo-fuzz\n' ; \
		exit 1 ; \
	}
	@cargo +nightly fuzz build roundtrip

fuzz: fuzz-corpus fuzz-build
	$(call log,Fuzzing roundtrip)
	@cargo +nightly fuzz run roundtrip $(FUZZ_CORPUS)/roundtrip -- -max_len=32
