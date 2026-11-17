NAME   := vault
TARGET := $(shell rustc -vV | awk '/^host:/ {print $$2}')
PREFIX ?= $(HOME)/.local

SIGN_ID ?= -
OS := $(shell uname -s)
MUSL_LINK_FLAGS := $(if $(findstring linux-musl,$(TARGET)),-C link-arg=-fuse-ld=mold,)

test:
	@bash -o pipefail -c 'cargo test -- --show-output 2>&1 | awk '\''/skipped (age interoperability|keyring assertions|key timeout query|cache scope assertions):/ { count++ } { print } END { printf "Skipped optional checks: %d\n", count }'\'''

test-ci:
	docker run --rm --init --platform "$(PLATFORM)" -e CI -v "$(CURDIR):/vault" -w /vault "$(IMAGE)" make test

lint:
	cargo clippy --all-targets --all-features -- --deny warnings

coverage:
	cargo llvm-cov --branch --html --output-dir .work/coverage
	cargo llvm-cov report --branch --summary-only

BASE ?= origin/main
MUTANTS_PLATFORM ?= $(if $(filter Darwin,$(OS)),macos,linux)
MUTANTS_SHARD ?=

mutants-selftest:
	python3 -B -m unittest discover -s scripts -p 'test_mutants_gate.py'

mutants-diff: mutants-selftest
	python3 -B scripts/mutants_gate.py "$(BASE)" "$(MUTANTS_PLATFORM)" "$(MUTANTS_SHARD)"

install: dist
	$(if $(filter Darwin,$(OS)),codesign --sign "$(SIGN_ID)" --force --timestamp=none target/$(TARGET)/dist/$(NAME),:)
	mkdir -p $(PREFIX)/bin
	cp target/$(TARGET)/dist/$(NAME) $(PREFIX)/bin/$(NAME)

dist:
	cargo clean -p $(NAME) --profile dist --target $(TARGET)
	RUSTFLAGS="-Zlocation-detail=none -Zshare-generics=y -Zunstable-options -Cpanic=immediate-abort -Cforce-unwind-tables=n -Clink-arg=-Wl,-x $(MUSL_LINK_FLAGS)" \
	cargo build --profile dist \
	  -Z build-std=std \
	  -Z build-std-features= \
	  --target $(TARGET)

verify-dist:
	@test -f "target/$(TARGET)/dist/$(NAME)"
	@if echo "$(TARGET)" | grep -q -- '-linux-musl$$'; then \
		command -v readelf >/dev/null || { echo 'readelf is required for dist verification' >&2; exit 1; }; \
		file "target/$(TARGET)/dist/$(NAME)" | grep -Eq 'static-pie linked|statically linked' || { echo 'dist binary is not statically linked' >&2; exit 1; }; \
		file "target/$(TARGET)/dist/$(NAME)" | grep -q 'stripped' || { echo 'dist binary is not stripped' >&2; exit 1; }; \
		! readelf -l "target/$(TARGET)/dist/$(NAME)" | grep -q INTERP || { echo 'dist binary has a dynamic ELF interpreter' >&2; exit 1; }; \
		! readelf -d "target/$(TARGET)/dist/$(NAME)" | grep -q NEEDED || { echo 'dist binary has dynamic dependencies' >&2; exit 1; }; \
	else \
		echo "Skipping ELF checks for $(TARGET)"; \
	fi

.PHONY: test test-ci lint coverage mutants-selftest mutants-diff install dist verify-dist
