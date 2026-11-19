NAME   := vault
TARGET := $(shell rustc -vV | awk '/^host:/ {print $$2}')
PREFIX ?= $(HOME)/.local

SIGN_ID ?= -
OS := $(shell uname -s)
MUSL_LINK_FLAGS := $(if $(findstring linux-musl,$(TARGET)),-C link-arg=-fuse-ld=mold,)

test:
	cargo test

test-ci:
	docker run --rm --init --platform "$(PLATFORM)" -e CI -v "$(CURDIR):/vault" -w /vault "$(IMAGE)" sh -ec '\
		echo "CI skips Linux session keyring test: owner-run boundary (container keyctl unavailable)" >&2; \
		cargo test -- --test-threads=1 --skip identity_cache_permissions_expiry_refresh_and_revocation_are_enforced; \
		output=$$(cargo test --test terminal_cli pinned_rage_interoperates_with_vault_age_files -- --nocapture 2>&1) || { echo "$$output"; exit 1; }; \
		echo "$$output"; \
		case "$$output" in *"rage interoperability assertions executed"*) ;; *) echo "rage interoperability assertions did not execute" >&2; exit 1 ;; esac'

lint:
	cargo clippy --all-targets --all-features -- --deny warnings

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

.PHONY: test test-ci lint install dist verify-dist
