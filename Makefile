NAME   := vault
TARGET := $(shell rustc -vV | awk '/^host:/ {print $$2}')
PREFIX ?= $(HOME)/usr

SIGN_ID ?= -
OS := $(shell uname -s)
MUSL_LINK_FLAGS := $(if $(findstring linux-musl,$(TARGET)),-C link-arg=-fuse-ld=mold,)

lint:
	cargo clippy --fix --allow-dirty --all-targets --all-features -- --deny warnings

install: dist
	$(if $(filter Darwin,$(OS)),codesign --sign "$(SIGN_ID)" --force --timestamp=none target/$(TARGET)/dist/$(NAME),:)
	mkdir -p $(PREFIX)/bin
	cp target/$(TARGET)/dist/$(NAME) $(PREFIX)/bin/$(NAME)

dist:
	cargo clean -p $(NAME) --release --target $(TARGET)
	RUSTFLAGS="-Zlocation-detail=none -Zshare-generics=y -Zunstable-options -Cpanic=immediate-abort -Cforce-unwind-tables=n -Clink-arg=-Wl,-x $(MUSL_LINK_FLAGS)" \
	cargo build --profile dist \
	  -Z build-std=std \
	  -Z build-std-features= \
	  --target $(TARGET)

.PHONY: lint install dist
