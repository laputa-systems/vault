# Builder image for Linux musl (statically linked) builds, tests, and releases.
# Toolchain bump: edit rust-toolchain.toml only; this image reads the channel
# from it. Bump LLVM_* and RUSTUP_VERSION (plus its checksums) separately.
FROM alpine:3.24.1

ARG TARGETARCH
ARG LLVM_VERSION=23.1.0-rc2
ARG LLVM_RELEASE_SHA=6eb5fb9
ARG RUSTUP_VERSION=1.29.1
ARG RUSTUP_X86_64_SHA256=331228566cc931f32cd684f9bebc5956a5e5d7394c8d5de595f196a658ab98e6
ARG RUSTUP_AARCH64_SHA256=1ddf36182ac5d1782dbeefcb9bea7f5f9412d88f4a0d5047b1564a223624e8c6

# gcc provides the cc default linker used by vault's plain-cargo Makefile flow;
# mold is required because the Makefile passes -fuse-ld=mold for musl targets.
RUN apk add --no-cache \
    binutils \
    bash \
    file \
    gcc \
    make \
    mold \
    strace \
    musl-dev \
    libgcc \
    git \
    tzdata

# Tests link libutil for Unix PTY support (openpty); musl provides those
# symbols in libc, so an empty archive satisfies the legacy library name
# without adding a glibc runtime dependency.
RUN ar rcs /usr/lib/libutil.a

# LLVM tools must be musl-linked to run in this Alpine image.
RUN case "$TARGETARCH" in \
        amd64) arch=x86_64; sum=36647cca0bf57d206a6ce757d07a9d8489ef6ccf283a2cc7f740d1cba99a088b ;; \
        arm64) arch=aarch64; sum=0c9bd6f0fefa26dbdb7d6ed568f3799b558428b1ce1264656aa328fc6fd9e32d ;; \
        *) echo "unsupported TARGETARCH: $TARGETARCH" >&2; exit 1 ;; \
    esac \
    && archive=/vault/.work/tmp/llvm.tar.xz \
    && mkdir -p /vault/.work/tmp \
    && wget -O "$archive" "https://github.com/laputa-systems/llvm-prebuilt-musl/releases/download/llvm-musl-${LLVM_VERSION}-${LLVM_RELEASE_SHA}/clang+llvm-${LLVM_VERSION}-${arch}-linux-musl.tar.xz" \
    && echo "$sum  $archive" | sha256sum -c - \
    && mkdir -p /opt/llvm-musl \
    && tar xf "$archive" -C /opt/llvm-musl --strip-components=1 \
    && test -f /opt/llvm-musl/lib/libclang.so \
    && rm "$archive"

RUN for target in x86_64-unknown-linux-musl aarch64-unknown-linux-musl; do \
        stub_dir="/usr/lib/e-crt/$target"; \
        mkdir -p "$stub_dir"; \
        for obj in crtbegin.o crtbeginS.o crtbeginT.o crtend.o crtendS.o; do \
            /opt/llvm-musl/bin/clang --target="$target" -x c -c /dev/null -o "$stub_dir/$obj"; \
        done; \
    done

RUN case "$TARGETARCH" in \
        amd64) arch=x86_64; sum=$RUSTUP_X86_64_SHA256 ;; \
        arm64) arch=aarch64; sum=$RUSTUP_AARCH64_SHA256 ;; \
        *) echo "unsupported TARGETARCH: $TARGETARCH" >&2; exit 1 ;; \
    esac \
    && init=/vault/.work/tmp/rustup-init \
    && wget -O "$init" "https://static.rust-lang.org/rustup/archive/${RUSTUP_VERSION}/${arch}-unknown-linux-musl/rustup-init" \
    && echo "$sum  $init" | sha256sum -c - \
    && chmod +x "$init" \
    && "$init" -y --default-toolchain none \
    && rm "$init"

ENV PATH="/opt/llvm-musl/bin:/root/.cargo/bin:$PATH" \
    CC="/opt/llvm-musl/bin/clang" \
    AR="/opt/llvm-musl/bin/llvm-ar" \
    RANLIB="/opt/llvm-musl/bin/llvm-ranlib" \
    LIBRARY_PATH="/opt/llvm-musl/lib" \
    LIBCLANG_PATH="/opt/llvm-musl/lib" \
    CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_LINKER="/opt/llvm-musl/bin/clang" \
    CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_LINKER="/opt/llvm-musl/bin/clang"

COPY rust-toolchain.toml /tmp/rust-toolchain.toml
# clippy runs inside this image in CI; llvm-tools is a declared toolchain
# component in rust-toolchain.toml, so install both alongside the musl targets.
RUN channel="$(sed -n 's/^channel *= *"\(.*\)"/\1/p' /tmp/rust-toolchain.toml)" \
    && test -n "$channel" \
    && rustup toolchain install "$channel" \
        --target x86_64-unknown-linux-musl \
        --target aarch64-unknown-linux-musl \
        --component rust-src \
        --component llvm-tools \
        --component clippy \
    && rustup default "$channel" \
    && rm /tmp/rust-toolchain.toml

# Host proc-macro links search rustc's target library directory for CRT
# startup objects. Keep those objects available there without changing the
# target's build-std Rust flags.
RUN host_target="$(rustc -vV | awk '/^host:/ {print $2}')" \
    && host_libdir="$(rustc --print target-libdir)" \
    && for obj in crtbegin.o crtbeginS.o crtbeginT.o crtend.o crtendS.o; do \
        ln -sf "/usr/lib/e-crt/$host_target/$obj" "$host_libdir/$obj"; \
    done

# Alpine keeps these libraries outside the Rust musl target directory.
RUN host_libdir="$(rustc --print target-libdir)" \
    && ln -sf /usr/lib/libgcc_s.so.1 "$host_libdir/libgcc_s.so" \
    && ln -sf /usr/lib/libgcc_s.so.1 "$host_libdir/libgcc_s.so.1" \
    && ln -sf /usr/lib/libc.so "$host_libdir/libc.so"

RUN cat > /usr/local/bin/musl-cargo <<'EOF' \
    && chmod +x /usr/local/bin/musl-cargo
#!/bin/sh
set -eu

target=${MUSL_TARGET:?MUSL_TARGET is required}
case "$target" in
    x86_64-unknown-linux-musl)
        crt=/usr/lib/e-crt/x86_64-unknown-linux-musl
        ;;
    aarch64-unknown-linux-musl)
        crt=/usr/lib/e-crt/aarch64-unknown-linux-musl
        ;;
    *)
        exec cargo "$@"
        ;;
esac

mode=${MUSL_BUILD_MODE:-static}
native="-L native=/usr/lib -Clink-arg=-B$crt"
release="-Cpanic=abort"
case "$mode" in
    static|test|driver)
        flags=$native
        ;;
    release-static)
        flags="$native $release -Ctarget-feature=+crt-static"
        ;;
    *)
        echo "musl-cargo: unknown build mode: $mode" >&2
        exit 2
        ;;
esac

target_env=$(printf '%s' "$target" | tr '[:lower:]-' '[:upper:]_')
linker_var="CARGO_TARGET_${target_env}_LINKER"
rustflags_var="CARGO_TARGET_${target_env}_RUSTFLAGS"
export "$linker_var=clang"
if [ "$mode" = driver ] || [ "$mode" = test ]; then
    # Cargo builds proc-macro and test-support crates for the container host,
    # where target-scoped flags do not apply. Keep those links on the same
    # musl CRT path as the instrumented binary.
    unset CARGO_ENCODED_RUSTFLAGS
    export RUSTFLAGS="$flags"
else
    export "$rustflags_var=$flags"
fi
exec cargo "$@"
EOF

WORKDIR /vault
