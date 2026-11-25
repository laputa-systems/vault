# Builder image for Linux musl (statically linked) builds, tests, and releases.
# Toolchain bump: edit rust-toolchain.toml only; this image reads the channel
# from it. Bump LLVM_* and RUSTUP_VERSION (plus its checksums) separately.
FROM alpine:3.24.2@sha256:294b683cb724975bec92580e1e685676bd4b50bda910ddb8c51d4cabeaec77e6
COPY --from=oci.17166969.xyz/owned-tools@sha256:aaec19e7a44cbc53b40db2d22093600ee888689b89be94da90e5398ed02f1883 /opt/laputa /opt/laputa
ENV PATH=$PATH:/opt/laputa/bin

ARG TARGETARCH
ARG LLVM_VERSION=23.1.5
ARG LLVM_RELEASE_SHA=dc0d9b9
ARG RAGE_VERSION=0.12.1
ARG RAGE_X86_64_SHA256=e36bfce012d34d191ee2d8372e061de0d3069c8585c4ab6396524a2a0e08bf32
ARG RAGE_ARM64_SHA256=9c4bd3bc27370ed36962632278a0264534699118493aa989088838b68de1c3d4
ARG RUSTUP_VERSION=1.29.3
ARG RUSTUP_X86_64_SHA256=1552169aba2836777136ccff7a381e95c17233b5d8250cd5e10ae3cb971bfcfc
ARG RUSTUP_AARCH64_SHA256=956deacdc27ab82ae7ac821d5d3e9e95e4795d476d17efe99743bb8531ca1031

# gcc provides the cc default linker used by vault's plain-cargo Makefile flow;
# mold is required because the Makefile passes -fuse-ld=mold for musl targets.
RUN apk add --no-cache \
    binutils=2.45.1-r1 \
    bash=5.3.9-r1 \
    file=5.47-r2 \
    gcc=15.2.0-r5 \
    make=4.4.1-r4 \
    strace=6.19-r1 \
    musl-dev=1.2.6-r3 \
    libgcc=15.2.0-r5 \
    tzdata=2026f-r0

# Tests link libutil for Unix PTY support (openpty); musl provides those
# symbols in libc, so an empty archive satisfies the legacy library name
# without adding a glibc runtime dependency.
RUN ar rcs /usr/lib/libutil.a

# LLVM tools must be musl-linked to run in this Alpine image.
RUN case "$TARGETARCH" in \
        amd64) arch=x86_64; sum=c43f18f143cc17f49814b6c5dda8a1122d17b6bcdff9848b6f77e97b33026dfe ;; \
        arm64) arch=aarch64; sum=fe0a382993c36a04a505157b59503a7294db97e2ac9923e5630f8b393b78f118 ;; \
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
        amd64) arch=amd64; sum=$RAGE_X86_64_SHA256 ;; \
        arm64) arch=arm64; sum=$RAGE_ARM64_SHA256 ;; \
        *) echo "unsupported TARGETARCH: $TARGETARCH" >&2; exit 1 ;; \
    esac \
    && archive=/vault/.work/tmp/rage.deb \
    && wget -O "$archive" "https://github.com/str4d/rage/releases/download/v${RAGE_VERSION}/rage-musl_${RAGE_VERSION}-1_${arch}.deb" \
    && echo "$sum  $archive" | sha256sum -c - \
    && ar p "$archive" data.tar.xz | tar xJf - -C /usr/local/bin --strip-components=3 ./usr/bin/rage ./usr/bin/rage-keygen \
    && rm "$archive"

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
