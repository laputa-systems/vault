# Builder image for Linux musl (statically linked) builds, tests, and releases.
# Toolchain bump: edit rust-toolchain.toml only; this image reads the channel
# from it.
FROM alpine:3.24.1

RUN apk add --no-cache \
    bash \
    binutils \
    file \
    gcc \
    git \
    make \
    mold \
    musl-dev \
    rustup

# Tests link libutil for Unix PTY support (openpty); musl provides those
# symbols in libc, so an empty archive satisfies the legacy library name
# without adding a glibc runtime dependency.
RUN ar rcs /usr/lib/libutil.a

RUN rustup-init -y --default-toolchain none

ENV PATH="/root/.cargo/bin:$PATH"

COPY rust-toolchain.toml /tmp/rust-toolchain.toml
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

WORKDIR /vault
