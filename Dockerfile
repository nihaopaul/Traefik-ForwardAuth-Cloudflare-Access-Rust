FROM rust:1 AS build-env

# `ring` (pulled in by rustls) compiles C and assembly, so building for a musl
# target needs a musl-targeting C toolchain alongside the Rust std for that target.
RUN apt-get update \
    && apt-get install --no-install-recommends -y musl-tools \
    && rm -rf /var/lib/apt/lists/*

# Map the Docker arch onto the Rust triple so this builds on amd64 and arm64.
ARG TARGETARCH
RUN case "$TARGETARCH" in \
      amd64) target=x86_64-unknown-linux-musl ;; \
      arm64) target=aarch64-unknown-linux-musl ;; \
      *) echo "unsupported TARGETARCH: '$TARGETARCH'" >&2; exit 1 ;; \
    esac \
    && echo "$target" > /rust-target \
    && rustup target add "$target"

WORKDIR /app
COPY . /app

# Statically linked, so the runtime image needs no libc at all. cc-rs picks up
# musl-gcc from musl-tools on its own, so no CC override is needed here.
RUN target="$(cat /rust-target)" \
    && cargo build --release --locked --target "$target" \
    && cp "target/$target/release/traefik-forward-auth-rust" /traefik-forward-auth-rust

FROM gcr.io/distroless/static-debian13
COPY --from=build-env /traefik-forward-auth-rust /
CMD ["./traefik-forward-auth-rust"]
