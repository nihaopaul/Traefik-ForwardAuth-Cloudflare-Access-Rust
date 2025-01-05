FROM rust:1 AS build-env
WORKDIR /app
COPY . /app
RUN cargo build --release

FROM gcr.io/distroless/cc-debian12
COPY --from=build-env /app/target/release/traefik-forward-auth-rust /
CMD ["./traefik-forward-auth-rust"]