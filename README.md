# Traefik Forward Auth for Cloudflare Access

A small service that lets **Traefik** enforce **Cloudflare Zero Trust** access rules on any route it serves.

Cloudflare Access puts a login screen in front of your apps and hands the browser a signed `CF_Authorization` cookie. Traefik can't check that cookie by itself. This service does: Traefik asks it about every request, and it answers `200` (allow) or `403` (deny). Works with Traefik 2.x and 3.x.

> Originally attempted as a native Traefik plugin, but Traefik's WASM support follows the R1 spec and is too limited. This is a Rust port of [Traefik-ForwardAuth-Cloudflare-Access](https://github.com/nihaopaul/Traefik-ForwardAuth-Cloudflare-Access).

## How it works

1. A user hits your app. Traefik pauses the request and asks this service `GET /auth`, forwarding the cookies.
2. The service reads the `CF_Authorization` cookie. No cookie → `403`, and Cloudflare shows the login page.
3. It verifies the cookie's JWT signature against your team's public keys, and checks the token was issued for one of *your* applications (its `aud`).
4. Valid → `200` and Traefik serves the request. Anything else → `403`.

It keeps itself current in the background, so you don't restart it when things change in Cloudflare:

- **Public keys** refresh every 24 hours (Cloudflare rotates them).
- **Application list** refreshes every hour (so new apps start working on their own).

Nothing is stored on disk and no state is kept between requests.

## Quick start

```yaml
services:
  forward-auth-rust:
    image: nihaopaul/forward-auth-rust:0.4.1
    restart: unless-stopped
    environment:
      CF_DOMAIN: https://yourteam.cloudflareaccess.com
      CF_ORG: your-cloudflare-account-id
      CF_TOKEN: your-read-only-api-token
      PORT: '9001'
    ports:
      - '9001:9001'
    deploy:
      resources:
        limits:
          cpus: '1'
          memory: 50M
```

Then tell Traefik to use it as a middleware:

```yaml
http:
  middlewares:
    cf-auth:
      forwardAuth:
        address: "http://forward-auth-rust:9001/auth"
```

And apply it to a route:

```yaml
http:
  routers:
    dashboard:
      rule: Host(`traefik.example.com`)
      service: api@internal
      entryPoints:
        - websecure
      middlewares:
        - cf-auth
```

## Configuration

| Variable | Required | Description |
| --- | --- | --- |
| `CF_DOMAIN` | yes | Your Zero Trust team domain, including `https://` — the hostname where Cloudflare shows your login page. |
| `CF_ORG` | yes | Your Cloudflare **account ID** — the value in your dashboard URL, `https://dash.cloudflare.com/{account-id}`. |
| `CF_TOKEN` | yes | API token with **Account → Access: Apps and Policies → Read**. Read-only is enough. |
| `PORT` | no | Port to listen on. Defaults to `3000`. |

The service listens on `0.0.0.0` and exposes a single endpoint, `GET /auth`.

## Notes

**Protect the right things.** This gates on "is this a valid login for one of my Cloudflare apps" — it does not evaluate per-application policies. Two apps behind the same instance can accept each other's tokens, so think carefully before putting it in front of a writable dashboard or API.

**Runs on x86 and ARM.** Images are published for `linux/amd64` and `linux/arm64` under a single tag, so `docker pull` fetches the right one for your host — no `platform:` override needed on a Raspberry Pi, an Ampere VPS, or Apple silicon. (Releases before 0.4.1 were amd64 only.)

**Pin a version.** The example uses `:0.4.1` rather than `:latest` so an unattended `docker compose pull` can't change what you're running.

## Building from source

Any recent stable Rust toolchain will do:

```bash
cargo test --workspace                        # run the test suite
cargo build --release --locked --workspace    # release build
```

Or, if you would rather not install Rust, [devbox](https://www.jetify.com/devbox)
supplies the toolchain and wraps the same commands:

```bash
devbox run test
devbox run build
```

The container image is a statically linked musl binary on `distroless/static`, about 12 MB uncompressed, with no shell and no libc in the runtime layer.
