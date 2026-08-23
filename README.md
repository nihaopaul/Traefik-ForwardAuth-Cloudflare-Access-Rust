# Traefik Forward Auth for Cloudflare Access

A small service that lets **Traefik** enforce **Cloudflare Zero Trust** access rules on any route it serves.

Cloudflare Access puts a login screen in front of your apps and sends a signed JWT in the `Cf-Access-Jwt-Assertion` header and `CF_Authorization` cookie. Traefik can't check that JWT by itself. This service does: Traefik asks it about every request, and it answers `200` (allow) or `403` (deny). Works with Traefik 2.x and 3.x.

> Originally attempted as a native Traefik plugin, but Traefik's WASM support follows the R1 spec and is too limited. This is a Rust port of [Traefik-ForwardAuth-Cloudflare-Access](https://github.com/nihaopaul/Traefik-ForwardAuth-Cloudflare-Access).

## How it works

1. A user hits your app. Traefik pauses the request and asks this service `GET /auth`, forwarding the request credentials.
2. The service prefers the `Cf-Access-Jwt-Assertion` header and falls back to the `CF_Authorization` cookie. No token → `403`, and Cloudflare shows the login page.
3. It verifies the JWT signature and issuer against your team's public keys and domain, requires a Cloudflare Access application token (`type: app`), and checks the token was issued for one of *your* applications (its `aud`).
4. Valid → `200` and Traefik serves the request. Anything else → `403`.

Cloudflare Access identities may come from an interactive user (`email`) or a service token (`common_name`). Both are accepted after the same signature, issuer, application-token, expiry, and audience checks.

It keeps itself current in the background, so you don't restart it when things change in Cloudflare:

- **Public keys** refresh every 24 hours (Cloudflare rotates them).
- **Application list** refreshes every hour (so new apps start working on their own).

Nothing is stored on disk and no state is kept between requests.

On startup, the service loads both the signing keys and the complete self-hosted application list before opening its listening port. If either initial fetch fails, startup fails instead of briefly serving an empty configuration. Later refresh failures keep the last complete version.

## Quick start

```yaml
services:
  forward-auth-rust:
    image: nihaopaul/forward-auth-rust:0.6.0
    restart: unless-stopped
    environment:
      CF_DOMAIN: https://yourteam.cloudflareaccess.com
      CF_ORG: your-cloudflare-account-id
      CF_TOKEN: your-read-only-api-token
      PORT: '9001'
    expose:
      - '9001'
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

## Bind routes to Cloudflare applications

Set `X-Auth-Audience` in Traefik immediately before ForwardAuth to validate a route against one Cloudflare Access application. In the default `any_app` mode, routes without this header continue using the discovered application catalog, so routes can be migrated one at a time. `per_app` mode requires every request to have exactly one valid binding and never loads the catalog.

The header is a trusted internal control, not client input. Strip any client-supplied value with an entrypoint middleware that runs before router middlewares:

```yaml
# Static Traefik configuration
entryPoints:
  websecure:
    address: ":443"
    http:
      middlewares:
        - strip-auth-audience@file
```

Then define the global stripping middleware, a per-application setter, and the shared ForwardAuth middleware in dynamic configuration:

```yaml
http:
  middlewares:
    strip-auth-audience:
      headers:
        customRequestHeaders:
          X-Auth-Audience: "" # remove untrusted client input

    dashboard-audience:
      headers:
        customRequestHeaders:
          X-Auth-Audience: "<dashboard-application-aud>"

    cf-auth:
      forwardAuth:
        address: "http://forward-auth-rust:9001/auth"

  routers:
    dashboard:
      rule: Host(`traefik.example.com`)
      service: api@internal
      entryPoints:
        - websecure
      middlewares:
        - dashboard-audience@file # set the trusted route binding first
        - cf-auth@file            # ForwardAuth receives that binding
```

[Traefik prepends entrypoint middlewares](https://doc.traefik.io/traefik/reference/install-configuration/entrypoints/#httpmiddlewares) to each router's middleware list, and its [Headers middleware](https://doc.traefik.io/traefik/reference/routing-configuration/http/middlewares/headers/#configuration-options) removes a request header when configured with an empty value. Per-application setters overwrite the stripped value before ForwardAuth. If `authRequestHeaders` is configured on ForwardAuth, include `X-Auth-Audience`, `Cf-Access-Jwt-Assertion`, and `Cookie`; leaving it unset forwards all request headers.

Keep the auth service reachable only from Traefik's private network. A caller that can reach it directly can supply the trusted header. Never derive the audience from `X-Forwarded-Uri`, the original query string, host, or another client-controlled value.

The header must occur exactly once, contain 1–256 non-whitespace characters, and contain no comma. Its value is checked directly against the signed JWT without requiring catalog membership, so catalog refreshes cannot break a bound route and a typo fails closed.

For a fully bound deployment, remove the Applications API credentials and enable strict mode:

```yaml
environment:
  CF_AUTHORIZATION_MODE: per_app
  CF_DOMAIN: https://yourteam.cloudflareaccess.com
```

## Configuration

| Variable | Required | Description |
| --- | --- | --- |
| `CF_DOMAIN` | yes | Your Zero Trust team domain, including `https://` — the hostname where Cloudflare shows your login page. |
| `CF_AUTHORIZATION_MODE` | no | `any_app` (default) permits catalog-backed unbound routes; `per_app` requires every route to supply a trusted audience binding. Other values fail startup. |
| `CF_ORG` | `any_app` only | Your Cloudflare **account ID** — the value in your dashboard URL, `https://dash.cloudflare.com/{account-id}`. Never read in `per_app`. |
| `CF_TOKEN` | `any_app` only | API token with **Account → Access: Apps and Policies → Read**. Never read or used in `per_app`. |
| `PORT` | no | Port to listen on. Defaults to `3000`. |

The service listens on `0.0.0.0` and exposes a single endpoint, `GET /auth`.

## Notes

**Bind sensitive routes.** By default, unbound routes accept a valid application token for any discovered Cloudflare Access app. Bind a route by having Traefik set its trusted `X-Auth-Audience`, or use `CF_AUTHORIZATION_MODE=per_app` to require every route to be bound. A fully bound deployment needs no Cloudflare API token. Cloudflare evaluates each application's policies; this service validates the resulting app-specific token.

**Expiry allows normal clock skew.** JWT expiration uses jsonwebtoken's 60-second leeway, so `expired_token` is logged only after a token is more than 60 seconds past its `exp` value.

**Denials are diagnosable without leaking credentials.** The service logs stable reason codes for rejected requests. Detailed denial events are limited per reason, with suppressed-event summaries, and tokens, cookies, signing keys, identities, and full claims are never logged.

**Runs on x86 and ARM.** Images are published for `linux/amd64` and `linux/arm64` under a single tag, so `docker pull` fetches the right one for your host — no `platform:` override needed on a Raspberry Pi, an Ampere VPS, or Apple silicon. (Releases before 0.4.1 were amd64 only.)

**Pin a version.** The example uses `:0.6.0` rather than `:latest` so an unattended `docker compose pull` can't change what you're running.

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
