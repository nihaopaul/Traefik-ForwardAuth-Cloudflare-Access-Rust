# Traefik Forward Auth for Cloudflare Access

A small service that lets **Traefik** enforce **Cloudflare Zero Trust** access rules on any route it serves.

Cloudflare Access puts a login screen in front of your apps and sends a signed JWT in the `Cf-Access-Jwt-Assertion` header and `CF_Authorization` cookie. Traefik can't check that JWT by itself. This service does: Traefik asks it about every request, and it answers `200` (allow) or `403` (deny). Works with Traefik 2.x and 3.x.

> Originally attempted as a native Traefik plugin, but Traefik's WASM support follows the R1 spec and is too limited. This is a Rust port of [Traefik-ForwardAuth-Cloudflare-Access](https://github.com/nihaopaul/Traefik-ForwardAuth-Cloudflare-Access).

## How it works

1. A user hits your app. Traefik pauses the request and asks this service `GET /auth`, forwarding the request credentials.
2. The service prefers the `Cf-Access-Jwt-Assertion` header and falls back to the `CF_Authorization` cookie. No token → `403`, and Cloudflare shows the login page.
3. It verifies the JWT signature and issuer against your team's public keys and domain, requires a Cloudflare Access application token (`type: app`), and checks the token's `aud` against the application bound to that Traefik route.
4. Valid → `200` and Traefik serves the request. Anything else → `403`.

Cloudflare Access identities may come from an interactive user (`email`) or a service token (`common_name`). Both are accepted after the same signature, issuer, application-token, expiry, and audience checks.

It refreshes Cloudflare's public signing keys every 24 hours, so key rotation does not require a restart. The recommended `per_app` setup makes no Cloudflare Applications API requests.

Nothing is stored on disk and no state is kept between requests.

On startup, the service loads the signing keys before opening its listening port. If the initial fetch fails, startup fails instead of briefly serving an unusable configuration. Later refresh failures keep the last complete version.

## Quick start

```yaml
services:
  forward-auth-rust:
    image: nihaopaul/forward-auth-rust:0.6.0
    restart: unless-stopped
    environment:
      CF_AUTHORIZATION_MODE: per_app
      CF_DOMAIN: https://yourteam.cloudflareaccess.com
      PORT: '9001'
    expose:
      - '9001'
    deploy:
      resources:
        limits:
          cpus: '1'
          memory: 50M
```

The recommended `per_app` mode requires every protected route to identify its Cloudflare Access application. Set `X-Auth-Audience` in Traefik immediately before ForwardAuth, using the application's AUD from the Cloudflare Zero Trust dashboard.

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

Define the global stripping middleware, a per-application setter, and the shared ForwardAuth middleware in dynamic configuration:

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

The header must occur exactly once, contain 1–256 non-whitespace characters, and contain no comma. Its value is checked directly against the signed JWT without requiring catalog membership, so a typo fails closed.

## Configuration

| Variable | Required | Description |
| --- | --- | --- |
| `CF_DOMAIN` | yes | Your Zero Trust team domain, including `https://` — the hostname where Cloudflare shows your login page. |
| `CF_AUTHORIZATION_MODE` | yes for new deployments | Set to `per_app`. If omitted, the service uses legacy `any_app` only for backward compatibility. Other values fail startup. |
| `PORT` | no | Port to listen on. Defaults to `3000`. |

The service listens on `0.0.0.0` and exposes a single endpoint, `GET /auth`.

## Legacy approach: catalog-backed `any_app`

> **Not recommended for new deployments.** This mode exists for backward compatibility and route-by-route migration. It accepts a valid application token for any self-hosted Cloudflare Access application discovered in the account when a route has no explicit audience binding.

Legacy deployments omit `CF_AUTHORIZATION_MODE` or set it to `any_app`, and require Cloudflare Applications API credentials:

| Legacy variable | Required | Description |
| --- | --- | --- |
| `CF_ORG` | yes | Your Cloudflare **account ID** — the value in the dashboard URL, `https://dash.cloudflare.com/{account-id}`. |
| `CF_TOKEN` | yes | API token with **Account → Access: Apps and Policies → Read**. Read-only is enough. |

```yaml
services:
  forward-auth-rust:
    image: nihaopaul/forward-auth-rust:0.6.0
    environment:
      CF_AUTHORIZATION_MODE: any_app
      CF_DOMAIN: https://yourteam.cloudflareaccess.com
      CF_ORG: your-cloudflare-account-id
      CF_TOKEN: your-read-only-api-token
      PORT: '9001'
```

An unbound legacy middleware needs only ForwardAuth:

```yaml
http:
  middlewares:
    cf-auth:
      forwardAuth:
        address: "http://forward-auth-rust:9001/auth"
```

In `any_app`, the service loads the complete self-hosted application catalog before binding its listener and refreshes it hourly. Initial catalog failure aborts startup; later failures retain the last complete catalog. `CF_ORG` and `CF_TOKEN` remain mandatory even if some routes are explicitly bound, because other routes may still need catalog fallback.

To migrate without a flag day, add the trusted `X-Auth-Audience` middleware to routes one at a time while still using `any_app`. Once every protected route is bound, switch to `per_app` and remove `CF_ORG` and `CF_TOKEN`.

## Notes

**Bind every protected route.** `per_app` needs no Cloudflare API token and prevents one application's token from being accepted through another application's route. Cloudflare evaluates each application's policies; this service validates the resulting app-specific token.

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
