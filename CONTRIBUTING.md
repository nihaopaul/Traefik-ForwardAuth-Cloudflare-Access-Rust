# Contributing

Thanks for looking. This is a small, single-purpose service maintained by one
person in spare time — please read [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) for
what that means in practice. Short version: contributions are welcome, and
nothing here is owed in either direction.

## Before you write code

For a typo, a doc fix, or an obvious one-line bug, just open the pull request.

For anything larger — a new endpoint, a new dependency, a change to how
verification works — **open an issue first**. I would rather talk about it for
five minutes than decline a weekend of your work because it takes the project
somewhere I do not want to maintain.

## Getting set up

All you need is a recent stable Rust toolchain — whatever
[rustup](https://rustup.rs) gives you is fine. The project is edition 2021 and
does not depend on nightly.

```bash
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo build --release --locked --workspace
sh tests/traefik/run.sh
```

Pull request CI runs the first four, which need only the Rust toolchain. The
Traefik integration test starts real containers, so CI runs it on release only,
where it gates the image build. Run it locally when you change the
audience-binding path or the middleware contract it depends on.

### Optional: devbox

If you would rather not manage a toolchain yourself,
[devbox](https://www.jetify.com/devbox) will supply one. It is entirely
optional — nothing in the project requires it.

```bash
devbox shell        # a shell with the toolchain already on PATH
devbox run lint     # fmt + clippy
devbox run test
devbox run build
```

### About the tests

The Rust test suite is hermetic. HTTP calls to Cloudflare are stubbed with
`mockito`, and the JWT tests generate a throwaway RSA keypair at run time, so
you need **no Cloudflare account, no API token, and no network** to run it.

`tests/traefik/run.sh` separately starts a real Traefik instance and a local
auth probe to verify the trusted audience-header middleware chain. It uses no
Cloudflare credentials, but its container images must already exist locally or
be downloadable. This test covers Traefik's header behavior; the Rust tests
separately cover the service's header parsing and authorization-mode behavior.

To try it against real traffic you will need a Zero Trust team domain and a
read-only API token — see the Configuration table in
[README.md](README.md#configuration).

## Layout

| Path | What lives there |
| --- | --- |
| `src/main.rs` | The axum service: reads config from the environment and serves `GET /auth`. |
| `cloudflare-authenticator/` | JWT verification — fetches the JWKS, checks signature and `aud`. |
| `cloudflare-dynamic-config/` | Polls the Cloudflare API for the list of Access apps. |
| `tests/traefik/` | Container integration test for trusted per-route audience binding. |

The two subcrates are workspace members and hold most of the logic and most of
the tests.

## Style

- `cargo fmt --all` and a clippy run clean of warnings are both enforced in
  CI, so run them before you push. Please do not reformat files you are not
  otherwise changing — it buries the actual diff.
- Match the surrounding code. Comments here explain *why* something is done,
  not what the line does — the existing ones are a decent guide.
- New behaviour needs a test. Bug fixes should come with the test that fails
  without the fix.
- Keep the dependency list short. The release image is a statically linked
  musl binary on `distroless/static` at about 12 MB, and I would like it to
  stay that way; a new crate needs to earn its place.

## AI-assisted contributions

These are welcome. I use models on this project myself, so it would be odd to
hold it against you.

Two conditions, and they are the same ones I hold myself to: read the diff and
understand it before you send it, and make sure the tests actually exercise the
change rather than just passing next to it. A pull request you cannot explain
in review is the problem — not the tool that produced it.

The pull request template asks which model you used and its context window.
That is for calibration, not judgement — it tells me what kind of mistakes to
look for.

## Pull requests

Branch off `main` and target `main`. CI builds and tests every PR, and that has
to be green before I will merge.

Recent history uses conventional-commit prefixes (`fix:`, `feat:`, `docs:`,
`ci:`, `chore:`) — follow that if it is natural, but a clear sentence beats a
correctly-prefixed vague one.

A few things that make review quick:

- One concern per PR.
- Say what you tested, and how.
- Do not bump the version in `Cargo.toml`, and do not edit `Cargo.lock` by
  hand. Releases are cut separately (see below).

Dependency bumps are handled by Dependabot, so there is no need to send those.

## Scope

Likely to be accepted: bug fixes, better error messages, test coverage,
hardening of the verification path, docs and deployment examples, build and CI
improvements.

Likely to be declined: anything that turns this into a general-purpose auth
proxy, config-file formats, plugin systems, or features that only make sense
for one person's deployment. The service does one thing — answer `200` or `403`
for Traefik — and the small surface is the point.

Worth an issue before you start: per-application policy evaluation. It is a
real gap (see the first note in the README) but it changes the security model,
so I would want to agree on the shape first.

## Security issues

Do not open a public issue or PR for a vulnerability. Report it privately —
see [SECURITY.md](SECURITY.md).

## Releases

Cutting releases is a maintainer job. Publishing a GitHub release triggers CI
to build and push multi-arch (`amd64` + `arm64`) images to Docker Hub under a
single tag. Tags are bare versions, no `v` prefix — `0.4.1`, not `v0.4.1`.

## Licence

The project is MIT ([LICENSE](LICENSE)). By opening a pull request you agree
your contribution is licensed the same way. There is no CLA.
