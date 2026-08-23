## What this changes

<!-- One or two sentences. If it fixes an issue, say "Fixes #123". -->

## Why

<!-- What was wrong, or what this makes possible. Skip if it is obvious from above. -->

## How it was tested

<!-- Commands you ran, and anything you checked by hand against a real Traefik
     or Cloudflare Access setup. "cargo test" alone is fine for small fixes. -->

## AI assistance

AI-assisted contributions are welcome here — this is not a trick question and
a "yes" counts against nothing. Knowing what wrote the code just helps me
review it properly.

- **Model(s) used:** <!-- e.g. Claude Opus 5, GPT-5.2, none -->
- **Context window:** <!-- e.g. 200k, 1M, not sure -->

If you used a model, please say that you have read the diff yourself and
understand what it does. You are the author of the pull request either way.

## Checklist

- [ ] `cargo fmt --all --check` passes
- [ ] `cargo clippy --workspace --all-targets -- -D warnings` is clean
- [ ] `cargo test --workspace` passes
- [ ] Tests cover the new behaviour, or the bug this fixes
- [ ] No version bump in `Cargo.toml`, and `Cargo.lock` was not hand-edited
- [ ] One concern in this PR

<!-- Not a security fix, right? Vulnerabilities go through the private advisory
     form instead — see SECURITY.md. -->
