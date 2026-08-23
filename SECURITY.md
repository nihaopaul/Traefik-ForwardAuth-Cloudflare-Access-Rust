# Security Policy

## Supported Versions

This project is pre-1.0. There are no long-term support branches, and no
security backports to older releases.

| Version | Supported                         |
| ------- | --------------------------------- |
| 0.4.x   | :white_check_mark: (latest only)  |
| < 0.4   | :x:                               |

Only the most recent release gets fixes. When a newer minor version ships, the
previous one stops being supported the same day — so if you are running this,
plan on tracking the current tag rather than pinning indefinitely.

Once 1.0 lands, this policy will be replaced with real support commitments.
Until then, treat the project as best effort: fixes land when they land, and
there is no response-time guarantee, no coordinated-disclosure timeline, and no
promise that any given report will be acted on.

## Reporting a Vulnerability

Please report vulnerabilities privately through GitHub, using
[Security → Report a vulnerability](https://github.com/nihaopaul/Traefik-ForwardAuth-Cloudflare-Access-Rust/security/advisories/new).

Do not open a public issue for a security problem.

Helpful things to include:

- The version or commit you tested.
- What an attacker can do (e.g. bypass `/auth` and reach a protected route).
- Steps to reproduce, ideally a request that gets a `200` when it should get a `403`.

What to expect:

- Acknowledgement when I get to it. This is a spare-time project, so that may
  take a while; there is no SLA.
- If the report is accepted, the fix goes out in the next release and the
  advisory is published with credit unless you would rather stay anonymous.
- If it is declined, you will get a short explanation of why. You are free to
  disclose publicly at that point.

Out of scope: issues in Cloudflare Access, Traefik, or your own configuration
(for example, running the service on a port that is exposed to the internet
instead of only to Traefik).
