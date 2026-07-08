# Secure a Download Endpoint Against SSRF — Starter

Starter for the DARE Labs lab: [Secure a Download Endpoint Against SSRF](https://darelabs.tech/labs/secure-a-download-endpoint-against-ssrf).

This is an **incomplete** starter repository. The `SafeFetch` class currently
does a **naive** HTTP GET that follows anything you point it at — it is
vulnerable to **Server-Side Request Forgery (SSRF)**. Your job is to harden it
until the security specs pass.

## Objective

Turn the naive URL fetcher into a safe one:

- **HTTPS only** — reject `http://` and any non-`https` scheme.
- **Block private / internal IPs** — resolve the host via DNS and refuse to
  connect if it points at a blocked range:
  - `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16` (private)
  - `127.0.0.0/8` (loopback)
  - `169.254.0.0/16` (link-local — **includes `169.254.169.254`, the cloud
    metadata endpoint!**)
  - IPv6: `::1` (loopback), `fc00::/7` (unique-local), `fe80::/10` (link-local)
- **Limit redirects** — follow at most **2** redirects, re-validating the host
  (scheme + IP) on every hop.
- **Impose limits** — enforce a **maximum download size** and a **timeout**.

## How to run

```bash
bundle install
bundle exec rspec
```

## What is incomplete

`lib/safe_fetch.rb` contains the naive fetcher with `# TODO:` markers where each
protection must be added, plus an empty `private_ip?(ip)` helper. As shipped, the
security specs **fail** because nothing is blocked. The "downloads a small file"
spec already passes.

## Completion criteria

You are done when **all specs are green**:

```bash
bundle exec rspec
```

No real network access is used — every response is stubbed with WebMock and DNS
is stubbed with `Resolv`.
