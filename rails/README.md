# Secure a Download Endpoint Against SSRF — Rails variant

A tiny, real Rails API with one endpoint:

```
POST /downloads   { "file_url": "https://example.com/file.pdf" }
```

The endpoint hands `file_url` to `app/services/safe_fetch.rb`, which downloads
the file. **In the starter state `SafeFetch` is naive: it follows any URL it is
given** — a textbook Server-Side Request Forgery (SSRF) sink. Your job is to
harden it.

> Rails variant of this lab. There are also `python/` and `typescript/`
> variants of the same exercise.

Lab page: https://darelabs.tech/labs/secure-a-download-endpoint-against-ssrf

## Setup

```bash
bundle install
bundle exec rspec
```

No real network is used — the specs stub HTTP with WebMock and DNS with
`Resolv`. Everything runs offline.

## What is incomplete

`app/services/safe_fetch.rb` has 5 `TODO`s. In the initial state it:

- follows `http://` (and any other scheme), not just `https://`
- never resolves the host, so DNS can point a public-looking name at internal
  addresses (`127.0.0.1`, `10.0.0.5`, `169.254.169.254` — the cloud metadata
  endpoint, ...)
- follows redirects without re-checking the target host
- reads the whole response body into memory with no size cap

`private_ip?(ip)` is a stub that always returns `false`.

## Your task

Make the security specs in `spec/requests/downloads_spec.rb` pass **without
weakening them**, while keeping the happy-path spec green:

1. Accept only `https://`.
2. Resolve the host with `Resolv.getaddresses` and reject if **any** address is
   private/loopback/link-local:
   - IPv4: `127.0.0.0/8`, `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`,
     `169.254.0.0/16`
   - IPv6: `::1/128`, `fc00::/7`, `fe80::/10`
3. Allow at most `MAX_REDIRECTS` (2) redirects, re-running checks 1 and 2 on
   every redirect target.
4. Enforce `MAX_BYTES` and the request timeouts.

## Success criterion

`bundle exec rspec` is all green — the happy path downloads, and every SSRF
attempt (bad scheme, private/loopback/link-local IP, metadata address, redirect
to a private host, oversized file) returns HTTP 422.
