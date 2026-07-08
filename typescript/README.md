# Secure a Download Endpoint Against SSRF — TypeScript starter

Incomplete starter. You finish it by making the failing tests pass.

Lab: https://darelabs.tech/labs/secure-a-download-endpoint-against-ssrf

> This is the **TypeScript (Node + Express)** variant. There are also `rails/`
> and `python/` variants of the same lab.

## The endpoint

`POST /downloads` with a JSON body `{ "fileUrl": "https://..." }`. The route
downloads the URL through `safeFetch(url)` and answers `200 { ok, size }` or
`400 { error }`.

In the starting state `safeFetch` is **naive** and vulnerable to SSRF: it fetches
whatever URL it is handed. Your job is to harden it.

## Setup

```bash
npm install
npm test        # vitest run
```

The security specs **fail** on the starter; the happy-path spec passes. No test
touches the real network — DNS and `fetch` are mocked.

## Your task

Harden `src/safeFetch.ts` until every spec is green:

1. **Protocol allow-list** — only `https:` is allowed.
2. **Block internal IPs** — implement `isBlockedIp(ip)` for loopback / private /
   link-local ranges: `127.0.0.0/8`, `10.0.0.0/8`, `172.16.0.0/12`,
   `192.168.0.0/16`, `169.254.0.0/16` (including the cloud metadata address
   `169.254.169.254`), plus IPv6 `::1`, `fc00::/7`, `fe80::/10`. Resolve the
   host with `lookup()` and reject when the resolved address is blocked.
3. **Safe redirects** — follow at most `MAX_REDIRECTS` (2) redirects, and
   **re-validate the host of every hop** (an allowed host can 302 you to a
   private one).
4. **Bounds** — enforce `MAX_BYTES` on the body and `TIMEOUT_MS` on the request.

## Done criteria

`npm test` is fully green — all SSRF specs plus the happy path — without
loosening or deleting the assertions in `test/ssrf.test.ts`.

## Layout

- `src/safeFetch.ts` — the function you harden (naive, with TODOs).
- `src/app.ts` — Express app and the `POST /downloads` route.
- `src/server.ts` — optional local runner (`npm run build && npm start`).
- `test/ssrf.test.ts` — the specs you must satisfy.
