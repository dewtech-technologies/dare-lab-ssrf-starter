import { lookup } from "node:dns/promises";

/**
 * Hard limits the hardened implementation must enforce.
 * They are already wired into the tests — do not rename them.
 */
export const MAX_BYTES = 1 * 1024 * 1024; // 1 MiB
export const MAX_REDIRECTS = 2;
export const TIMEOUT_MS = 5000;

/** Thrown when a request is rejected for SSRF / policy reasons. */
export class SsrfError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "SsrfError";
  }
}

/**
 * TODO (student): return true for any IP an attacker could use to reach
 * internal infrastructure. You MUST cover, at minimum:
 *
 *   IPv4:
 *     - 127.0.0.0/8      (loopback)
 *     - 10.0.0.0/8       (private)
 *     - 172.16.0.0/12    (private)
 *     - 192.168.0.0/16   (private)
 *     - 169.254.0.0/16   (link-local, INCLUDING 169.254.169.254 cloud metadata!)
 *
 *   IPv6:
 *     - ::1              (loopback)
 *     - fc00::/7         (unique local)
 *     - fe80::/10        (link-local)
 *
 * The naive version below blocks nothing.
 */
export function isBlockedIp(_ip: string): boolean {
  // TODO: implement the checks above.
  return false;
}

/**
 * NAIVE, VULNERABLE implementation. It happily fetches whatever URL it is
 * given — attacker-controlled hosts, private IPs, redirects to the metadata
 * service, unbounded response bodies. Harden it until the security specs pass.
 *
 * Requirements to make the tests green:
 *   1. Only allow the `https:` protocol (reject http:, file:, gopher:, ...).
 *   2. Resolve the host with `lookup()` and reject when `isBlockedIp(address)`.
 *   3. Follow at most MAX_REDIRECTS redirects, RE-VALIDATING the host of every
 *      hop (an allowed host can 302 you to http://169.254.169.254).
 *   4. Enforce MAX_BYTES on the response body and TIMEOUT_MS on the request.
 *
 * Throw `SsrfError` (or any Error) when a request must be blocked.
 */
export async function safeFetch(rawUrl: string): Promise<Buffer> {
  // TODO: parse rawUrl and enforce protocol === "https:".
  // TODO: resolve the host and reject blocked IPs.
  // TODO: fetch with manual redirect handling (revalidate each hop).
  // TODO: enforce size + timeout while reading the body.

  const res = await fetch(rawUrl);
  const buf = Buffer.from(await res.arrayBuffer());
  return buf;
}
