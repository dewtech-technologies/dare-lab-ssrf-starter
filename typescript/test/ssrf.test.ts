import { describe, it, expect, beforeEach, vi } from "vitest";
import request from "supertest";

/**
 * ---------------------------------------------------------------------------
 * NO REAL NETWORK. Everything below is stubbed:
 *   - `node:dns/promises` lookup() -> a controllable in-memory map.
 *   - global `fetch`             -> a controllable per-test responder.
 * ---------------------------------------------------------------------------
 */

// Map of hostname -> IP the hardened code will "resolve".
const dnsMap = new Map<string, string>();

vi.mock("node:dns/promises", () => ({
  lookup: async (host: string) => {
    const address = dnsMap.get(host);
    if (!address) throw new Error(`no mock DNS entry for ${host}`);
    return { address, family: address.includes(":") ? 6 : 4 };
  },
}));

// Per-test fetch behaviour.
let fetchImpl: (url: string, init?: unknown) => Promise<Response>;

beforeEach(() => {
  dnsMap.clear();
  fetchImpl = async () => new Response("default", { status: 200 });
  vi.stubGlobal("fetch", (url: unknown, init?: unknown) =>
    fetchImpl(String(url), init),
  );
});

// Imported AFTER the vi.mock above (which vitest hoists) so app.ts picks up
// the mocked dns module.
import { createApp } from "../src/app.js";

const app = createApp();

describe("POST /downloads — SSRF hardening", () => {
  // --- security specs: FAIL on the naive starter, PASS once hardened ---

  it("rejects non-https (http) URLs", async () => {
    dnsMap.set("safe.example.com", "93.184.216.34");
    fetchImpl = async () => new Response("secret", { status: 200 });

    const res = await request(app)
      .post("/downloads")
      .send({ fileUrl: "http://safe.example.com/file" });

    expect(res.status).toBe(400);
  });

  it("rejects a host that resolves to loopback 127.0.0.1", async () => {
    dnsMap.set("evil.example.com", "127.0.0.1");
    fetchImpl = async () => new Response("secret", { status: 200 });

    const res = await request(app)
      .post("/downloads")
      .send({ fileUrl: "https://evil.example.com/file" });

    expect(res.status).toBe(400);
  });

  it("rejects a host that resolves to a private 10.0.0.5", async () => {
    dnsMap.set("evil.example.com", "10.0.0.5");

    const res = await request(app)
      .post("/downloads")
      .send({ fileUrl: "https://evil.example.com/file" });

    expect(res.status).toBe(400);
  });

  it("rejects the cloud metadata IP 169.254.169.254", async () => {
    dnsMap.set("metadata.example.com", "169.254.169.254");

    const res = await request(app)
      .post("/downloads")
      .send({ fileUrl: "https://metadata.example.com/latest/meta-data/" });

    expect(res.status).toBe(400);
  });

  it("rejects a redirect that points at a private host", async () => {
    dnsMap.set("safe.example.com", "93.184.216.34");
    dnsMap.set("internal.example.com", "10.0.0.5");

    fetchImpl = async (url) => {
      if (url.includes("safe.example.com")) {
        return new Response(null, {
          status: 302,
          headers: { location: "https://internal.example.com/file" },
        });
      }
      return new Response("secret", { status: 200 });
    };

    const res = await request(app)
      .post("/downloads")
      .send({ fileUrl: "https://safe.example.com/file" });

    expect(res.status).toBe(400);
  });

  it("cuts off a response larger than the size limit", async () => {
    dnsMap.set("safe.example.com", "93.184.216.34");
    const big = "x".repeat(2 * 1024 * 1024); // 2 MiB > MAX_BYTES (1 MiB)
    fetchImpl = async () => new Response(big, { status: 200 });

    const res = await request(app)
      .post("/downloads")
      .send({ fileUrl: "https://safe.example.com/big.bin" });

    expect(res.status).toBe(400);
  });

  // --- happy path: passes even on the naive starter ---

  it("downloads a small file from an allowed host", async () => {
    dnsMap.set("safe.example.com", "93.184.216.34");
    fetchImpl = async () => new Response("hello", { status: 200 });

    const res = await request(app)
      .post("/downloads")
      .send({ fileUrl: "https://safe.example.com/hello.txt" });

    expect(res.status).toBe(200);
    expect(res.body.size).toBe(5);
  });
});
