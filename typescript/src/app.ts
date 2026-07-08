import express from "express";
import { safeFetch } from "./safeFetch.js";

/**
 * Builds the Express app. Exported (instead of listening immediately) so the
 * tests can drive it with supertest without opening a real socket.
 */
export function createApp() {
  const app = express();
  app.use(express.json());

  // POST /downloads  { "fileUrl": "https://..." }
  app.post("/downloads", async (req, res) => {
    const fileUrl = (req.body ?? {}).fileUrl;

    if (typeof fileUrl !== "string" || fileUrl.length === 0) {
      return res.status(400).json({ error: "fileUrl is required" });
    }

    try {
      const body = await safeFetch(fileUrl);
      return res.status(200).json({ ok: true, size: body.length });
    } catch (err) {
      // Any rejection from safeFetch (SSRF, oversize, timeout) => 400.
      return res.status(400).json({ error: (err as Error).message });
    }
  });

  return app;
}
