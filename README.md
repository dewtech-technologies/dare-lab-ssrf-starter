# DARE Lab Starter — Secure a Download Endpoint Against SSRF

Starter project for the DARE Labs lab **[Secure a Download Endpoint Against SSRF](https://darelabs.tech/labs/secure-a-download-endpoint-against-ssrf)**.

Pick your stack, then complete the lab by making the failing tests pass. The goal is the
same in every language: harden a naive `POST /downloads` endpoint that fetches a
user-supplied URL. You must block SSRF — reject non-HTTPS, private/loopback/link-local
IPs (incl. the cloud metadata address `169.254.169.254`), re-validate the host across
redirects, and enforce a size + timeout cap. The tests define the target behavior — they
start red; make them green.

| Stack | Folder | Run |
|-------|--------|-----|
| Ruby / Rails | [`rails/`](rails/) | `bundle install && bundle exec rspec` |
| Python / FastAPI | [`python/`](python/) | `pip install -r requirements.txt && pytest` |
| TypeScript / Node | [`typescript/`](typescript/) | `npm install && npm test` |

Each folder has its own README with details. You only need to complete **one** stack.

---
Part of [DARE Labs](https://darelabs.tech) — learn AI-assisted engineering with the DARE method.
