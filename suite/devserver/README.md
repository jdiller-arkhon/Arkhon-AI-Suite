# arkhon-suite-dev

Runs the suite prototype against the **real engine** on this computer.

```bash
cargo run -p arkhon-suite-dev            # http://127.0.0.1:4317/dashboard.html#people
cargo run -p arkhon-suite-dev -- --reset # start over with the example company
```

- Data is saved to `.arkhon-dev/org.json` (git-ignored) with atomic writes.
- **View as** (top of Company settings) switches the acting person, so you can check what each role can see and do.
  - This is development-only identity, sent in the `x-arkhon-as` header.
  - The desktop app uses the signed-in local session instead.
- **Security:**
  - binds to `127.0.0.1` only;
  - checks the `Host` header, which blocks DNS rebinding;
  - rejects foreign `Origin` headers;
  - requires JSON plus a custom header on writes, so no cross-site form can trigger them;
  - sends `no-store`, `nosniff` and `DENY` framing headers.
- `--dump-view` prints the engine snapshot embedded in `dashboard.html` for the static preview. A test fails if the two drift apart.

API: `GET /api/view`, `POST /api/command`, `GET /api/activity`, `GET /api/people`. See `src/lib.rs`.
