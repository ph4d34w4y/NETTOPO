[CONTRIBUTING.md](https://github.com/user-attachments/files/30516114/CONTRIBUTING.md)
# Contributing to NetTopo

Thanks for your interest in improving NetTopo. This is a network-security analysis tool, so contributions are held to one guiding principle above all:

> **A wrong permit/deny verdict is worse than no answer.** Correctness and honesty about approximations matter more than breadth. Every change that touches analysis logic must come with tests that assert *known-correct* verdicts.

Please read this whole document before opening a pull request.

---

## Table of contents

- [Guiding principles](#guiding-principles)
- [Project layout](#project-layout)
- [Development setup](#development-setup)
- [Running the tests](#running-the-tests)
- [The build/inject step](#the-buildinject-step)
- [Adding a vendor](#adding-a-vendor)
- [Coding conventions](#coding-conventions)
- [Security & privacy requirements](#security--privacy-requirements)
- [Pull request checklist](#pull-request-checklist)
- [Reporting bugs & requesting vendors](#reporting-bugs--requesting-vendors)
- [Third-party components](#third-party-components)

---

## Guiding principles

1. **Verifiable correctness.** Analysis changes need unit or end-to-end tests with expected verdicts you can defend. If you can't state the correct answer for a test case, don't guess in the code.
2. **Honesty about limits.** When a rule references something the engine can't resolve, flag the result as *uncertain* rather than assuming permit or deny. When a vendor format is only partially modeled, say so in code comments and in the README's limitations.
3. **No silent over-permitting.** If a modeling shortcut could make traffic look *more* reachable than it really is, prefer the conservative interpretation or flag it — over-permitting hides risk.
4. **Offline & self-contained.** NetTopo must keep running as a single HTML file with no network calls. Don't add runtime dependencies on external services or CDNs.

## Project layout

NetTopo ships as one self-contained `nettopo.html`, but it is **developed from separate source files** and assembled by an injection step. A typical repo layout:

```
nettopo.html                 # distributable build (engine injected, libs inlined)
package.json                 # scripts: inject, check, test:engine, test:browser, test, serve
src/
  reach-engine.js            # standalone, Node-testable reachability engine
  pfsense-reach.js           # pfSense rule extractor (DOMParser; browser-only)
  inject.js                  # assembles the engine block into nettopo.html
  serve.js                   # static server (serves repo root) for browser tests
tests/
  check-syntax.js            # parses every inline <script> block (acorn)
  runtest.sh                 # starts the server, runs one browser suite, tears down
  engine/reach-test*.js      # engine unit tests (run directly in Node)
  browser/*.js               # Puppeteer end-to-end tests
  browser/_chrome.js         # locates a Chrome/Chromium (honors $CHROME_PATH)
  fixtures/                  # sample configs & flow files used by tests
  screenshots/               # test-generated artifacts (gitignored)
libs/
  d3.min.js                  # D3 v7 (ISC) — inlined into the build
  xlsx.full.min.js           # SheetJS CE (Apache-2.0) — inlined into the build
docs/
  DEVELOPMENT.md             # developer setup & commands
  *.png                      # screenshots used by the README
```

> If your clone only contains `nettopo.html`, ask the maintainer for the split source and test files — editing the giant build output directly is error-prone and not how the analysis is maintained or tested.

The **per-vendor config parsers**, the **audit engine**, the **D3 renderer**, and the **analysis panels** (reachability, attack sim, segmentation, intent-vs-reality, drift, NERC-CIP) live in inline `<script>` blocks inside `nettopo.html`. The **reachability engine** is authored in `src/reach-engine.js` and injected into the HTML so the same code can be unit-tested in Node.

## Development setup

Requirements:

- **Node.js** (18+) for running tests and the inject step.
- **A Chromium build** for Puppeteer-based browser tests (`puppeteer-core` + a local Chrome).
- No framework, bundler, or package build — the app is plain HTML/JS.

```bash
npm install            # dev dependencies: acorn (syntax check), puppeteer-core
```

## Running the tests

**Engine unit tests** run directly in Node (fast, no browser):

```bash
node tests/engine/reach-test.js   # core reachability
node tests/engine/reach-test4.js  # IPv6, Palo Alto, Arista, source NAT
# ...or: npm run test:engine
```

**Browser end-to-end tests** use the shared server + Puppeteer via the helper:

```bash
./tests/runtest.sh tests/browser/e2e.js
./tests/runtest.sh tests/browser/reachui-test.js
# ...or: npm run test:browser
# ...
```

> Use `runtest.sh` rather than backgrounding the server manually — plain `&` backgrounding races the server startup and produces flaky failures.

**Before every commit that changes JS**, run a syntax check on all inline blocks. The build must parse cleanly:

```bash
# parse each inline <script> block with acorn; must report 0 errors
node tests/check-syntax.js   # or: npm run check
```

A change is not ready until **every** engine unit test and **every** browser suite passes.

## The build/inject step

The reachability engine is the single source of truth. After editing `src/reach-engine.js`:

1. Run the inject step to regenerate the engine block inside `nettopo.html`.
2. Re-run the syntax check and the full test suite.
3. **Verify the file renders when opened directly** (see below).

### Always verify a direct `file://` render

A subtle failure mode is producing an HTML file that passes JS tests through a local server but **fails when opened directly** (e.g. CSS leaking as text from a malformed `<style>` block, or CDN scripts blocked by CORS on a `file://` origin). Before you push:

- Open `nettopo.html` directly in a browser (double-click / `file://`), not just through the test server.
- Confirm the header renders (no raw CSS visible), the graph draws with sample data, and the console is error-free.
- Confirm the HTML tags balance (`<style>`/`</style>`, `<body>`/`</body>`, `<html>`/`</html>` each appear once **outside** script contents) and there are **zero** `cdnjs`/external `<script src>` references.

This check has caught real regressions; treat it as mandatory.

## Adding a vendor

Adding support for a new device requires four coordinated pieces plus tests:

1. **Engine rule extractor** in `src/reach-engine.js` — `rulesYourVendor(text)` that returns the normalized model:
   ```js
   {
     rules: [ { action, proto, src, dst, dports, from, to, raw, seq } ],
     acls?: { NAME: [rules] },        // if the vendor binds ACLs to interfaces
     bindings?: [ { acl, dir, zone } ],
     nat?: { dnat: [...], snat: [...] },
     secLevels?, sameSecInter?,        // ASA-style, if applicable
     defaultAction: 'deny' | 'permit',
     zoneScoped: boolean
   }
   ```
   Resolve address/service objects and groups (recursively, with a cycle guard). Where something can't be resolved, mark it so the evaluator returns `uncertain` rather than a false verdict.

2. **App parser** `parseYourVendor(text, fname)` (inline in `nettopo.html`) — produces the topology/detail model: `name`, `ifaces` (`{name, ip, bits, zone}`), `acls` (counts), `aclSamples`, `vlans` if relevant, etc.

3. **Audit function** `auditYourVendor(text, dev)` — vendor-appropriate findings (telnet/HTTP mgmt, default SNMP, overly-permissive rules, etc.).

4. **Classifier detection** in the parse dispatcher — order it carefully so it doesn't collide with a similar vendor (e.g. IOS-like OT switches must be distinguished from Cisco). Wire `d.reach = rulesYourVendor(text)`, `d.findings = auditYourVendor(...)`.

5. **Tests** — at minimum:
   - Engine unit tests with several known-verdict cases (permit, explicit deny, implicit deny, port mismatch, zone/binding behavior, object resolution).
   - A browser test asserting the config classifies as your vendor and reachability returns the expected verdicts.

**Be honest about format fidelity.** Many vendor formats (especially OT/ICS) are proprietary and variable. Target common/representative patterns, note in comments what you did and didn't cover, and add the vendor to the README's supported list with any caveats.

## Coding conventions

- **Plain ES2020+ JavaScript.** No TypeScript, no build tooling, no frameworks.
- **No runtime dependencies** beyond the two inlined libraries. Don't add `import`/`require` of external packages into the app.
- **Escape all user/config content** before inserting into the DOM (use the existing `esc()`/`escH` helpers). Config text is untrusted input.
- **Guard CSV/spreadsheet exports** against formula injection (the existing exporters do this — match the pattern).
- Keep functions small and the rule IR consistent; the evaluator assumes the shapes documented above.
- Match the surrounding style (2-space indent, terse helpers). This isn't a linted codebase; readability and correctness are what matter.

## Security & privacy requirements

Because NetTopo is run against sensitive firewall configurations, contributions **must not** weaken its privacy posture:

- **No network egress.** Don't add `fetch`/`XHR`/WebSocket calls, telemetry, analytics, or external asset loads. The Content-Security-Policy (`default-src 'none'`, `connect-src 'none'`) must remain intact.
- **No CDNs.** Libraries stay inlined; don't reintroduce `<script src="https://...">`.
- **No persistence of config data** to disk/`localStorage`/cookies. In-memory state only.
- Treat all parsed input as untrusted and escape it on output.

PRs that violate these will not be merged regardless of feature value.

## Pull request checklist

Before opening a PR, confirm:

- [ ] All engine unit tests pass.
- [ ] All browser end-to-end suites pass.
- [ ] Syntax check reports 0 errors on every inline block.
- [ ] `nettopo.html` renders correctly opened directly via `file://` (no CSS leak, graph draws, console clean).
- [ ] HTML tags balance and there are no external `<script src>` / CDN references.
- [ ] New/changed analysis logic has tests with **known-correct verdicts**.
- [ ] New approximations or partial vendor support are documented (code comments + README limitations).
- [ ] The privacy/CSP posture is unchanged.

In the PR description, state what you changed, why the test verdicts are correct, and any modeling shortcuts or known gaps.

## Reporting bugs & requesting vendors

When filing an issue:

- **For a wrong verdict:** include a *minimal, sanitized* config snippet, the query (src/dst/proto/port), the verdict you got, and the verdict you expected with a one-line justification. **Redact real addresses and any sensitive details** — never paste production configs into a public issue.
- **For a new vendor:** describe the format and, ideally, provide a small sanitized sample plus the expected reachability for a couple of flows.
- **For a parse failure:** include the smallest config fragment that reproduces it.

## Third-party components

NetTopo inlines two permissively-licensed libraries; retain their notices:

- **D3.js** — ISC License — https://github.com/d3/d3
- **SheetJS Community Edition (xlsx)** — Apache License 2.0 — https://sheetjs.com

When updating an inlined library, update its version note and re-run the full suite (rendering and export paths depend on both).

---

By contributing, you agree that your contributions are licensed under the same terms as the project (see `LICENSE`).
ng CONTRIBUTING.md…]()
