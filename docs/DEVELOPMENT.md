# Development notes

## Layout
- `nettopo.html` — the distributable build. Ship this. It has the reachability
  engine injected and D3 + SheetJS inlined, so it runs offline from `file://`.
- `src/reach-engine.js` — canonical reachability engine (Node-testable).
- `src/pfsense-reach.js` — pfSense extractor (browser-only; uses DOMParser).
- `src/inject.js` — rebuilds the engine block inside `nettopo.html` from the above.
- `src/serve.js` — static server (repo root) for browser tests.
- `tests/engine/` — Node unit tests for the engine (fast, no browser).
- `tests/browser/` — Puppeteer end-to-end tests (drive the real UI).
- `tests/fixtures/` — sample configs and flow files used by the tests.
- `libs/` — the un-inlined library copies (source of the inlined blocks).

## Prerequisites
- Node 18+.
- A Chrome/Chromium for the browser tests. The tests locate it via
  `tests/browser/_chrome.js`: it checks `$CHROME_PATH`, then puppeteer's
  bundled browser, then common system paths. If none is found, set it:
  ```
  export CHROME_PATH=/path/to/chrome-or-chromium
  ```

## Install
```
npm install         # acorn (syntax check) + puppeteer-core
```
(Alternatively `npm i -D puppeteer` to get a bundled Chromium picked up automatically.)

## Everyday commands
```
npm run check         # syntax-check every inline <script> block in nettopo.html
npm run test:engine   # engine unit tests (Node)
npm run test:browser  # end-to-end UI tests (Puppeteer)
npm test              # all of the above
npm run serve         # serve the repo at http://127.0.0.1:8077 for manual use
```

## Editing the engine
The engine is authored in `src/reach-engine.js` and **injected** into
`nettopo.html`. After editing it:
```
npm run inject        # regenerate the engine block in nettopo.html
npm run check         # confirm it parses
npm test              # confirm nothing regressed
```
Then open `nettopo.html` directly (double-click / file://) and confirm it
renders — no CSS leaking as text, the graph draws with sample data, console clean.
This direct-render check is mandatory; it catches failures the server can mask.

## Editing parsers / UI
The per-vendor config parsers, audit engine, D3 renderer, and analysis panels
live in inline `<script>` blocks in `nettopo.html`. Edit them there, then
`npm run check` and `npm test`.
