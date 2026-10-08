// Synthetic local graph imports under the unchanged production CSP.
"use strict";
const assert = require("node:assert/strict");
const http = require("node:http");
const fs = require("node:fs");
const path = require("node:path");
const { chromium } = require("playwright");
const root = path.resolve(__dirname, "../public");
const config = JSON.parse(fs.readFileSync(path.resolve(__dirname, "../vercel.json"), "utf8"));
const csp = config.headers.flatMap(rule => rule.headers || [])
  .find(header => header.key.toLowerCase() === "content-security-policy")?.value;
assert.ok(csp, "Run the graph under the production CSP");

const apiFixtures = {
  "/api/catalog": { version: "graph-fixture", metrics: {} },
  "/api/config": { control_plane: "configured" },
  "/api/session": { authenticated: true, user: { email: "analyst@example.org" } },
  "/api/organisations": { organisations: [] }, "/api/cases": { cases: [] },
  "/api/assets": { assets: [] }, "/api/jobs": { jobs: [] },
};
function fixture(count) {
  return {
    schema_version: "traceatlas-graph/1", case_id: "synthetic-viewport-fixture",
    title: "Synthetic graph viewport fixture", synthetic: true,
    nodes: Array.from({ length: count }, (_, index) => ({
      id: `node-${String(index).padStart(3, "0")}`,
      label: index % 3 === 0 ? "界".repeat(28) : index % 3 === 1 ? "🧪".repeat(14) : `Synthetic node ${index}`,
      type: "LABEL", source: "offline-fixture", classification: "observed", confidence: 90,
      details: "Synthetic browser regression; no real person or network collection.",
    })),
    edges: Array.from({ length: Math.floor(count / 2) }, (_, index) => ({
      id: `edge-${index}`, source: `node-${String(index * 2).padStart(3, "0")}`,
      target: `node-${String(index * 2 + 1).padStart(3, "0")}`,
      label: "synthetic_link", classification: "observed", confidence: 90,
    })),
    evidence: [],
  };
}

(async () => {
  const unexpectedApis = [], apiRequests = [];
  const server = http.createServer((req, res) => {
    const pathname = new URL(req.url, "http://localhost").pathname;
    if (pathname.startsWith("/api/")) {
      apiRequests.push(pathname);
      const body = apiFixtures[pathname];
      if (req.method !== "GET" || !body) {
        unexpectedApis.push(`${req.method} ${pathname}`);
        res.writeHead(500, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ error: "unexpected_offline_test_request" })); return;
      }
      res.writeHead(200, { "Content-Type": "application/json", "Content-Security-Policy": csp });
      res.end(JSON.stringify(body)); return;
    }
    if (pathname === "/favicon.ico") { res.writeHead(204); res.end(); return; }
    let name;
    try { name = decodeURIComponent(pathname); }
    catch { res.writeHead(400); res.end(); return; }
    if (name.endsWith("/")) name += "index.html";
    const file = path.resolve(root, "." + name);
    if (!file.startsWith(root + path.sep) || !fs.existsSync(file) || !fs.statSync(file).isFile()) {
      res.writeHead(404); res.end(); return;
    }
    const contentType = { ".js": "text/javascript", ".css": "text/css", ".json": "application/json" }[path.extname(file)] || "text/html";
    res.writeHead(200, { "Content-Type": contentType, "Content-Security-Policy": csp });
    res.end(fs.readFileSync(file));
  });
  await new Promise(resolve => server.listen(0, "127.0.0.1", resolve));
  let browser;
  try {
    browser = await chromium.launch({ headless: true, args: ["--no-sandbox"] });
    const page = await browser.newPage({ viewport: { width: 1280, height: 900 } });
    const errors = [], external = [];
    page.on("pageerror", error => errors.push(error.message));
    page.on("console", message => { if (message.type() === "error") errors.push(message.text()); });
    const base = `http://127.0.0.1:${server.address().port}`;
    await page.route("**/*", route => {
      const url = new URL(route.request().url());
      if (url.origin !== base) { external.push(url.origin); return route.abort(); }
      return route.continue();
    });
    await page.goto(base + "/");
    await page.locator("#workspace:not([hidden])").waitFor();
    await page.waitForFunction(() => document.querySelector("#graph-case").options.length === 1);
    await page.waitForLoadState("networkidle");
    const startupRequests = apiRequests.length;
    for (const size of [{ width: 1280, height: 900 }, { width: 390, height: 844 }]) {
      await page.setViewportSize(size);
      for (const count of [20, 250]) {
        await page.locator("#graph-import").setInputFiles({
          name: `synthetic-${count}.json`, mimeType: "application/json",
          buffer: Buffer.from(JSON.stringify(fixture(count))),
        });
        await page.waitForFunction(expected => document.querySelectorAll("#case-graph .graph-node").length === expected, count);
        for (const mode of ["radial", "grid", "layered"]) {
          await page.selectOption("#graph-layout", mode);
          const result = await page.evaluate(async () => {
            await document.fonts.ready;
            await new Promise(resolve => requestAnimationFrame(resolve));
            const svg = document.querySelector("#case-graph"), v = svg.viewBox.baseVal;
            const box = node => {
              const b = node.getBBox();
              return { x: b.x, y: b.y, width: b.width, height: b.height };
            };
            return {
              view: { x: v.x, y: v.y, width: v.width, height: v.height },
              total: box(svg), items: [...svg.querySelectorAll("circle, text, line")].map(box),
              count: svg.querySelectorAll(".graph-node").length,
              empty: !document.querySelector("#graph-empty").hidden,
              status: document.querySelector("#graph-status").textContent,
            };
          });
          const context = `${size.width}px / ${count} nodes / ${mode}`;
          assert.equal(result.count, count, context);
          assert.equal(result.empty, false, context);
          assert.doesNotMatch(result.status, /drawing capped/i, context);
          const v = result.view;
          assert.ok(Object.values(v).every(Number.isFinite), context + ": finite viewport");
          assert.ok(v.width >= 800 && v.height >= 420, context + ": minimum viewport");
          if (mode === "radial") assert.ok(v.y < 0, context + ": negative Y preserved");
          if (mode === "radial" && count === 250) assert.ok(v.x < 0, context + ": negative X preserved");
          for (const b of [result.total, ...result.items]) {
            assert.ok(Object.values(b).every(Number.isFinite), context + ": finite SVG bounds");
            const tolerance = 0.01;
            assert.ok(b.x >= v.x - tolerance && b.y >= v.y - tolerance &&
              b.x + b.width <= v.x + v.width + tolerance && b.y + b.height <= v.y + v.height + tolerance,
              context + ": node, label or edge outside viewBox: " + JSON.stringify({ view: v, bounds: b }));
          }
        }
      }
    }
    assert.equal(apiRequests.length, startupRequests, "Local import/layout never calls a collection API");
    assert.deepEqual(unexpectedApis, []);
    assert.deepEqual(external, [], "All requests remained on the offline fixture server");
    assert.deepEqual(errors, [], "No browser exceptions, CSP errors or failed resources");
    console.log("PASS: radial/grid/layered graph bounds contain 20 and 250 synthetic nodes, Unicode labels and links at desktop/mobile widths; no external requests");
  } finally {
    if (browser) await browser.close();
    await new Promise(resolve => server.close(resolve));
  }
})().catch(error => { console.error(error); process.exitCode = 1; });
