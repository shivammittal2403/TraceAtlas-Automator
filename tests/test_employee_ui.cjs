// Optional browser regression: node tests/test_employee_ui.cjs
// Requires Playwright + Chromium. All API responses below are synthetic fixtures.
const assert = require("node:assert/strict");
const http = require("node:http");
const fs = require("node:fs");
const path = require("node:path");
const { chromium } = require("playwright");
const root = path.resolve(__dirname, "../public");
const caseId = "11111111-1111-4111-8111-111111111111";
const secondCase = "22222222-2222-4222-8222-222222222222";
const fixture = {
  schema: "traceatlas.employee.brief.v1", case_id: caseId, objective: "Review service exposure evidence", mode: "pt",
  evidence_digest: "a".repeat(64), summary: {observations: 1, scenarios: 1, withheld: 0, coverage_failures: 0, truncated: false},
  facts: [{id: "e1", source: "synthetic provider", title: "<img src=x onerror=window.injected=1>", freshness: "recent", data: {ports: [443]}, interpretation: "Source observation; validation required."}],
  scenarios: [{title: "Potential service exposure", statement: "A provider reports a service.", alternative_explanation: "It may be an intended public service.", next_check: "Confirm against the owned asset inventory.", evidence_ids: ["e1"]}],
  insights: [], skills: [], knowledge_references: [], coverage_gaps: [], withheld: [], questions: ["Is the record current?"], limitations: ["Synthetic browser test fixture."],
};

(async () => {
  const server = http.createServer((req, res) => {
    const pathname = new URL(req.url, "http://localhost").pathname;
    const name = pathname === "/" ? "index.html" : pathname.slice(1);
    if (!/^[a-z0-9.-]+$/.test(name)) { res.writeHead(404); res.end(); return; }
    const file = path.join(root, name);
    if (!fs.existsSync(file)) { res.writeHead(404); res.end(); return; }
    const type = name.endsWith(".js") ? "text/javascript" : name.endsWith(".css") ? "text/css" : "text/html";
    res.writeHead(200, {"Content-Type": type}); res.end(fs.readFileSync(file));
  });
  await new Promise(resolve => server.listen(0, "127.0.0.1", resolve));
  let browser;
  try {
    browser = await chromium.launch({headless: true, args: ["--no-sandbox"]});
    const page = await browser.newPage({viewport: {width: 1440, height: 1000}});
    const errors = [];
    const decisions = [];
    const jobRequests = [];
    let queued = false;
    let decision = "pending";
    let slowReply = null;
    let shouldDelay = false;
    page.on("pageerror", error => errors.push(error.message));
    await page.route("**/api/**", async route => {
      const req = route.request();
      const url = new URL(req.url());
      const respond = body => route.fulfill({status: 200, contentType: "application/json", body: JSON.stringify(body)});
      if (url.pathname === "/api/config") return respond({control_plane: "configured"});
      if (url.pathname === "/api/session") return respond({authenticated: req.method() !== "DELETE", user: {email: "analyst@example.org"}});
      if (url.pathname === "/api/catalog") return respond({version: "test", metrics: {}});
      if (url.pathname === "/api/organisations") return respond({organisations: [{id: "org", name: "Synthetic organization"}]});
      if (url.pathname === "/api/cases") return respond({cases: [{id: caseId, organisation_id: 'org', title: "Fixture case"}, {id: secondCase, organisation_id: 'org', title: "Other case"}]});
      if (url.pathname === "/api/assets") return respond({assets: [{id: 'asset-fixture', organisation_id: 'org', label: 'Synthetic domain', target_type: 'domain', target_value: 'example.org'}]});
      if (url.pathname === "/api/jobs") {
        if (req.method() === 'POST') {
          jobRequests.push(req.postDataJSON());
          if (jobRequests.length === 1) return route.abort('connectionreset');
          return respond({job: {id: 'fixture-job'}});
        }
        return respond({jobs: []});
      }
      if (url.pathname === "/api/employee") {
        const body = req.postDataJSON();
        if (body.action === "queue-review") {
          assert.equal(body.expected_evidence_digest, fixture.evidence_digest);
          assert.equal(body.case_id, caseId);
          queued = true;
          return respond({review: {id: "review-1"}, executes_actions: false});
        }
        if (shouldDelay) { await new Promise(resolve => { slowReply = resolve; }); }
        return respond({brief: fixture});
      }
      if (url.pathname === "/api/reviews") {
        if (req.method() === "POST") { const body = req.postDataJSON(); decisions.push(body); decision = body.decision; }
        return respond({reviews: queued ? [{id: "review-1", title: "Employee brief", kind: "model-output", priority: "normal", status: decision, context: {type: "employee-brief", objective: fixture.objective, scenarios: fixture.scenarios}}] : []});
      }
      throw new Error("Unexpected test request: " + url.pathname);
    });
    await page.goto(`http://127.0.0.1:${server.address().port}/`);
    await page.selectOption('#job-case', caseId);
    await page.selectOption('#job-asset', 'asset-fixture');
    await page.check('#job-authorized');
    await page.locator('#job-form button[type=submit]').click();
    await page.waitForFunction(() => document.querySelector('#workspace-error').textContent.length > 0);
    await page.locator('#job-form button[type=submit]').click();
    await page.waitForFunction(() => !document.querySelector('#job-authorized').checked);
    assert.equal(jobRequests.length, 2);
    assert.equal(jobRequests[0].idempotency_key, jobRequests[1].idempotency_key);
    assert.equal(await page.evaluate(() => TraceAtlasTargetValidation.isPublicIpAddress('::::')), false);
    assert.equal(await page.evaluate(() => TraceAtlasTargetValidation.isPublicIpAddress('2606:4700:4700::1111')), true);
    await page.selectOption("#employee-case", caseId);
    await page.selectOption("#employee-mode", "pt");
    await page.fill("#employee-objective", fixture.objective);
    await page.click("#employee-build");
    await page.locator("#employee-result:not([hidden])").waitFor();
    assert.match(await page.locator("#employee-scenarios").textContent(), /intended public service/);
    assert.equal(await page.locator("#employee-facts img").count(), 0);
    assert.equal(await page.evaluate(() => window.injected), undefined);
    await page.click("#employee-queue");
    await page.getByText("Read the evidence and scenario snapshot before deciding").waitFor();
    assert.ok(queued);
    await page.locator("#review-list button").click();
    await page.fill("#review-rationale", "Synthetic test: require further independent evidence.");
    await page.click("#review-reject");
    await page.waitForFunction(() => document.querySelector("#review-list").textContent.includes("REJECTED"));
    assert.equal(decisions[0].decision, "rejected");

    // An outstanding response must not repaint a different selected case.
    shouldDelay = true;
    await page.click("#employee-build");
    while (!slowReply) await new Promise(resolve => setTimeout(resolve, 10));
    await page.selectOption("#employee-case", secondCase);
    slowReply();
    await page.waitForLoadState("networkidle");
    assert.equal(await page.locator("#employee-result").isVisible(), false);
    assert.equal(await page.locator("#employee-facts").textContent(), "");
    await page.click("#logout");
    assert.equal(await page.locator("#employee-result").isVisible(), false);
    assert.deepEqual(errors, []);
    if (process.env.TRACEATLAS_UI_SCREENSHOT) await page.screenshot({path: process.env.TRACEATLAS_UI_SCREENSHOT, fullPage: true});
    console.log("PASS: job retry reuses key, IPv6 validation, brief, untrusted text rendering, review decision, stale-response isolation, logout clearing");
  } finally {
    if (browser) await browser.close();
    await new Promise(resolve => server.close(resolve));
  }
})().catch(error => { console.error(error); process.exitCode = 1; });
