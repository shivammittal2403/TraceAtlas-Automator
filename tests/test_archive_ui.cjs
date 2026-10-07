// Local public-content browser regression under the unchanged production CSP.
const assert = require('node:assert/strict');
const http = require('node:http');
const fs = require('node:fs');
const path = require('node:path');
const { chromium } = require('playwright');
const root = path.resolve(__dirname, '../public');
const config = JSON.parse(fs.readFileSync(path.resolve(__dirname, '../vercel.json')));
const csp = config.headers[0].headers.find(h => h.key === 'Content-Security-Policy').value;

(async () => {
  const server = http.createServer((req, res) => {
    const url = new URL(req.url, 'http://localhost');
    let name = decodeURIComponent(url.pathname);
    if (name.endsWith('/')) name += 'index.html';
    const file = path.resolve(root, '.' + name);
    if (!file.startsWith(root + path.sep) || !fs.existsSync(file) || !fs.statSync(file).isFile()) {
      res.writeHead(404); res.end(); return;
    }
    const ext = path.extname(file);
    res.writeHead(200, {'Content-Type': ({'.js':'text/javascript', '.css':'text/css', '.json':'application/json'})[ext] || 'text/html',
                       'Content-Security-Policy': csp});
    res.end(fs.readFileSync(file));
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  let browser;
  try {
    browser = await chromium.launch({headless:true, args:['--no-sandbox']});
    const page = await browser.newPage({viewport:{width:1280, height:900}});
    const errors = [];
    const external = [];
    page.on('pageerror', error => errors.push(error.message));
    await page.route('**/*', route => {
      const url = new URL(route.request().url());
      if (url.hostname !== '127.0.0.1') {external.push(url.origin); return route.abort();}
      return route.continue();
    });
    const base = `http://127.0.0.1:${server.address().port}`;
    await page.goto(base + '/directory/#/tools');
    await page.waitForSelector('#toolGrid .tool-card');
    const toolCount = await page.locator('#toolGrid .tool-card').count();
    assert(toolCount >= 90, 'Preserved directory records rendered');
    await page.locator('#toolSearch').fill('SpiderFoot');
    assert.deepEqual((await page.locator('#toolGrid .tool-card h3').allTextContents()).sort(),
                     ['SpiderFoot', 'SpiderFoot HX']);
    await page.goto(base + '/directory/#/finder');
    for (let step = 0; step < 3; step++) await page.locator('[data-finder-action="choose"]').first().click();
    await page.waitForSelector('[data-finder-action="reset"]');
    await page.locator('[data-finder-action="reset"]').click();
    assert((await page.locator('[data-finder-action="choose"]').count()) > 0);
    await page.goto(base + '/academy/');
    await page.waitForFunction(() => document.querySelector('#academy-status').textContent.includes('19 of 19'));
    assert.equal(await page.locator('#academy-list .card').count(), 19);
    await page.locator('#academy-search').fill('Introduction to OSINT');
    assert.equal(await page.locator('#academy-list .card').count(), 1);
    await page.locator('#academy-list .card a').click();
    await page.waitForSelector('#academy-lesson .quiz');
    const quiz = page.locator('#academy-lesson .quiz').first();
    await quiz.locator('input').nth(2).check();
    await quiz.locator('button').click();
    assert((await quiz.locator('[role="status"]').textContent()).startsWith('Correct.'));
    await page.goto(base + '/academy/resources.html');
    await page.waitForFunction(() => document.querySelector('#academy-status').textContent.includes('207 of 207'));
    assert.equal(await page.locator('#academy-list .card').count(), 207);
    await page.locator('#academy-search').fill('Shodan');
    assert((await page.locator('#academy-list .card').count()) >= 1);
    // Malicious rich content is a fixture, never a real external document.
    await page.route('**/academy/modules/intro-to-osint.json', route => route.fulfill({
      contentType:'application/json', body:JSON.stringify({title:'Injection fixture', difficulty:'Beginner', duration:1,
        sections:[{title:'Safe content', content:'<script>window.injected=true</script><img src="https://fixture.invalid/image" onerror="window.injected=true"><a href="javascript:window.injected=true">unsafe</a><p>Readable evidence</p>'}]})
    }));
    await page.goto(base + '/academy/training.html?module=intro-to-osint');
    await page.waitForSelector('#academy-lesson h3');
    assert.equal(await page.evaluate(() => window.injected), undefined);
    assert.equal(await page.locator('#academy-lesson script, #academy-lesson img, #academy-lesson [onclick]').count(), 0);
    assert.equal(await page.locator('#academy-lesson a[href^="javascript:"]').count(), 0);
    assert.deepEqual(external, []);
    assert.deepEqual(errors, []);
    await page.setViewportSize({width:390, height:844});
    await page.goto(base + '/academy/');
    await page.waitForSelector('#academy-list .card');
    assert(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 1));
    console.log(JSON.stringify({passed:true, directory_records:toolCount, training_modules:19,
                               resource_references:207, external_requests:0, browser_errors:0,
                               csp:'unchanged', injection:'rejected', mobile_overflow:false}));
  } finally {
    if (browser) await browser.close();
    await new Promise(resolve => server.close(resolve));
  }
})().catch(error => {console.error(error); process.exitCode=1;});
