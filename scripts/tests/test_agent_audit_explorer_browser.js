// SPDX-License-Identifier: Apache-2.0
// Optional browser fixture: NODE_PATH=<playwright node_modules> node scripts/tests/test_agent_audit_explorer_browser.js
// Set PLAYWRIGHT_CHROMIUM_EXECUTABLE when the Playwright browser bundle is unavailable.
'use strict';

const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { pathToFileURL } = require('node:url');

const template = fs.readFileSync(path.join(__dirname, '..', 'agent-audit-explorer.html'), 'utf8');
const inlineScript = template.match(/<script>\n([^]*?)\n<\/script>/)?.[0]?.replace(/^<script>/, '').replace(/<\/script>$/, '');
assert.ok(inlineScript, 'inline script missing');
const scriptHash = crypto.createHash('sha256').update(inlineScript).digest('base64');
assert.ok(template.includes(`script-src 'sha256-${scriptHash}'`), 'CSP inline-script hash is stale');
const escapeJson = (value) => JSON.stringify(value).replace(/[<>&\u2028\u2029]/g, (character) =>
  ({ '<': '\\u003c', '>': '\\u003e', '&': '\\u0026', '\u2028': '\\u2028', '\u2029': '\\u2029' })[character]);
const htmlFor = (report) => template.replace('__AUDIT_DATA__', escapeJson(report));

function event(id, changes = {}) {
  return {
    id, timestamp: '2026-10-17T09:00:00Z', event: 'pre_tool_use', verdict: 'allow', tool: 'Bash',
    session_alias: 'Session 1', mode: 'enforced', stage: 'decision', rule: 'read-only', reason: null,
    detectors: [], severity: [], taint_origin: null, latency_ms: 1.2, correlation: null,
    evidence_missing: ['Host execution is not proven'], details: [], ...changes
  };
}

function report(events, changes = {}) {
  return {
    meta: {
      generated_at: '2026-10-17T10:00:00Z', source_status: 'complete',
      totals: { lines: events.length, accepted: events.length, malformed: 0, unsupported: 0, skipped: 0 },
      limits: { input_bytes: 1, line_bytes: 1, records: 10000, depth: 16, output_bytes: 8388608 },
      notices: [], ...changes
    }, events
  };
}

async function main() {
  const ownedPath = process.env.SOU75_REPORT_HTML || process.env.SOU75_OWNED_REPORT;
  let chromium;
  try { ({ chromium } = require('playwright')); }
  catch (_) {
    try { ({ chromium } = require('playwright-core')); }
    catch (_) { console.log('SKIP: optional Playwright package unavailable'); return; }
  }
  const launch = { headless: true };
  if (process.env.PLAYWRIGHT_CHROMIUM_EXECUTABLE) launch.executablePath = process.env.PLAYWRIGHT_CHROMIUM_EXECUTABLE;
  let browser;
  try { browser = await chromium.launch(launch); }
  catch (error) {
    if (!launch.executablePath && /Executable doesn't exist|Please run/.test(error.message)) {
      console.log('SKIP: optional Chromium browser unavailable'); return;
    }
    throw error;
  }
  try {
    const context = await browser.newContext({ viewport: { width: 390, height: 844 } });
    const requests = [];
    await context.route('**/*', (route) => {
      if (route.request().url().startsWith('file:')) return route.continue();
      requests.push(route.request().url());
      return route.abort();
    });
    const page = await context.newPage();
    const fixtureDir = fs.mkdtempSync(path.join(os.tmpdir(), 'sou75-browser-'));
    const errors = [];
    page.on('pageerror', (error) => errors.push(error.message));
    const malicious = '</script><img src="https://example.invalid/exfil" onerror="window.__executed = true">';
    const events = [
      event(1, { tool: malicious }),
      event(2, { verdict: 'ask', tool: 'Read', session_alias: 'Session 2', mode: 'shadow',
        reason: 'Approval needed', timestamp: '2026-10-18T09:00:00Z' }),
      event(3, { event: 'native_result', verdict: 'deny', stage: 'result', released: false, tool: 'MCP tool 1',
        session_alias: 'Session 2', correlation: 'Call 1', reason: 'Result withheld; prior side effects may remain' }),
      event(4, { event: 'post_tool_use', stage: 'observation', mode: 'unknown',
        evidence_missing: ['Result details unavailable'] }),
      ...Array.from({ length: 102 }, (_, index) => event(index + 5, { tool: 'Read' }))
    ];
    const fixtureHtml = htmlFor(report(events, { source_status: 'partial',
      totals: { lines: 107, accepted: 106, malformed: 1, unsupported: 0, skipped: 0 },
      notices: ['One malformed line was skipped'] }));
    const fixturePath = path.join(fixtureDir, 'fixture.html');
    fs.writeFileSync(fixturePath, fixtureHtml, { mode: 0o600 });
    await page.goto(pathToFileURL(fixturePath).href);
    await page.locator('#timeline-panel').waitFor({ state: 'visible' });
    assert.equal(await page.locator('#count-events').innerText(), '106');
    assert.equal(await page.locator('#event-rows tr').count(), 50);
    assert.match(await page.locator('#report-notice').innerText(), /partial/i);
    assert.equal(await page.evaluate(() => window.__executed === true), false);
    assert.deepEqual(requests, []);
    assert.deepEqual(errors, []);
    assert.equal(await page.locator('#load-error').isVisible(), false);

    await page.locator('#verdict').selectOption('deny');
    assert.equal(await page.locator('#event-rows tr').count(), 1);
    assert.match(await page.locator('#filter-count').innerText(), /1 of 106/);
    await page.locator('#event-rows button').focus();
    await page.keyboard.press('Enter');
    assert.match(await page.locator('#detail-panel').innerText(), /Result withheld/);
    assert.match(await page.locator('#detail-panel').innerText(), /Call 1/);
    await page.locator('#close-detail').click();
    assert.equal(await page.locator('#detail-panel').isVisible(), false);

    await page.locator('#clear').click();
    await page.locator('#event').selectOption('native_result');
    assert.equal(await page.locator('#event-rows tr').count(), 1);
    await page.locator('#clear').click();
    await page.locator('#from-date').fill('2026-10-18');
    assert.equal(await page.locator('#event-rows tr').count(), 1);
    await page.locator('#to-date').fill('2026-10-17');
    assert.equal(await page.locator('#empty').isVisible(), true);
    await page.locator('#clear').click();
    await page.locator('#session').fill('Session 2');
    await page.waitForFunction(() => document.getElementById('filter-count').textContent.includes('2 of 106'));
    await page.locator('#tool').fill('MCP tool');
    await page.waitForFunction(() => document.getElementById('filter-count').textContent.includes('1 of 106'));
    await page.locator('#from-date').fill('2026-10-18');
    assert.equal(await page.locator('#empty').isVisible(), true);
    await page.locator('#clear').click();
    await page.locator('#next').click();
    assert.match(await page.locator('#page-label').innerText(), /Page 2 of 3/);
    assert.equal(await page.locator('#event-rows tr').count(), 50);
    assert.equal(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth), true);
    assert.deepEqual(requests, []);
    assert.deepEqual(errors, []);

    const stressEvents = Array.from({ length: 10000 }, (_, index) =>
      event(index + 1, { tool: index === 9999 ? 'Unique tool' : 'Bash' }));
    const stressHtml = htmlFor(report(stressEvents));
    assert.ok(Buffer.byteLength(stressHtml, 'utf8') <= 8 * 1024 * 1024);
    const initializationStarted = Date.now();
    await page.setContent(stressHtml);
    await page.locator('#timeline-panel').waitFor({ state: 'visible', timeout: 5000 });
    const initializationMs = Date.now() - initializationStarted;
    assert.equal((await page.locator('#count-events').innerText()).replace(/\D/g, ''), '10000');
    assert.equal(await page.locator('#event-rows tr').count(), 50);
    assert.ok(initializationMs < 5000, `10k initialization took ${initializationMs} ms`);
    const filterStarted = Date.now();
    await page.locator('#tool').fill('Unique tool');
    await page.waitForFunction(() => document.getElementById('filter-count').textContent.replace(/\D/g, '') === '110000');
    const filterMs = Date.now() - filterStarted;
    assert.ok(filterMs < 2000, `10k filter took ${filterMs} ms`);
    assert.equal(await page.locator('#event-rows tr').count(), 1);
    assert.deepEqual(requests, []);
    assert.deepEqual(errors, []);

    if (ownedPath) {
      const owned = fs.readFileSync(ownedPath, 'utf8');
      assert.equal(owned.includes('__AUDIT_DATA__'), false, 'generator must embed projected data');
      const embedded = JSON.parse(owned.match(/<script type="application\/json" id="audit-data">([^]*?)<\/script>/)[1]);
      assert.equal(embedded.events.length, 14);
      assert.equal(embedded.events.filter((e) => e.stage === 'admission' && e.verdict === 'allow').length, 3);
      assert.equal(embedded.events.filter((e) => e.stage === 'result' && e.released === false).length, 1);
      assert.ok(embedded.events.some((e) => e.mode === 'shadow' && ['ask', 'deny'].includes(e.verdict)));
      const ownedFixturePath = path.join(fixtureDir, 'owned.html');
      fs.writeFileSync(ownedFixturePath, owned, { mode: 0o600 });
      await page.goto(pathToFileURL(ownedFixturePath).href);
      await page.locator('#timeline-panel').waitFor({ state: 'visible', timeout: 5000 });
      assert.equal(await page.locator('#load-error').isVisible(), false);
      assert.equal(await page.locator('#count-events').innerText(), '14');
      assert.equal(await page.locator('#count-withheld').innerText(), '1');
      await page.locator('#verdict').selectOption('ask');
      await page.locator('#event').selectOption('native_result');
      assert.equal(await page.locator('#event-rows tr').count(), 1);
      await page.locator('#event-rows button').click();
      assert.match(await page.locator('#detail-panel').innerText(), /Result withheld/);
      assert.match(await page.locator('#detail-panel').innerText(), /Call [0-9]+/);
      assert.deepEqual(requests, []);
      assert.deepEqual(errors, []);
    }
    await context.close();
    fs.rmSync(fixtureDir, { recursive: true, force: true });
    console.log(`PASS: CSP, filters, details, pagination, small screen, XSS inertness, offline silence; ` +
      `10k initialization ${initializationMs} ms, filter ${filterMs} ms` +
      (ownedPath ? ', owned generated report' : ''));
  } finally { await browser.close(); }
}

main().catch((error) => { console.error(error); process.exitCode = 1; });
