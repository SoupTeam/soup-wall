// SPDX-License-Identifier: Apache-2.0
// Optional: NODE_PATH=<playwright node_modules> SOU80_REPORT_HTML=<private index.html>
//           PLAYWRIGHT_CHROMIUM_EXECUTABLE=<browser> node scripts/tests/test_roadmap_support_browser.js
'use strict';

const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { pathToFileURL } = require('node:url');

function withReport(html, report) {
  const match = html.match(/<script>(const REPORT=([^]*?);\n"use strict";[^]*?)<\/script>/);
  assert.ok(match, 'embedded report not found');
  const script = match[1].replace(match[2], JSON.stringify(report).replace(/</g, '\\u003c'));
  const oldHash = crypto.createHash('sha256').update(match[1]).digest('base64');
  const newHash = crypto.createHash('sha256').update(script).digest('base64');
  return html.replace(match[1], script).replace(`script-src 'sha256-${oldHash}'`,
    `script-src 'sha256-${newHash}'`);
}

async function main() {
  const input = process.env.SOU80_REPORT_HTML;
  assert.ok(input, 'SOU80_REPORT_HTML must name a generated private report');
  let chromium;
  try { ({ chromium } = require('playwright')); }
  catch (_) {
    try { ({ chromium } = require('playwright-core')); }
    catch (_) { console.log('SKIP: optional Playwright package unavailable'); return; }
  }
  const launch = { headless: true };
  if (process.env.PLAYWRIGHT_CHROMIUM_EXECUTABLE) {
    launch.executablePath = process.env.PLAYWRIGHT_CHROMIUM_EXECUTABLE;
  }
  const browser = await chromium.launch(launch);
  const context = await browser.newContext({ viewport: { width: 390, height: 844 } });
  const network = [];
  const errors = [];
  await context.route('**/*', route => {
    if (route.request().url().startsWith('file:')) return route.continue();
    network.push(route.request().url());
    return route.abort();
  });
  const page = await context.newPage();
  page.on('pageerror', error => errors.push(error.message));
  const temp = fs.mkdtempSync(path.join(os.tmpdir(), 'sou80-browser-'));
  try {
    const html = fs.readFileSync(input, 'utf8');
    assert.ok(html.includes("connect-src 'none'"));
    await page.goto(pathToFileURL(path.resolve(input)).href);
    await page.locator('.criterion').first().waitFor();
    assert.equal(await page.locator('.criterion').count(), 8);
    assert.match(await page.locator('#summary').innerText(), /38 matching criteria/);
    await page.locator('#next').click();
    assert.match(await page.locator('#page-label').innerText(), /Page 2 of 5/);
    assert.equal(await page.locator('.criterion').count(), 8);
    await page.locator('#phase').selectOption('Phase 5');
    assert.equal(await page.locator('.criterion').count(), 5);
    await page.locator('#platform').selectOption('macos');
    await page.locator('#status').selectOption('unbound');
    assert.equal(await page.locator('.criterion').count(), 5);
    await page.locator('.cap-details summary').first().click();
    await page.locator('.evidence summary').first().click();
    assert.match(await page.locator('.evidence').first().innerText(), /self-test-macos-run/);
    assert.match(await page.locator('.evidence').first().innerText(), /source commit/);
    assert.equal(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth), true);
    if (process.env.SOU80_SCREENSHOT_DIR) {
      await page.locator('#phase').selectOption('all');
      await page.locator('#platform').selectOption('all');
      await page.locator('#status').selectOption('all');
      await page.evaluate(() => scrollTo(0, 0));
      await page.screenshot({ path: path.join(process.env.SOU80_SCREENSHOT_DIR,
        'sou80-support-mobile.png'), fullPage: false });
      await page.setViewportSize({ width: 1280, height: 900 });
      await page.locator('#phase').selectOption('Phase 1');
      await page.locator('#status').selectOption('historical');
      await page.locator('.cap-details summary').first().click();
      await page.locator('.evidence summary').first().click();
      await page.evaluate(() => scrollTo(0, 0));
      await page.screenshot({ path: path.join(process.env.SOU80_SCREENSHOT_DIR,
        'sou80-support-desktop.png'), fullPage: false });
    }

    const match = html.match(/<script>(const REPORT=([^]*?);\n"use strict";[^]*?)<\/script>/);
    assert.ok(match, 'embedded report not found');
    const report = JSON.parse(match[2]);
    report.capabilities[0].title = '</script><img src=https://example.invalid/leak onerror="window.__executed=true">';
    const attacked = withReport(html, report);
    const fixture = path.join(temp, 'unsafe-title.html');
    fs.writeFileSync(fixture, attacked, { mode: 0o600 });
    await page.goto(pathToFileURL(fixture).href);
    await page.locator('.criterion').first().waitFor();
    assert.equal(await page.evaluate(() => window.__executed === true), false);
    assert.equal(await page.locator('img').count(), 0);

    const stress = JSON.parse(match[2]);
    const sampleEvidence = stress.capabilities.find(cap => cap.evidence.length).evidence[0];
    stress.capabilities = Array.from({ length: 128 }, (_, i) => ({
      ...stress.capabilities[0], id: `stress-${i}`,
      evidence: i === 0 ? Array.from({ length: 128 }, (_, j) =>
        ({ ...sampleEvidence, id: `stress-evidence-${j}` })) : []
    }));
    stress.criteria = Array.from({ length: 64 }, (_, i) => ({
      ...stress.criteria[0], id: `phase-1.${i + 1}`, phase: 'Phase 1',
      capabilities: stress.capabilities.map(cap => cap.id)
    }));
    const stressFile = path.join(temp, 'bounded-stress.html');
    fs.writeFileSync(stressFile, withReport(html, stress), { mode: 0o600 });
    const started = Date.now();
    await page.goto(pathToFileURL(stressFile).href);
    await page.locator('.criterion').first().waitFor({ timeout: 10000 });
    const initialMs = Date.now() - started;
    assert.equal(await page.locator('.criterion').count(), 8);
    assert.match(await page.locator('#summary').innerText(), /64 matching criteria/);
    assert.ok(initialMs < 10000, `bounded initialization took ${initialMs} ms`);
    const filterStarted = Date.now();
    await page.locator('#status').selectOption('missing');
    assert.equal(await page.locator('.criterion').count(), 8);
    const filterMs = Date.now() - filterStarted;
    assert.ok(filterMs < 5000, `bounded filter took ${filterMs} ms`);
    assert.deepEqual(network, []);
    assert.deepEqual(errors, []);
    console.log(`PASS: owned report, filters, paging, drilldown, mobile layout, CSP, XSS inertness, offline silence; ` +
      `bounded initialization ${initialMs} ms, filter ${filterMs} ms`);
  } finally {
    await context.close();
    await browser.close();
    fs.rmSync(temp, { recursive: true, force: true });
  }
}

main().catch(error => { console.error(error); process.exitCode = 1; });
