import { readFile, open } from 'node:fs/promises';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createServer } from 'node:net';
import { createHmac, createHash, X509Certificate, randomUUID } from 'node:crypto';
import { spawn } from 'node:child_process';
import { setTimeout as delay } from 'node:timers/promises';
import { chromium } from 'playwright';

export function totp(secret, step) {
  let bits = '';
  for (const letter of secret) bits += 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'.indexOf(letter).toString(2).padStart(5, '0');
  const key = Buffer.from(bits.match(/.{8}/g).map(value => parseInt(value, 2)));
  const counter = Buffer.alloc(8); counter.writeBigUInt64BE(BigInt(step));
  const hash = createHmac('sha1', key).update(counter).digest();
  return String((hash.readUInt32BE(hash[19] & 15) & 0x7fffffff) % 1000000).padStart(6, '0');
}

export function latestMatchingStep(otp, usedStep, currentStep) {
  const code = otp(usedStep);
  // Conservatively include the verifier's next-step allowance when the request has completed.
  for (let candidate = currentStep + 1; candidate > usedStep; candidate--) {
    if (otp(candidate) === code) return candidate;
  }
  return usedStep;
}

export async function createScenario(directory, suite) {
  const started = performance.now();
  const root = fileURLToPath(new URL('../../../', import.meta.url));
  const fixture = JSON.parse(await readFile(join(directory, 'fixture.json'), 'utf8'));
  const children = [], logs = [], contexts = [];
  const completions = new WeakMap();
  const usedSteps = new Map();
  let browser, stage = 'browser-start', checks = 0, lastStatus, cancelled = false;
  for (const signal of ['SIGINT', 'SIGTERM']) process.once(signal, () => {
    cancelled = true; process.exitCode = 1;
    for (const child of children) child.kill('SIGTERM');
    browser?.close().catch(() => {});
  });
  function check(value) { if (!value) throw new Error('Check failed'); checks++; }
  function status(result, expected) { lastStatus = result?.status; check(lastStatus === expected); return result.body; }
  function progress(label) { stage = label; lastStatus = undefined; process.stdout.write(JSON.stringify({ event: 'browser_stage', suite, stage, checks, elapsedMs: Math.round(performance.now() - started) }) + '\n'); }
  function secret() { return 'orchard amber bridge ocean ' + randomUUID(); }

  async function freshCode(secret) {
    const usedStep = usedSteps.get(secret);
    if (usedStep !== undefined && usedStep >= 0) {
      // The previous request has completed; include every window it could have reached.
      usedSteps.set(secret, latestMatchingStep(step => totp(secret, step), usedStep, Math.floor(Date.now() / 30000)));
    }
    for (;;) {
      if (cancelled) throw new Error();
      const now = Date.now(), step = Math.floor(now / 30000);
      if (step > (usedSteps.get(secret) ?? -1) && now % 30000 < 27000) {
        const code = totp(secret, step);
        usedSteps.set(secret, step); return code;
      }
      await delay(250);
    }
  }
  async function identityPage(context) {
    const page = await context.newPage(); await page.goto(fixture.issuer + '/identity'); return page;
  }
  async function submit(page, formId, fields) {
    const form = page.locator('#' + formId);
    for (const [name, value] of Object.entries(fields)) {
      const input = form.locator(`[name="${name}"]`);
      if (name === 'json') await input.setChecked(value);
      else if (name === 'method') await input.selectOption(value);
      else await input.fill(String(value));
    }
    await page.locator('#hide').click();
    await form.locator('button').click();
    await page.waitForFunction(() => document.querySelector('#result').textContent.length > 0);
    const result = JSON.parse(await page.locator('#result').textContent());
    check(await form.locator('input[type="password"]').evaluateAll(inputs => inputs.every(input => input.value === '')));
    return result;
  }
  async function operation(page, path, fields, json = false) {
    return submit(page, 'operation', { path, method: fields === undefined ? 'GET' : 'POST', fields: JSON.stringify(fields ?? {}), json });
  }
  async function login(page, username, password) { return submit(page, 'login', { username, password }); }
  async function hide(page) { await page.locator('#hide').click(); check(await page.locator('#result').textContent() === ''); }
  async function clickResult(page, id) {
    await page.locator('#hide').click(); await page.locator('#' + id).click();
    await page.waitForFunction(() => document.querySelector('#result').textContent.length > 0);
    return JSON.parse(await page.locator('#result').textContent());
  }
  async function browserFetch(page, path, method = 'GET', fields, csrf = false) {
    return page.evaluate(async ({path, method, fields, csrf}) => {
      const headers = { Accept: 'application/json' };
      if (csrf) { const token = await (await fetch('/api/csrf')).json(); headers[token.headerName] = token.token; }
      if (fields !== undefined) headers['Content-Type'] = 'application/x-www-form-urlencoded';
      const response = await fetch(path, { method, headers, credentials: 'same-origin', redirect: 'error', cache: 'no-store',
        ...(fields !== undefined ? {body: new URLSearchParams(fields)} : {}) });
      return {status: response.status, body: await response.json().catch(() => null)};
    }, {path, method, fields, csrf});
  }
  async function applicationForm(page, path, fields) {
    const origin = new URL(page.url()).origin;
    const response = page.waitForResponse(response => response.request().isNavigationRequest()
      && new URL(response.url()).origin === origin && new URL(response.url()).pathname === path);
    await page.evaluate(({path, fields}) => {
      const form = document.createElement('form'); form.method = 'POST'; form.action = path;
      for (const [name, value] of Object.entries(fields)) {
        const input = document.createElement('input'); input.type = 'hidden'; input.name = name; input.value = value; form.append(input);
      }
      document.body.append(form); form.submit();
    }, {path, fields});
    const result = await response; await page.waitForURL(origin + path); await page.waitForLoadState('domcontentloaded');
    return result.status();
  }
  async function freeOrigin(host) {
    const server = createServer();
    await new Promise((done, reject) => { server.once('error', reject); server.listen(0, host, done); });
    const port = server.address().port; await new Promise(done => server.close(done)); return `https://${host}:${port}`;
  }
  async function startExample(file, env, origin) {
    const log = await open(join(directory, `${file}-${children.length}.log`), 'wx', 0o600); logs.push(log);
    const process = spawn(globalThis.process.execPath, [join(root, 'examples/oidc', file)], {
      cwd: join(root, 'examples/oidc'), env: { PATH: globalThis.process.env.PATH, NODE_EXTRA_CA_CERTS: fixture.certificate, ...env },
      stdio: ['ignore', log.fd, log.fd],
    });
    completions.set(process, new Promise(done => process.once('close', done)));
    children.push(process); let error = false; process.on('error', () => { error = true; });
    const deadline = Date.now() + 20000;
    while (Date.now() < deadline) {
      if (cancelled || error || process.exitCode !== null || process.signalCode !== null) throw new Error();
      try { if ((await fetch(origin + '/health', {signal: AbortSignal.timeout(1000)})).status === 200) return process; } catch { }
      await delay(100);
    }
    throw new Error();
  }
  async function stopExample(child) {
    const closed = completions.get(child);
    if (child.exitCode !== null || child.signalCode !== null) { await closed; return; }
    child.kill('SIGTERM'); await Promise.race([closed, delay(5000, undefined, {ref: false})]);
    if (child.exitCode === null && child.signalCode === null) child.kill('SIGKILL');
    await closed;
  }
  async function completeApplicationLogin(page, origin, credentials) {
    await page.goto(origin + '/'); await page.getByRole('button', {name: 'Sign in with IAM', exact: true}).click();
    await page.waitForURL(url => url.origin === fixture.issuer && url.pathname === '/identity' || url.origin === origin && url.pathname === '/profile');
    if (new URL(page.url()).origin === fixture.issuer) {
      await page.locator('#interaction').waitFor({state: 'visible'});
      await page.waitForFunction(() => { try { return typeof JSON.parse(document.querySelector('#interaction-view').textContent).loginRequired === 'boolean'; } catch { return false; } });
      const view = JSON.parse(await page.locator('#interaction-view').textContent());
      if (view.loginRequired) {
        if (!credentials) throw new Error('Unexpected password interaction');
        status(await login(page, credentials.username, credentials.password), 204);
      }
      await page.locator('#continue').waitFor({state: 'visible'});
      await page.waitForFunction(() => !document.querySelector('#continue').disabled);
      await page.locator('#continue').click();
    }
    await page.waitForURL(origin + '/profile'); await page.locator('[data-profile="sub"]').waitFor();
  }

  const certificate = new X509Certificate(await readFile(fixture.certificate));
  const pin = createHash('sha256').update(certificate.publicKey.export({type: 'spki', format: 'der'})).digest('base64');
  browser = await chromium.launch({headless: true, args: [`--ignore-certificate-errors-spki-list=${pin}`]});

  async function administrator() {
    const adminContext = await browser.newContext(); contexts.push(adminContext);
    const admin = await identityPage(adminContext);
    progress('anonymous-and-admin-mfa');
    status(await operation(admin, '/api/me'), 401);
    status(await login(admin, fixture.adminUsername, fixture.adminPassword), 204);
    status(await operation(admin, '/api/admin/me'), 403);
    status(await submit(admin, 'mfa', {code: await freshCode(fixture.adminTotpSecret)}), 204);
    status(await operation(admin, '/api/admin/me'), 200);
    status(await browserFetch(admin, '/api/me/profile', 'POST', {displayName: 'Should not change'}), 403);
    const adminSessions = status(await operation(admin, '/api/me/sessions'), 200);
    check(adminSessions.items.length === 1 && adminSessions.items[0].current);
    const adminSessionId = adminSessions.items[0].id;

    return {admin, adminSessionId};
  }

  function application(registration) {
    const {name, origin, apiOrigin, audience, clientId, clientSecret, resourceId, validationSecret} = registration;
    return {...registration, env: {
      IAM_ISSUER: fixture.issuer, IAM_IDENTITY_FRONTEND_URI: fixture.issuer + '/identity',
      RP_NAME: name, RP_ORIGIN: origin, RP_CLIENT_ID: clientId, RP_CLIENT_SECRET: clientSecret,
      RP_TLS_CERT_FILE: fixture.certificate, RP_TLS_KEY_FILE: fixture.privateKey,
      API_ORIGIN: apiOrigin, API_AUDIENCE: audience, API_VALIDATION_CLIENT_ID: resourceId, API_VALIDATION_CLIENT_SECRET: validationSecret,
      API_TLS_CERT_FILE: fixture.certificate, API_TLS_KEY_FILE: fixture.privateKey,
    }};
  }

  async function verifyAuditSecrets(page, values) {
    const audits = status(await operation(page, '/api/admin/audits?pageSize=100'), 200);
    check(audits.items.length > 0);
    const serialized = JSON.stringify(audits);
    check(!values.some(value => serialized.includes(value)));
  }

  async function verifyStorage() {
    for (const context of contexts) for (const page of context.pages()) {
      check(await page.evaluate(() => localStorage.length + sessionStorage.length) === 0);
    }
  }

  function snapshot() {
    return {suite, stage, status: lastStatus, checks, cancelled, elapsedMs: Math.round(performance.now() - started)};
  }

  async function close() {
    const stopped = await Promise.allSettled([browser?.close(), ...children.map(stopExample)]);
    const closed = await Promise.allSettled(logs.map(log => log.close()));
    if ([...stopped, ...closed].some(result => result.status === 'rejected')) throw new Error();
  }

  return {fixture, suite, browser, contexts, check, status, progress, secret, freshCode, identityPage, submit, operation, login, hide,
    clickResult, applicationForm, freeOrigin, startExample, stopExample, completeApplicationLogin, administrator, application,
    verifyAuditSecrets, verifyStorage, snapshot, close};
}
