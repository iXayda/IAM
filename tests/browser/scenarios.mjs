import { readFile, open } from 'node:fs/promises';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createServer } from 'node:net';
import { createHmac, createHash, X509Certificate, randomUUID } from 'node:crypto';
import { spawn } from 'node:child_process';
import { setTimeout as delay } from 'node:timers/promises';
import { chromium } from 'playwright';

const directory = process.argv[2];
const root = fileURLToPath(new URL('../../', import.meta.url));
const fixture = JSON.parse(await readFile(join(directory, 'fixture.json'), 'utf8'));
const children = [], logs = [], contexts = [];
const usedSteps = new Map();
let browser, stage = 'browser-start', checks = 0, lastStatus;
for (const signal of ['SIGINT', 'SIGTERM']) process.once(signal, () => {
  process.exitCode = 1;
  for (const child of children) child.kill('SIGTERM');
  browser?.close().catch(() => {});
});
function check(value) { if (!value) throw new Error('Check failed'); checks++; }
function status(result, expected) { lastStatus = result?.status; check(lastStatus === expected); return result.body; }
function progress(label) { stage = label; lastStatus = undefined; process.stdout.write(JSON.stringify({ event: 'browser_stage', stage, checks }) + '\n'); }
function secret() { return 'orchard amber bridge ocean ' + randomUUID(); }

function totp(secret, step) {
  let bits = '';
  for (const letter of secret) bits += 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'.indexOf(letter).toString(2).padStart(5, '0');
  const key = Buffer.from(bits.match(/.{8}/g).map(value => parseInt(value, 2)));
  const counter = Buffer.alloc(8); counter.writeBigUInt64BE(BigInt(step));
  const hash = createHmac('sha1', key).update(counter).digest();
  return String((hash.readUInt32BE(hash[19] & 15) & 0x7fffffff) % 1000000).padStart(6, '0');
}
async function freshCode(secret) {
  for (;;) {
    const step = Math.floor(Date.now() / 30000);
    if (step > (usedSteps.get(secret) ?? -1) && Date.now() % 30000 < 27000) {
      usedSteps.set(secret, step); return totp(secret, step);
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
  children.push(process); let error = false; process.on('error', () => { error = true; });
  const deadline = Date.now() + 20000;
  while (Date.now() < deadline) {
    if (error || process.exitCode !== null || process.signalCode !== null) throw new Error();
    try { if ((await fetch(origin + '/health', {signal: AbortSignal.timeout(1000)})).status === 200) return process; } catch { }
    await delay(100);
  }
  throw new Error();
}
async function stopExample(child) {
  if (child.exitCode !== null || child.signalCode !== null) return;
  child.kill('SIGTERM'); await Promise.race([new Promise(done => child.once('exit', done)), delay(5000)]);
  if (child.exitCode === null && child.signalCode === null) child.kill('SIGKILL');
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

try {
  const certificate = new X509Certificate(await readFile(fixture.certificate));
  const pin = createHash('sha256').update(certificate.publicKey.export({type: 'spki', format: 'der'})).digest('base64');
  browser = await chromium.launch({headless: true, args: [`--ignore-certificate-errors-spki-list=${pin}`]});
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

  progress('account-creation-and-setup');
  const user = status(await operation(admin, '/api/admin/users', {username: 'browser-user', displayName: 'Browser user', code: await freshCode(fixture.adminTotpSecret)}), 201);
  const setup = status(await operation(admin, `/api/admin/users/${user.id}/setup`, {code: await freshCode(fixture.adminTotpSecret)}), 200);
  await hide(admin);
  const userContext = await browser.newContext(); contexts.push(userContext);
  const userPage = await identityPage(userContext); let password = secret();
  status(await submit(userPage, 'setup', {userId: user.id, token: setup.token, password}), 204);
  status(await submit(userPage, 'setup', {userId: user.id, token: setup.token, password}), 400);
  status(await login(userPage, user.username, password), 204);
  status(await operation(userPage, '/api/admin/users'), 403);
  status(await operation(userPage, `/api/me/sessions/${adminSessionId}/revoke`, {}), 404);
  status(await operation(userPage, '/api/me/profile', {displayName: 'Browser verified user'}), 204);
  const profile = status(await clickResult(userPage, 'profile'), 200); check(profile.displayName === 'Browser verified user');
  await hide(userPage);

  const applications = [];
  for (const [name, rpHost, apiHost] of [['a', '127.0.0.2', '127.0.0.4'], ['b', '127.0.0.3', '127.0.0.5']]) {
    progress(`register-application-${name}`);
    const resource = status(await operation(admin, '/api/admin/resources', {audience: `orders-${name}`, displayName: `Orders ${name}`, code: await freshCode(fixture.adminTotpSecret)}), 201);
    progress(`application-${name}-role`);
    const role = status(await operation(admin, `/api/admin/resources/${resource.id}/roles`, {roleCode: 'reader', displayName: 'Reader', code: await freshCode(fixture.adminTotpSecret)}), 201);
    progress(`application-${name}-binding`);
    status(await operation(admin, `/api/admin/users/${user.id}/roles/${role.id}/grant`, {version: 0, code: await freshCode(fixture.adminTotpSecret)}), 200);
    const origin = await freeOrigin(rpHost), apiOrigin = await freeOrigin(apiHost);
    progress(`application-${name}-client`);
    const client = status(await operation(admin, '/api/admin/clients', {configuration: {displayName: `Application ${name}`, resourceId: resource.id,
      redirectUris: [origin + '/callback'], scopes: ['openid', 'profile', 'offline_access'], allowedRoleIds: [role.id]}, code: await freshCode(fixture.adminTotpSecret)}, true), 201);
    progress(`application-${name}-validator`);
    const validator = status(await operation(admin, `/api/admin/resources/${resource.id}/validation-credential/rotate`, {version: 0, code: await freshCode(fixture.adminTotpSecret)}, true), 200);
    const queriedClient = status(await operation(admin, `/api/admin/clients/${client.client.id}`), 200);
    check(!JSON.stringify(queriedClient).includes(client.secret));
    const queriedValidator = status(await operation(admin, `/api/admin/resources/${resource.id}/validation-credential`), 200);
    check(!JSON.stringify(queriedValidator).includes(validator.secret)); await hide(admin);
    const env = {IAM_ISSUER: fixture.issuer, IAM_IDENTITY_FRONTEND_URI: fixture.issuer + '/identity',
      RP_NAME: name, RP_ORIGIN: origin, RP_CLIENT_ID: client.client.id, RP_CLIENT_SECRET: client.secret,
      RP_TLS_CERT_FILE: fixture.certificate, RP_TLS_KEY_FILE: fixture.privateKey,
      API_ORIGIN: apiOrigin, API_AUDIENCE: resource.audience, API_VALIDATION_CLIENT_ID: resource.id, API_VALIDATION_CLIENT_SECRET: validator.secret,
      API_TLS_CERT_FILE: fixture.certificate, API_TLS_KEY_FILE: fixture.privateKey};
    applications.push({name, origin, apiOrigin, env, clientId: client.client.id, resourceId: resource.id, roleId: role.id});
  }
  progress('two-independent-applications');
  for (const app of applications) await startExample('api.mjs', app.env, app.apiOrigin);
  for (const app of applications) app.process = await startExample('rp.mjs', app.env, app.origin);
  // Separate browser proves that the applications themselves require exactly one password interaction.
  const appContext = await browser.newContext(); contexts.push(appContext);
  const callbacks = new Map(); let passwords = 0;
  appContext.on('request', request => {
    const url = new URL(request.url());
    if (url.origin === fixture.issuer && url.pathname === '/login' && request.method() === 'POST') passwords++;
    if (applications.some(app => url.origin === app.origin) && url.pathname === '/callback') callbacks.set(url.origin, url.href);
  });
  const pageA = await appContext.newPage(), pageB = await appContext.newPage();
  await completeApplicationLogin(pageA, applications[0].origin, {username: user.username, password});
  check(await pageA.locator('[data-profile="sub"]').textContent() === user.id);
  await completeApplicationLogin(pageB, applications[1].origin);
  check(await pageB.locator('[data-profile="sub"]').textContent() === user.id); check(passwords === 1);
  for (const [page, app] of [[pageA, applications[0]], [pageB, applications[1]]]) {
    const cookie = (await appContext.cookies(app.origin)).find(value => value.name === `__Host-IAM-RP-${app.name}`);
    check(cookie?.httpOnly && cookie.secure && cookie.sameSite === 'Lax');
    check(await page.evaluate(() => localStorage.length + sessionStorage.length) === 0);
    check((await page.goto(app.origin + '/orders')).status() === 200);
    await page.goto(app.origin + '/profile');
  }
  progress('callback-replay-csrf-refresh');
  check((await pageA.goto(callbacks.get(applications[0].origin))).status() === 400);
  await pageA.goto(applications[0].origin + '/profile');
  check(await applicationForm(pageA, '/refresh', {csrf_token: 'wrong'}) === 403);
  await pageA.goto(applications[0].origin + '/profile');
  await pageA.getByRole('button', {name: '续期应用访问', exact: true}).click();
  await pageA.waitForURL(applications[0].origin + '/profile');
  check(await pageA.locator('[data-profile="sub"]').textContent() === user.id);
  check((await pageA.goto(applications[0].apiOrigin + '/orders')).status() === 401);
  await pageA.goto(applications[0].origin + '/profile');

  progress('cross-resource-isolation');
  await stopExample(applications[1].process);
  applications[1].process = await startExample('rp.mjs', {...applications[1].env, API_ORIGIN: applications[0].apiOrigin}, applications[1].origin);
  await completeApplicationLogin(pageB, applications[1].origin);
  check((await pageB.goto(applications[1].origin + '/orders')).status() === 401);
  await stopExample(applications[1].process);
  applications[1].process = await startExample('rp.mjs', applications[1].env, applications[1].origin);
  await completeApplicationLogin(pageB, applications[1].origin);
  check((await pageB.goto(applications[1].origin + '/orders')).status() === 200);

  progress('local-and-iam-logout');
  await pageA.goto(applications[0].origin + '/profile');
  await pageA.getByRole('button', {name: '退出此应用', exact: true}).click();
  await pageA.waitForURL(applications[0].origin + '/signed-out');
  check((await pageA.goto(applications[0].origin + '/profile')).status() === 401);
  check((await pageB.goto(applications[1].origin + '/profile')).status() === 200);
  await completeApplicationLogin(pageA, applications[0].origin); check(passwords === 1);
  const identity = await identityPage(appContext);
  status(await clickResult(identity, 'logout'), 204);
  status(await clickResult(identity, 'profile'), 401);
  check((await pageA.goto(applications[0].origin + '/profile')).status() === 200);
  check((await pageB.goto(applications[1].origin + '/profile')).status() === 200);

  progress('authorization-and-session-revocation');
  const authorizations = status(await operation(userPage, '/api/me/authorizations'), 200);
  const aGrant = authorizations.items.filter(value => value.clientId === applications[0].clientId && value.status === 'ACTIVE').at(-1);
  check(aGrant);
  status(await operation(userPage, `/api/me/authorizations/${aGrant.id}/revoke`, {}), 204);
  await delay(5100);
  check((await pageA.goto(applications[0].origin + '/orders')).status() === 401);
  check((await pageB.goto(applications[1].origin + '/orders')).status() === 200);
  // Other grants remain separate; revoke-all is the definitive all-app boundary.
  status(await operation(userPage, '/api/me/sessions/revoke-all', {}), 204);
  status(await clickResult(userPage, 'profile'), 401);
  await delay(5100);
  check((await pageA.goto(applications[0].origin + '/orders')).status() === 401);
  check((await pageB.goto(applications[1].origin + '/orders')).status() === 401);

  progress('password-recovery-and-proof-replay');
  const recovery = status(await operation(admin, `/api/admin/users/${user.id}/password-recovery`, {code: await freshCode(fixture.adminTotpSecret)}), 200);
  await hide(admin); const nextPassword = secret();
  status(await submit(userPage, 'recovery', {userId: user.id, token: recovery.token, newPassword: nextPassword}), 204);
  status(await submit(userPage, 'recovery', {userId: user.id, token: recovery.token, newPassword: secret()}), 400);
  status(await login(userPage, user.username, password), 401);
  password = nextPassword; status(await login(userPage, user.username, password), 204);

  progress('factor-enrollment-replacement-and-recovery');
  const enrollment = status(await operation(userPage, '/api/me/mfa/totp/enrollment', {currentPassword: password}), 200); await hide(userPage);
  const codes = status(await operation(userPage, '/api/me/mfa/totp/enrollment/confirm', {factorId: enrollment.factorId, code: await freshCode(enrollment.secret)}), 200);
  check(codes.codes.length === 10); await hide(userPage);
  // An application user's TOTP does not grant IAM administration.
  status(await operation(userPage, '/api/admin/me'), 403);
  const replacement = status(await operation(userPage, '/api/me/mfa/totp/replacement', {currentPassword: password, code: await freshCode(enrollment.secret)}), 200); await hide(userPage);
  const replacedCodes = status(await operation(userPage, '/api/me/mfa/totp/replacement/complete', {replacementId: replacement.replacementId, token: replacement.token, code: await freshCode(replacement.secret)}), 200);
  check(replacedCodes.codes.length === 10); await hide(userPage);
  // Factor changes end prior sessions. Recovery authenticates password again and consumes one code.
  status(await login(userPage, user.username, password), 204);
  const factorRecovery = status(await operation(userPage, '/api/me/mfa/totp/recovery', {currentPassword: password, recoveryCode: replacedCodes.codes[0]}), 200); await hide(userPage);
  status(await operation(userPage, '/api/admin/me'), 403);
  const recoveredCodes = status(await operation(userPage, '/api/me/mfa/totp/recovery/complete', {recoveryId: factorRecovery.recoveryId, token: factorRecovery.token, code: await freshCode(factorRecovery.secret)}), 200);
  check(recoveredCodes.codes.length === 10); await hide(userPage);
  status(await login(userPage, user.username, password), 204);
  status(await operation(userPage, '/api/me/mfa/totp/recovery', {currentPassword: password, recoveryCode: replacedCodes.codes[0]}), 400);

  progress('administrator-forced-logout-and-audits');
  status(await operation(admin, `/api/admin/users/${user.id}/sessions/revoke-all`, {code: await freshCode(fixture.adminTotpSecret)}), 204);
  status(await clickResult(userPage, 'profile'), 401);
  const audits = status(await operation(admin, '/api/admin/audits?pageSize=100'), 200);
  check(audits.items.length > 0);
  const serialized = JSON.stringify(audits);
  check(![fixture.adminPassword, fixture.adminTotpSecret, password, setup.token, recovery.token, factorRecovery.token].some(value => serialized.includes(value)));
  for (const context of contexts) for (const page of context.pages()) {
    check(await page.evaluate(() => localStorage.length + sessionStorage.length) === 0);
  }
  progress('complete');
  process.stdout.write(JSON.stringify({event: 'browser_verification_passed', checks, skipped: 0}) + '\n');
} catch {
  process.stderr.write(JSON.stringify({event: 'browser_scenario_failed', stage, status: lastStatus, checks}) + '\n');
  // Safe diagnostic only: no Playwright exception, response, URL, profile or secrets.
  process.stdout.write(JSON.stringify({event: 'browser_scenario_failed', stage, status: lastStatus, checks}) + '\n');
  process.exitCode = 1;
} finally {
  await browser?.close();
  for (const child of children) await stopExample(child);
  for (const log of logs) await log.close();
}
