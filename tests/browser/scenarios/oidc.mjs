import { setTimeout as delay } from 'node:timers/promises';

export async function verifyOidc(scenario) {
  const {fixture, browser, contexts, check, status, progress, identityPage, operation, login, clickResult, applicationForm,
    startExample, stopExample, completeApplicationLogin, application, administrator, verifyAuditSecrets} = scenario;
  const user = fixture.user;
  const password = user.password;
  const applications = fixture.applications.map(application);
  check(applications.length === 2 && applications[0].resourceId !== applications[1].resourceId);
  const userContext = await browser.newContext(); contexts.push(userContext);
  const userPage = await identityPage(userContext);
  status(await login(userPage, user.username, password), 204);
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

  progress('application-audit-secrets');
  const {admin} = await administrator();
  await verifyAuditSecrets(admin, [fixture.adminPassword, fixture.adminTotpSecret, password,
    ...applications.flatMap(app => [app.clientSecret, app.validationSecret])]);
}
