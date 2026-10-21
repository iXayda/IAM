export async function verifyApplication(scenario) {
  const {fixture, suite, browser, contexts, check, status, progress, freshCode, operation, hide, freeOrigin,
    startExample, completeApplicationLogin, administrator, application, verifyAuditSecrets} = scenario;
  const {admin} = await administrator();
  const user = fixture.user;
  const [name, rpHost, apiHost] = suite === 'application-a' ? ['a', '127.0.0.2', '127.0.0.4'] : ['b', '127.0.0.3', '127.0.0.5'];
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
  const app = application({name, origin, apiOrigin, audience: resource.audience, clientId: client.client.id,
    clientSecret: client.secret, resourceId: resource.id, roleId: role.id, validationSecret: validator.secret});

  progress('registered-application-login');
  await startExample('api.mjs', app.env, app.apiOrigin);
  await startExample('rp.mjs', app.env, app.origin);
  const context = await browser.newContext(); contexts.push(context);
  const page = await context.newPage();
  await completeApplicationLogin(page, app.origin, user);
  check(await page.locator('[data-profile="sub"]').textContent() === user.id);
  check((await page.goto(app.origin + '/orders')).status() === 200);
  await verifyAuditSecrets(admin, [fixture.adminPassword, fixture.adminTotpSecret, user.password, app.clientSecret, app.validationSecret]);
}
