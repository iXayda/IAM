export async function verifyAccounts(scenario) {
  const {fixture, browser, contexts, status, progress, secret, freshCode, identityPage, submit, operation, login, hide, clickResult,
    check, administrator, verifyAuditSecrets} = scenario;
  const {admin, adminSessionId} = await administrator();
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

  status(await operation(userPage, '/api/me/sessions/revoke-all', {}), 204);
  status(await clickResult(userPage, 'profile'), 401);

  progress('password-recovery-and-proof-replay');
  const recovery = status(await operation(admin, `/api/admin/users/${user.id}/password-recovery`, {code: await freshCode(fixture.adminTotpSecret)}), 200);
  await hide(admin); const nextPassword = secret();
  status(await submit(userPage, 'recovery', {userId: user.id, token: recovery.token, newPassword: nextPassword}), 204);
  status(await submit(userPage, 'recovery', {userId: user.id, token: recovery.token, newPassword: secret()}), 400);
  status(await login(userPage, user.username, password), 401);
  password = nextPassword; status(await login(userPage, user.username, password), 204);

  progress('administrator-forced-logout-and-audits');
  status(await operation(admin, `/api/admin/users/${user.id}/sessions/revoke-all`, {code: await freshCode(fixture.adminTotpSecret)}), 204);
  status(await clickResult(userPage, 'profile'), 401);
  await verifyAuditSecrets(admin, [fixture.adminPassword, fixture.adminTotpSecret, password, setup.token, recovery.token]);
}
