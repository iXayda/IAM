export async function verifyMfa(scenario) {
  const {fixture, browser, contexts, check, status, progress, freshCode, identityPage, operation, login, hide,
    administrator, verifyAuditSecrets} = scenario;
  const user = fixture.user;
  const password = user.password;
  const context = await browser.newContext(); contexts.push(context);
  const userPage = await identityPage(context);
  status(await login(userPage, user.username, password), 204);
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

  progress('factor-audit-secrets');
  const {admin} = await administrator();
  await verifyAuditSecrets(admin, [fixture.adminPassword, fixture.adminTotpSecret, password, enrollment.secret,
    replacement.token, replacement.secret, factorRecovery.token, factorRecovery.secret, ...replacedCodes.codes]);
}
