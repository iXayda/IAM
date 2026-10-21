import { verifyAccounts } from './accounts.mjs';
import { verifyApplication } from './application.mjs';
import { verifyOidc } from './oidc.mjs';
import { verifyMfa } from './mfa.mjs';

export const scenarios = Object.freeze({
  accounts: verifyAccounts,
  'application-a': verifyApplication,
  'application-b': verifyApplication,
  oidc: verifyOidc,
  mfa: verifyMfa,
});
