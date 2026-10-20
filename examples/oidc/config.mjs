import { readFileSync, statSync } from 'node:fs';
import { isIP } from 'node:net';

export function configurationError(field) {
  const error = new Error(`Invalid example configuration: ${field}`);
  error.code = 'invalid_configuration';
  return error;
}

export function required(env, field) {
  const value = env[field];
  if (typeof value !== 'string' || !value || value.length > 4096) throw configurationError(field);
  return value;
}

export function httpsOrigin(value) {
  let url;
  try { url = new URL(value); } catch { throw configurationError('HTTPS origin'); }
  if (url.protocol !== 'https:' || !url.hostname || url.username || url.password
      || url.pathname !== '/' || url.search || url.hash) throw configurationError('HTTPS origin');
  return url;
}

export function httpsIssuer(value) {
  if (typeof value !== 'string') throw configurationError('IAM_ISSUER');
  httpsOrigin(value);
  // Issuer identity is exact; URL serialization changes its spelling.
  return value;
}

export function identityFrontendUri(value, issuer) {
  let url;
  try { url = new URL(value); } catch { throw configurationError('IAM_IDENTITY_FRONTEND_URI'); }
  if (url.protocol !== 'https:' || url.origin !== httpsOrigin(issuer).origin || url.username || url.password || url.search || url.hash)
    throw configurationError('IAM_IDENTITY_FRONTEND_URI');
  return url;
}

function tlsFile(path, field) {
  try {
    const info = statSync(path);
    if (!info.isFile() || info.size < 1 || info.size > 131072) throw new Error();
    return readFileSync(path);
  } catch { throw configurationError(field); }
}

function tls(env, prefix) {
  return {
    key: tlsFile(required(env, `${prefix}_TLS_KEY_FILE`), `${prefix} TLS key`),
    cert: tlsFile(required(env, `${prefix}_TLS_CERT_FILE`), `${prefix} TLS certificate`),
    minVersion: 'TLSv1.2',
  };
}

function integer(env, name, fallback, min, max) {
  if (env[name] === undefined) return fallback;
  if (!/^[0-9]+$/.test(env[name])) throw configurationError(name);
  const value = Number(env[name]);
  if (!Number.isSafeInteger(value) || value < min || value > max) throw configurationError(name);
  return value;
}

function bind(env, prefix, origin) {
  const host = env[`${prefix}_BIND_ADDRESS`] ?? origin.hostname.replace(/^\[|\]$/g, '');
  if (!isIP(host) && !/^[a-zA-Z0-9](?:[a-zA-Z0-9.-]*[a-zA-Z0-9])?$/.test(host))
    throw configurationError(`${prefix}_BIND_ADDRESS`);
  return host;
}

export function loadRpConfig(env = process.env) {
  const issuer = httpsIssuer(required(env, 'IAM_ISSUER'));
  const origin = httpsOrigin(required(env, 'RP_ORIGIN'));
  const name = required(env, 'RP_NAME');
  if (!/^[a-z][a-z0-9_]{0,31}$/.test(name)) throw configurationError('RP_NAME');
  const scopes = (env.RP_SCOPES ?? 'openid profile offline_access').split(' ');
  if (!scopes.includes('openid') || new Set(scopes).size !== scopes.length
      || scopes.some(scope => !['openid', 'profile', 'offline_access'].includes(scope))) throw configurationError('RP_SCOPES');
  return {
    issuer, origin, name, identityFrontendUri: identityFrontendUri(required(env, 'IAM_IDENTITY_FRONTEND_URI'), issuer).href,
    clientId: required(env, 'RP_CLIENT_ID'), clientSecret: required(env, 'RP_CLIENT_SECRET'),
    scopes, apiOrigin: env.API_ORIGIN ? httpsOrigin(env.API_ORIGIN) : undefined,
    tls: tls(env, 'RP'), bindAddress: bind(env, 'RP', origin),
    sessionTtlMs: integer(env, 'RP_SESSION_TTL_SECONDS', 3600, 60, 28800) * 1000,
    transactionTtlMs: integer(env, 'RP_TRANSACTION_TTL_SECONDS', 300, 1, 600) * 1000,
    maxSessions: integer(env, 'RP_MAX_SESSIONS', 1000, 1, 10000),
  };
}

export function loadApiConfig(env = process.env) {
  const issuer = httpsIssuer(required(env, 'IAM_ISSUER'));
  const origin = httpsOrigin(required(env, 'API_ORIGIN'));
  const audience = required(env, 'API_AUDIENCE');
  if (!/^[\x21-\x7e]{1,256}$/.test(audience)) throw configurationError('API_AUDIENCE');
  return {
    issuer, origin, audience, validatorId: required(env, 'API_VALIDATION_CLIENT_ID'),
    validatorSecret: required(env, 'API_VALIDATION_CLIENT_SECRET'),
    readRole: env.API_READ_ROLE ?? 'reader', writeRole: env.API_WRITE_ROLE ?? 'editor',
    positiveCacheMs: integer(env, 'API_POSITIVE_CACHE_SECONDS', 5, 0, 5) * 1000,
    tls: tls(env, 'API'), bindAddress: bind(env, 'API', origin),
  };
}
