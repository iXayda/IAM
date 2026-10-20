import { createServer } from 'node:https';
import { createHash } from 'node:crypto';
import { resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { createRemoteJWKSet, customFetch, decodeProtectedHeader, jwtVerify, errors } from 'jose';
import { httpsIssuer, httpsOrigin, loadApiConfig } from './config.mjs';
import { createBoundedFetch, requestUrl, sendJson } from './http.mjs';

const ROLE = /^[a-z][a-z0-9_]{0,63}$/;
const REQUIRED = ['iss', 'sub', 'aud', 'exp', 'iat', 'nbf', 'jti', 'client_id', 'scope', 'roles', 'authorization_id'];
const ALLOWED_SCOPES = new Set(['openid', 'profile', 'offline_access']);

export class ApiRejection extends Error {
  constructor(status, code) { super('Resource request rejected'); this.status = status; this.code = code; }
}
function invalid() { throw new ApiRejection(401, 'invalid_token'); }
const boundedString = value => typeof value === 'string' && /^[^\s\x00-\x1f\x7f]{1,256}$/.test(value);
const numericDate = value => Number.isSafeInteger(value) && value > 0;

function values(value, kind) {
  const result = kind === 'scope' ? typeof value === 'string' && value.length <= 1024 ? value.split(' ') : undefined : value;
  if (!Array.isArray(result) || result.length > 100 || new Set(result).size !== result.length
      || result.some(item => typeof item !== 'string' || !(kind === 'scope' ? ALLOWED_SCOPES.has(item) : ROLE.test(item)))) invalid();
  return result;
}
function audience(value, expected) {
  return typeof value === 'string' ? value === expected : Array.isArray(value) && value.length === 1 && value[0] === expected;
}
function equalSet(left, right) { return left.length === right.length && left.every(item => right.includes(item)); }
function encoded(value) { return new URLSearchParams({ x: value }).toString().slice(2); }

export function bearerToken(request) {
  const headers = [];
  for (let index = 0; index < request.rawHeaders.length; index += 2)
    if (request.rawHeaders[index].toLowerCase() === 'authorization') headers.push(request.rawHeaders[index + 1]);
  if (headers.length !== 1 || typeof headers[0] !== 'string' || headers[0].length > 16391) invalid();
  const token = /^Bearer ([A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+)$/i.exec(headers[0]);
  if (!token) invalid();
  return token[1];
}

/** Trust is deployment configuration only. Every request verifies its JWT before using an online positive cache. */
export function createOnlineAccessVerifier(config, { trustedResolver, fetchImpl, now = Date.now, maxCacheEntries = 1000 } = {}) {
  const issuer = httpsIssuer(config.issuer);
  if (!boundedString(config.audience) || !boundedString(config.validatorId)
      || typeof config.validatorSecret !== 'string' || !config.validatorSecret || config.validatorSecret.length > 4096
      || !Number.isSafeInteger(config.positiveCacheMs ?? 5000) || (config.positiveCacheMs ?? 5000) < 0
      || (config.positiveCacheMs ?? 5000) > 5000 || !Number.isSafeInteger(maxCacheEntries)
      || maxCacheEntries < 1 || maxCacheEntries > 10000) throw new TypeError('Invalid resource trust configuration');
  const cacheMs = config.positiveCacheMs ?? 5000;
  const boundedFetch = fetchImpl ?? createBoundedFetch([httpsOrigin(issuer).origin], { timeoutMs: 3000, maxBytes: 65536 });
  const jwks = trustedResolver ?? createRemoteJWKSet(new URL('/oauth2/jwks', issuer), {
    [customFetch]: boundedFetch, timeoutDuration: 3000, cooldownDuration: 5000, cacheMaxAge: 60000,
  });
  const basic = Buffer.from(`${encoded(config.validatorId)}:${encoded(config.validatorSecret)}`).toString('base64');
  const cache = new Map();
  const inflight = new Map();
  let epoch = 0;
  function dependencyFailed() { epoch++; cache.clear(); }

  async function local(token) {
    if (typeof token !== 'string' || !token || token.length > 16384) invalid();
    let header;
    try { header = decodeProtectedHeader(token); } catch { invalid(); }
    if (header.alg !== 'RS256' || header.typ !== 'at+jwt' || !boundedString(header.kid)
        || ['jku', 'jwk', 'x5u'].some(name => name in header)) invalid();
    let payload;
    try {
      ({ payload } = await jwtVerify(token, jwks, { issuer, audience: config.audience, algorithms: ['RS256'],
        typ: 'at+jwt', requiredClaims: REQUIRED, clockTolerance: 30, currentDate: new Date(now()) }));
    } catch (error) {
      if (error instanceof errors.JOSEError && !['ERR_JWKS_TIMEOUT', 'ERR_JWKS_INVALID'].includes(error.code)) invalid();
      dependencyFailed();
      throw new ApiRejection(503, 'verification_unavailable');
    }
    if (!audience(payload.aud, config.audience) || ![payload.sub, payload.client_id, payload.jti, payload.authorization_id].every(boundedString)
        || ![payload.exp, payload.iat, payload.nbf].every(numericDate) || payload.exp <= payload.iat
        || payload.exp - payload.iat > 300 || payload.nbf > payload.exp || payload.iat > now() / 1000 + 30
        || payload.exp * 1000 <= now()) invalid();
    values(payload.scope, 'scope'); values(payload.roles, 'roles');
    return payload;
  }

  async function introspect(key, token, claims) {
    const started = now();
    const generation = epoch;
    let body;
    try {
      const response = await boundedFetch(new URL('/oauth2/introspect', issuer), {
        method: 'POST', headers: { Authorization: `Basic ${basic}`, 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({ token, token_type_hint: 'access_token' }),
      });
      if (response.status !== 200 || !/^application\/json(?:\s*;|$)/i.test(response.headers.get('content-type') ?? ''))
        throw new Error();
      body = await response.json();
      if (!body || typeof body !== 'object' || Array.isArray(body) || typeof body.active !== 'boolean') throw new Error();
    } catch {
      // A known dependency failure invalidates every retained positive. No stale or offline fallback is used.
      dependencyFailed();
      throw new ApiRejection(503, 'validation_unavailable');
    }
    if (generation !== epoch) throw new ApiRejection(503, 'validation_unavailable');
    if (body.active !== true) { cache.delete(key); invalid(); }
    if (body.token_type !== 'Bearer' || body.iss !== issuer || body.sub !== claims.sub || body.client_id !== claims.client_id
        || (body.jti !== undefined && body.jti !== claims.jti) || !audience(body.aud, config.audience) || body.exp !== claims.exp || body.iat !== claims.iat || body.nbf !== claims.nbf
        || !equalSet(values(body.scope, 'scope'), values(claims.scope, 'scope'))
        || !equalSet(values(body.roles, 'roles'), values(claims.roles, 'roles')) || body.exp * 1000 <= now()) invalid();
    const principal = Object.freeze({ subject: body.sub, clientId: body.client_id, audience: config.audience,
      roles: Object.freeze([...body.roles]), scopes: Object.freeze(values(body.scope, 'scope')) });
    const expiresAt = Math.min(started + cacheMs, claims.exp * 1000);
    if (expiresAt > now()) {
      for (const [cachedKey, cached] of cache) if (cached.expiresAt <= now()) cache.delete(cachedKey);
      if (cache.size >= maxCacheEntries) cache.delete(cache.keys().next().value);
      cache.set(key, { expiresAt, principal });
    }
    return principal;
  }

  return async function verify(token) {
    const claims = await local(token);
    const key = createHash('sha256').update(JSON.stringify([config.validatorId, config.audience, token])).digest('base64url');
    const cached = cache.get(key);
    if (cached?.expiresAt > now()) return cached.principal;
    cache.delete(key);
    if (inflight.has(key)) return inflight.get(key);
    const operation = introspect(key, token, claims);
    inflight.set(key, operation);
    try { return await operation; } finally { inflight.delete(key); }
  };
}

export function createApiHandler(config, verify) {
  const origin = httpsOrigin(config.origin).origin;
  const roles = { GET: config.readRole ?? 'reader', POST: config.writeRole ?? 'editor' };
  if (!Object.values(roles).every(role => ROLE.test(role))) throw new TypeError('Invalid route role');
  return async (request, response) => {
    try {
      const url = requestUrl(request, origin);
      if ([...url.searchParams].length) throw new ApiRejection(400, 'invalid_request');
      if (request.method === 'GET' && url.pathname === '/health') return sendJson(response, 200, { status: 'UP' });
      if (url.pathname !== '/orders') throw new ApiRejection(404, 'not_found');
      if (!roles[request.method]) throw new ApiRejection(405, 'method_not_allowed');
      const principal = await verify(bearerToken(request));
      if (!principal.roles.includes(roles[request.method])) throw new ApiRejection(403, 'insufficient_role');
      let length = 0;
      for await (const chunk of request.iterator({ destroyOnReturn: false })) {
        length += chunk.length;
        if (length > 4096) throw new ApiRejection(413, 'request_too_large');
      }
      sendJson(response, 200, request.method === 'GET' ? { orders: [{ id: 'sample-order-001', description: '示例订单' }] }
        : { accepted: true, persisted: false });
    } catch (error) {
      const failure = error instanceof ApiRejection ? error : error.code === 'invalid_request'
        ? new ApiRejection(400, 'invalid_request') : new ApiRejection(503, 'validation_unavailable');
      const headers = { Connection: 'close' };
      if (failure.status === 401) headers['WWW-Authenticate'] = 'Bearer error="invalid_token"';
      if (failure.status === 405) headers.Allow = 'GET, POST';
      sendJson(response, failure.status, { error: failure.code }, headers);
    }
  };
}

export function createApiServer(config) {
  const server = createServer({ ...config.tls, minVersion: 'TLSv1.2', maxHeaderSize: 16384 },
    createApiHandler(config, createOnlineAccessVerifier(config)));
  server.requestTimeout = 10000; server.headersTimeout = 5000; server.keepAliveTimeout = 1000;
  return server;
}

async function main() {
  const config = loadApiConfig();
  const server = createApiServer(config);
  await new Promise((done, reject) => { server.once('error', reject); server.listen(Number(config.origin.port || 443), config.bindAddress, done); });
  process.stdout.write(JSON.stringify({ event: 'api_ready', origin: config.origin.origin }) + '\n');
  for (const signal of ['SIGINT', 'SIGTERM']) process.once(signal, () => { server.close(); server.closeAllConnections(); });
}
if (process.argv[1] && pathToFileURL(resolve(process.argv[1])).href === import.meta.url)
  await main().catch(() => { process.stderr.write('{"event":"api_start_failed"}\n'); process.exitCode = 1; });
