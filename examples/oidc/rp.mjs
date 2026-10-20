import { createServer } from 'node:https';
import { timingSafeEqual } from 'node:crypto';
import { resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import * as oidc from 'openid-client';
import { httpsIssuer, httpsOrigin, identityFrontendUri, loadRpConfig } from './config.mjs';
import { applySecurityHeaders, createBoundedFetch, readForm, requestUrl, sendJson } from './http.mjs';
import { createSessionStore, ReauthenticationRequired } from './sessions.mjs';

const CALLBACK_FIELDS = ['code', 'state', 'error', 'error_description', 'error_uri', 'iss', 'session_state'];
const SCOPES = ['openid', 'profile', 'offline_access'];
function invalid() { const error = new Error('Invalid RP request'); error.code = 'invalid_request'; return error; }
function escape(value) { return String(value).replace(/[&<>"']/g, character => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[character]); }
function parameters(url, allowed = []) {
  const seen = new Set();
  for (const [key] of url.searchParams) {
    if (!allowed.includes(key) || seen.has(key)) throw invalid();
    seen.add(key);
  }
}
function html(response, status, title, content, issuer, formPage = false) {
  applySecurityHeaders(response);
  if (formPage) response.setHeader('Referrer-Policy', 'same-origin');
  response.setHeader('Content-Security-Policy', `default-src 'none'; form-action 'self' ${issuer}; frame-ancestors 'none'; base-uri 'none'`);
  response.writeHead(status, { 'Content-Type': 'text/html; charset=utf-8' });
  response.end('<!doctype html><html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">'
    + `<title>${escape(title)}</title></head><body><main><h1>${escape(title)}</h1>${content}</main></body></html>`);
}
function redirect(response, target) { applySecurityHeaders(response); response.writeHead(303, { Location: target }); response.end(); }
function form(action, label, session) {
  return `<form method="post" action="${action}"><input type="hidden" name="csrf_token" value="${escape(session.csrfToken)}">`
    + `<button type="submit">${escape(label)}</button></form>`;
}
function readCookie(request, name) {
  const header = request.headers.cookie;
  if (typeof header !== 'string' || header.length > 8192) return undefined;
  const matches = header.split(';').map(part => part.trim()).filter(part => part.startsWith(`${name}=`));
  if (matches.length !== 1) return undefined;
  const id = matches[0].slice(name.length + 1);
  return /^[A-Za-z0-9_-]{43}$/.test(id) ? id : undefined;
}
function cookie(response, name, session) {
  const age = session ? Math.max(1, Math.ceil((session.expiresAt - Date.now()) / 1000)) : 0;
  response.setHeader('Set-Cookie', `${name}=${session?.id ?? ''}; Path=/; Max-Age=${age}; Secure; HttpOnly; SameSite=Lax`);
}
function authorizedAction(request, session, fields, origin) {
  const origins = [];
  for (let index = 0; index < request.rawHeaders.length; index += 2)
    if (request.rawHeaders[index].toLowerCase() === 'origin') origins.push(request.rawHeaders[index + 1]);
  const token = fields.get('csrf_token');
  if (!session || origins.length !== 1 || origins[0] !== origin || typeof token !== 'string' || !/^[A-Za-z0-9_-]{43}$/.test(token)) return false;
  return timingSafeEqual(Buffer.from(token), Buffer.from(session.csrfToken));
}
function grantedScopes(tokens) {
  if (typeof tokens.scope !== 'string') throw invalid();
  const scopes = tokens.scope.split(' ');
  if (!scopes.length || scopes.some(value => !SCOPES.includes(value)) || new Set(scopes).size !== scopes.length) throw invalid();
  if (tokens.refresh_token !== undefined && !scopes.includes('offline_access')) throw invalid();
  return scopes;
}
function tokenAuthentication(tokens, before) {
  const scopes = grantedScopes(tokens);
  if (typeof tokens.access_token !== 'string' || !tokens.access_token || !/^bearer$/i.test(tokens.token_type ?? '')
      || !Number.isSafeInteger(tokens.expires_in) || tokens.expires_in < 1 || tokens.expires_in > 300) throw invalid();
  const claims = tokens.claims();
  if (!before && (!scopes.includes('openid') || !claims || typeof tokens.id_token !== 'string')) throw invalid();
  if (claims && (typeof claims.sub !== 'string' || !claims.sub || !Number.isSafeInteger(claims.auth_time)
      || claims.auth_time < 1 || claims.auth_time > Date.now() / 1000 + 30
      || !Number.isSafeInteger(claims.exp))) throw invalid();
  if (before && claims && (claims.sub !== before.subject || claims.auth_time !== before.authTime)) throw invalid();
  if (!scopes.includes('openid') && tokens.id_token !== undefined) throw invalid();
  return {
    accessToken: tokens.access_token, refreshToken: tokens.refresh_token,
    subject: claims?.sub ?? before.subject, authTime: claims?.auth_time ?? before.authTime, scopes,
    accessExpiresAt: Math.min(Date.now() + tokens.expires_in * 1000, claims ? claims.exp * 1000 : Infinity),
  };
}
function profile(value, subject) {
  if (!value || value.sub !== subject) throw invalid();
  const selected = { sub: subject };
  for (const name of ['name', 'preferred_username']) if (value[name] !== undefined) {
    if (typeof value[name] !== 'string' || value[name].length > 1024) throw invalid();
    selected[name] = value[name];
  }
  return selected;
}
function metadata(config, issuer) {
  const values = config.serverMetadata();
  if (values.issuer !== issuer || !values.response_types_supported?.includes('code')
      || !values.response_modes_supported?.includes('query') || !values.code_challenge_methods_supported?.includes('S256')
      || !values.token_endpoint_auth_methods_supported?.includes('client_secret_basic')
      || !values.id_token_signing_alg_values_supported?.includes('RS256')) throw invalid();
  const origin = httpsOrigin(issuer).origin;
  for (const field of ['authorization_endpoint', 'token_endpoint', 'jwks_uri', 'userinfo_endpoint']) {
    const endpoint = new URL(values[field]);
    if (endpoint.protocol !== 'https:' || endpoint.origin !== origin || endpoint.username || endpoint.password || endpoint.hash) throw invalid();
  }
}

/** The same confidential Web/BFF implementation runs as RP A and RP B with independent configuration. */
export async function createRpServer(configuration) {
  const issuer = httpsIssuer(configuration.issuer);
  const issuerUrl = httpsOrigin(issuer);
  const origin = httpsOrigin(configuration.origin);
  if (!/^[a-z][a-z0-9_]{0,31}$/.test(configuration.name) || typeof configuration.clientId !== 'string'
      || !configuration.clientId || typeof configuration.clientSecret !== 'string' || !configuration.clientSecret) throw invalid();
  const scope = configuration.scopes ?? SCOPES;
  if (!Array.isArray(scope) || !scope.includes('openid') || new Set(scope).size !== scope.length
      || scope.some(value => !SCOPES.includes(value))) throw invalid();
  const identityFrontend = identityFrontendUri(configuration.identityFrontendUri, issuer);
  const fetchIam = createBoundedFetch([issuerUrl.origin]);
  const config = await oidc.discovery(issuerUrl, configuration.clientId, {
    token_endpoint_auth_method: 'client_secret_basic', id_token_signed_response_alg: 'RS256',
  }, oidc.ClientSecretBasic(configuration.clientSecret), {
    execute: [oidc.enableNonRepudiationChecks], [oidc.customFetch]: fetchIam, timeout: 10,
  });
  metadata(config, issuer);
  const store = createSessionStore(configuration);
  const name = `__Host-IAM-RP-${configuration.name}`;
  const callback = new URL('/callback', origin).href;
  const apiOrigin = configuration.apiOrigin ? httpsOrigin(configuration.apiOrigin) : undefined;
  const fetchApi = apiOrigin ? createBoundedFetch([apiOrigin.origin], { timeoutMs: 5000, maxBytes: 65536 }) : undefined;
  const refresh = async (parent, before) => tokenAuthentication(await oidc.refreshTokenGrant(config, parent), before);
  const render = (response, status, title, content, formPage = false) => html(response, status, title, content, issuerUrl.origin, formPage);

  async function handle(request, response) {
    const url = requestUrl(request, origin);
    const id = readCookie(request, name);
    const session = store.get(id);
    if (request.method === 'GET' && url.pathname === '/health') {
      parameters(url); return sendJson(response, 200, { status: 'UP', component: 'oidc-bff', name: configuration.name });
    }
    if (request.method === 'GET' && url.pathname === '/') {
      parameters(url);
      if (session?.authentication) return redirect(response, '/profile');
      const anonymous = session ?? store.create();
      cookie(response, name, anonymous);
      return render(response, 200, `应用 ${configuration.name}`, '<p>使用 IAM 账号登录此应用。</p>'
        + form('/login', 'Sign in with IAM', anonymous), true);
    }
    if (request.method === 'POST' && ['/login', '/logout', '/refresh'].includes(url.pathname)) {
      parameters(url);
      const fields = await readForm(request, { allowedKeys: ['csrf_token'] });
      const current = store.get(id);
      if (!authorizedAction(request, current, fields, origin.origin)) return render(response, 403, '请求被拒绝', '<a href="/">返回应用</a>');
      if (url.pathname === '/login') {
        if (current.authentication) return redirect(response, '/profile');
        const verifier = oidc.randomPKCECodeVerifier(), state = oidc.randomState(), nonce = oidc.randomNonce();
        const challenge = await oidc.calculatePKCECodeChallenge(verifier);
        if (!store.beginLogin(id, { verifier, state, nonce })) throw invalid();
        return redirect(response, oidc.buildAuthorizationUrl(config, { redirect_uri: callback, scope: scope.join(' '),
          code_challenge: challenge, code_challenge_method: 'S256', state, nonce, response_mode: 'query' }).href);
      }
      if (url.pathname === '/refresh') {
        await store.access(id, refresh, { forceRefresh: true });
        return redirect(response, '/profile');
      }
      store.delete(id); cookie(response, name);
      return redirect(response, '/signed-out');
    }
    if (request.method === 'GET' && url.pathname === '/callback') {
      parameters(url, CALLBACK_FIELDS);
      const transaction = store.takeLogin(id, url.searchParams.get('state'));
      if (!transaction) throw invalid();
      try {
        const tokens = await oidc.authorizationCodeGrant(config, url, { expectedState: transaction.state,
          expectedNonce: transaction.nonce, pkceCodeVerifier: transaction.verifier, idTokenExpected: true });
        const authentication = tokenAuthentication(tokens);
        if (authentication.scopes.some(value => !scope.includes(value))) throw invalid();
        await oidc.fetchUserInfo(config, authentication.accessToken, authentication.subject);
        const created = store.commitLogin(id, transaction.exchangeId, authentication);
        if (!created) throw invalid();
        cookie(response, name, created);
        return redirect(response, '/profile');
      } catch {
        if (store.cancelLogin(id, transaction.exchangeId)) cookie(response, name);
        return render(response, 400, '登录未完成', '<p>请重新发起登录。</p><a href="/">登录</a>');
      }
    }
    if (request.method === 'GET' && url.pathname === '/profile') {
      parameters(url);
      const authentication = await store.access(id, refresh);
      let userinfo;
      try { userinfo = profile(await oidc.fetchUserInfo(config, authentication.accessToken, authentication.subject), authentication.subject); }
      catch {
        // Refresh replaces this snapshot before I/O; a late failure must not discard its successor.
        if (store.get(id)?.authentication === authentication) store.delete(id);
        throw new ReauthenticationRequired();
      }
      const current = store.get(id);
      if (!current) throw new ReauthenticationRequired();
      const labels = { sub: 'Subject', name: '姓名', preferred_username: '用户名' };
      const rows = Object.entries(userinfo).map(([field, value]) => `<dt>${labels[field]}</dt><dd data-profile="${field}">${escape(value)}</dd>`).join('');
      return render(response, 200, `应用 ${configuration.name} 已登录`, '<dl>' + rows + '</dl>'
        + (apiOrigin ? '<p><a href="/orders">查看示例订单</a></p>' : '')
        + (authentication.refreshToken ? form('/refresh', '续期应用访问', current) : '')
        + form('/logout', '退出此应用', current), true);
    }
    if (request.method === 'GET' && url.pathname === '/orders' && apiOrigin) {
      parameters(url);
      const authentication = await store.access(id, refresh);
      try {
        const upstream = await fetchApi(new URL('/orders', apiOrigin), { headers: { Authorization: `Bearer ${authentication.accessToken}` } });
        if (![200, 401, 403, 503].includes(upstream.status)) throw invalid();
        if (upstream.status === 401) {
          if (store.get(id)?.authentication === authentication) store.delete(id);
          throw new ReauthenticationRequired();
        }
        if (upstream.status === 403) return sendJson(response, 403, { error: 'insufficient_role' });
        if (upstream.status === 503) return sendJson(response, 503, { error: 'resource_unavailable' });
        const orders = await upstream.json();
        return sendJson(response, 200, orders);
      } catch (error) {
        if (error instanceof ReauthenticationRequired) throw error;
        return sendJson(response, 503, { error: 'resource_unavailable' });
      }
    }
    if (request.method === 'GET' && url.pathname === '/signed-out') {
      parameters(url);
      return render(response, 200, '已退出应用', '<p>此应用会话已清除。其他应用及 IAM 会话分别管理。</p>'
        + `<a href="${escape(identityFrontend.href)}">管理 IAM 会话</a> <a href="/">再次登录</a>`);
    }
    render(response, 404, '页面不存在', '<a href="/">返回应用</a>');
  }

  const server = createServer({ ...configuration.tls, minVersion: 'TLSv1.2', maxHeaderSize: 16384 }, (request, response) => {
    handle(request, response).catch(error => {
      if (response.headersSent || response.destroyed) return response.destroy();
      if (error instanceof ReauthenticationRequired) {
        if (!store.get(readCookie(request, name))) cookie(response, name);
        return render(response, 401, '需要重新登录', '<p>应用授权已失效或续期未完成，请重新登录。</p><a href="/">登录</a>');
      }
      response.setHeader('Connection', 'close');
      render(response, error.code === 'session_capacity' ? 503 : 400, '请求未完成', '<a href="/">返回应用</a>');
    });
  });
  server.requestTimeout = 15000; server.headersTimeout = 10000; server.keepAliveTimeout = 1000;
  server.on('close', () => store.clear());
  return server;
}

async function main() {
  const config = loadRpConfig();
  const server = await createRpServer(config);
  await new Promise((done, reject) => { server.once('error', reject); server.listen(Number(config.origin.port || 443), config.bindAddress, done); });
  process.stdout.write(JSON.stringify({ event: 'rp_ready', name: config.name, origin: config.origin.origin }) + '\n');
  for (const signal of ['SIGINT', 'SIGTERM']) process.once(signal, () => { server.close(); server.closeAllConnections(); });
}
if (process.argv[1] && pathToFileURL(resolve(process.argv[1])).href === import.meta.url)
  await main().catch(() => { process.stderr.write('{"event":"rp_start_failed"}\n'); process.exitCode = 1; });
