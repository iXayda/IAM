import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createServer, request } from 'node:http';
import { exportJWK, generateKeyPair, SignJWT } from 'jose';
import { createRpServer } from './rp.mjs';

const issuer = 'https://iam.example.test';
const origin = 'https://rp.example.test';
const apiOrigin = 'https://resource.example.test';
const keys = await generateKeyPair('RS256', { modulusLength: 2048 });
const jwk = { ...await exportJWK(keys.publicKey), kid: 'test-key', alg: 'RS256', use: 'sig' };
const json = (body, status = 200) => new Response(JSON.stringify(body), {
  status, headers: { 'Content-Type': 'application/json' },
});

function barrier() {
  let started, release;
  const entered = new Promise(done => { started = done; });
  const pending = new Promise(done => { release = done; });
  return { entered, release, async wait() { started(); await pending; } };
}

async function fixture(t) {
  const state = { token: undefined, nonce: undefined, refreshCalls: [], rejected: false };
  const authTime = Math.floor(Date.now() / 1000);
  t.mock.method(globalThis, 'fetch', async (input, options) => {
    const url = new URL(input);
    const headers = new Headers(options.headers);
    assert.equal(options.redirect, 'error');
    if (url.href === issuer + '/.well-known/openid-configuration') return json({
      issuer, authorization_endpoint: issuer + '/oauth2/authorize', token_endpoint: issuer + '/oauth2/token',
      jwks_uri: issuer + '/oauth2/jwks', userinfo_endpoint: issuer + '/userinfo',
      response_types_supported: ['code'], response_modes_supported: ['query'],
      code_challenge_methods_supported: ['S256'], token_endpoint_auth_methods_supported: ['client_secret_basic'],
      id_token_signing_alg_values_supported: ['RS256'],
    });
    if (url.href === issuer + '/oauth2/jwks') return json({ keys: [jwk] });
    if (url.href === issuer + '/oauth2/token') {
      assert.equal(options.method, 'POST');
      assert.equal(headers.get('Authorization'), 'Basic ' + Buffer.from('client:secret').toString('base64'));
      const fields = new URLSearchParams(options.body);
      const grant = fields.get('grant_type');
      if (grant === 'refresh_token') {
        state.refreshCalls.push(fields.get('refresh_token'));
        await state.refreshGate?.wait();
        if (state.refreshFailure) return json({ error: 'invalid_grant' }, 400);
      } else {
        assert.equal(grant, 'authorization_code');
        assert.equal(fields.get('code'), 'test-code');
        assert.ok(fields.get('code_verifier'));
      }
      state.token = grant === 'refresh_token' ? 'access-2' : 'access-1';
      const tokens = { access_token: state.token, refresh_token: grant === 'refresh_token' ? 'refresh-2' : 'refresh-1',
        token_type: 'Bearer', expires_in: 300, scope: 'openid profile offline_access' };
      if (grant === 'authorization_code') tokens.id_token = await new SignJWT({
        iss: issuer, aud: 'client', sub: 'stable-user', auth_time: authTime, nonce: state.nonce,
        iat: Math.floor(Date.now() / 1000), exp: Math.floor(Date.now() / 1000) + 300,
      }).setProtectedHeader({ alg: 'RS256', kid: jwk.kid, typ: 'JWT' }).sign(keys.privateKey);
      return json(tokens);
    }
    const route = url.href === issuer + '/userinfo' ? 'profile' : url.href === apiOrigin + '/orders' ? 'orders' : undefined;
    assert.ok(route, 'Unexpected upstream request: ' + url.href);
    const token = headers.get('Authorization')?.slice(7);
    if (state.oldGate?.route === route && state.oldGate.token === token) await state.oldGate.wait();
    if (token !== state.token || state.rejected) return json({ error: 'invalid_token' }, 401);
    return json(route === 'profile' ? { sub: 'stable-user', name: 'Test user' } : { orders: [] });
  });
  const rp = await createRpServer({ issuer, origin, apiOrigin, name: 'test', clientId: 'client', clientSecret: 'secret',
    identityFrontendUri: issuer + '/identity' });
  // Exercise the real request listener over loopback HTTP; TLS configuration is outside these lifecycle tests.
  const server = createServer((incoming, outgoing) => rp.emit('request', incoming, outgoing));
  t.after(async () => {
    state.oldGate?.release(); state.refreshGate?.release();
    server.closeAllConnections();
    await new Promise(done => server.close(done));
    rp.close();
  });
  await new Promise((done, reject) => { server.once('error', reject); server.listen(0, '127.0.0.1', done); });
  function send(path, { cookie, csrf, method = 'GET' } = {}) {
    return new Promise((done, reject) => {
      const body = method === 'POST' ? new URLSearchParams({ csrf_token: csrf }).toString() : undefined;
      const outgoing = request({ host: '127.0.0.1', port: server.address().port, path, method,
        headers: { Host: 'rp.example.test', ...(cookie ? { Cookie: cookie } : {}),
          ...(body ? { Origin: origin, 'Content-Type': 'application/x-www-form-urlencoded', 'Content-Length': Buffer.byteLength(body) } : {}) },
      }, incoming => {
        const chunks = [];
        incoming.on('data', chunk => chunks.push(chunk));
        incoming.on('end', () => done({ status: incoming.statusCode, headers: incoming.headers, body: Buffer.concat(chunks).toString() }));
      });
      outgoing.on('error', reject); outgoing.end(body);
    });
  }
  const anonymous = await send('/');
  assert.equal(anonymous.status, 200);
  const anonymousCookie = anonymous.headers['set-cookie'][0].split(';')[0];
  const csrf = html => /name="csrf_token" value="([^"]+)"/.exec(html)[1];
  const authorization = await send('/login', { cookie: anonymousCookie, csrf: csrf(anonymous.body), method: 'POST' });
  assert.equal(authorization.status, 303);
  const url = new URL(authorization.headers.location);
  state.nonce = url.searchParams.get('nonce');
  const callback = await send('/callback?' + new URLSearchParams({ code: 'test-code', state: url.searchParams.get('state') }), { cookie: anonymousCookie });
  assert.equal(callback.status, 303, callback.body);
  const cookie = callback.headers['set-cookie'][0].split(';')[0];
  const profile = await send('/profile', { cookie });
  assert.equal(profile.status, 200);
  const session = { cookie, csrf: csrf(profile.body) };
  const post = path => send(path, { ...session, method: 'POST' });
  const blockOld = route => (state.oldGate = { ...barrier(), route, token: state.token });
  const blockRefresh = () => (state.refreshGate = barrier());
  return { state, send, post, session, blockOld, blockRefresh };
}

function cleared(response) {
  assert.match(response.headers['set-cookie']?.[0] ?? '', /; Max-Age=0;/);
}

for (const route of ['profile', 'orders']) {
  test(`${route}: a late old-token rejection cannot delete a refreshed session`, { timeout: 5000 }, async t => {
    const { state, send, post, session, blockOld } = await fixture(t);
    const old = blockOld(route);
    const pending = send('/' + route, session); await old.entered;
    assert.equal((await post('/refresh')).status, 303);
    assert.equal((await send('/' + route, session)).status, 200);
    old.release();
    const rejected = await pending;
    assert.equal(rejected.status, 401);
    assert.equal(rejected.headers['set-cookie'], undefined);
    assert.equal((await send('/' + route, session)).status, 200);
    assert.deepEqual(state.refreshCalls, ['refresh-1']);
  });

  test(`${route}: a late old-token rejection cannot delete a refresh in flight`, { timeout: 5000 }, async t => {
    const { state, send, post, session, blockOld, blockRefresh } = await fixture(t);
    const old = blockOld(route), refresh = blockRefresh();
    const pending = send('/' + route, session); await old.entered;
    const refreshing = post('/refresh'); await refresh.entered;
    state.rejected = true; old.release();
    const rejected = await pending;
    state.rejected = false; refresh.release();
    const refreshed = await refreshing;
    assert.equal(rejected.status, 401);
    assert.equal(rejected.headers['set-cookie'], undefined);
    assert.equal(refreshed.status, 303);
    assert.equal((await send('/' + route, session)).status, 200);
    assert.deepEqual(state.refreshCalls, ['refresh-1']);
  });

  test(`${route}: rejection of the current authentication still clears the session`, { timeout: 5000 }, async t => {
    const { state, send, post, session } = await fixture(t);
    state.rejected = true;
    const rejected = await send('/' + route, session);
    assert.equal(rejected.status, 401); cleared(rejected);
    state.rejected = false;
    assert.equal((await send('/' + route, session)).status, 401);
    assert.equal((await post('/refresh')).status, 403);
    assert.deepEqual(state.refreshCalls, []);
  });

  test(`${route}: logout cannot be undone by a refresh or an older request`, { timeout: 5000 }, async t => {
    const { state, send, post, session, blockOld, blockRefresh } = await fixture(t);
    const old = blockOld(route), refresh = blockRefresh();
    const pending = send('/' + route, session); await old.entered;
    const refreshing = post('/refresh'); await refresh.entered;
    const logout = await post('/logout');
    assert.equal(logout.status, 303); cleared(logout);
    refresh.release();
    const refreshed = await refreshing;
    assert.equal(refreshed.status, 401); cleared(refreshed);
    old.release();
    const rejected = await pending;
    assert.equal(rejected.status, 401); cleared(rejected);
    assert.equal((await send('/' + route, session)).status, 401);
    assert.equal((await post('/refresh')).status, 403);
    assert.deepEqual(state.refreshCalls, ['refresh-1']);
  });

  test(`${route}: a failed refresh cannot be restored by an older rejection or retry its parent`, { timeout: 5000 }, async t => {
    const { state, send, post, session, blockOld, blockRefresh } = await fixture(t);
    const old = blockOld(route), refresh = blockRefresh();
    const pending = send('/' + route, session); await old.entered;
    const refreshing = post('/refresh'); await refresh.entered;
    state.refreshFailure = true; refresh.release();
    const refreshed = await refreshing;
    assert.equal(refreshed.status, 401); cleared(refreshed);
    state.rejected = true; old.release();
    const rejected = await pending;
    assert.equal(rejected.status, 401); cleared(rejected);
    state.rejected = false;
    assert.equal((await send('/' + route, session)).status, 401);
    assert.equal((await post('/refresh')).status, 403);
    assert.deepEqual(state.refreshCalls, ['refresh-1']);
  });
}
