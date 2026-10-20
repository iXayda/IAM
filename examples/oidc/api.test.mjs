import { test } from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPair, SignJWT } from 'jose';
import { createServer, request } from 'node:http';
import { ApiRejection, createApiHandler, createOnlineAccessVerifier } from './api.mjs';

const issuer = 'https://iam.example.test';
const audience = 'orders-api';
const keys = await generateKeyPair('RS256', { modulusLength: 2048 });
const config = { issuer, audience, validatorId: 'validator-orders', validatorSecret: 'independent-resource-secret', positiveCacheMs: 5000 };
function fixture({ expiresIn = 300, cacheMs = 5000, configuredIssuer = issuer } = {}) {
  const clock = { value: 2000000000000 };
  const claims = { iss: configuredIssuer, sub: 'user-uuid', aud: [audience], iat: clock.value / 1000,
    nbf: clock.value / 1000, exp: clock.value / 1000 + expiresIn, jti: 'opaque-jti', client_id: 'rp-a',
    authorization_id: 'opaque-grant-id', scope: 'openid profile offline_access', roles: ['reader'] };
  const state = { calls: 0, active: true, outage: false, response: undefined };
  const verifier = createOnlineAccessVerifier({ ...config, issuer: configuredIssuer, positiveCacheMs: cacheMs }, {
    trustedResolver: keys.publicKey, now: () => clock.value,
    fetchImpl: async (input, options) => {
      state.calls++;
      assert.equal(input.href, new URL('/oauth2/introspect', configuredIssuer).href);
      assert.equal(options.method, 'POST');
      assert.equal(Buffer.from(options.headers.Authorization.slice(6), 'base64').toString(), 'validator-orders:independent-resource-secret');
      assert.equal(options.body.get('token_type_hint'), 'access_token');
      if (state.outage) throw new Error('Validation transport unavailable');
      return new Response(JSON.stringify(state.response ?? (state.active ? { ...claims, active: true, token_type: 'Bearer' } : { active: false })),
        { status: 200, headers: { 'Content-Type': 'application/json' } });
    },
  });
  const sign = (overrides = {}, header = {}) => new SignJWT({ ...claims, ...overrides })
    .setProtectedHeader({ alg: 'RS256', typ: 'at+jwt', kid: 'configured-key', ...header }).sign(keys.privateKey);
  return { clock, claims, state, verifier, sign };
}
const rejects = (action, status) => assert.rejects(action, error => error instanceof ApiRejection && error.status === status);

const issuerIdentities = [issuer, issuer + '/', issuer + ':443', 'https://IAM.example.test'];
for (const configuredIssuer of issuerIdentities) {
  test(`JWT and introspection require the exact configured issuer: ${configuredIssuer}`, async () => {
    const { claims, state, verifier, sign } = fixture({ configuredIssuer, cacheMs: 0 });
    for (const otherIssuer of issuerIdentities.filter(value => value !== configuredIssuer))
      await rejects(verifier(await sign({ iss: otherIssuer })), 401);
    assert.equal(state.calls, 0);
    const token = await sign();
    assert.equal((await verifier(token)).subject, claims.sub);
    assert.equal(state.calls, 1);
    state.response = { ...claims, iss: issuerIdentities.find(value => value !== configuredIssuer), active: true, token_type: 'Bearer' };
    await rejects(verifier(token), 401);
    assert.equal(state.calls, 2);
  });
}

test('positive cache expires at five seconds and revoked grants are refused after the boundary', async () => {
  const { clock, state, verifier, sign } = fixture();
  const token = await sign();
  assert.deepEqual((await verifier(token)).roles, ['reader']);
  state.active = false;
  clock.value += 4999;
  await verifier(token);
  assert.equal(state.calls, 1);
  clock.value++;
  await rejects(verifier(token), 401);
  assert.equal(state.calls, 2);
});

test('positive cache never survives the exact JWT expiration even with signature clock tolerance', async () => {
  const { clock, state, verifier, sign } = fixture({ expiresIn: 2 });
  const token = await sign();
  await verifier(token);
  clock.value += 1999; await verifier(token);
  clock.value++; await rejects(verifier(token), 401);
  assert.equal(state.calls, 1);
});

test('known introspection outage clears cached positives and does not fall back to offline access', async () => {
  const { state, verifier, sign } = fixture();
  const first = await sign();
  const second = await sign({ jti: 'second-jti' });
  await verifier(first);
  state.outage = true;
  await rejects(verifier(second), 503);
  await rejects(verifier(first), 503);
  assert.equal(state.calls, 3);
});

test('zero-cache configuration rechecks every protected operation', async () => {
  const { state, verifier, sign } = fixture({ cacheMs: 0 });
  const token = await sign();
  await verifier(token);
  state.active = false;
  await rejects(verifier(token), 401);
  assert.equal(state.calls, 2);
});

test('standard introspection without an optional jti claim still binds all supported fields to the signed token', async () => {
  const { claims, state, verifier, sign } = fixture();
  const { jti, ...introspection } = claims;
  state.response = { ...introspection, active: true, token_type: 'Bearer' };
  assert.equal((await verifier(await sign())).subject, claims.sub);
});

test('ID token purpose, issuer, resource audience and token-provided key URLs are rejected before introspection', async () => {
  const { state, verifier, sign } = fixture();
  for (const token of [await sign({}, { typ: 'JWT' }), await sign({ iss: 'https://other.example.test' }),
    await sign({ aud: ['another-resource'] }), await sign({ aud: [audience, 'another-resource'] }),
    await sign({}, { jku: 'https://attacker.example.test/jwks' })]) await rejects(verifier(token), 401);
  assert.equal(state.calls, 0);
});

test('active introspection for a different resource or a different subject cannot authorize a signed token', async () => {
  for (const change of [{ aud: ['another-resource'] }, { sub: 'different-user' }, { jti: 'different-token' }, { roles: ['editor'] }]) {
    const { claims, state, verifier, sign } = fixture();
    state.response = { ...claims, active: true, token_type: 'Bearer', ...change };
    await rejects(verifier(await sign()), 401);
  }
});

test('parallel validation deduplicates an uncached token without bypassing local JWT checks', async () => {
  const { state, verifier, sign } = fixture();
  const token = await sign();
  await Promise.all(Array.from({ length: 16 }, () => verifier(token)));
  assert.equal(state.calls, 1);
});

test('a response started before a known outage cannot repopulate positive authorization afterward', async () => {
  const {claims, sign} = fixture();
  let release, started;
  const waiting = new Promise(done => { started = done; });
  const blocked = new Promise(done => { release = done; });
  let calls = 0;
  const verifier = createOnlineAccessVerifier(config, {trustedResolver: keys.publicKey, now: () => 2000000000000,
    fetchImpl: async () => {
      calls++;
      if (calls !== 1) throw new Error('outage');
      started(); await blocked;
      return new Response(JSON.stringify({...claims, active: true, token_type: 'Bearer'}), {headers: {'content-type': 'application/json'}});
    }});
  const first = await sign(); const second = await sign({jti: 'different-token'});
  const pending = verifier(first); await waiting;
  await rejects(verifier(second), 503); release();
  await rejects(pending, 503); await rejects(verifier(first), 503);
  assert.equal(calls, 3);
});

test('resource HTTP authorization requires a single Bearer and checks the operation role on every request', async () => {
  let validations = 0;
  const server = createServer(createApiHandler({origin: 'https://resource.example.test'}, async () => {
    validations++; return {roles: ['reader']};
  }));
  await new Promise(done => server.listen(0, '127.0.0.1', done));
  const target = `http://127.0.0.1:${server.address().port}/orders`;
  const headers = {Host: 'resource.example.test', Authorization: 'Bearer e30.e30.signature'};
  const send = options => new Promise((done, reject) => {
    const call = request(target, options, response => { response.resume(); response.on('end', () => done(response.statusCode)); });
    call.on('error', reject); call.end();
  });
  try {
    assert.equal(await send({headers}), 200);
    assert.equal(await send({method: 'POST', headers}), 403);
    assert.equal(await send({headers: {Host: headers.Host, Cookie: '__Host-IAMSESSION=untrusted'}}), 401);
    const duplicate = await send({headers: ['Host', headers.Host, 'Authorization', headers.Authorization, 'Authorization', headers.Authorization]});
    assert.equal(duplicate, 401); assert.equal(validations, 2);
    assert.equal(await send({method: 'DELETE', headers}), 405);
    assert.equal(await send({headers: {...headers, Host: 'untrusted.example.test'}}), 400);
    assert.equal(validations, 2);
  } finally { server.closeAllConnections(); await new Promise(done => server.close(done)); }
});
