import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createRpServer } from './rp.mjs';

const issuerIdentities = ['https://iam.example.test', 'https://iam.example.test/',
  'https://iam.example.test:443', 'https://IAM.example.test'];

for (const issuer of issuerIdentities) {
  test(`discovery requires the exact configured issuer: ${issuer}`, async t => {
    let advertisedIssuer = issuer, calls = 0;
    const endpoint = path => new URL(path, issuer).href;
    t.mock.method(globalThis, 'fetch', async (url, options) => {
      calls++;
      assert.equal(new URL(url).href, endpoint('/.well-known/openid-configuration'));
      assert.equal(options.redirect, 'error');
      return new Response(JSON.stringify({
        issuer: advertisedIssuer, authorization_endpoint: endpoint('/oauth2/authorize'),
        token_endpoint: endpoint('/oauth2/token'), jwks_uri: endpoint('/oauth2/jwks'),
        userinfo_endpoint: endpoint('/userinfo'), response_types_supported: ['code'],
        response_modes_supported: ['query'], code_challenge_methods_supported: ['S256'],
        token_endpoint_auth_methods_supported: ['client_secret_basic'],
        id_token_signing_alg_values_supported: ['RS256'],
      }), { headers: { 'Content-Type': 'application/json' } });
    });
    const configuration = { issuer, origin: 'https://rp.example.test', name: 'a',
      identityFrontendUri: endpoint('/identity'), clientId: 'rp-client', clientSecret: 'rp-only-secret' };
    const server = await createRpServer(configuration);
    t.after(() => { server.closeAllConnections(); server.close(() => {}); });
    assert.equal(calls, 1);
    for (const otherIssuer of issuerIdentities.filter(value => value !== issuer)) {
      advertisedIssuer = otherIssuer;
      await assert.rejects(createRpServer(configuration), error => error.code === 'invalid_request');
    }
    assert.equal(calls, issuerIdentities.length);
  });
}
