import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, writeFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { httpsOrigin, identityFrontendUri, loadRpConfig, loadApiConfig } from './config.mjs';

const issuer = 'https://iam.example.test';
const invalid = error => error.code === 'invalid_configuration';

test('issuer and application origins are explicit HTTPS roots; identity frontend stays in the issuer origin', () => {
  assert.equal(httpsOrigin(issuer).origin, issuer);
  assert.equal(identityFrontendUri(issuer + '/identity', issuer).pathname, '/identity');
  for (const value of ['http://iam.example.test', issuer + '/path', issuer + '#fragment', issuer + '?query', 'https://user@iam.example.test'])
    assert.throws(() => httpsOrigin(value), invalid);
  for (const value of ['https://other.example.test/identity', issuer + '/identity?next=anything', issuer + '/identity#token'])
    assert.throws(() => identityFrontendUri(value, issuer), invalid);
});

test('configuration preserves deployment bounds and keeps RP and validator credentials independent', async () => {
  const directory = await mkdtemp(join(tmpdir(), 'iam-example-config-'));
  try {
    const key = join(directory, 'key'), certificate = join(directory, 'certificate');
    await writeFile(key, 'test-key', {mode: 0o600}); await writeFile(certificate, 'test-certificate', {mode: 0o600});
    const env = {IAM_ISSUER: issuer, IAM_IDENTITY_FRONTEND_URI: issuer + '/identity', RP_NAME: 'a', RP_ORIGIN: 'https://a.example.test',
      RP_CLIENT_ID: 'rp-client', RP_CLIENT_SECRET: 'rp-only-secret', RP_TLS_KEY_FILE: key, RP_TLS_CERT_FILE: certificate,
      API_ORIGIN: 'https://api.example.test', API_AUDIENCE: 'orders', API_VALIDATION_CLIENT_ID: 'resource-id',
      API_VALIDATION_CLIENT_SECRET: 'resource-only-secret', API_TLS_KEY_FILE: key, API_TLS_CERT_FILE: certificate};
    assert.equal(loadRpConfig(env).clientSecret, 'rp-only-secret');
    assert.equal(loadApiConfig(env).validatorSecret, 'resource-only-secret');
    assert.equal(loadApiConfig(env).positiveCacheMs, 5000);
    for (const value of [issuer, issuer + '/', issuer + ':443', 'https://IAM.example.test']) {
      assert.equal(loadRpConfig({...env, IAM_ISSUER: value}).issuer, value);
      assert.equal(loadApiConfig({...env, IAM_ISSUER: value}).issuer, value);
    }
    for (const change of [{RP_SCOPES: 'openid openid'}, {RP_SCOPES: 'openid administrator'}, {RP_TRANSACTION_TTL_SECONDS: '601'},
      {RP_SESSION_TTL_SECONDS: '28801'}, {RP_MAX_SESSIONS: '0'}, {RP_TLS_KEY_FILE: directory}])
      assert.throws(() => loadRpConfig({...env, ...change}), invalid);
    assert.throws(() => loadApiConfig({...env, API_POSITIVE_CACHE_SECONDS: '6'}), invalid);
  } finally { await rm(directory, {recursive: true, force: true}); }
});
