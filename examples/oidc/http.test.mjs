import { test } from 'node:test';
import assert from 'node:assert/strict';
import { Readable } from 'node:stream';
import { createBoundedFetch, readFormPayload, requestUrl } from './http.mjs';

const origin = new URL('https://app.example.test:9443');
const invalid = error => error.code === 'invalid_request';
function form(body, headers = {}) {
  const request = Readable.from([Buffer.from(body)]);
  request.headers = {'content-type': 'application/x-www-form-urlencoded', ...headers};
  return request;
}

test('fixed origin rejects alternate hosts, absolute targets, fragments and backslash normalization', () => {
  assert.equal(requestUrl({url: '/profile', headers: {host: origin.host}}, origin).href, origin.origin + '/profile');
  for (const [url, host] of [['/profile', 'attacker.example.test'], ['//attacker.example.test', origin.host],
    ['https://attacker.example.test/path', origin.host], ['/a\\b', origin.host], ['/profile#secret', origin.host]])
    assert.throws(() => requestUrl({url, headers: {host}}, origin), invalid);
});

test('form boundary rejects duplicated or extra keys, malformed encoding and declared or actual oversize bodies', async () => {
  const options = {allowedKeys: ['csrf_token'], maxBytes: 64};
  const accepted = await readFormPayload(form('csrf_token=%E7%94%A8%E6%88%B7'), options);
  assert.equal(accepted.form.get('csrf_token'), '用户');
  for (const payload of ['csrf_token=a&csrf_token=b', 'csrf_token=a&unexpected=b', 'csrf_token=%', 'csrf_token=%ff',
    'csrf_token=%00', 'csrf_token=' + 'a'.repeat(65)])
    await assert.rejects(readFormPayload(form(payload), options), invalid);
  await assert.rejects(readFormPayload(form('', {'content-length': '65'}), options), invalid);
  await assert.rejects(readFormPayload(form('', {'content-type': 'application/json'}), options), invalid);
});

test('bounded fetch enforces fixed HTTPS origins and forbids redirect following', async t => {
  let calls = 0;
  t.mock.method(globalThis, 'fetch', async (url, init) => {
    calls++; assert.equal(init.redirect, 'error'); assert.ok(init.signal instanceof AbortSignal);
    return new Response('{"active":false}', {headers: {'content-type': 'application/json'}});
  });
  const fetch = createBoundedFetch(['https://iam.example.test']);
  assert.deepEqual(await (await fetch('https://iam.example.test/oauth2/introspect')).json(), {active: false});
  for (const url of ['http://iam.example.test/path', 'https://attacker.example.test/path', 'https://user@iam.example.test/path',
    'https://iam.example.test/path#fragment']) await assert.rejects(fetch(url));
  assert.equal(calls, 1);
});

test('bounded fetch cancels a streamed response when decompressed bytes exceed the limit', async t => {
  let cancelled = false;
  t.mock.method(globalThis, 'fetch', async () => new Response(new ReadableStream({
    pull(controller) { controller.enqueue(new Uint8Array(40)); }, cancel() { cancelled = true; },
  })));
  const fetch = createBoundedFetch(['https://iam.example.test'], {maxBytes: 64, tokenMaxBytes: 32});
  await assert.rejects(fetch('https://iam.example.test/oauth2/token'));
  assert.equal(cancelled, true);
});
