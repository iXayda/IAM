import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createSessionStore, ReauthenticationRequired } from './sessions.mjs';

function authenticatedStore() {
  const clock = { value: 2000000000000 };
  const store = createSessionStore({ now: () => clock.value });
  const anonymous = store.create();
  const values = { verifier: 'v'.repeat(64), state: 's'.repeat(43), nonce: 'n'.repeat(43) };
  assert.equal(store.beginLogin(anonymous.id, values), true);
  const transaction = store.takeLogin(anonymous.id, values.state);
  const authentication = { subject: 'stable-user-id', authTime: 1900000000,
    accessToken: 'access-1', refreshToken: 'parent-refresh',
    accessExpiresAt: clock.value + 5000, scopes: ['openid', 'profile', 'offline_access'] };
  const session = store.commitLogin(anonymous.id, transaction.exchangeId, authentication);
  return { clock, store, session, authentication };
}

test('parallel BFF requests share one refresh and never submit the same parent twice', async () => {
  const { clock, store, session, authentication } = authenticatedStore();
  let calls = 0, release;
  const pending = new Promise(done => { release = done; });
  const refresh = async parent => {
    calls++; assert.equal(parent, 'parent-refresh');
    assert.equal(store.get(session.id).authentication.refreshToken, undefined);
    await pending;
    return { ...authentication, accessToken: 'access-2', refreshToken: 'successor-refresh', accessExpiresAt: clock.value + 300000 };
  };
  const requests = Array.from({ length: 16 }, () => store.access(session.id, refresh));
  assert.equal(calls, 1);
  release();
  const results = await Promise.all(requests);
  assert.ok(results.every(result => result.accessToken === 'access-2'));
  assert.equal((await store.access(session.id, refresh)).refreshToken, 'successor-refresh');
  assert.equal(calls, 1);
});

test('lost refresh response requires reauthentication and cannot retry a consumed parent', async () => {
  const { store, session } = authenticatedStore();
  let calls = 0;
  const refresh = async () => { calls++; throw new Error('Response lost after remote commit'); };
  await assert.rejects(store.access(session.id, refresh), ReauthenticationRequired);
  await assert.rejects(store.access(session.id, refresh), ReauthenticationRequired);
  assert.equal(calls, 1);
  assert.equal(store.get(session.id), undefined);
});

test('logout while refresh is in flight prevents the later response restoring RP authentication', async () => {
  const { clock, store, session, authentication } = authenticatedStore();
  let release;
  const pending = new Promise(done => { release = done; });
  const operation = store.access(session.id, async () => {
    await pending;
    return { ...authentication, refreshToken: 'successor', accessExpiresAt: clock.value + 300000 };
  });
  store.delete(session.id);
  release();
  await assert.rejects(operation, ReauthenticationRequired);
  assert.equal(store.get(session.id), undefined);
});

test('refresh cannot restore dropped scopes or invent a new authentication time', async () => {
  for (const change of [{ authTime: 1900000010 }, { subject: 'different-subject' }, { refreshToken: 'parent-refresh' },
    { scopes: ['openid', 'profile', 'offline_access', 'api.read'] }]) {
    const { clock, store, session, authentication } = authenticatedStore();
    await assert.rejects(store.access(session.id, async () => ({ ...authentication,
      accessExpiresAt: clock.value + 300000, refreshToken: 'successor', ...change })), ReauthenticationRequired);
    assert.equal(store.get(session.id), undefined);
  }
});

test('one-time login state survives a wrong state, is consumed before I/O, and cannot commit after replacement', () => {
  const store = createSessionStore();
  const session = store.create();
  const values = { verifier: 'v'.repeat(64), state: 's'.repeat(43), nonce: 'n'.repeat(43) };
  store.beginLogin(session.id, values);
  assert.equal(store.takeLogin(session.id, 'wrong'), undefined);
  const taken = store.takeLogin(session.id, values.state);
  assert.ok(taken);
  assert.equal(store.takeLogin(session.id, values.state), undefined);
  store.beginLogin(session.id, { ...values, state: 'r'.repeat(43) });
  assert.equal(store.commitLogin(session.id, taken.exchangeId, {}), undefined);
});
