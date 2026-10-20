import { randomBytes } from 'node:crypto';

const opaque = () => randomBytes(32).toString('base64url');
const validId = value => typeof value === 'string' && /^[A-Za-z0-9_-]{43}$/.test(value);

export class ReauthenticationRequired extends Error {
  constructor() { super('Sign in again'); this.code = 'reauthentication_required'; }
}

/** Bounded single-process example storage. Tokens never leave the BFF. A restart requires a new login. */
export function createSessionStore({ maxSessions = 1000, sessionTtlMs = 3600000,
  transactionTtlMs = 300000, now = Date.now } = {}) {
  if (!Number.isSafeInteger(maxSessions) || maxSessions < 1 || maxSessions > 10000
      || !Number.isSafeInteger(sessionTtlMs) || sessionTtlMs < 1 || sessionTtlMs > 28800000
      || !Number.isSafeInteger(transactionTtlMs) || transactionTtlMs < 1 || transactionTtlMs > 600000
      || typeof now !== 'function') throw new TypeError('Invalid session bounds');
  const sessions = new Map();

  function find(id) {
    if (!validId(id)) return undefined;
    const session = sessions.get(id);
    if (session && session.expiresAt <= now()) { sessions.delete(id); return undefined; }
    return session;
  }
  function view(session) {
    return session && Object.freeze({ id: session.id, csrfToken: session.csrfToken,
      expiresAt: session.expiresAt, authentication: session.authentication });
  }
  function allocate(ttl = sessionTtlMs) {
    for (const [id, session] of sessions) if (session.expiresAt <= now()) sessions.delete(id);
    if (sessions.size >= maxSessions) {
      const error = new Error('Session capacity reached'); error.code = 'session_capacity'; throw error;
    }
    const session = { id: opaque(), csrfToken: opaque(), expiresAt: now() + ttl };
    sessions.set(session.id, session);
    return session;
  }
  function authentication(value) {
    if (!value || typeof value.accessToken !== 'string' || !value.accessToken
        || typeof value.subject !== 'string' || !value.subject
        || !Number.isSafeInteger(value.accessExpiresAt) || value.accessExpiresAt <= now()
        || !Number.isSafeInteger(value.authTime) || value.authTime < 1 || !Array.isArray(value.scopes)
        || value.refreshToken !== undefined && (typeof value.refreshToken !== 'string' || !value.refreshToken))
      throw new TypeError('Invalid server authentication');
    return Object.freeze({ accessToken: value.accessToken, refreshToken: value.refreshToken, subject: value.subject,
      authTime: value.authTime, accessExpiresAt: value.accessExpiresAt, scopes: Object.freeze([...value.scopes]) });
  }

  return Object.freeze({
    create() { return view(allocate()); },
    get(id) { return view(find(id)); },
    delete(id) { return sessions.delete(id); },
    clear() { sessions.clear(); },

    beginLogin(id, values) {
      const session = find(id);
      if (!session || session.authentication || !values
          || !['verifier', 'state', 'nonce'].every(name => typeof values[name] === 'string'
            && values[name].length >= 32 && values[name].length <= 256)) return false;
      session.login = Object.freeze({ ...values, expiresAt: Math.min(session.expiresAt, now() + transactionTtlMs) });
      delete session.exchange;
      return true;
    },
    takeLogin(id, state) {
      const session = find(id);
      if (!session?.login || session.login.state !== state) return undefined;
      const transaction = session.login;
      delete session.login;
      if (transaction.expiresAt <= now()) return undefined;
      const exchangeId = opaque();
      session.exchange = { id: exchangeId, expiresAt: transaction.expiresAt };
      return Object.freeze({ ...transaction, exchangeId });
    },
    cancelLogin(id, exchangeId) {
      const session = find(id);
      return session?.exchange?.id === exchangeId && sessions.delete(id);
    },
    commitLogin(id, exchangeId, value) {
      const session = find(id);
      if (!session?.exchange || session.exchange.id !== exchangeId || session.exchange.expiresAt <= now()) return undefined;
      const authenticated = authentication(value);
      sessions.delete(id);
      const replacement = allocate();
      replacement.authentication = authenticated;
      return view(replacement);
    },

    async access(id, refresh, { minimumRemainingMs = 30000, forceRefresh = false } = {}) {
      const session = find(id);
      if (!session?.authentication) throw new ReauthenticationRequired();
      if (session.refreshing) return session.refreshing;
      if (!forceRefresh && session.authentication.accessExpiresAt > now() + minimumRemainingMs)
        return session.authentication;
      const before = session.authentication;
      if (!before.refreshToken) { sessions.delete(id); throw new ReauthenticationRequired(); }
      const parent = before.refreshToken;
      // Remove the parent synchronously, before any I/O. Its result may be lost; it is never retried.
      session.authentication = Object.freeze({ ...before, refreshToken: undefined });
      const operation = (async () => {
        try {
          const value = await refresh(parent, before);
          if (find(id) !== session) throw new ReauthenticationRequired();
          const next = authentication(value);
          if (next.subject !== before.subject || next.authTime !== before.authTime
              || next.scopes.some(scope => !before.scopes.includes(scope))
              || next.refreshToken && (next.refreshToken === parent || !next.scopes.includes('offline_access')))
            throw new ReauthenticationRequired();
          session.authentication = next;
          return next;
        } catch {
          // Network loss, invalid response, provider denial, or local expiry all destroy local authorization.
          if (sessions.get(id) === session) sessions.delete(id);
          throw new ReauthenticationRequired();
        } finally { delete session.refreshing; }
      })();
      session.refreshing = operation;
      return operation;
    },

  });
}
