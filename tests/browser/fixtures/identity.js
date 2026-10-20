(() => {
  'use strict';
  let interaction;
  let busy = false;
  const output = document.querySelector('#result');
  const clear = () => { output.textContent = ''; };
  function show(result) { output.textContent = JSON.stringify(result); }
  function path(value) {
    if (typeof value !== 'string' || !value.startsWith('/') || value.startsWith('//') || value.includes('\\') || value.includes('#')) throw new Error();
    const url = new URL(value, location.origin);
    if (url.origin !== location.origin || !['/login', '/logout', '/admin/mfa'].includes(url.pathname) && !url.pathname.startsWith('/api/')) throw new Error();
    return value;
  }
  async function request(target, method = 'GET', fields, json = false) {
    const headers = { Accept: 'application/json' };
    if (method === 'POST') {
      const csrf = await fetch('/api/csrf', { credentials: 'same-origin', redirect: 'error', cache: 'no-store' });
      if (!csrf.ok) throw new Error();
      const token = await csrf.json(); headers[token.headerName] = token.token;
      headers['Content-Type'] = json ? 'application/json' : 'application/x-www-form-urlencoded';
    }
    const response = await fetch(path(target), { method, headers, credentials: 'same-origin', redirect: 'error', cache: 'no-store',
      ...(method === 'POST' ? { body: json ? JSON.stringify(fields ?? {}) : new URLSearchParams(fields ?? {}) } : {}) });
    return { status: response.status, body: await response.json().catch(() => null) };
  }
  async function viewInteraction() {
    if (!interaction) return;
    const result = await request('/api/authorization-interactions/' + interaction);
    document.querySelector('#interaction').hidden = false;
    document.querySelector('#interaction-view').textContent = JSON.stringify(result.body);
    document.querySelector('#continue').disabled = result.status !== 200 || result.body.loginRequired;
  }
  function form(id, action) {
    document.querySelector('#' + id).addEventListener('submit', async event => {
      event.preventDefault(); if (busy) return; busy = true; clear();
      const form = event.currentTarget; const fields = Object.fromEntries(new FormData(form)); form.reset();
      try { show(await action(fields)); await viewInteraction(); }
      catch { show({ status: 0, error: 'interaction_failed' }); }
      finally { busy = false; }
    });
  }
  function button(id, action) {
    document.querySelector('#' + id).addEventListener('click', async () => {
      if (busy) return; busy = true; clear();
      try { const result = await action(); if (result !== undefined) show(result); }
      catch { show({ status: 0, error: 'interaction_failed' }); }
      finally { busy = false; }
    });
  }
  form('login', fields => request('/login', 'POST', fields, true));
  form('mfa', fields => request('/admin/mfa', 'POST', fields));
  form('setup', fields => request('/api/account-setup/complete', 'POST', fields));
  form('recovery', fields => request('/api/password-recovery/complete', 'POST', fields));
  form('operation', fields => {
    if (!['GET', 'POST'].includes(fields.method)) throw new Error();
    const values = JSON.parse(fields.fields || '{}');
    if (values === null || typeof values !== 'object' || Array.isArray(values)) throw new Error();
    return request(fields.path, fields.method, values, fields.json === 'on');
  });
  button('profile', () => request('/api/me'));
  button('logout', () => request('/logout', 'POST'));
  document.querySelector('#hide').addEventListener('click', clear);
  async function complete(decision) {
    const result = await request('/api/authorization-interactions/' + interaction + '/complete', 'POST', { decision }, true);
    if (result.status !== 200) return result;
    const target = new URL(result.body.redirectUri);
    if (target.protocol !== 'https:' || target.username || target.password || target.hash) throw new Error();
    interaction = undefined; clear(); location.replace(target.href); return undefined;
  }
  button('continue', () => complete('continue')); button('cancel', () => complete('cancel'));
  const candidate = new URL(location.href).searchParams.get('interaction');
  history.replaceState(null, '', '/identity');
  if (candidate && /^[A-Za-z0-9_-]{43}$/.test(candidate)) interaction = candidate;
  viewInteraction().catch(() => show({ status: 0, error: 'interaction_failed' }));
  addEventListener('pagehide', () => { interaction = undefined; clear(); document.querySelectorAll('form').forEach(form => form.reset()); document.querySelector('#interaction-view').textContent = ''; });
})();
