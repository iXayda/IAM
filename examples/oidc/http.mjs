export function applySecurityHeaders(response) {
  response.setHeader('Strict-Transport-Security', 'max-age=31536000');
  response.setHeader('X-Frame-Options', 'DENY');
  response.setHeader('Cache-Control', 'no-store');
  response.setHeader('Referrer-Policy', 'no-referrer');
  response.setHeader('X-Content-Type-Options', 'nosniff');
  response.setHeader('Content-Security-Policy', "default-src 'none'; style-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'");
}

export function sendJson(response, status, payload, extraHeaders = {}) {
  applySecurityHeaders(response);
  for (const [name, value] of Object.entries(extraHeaders)) response.setHeader(name, value);
  response.writeHead(status, {'Content-Type': 'application/json; charset=utf-8'});
  response.end(JSON.stringify(payload));
}

function invalidRequest() {
  const error = new Error('Invalid request');
  error.code = 'invalid_request';
  return error;
}

export function requestUrl(request, fixedOrigin) {
  const path = request.url;
  if (typeof path !== 'string' || path.length > 8192 || !path.startsWith('/')
      || path.startsWith('//') || path.includes('\\') || path.includes('#') || /[\x00-\x20\x7f]/.test(path)) throw invalidRequest();
  const configured = new URL(fixedOrigin);
  if (request.headers.host !== configured.host) throw invalidRequest();
  const origin = configured.origin;
  let url;
  try { url = new URL(path, origin); } catch { throw invalidRequest(); }
  if (url.origin !== origin) throw invalidRequest();
  return url;
}

export async function readFormPayload(request, {allowedKeys, maxBytes = 4096}) {
  if (!Number.isSafeInteger(maxBytes) || maxBytes < 1 || maxBytes > 65536
      || !Array.isArray(allowedKeys) || !allowedKeys.every(key => typeof key === 'string')) throw invalidRequest();
  if (!/^application\/x-www-form-urlencoded(?:\s*;\s*charset=utf-8)?$/i.test(request.headers['content-type'] || '')) throw invalidRequest();
  const contentLength = request.headers['content-length'];
  if (contentLength !== undefined && (!/^[0-9]+$/.test(contentLength) || Number(contentLength) > maxBytes)) throw invalidRequest();
  const chunks = [];
  let size = 0;
  for await (const chunk of request) {
    size += chunk.length;
    if (size > maxBytes) throw invalidRequest();
    chunks.push(chunk);
  }
  let source;
  try { source = new TextDecoder('utf-8', {fatal: true}).decode(Buffer.concat(chunks)); }
  catch { throw invalidRequest(); }
  if (/%(?![a-fA-F0-9]{2})/.test(source)) throw invalidRequest();
  // URLSearchParams alone replaces invalid percent-encoded UTF-8. Decode strictly first.
  try {
    for (const component of source.split('&')) for (const part of component.split('=')) {
      if (decodeURIComponent(part.replace(/\+/g, ' ')).includes('\0')) throw invalidRequest();
    }
  } catch { throw invalidRequest(); }
  const form = new URLSearchParams(source);
  const seen = new Set();
  for (const [key] of form) {
    if (!allowedKeys.includes(key) || seen.has(key)) throw invalidRequest();
    seen.add(key);
  }
  return { form, body: source };
}

export async function readForm(request, options) {
  return (await readFormPayload(request, options)).form;
}

function upstreamError() {
  const error = new Error('Upstream response rejected');
  error.code = 'upstream_rejected';
  return error;
}

export function createBoundedFetch(allowedOrigins, {timeoutMs = 10000, maxBytes = 1048576, tokenMaxBytes = 65536} = {}) {
  if (!Array.isArray(allowedOrigins) || !allowedOrigins.length || !Number.isSafeInteger(timeoutMs)
      || timeoutMs < 1 || timeoutMs > 30000 || !Number.isSafeInteger(maxBytes) || maxBytes < 1 || maxBytes > 4194304
      || !Number.isSafeInteger(tokenMaxBytes) || tokenMaxBytes < 1 || tokenMaxBytes > maxBytes) throw upstreamError();
  const origins = new Set(allowedOrigins.map(value => {
    const url = new URL(value);
    if (url.protocol !== 'https:' || url.username || url.password || url.pathname !== '/' || url.search || url.hash) throw upstreamError();
    return url.origin;
  }));
  return async (input, init = {}) => {
    let url;
    try { url = new URL(input instanceof Request ? input.url : input); }
    catch { throw upstreamError(); }
    if (url.protocol !== 'https:' || url.username || url.password || url.hash || !origins.has(url.origin)) throw upstreamError();
    const signals = [AbortSignal.timeout(timeoutMs), init.signal || (input instanceof Request ? input.signal : null)].filter(Boolean);
    const response = await fetch(input, {...init, redirect: 'error', signal: AbortSignal.any(signals)});
    const limit = url.pathname === '/oauth2/token' ? tokenMaxBytes : maxBytes;
    const length = response.headers.get('content-length');
    if (length !== null && (!/^[0-9]+$/.test(length) || Number(length) > limit)) {
      await response.body?.cancel().catch(() => {});
      throw upstreamError();
    }
    const reader = response.body?.getReader();
    const chunks = [];
    let size = 0;
    try {
      if (reader) for (;;) {
        const {value, done} = await reader.read();
        if (done) break;
        size += value.byteLength;
        if (size > limit) throw upstreamError();
        chunks.push(value);
      }
    } catch (error) {
      await reader?.cancel().catch(() => {});
      throw error;
    } finally { reader?.releaseLock(); }
    const body = [204, 205, 304].includes(response.status) ? null : Buffer.concat(chunks, size);
    const bounded = new Response(body, {status: response.status, statusText: response.statusText, headers: response.headers});
    Object.defineProperty(bounded, 'url', {value: response.url});
    Object.defineProperty(bounded, 'redirected', {value: response.redirected});
    return bounded;
  };
}
