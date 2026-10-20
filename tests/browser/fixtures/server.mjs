import { readFileSync } from 'node:fs';
import { createServer, request as httpsUpstream } from 'node:https';
import { request as httpUpstream } from 'node:http';

/** Fixed HTTPS ingress; either verified TLS or an explicitly trusted loopback HTTP upstream. */
export function createIdentityFrontend(fixture) {
  const origin = new URL(fixture.issuer); const backend = new URL(fixture.backend);
  const certificate = readFileSync(fixture.certificate); const key = readFileSync(fixture.privateKey);
  const files = new Map([
    ['/identity', ['text/html; charset=utf-8', readFileSync(new URL('./identity.html', import.meta.url))]],
    ['/identity.js', ['text/javascript; charset=utf-8', readFileSync(new URL('./identity.js', import.meta.url))]],
  ]);
  const server = createServer({ key, cert: certificate, minVersion: 'TLSv1.2', maxHeaderSize: 16384 }, (request, response) => {
    if (request.headers.host !== origin.host || !['GET', 'POST'].includes(request.method) || !request.url.startsWith('/') || request.url.startsWith('//')) {
      response.writeHead(400); response.end(); return;
    }
    const url = new URL(request.url, origin);
    if (request.method === 'GET' && files.has(url.pathname)) {
      const [type, bytes] = files.get(url.pathname);
      response.writeHead(200, { 'Content-Type': type, 'Cache-Control': 'no-store', 'Referrer-Policy': 'no-referrer',
        'Strict-Transport-Security': 'max-age=31536000', 'X-Content-Type-Options': 'nosniff', 'X-Frame-Options': 'DENY',
        'Content-Security-Policy': "default-src 'none'; script-src 'self'; connect-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'" });
      response.end(bytes); return;
    }
    if (!['/login', '/logout', '/admin/mfa', '/userinfo', '/readyz', '/livez'].includes(url.pathname)
        && !['/api/', '/oauth2/', '/.well-known/'].some(prefix => url.pathname.startsWith(prefix))) {
      response.writeHead(404); response.end(); return;
    }
    const headers = { ...request.headers, host: origin.host };
    for (const name of Object.keys(headers)) if (name === 'forwarded' || name.startsWith('x-forwarded-') || ['connection', 'proxy-authorization', 'proxy-connection'].includes(name)) delete headers[name];
    if (backend.protocol === 'http:') {
      headers['x-forwarded-proto'] = 'https';
      headers['x-forwarded-for'] = request.socket.remoteAddress;
    }
    const upstream = backend.protocol === 'https:' ? httpsUpstream : httpUpstream;
    const proxy = upstream({ protocol: backend.protocol, hostname: backend.hostname, port: backend.port, path: request.url,
      method: request.method, headers, ...(backend.protocol === 'https:' ? {ca: certificate} : {}), timeout: 10000 }, incoming => {
      response.writeHead(incoming.statusCode, incoming.headers); incoming.pipe(response);
    });
    proxy.on('timeout', () => proxy.destroy());
    proxy.on('error', () => { if (!response.headersSent) response.writeHead(502, { 'Cache-Control': 'no-store' }); response.end(); });
    request.on('aborted', () => proxy.destroy()); request.pipe(proxy);
  });
  server.requestTimeout = 15000; server.headersTimeout = 10000; server.keepAliveTimeout = 1000;
  return server;
}
