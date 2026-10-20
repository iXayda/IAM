import { mkdtemp, chmod, readFile, rm, open } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve, delimiter } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createServer } from 'node:net';
import { spawn } from 'node:child_process';
import { setTimeout as delay } from 'node:timers/promises';
import { createIdentityFrontend } from './fixtures/server.mjs';

const root = fileURLToPath(new URL('../../', import.meta.url));
let directory, fixture, frontend, worker, fixtureLog, workerLog, stage = 'fixture-configuration';
let cancelled = false;
let proxy = false;
for (const signal of ['SIGINT', 'SIGTERM']) process.once(signal, () => {
  cancelled = true; worker?.kill('SIGTERM'); fixture?.stdin?.end();
});

async function freePort() {
  const server = createServer();
  await new Promise((done, reject) => { server.once('error', reject); server.listen(0, '127.0.0.1', done); });
  const port = server.address().port;
  await new Promise(done => server.close(done));
  return port;
}
async function stop(process) {
  if (!process || process.exitCode !== null || process.signalCode !== null) return;
  process.stdin?.end();
  await Promise.race([new Promise(done => process.once('exit', done)), delay(15000)]);
  if (process.exitCode === null && process.signalCode === null) process.kill('SIGTERM');
  await Promise.race([new Promise(done => process.once('exit', done)), delay(5000)]);
  if (process.exitCode === null && process.signalCode === null) process.kill('SIGKILL');
}

try {
  process.umask(0o077);
  const args = process.argv.slice(2);
  if (args.length > 1 || args.length === 1 && args[0] !== '--proxy') throw new Error();
  proxy = args.length === 1;
  directory = await mkdtemp(join(tmpdir(), 'iam-browser-'));
  await chmod(directory, 0o700);
  const classpathFile = resolve(root, 'target/acceptance-classpath.txt');
  const dependencies = (await readFile(classpathFile, 'utf8')).trim();
  if (!dependencies) throw new Error();
  const java = process.env.JAVA_HOME ? join(process.env.JAVA_HOME, 'bin/java') : 'java';
  const classpath = [join(root, 'target/test-classes'), join(root, 'target/classes'), dependencies].join(delimiter);
  const issuer = `https://127.0.0.1:${await freePort()}`;
  const fixtureEnvironment = Object.fromEntries(Object.entries(process.env).filter(([name]) =>
    !/^(?:SPRING_|SERVER_|IAM_|MANAGEMENT_|LOGGING_|JAVA_TOOL_OPTIONS$|JDK_JAVA_OPTIONS$|_JAVA_OPTIONS$)/.test(name)));
  fixtureLog = await open(join(directory, 'fixture.log'), 'wx', 0o600);
  fixture = spawn(java, ['-cp', classpath, 'com.ixayda.iam.IdentityAcceptanceFixture', directory, issuer, ...(proxy ? ['--proxy'] : [])], {
    cwd: root, env: fixtureEnvironment, stdio: ['pipe', fixtureLog.fd, fixtureLog.fd],
  });
  let startError = false;
  fixture.on('error', () => { startError = true; });
  let configuration;
  const deadline = Date.now() + 120000;
  stage = 'database-runtime-start';
  while (Date.now() < deadline) {
    if (cancelled || startError || fixture.exitCode !== null || fixture.signalCode !== null) throw new Error();
    try { configuration = JSON.parse(await readFile(join(directory, 'fixture.json'), 'utf8')); break; }
    catch { await delay(250); }
  }
  if (!configuration) throw new Error();
  frontend = createIdentityFrontend(configuration);
  await new Promise((done, reject) => { frontend.once('error', reject); frontend.listen(Number(new URL(issuer).port), '127.0.0.1', done); });
  stage = 'browser-scenarios';
  workerLog = await open(join(directory, 'worker.log'), 'wx', 0o600);
  worker = spawn(process.execPath, [fileURLToPath(new URL('./scenarios.mjs', import.meta.url)), directory], {
    cwd: root, env: { ...process.env, NODE_EXTRA_CA_CERTS: configuration.certificate }, stdio: ['ignore', 'pipe', workerLog.fd],
  });
  // The worker emits only fixed stage labels and counts, never requests, credentials or exception text.
  worker.stdout.pipe(process.stdout);
  const timeout = setTimeout(() => worker.kill('SIGTERM'), 1200000);
  const code = await new Promise((done, reject) => { worker.once('error', reject); worker.once('exit', done); });
  clearTimeout(timeout);
  if (code !== 0) throw new Error();
} catch {
  process.stderr.write(JSON.stringify({ event: 'browser_verification_failed', stage }) + '\n');
  process.exitCode = 1;
} finally {
  await stop(worker);
  if (frontend) { frontend.closeAllConnections(); await new Promise(done => frontend.close(done)); }
  await stop(fixture);
  await fixtureLog?.close(); await workerLog?.close();
  if (directory) await rm(directory, { recursive: true, force: true });
}
