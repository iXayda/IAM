import { mkdtemp, chmod, readFile, rm, open } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve, delimiter } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createServer } from 'node:net';
import { spawn } from 'node:child_process';
import { createInterface } from 'node:readline';
import { setTimeout as delay } from 'node:timers/promises';
import { createIdentityFrontend } from './fixtures/server.mjs';
import { scenarios } from './scenarios/index.mjs';

const root = fileURLToPath(new URL('../../', import.meta.url));
const started = performance.now();
let fixture, worker, proxy = false, stage = 'suite-selection', suite, cancelled = false;
for (const signal of ['SIGINT', 'SIGTERM']) process.once(signal, () => {
  cancelled = true;
  void stop(worker, true).catch(() => {});
  fixture?.child.stdin?.end();
});

function launch(command, args, options) {
  const child = spawn(command, args, options);
  const running = {child, failed: false};
  child.on('error', () => { running.failed = true; });
  running.closed = new Promise(done => child.once('close', (code, signal) => done({code, signal})));
  return running;
}

async function freePort() {
  const server = createServer();
  await new Promise((done, reject) => { server.once('error', reject); server.listen(0, '127.0.0.1', done); });
  const port = server.address().port;
  await new Promise(done => server.close(done));
  return port;
}

async function stop(running, terminate = false) {
  if (!running) return;
  const {child, closed} = running;
  if (child.exitCode === null && child.signalCode === null && !running.failed) {
    if (terminate) child.kill('SIGTERM');
    else child.stdin?.end();
    await Promise.race([closed, delay(terminate ? 5000 : 15000, undefined, {ref: false})]);
    if (child.exitCode === null && child.signalCode === null) child.kill('SIGKILL');
  }
  return await closed;
}

async function collectResults(stdout, selectedSuite) {
  const lines = createInterface({input: stdout, crlfDelay: Infinity});
  let passed, invalid = false;
  for await (const line of lines) {
    try {
      const record = JSON.parse(line);
      if (passed || record.suite !== selectedSuite || typeof record.stage !== 'string' || !/^[a-z][a-z0-9-]{0,63}$/.test(record.stage)
          || !Number.isSafeInteger(record.checks) || record.checks < 0
          || !Number.isSafeInteger(record.elapsedMs) || record.elapsedMs < 0) throw new Error();
      if (record.event === 'browser_scenario_passed') {
        if (record.stage !== 'complete' || record.cancelled !== false || record.skipped !== 0 || record.checks === 0) throw new Error();
        passed = record;
      } else if (record.event === 'browser_scenario_failed') invalid = true;
      else if (record.event !== 'browser_stage') throw new Error();
      // Forward only stage labels and numeric results; never echo arbitrary worker output.
      process.stdout.write(JSON.stringify({event: record.event, suite: selectedSuite, stage: record.stage,
        checks: record.checks, elapsedMs: record.elapsedMs,
        ...(Number.isSafeInteger(record.status) && record.status >= 100 && record.status <= 599 ? {status: record.status} : {}),
        ...(passed ? {skipped: 0} : {})}) + '\n');
    } catch { invalid = true; }
  }
  if (invalid || !passed) throw new Error();
  return passed;
}

async function verify(selectedSuite) {
  let directory, frontend, fixtureLog, workerLog, timeout;
  try {
    stage = 'fixture-configuration';
    directory = await mkdtemp(join(tmpdir(), 'iam-browser-'));
    await chmod(directory, 0o700);
    const dependencies = (await readFile(resolve(root, 'target/acceptance-classpath.txt'), 'utf8')).trim();
    if (!dependencies || cancelled) throw new Error();
    const java = process.env.JAVA_HOME ? join(process.env.JAVA_HOME, 'bin/java') : 'java';
    const classpath = [join(root, 'target/test-classes'), join(root, 'target/classes'), dependencies].join(delimiter);
    const issuer = `https://127.0.0.1:${await freePort()}`;
    const fixtureEnvironment = Object.fromEntries(Object.entries(process.env).filter(([name]) =>
      !/^(?:SPRING_|SERVER_|IAM_|MANAGEMENT_|LOGGING_|JAVA_TOOL_OPTIONS$|JDK_JAVA_OPTIONS$|_JAVA_OPTIONS$)/.test(name)));
    fixtureLog = await open(join(directory, 'fixture.log'), 'wx', 0o600);
    fixture = launch(java, ['-Xmx512m', '-cp', classpath, 'com.ixayda.iam.IdentityAcceptanceFixture', directory, issuer, selectedSuite, ...(proxy ? ['--proxy'] : [])], {
      cwd: root, env: fixtureEnvironment, stdio: ['pipe', fixtureLog.fd, fixtureLog.fd],
    });
    let configuration;
    const deadline = Date.now() + 120000;
    stage = 'database-runtime-start';
    while (Date.now() < deadline) {
      if (cancelled || fixture.failed || fixture.child.exitCode !== null || fixture.child.signalCode !== null) throw new Error();
      try { configuration = JSON.parse(await readFile(join(directory, 'fixture.json'), 'utf8')); break; }
      catch { await delay(250); }
    }
    if (!configuration || cancelled) throw new Error();
    frontend = createIdentityFrontend(configuration);
    await new Promise((done, reject) => { frontend.once('error', reject); frontend.listen(Number(new URL(issuer).port), '127.0.0.1', done); });
    stage = 'browser-scenarios';
    workerLog = await open(join(directory, 'worker.log'), 'wx', 0o600);
    worker = launch(process.execPath, [fileURLToPath(new URL('./scenarios.mjs', import.meta.url)), directory, selectedSuite], {
      cwd: root, env: {...process.env, NODE_EXTRA_CA_CERTS: configuration.certificate}, stdio: ['ignore', 'pipe', workerLog.fd],
    });
    let timedOut = false;
    timeout = setTimeout(() => { timedOut = true; void stop(worker, true).catch(() => {}); }, 600000);
    const [result, exit] = await Promise.all([collectResults(worker.child.stdout, selectedSuite), worker.closed]);
    if (cancelled || timedOut || worker.failed || exit.code !== 0 || exit.signal !== null) throw new Error();
    return result;
  } finally {
    clearTimeout(timeout);
    await stop(worker, true); worker = undefined;
    if (frontend) { frontend.closeAllConnections(); await new Promise(done => frontend.close(done)); }
    const fixtureExit = await stop(fixture); fixture = undefined;
    await fixtureLog?.close(); await workerLog?.close();
    if (directory) await rm(directory, {recursive: true, force: true});
    if (fixtureExit && (fixtureExit.code !== 0 || fixtureExit.signal !== null)) throw new Error();
  }
}

try {
  process.umask(0o077);
  let selectedSuite;
  for (const argument of process.argv.slice(2)) {
    if (argument === '--proxy' && !proxy) proxy = true;
    else if (!selectedSuite && Object.hasOwn(scenarios, argument)) selectedSuite = argument;
    else throw new Error();
  }
  const selected = selectedSuite ? [selectedSuite] : Object.keys(scenarios);
  let checks = 0;
  for (suite of selected) {
    if (cancelled) throw new Error();
    checks += (await verify(suite)).checks;
  }
  process.stdout.write(JSON.stringify({event: 'browser_verification_passed', transport: proxy ? 'proxy' : 'tls', scenarios: selected.length, checks,
    skipped: 0, elapsedMs: Math.round(performance.now() - started)}) + '\n');
} catch {
  process.stderr.write(JSON.stringify({event: 'browser_verification_failed', ...(Object.hasOwn(scenarios, suite) ? {suite} : {}), stage}) + '\n');
  process.exitCode = 1;
}
