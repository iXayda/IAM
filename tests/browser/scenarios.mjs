import { scenarios } from './scenarios/index.mjs';
import { createScenario } from './scenarios/support.mjs';

const directory = process.argv[2];
const suite = process.argv[3];
let scenario;
let passed = false;
try {
  if (!Object.hasOwn(scenarios, suite)) throw new Error();
  scenario = await createScenario(directory, suite);
  await scenarios[suite](scenario);
  await scenario.verifyStorage();
  scenario.check(!scenario.snapshot().cancelled);
  scenario.progress('complete');
  passed = true;
} catch {
  passed = false;
} finally {
  try { await scenario?.close(); }
  catch { passed = false; }
}
if (passed && !scenario.snapshot().cancelled) {
  process.stdout.write(JSON.stringify({event: 'browser_scenario_passed', ...scenario.snapshot(), skipped: 0}) + '\n');
} else {
  const result = scenario?.snapshot() ?? {suite: 'unknown', stage: 'browser-start', checks: 0};
  // Fixed labels and numeric metadata only; Playwright exceptions and protocol data stay private.
  process.stdout.write(JSON.stringify({event: 'browser_scenario_failed', ...result}) + '\n');
  process.exitCode = 1;
}
