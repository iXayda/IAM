import { strict as assert } from 'node:assert';
import test from 'node:test';
import { latestMatchingStep, totp } from './support.mjs';

const secret = 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ';
const otp = step => totp(secret, step);

test('accounts for a proof submitted across a window with a later matching code', () => {
  const step = 153567;
  assert.equal(otp(step), '468457');
  assert.equal(otp(step + 1), '214300');
  assert.equal(otp(step + 2), '468457');
  assert.equal(latestMatchingStep(otp, step, step), step);
  assert.equal(latestMatchingStep(otp, step, step + 1), step + 2);
  assert.equal(latestMatchingStep(otp, step + 2, step + 2), step + 2);
});

test('keeps the original step when a normal proof crosses a window', () => {
  const step = 153568;
  assert.equal(latestMatchingStep(otp, step, step), step);
  assert.equal(latestMatchingStep(otp, step, step + 1), step);
});

test('retains a future marker obtained from the database or an earlier reservation', () => {
  assert.equal(latestMatchingStep(otp, 153569, 153567), 153569);
});

test('accounts for adjacent matching codes in the same window', () => {
  const step = 59761102;
  const adjacent = step => totp('FZ5Z7IQ6M3WKTAWW3YZHO346OXGE35CC', step);
  assert.equal(adjacent(step), '446938');
  assert.equal(adjacent(step + 1), '446938');
  assert.equal(latestMatchingStep(adjacent, step, step), step + 1);
});

test('finds the highest possible match after several windows without extending the observation time', () => {
  const matches = new Set([10, 12, 15, 22]);
  const repeated = step => matches.has(step) ? '123456' : String(step).padStart(6, '0');
  assert.equal(latestMatchingStep(repeated, 10, 20), 15);
  assert.equal(latestMatchingStep(repeated, 10, 21), 22);
});

test('accepts step zero as a valid previous marker', () => {
  const repeated = step => step === 0 || step === 2 ? '123456' : '654321';
  assert.equal(latestMatchingStep(repeated, 0, 1), 2);
});
