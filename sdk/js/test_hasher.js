const fs = require('fs');
const path = require('path');
const assert = require('assert');
const { normalisePhone, hashPhone, InvalidPhone } = require('./hasher');

const testCases = JSON.parse(fs.readFileSync(path.join(__dirname, '../test_values.json'), 'utf-8'));
const SAMPLE_KEY = 'test_partner_secret_key_123';

console.log(`Running JavaScript SDK tests with ${testCases.length} cases...`);

let passed = 0;
for (const tc of testCases) {
  if (tc.valid) {
    try {
      const norm = normalisePhone(tc.input);
      assert.strictEqual(norm, tc.normalized, `Normalised mismatch for ${tc.input}`);
      
      const hash = hashPhone(tc.input, SAMPLE_KEY);
      assert.strictEqual(typeof hash, 'string');
      assert.strictEqual(hash.length, 64, 'SHA256 hex must be 64 characters');
      passed++;
    } catch (err) {
      console.error(`FAIL: Expected valid for '${tc.input}' (${tc.description}), but got error: ${err.message}`);
      process.exit(1);
    }
  } else {
    try {
      normalisePhone(tc.input);
      console.error(`FAIL: Expected InvalidPhone for '${tc.input}' (${tc.description}), but succeeded`);
      process.exit(1);
    } catch (err) {
      assert(err instanceof InvalidPhone, `Expected InvalidPhone, got ${err.name}`);
      passed++;
    }
  }
}

console.log(`All ${passed} JavaScript SDK test cases passed successfully!`);
