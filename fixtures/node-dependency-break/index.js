'use strict';

const crypto = require('node:crypto');

// DEP0106 reached End-of-Life in Node 22. Baseline Node 20 still exposes this
// legacy API, while the strictly newer Node 22 candidate removes it.
function legacyCipherAvailable() {
  const cipher = crypto.createCipher('aes192', 'tomorrowci-fixture-key');
  return typeof cipher.update === 'function';
}

module.exports = { legacyCipherAvailable };
