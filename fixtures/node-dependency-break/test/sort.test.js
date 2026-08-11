'use strict';

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const { legacyCipherAvailable } = require('../index.js');

describe('legacy Node crypto compatibility', () => {
  it('retains crypto.createCipher', () => {
    assert.equal(legacyCipherAvailable(), true);
  });
});
