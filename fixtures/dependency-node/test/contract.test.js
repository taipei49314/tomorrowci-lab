'use strict';

const assert = require('node:assert/strict');
const contract = require('m2-node-contract');
const noise = require('m2-node-noise');

assert.equal(contract.transform('alpha'), 'ALPHA', 'M2_NODE_BREAKING_API_V2');
assert.equal(noise.marker(), 'stable', 'unexpected noise package behavior');
console.log('node dependency contract: PASS');
