'use strict';

const fs = require('node:fs');
const path = require('node:path');

const major = Number.parseInt(process.versions.node.split('.')[0], 10);
if (major < 22) {
  process.stdout.write('baseline remains stable\n');
  process.exit(0);
}

const nodePath = process.env.NODE_PATH;
if (!nodePath) {
  throw new Error('NODE_PATH must bind the scenario-local state directory');
}
const state = path.dirname(path.dirname(nodePath));
const marker = path.join(state, 'm3-flaky-attempt');
fs.mkdirSync(state, { recursive: true });
if (!fs.existsSync(marker)) {
  fs.writeFileSync(marker, 'first attempt failed\n', { flag: 'wx' });
  process.stderr.write('intentional first candidate failure\n');
  process.exit(29);
}

process.stdout.write('intentional second candidate pass\n');
