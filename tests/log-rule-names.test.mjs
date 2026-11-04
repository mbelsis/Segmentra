import assert from 'node:assert/strict';
import { test } from 'node:test';
import { expandRuleLabel } from '../apps/api/dist/services/log-parser.js';

const rules = [
  { comment: 'Legacy service is closed', action: 'DENY' },
  { comment: 'Legacy service allowed once', action: 'ALLOW' },
  { comment: 'Legacy service old name', action: 'DENY' },
];

test('a cut-off rule name becomes the newest rule with the same action', () => {
  assert.equal(expandRuleLabel('Legacy serv', 'DENY', rules), 'Legacy service is closed');
  assert.equal(expandRuleLabel('Legacy serv', 'ALLOW', rules), 'Legacy service allowed once');
});

test('a name that matches nothing stays as it is, and no name stays empty', () => {
  assert.equal(expandRuleLabel('default', 'DENY', rules), 'default');
  assert.equal(expandRuleLabel(undefined, 'DENY', rules), null);
});
