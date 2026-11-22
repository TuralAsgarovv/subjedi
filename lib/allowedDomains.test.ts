import test from 'node:test';
import assert from 'node:assert/strict';
import { isAllowedDomain, parseAllowedDomains } from './allowedDomains.ts';

test('allowlist accepts its apex and subdomains but not lookalike domains', () => {
  const allowed = parseAllowedDomains('example.com, example.co.uk');

  assert.equal(isAllowedDomain('example.com', allowed), true);
  assert.equal(isAllowedDomain('api.dev.example.com', allowed), true);
  assert.equal(isAllowedDomain('example.co.uk', allowed), true);
  assert.equal(isAllowedDomain('example.com.evil.test', allowed), false);
  assert.equal(isAllowedDomain('other.test', allowed), false);
});

test('allowlist requires apex domains and is empty when unconfigured', () => {
  assert.deepEqual(parseAllowedDomains(''), new Set());
  assert.throws(() => parseAllowedDomains('www.example.com'), /apex domains only/);
  assert.throws(() => parseAllowedDomains('not-a-domain'), /invalid domain/);
});
