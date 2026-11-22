import test from 'node:test';
import assert from 'node:assert/strict';
import {
  classifyHttpStatus,
  isPrivateIp,
  isValidProbeTarget,
} from './probe.ts';

test('isPrivateIp blocks loopback, RFC1918, link-local, and ULA addresses', () => {
  assert.equal(isPrivateIp('127.0.0.1'), true);
  assert.equal(isPrivateIp('10.0.0.5'), true);
  assert.equal(isPrivateIp('172.16.0.1'), true);
  assert.equal(isPrivateIp('192.168.1.1'), true);
  assert.equal(isPrivateIp('169.254.169.254'), true);
  assert.equal(isPrivateIp('::1'), true);
  assert.equal(isPrivateIp('fe80::1'), true);
  assert.equal(isPrivateIp('8.8.8.8'), false);
  assert.equal(isPrivateIp('140.82.121.4'), false);
});

test('classifyHttpStatus maps HTTP status codes to clear Azerbaijani states', () => {
  assert.deepEqual(classifyHttpStatus(200), { state: 'live', label: '200 · Aktiv' });
  assert.deepEqual(classifyHttpStatus(301), { state: 'redirect', label: '301 · Yönləndirmə' });
  assert.deepEqual(classifyHttpStatus(403), { state: 'restricted', label: '403 · Qorunan' });
  assert.deepEqual(classifyHttpStatus(404), { state: 'restricted', label: '404 · Cavab var' });
  assert.deepEqual(classifyHttpStatus(502), { state: 'error', label: '502 · Server xətası' });
});

test('isValidProbeTarget rejects internal hostnames and preserves public subdomains', () => {
  assert.equal(isValidProbeTarget('localhost'), null);
  assert.equal(isValidProbeTarget('db.internal'), null);
  assert.equal(isValidProbeTarget('api.github.com'), 'api.github.com');
  assert.equal(isValidProbeTarget('*.docs.github.com'), 'docs.github.com');
});
