import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import assert from 'node:assert/strict';
import { SubdomainStore } from './db.ts';

test('SubdomainStore caches, retrieves, and tracks stats accurately', () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'crt-recon-'));
  const dbPath = path.join(tmpDir, 'test.db');
  const store = new SubdomainStore(dbPath);

  try {
    store.init();
    assert.deepEqual(store.getStats(), { total_apexes: 0, total_subdomains: 0 });
    assert.equal(store.getCached('example.com'), null);

    const rows = [
      { subdomain: 'api.example.com', first_seen: '2021-04-12' },
      { subdomain: 'dev.example.com', first_seen: '2023-08-01' },
    ];
    store.saveResults('example.com', rows);

    const cached = store.getCached('example.com');
    assert.ok(cached);
    assert.equal(cached.isFresh, true);
    assert.deepEqual(cached.rows, rows);
    assert.deepEqual(store.getStats(), { total_apexes: 1, total_subdomains: 2 });

    // Expired TTL check
    const expired = store.getCached('example.com', -1);
    assert.ok(expired);
    assert.equal(expired.isFresh, false);

    // Empty results must not poison cache
    store.saveResults('empty.com', []);
    assert.equal(store.getCached('empty.com'), null);
  } finally {
    store.close();
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});
