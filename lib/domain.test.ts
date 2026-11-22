import test from 'node:test';
import assert from 'node:assert/strict';
import {
  cleanHostInput,
  extractCertSpotterSubdomains,
  extractCrtSubdomains,
  extractHackerTargetSubdomains,
  mergeSubdomainSources,
  normalizeApex,
} from './domain.ts';

test('cleanHostInput strips scheme, auth, port, path, and wildcards', () => {
  assert.equal(
    cleanHostInput('  HTTPS://user:pass@*.API.GitHub.COM:8443/v1/users?q=1#top  '),
    'api.github.com'
  );
  assert.equal(cleanHostInput('*.*.dev.openai.com.'), 'dev.openai.com');
});

test('normalizeApex extracts true eTLD+1 apex domain', () => {
  assert.equal(normalizeApex('https://docs.api.openai.com/overview'), 'openai.com');
  assert.equal(normalizeApex('https://www.nestle.com/'), 'nestle.com');
  assert.equal(normalizeApex('*.sub.bbc.co.uk:443'), 'bbc.co.uk');
  assert.equal(normalizeApex('sub.mail.gov.az'), 'mail.gov.az');
  assert.equal(normalizeApex('portal.e-gov.az'), 'e-gov.az');
});

test('normalizeApex rejects empty, IP, and invalid domains', () => {
  assert.throws(() => normalizeApex(''));
  assert.throws(() => normalizeApex('not-a-domain'));
  assert.throws(() => normalizeApex('192.168.1.1'));
  assert.throws(() => normalizeApex('http://localhost'));
});

test('extractCrtSubdomains deduplicates, filters scope, and keeps earliest date', () => {
  const records = [
    {
      common_name: '*.api.example.com',
      name_value: 'api.example.com\n*.dev.example.com\nunrelated.org\nadmin@example.com',
      not_before: '2024-05-12T00:00:00',
    },
    {
      common_name: 'api.example.com',
      name_value: 'api.example.com\nexample.com',
      not_before: '2021-03-04T12:30:00',
    },
    {
      common_name: 'cdn.example.com',
      name_value: 'cdn.example.com',
      entry_timestamp: '2022-11-19T08:00:00.123',
    },
  ];

  const extracted = extractCrtSubdomains(records, 'example.com');
  assert.deepEqual(extracted, [
    { subdomain: 'api.example.com', first_seen: '2021-03-04' },
    { subdomain: 'cdn.example.com', first_seen: '2022-11-19' },
    { subdomain: 'dev.example.com', first_seen: '2024-05-12' },
    { subdomain: 'example.com', first_seen: '2021-03-04' },
  ]);
});

test('extractCertSpotterSubdomains and extractHackerTargetSubdomains parse and merge cleanly', () => {
  const cs = extractCertSpotterSubdomains(
    [
      {
        dns_names: ['*.shop.nestle.com', 'www.nestle.com', 'other.com'],
        not_before: '2023-02-10T00:00:00Z',
      },
    ],
    'nestle.com'
  );
  const ht = extractHackerTargetSubdomains(
    'API count exceeded - ignored\nwww.nestle.com,1.2.3.4\nhes.nestle.com,5.6.7.8\nevil.org,1.1.1.1',
    'nestle.com'
  );
  const merged = mergeSubdomainSources([cs, ht]);
  assert.deepEqual(merged, [
    { subdomain: 'hes.nestle.com', first_seen: '—' },
    { subdomain: 'shop.nestle.com', first_seen: '2023-02-10' },
    { subdomain: 'www.nestle.com', first_seen: '2023-02-10' },
  ]);
});
