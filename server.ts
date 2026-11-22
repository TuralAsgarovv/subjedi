import 'dotenv/config';
import express from 'express';
import path from 'node:path';
import { performance } from 'node:perf_hooks';
import { fileURLToPath } from 'node:url';
import { SubdomainStore } from './lib/db.ts';
import { isAllowedDomain, parseAllowedDomains } from './lib/allowedDomains.ts';
import {
  extractCertSpotterSubdomains,
  extractCrtSubdomains,
  extractHackerTargetSubdomains,
  mergeSubdomainSources,
  normalizeApex,
  type CertSpotterRecord,
  type CrtRecord,
  type SubdomainEntry,
} from './lib/domain.ts';
import { isValidProbeTarget, probeBatch, type ProbeResult } from './lib/probe.ts';

const PORT = Number(process.env.PORT || 3000);
const CRT_SH_URL = 'https://crt.sh/';
const CERTSPOTTER_URL = 'https://api.certspotter.com/v1/issuances';
const HACKERTARGET_URL = 'https://api.hackertarget.com/hostsearch/';
const CRT_TIMEOUT_MS = 8_000;
const FAST_SOURCE_TIMEOUT_MS = 6_000;
const RECON_USER_AGENT = 'Mozilla/5.0 (compatible; subjedi/1.0)';
const allowedDomains = parseAllowedDomains(process.env.ALLOWED_DOMAINS);

const store = new SubdomainStore();
store.init();

class UpstreamHttpError extends Error {
  readonly statusCode: number;

  constructor(statusCode: number, message: string) {
    super(message);
    this.statusCode = statusCode;
  }
}

async function fetchWithTimeout(
  url: string,
  timeoutMs: number,
  accept: string
): Promise<Response> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);

  try {
    return await fetch(url, {
      method: 'GET',
      headers: {
        'User-Agent': RECON_USER_AGENT,
        Accept: accept,
      },
      signal: controller.signal,
    });
  } catch (err) {
    if (err instanceof Error && err.name === 'AbortError') {
      throw new UpstreamHttpError(504, 'Sorğu vaxt aşımına uğradı.');
    }
    const detail = err instanceof Error ? err.message : String(err);
    throw new UpstreamHttpError(502, `Şəbəkə xətası: ${detail}`);
  } finally {
    clearTimeout(timer);
  }
}

async function fetchCrtSh(apex: string): Promise<SubdomainEntry[]> {
  const url = `${CRT_SH_URL}?q=${encodeURIComponent(`%.${apex}`)}&output=json`;
  const response = await fetchWithTimeout(
    url,
    CRT_TIMEOUT_MS,
    'application/json,text/plain,*/*'
  );

  if (!response.ok) {
    throw new UpstreamHttpError(response.status === 429 ? 429 : 502, `HTTP ${response.status}`);
  }

  const rawText = (await response.text()).trim();
  if (!rawText) {
    return [];
  }

  let payload: unknown;
  try {
    payload = JSON.parse(rawText);
  } catch {
    throw new UpstreamHttpError(502, 'Etibarsız JSON cavabı.');
  }

  if (!Array.isArray(payload)) {
    throw new UpstreamHttpError(502, 'Gözlənilməz cavab formatı.');
  }

  return extractCrtSubdomains(payload as CrtRecord[], apex);
}

async function fetchCertSpotter(apex: string): Promise<SubdomainEntry[]> {
  const url = `${CERTSPOTTER_URL}?domain=${encodeURIComponent(apex)}&include_subdomains=true&expand=dns_names`;
  const response = await fetchWithTimeout(
    url,
    FAST_SOURCE_TIMEOUT_MS,
    'application/json,*/*'
  );

  if (!response.ok) {
    throw new UpstreamHttpError(response.status === 429 ? 429 : 502, `HTTP ${response.status}`);
  }

  let payload: unknown;
  try {
    payload = await response.json();
  } catch {
    throw new UpstreamHttpError(502, 'Etibarsız JSON cavabı.');
  }

  if (!Array.isArray(payload)) {
    throw new UpstreamHttpError(502, 'Gözlənilməz cavab formatı.');
  }

  return extractCertSpotterSubdomains(payload as CertSpotterRecord[], apex);
}

async function fetchHackerTarget(apex: string): Promise<SubdomainEntry[]> {
  const url = `${HACKERTARGET_URL}?q=${encodeURIComponent(apex)}`;
  const response = await fetchWithTimeout(
    url,
    FAST_SOURCE_TIMEOUT_MS,
    'text/plain,*/*'
  );

  if (!response.ok) {
    throw new UpstreamHttpError(response.status === 429 ? 429 : 502, `HTTP ${response.status}`);
  }

  const rawText = (await response.text()).trim();
  if (!rawText) {
    return [];
  }

  const lower = rawText.toLowerCase();
  if (lower.startsWith('error ') || lower.includes('api count exceeded')) {
    throw new UpstreamHttpError(429, rawText);
  }

  return extractHackerTargetSubdomains(rawText, apex);
}

async function fetchAllPassiveSources(apex: string): Promise<SubdomainEntry[]> {
  const settled = await Promise.allSettled([
    fetchCrtSh(apex),
    fetchCertSpotter(apex),
    fetchHackerTarget(apex),
  ]);

  const fulfilledLists: SubdomainEntry[][] = [];
  const rejectedErrors: UpstreamHttpError[] = [];

  for (const result of settled) {
    if (result.status === 'fulfilled') {
      fulfilledLists.push(result.value);
    } else if (result.reason instanceof UpstreamHttpError) {
      rejectedErrors.push(result.reason);
    } else {
      rejectedErrors.push(new UpstreamHttpError(502, 'Mənbə xətası.'));
    }
  }

  const merged = fulfilledLists.length > 0 ? mergeSubdomainSources(fulfilledLists) : [];

  if (fulfilledLists.length === 0 || (merged.length === 0 && rejectedErrors.length > 0)) {
    const allTimedOut =
      rejectedErrors.length > 0 &&
      rejectedErrors.every((err) => err.statusCode === 504);
    if (allTimedOut) {
      throw new UpstreamHttpError(
        504,
        'Mənbə sorğuları vaxt aşımına uğradı. Zəhmət olmasa bir az sonra yenidən cəhd edin.'
      );
    }
    throw new UpstreamHttpError(
      502,
      'Subdomen mənbələrindən cavab alınmadı. Zəhmət olmasa bir az sonra yenidən cəhd edin.'
    );
  }

  return merged;
}

const app = express();
const api = express.Router();
app.disable('x-powered-by');
app.use(express.json({ limit: '64kb' }));

api.get('/v1/search', async (req, res) => {
  const started = performance.now();
  const rawApex = typeof req.query.apex === 'string' ? req.query.apex : '';
  const format = req.query.format === 'json' ? 'json' : 'text';
  const includeDates = req.query.dates === '1';
  const forceRefresh = req.query.refresh === '1';

  let normalizedApex: string;
  try {
    normalizedApex = normalizeApex(rawApex);
  } catch (err) {
    const message =
      err instanceof Error ? err.message : 'Etibarlı domen adı daxil edin.';
    res.status(400).json({ detail: message });
    return;
  }

  if (allowedDomains.size === 0) {
    res.status(503).json({
      detail: 'Skan API deaktivdir. ALLOWED_DOMAINS mühit dəyişənini qurun.',
    });
    return;
  }
  if (!isAllowedDomain(normalizedApex, allowedDomains)) {
    res.status(403).json({ detail: 'Bu domen ALLOWED_DOMAINS siyahısında deyil.' });
    return;
  }

  const cachedEntry = store.getCached(normalizedApex);
  let isCached = false;
  let isStale = false;
  let rows: SubdomainEntry[] = [];
  let fetchedAtSec = Date.now() / 1000;

  if (
    !forceRefresh &&
    cachedEntry &&
    cachedEntry.isFresh &&
    cachedEntry.rows.length > 0
  ) {
    isCached = true;
    rows = cachedEntry.rows;
    fetchedAtSec = cachedEntry.lastFetchedAt;
  } else {
    try {
      rows = await fetchAllPassiveSources(normalizedApex);
      if (rows.length > 0) {
        store.saveResults(normalizedApex, rows);
      }
      fetchedAtSec = Date.now() / 1000;
    } catch (err) {
      if (cachedEntry && cachedEntry.rows.length > 0) {
        isCached = true;
        isStale = true;
        rows = cachedEntry.rows;
        fetchedAtSec = cachedEntry.lastFetchedAt;
      } else if (err instanceof UpstreamHttpError) {
        res.status(err.statusCode).json({ detail: err.message });
        return;
      } else {
        res.status(502).json({
          detail:
            'Subdomen mənbələrindən cavab alınarkən gözlənilməz xəta baş verdi.',
        });
        return;
      }
    }
  }

  const elapsedMs = Math.round((performance.now() - started) * 10) / 10;
  res.setHeader('X-Cache', isStale ? 'STALE' : isCached ? 'HIT' : 'MISS');
  res.setHeader('X-Response-Time-Ms', String(elapsedMs));

  if (format === 'json') {
    const cachedProbes = store.getCachedProbes(rows.map((r) => r.subdomain));
    res.json({
      apex: normalizedApex,
      count: rows.length,
      cached: isCached,
      stale: isStale,
      fetched_at: new Date(fetchedAtSec * 1000).toISOString(),
      elapsed_ms: elapsedMs,
      subdomains: includeDates
        ? rows.map((r) => ({
            ...r,
            probe: cachedProbes.get(r.subdomain) ?? null,
          }))
        : rows.map((r) => r.subdomain),
    });
    return;
  }

  const lines = includeDates
    ? rows.map((r) => `${r.subdomain}\t${r.first_seen}`)
    : rows.map((r) => r.subdomain);
  const textBody = lines.length > 0 ? `${lines.join('\n')}\n` : '';
  res.type('text/plain; charset=utf-8').send(textBody);
});

api.post('/v1/probe', async (req, res) => {
  const body = req.body as { subdomains?: unknown } | undefined;
  if (!body || !Array.isArray(body.subdomains)) {
    res.status(400).json({ detail: 'subdomains massivi tələb olunur.' });
    return;
  }

  const uniqueTargets = Array.from(
    new Set(
      body.subdomains
        .filter((item): item is string => typeof item === 'string')
        .map((s) => s.trim().toLowerCase())
        .filter(Boolean)
    )
  ).slice(0, 50);

  if (uniqueTargets.length === 0) {
    res.status(400).json({ detail: 'Yoxlanılacaq subdomen siyahısı boşdur.' });
    return;
  }

  if (allowedDomains.size === 0) {
    res.status(503).json({
      detail: 'Skan API deaktivdir. ALLOWED_DOMAINS mühit dəyişənini qurun.',
    });
    return;
  }
  for (const target of uniqueTargets) {
    const host = isValidProbeTarget(target);
    if (!host) {
      res.status(400).json({ detail: 'Etibarsız subdomen adı.' });
      return;
    }
    if (!isAllowedDomain(host, allowedDomains)) {
      res.status(403).json({
        detail: 'Bütün yoxlama hədəfləri ALLOWED_DOMAINS daxilində olmalıdır.',
      });
      return;
    }
  }

  const cachedMap = store.getCachedProbes(uniqueTargets);
  const missingTargets = uniqueTargets.filter((sub) => !cachedMap.has(sub));

  if (missingTargets.length > 0) {
    const freshResults = await probeBatch(missingTargets, 15);
    store.saveProbes(freshResults);
    for (const item of freshResults) {
      cachedMap.set(item.subdomain, item);
    }
  }

  const results: Record<string, ProbeResult> = {};
  for (const sub of uniqueTargets) {
    const entry = cachedMap.get(sub);
    if (entry) {
      results[sub] = entry;
    }
  }

  res.json({
    results,
    cached_count: uniqueTargets.length - missingTargets.length,
    probed_count: missingTargets.length,
  });
});

api.get('/v1/stats', (_req, res) => {
  res.json(store.getStats());
});

app.use('/api', api);
app.use(api);

const staticDir = path.resolve(process.cwd(), 'static');
app.use(express.static(staticDir, { extensions: ['html'] }));

export default app;

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  app.listen(PORT, '0.0.0.0', () => {
    console.log(`subjedi server running at http://0.0.0.0:${PORT}`);
  });
}
