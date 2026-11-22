import fs from 'node:fs';
import path from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import type { SubdomainEntry } from './domain.ts';
import type { ProbeResult, ProbeState } from './probe.ts';

export const CACHE_TTL_SECONDS = 24 * 60 * 60;
export const PROBE_TTL_SECONDS = 60 * 60;

export interface CachedResult {
  apex: string;
  rows: SubdomainEntry[];
  lastFetchedAt: number;
  isFresh: boolean;
}

export interface StoreStats {
  total_apexes: number;
  total_subdomains: number;
}

export function resolveSqlitePath(): string {
  const explicit = (process.env.SUBDOMAINS_DB_PATH || '').trim();
  if (explicit) {
    return explicit;
  }
  if (process.env.VERCEL || process.env.AWS_LAMBDA_FUNCTION_NAME) {
    return '/tmp/subdomains.db';
  }
  return path.resolve(process.cwd(), 'subdomains.db');
}

export class SubdomainStore {
  private readonly dbPath: string;
  private db: DatabaseSync | null = null;

  constructor(dbPath?: string) {
    this.dbPath = dbPath || resolveSqlitePath();
  }

  private getDb(): DatabaseSync {
    if (!this.db) {
      fs.mkdirSync(path.dirname(this.dbPath), { recursive: true });
      this.db = new DatabaseSync(this.dbPath);
      this.db.exec('PRAGMA journal_mode = WAL; PRAGMA synchronous = NORMAL;');
    }
    return this.db;
  }

  init(): void {
    const db = this.getDb();
    db.exec(`
      CREATE TABLE IF NOT EXISTS subdomains (
        apex TEXT NOT NULL,
        subdomain TEXT NOT NULL,
        first_seen TEXT NOT NULL,
        PRIMARY KEY (apex, subdomain, first_seen)
      );
      CREATE INDEX IF NOT EXISTS idx_subdomains_apex ON subdomains (apex);
      CREATE TABLE IF NOT EXISTS apex_meta (
        apex TEXT PRIMARY KEY,
        last_fetched_at REAL NOT NULL,
        total_count INTEGER NOT NULL DEFAULT 0
      );
      CREATE TABLE IF NOT EXISTS probe_cache (
        subdomain TEXT PRIMARY KEY,
        state TEXT NOT NULL,
        http_code INTEGER,
        scheme TEXT,
        label TEXT NOT NULL,
        latency_ms INTEGER,
        checked_at REAL NOT NULL
      );
      DELETE FROM apex_meta WHERE total_count = 0;
    `);
  }

  getCached(apex: string, ttlSeconds: number = CACHE_TTL_SECONDS): CachedResult | null {
    const db = this.getDb();
    const meta = db
      .prepare('SELECT last_fetched_at FROM apex_meta WHERE apex = ?')
      .get(apex) as { last_fetched_at: number } | undefined;

    if (!meta) {
      return null;
    }

    const nowSec = Date.now() / 1000;
    const isFresh = nowSec - meta.last_fetched_at < ttlSeconds;

    const rows = db
      .prepare(
        'SELECT subdomain, first_seen FROM subdomains WHERE apex = ? ORDER BY subdomain ASC'
      )
      .all(apex) as Array<{ subdomain: string; first_seen: string }>;

    return {
      apex,
      rows: rows.map((r) => ({
        subdomain: String(r.subdomain),
        first_seen: String(r.first_seen),
      })),
      lastFetchedAt: Number(meta.last_fetched_at),
      isFresh,
    };
  }

  saveResults(apex: string, rows: SubdomainEntry[]): void {
    if (rows.length === 0) {
      return;
    }
    const db = this.getDb();
    const nowSec = Date.now() / 1000;

    db.exec('BEGIN');
    try {
      db.prepare('DELETE FROM subdomains WHERE apex = ?').run(apex);
      const insertStmt = db.prepare(
        'INSERT OR IGNORE INTO subdomains (apex, subdomain, first_seen) VALUES (?, ?, ?)'
      );
      for (const row of rows) {
        insertStmt.run(apex, row.subdomain, row.first_seen);
      }

      db.prepare(
        `
        INSERT INTO apex_meta (apex, last_fetched_at, total_count)
        VALUES (?, ?, ?)
        ON CONFLICT(apex) DO UPDATE SET
          last_fetched_at = excluded.last_fetched_at,
          total_count = excluded.total_count
      `
      ).run(apex, nowSec, rows.length);
      db.exec('COMMIT');
    } catch (error) {
      db.exec('ROLLBACK');
      throw error;
    }
  }

  getStats(): StoreStats {
    const db = this.getDb();
    const row = db
      .prepare(
        `
        SELECT
          (SELECT COUNT(*) FROM apex_meta) AS total_apexes,
          (SELECT COUNT(*) FROM subdomains) AS total_subdomains
      `
      )
      .get() as { total_apexes: number; total_subdomains: number } | undefined;

    return {
      total_apexes: Number(row?.total_apexes ?? 0),
      total_subdomains: Number(row?.total_subdomains ?? 0),
    };
  }

  getCachedProbes(
    subdomains: string[],
    ttlSeconds: number = PROBE_TTL_SECONDS
  ): Map<string, ProbeResult> {
    const resultMap = new Map<string, ProbeResult>();
    if (subdomains.length === 0) return resultMap;

    const db = this.getDb();
    const minCheckedAt = Date.now() / 1000 - ttlSeconds;
    const chunkSize = 400;

    for (let i = 0; i < subdomains.length; i += chunkSize) {
      const chunk = subdomains.slice(i, i + chunkSize);
      const placeholders = chunk.map(() => '?').join(',');
      const rows = db
        .prepare(
          `SELECT subdomain, state, http_code, scheme, label, latency_ms
           FROM probe_cache
           WHERE checked_at >= ? AND subdomain IN (${placeholders})`
        )
        .all(minCheckedAt, ...chunk) as Array<{
        subdomain: string;
        state: string;
        http_code: number | null;
        scheme: 'https' | 'http' | null;
        label: string;
        latency_ms: number | null;
      }>;

      for (const row of rows) {
        resultMap.set(row.subdomain, {
          subdomain: row.subdomain,
          state: row.state as ProbeState,
          http_code: row.http_code === null ? null : Number(row.http_code),
          scheme: row.scheme,
          label: row.label,
          latency_ms: row.latency_ms === null ? null : Number(row.latency_ms),
        });
      }
    }

    return resultMap;
  }

  saveProbes(results: ProbeResult[]): void {
    if (results.length === 0) return;
    const db = this.getDb();
    const nowSec = Date.now() / 1000;

    db.exec('BEGIN');
    try {
      const stmt = db.prepare(
        `
        INSERT INTO probe_cache (subdomain, state, http_code, scheme, label, latency_ms, checked_at)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(subdomain) DO UPDATE SET
          state = excluded.state,
          http_code = excluded.http_code,
          scheme = excluded.scheme,
          label = excluded.label,
          latency_ms = excluded.latency_ms,
          checked_at = excluded.checked_at
      `
      );
      for (const item of results) {
        stmt.run(
          item.subdomain,
          item.state,
          item.http_code,
          item.scheme,
          item.label,
          item.latency_ms,
          nowSec
        );
      }
      db.exec('COMMIT');
    } catch (error) {
      db.exec('ROLLBACK');
      throw error;
    }
  }

  close(): void {
    if (this.db) {
      this.db.close();
      this.db = null;
    }
  }
}
