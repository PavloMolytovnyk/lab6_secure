import { DatabaseSync } from 'node:sqlite';
import { resolve } from 'node:path';

export function openDatabase(dataDir) {
  const db = new DatabaseSync(resolve(dataDir, 'lab6.sqlite'));
  db.exec(`PRAGMA foreign_keys=ON; PRAGMA journal_mode=WAL; PRAGMA busy_timeout=5000;
    CREATE TABLE IF NOT EXISTS users (
      id TEXT PRIMARY KEY, email TEXT UNIQUE NOT NULL COLLATE NOCASE, name TEXT NOT NULL,
      password_hash TEXT, role TEXT NOT NULL CHECK(role IN ('user','admin')) DEFAULT 'user',
      activated_at INTEGER, blocked INTEGER NOT NULL DEFAULT 0,
      mfa_enabled INTEGER NOT NULL DEFAULT 0, failed_attempts INTEGER NOT NULL DEFAULT 0,
      locked_until INTEGER NOT NULL DEFAULT 0, last_failed_at INTEGER NOT NULL DEFAULT 0,
      created_at INTEGER NOT NULL
    ) STRICT;
    CREATE TABLE IF NOT EXISTS sessions (
      id_hash TEXT PRIMARY KEY, user_id TEXT REFERENCES users(id) ON DELETE CASCADE,
      csrf TEXT NOT NULL, created_at INTEGER NOT NULL, expires_at INTEGER NOT NULL,
      last_seen_at INTEGER NOT NULL
    ) STRICT;
    CREATE TABLE IF NOT EXISTS captchas (
      id TEXT PRIMARY KEY, session_hash TEXT NOT NULL, answer_hash TEXT NOT NULL,
      image BLOB NOT NULL, expires_at INTEGER NOT NULL, consumed_at INTEGER
    ) STRICT;
    CREATE TABLE IF NOT EXISTS email_tokens (
      hash TEXT PRIMARY KEY, user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      purpose TEXT NOT NULL CHECK(purpose IN ('activate','reset')),
      created_at INTEGER NOT NULL, expires_at INTEGER NOT NULL, consumed_at INTEGER
    ) STRICT;
    CREATE TABLE IF NOT EXISTS otp_challenges (
      id TEXT PRIMARY KEY, user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      session_hash TEXT NOT NULL, purpose TEXT NOT NULL,
      code_hash TEXT NOT NULL, attempts INTEGER NOT NULL DEFAULT 0,
      created_at INTEGER NOT NULL, expires_at INTEGER NOT NULL, consumed_at INTEGER
    ) STRICT;
    CREATE TABLE IF NOT EXISTS audit_log (
      id INTEGER PRIMARY KEY AUTOINCREMENT, user_id TEXT, email TEXT,
      event TEXT NOT NULL, result TEXT NOT NULL, detail TEXT NOT NULL,
      ip TEXT NOT NULL, user_agent TEXT NOT NULL, created_at INTEGER NOT NULL
    ) STRICT;
    CREATE TABLE IF NOT EXISTS rate_limits (
      key TEXT PRIMARY KEY, count INTEGER NOT NULL, expires_at INTEGER NOT NULL
    ) STRICT;
    CREATE TABLE IF NOT EXISTS mail_messages (
      id TEXT PRIMARY KEY, recipient TEXT NOT NULL, subject TEXT NOT NULL,
      body TEXT NOT NULL, created_at INTEGER NOT NULL
    ) STRICT;
    CREATE TABLE IF NOT EXISTS mail_jobs (
      id TEXT PRIMARY KEY, payload TEXT NOT NULL, attempts INTEGER NOT NULL DEFAULT 0,
      next_attempt INTEGER NOT NULL, created_at INTEGER NOT NULL, sent_at INTEGER,
      last_error TEXT
    ) STRICT;
    CREATE TABLE IF NOT EXISTS oidc_requests (
      state_hash TEXT PRIMARY KEY, session_hash TEXT NOT NULL, provider TEXT NOT NULL,
      nonce_hash TEXT NOT NULL, verifier TEXT NOT NULL, expires_at INTEGER NOT NULL
    ) STRICT;
    CREATE TABLE IF NOT EXISTS identities (
      provider TEXT NOT NULL, subject TEXT NOT NULL,
      user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      PRIMARY KEY(provider,subject)
    ) STRICT;
    CREATE INDEX IF NOT EXISTS audit_created ON audit_log(created_at DESC);
    CREATE INDEX IF NOT EXISTS tokens_user ON email_tokens(user_id,purpose);
    CREATE INDEX IF NOT EXISTS otp_user ON otp_challenges(user_id,purpose);
  `);
  return {
    raw: db,
    get(sql, ...args) { return db.prepare(sql).get(...args); },
    all(sql, ...args) { return db.prepare(sql).all(...args); },
    run(sql, ...args) { return db.prepare(sql).run(...args); },
    transaction(fn) {
      db.exec('BEGIN IMMEDIATE');
      try { const result = fn();db.exec('COMMIT');return result; }
      catch (error) { db.exec('ROLLBACK');throw error; }
    },
    close() { db.close(); },
  };
}
