import { readFileSync, existsSync, mkdirSync, writeFileSync } from 'node:fs';
import { resolve, dirname } from 'node:path';
import { randomBytes } from 'node:crypto';
import { fileURLToPath } from 'node:url';

export const PROJECT_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');

export function readEnvironment(path = resolve(PROJECT_ROOT, '.env')) {
  if (!existsSync(path)) return;
  for (const line of readFileSync(path, 'utf8').split(/\r?\n/)) {
    const match = line.match(/^\s*([A-Z_][A-Z0-9_]*)=(.*)$/);
    if (!match || process.env[match[1]] !== undefined) continue;
    process.env[match[1]] = match[2].trim().replace(/^(['"])(.*)\1$/, '$2');
  }
}

export function loadConfig(overrides = {}) {
  const production = process.env.NODE_ENV === 'production';
  const config = {
    production, host: process.env.HOST ?? '127.0.0.1',
    port: Number(process.env.PORT ?? 3000),
    appUrl: process.env.APP_URL ?? 'http://127.0.0.1:3000',
    demo: (process.env.DEMO_MODE ?? (production ? 'false' : 'true')) === 'true',
    dataDir: resolve(PROJECT_ROOT, process.env.DATA_DIR ?? '.runtime'),
    adminEmail: process.env.ADMIN_EMAIL ?? 'admin@lab.test',
    adminPassword: process.env.ADMIN_PASSWORD ?? (production ? '' : 'Admin2026!StudyOnly'),
    mailTransport: process.env.MAIL_TRANSPORT ?? (production ? 'smtp' : 'outbox'),
    mailFrom: process.env.MAIL_FROM ?? 'Security Lab <no-reply@example.com>',
    smtpHost: process.env.SMTP_HOST ?? '', smtpPort: Number(process.env.SMTP_PORT ?? 465),
    smtpSecurity: process.env.SMTP_SECURITY ?? 'tls',
    smtpUser: process.env.SMTP_USER ?? '', smtpPassword: process.env.SMTP_PASSWORD ?? '',
    googleClientId: process.env.GOOGLE_CLIENT_ID ?? '',
    googleClientSecret: process.env.GOOGLE_CLIENT_SECRET ?? '',
    demoOidcPort: Number(process.env.DEMO_OIDC_PORT ?? 3101),
    lockThreshold: 5, lockDurationMs: 15 * 60_000,
    sessionTtlMs: 8 * 60 * 60_000, sessionIdleMs: 30 * 60_000,
    activationTtlMs: 30 * 60_000, resetTtlMs: 15 * 60_000,
    otpTtlMs: 5 * 60_000, captchaTtlMs: 5 * 60_000,
    ...overrides,
  };
  config.appUrl = new URL(config.appUrl).origin;
  if (config.demo && !['127.0.0.1', 'localhost', '::1'].includes(config.host)) {
    throw new Error('DEMO_MODE дозволений лише з локальним HOST.');
  }
  if (config.production && (config.demo || config.mailTransport !== 'smtp' || !config.appUrl.startsWith('https://'))) {
    throw new Error('Production потребує HTTPS, SMTP та DEMO_MODE=false.');
  }
  if (!config.demo && config.mailTransport === 'outbox') throw new Error('Outbox доступний лише в DEMO_MODE.');
  if (config.production && !config.smtpHost) throw new Error('Production потребує SMTP_HOST.');
  if (!['tls', 'starttls'].includes(config.smtpSecurity)) throw new Error('SMTP_SECURITY: tls або starttls.');
  mkdirSync(config.dataDir, { recursive: true, mode: 0o700 });
  const keyPath = resolve(config.dataDir, 'secret.key');
  if (!existsSync(keyPath)) writeFileSync(keyPath, randomBytes(32), { flag: 'wx', mode: 0o600 });
  config.secretKey = readFileSync(keyPath);
  if (config.secretKey.length !== 32) throw new Error('secret.key має містити 32 байти.');
  config.cookieName = config.production ? '__Host-lab6_session' : 'lab6_session';
  return config;
}
