import { randomBytes, randomInt, scrypt, timingSafeEqual, createHash, createHmac, createCipheriv, createDecipheriv } from 'node:crypto';
import { promisify } from 'node:util';

const derive = promisify(scrypt);
const N = 32768, R = 8, P = 1;
const COMMON = new Set(['password1!', 'password123!', 'qwerty123!', 'admin123!', 'welcome1!', '12345678a!']);
export const randomToken = (size = 32) => randomBytes(size).toString('base64url');
export const sha256 = value => createHash('sha256').update(value).digest('hex');
export const hmac = (key, value) => createHmac('sha256', key).update(value).digest('hex');
export const generateOtp = () => randomInt(0, 1_000_000).toString().padStart(6, '0');

export function passwordErrors(password) {
  if (typeof password !== 'string') return ['Введіть пароль.'];
  const errors = [];
  if ([...password].length < 8) errors.push('Щонайменше 8 символів.');
  if ([...password].length > 128) errors.push('Не більше 128 символів.');
  if (!/\p{Lu}/u.test(password)) errors.push('Додайте велику літеру.');
  if (!/\p{Ll}/u.test(password)) errors.push('Додайте малу літеру.');
  if (!/[0-9]/.test(password)) errors.push('Додайте цифру.');
  if (!/[\p{P}\p{S}]/u.test(password)) errors.push('Додайте спеціальний символ.');
  if (/[\x00-\x1f\x7f]/.test(password)) errors.push('Керівні символи заборонено.');
  if (COMMON.has(password.toLowerCase())) errors.push('Цей пароль надто поширений.');
  return errors;
}

export async function hashPassword(password) {
  const salt = randomBytes(16);
  const key = await derive(password, salt, 64, { N, r: R, p: P, maxmem: 64 * 1024 * 1024 });
  return `scrypt$${N}$${R}$${P}$${salt.toString('base64url')}$${key.toString('base64url')}`;
}

export async function verifyPassword(password, encoded) {
  if (typeof password !== 'string' || password.length > 512 || !encoded) return false;
  const [algorithm, n, r, p, salt, saved] = encoded.split('$');
  if (algorithm !== 'scrypt' || Number(n) !== N || Number(r) !== R || Number(p) !== P || !salt || !saved) return false;
  const expected = Buffer.from(saved, 'base64url');
  if (expected.length !== 64) return false;
  const actual = await derive(password, Buffer.from(salt, 'base64url'), 64, { N, r: R, p: P, maxmem: 64 * 1024 * 1024 });
  return timingSafeEqual(actual, expected);
}

export function safeEqual(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string') return false;
  const x = Buffer.from(a), y = Buffer.from(b);
  return x.length === y.length && timingSafeEqual(x, y);
}

export function normalizeEmail(value) {
  if (typeof value !== 'string') return '';
  const email = value.trim().toLowerCase();
  return email.length <= 254 && /^[^\s<>@]+@[^\s<>@]+\.[^\s<>@]+$/.test(email) && !/[\r\n]/.test(email) ? email : '';
}

export function encryptSecret(value, key) {
  const iv = randomBytes(12), cipher = createCipheriv('aes-256-gcm', key, iv);
  const encrypted = Buffer.concat([cipher.update(value, 'utf8'), cipher.final()]);
  return Buffer.concat([iv, cipher.getAuthTag(), encrypted]).toString('base64url');
}

export function decryptSecret(value, key) {
  const data = Buffer.from(value, 'base64url');
  const decipher = createDecipheriv('aes-256-gcm', key, data.subarray(0, 12));
  decipher.setAuthTag(data.subarray(12, 28));
  return Buffer.concat([decipher.update(data.subarray(28)), decipher.final()]).toString('utf8');
}

export function escapeHtml(value = '') {
  return String(value).replace(/[&<>"']/g, char => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[char]);
}

export class HttpError extends Error {
  constructor(status, message, code = 'request_error', details) {
    super(message);this.status = status;this.code = code;this.details = details;
  }
}
