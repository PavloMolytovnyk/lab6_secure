import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { loadConfig } from '../src/config.mjs';
import { createApplication } from '../src/app.mjs';
import { generateCaptchaText } from '../src/captcha.mjs';
import { startDemoProvider } from '../src/demo-provider.mjs';

export async function fixture({ provider = false, ...overrides } = {}) {
  const dataDir = mkdtempSync(join(tmpdir(), 'lab6-test-'));
  const config = loadConfig({ dataDir, port: 0, appUrl: 'http://127.0.0.1:3000', demoOidcPort: 0, adminPassword: 'Admin2026!StudyOnly', demo: true, production: false, mailTransport: 'outbox', ...overrides });
  let offset = 0, lastCaptcha = '';
  const app = await createApplication({ config, now: () => Date.now() + offset, captchaTextFactory: () => { lastCaptcha = generateCaptchaText();return lastCaptcha; } });
  await app.listen(0);config.appUrl = 'http://127.0.0.1:' + app.server.address().port;
  const oidcProvider = provider ? await startDemoProvider(config) : null;
  return {
    app, config, base: config.appUrl,
    advance(ms) { offset += ms; },
    get captchaAnswer() { return lastCaptcha; },
    mails(to) { return app.db.all('SELECT * FROM mail_messages WHERE recipient=? ORDER BY rowid DESC', to); },
    token(to, path) { const message = this.mails(to).find(m => m.body.includes('/' + path + '?token='));return new URL(message.body.match(/https?:\/\/[^\s]+/)[0]).searchParams.get('token'); },
    otp(to) { const message = this.mails(to).find(m => m.body.startsWith('Код підтвердження:'));return /Код підтвердження: ([0-9]{6})/.exec(message.body)[1]; },
    async close() { await app.close();await oidcProvider?.close();rmSync(dataDir, { recursive: true, force: true }); },
  };
}

export class Client {
  constructor(base) { this.base = base;this.cookies = new Map();this.csrf = ''; }
  async request(path, options = {}) {
    const headers = { cookie: [...this.cookies].map(([k,v]) => k + '=' + v).join('; '), ...options.headers };
    const response = await fetch(new URL(path, this.base), { ...options, headers, redirect: 'manual' });
    for (const line of response.headers.getSetCookie()) { const first = line.split(';')[0], pos = first.indexOf('=');this.cookies.set(first.slice(0,pos), first.slice(pos+1)); }
    const text = await response.text();let data;
    try { data = JSON.parse(text); } catch { data = text; }
    if (data?.csrf) this.csrf = data.csrf;
    return { status: response.status, data, headers: response.headers, text };
  }
  get(path) { return this.request(path); }
  post(path, body, headers = {}) { return this.request(path, { method: 'POST', headers: { 'content-type': 'application/json', 'x-csrf-token': this.csrf, origin: this.base, ...headers }, body: JSON.stringify(body) }); }
  async init() { await this.get('/api/session');return this; }
}
export async function register(f, client, email = 'student@example.test', password = 'Student2026!Secure', name = 'Павло Студент') {
  const captcha = (await client.get('/api/captcha')).data;
  return client.post('/api/auth/register', { email, name, password, captchaId: captcha.id, captchaAnswer: f.captchaAnswer });
}
export async function activeUser(f, client, email = 'student@example.test', password = 'Student2026!Secure') {
  await register(f, client, email, password);await client.post('/api/auth/activate', { token: f.token(email,'activate') });
  return client.post('/api/auth/login', { email, password });
}
export async function admin(f) { const client = await new Client(f.base).init();await client.post('/api/auth/login', { email: f.config.adminEmail, password: f.config.adminPassword });return client; }

export async function oidcFlow(f, client) {
  const start = await client.get('/auth/oidc/start/demo');
  const provider = new Client('http://localhost:' + f.config.demoOidcPort);
  const form = await provider.get(start.headers.get('location'));
  const transaction = /name="transaction" value="([^"]+)"/.exec(form.text)[1];
  const login = await provider.request('/authorize', { method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded', origin: provider.base }, body: new URLSearchParams({ transaction, email:'oidc.user@provider.test',password:'Provider2026!StudyOnly' }).toString() });
  const callback = login.headers.get('location');
  const result = await client.get(callback);
  return { start, form, login, callback, result, provider };
}
