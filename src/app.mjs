import http from 'node:http';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { randomUUID } from 'node:crypto';
import { PROJECT_ROOT, loadConfig } from './config.mjs';
import { openDatabase } from './database.mjs';
import { createCaptchaService } from './captcha.mjs';
import { createMailer } from './mailer.mjs';
import { createOidcClient } from './oidc.mjs';
import { randomToken, sha256, hmac, safeEqual, hashPassword, verifyPassword, passwordErrors, normalizeEmail, generateOtp, encryptSecret, decryptSecret, HttpError } from './security.mjs';

export async function createApplication(options = {}) {
  const config = options.config ?? loadConfig(), now = options.now ?? Date.now;
  const db = openDatabase(config.dataDir), mailer = options.mailer ?? createMailer(db, config, now);
  const captcha = createCaptchaService(db, config, now, options.captchaTextFactory);
  const oidc = createOidcClient(config, options.fetcher ?? fetch);
  const dummyHash = await hashPassword(randomToken());
  if (!db.get('SELECT id FROM users WHERE role=?', 'admin')) {
    if (!config.adminPassword || passwordErrors(config.adminPassword).length) throw new Error('Задайте сильний ADMIN_PASSWORD для першого запуску.');
    const email = normalizeEmail(config.adminEmail);
    if (!email) throw new Error('Некоректний ADMIN_EMAIL.');
    db.run('INSERT INTO users(id,email,name,password_hash,role,activated_at,created_at) VALUES(?,?,?,?,?,?,?)', randomUUID(), email, 'Адміністратор', await hashPassword(config.adminPassword), 'admin', now(), now());
  }
  mailer.start?.();

  function audit(ctx, event, result, email = '', userId = null, detail = '') {
    db.run('INSERT INTO audit_log(user_id,email,event,result,detail,ip,user_agent,created_at) VALUES(?,?,?,?,?,?,?,?)', userId, email.slice(0,254), event, result, detail.slice(0,300), ctx.ip, String(ctx.req.headers['user-agent'] ?? '').slice(0,300), now());
  }
  function rateLimit(key, max, duration) {
    const saved = db.get('SELECT * FROM rate_limits WHERE key=?', key), timestamp = now();
    if (!saved || saved.expires_at <= timestamp) {
      db.run('INSERT INTO rate_limits(key,count,expires_at) VALUES(?,1,?) ON CONFLICT(key) DO UPDATE SET count=1,expires_at=excluded.expires_at', key, timestamp + duration);return;
    }
    if (saved.count >= max) throw new HttpError(429, 'Забагато запитів. Спробуйте пізніше.', 'rate_limited');
    db.run('UPDATE rate_limits SET count=count+1 WHERE key=?', key);
  }
  function cookie(res, raw, maxAge) {
    res.setHeader('set-cookie', `${config.cookieName}=${raw}; Path=/; HttpOnly; SameSite=Lax; Max-Age=${maxAge}${config.production ? '; Secure' : ''}`);
  }
  function newSession(res, userId = null) {
    const raw = randomToken(), timestamp = now(), duration = userId ? config.sessionTtlMs : config.sessionIdleMs;
    const value = { id_hash: sha256(raw), user_id: userId, csrf: randomToken(), created_at: timestamp, expires_at: timestamp + duration, last_seen_at: timestamp };
    db.run('INSERT INTO sessions(id_hash,user_id,csrf,created_at,expires_at,last_seen_at) VALUES(?,?,?,?,?,?)', value.id_hash, userId, value.csrf, timestamp, value.expires_at, timestamp);
    cookie(res, raw, Math.floor(duration / 1000));return value;
  }
  function getSession(req, res) {
    const value = (req.headers.cookie ?? '').split(';').map(s => s.trim()).find(s => s.startsWith(config.cookieName + '='))?.slice(config.cookieName.length + 1);
    let session = /^[A-Za-z0-9_-]{43}$/.test(value ?? '') ? db.get('SELECT * FROM sessions WHERE id_hash=?', sha256(value)) : null;
    if (session && (session.expires_at <= now() || session.last_seen_at + config.sessionIdleMs <= now())) {
      db.run('DELETE FROM sessions WHERE id_hash=?', session.id_hash);session = null;
    }
    if (!session) return newSession(res);
    db.run('UPDATE sessions SET last_seen_at=? WHERE id_hash=?', now(), session.id_hash);return session;
  }
  function rotateSession(ctx, userId) {
    db.run('DELETE FROM sessions WHERE id_hash=?', ctx.session.id_hash);
    db.run('DELETE FROM oidc_requests WHERE session_hash=?', ctx.session.id_hash);
    ctx.session = newSession(ctx.res, userId);
  }
  function publicUser(user) {
    return { id: user.id, email: user.email, name: user.name, role: user.role, activated: Boolean(user.activated_at), activatedAt: user.activated_at, blocked: Boolean(user.blocked), mfaEnabled: Boolean(user.mfa_enabled), createdAt: user.created_at, hasPassword: Boolean(user.password_hash), lockedUntil: user.locked_until, failedAttempts: user.failed_attempts, providers: db.all('SELECT provider FROM identities WHERE user_id=?', user.id).map(r => r.provider) };
  }
  function requireUser(ctx, role) {
    const user = ctx.session.user_id ? db.get('SELECT * FROM users WHERE id=?', ctx.session.user_id) : null;
    if (!user || !user.activated_at || user.blocked) throw new HttpError(401, 'Увійдіть до активного облікового запису.', 'unauthorized');
    if (role && user.role !== role) throw new HttpError(403, 'Ця дія доступна лише адміністратору.', 'forbidden');
    return user;
  }
  function validatePassword(value) {
    const errors = passwordErrors(value);if (errors.length) throw new HttpError(400, 'Пароль не відповідає політиці.', 'password_policy', errors);
  }
  async function issueEmailToken(user, purpose) {
    const token = randomToken(), timestamp = now(), duration = purpose === 'activate' ? config.activationTtlMs : config.resetTtlMs;
    db.run('UPDATE email_tokens SET consumed_at=? WHERE user_id=? AND purpose=? AND consumed_at IS NULL', timestamp, user.id, purpose);
    db.run('INSERT INTO email_tokens(hash,user_id,purpose,created_at,expires_at) VALUES(?,?,?,?,?)', sha256(token), user.id, purpose, timestamp, timestamp + duration);
    const path = purpose === 'activate' ? '/activate' : '/reset';
    const subject = purpose === 'activate' ? 'Активуйте обліковий запис SecureSpace' : 'Відновлення пароля SecureSpace';
    await mailer.send(user.email, subject, `${user.name},\n\n${purpose === 'activate' ? 'Для підтвердження email та активації облікового запису' : 'Для встановлення нового пароля'} відкрийте посилання:\n${config.appUrl}${path}?token=${token}\n\nПосилання одноразове та діє ${duration / 60_000} хвилин. Якщо ви не ініціювали запит, ігноруйте цей лист.`);
  }
  async function issueOtp(ctx, user, purpose) {
    const timestamp = now();
    const last = db.get('SELECT created_at FROM otp_challenges WHERE user_id=? AND purpose=? ORDER BY created_at DESC LIMIT 1', user.id, purpose);
    if (last && last.created_at + 30_000 > timestamp) throw new HttpError(429, 'Новий код можна отримати через 30 секунд.');
    rateLimit('otp:' + user.id, 10, 15 * 60_000);
    const id = randomToken(18), code = generateOtp();
    db.run('UPDATE otp_challenges SET consumed_at=? WHERE user_id=? AND purpose=? AND consumed_at IS NULL', timestamp, user.id, purpose);
    db.run('INSERT INTO otp_challenges(id,user_id,session_hash,purpose,code_hash,created_at,expires_at) VALUES(?,?,?,?,?,?,?)', id, user.id, ctx.session.id_hash, purpose, hmac(config.secretKey, id + ':' + code), timestamp, timestamp + config.otpTtlMs);
    await mailer.send(user.email, `Код підтвердження SecureSpace: ${purpose === 'login' ? 'вхід' : purpose === 'enable' ? 'увімкнення 2FA' : 'вимкнення 2FA'}`, `Код підтвердження: ${code}\n\nДіє 5 хвилин, лише для однієї операції. Не передавайте код іншим людям.\nОперація: ${purpose}.`);
    return { challengeId: id, expiresAt: timestamp + config.otpTtlMs };
  }
  function consumeOtp(ctx, id, code, purpose) {
    if (typeof id !== 'string' || typeof code !== 'string') throw new HttpError(400, 'Вкажіть ID перевірки та код.', 'otp_invalid');
    const outcome = db.transaction(() => {
      const item = db.get('SELECT * FROM otp_challenges WHERE id=? AND session_hash=? AND purpose=?', String(id ?? ''), ctx.session.id_hash, purpose);
      if (!item || item.consumed_at || item.expires_at <= now() || item.attempts >= 5) return { error: 'Код застарів або вже використаний.' };
      db.run('UPDATE otp_challenges SET attempts=attempts+1 WHERE id=?', item.id);
      if (!/^[0-9]{6}$/.test(String(code ?? '')) || !safeEqual(item.code_hash, hmac(config.secretKey, item.id + ':' + code))) {
        if (item.attempts + 1 >= 5) db.run('UPDATE otp_challenges SET consumed_at=? WHERE id=?', now(), item.id);
        return { error: 'Неправильний код підтвердження.', userId: item.user_id };
      }
      db.run('UPDATE otp_challenges SET consumed_at=? WHERE id=?', now(), item.id);return { item };
    });
    if (outcome.error) {
      audit(ctx, 'mfa_' + purpose, 'failure', '', outcome.userId ?? null, outcome.error);
      throw new HttpError(400, outcome.error, 'otp_invalid');
    }
    return outcome.item;
  }
  function json(ctx, status, value) {
    ctx.res.writeHead(status, { 'content-type': 'application/json; charset=utf-8' });ctx.res.end(JSON.stringify(value));
  }
  async function readJson(req) {
    if (!req.headers['content-type']?.startsWith('application/json')) throw new HttpError(415, 'Потрібен Content-Type application/json.');
    let body = '';
    for await (const part of req) { body += part;if (Buffer.byteLength(body) > 16_384) throw new HttpError(413, 'Запит завеликий.'); }
    try { const value = JSON.parse(body);if (!value || Array.isArray(value) || typeof value !== 'object') throw new Error();return value; }
    catch { throw new HttpError(400, 'Некоректний JSON.'); }
  }
  function requestHeaders(res) {
    res.setHeader('content-security-policy', "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'; object-src 'none'");
    res.setHeader('x-content-type-options', 'nosniff');res.setHeader('x-frame-options', 'DENY');
    res.setHeader('referrer-policy', 'no-referrer');res.setHeader('cache-control', 'no-store');
    res.setHeader('permissions-policy', 'camera=(), microphone=(), geolocation=()');
    if (config.production) res.setHeader('strict-transport-security', 'max-age=31536000; includeSubDomains');
  }

  const server = http.createServer(async (req, res) => {
    requestHeaders(res);
    const ctx = { req, res, ip: (req.socket.remoteAddress ?? 'unknown').replace(/^::ffff:/, '') };
    try {
      if ((req.url?.length ?? 0) > 12_000) throw new HttpError(414, 'URL завеликий.');
      const url = new URL(req.url, config.appUrl), path = url.pathname, method = req.method;
      if (path === '/health') return json(ctx, 200, { status: 'ok' });
      if (method === 'GET' && ['/app.js', '/styles.css', '/favicon.svg'].includes(path)) {
        const type = path.endsWith('.js') ? 'text/javascript' : path.endsWith('.css') ? 'text/css' : 'image/svg+xml';
        res.writeHead(200, { 'content-type': type + '; charset=utf-8' });return res.end(readFileSync(resolve(PROJECT_ROOT, 'public', path.slice(1))));
      }
      ctx.session = getSession(req, res);
      if (method === 'POST' && path.startsWith('/api/')) {
        if ((req.headers.origin && req.headers.origin !== config.appUrl) || !safeEqual(req.headers['x-csrf-token'], ctx.session.csrf)) throw new HttpError(403, 'Перевірка CSRF не пройшла. Оновіть сторінку.', 'csrf');
      }
      if (method === 'GET' && path === '/api/session') {
        const user = ctx.session.user_id ? db.get('SELECT * FROM users WHERE id=?', ctx.session.user_id) : null;
        if (user?.blocked) { rotateSession(ctx, null); }
        return json(ctx, 200, { csrf: ctx.session.csrf, user: user && !user.blocked && user.activated_at ? publicUser(user) : null, demo: config.demo, mailTransport: config.mailTransport, providers: Object.values(oidc.providers()).map(p => ({ id: p.name, label: p.label })), googleConfigured: Boolean(config.googleClientId && config.googleClientSecret), policy: { minLength: 8, lockThreshold: config.lockThreshold, lockMinutes: config.lockDurationMs / 60_000 } });
      }
      if (method === 'GET' && path === '/api/captcha') {
        rateLimit('captcha:' + ctx.ip, 60, 60_000);return json(ctx, 200, captcha.create(ctx.session.id_hash));
      }
      const image = /^\/api\/captcha\/([A-Za-z0-9_-]+)\.png$/.exec(path);
      if (method === 'GET' && image) { const png = captcha.image(image[1], ctx.session.id_hash);res.writeHead(200, { 'content-type': 'image/png' });return res.end(png); }
      if (method === 'POST' && path === '/api/auth/register') {
        rateLimit('register:' + ctx.ip, 20, 15 * 60_000);
        const body = await readJson(req), email = normalizeEmail(body.email), name = typeof body.name === 'string' ? body.name.trim() : '';
        validatePassword(body.password);
        if (!email || name.length < 2 || name.length > 80) throw new HttpError(400, 'Вкажіть коректний email та ім’я від 2 до 80 символів.');
        if (!captcha.consume(body.captchaId, body.captchaAnswer, ctx.session.id_hash)) throw new HttpError(400, 'Неправильний код CAPTCHA.', 'captcha_invalid');
        const passwordHash = await hashPassword(body.password);
        if (!db.get('SELECT id FROM users WHERE email=?', email)) {
          const id = randomUUID();
          try { db.run('INSERT INTO users(id,email,name,password_hash,created_at) VALUES(?,?,?,?,?)', id, email, name, passwordHash, now()); }
          catch (error) { if (!String(error.message).includes('UNIQUE')) throw error; }
          const user = db.get('SELECT * FROM users WHERE id=?', id);
          if (user) { await issueEmailToken(user, 'activate');audit(ctx, 'register', 'success', email, id); }
        }
        return json(ctx, 202, { message: 'Якщо адресу можна зареєструвати, лист з активацією надіслано. Перевірте пошту.' });
      }
      if (method === 'POST' && path === '/api/auth/activate') {
        rateLimit('activate:' + ctx.ip, 30, 60_000);const body = await readJson(req);
        const user = db.transaction(() => {
          const token = db.get('SELECT * FROM email_tokens WHERE hash=? AND purpose=?', sha256(typeof body.token === 'string' ? body.token : ''), 'activate');
          if (!token || token.consumed_at || token.expires_at <= now()) throw new HttpError(400, 'Посилання активації застаріло або вже використане.', 'token_invalid');
          db.run('UPDATE email_tokens SET consumed_at=? WHERE hash=?', now(), token.hash);db.run('UPDATE users SET activated_at=? WHERE id=?', now(), token.user_id);
          return db.get('SELECT * FROM users WHERE id=?', token.user_id);
        });
        audit(ctx, 'activation', 'success', user.email, user.id);return json(ctx, 200, { message: 'Обліковий запис активовано. Тепер можна увійти.' });
      }
      if (method === 'POST' && ['/api/auth/forgot', '/api/auth/resend-activation'].includes(path)) {
        rateLimit('email:' + ctx.ip, 15, 15 * 60_000);const body = await readJson(req), email = normalizeEmail(body.email);
        if (!email) throw new HttpError(400, 'Введіть коректний email.');
        rateLimit('email-account:' + hmac(config.secretKey, email), 5, 15 * 60_000);
        const user = db.get('SELECT * FROM users WHERE email=?', email), purpose = path.endsWith('forgot') ? 'reset' : 'activate';
        if (user && !user.blocked && (purpose === 'reset' ? Boolean(user.password_hash) : !user.activated_at)) await issueEmailToken(user, purpose);
        audit(ctx, purpose + '_request', 'accepted', email);
        return json(ctx, 202, { message: 'Якщо обліковий запис підходить для цієї операції, лист надіслано.' });
      }
      if (method === 'POST' && path === '/api/auth/reset') {
        rateLimit('reset:' + ctx.ip, 15, 15 * 60_000);const body = await readJson(req);validatePassword(body.password);
        const hash = sha256(typeof body.token === 'string' ? body.token : '');
        const token = db.get('SELECT * FROM email_tokens WHERE hash=? AND purpose=? AND consumed_at IS NULL AND expires_at>?', hash, 'reset', now());
        if (!token) throw new HttpError(400, 'Посилання відновлення застаріло або вже використане.', 'token_invalid');
        const passwordHash = await hashPassword(body.password);
        const user = db.transaction(() => {
          const fresh = db.get('SELECT * FROM email_tokens WHERE hash=? AND consumed_at IS NULL AND expires_at>?', hash, now());
          const target = fresh ? db.get('SELECT * FROM users WHERE id=?', fresh.user_id) : null;
          if (!fresh || !target || target.blocked) throw new HttpError(400, 'Посилання недійсне.', 'token_invalid');
          db.run('UPDATE users SET password_hash=?,failed_attempts=0,locked_until=0,last_failed_at=0 WHERE id=?', passwordHash, target.id);
          db.run('UPDATE email_tokens SET consumed_at=? WHERE user_id=? AND purpose=? AND consumed_at IS NULL', now(), target.id, 'reset');
          db.run('DELETE FROM sessions WHERE user_id=?', target.id);db.run('DELETE FROM otp_challenges WHERE user_id=?', target.id);return target;
        });
        audit(ctx, 'password_reset', 'success', user.email, user.id);return json(ctx, 200, { message: 'Пароль змінено. Усі попередні сесії завершено. Увійдіть із новим паролем.' });
      }
      if (method === 'POST' && path === '/api/auth/login') {
        rateLimit('login-ip:' + ctx.ip, 80, 15 * 60_000);
        const body = await readJson(req), email = normalizeEmail(body.email);
        if (!email || typeof body.password !== 'string' || body.password.length > 512) throw new HttpError(400, 'Введіть email та пароль.');
        let user = db.get('SELECT * FROM users WHERE email=?', email);
        const unknownKey = 'failed:' + hmac(config.secretKey, email), unknown = db.get('SELECT * FROM rate_limits WHERE key=?', unknownKey);
        if ((user && (user.blocked || user.locked_until > now())) || (!user && unknown && unknown.count >= config.lockThreshold && unknown.expires_at > now())) {
          audit(ctx, 'login', 'blocked', email, user?.id ?? null, 'Account or temporary lock');
          throw new HttpError(423, 'Вхід тимчасово недоступний. Після ліміту спроб зачекайте 15 хвилин або зверніться до адміністратора.', 'account_locked');
        }
        const verifiedHash = user?.password_hash ?? dummyHash;
        const validPassword = await verifyPassword(body.password, verifiedHash);
        user = user ? db.get('SELECT * FROM users WHERE id=?', user.id) : null;
        const valid = validPassword && user?.password_hash === verifiedHash;
        if (!valid || !user?.password_hash) {
          let count;
          if (user) {
            count = user.last_failed_at + config.lockDurationMs > now() ? user.failed_attempts + 1 : 1;
            db.run('UPDATE users SET failed_attempts=?,last_failed_at=?,locked_until=? WHERE id=?', count, now(), count >= config.lockThreshold ? now() + config.lockDurationMs : 0, user.id);
          } else {
            count = unknown && unknown.expires_at > now() ? unknown.count + 1 : 1;
            db.run('INSERT INTO rate_limits(key,count,expires_at) VALUES(?,?,?) ON CONFLICT(key) DO UPDATE SET count=excluded.count,expires_at=excluded.expires_at', unknownKey, count, now() + config.lockDurationMs);
          }
          audit(ctx, 'login', 'failure', email, user?.id ?? null, 'Invalid credentials; attempt ' + count);
          if (count >= config.lockThreshold) throw new HttpError(423, 'Ліміт невдалих спроб вичерпано. Вхід заблоковано на 15 хвилин.', 'account_locked');
          throw new HttpError(401, 'Неправильний email або пароль.', 'invalid_credentials');
        }
        if (user.blocked || user.locked_until > now()) throw new HttpError(423, 'Обліковий запис недоступний.', 'account_locked');
        if (!user.activated_at) { audit(ctx, 'login', 'activation_required', email, user.id);throw new HttpError(403, 'Спочатку активуйте обліковий запис через email.', 'activation_required'); }
        db.run('UPDATE users SET failed_attempts=0,locked_until=0,last_failed_at=0 WHERE id=?', user.id);
        if (user.mfa_enabled) {
          if (ctx.session.user_id) rotateSession(ctx, null);
          const challenge = await issueOtp(ctx, user, 'login');audit(ctx, 'login', 'mfa_required', email, user.id);
          return json(ctx, 200, { mfaRequired: true, ...challenge, csrf:ctx.session.csrf, message: 'Введіть код із листа для завершення входу.' });
        }
        rotateSession(ctx, user.id);audit(ctx, 'login', 'success', email, user.id);return json(ctx, 200, { user: publicUser(user), csrf: ctx.session.csrf });
      }
      if (method === 'POST' && path === '/api/auth/mfa/verify') {
        rateLimit('mfa-ip:' + ctx.ip, 40, 60_000);const body = await readJson(req);
        const challenge = consumeOtp(ctx, body.challengeId, body.code, 'login'), user = db.get('SELECT * FROM users WHERE id=?', challenge.user_id);
        if (!user || user.blocked || !user.activated_at || user.locked_until > now() || !user.mfa_enabled) throw new HttpError(401, 'Обліковий запис недоступний.');
        rotateSession(ctx, user.id);audit(ctx, 'login', 'success', user.email, user.id, 'Email OTP verified');return json(ctx, 200, { user: publicUser(user), csrf: ctx.session.csrf });
      }
      if (method === 'POST' && path === '/api/auth/logout') {
        audit(ctx, 'logout', 'success', '', ctx.session.user_id);
        db.run('DELETE FROM otp_challenges WHERE session_hash=?', ctx.session.id_hash);rotateSession(ctx, null);return json(ctx, 200, { message: 'Вихід виконано.', csrf: ctx.session.csrf });
      }
      if (method === 'GET' && path === '/api/profile') return json(ctx, 200, { user: publicUser(requireUser(ctx)) });
      if (method === 'POST' && path === '/api/profile/name') {
        const user = requireUser(ctx), body = await readJson(req), name = typeof body.name === 'string' ? body.name.trim() : '';
        if (name.length < 2 || name.length > 80) throw new HttpError(400, 'Ім’я має містити від 2 до 80 символів.');
        db.run('UPDATE users SET name=? WHERE id=?', name, user.id);audit(ctx, 'profile_update', 'success', user.email, user.id);return json(ctx, 200, { message: 'Профіль збережено.' });
      }
      if (method === 'POST' && path === '/api/profile/mfa/start') {
        const user = requireUser(ctx), purpose = user.mfa_enabled ? 'disable' : 'enable';
        const challenge = await issueOtp(ctx, user, purpose);audit(ctx, 'mfa_' + purpose, 'requested', user.email, user.id);return json(ctx, 200, { ...challenge, purpose, message: 'Підтвердьте зміну кодом із листа.' });
      }
      if (method === 'POST' && path === '/api/profile/mfa/confirm') {
        const user = requireUser(ctx), body = await readJson(req), purpose = user.mfa_enabled ? 'disable' : 'enable';
        consumeOtp(ctx, body.challengeId, body.code, purpose);
        db.transaction(() => {
          db.run('UPDATE users SET mfa_enabled=? WHERE id=?', purpose === 'enable' ? 1 : 0, user.id);
          db.run('DELETE FROM sessions WHERE user_id=?', user.id);rotateSession(ctx, user.id);
        });
        audit(ctx, 'mfa_' + purpose, 'success', user.email, user.id);return json(ctx, 200, { message: purpose === 'enable' ? 'Двофакторну автентифікацію увімкнено.' : 'Двофакторну автентифікацію вимкнено.', csrf: ctx.session.csrf });
      }
      if (method === 'GET' && path === '/api/admin/users') {
        requireUser(ctx, 'admin');const users = db.all('SELECT * FROM users ORDER BY created_at DESC');
        return json(ctx, 200, { users: users.map(publicUser), stats: { total: users.length, active: users.filter(u => u.activated_at && !u.blocked).length, blocked: users.filter(u => u.blocked || u.locked_until > now()).length, mfa: users.filter(u => u.mfa_enabled).length } });
      }
      const moderation = /^\/api\/admin\/users\/([a-f0-9-]{36})\/(block|unblock)$/.exec(path);
      if (method === 'POST' && moderation) {
        const admin = requireUser(ctx, 'admin'), [, id, action] = moderation, target = db.get('SELECT * FROM users WHERE id=?', id);
        if (!target) throw new HttpError(404, 'Користувача не знайдено.');
        if (id === admin.id) throw new HttpError(400, 'Не можна змінювати блокування власного облікового запису.');
        if (action === 'block' && target.role === 'admin' && db.get("SELECT COUNT(*) n FROM users WHERE role='admin' AND blocked=0").n <= 1) throw new HttpError(400, 'Не можна заблокувати останнього адміністратора.');
        db.transaction(() => {
          db.run('UPDATE users SET blocked=?,failed_attempts=0,locked_until=0,last_failed_at=0 WHERE id=?', action === 'block' ? 1 : 0, id);
          db.run('DELETE FROM sessions WHERE user_id=?', id);db.run('DELETE FROM otp_challenges WHERE user_id=?', id);
        });
        audit(ctx, 'admin_' + action, 'success', target.email, admin.id, 'Target user ' + id);return json(ctx, 200, { message: action === 'block' ? 'Обліковий запис заблоковано, сесії завершено.' : 'Обліковий запис розблоковано, лічильник спроб скинуто.' });
      }
      if (method === 'GET' && path === '/api/admin/audit') {
        requireUser(ctx, 'admin');const search = (url.searchParams.get('search') ?? '').slice(0,100), result = (url.searchParams.get('result') ?? '').slice(0,30);
        const logs = db.all('SELECT * FROM audit_log WHERE (?=\'\' OR instr(lower(email),lower(?))>0) AND (?=\'\' OR result=?) ORDER BY id DESC LIMIT 200', search, search, result, result);
        return json(ctx, 200, { logs });
      }
      if (method === 'GET' && path === '/api/admin/mail') {
        requireUser(ctx, 'admin');if (!config.demo || config.mailTransport !== 'outbox') throw new HttpError(404, 'Перегляд локальної пошти вимкнено.');
        return json(ctx, 200, { messages: db.all('SELECT * FROM mail_messages ORDER BY created_at DESC,rowid DESC LIMIT 100') });
      }
      const start = /^\/auth\/oidc\/start\/(google|demo)$/.exec(path);
      if (method === 'GET' && start) {
        rateLimit('oidc:' + ctx.ip, 30, 15 * 60_000);
        const provider = oidc.get(start[1]), state = randomToken(), nonce = randomToken(), verifier = randomToken(48);
        db.run('DELETE FROM oidc_requests WHERE session_hash=? OR expires_at<=?', ctx.session.id_hash, now());
        db.run('INSERT INTO oidc_requests(state_hash,session_hash,provider,nonce_hash,verifier,expires_at) VALUES(?,?,?,?,?,?)', sha256(state), ctx.session.id_hash, provider.name, sha256(nonce), encryptSecret(verifier, config.secretKey), now() + 300_000);
        const target = await oidc.authorizationUrl(provider, state, nonce, verifier);res.writeHead(302, { location: target });return res.end();
      }
      const callback = /^\/auth\/oidc\/callback\/(google|demo)$/.exec(path);
      if (method === 'GET' && callback) {
        try {
          const provider = oidc.get(callback[1]), stateHash = sha256(url.searchParams.get('state') ?? '');
          const request = db.get('SELECT * FROM oidc_requests WHERE state_hash=? AND session_hash=? AND provider=? AND expires_at>?', stateHash, ctx.session.id_hash, provider.name, now());
          if (!request) throw new HttpError(400, 'Неправильний або використаний state OIDC.');
          db.run('DELETE FROM oidc_requests WHERE state_hash=?', stateHash);
          const code = url.searchParams.get('code');if (!code || url.searchParams.has('error')) throw new HttpError(400, 'Вхід у провайдера скасовано.');
          const claims = await oidc.exchange(provider, code, decryptSecret(request.verifier, config.secretKey), request.nonce_hash, now());
          const email = normalizeEmail(claims.email);if (!email) throw new HttpError(400, 'Провайдер не підтвердив email.');
          const identity = db.get('SELECT user_id FROM identities WHERE provider=? AND subject=?', provider.issuer, claims.sub);
          let user;
          if (identity) user = db.get('SELECT * FROM users WHERE id=?', identity.user_id);
          else {
            if (db.get('SELECT id FROM users WHERE email=?', email)) throw new HttpError(409, 'Цей email уже зареєстрований. Увійдіть існуючим способом; автоматичне злиття за email заборонено.');
            const id = randomUUID(), name = String(claims.name ?? 'Користувач OIDC').slice(0,80);
            db.transaction(() => {
              db.run('INSERT INTO users(id,email,name,activated_at,created_at) VALUES(?,?,?,?,?)', id, email, name, now(), now());
              db.run('INSERT INTO identities(provider,subject,user_id) VALUES(?,?,?)', provider.issuer, claims.sub, id);
            });user = db.get('SELECT * FROM users WHERE id=?', id);
          }
          if (!user || user.blocked || !user.activated_at || user.locked_until > now()) throw new HttpError(423, 'Обліковий запис недоступний.');
          let location = '/profile';
          if (user.mfa_enabled) {
            if (ctx.session.user_id) rotateSession(ctx, null);
            const challenge = await issueOtp(ctx, user, 'login');location = '/mfa?challenge=' + challenge.challengeId;audit(ctx, 'oidc_login', 'mfa_required', user.email, user.id);
          } else { rotateSession(ctx, user.id);audit(ctx, 'oidc_login', 'success', user.email, user.id, provider.name); }
          res.writeHead(302, { location });return res.end();
        } catch (error) {
          audit(ctx, 'oidc_login', 'failure', '', null, error instanceof HttpError ? error.message : 'Provider unavailable');
          res.writeHead(302, { location: '/login?error=' + encodeURIComponent(error instanceof HttpError ? error.message : 'OIDC-провайдер недоступний.') });return res.end();
        }
      }
      if (path.startsWith('/api/')) throw new HttpError(404, 'API маршрут не знайдено.');
      const pages = ['/', '/login', '/register', '/forgot', '/activate', '/reset', '/mfa', '/profile', '/admin/users', '/admin/audit', '/admin/mail'];
      if (method === 'GET' && pages.includes(path)) { res.writeHead(200, { 'content-type': 'text/html; charset=utf-8' });return res.end(readFileSync(resolve(PROJECT_ROOT, 'public/index.html'))); }
      throw new HttpError(404, 'Сторінку не знайдено.');
    } catch (error) {
      if (res.headersSent) { res.end();return; }
      if (!(error instanceof HttpError)) console.error('[server]', error.name, 'request failed');
      return json(ctx, error instanceof HttpError ? error.status : 500, { error: error instanceof HttpError ? error.message : 'Внутрішня помилка сервера.', code: error.code ?? 'server_error', ...(error.details ? { details: error.details } : {}) });
    }
  });
  server.requestTimeout = 15_000;server.headersTimeout = 10_000;
  return { server, db, config, mailer, captcha, async listen(port = config.port) { await new Promise((resolve, reject) => { server.once('error', reject);server.listen(port, config.host, resolve); });return server.address(); }, async close() { await new Promise(resolve => server.close(resolve));await mailer.stop?.();db.close(); } };
}
