import http from 'node:http';
import { generateKeyPairSync, sign } from 'node:crypto';
import { randomToken, hashPassword, verifyPassword, safeEqual, escapeHtml } from './security.mjs';
import { pkceChallenge } from './oidc.mjs';

export async function startDemoProvider(config) {
  const { publicKey, privateKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
  const kid = randomToken(12), jwk = { ...publicKey.export({ format: 'jwk' }), kid, alg: 'RS256', use: 'sig' };
  const transactions = new Map(), codes = new Map(), ipFailures = new Map();
  const passwordHash = await hashPassword('Provider2026!StudyOnly');
  let issuer = `http://localhost:${config.demoOidcPort}`;
  const redirectUri = config.appUrl + '/auth/oidc/callback/demo';
  const clientId = 'lab6-local-client', secret = config.demoOidcSecret ?? 'local-demo-client-secret';
  const headers = { 'cache-control': 'no-store', 'referrer-policy': 'same-origin', 'x-content-type-options': 'nosniff', 'content-security-policy': `default-src 'none'; style-src 'unsafe-inline'; form-action 'self' ${config.appUrl}; frame-ancestors 'none'; base-uri 'none'` };
  const sendJson = (res, status, value) => { res.writeHead(status, { ...headers, 'content-type': 'application/json' });res.end(JSON.stringify(value)); };
  const page = (id, error = '') => `<!doctype html><html lang="uk"><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>Тестовий OpenID Connect провайдер</title><style>body{margin:0;background:#f2f5fb;color:#14233e;font:16px system-ui;display:grid;place-items:center;min-height:100vh}.box{background:white;border:1px solid #dce3ed;border-radius:20px;padding:38px;max-width:440px;box-shadow:0 18px 60px #173b7014}h1{font-size:26px;margin:12px 0}label{display:block;margin:18px 0 6px}input{box-sizing:border-box;width:100%;padding:12px;border:1px solid #c5d1e3;border-radius:9px;font:inherit}button{width:100%;margin-top:24px;background:#345de3;color:white;border:0;border-radius:9px;padding:14px;font:600 16px system-ui}.tag{color:#345de3;font-weight:700}small,p{color:#61718c;line-height:1.6}.error{color:#b4233b}</style><main class="box"><div class="tag">OIDC · LOCAL DEMO</div><h1>Підтвердьте свою особу</h1><p>Окремий навчальний провайдер. Реальний Authorization Code flow із PKCE та підписаним ID token. Це не сервіс Google.</p>${error ? '<p class="error">' + escapeHtml(error) + '</p>' : ''}<form method="post" action="/authorize"><input type="hidden" name="transaction" value="${escapeHtml(id)}"><label for="email">Email провайдера</label><input id="email" name="email" type="email" value="oidc.user@provider.test" required><label for="password">Пароль провайдера</label><input id="password" name="password" type="password" required autocomplete="current-password"><button type="submit">Підтвердити та повернутися</button></form><p><small>Для локальної демонстрації: Provider2026!StudyOnly</small></p></main></html>`;
  const readForm = async req => {
    let body = '';
    for await (const part of req) { body += part;if (body.length > 10_000) throw new Error('Body too large'); }
    return new URLSearchParams(body);
  };
  const server = http.createServer(async (req, res) => {
    try {
      const url = new URL(req.url, issuer);
      for (const map of [transactions, codes]) for (const [id, value] of map) if (value.expires < Date.now()) map.delete(id);
      if (req.method === 'GET' && url.pathname === '/.well-known/openid-configuration') return sendJson(res, 200, { issuer, authorization_endpoint: issuer + '/authorize', token_endpoint: issuer + '/token', jwks_uri: issuer + '/jwks', response_types_supported: ['code'], subject_types_supported: ['public'], id_token_signing_alg_values_supported: ['RS256'], scopes_supported: ['openid', 'email', 'profile'], token_endpoint_auth_methods_supported: ['client_secret_post'], code_challenge_methods_supported: ['S256'] });
      if (req.method === 'GET' && url.pathname === '/jwks') return sendJson(res, 200, { keys: [jwk] });
      if (req.method === 'GET' && url.pathname === '/authorize') {
        const q = url.searchParams;
        if (q.get('client_id') !== clientId || q.get('redirect_uri') !== redirectUri || q.get('response_type') !== 'code' || q.get('code_challenge_method') !== 'S256' || !/^[A-Za-z0-9_-]{43}$/.test(q.get('code_challenge') ?? '') || (q.get('state')?.length ?? 0) < 22 || (q.get('nonce')?.length ?? 0) < 22 || !q.get('scope')?.split(' ').includes('openid')) return sendJson(res, 400, { error: 'invalid_request' });
        const id = randomToken(), cookie = randomToken();
        transactions.set(id, { cookie, state: q.get('state'), nonce: q.get('nonce'), challenge: q.get('code_challenge'), expires: Date.now() + 300_000 });
        res.writeHead(200, { ...headers, 'content-type': 'text/html; charset=utf-8', 'set-cookie': `lab6_oidc_tx=${cookie}; HttpOnly; SameSite=Lax; Path=/authorize; Max-Age=300` });return res.end(page(id));
      }
      if (req.method === 'POST' && url.pathname === '/authorize') {
        if (req.headers.origin && req.headers.origin !== issuer) return sendJson(res, 403, { error: 'invalid_origin' });
        const form = await readForm(req), id = form.get('transaction'), tx = transactions.get(id);
        const cookie = /(?:^|;\s*)lab6_oidc_tx=([^;]+)/.exec(req.headers.cookie ?? '')?.[1];
        if (!tx || !safeEqual(cookie, tx.cookie)) return sendJson(res, 400, { error: 'invalid_transaction' });
        const ip = req.socket.remoteAddress, limit = ipFailures.get(ip) ?? { count: 0, until: Date.now() + 60_000 };
        if (limit.until <= Date.now()) limit.count = 0;
        if (++limit.count > 10) return sendJson(res, 429, { error: 'rate_limited' });
        ipFailures.set(ip, limit);
        if (form.get('email') !== 'oidc.user@provider.test' || !await verifyPassword(form.get('password'), passwordHash)) {
          res.writeHead(401, { ...headers, 'content-type': 'text/html; charset=utf-8' });return res.end(page(id, 'Неправильні облікові дані провайдера.'));
        }
        transactions.delete(id);const code = randomToken();codes.set(code, { ...tx, expires: Date.now() + 60_000 });
        const target = new URL(redirectUri);target.searchParams.set('code', code);target.searchParams.set('state', tx.state);
        res.writeHead(302, { ...headers, location: target.toString(), 'set-cookie': 'lab6_oidc_tx=; HttpOnly; SameSite=Lax; Path=/authorize; Max-Age=0' });return res.end();
      }
      if (req.method === 'POST' && url.pathname === '/token') {
        const form = await readForm(req);
        if (form.get('grant_type') !== 'authorization_code' || form.get('client_id') !== clientId || !safeEqual(form.get('client_secret'), secret) || form.get('redirect_uri') !== redirectUri) return sendJson(res, 400, { error: 'invalid_client' });
        const code = form.get('code'), tx = codes.get(code);codes.delete(code);
        if (!tx || !safeEqual(pkceChallenge(form.get('code_verifier') ?? ''), tx.challenge)) return sendJson(res, 400, { error: 'invalid_grant' });
        const seconds = Math.floor(Date.now() / 1000);
        const head = Buffer.from(JSON.stringify({ alg: 'RS256', typ: 'JWT', kid })).toString('base64url');
        const body = Buffer.from(JSON.stringify({ iss: issuer, aud: clientId, sub: 'demo-oidc-user-001', email: 'oidc.user@provider.test', email_verified: true, name: 'Користувач OIDC', nonce: tx.nonce, iat: seconds, exp: seconds + 300 })).toString('base64url');
        const signature = sign('RSA-SHA256', Buffer.from(head + '.' + body), privateKey).toString('base64url');
        return sendJson(res, 200, { access_token: randomToken(), token_type: 'Bearer', expires_in: 300, id_token: head + '.' + body + '.' + signature });
      }
      sendJson(res, 404, { error: 'not_found' });
    } catch { sendJson(res, 400, { error: 'invalid_request' }); }
  });
  await new Promise((resolve, reject) => { server.once('error', reject);server.listen(config.demoOidcPort, '127.0.0.1', resolve); });
  config.demoOidcPort = server.address().port;issuer = `http://localhost:${config.demoOidcPort}`;
  return { server, issuer, close: () => new Promise(resolve => server.close(resolve)) };
}
