import { createPublicKey, verify, createHash } from 'node:crypto';
import { sha256, safeEqual, HttpError } from './security.mjs';

export const pkceChallenge = verifier => createHash('sha256').update(verifier).digest('base64url');

export function verifyIdToken(token, provider, nonceHash, jwks, now = Date.now()) {
  if (typeof token !== 'string' || token.length > 24_000) throw new HttpError(400, 'Некоректний ID token.');
  const parts = token.split('.');
  if (parts.length !== 3) throw new HttpError(400, 'Некоректний JWT.');
  let header, claims;
  try { header = JSON.parse(Buffer.from(parts[0], 'base64url'));claims = JSON.parse(Buffer.from(parts[1], 'base64url')); }
  catch { throw new HttpError(400, 'Некоректний JWT.'); }
  if (header.alg !== 'RS256' || typeof header.kid !== 'string' || header.crit) throw new HttpError(400, 'Неприпустимий алгоритм ID token.');
  const jwk = jwks.keys?.find(key => key.kid === header.kid && key.kty === 'RSA' && (!key.use || key.use === 'sig') && (!key.alg || key.alg === 'RS256'));
  if (!jwk) throw new HttpError(400, 'Ключ підпису провайдера не знайдено.');
  const key = createPublicKey({ key: jwk, format: 'jwk' });
  if (key.asymmetricKeyDetails?.modulusLength < 2048 || !verify('RSA-SHA256', Buffer.from(parts[0] + '.' + parts[1]), key, Buffer.from(parts[2], 'base64url'))) {
    throw new HttpError(400, 'Неправильний підпис ID token.');
  }
  const seconds = Math.floor(now / 1000), audiences = Array.isArray(claims.aud) ? claims.aud : [claims.aud];
  const issuers = provider.name === 'google' ? ['https://accounts.google.com', 'accounts.google.com'] : [provider.issuer];
  if (!issuers.includes(claims.iss) || !audiences.includes(provider.clientId) ||
      (audiences.length > 1 && claims.azp !== provider.clientId) || (claims.azp && claims.azp !== provider.clientId) ||
      !Number.isInteger(claims.exp) || claims.exp <= seconds || !Number.isInteger(claims.iat) || claims.iat > seconds + 60 ||
      (claims.nbf !== undefined && (!Number.isInteger(claims.nbf) || claims.nbf > seconds + 60)) ||
      typeof claims.sub !== 'string' || !claims.sub || claims.sub.length > 255 ||
      typeof claims.nonce !== 'string' || !safeEqual(sha256(claims.nonce), nonceHash) || claims.email_verified !== true) {
    throw new HttpError(400, 'Перевірка iss, aud, exp, nonce або email ID token не пройшла.');
  }
  return claims;
}

export function createOidcClient(config, fetcher = fetch) {
  const cache = new Map();
  const providers = () => ({
    ...(config.demo ? { demo: { name: 'demo', label: 'Тестовий OIDC', issuer: `http://localhost:${config.demoOidcPort}`, clientId: 'lab6-local-client', clientSecret: config.demoOidcSecret ?? 'local-demo-client-secret', redirectUri: config.appUrl + '/auth/oidc/callback/demo' } } : {}),
    ...(config.googleClientId && config.googleClientSecret ? { google: { name: 'google', label: 'Google', issuer: 'https://accounts.google.com', clientId: config.googleClientId, clientSecret: config.googleClientSecret, redirectUri: config.appUrl + '/auth/oidc/callback/google' } } : {}),
  });
  async function getJson(url, options = {}) {
    const response = await fetcher(url, { ...options, redirect: 'error', signal: AbortSignal.timeout(10_000) });
    if (!response.ok) throw new HttpError(502, 'OIDC-провайдер відхилив запит.');
    return response.json();
  }
  async function discovery(provider) {
    const old = cache.get(provider.issuer);
    if (old && old.until > Date.now()) return old.value;
    const value = await getJson(provider.issuer + '/.well-known/openid-configuration');
    if (value.issuer !== provider.issuer) throw new HttpError(502, 'Неправильний issuer провайдера.');
    for (const field of ['authorization_endpoint', 'token_endpoint', 'jwks_uri']) {
      const url = new URL(value[field]);
      if (provider.name === 'demo') {
        if (url.origin !== provider.issuer) throw new HttpError(502, 'Неприпустимий endpoint тестового провайдера.');
      } else if (url.protocol !== 'https:') throw new HttpError(502, 'OIDC потребує HTTPS.');
    }
    cache.set(provider.issuer, { value, until: Date.now() + 300_000 });return value;
  }
  return {
    providers,
    get(name) { const provider = providers()[name];if (!provider) throw new HttpError(404, 'OIDC-провайдер не налаштований.');return provider; },
    async authorizationUrl(provider, state, nonce, verifier) {
      const meta = await discovery(provider), url = new URL(meta.authorization_endpoint);
      for (const [key, value] of Object.entries({ response_type: 'code', client_id: provider.clientId, redirect_uri: provider.redirectUri, scope: 'openid email profile', state, nonce, code_challenge: pkceChallenge(verifier), code_challenge_method: 'S256' })) url.searchParams.set(key, value);
      return url.toString();
    },
    async exchange(provider, code, verifier, nonceHash, now) {
      const meta = await discovery(provider);
      const tokens = await getJson(meta.token_endpoint, { method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded' }, body: new URLSearchParams({ grant_type: 'authorization_code', code, redirect_uri: provider.redirectUri, client_id: provider.clientId, client_secret: provider.clientSecret, code_verifier: verifier }).toString() });
      const jwks = await getJson(meta.jwks_uri);
      return verifyIdToken(tokens.id_token, provider, nonceHash, jwks, now);
    },
  };
}
