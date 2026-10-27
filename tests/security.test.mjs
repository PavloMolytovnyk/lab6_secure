import test from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes, generateKeyPairSync, sign } from 'node:crypto';
import { passwordErrors, hashPassword, verifyPassword, randomToken, encryptSecret, decryptSecret, sha256 } from '../src/security.mjs';
import { renderCaptchaPng } from '../src/captcha.mjs';
import { verifyIdToken, pkceChallenge } from '../src/oidc.mjs';

test('Password policy rejects weak/common passwords and accepts Unicode letters', () => {
  for (const p of ['', 'weak', 'abcdefgh', 'Abcdefgh', 'Abcdefg1', 'Password1!']) assert.ok(passwordErrors(p).length);
  assert.deepEqual(passwordErrors('Пароль2026!Сильний'), []);
  assert.deepEqual(passwordErrors('Student2026!Secure'), []);
  assert.ok(passwordErrors('Aa1!'.repeat(40)).length);
});
test('scrypt salts are unique and comparison verifies the complete password', async () => {
  const a = await hashPassword('Student2026!Secure'), b = await hashPassword('Student2026!Secure');
  assert.notEqual(a,b);assert.match(a,/^scrypt\$32768\$8\$1\$/);
  assert.equal(await verifyPassword('Student2026!Secure',a),true);
  assert.equal(await verifyPassword('wrong',a),false);assert.equal(await verifyPassword('x','broken'),false);
});
test('Opaque tokens use 256 bits; AES-GCM detects altered encrypted secrets', () => {
  const token = randomToken();assert.equal(token.length,43);assert.notEqual(token,randomToken());
  const key = randomBytes(32), encrypted = encryptSecret('private verifier',key);
  assert.equal(decryptSecret(encrypted,key),'private verifier');
  const bytes = Buffer.from(encrypted,'base64url');bytes[20] ^= 1;
  assert.throws(() => decryptSecret(bytes.toString('base64url'),key));
});
test('CAPTCHA is a PNG raster and never embeds the clear answer as SVG text', () => {
  const png = renderCaptchaPng('AB2C3D');
  assert.deepEqual([...png.subarray(0,8)],[137,80,78,71,13,10,26,10]);
  assert.equal(png.includes(Buffer.from('AB2C3D')),false);
});
test('PKCE matches the RFC 7636 S256 reference vector', () => {
  assert.equal(pkceChallenge('dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk'),'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM');
});
test('OIDC validates RS256 signature, issuer, audience, time, verified email and nonce', () => {
  const {publicKey,privateKey} = generateKeyPairSync('rsa',{modulusLength:2048});
  const jwks = {keys:[{...publicKey.export({format:'jwk'}),kid:'test',use:'sig',alg:'RS256'}]};
  const provider={name:'demo',issuer:'http://localhost:3101',clientId:'lab6-local-client'};
  const seconds=Math.floor(Date.now()/1000), claims={iss:provider.issuer,aud:provider.clientId,sub:'id',email:'user@example.test',email_verified:true,nonce:'nonce',iat:seconds,exp:seconds+300};
  const make = (body,header={alg:'RS256',kid:'test'}) => {
    const data=Buffer.from(JSON.stringify(header)).toString('base64url')+'.'+Buffer.from(JSON.stringify(body)).toString('base64url');
    return data+'.'+sign('RSA-SHA256',Buffer.from(data),privateKey).toString('base64url');
  };
  assert.equal(verifyIdToken(make(claims),provider,sha256('nonce'),jwks).sub,'id');
  for(const patch of [{iss:'https://attacker.test'},{aud:'other'},{exp:seconds-1},{nonce:'other'},{email_verified:false},{iat:seconds+120},{azp:'other'}]) {
    assert.throws(()=>verifyIdToken(make({...claims,...patch}),provider,sha256('nonce'),jwks));
  }
  assert.throws(()=>verifyIdToken(make(claims,{alg:'none',kid:'test'}),provider,sha256('nonce'),jwks));
  const token=make(claims).split('.');token[1]=Buffer.from(JSON.stringify({...claims,sub:'attacker'})).toString('base64url');
  assert.throws(()=>verifyIdToken(token.join('.'),provider,sha256('nonce'),jwks));
});
