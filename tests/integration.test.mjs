import test from 'node:test';
import assert from 'node:assert/strict';
import { fixture, Client, register, activeUser, admin, oidcFlow } from './helpers.mjs';
import { sha256 } from '../src/security.mjs';

test('CSRF, foreign Origin, anonymous access and security headers', async t => {
  const f=await fixture();t.after(()=>f.close());const c=await new Client(f.base).init();
  assert.equal((await c.post('/api/auth/logout',{}, {'x-csrf-token':'wrong'})).status,403);
  assert.equal((await c.post('/api/auth/logout',{}, {origin:'https://attacker.test'})).status,403);
  assert.equal((await c.get('/api/profile')).status,401);
  assert.equal((await c.get('/api/admin/users')).status,401);
  const page=await c.get('/login');assert.match(page.headers.get('content-security-policy'),/frame-ancestors 'none'/);
  assert.equal(page.headers.get('x-content-type-options'),'nosniff');
});
test('Registration enforces password/CAPTCHA, ignores role escalation and hashes tokens', async t => {
  const f=await fixture();t.after(()=>f.close());const c=await new Client(f.base).init();
  let challenge=(await c.get('/api/captcha')).data;
  const data={name:'Студент',email:'student@example.test',password:'weak',captchaId:challenge.id,captchaAnswer:f.captchaAnswer,role:'admin'};
  assert.equal((await c.post('/api/auth/register',data)).data.code,'password_policy');
  data.password='Student2026!Secure';data.captchaAnswer='WRONG';
  assert.equal((await c.post('/api/auth/register',data)).data.code,'captcha_invalid');
  assert.equal((await c.post('/api/auth/register',{...data,captchaAnswer:f.captchaAnswer})).data.code,'captcha_invalid');
  challenge=(await c.get('/api/captcha')).data;
  assert.equal((await c.post('/api/auth/register',{...data,captchaId:challenge.id,captchaAnswer:f.captchaAnswer})).status,202);
  const user=f.app.db.get('SELECT * FROM users WHERE email=?',data.email);
  assert.equal(user.role,'user');assert.equal(user.activated_at,null);assert.notEqual(user.password_hash,data.password);
  const token=f.token(data.email,'activate');assert.ok(f.app.db.get('SELECT * FROM email_tokens WHERE hash=?',sha256(token)));
  assert.equal(f.app.db.get('SELECT * FROM email_tokens WHERE hash=?',token),undefined);
  assert.equal((await c.post('/api/auth/login',{email:data.email,password:data.password})).data.code,'activation_required');
});
test('CAPTCHA is bound to its session and expires', async t => {
  const f=await fixture();t.after(()=>f.close());const a=await new Client(f.base).init(),b=await new Client(f.base).init();
  const challenge=(await a.get('/api/captcha')).data,answer=f.captchaAnswer;
  assert.equal((await b.get(challenge.imageUrl)).status,404);
  assert.equal((await b.post('/api/auth/register',{email:'b@example.test',name:'Other',password:'Student2026!Secure',captchaId:challenge.id,captchaAnswer:answer})).status,400);
  f.advance(301_000);assert.equal((await a.get(challenge.imageUrl)).status,404);
});
test('Activation tokens are one use and have a real expiry', async t => {
  const f=await fixture();t.after(()=>f.close());const c=await new Client(f.base).init();
  await register(f,c);const token=f.token('student@example.test','activate');
  assert.equal((await c.post('/api/auth/activate',{token})).status,200);
  assert.equal((await c.post('/api/auth/activate',{token})).status,400);
  await register(f,c,'expired@example.test');const old=f.token('expired@example.test','activate');
  f.advance(31*60_000);await c.init();assert.equal((await c.post('/api/auth/activate',{token:old})).status,400);
});
test('Login rotates sessions, profile is private, RBAC is server enforced and logout revokes', async t => {
  const f=await fixture();t.after(()=>f.close());const c=await new Client(f.base).init();const original=c.cookies.get('lab6_session');
  const login=await activeUser(f,c);assert.equal(login.status,200);assert.notEqual(c.cookies.get('lab6_session'),original);
  assert.equal((await c.get('/api/profile')).data.user.email,'student@example.test');
  assert.equal((await c.get('/api/admin/users')).status,403);assert.equal((await c.get('/api/admin/audit')).status,403);assert.equal((await c.get('/api/admin/mail')).status,403);
  assert.equal('password_hash' in login.data.user,false);
  await c.post('/api/auth/logout',{});assert.equal((await c.get('/api/profile')).status,401);
});
test('Five failures lock the account; admin sees audit, unlocks and revokes blocked sessions', async t => {
  const f=await fixture();t.after(()=>f.close());const c=await new Client(f.base).init();await activeUser(f,c);await c.post('/api/auth/logout',{});
  for(let i=1;i<=5;i++)assert.equal((await c.post('/api/auth/login',{email:'student@example.test',password:'Wrong2026!Password'})).status,i===5?423:401);
  assert.equal((await c.post('/api/auth/login',{email:'student@example.test',password:'Student2026!Secure'})).status,423);
  const a=await admin(f),user=f.app.db.get('SELECT * FROM users WHERE email=?','student@example.test');
  const logs=(await a.get('/api/admin/audit?search=student&result=failure')).data.logs;
  assert.equal(logs.filter(x=>x.event==='login').length,5);assert.ok(logs.every(x=>x.ip==='127.0.0.1'));
  assert.equal((await a.post('/api/admin/users/'+user.id+'/unblock',{})).status,200);
  assert.equal((await c.post('/api/auth/login',{email:user.email,password:'Student2026!Secure'})).status,200);
  assert.equal((await a.post('/api/admin/users/'+user.id+'/block',{})).status,200);assert.equal((await c.get('/api/profile')).status,401);
  assert.equal((await a.post('/api/admin/users/'+user.id+'/unblock',{})).status,200);
});
test('Email 2FA enables/disables with proof, gates login and rejects OTP reuse', async t => {
  const f=await fixture();t.after(()=>f.close());const c=await new Client(f.base).init();await activeUser(f,c);
  const enable=(await c.post('/api/profile/mfa/start',{})).data;
  assert.equal((await c.post('/api/profile/mfa/confirm',{challengeId:enable.challengeId,code:'xxxxxx'})).status,400);
  assert.equal((await c.post('/api/profile/mfa/confirm',{challengeId:enable.challengeId,code:f.otp('student@example.test')})).status,200);
  await c.post('/api/auth/logout',{});
  const login=(await c.post('/api/auth/login',{email:'student@example.test',password:'Student2026!Secure'})).data;
  assert.equal(login.mfaRequired,true);assert.equal((await c.get('/api/profile')).status,401);
  const code=f.otp('student@example.test');
  assert.equal((await c.post('/api/auth/mfa/verify',{challengeId:login.challengeId,code})).status,200);
  assert.equal((await c.post('/api/auth/mfa/verify',{challengeId:login.challengeId,code})).status,400);
  const disable=(await c.post('/api/profile/mfa/start',{})).data;
  assert.equal((await c.post('/api/profile/mfa/confirm',{challengeId:disable.challengeId,code:f.otp('student@example.test')})).status,200);
  assert.equal((await c.get('/api/profile')).data.user.mfaEnabled,false);
});
test('OTP expires and five incorrect guesses consume a challenge', async t => {
  const f=await fixture();t.after(()=>f.close());const c=await new Client(f.base).init();await activeUser(f,c);
  const first=(await c.post('/api/profile/mfa/start',{})).data;f.advance(301_000);
  assert.equal((await c.post('/api/profile/mfa/confirm',{challengeId:first.challengeId,code:f.otp('student@example.test')})).status,400);
  const second=(await c.post('/api/profile/mfa/start',{})).data;
  for(let i=0;i<5;i++)assert.equal((await c.post('/api/profile/mfa/confirm',{challengeId:second.challengeId,code:'xxxxxx'})).status,400);
  assert.equal((await c.post('/api/profile/mfa/confirm',{challengeId:second.challengeId,code:f.otp('student@example.test')})).status,400);
});
test('Reset responses are generic, tokens single use, old sessions revoked and old password rejected', async t => {
  const f=await fixture();t.after(()=>f.close());const c=await new Client(f.base).init();await activeUser(f,c);
  const outsider=await new Client(f.base).init();
  const known=await outsider.post('/api/auth/forgot',{email:'student@example.test'}),unknown=await outsider.post('/api/auth/forgot',{email:'missing@example.test'});
  assert.equal(known.status,unknown.status);assert.deepEqual(known.data,unknown.data);
  const token=f.token('student@example.test','reset');
  assert.equal((await outsider.post('/api/auth/reset',{token,password:'weak'})).status,400);
  assert.equal((await outsider.post('/api/auth/reset',{token,password:'New2026!SecurePass'})).status,200);
  assert.equal((await c.get('/api/profile')).status,401);
  assert.equal((await outsider.post('/api/auth/reset',{token,password:'Other2026!Secure'})).status,400);
  assert.equal((await outsider.post('/api/auth/login',{email:'student@example.test',password:'Student2026!Secure'})).status,401);
  assert.equal((await outsider.post('/api/auth/login',{email:'student@example.test',password:'New2026!SecurePass'})).status,200);
});
test('Expired reset token is rejected', async t => {
  const f=await fixture();t.after(()=>f.close());const c=await new Client(f.base).init();await activeUser(f,c);
  await c.post('/api/auth/forgot',{email:'student@example.test'});const token=f.token('student@example.test','reset');
  f.advance(16*60_000);assert.equal((await c.post('/api/auth/reset',{token,password:'New2026!SecurePass'})).status,400);
});
test('Full HTTP OpenID Connect flow validates PKCE/JWKS and rejects state replay', async t => {
  const f=await fixture({provider:true});t.after(()=>f.close());const c=await new Client(f.base).init();
  const flow=await oidcFlow(f,c);
  assert.equal(flow.result.headers.get('location'),'/profile');
  const user=(await c.get('/api/profile')).data.user;assert.equal(user.email,'oidc.user@provider.test');assert.equal(user.role,'user');assert.equal(user.hasPassword,false);
  const other=await new Client(f.base).init();const replay=await other.get(flow.callback);assert.match(replay.headers.get('location'),/^\/login\?error=/);
  assert.equal((await other.get('/api/profile')).status,401);
  const replayToken=await flow.provider.request('/token',{method:'POST',headers:{'content-type':'application/x-www-form-urlencoded'},body:new URLSearchParams({grant_type:'authorization_code',code:new URL(flow.callback).searchParams.get('code'),redirect_uri:f.base+'/auth/oidc/callback/demo',client_id:'lab6-local-client',client_secret:'local-demo-client-secret',code_verifier:'x'.repeat(43)}).toString()});
  assert.equal(replayToken.status,400);
});
test('OIDC never automatically links an existing account by email', async t => {
  const f=await fixture({provider:true});t.after(()=>f.close());const c=await new Client(f.base).init();await register(f,c,'oidc.user@provider.test');
  const flow=await oidcFlow(f,c);assert.match(flow.result.headers.get('location'),/^\/login\?error=/);
  assert.equal((await c.get('/api/profile')).status,401);assert.equal(f.app.db.get('SELECT COUNT(*) n FROM identities').n,0);
});
test('Starting another MFA login removes a previously authenticated session', async t => {
  const f=await fixture();t.after(()=>f.close());const c=await new Client(f.base).init();await activeUser(f,c);
  f.app.db.run('UPDATE users SET mfa_enabled=1 WHERE email=?','student@example.test');
  const a=await admin(f);
  const result=await a.post('/api/auth/login',{email:'student@example.test',password:'Student2026!Secure'});
  assert.equal(result.data.mfaRequired,true);assert.equal((await a.get('/api/profile')).status,401);
  assert.equal((await a.post('/api/auth/mfa/verify',{challengeId:result.data.challengeId,code:f.otp('student@example.test')})).status,200);
  assert.equal((await a.get('/api/profile')).data.user.role,'user');
});
test('Malformed token/CAPTCHA inputs are rejected without server errors', async t => {
  const f=await fixture();t.after(()=>f.close());const c=await new Client(f.base).init();
  assert.equal((await c.post('/api/auth/activate',{token:{toString:'bad'}})).status,400);
  assert.equal((await c.post('/api/auth/reset',{token:{toString:'bad'},password:'Strong2026!Password'})).status,400);
  assert.equal((await c.post('/api/auth/register',{name:'Test User',email:'typed@example.test',password:'Strong2026!Password',captchaId:{toString:'bad'},captchaAnswer:'ABCDEF'})).status,400);
});
test('Password reset preserves the enrolled second factor and idle sessions expire', async t => {
  const f=await fixture();t.after(()=>f.close());const c=await new Client(f.base).init();await activeUser(f,c);
  f.app.db.run('UPDATE users SET mfa_enabled=1 WHERE email=?','student@example.test');
  await c.post('/api/auth/forgot',{email:'student@example.test'});
  await c.post('/api/auth/reset',{token:f.token('student@example.test','reset'),password:'New2026!SecurePass'});
  await c.init();const login=await c.post('/api/auth/login',{email:'student@example.test',password:'New2026!SecurePass'});
  assert.equal(login.data.mfaRequired,true);
  await c.post('/api/auth/mfa/verify',{challengeId:login.data.challengeId,code:f.otp('student@example.test')});
  f.advance(31*60_000);assert.equal((await c.get('/api/profile')).status,401);
});
