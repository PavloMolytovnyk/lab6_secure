import test from 'node:test';
import assert from 'node:assert/strict';
import tls from 'node:tls';
import {readFileSync} from 'node:fs';
import {spawn} from 'node:child_process';
import {fileURLToPath} from 'node:url';
import {fixture} from './helpers.mjs';
import {createMailer} from '../src/mailer.mjs';
import {decryptSecret} from '../src/security.mjs';

test('SMTP client verifies a trusted TLS certificate and delivers UTF-8 MIME with AUTH',async t=>{
  const ca=fileURLToPath(new URL('./fixtures/localhost-test-ca.pem',import.meta.url));
  const key=readFileSync(new URL('./fixtures/localhost-test-key.pem',import.meta.url));
  let delivered='',authorized=false;
  const server=tls.createServer({key,cert:readFileSync(ca)},socket=>{
    let buffer='',dataMode=false;
    socket.write('220 localhost SMTP test\r\n');
    socket.on('data',data=>{
      buffer+=data.toString();let n;
      while((n=buffer.indexOf('\r\n'))>=0){
        const line=buffer.slice(0,n);buffer=buffer.slice(n+2);
        if(dataMode){if(line==='.') {dataMode=false;socket.write('250 queued\r\n');}else delivered+=line+'\r\n';continue;}
        if(line.startsWith('EHLO'))socket.write('250-localhost\r\n250 AUTH PLAIN\r\n');
        else if(line.startsWith('AUTH PLAIN ')){authorized=Buffer.from(line.slice(11),'base64').toString()==='\0test-user\0test-password';socket.write(authorized?'235 authenticated\r\n':'535 denied\r\n');}
        else if(line.startsWith('MAIL FROM:')||line.startsWith('RCPT TO:'))socket.write('250 ok\r\n');
        else if(line==='DATA'){dataMode=true;socket.write('354 send data\r\n');}
        else if(line==='QUIT'){socket.end('221 bye\r\n');}
        else socket.write('500 invalid\r\n');
      }
    });
  });
  await new Promise(r=>server.listen(0,'127.0.0.1',r));t.after(()=>new Promise(r=>server.close(r)));
  const child=spawn(process.execPath,[fileURLToPath(new URL('./smtp-client.mjs',import.meta.url))],{env:{...process.env,NODE_EXTRA_CA_CERTS:ca,TEST_SMTP_PORT:String(server.address().port)},stdio:['ignore','pipe','pipe']});
  let out='',err='';child.stdout.on('data',b=>out+=b);child.stderr.on('data',b=>err+=b);
  const exit=await new Promise((r,j)=>{child.once('error',j);child.once('exit',r);});
  assert.equal(exit,0,err);assert.match(out,/SMTP sent/);assert.equal(authorized,true);
  assert.match(delivered,/To: <student@example.test>/);
  const encoded=delivered.split('\r\n\r\n')[1].replace(/\s/g,'');
  assert.equal(Buffer.from(encoded,'base64').toString(),'Перевірка доставки листа через TLS.');
});
test('SMTP queue encrypts message bodies and records failed delivery for retry',async t=>{
  const f=await fixture();t.after(()=>f.close());
  const mailer=createMailer(f.app.db,{...f.config,mailTransport:'smtp',smtpHost:''},Date.now);
  await mailer.send('student@example.test','Reset','Secret link: https://example.test/reset?token=secret');
  const queued=f.app.db.get('SELECT * FROM mail_jobs');
  assert.equal(queued.payload.includes('secret'),false);
  assert.match(JSON.parse(decryptSecret(queued.payload,f.config.secretKey)).body,/token=secret/);
  await mailer.processQueue();const failed=f.app.db.get('SELECT * FROM mail_jobs');
  assert.equal(failed.attempts,1);assert.equal(failed.sent_at,null);assert.ok(failed.next_attempt>Date.now());
});
