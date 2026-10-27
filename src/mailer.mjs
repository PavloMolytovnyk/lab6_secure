import net from 'node:net';
import tls from 'node:tls';
import { once } from 'node:events';
import { randomToken, normalizeEmail, encryptSecret, decryptSecret } from './security.mjs';

// TLS сертифікати SMTP перевіряються стандартним Node.js trust store.
export async function sendSmtp(config, message) {
  if (!config.smtpHost) throw new Error('SMTP_HOST не налаштовано.');
  let socket, buffer = '', current = [], replies = [], waiters = [], failure;
  const fail = error => {
    failure = error;
    for (const waiter of waiters.splice(0)) waiter.reject(error);
  };
  const onData = data => {
    buffer += data.toString('utf8');
    let end;
    while ((end = buffer.indexOf('\r\n')) !== -1) {
      const line = buffer.slice(0, end);buffer = buffer.slice(end + 2);current.push(line);
      if (/^\d{3} /.test(line)) {
        const reply = { code: Number(line.slice(0, 3)), text: current.join('\n') };current = [];
        const waiter = waiters.shift();if (waiter) waiter.resolve(reply);else replies.push(reply);
      }
    }
  };
  const attach = () => {
    socket.on('data', onData);socket.on('error', fail);
    socket.setTimeout(15_000, () => socket.destroy(new Error('SMTP timeout')));
    socket.on('end', () => fail(new Error('SMTP connection closed')));
  };
  const readReply = () => failure ? Promise.reject(failure) : replies.length ? Promise.resolve(replies.shift()) : new Promise((resolve, reject) => waiters.push({ resolve, reject }));
  const expect = async codes => {
    const reply = await readReply();
    if (!codes.includes(reply.code)) throw new Error('SMTP відхилив операцію: ' + reply.code);
  };
  const command = async (value, codes) => { socket.write(value + '\r\n');await expect(codes); };
  try {
    if (config.smtpSecurity === 'tls') {
      socket = tls.connect({ host: config.smtpHost, port: config.smtpPort, servername: config.smtpHost, minVersion: 'TLSv1.2', rejectUnauthorized: true });
      attach();await once(socket, 'secureConnect');
    } else {
      socket = net.connect({ host: config.smtpHost, port: config.smtpPort });attach();await once(socket, 'connect');
    }
    await expect([220]);await command('EHLO security-lab.local', [250]);
    if (config.smtpSecurity === 'starttls') {
      await command('STARTTLS', [220]);
      socket.removeAllListeners('data');socket.removeAllListeners('end');socket.removeAllListeners('error');
      socket = tls.connect({ socket, servername: config.smtpHost, minVersion: 'TLSv1.2', rejectUnauthorized: true });
      attach();await once(socket, 'secureConnect');await command('EHLO security-lab.local', [250]);
    }
    if (config.smtpUser) {
      const auth = Buffer.from('\0' + config.smtpUser + '\0' + config.smtpPassword).toString('base64');
      await command('AUTH PLAIN ' + auth, [235]);
    }
    const from = normalizeEmail(config.mailFrom.match(/<([^>]+)>/)?.[1] ?? config.mailFrom);
    const to = normalizeEmail(message.to);
    if (!from || !to) throw new Error('Некоректна адреса SMTP.');
    await command(`MAIL FROM:<${from}>`, [250]);await command(`RCPT TO:<${to}>`, [250, 251]);await command('DATA', [354]);
    const subject = Buffer.from(message.subject.replace(/[\r\n]/g, ' ')).toString('base64');
    const body = Buffer.from(message.body).toString('base64').match(/.{1,76}/g)?.join('\r\n') ?? '';
    const payload = [`From: <${from}>`, `To: <${to}>`, `Subject: =?UTF-8?B?${subject}?=`, `Date: ${new Date().toUTCString()}`, `Message-ID: <${randomToken(16)}@security-lab.local>`, 'MIME-Version: 1.0', 'Content-Type: text/plain; charset=UTF-8', 'Content-Transfer-Encoding: base64', '', body].join('\r\n');
    socket.write(payload + '\r\n.\r\n');await expect([250]);await command('QUIT', [221]);
  } finally { socket?.destroy(); }
}

export function createMailer(db, config, now) {
  let timer, running;
  const processQueue = async () => {
    if (running) return running;
    running = (async () => {
      const job = db.get('SELECT * FROM mail_jobs WHERE sent_at IS NULL AND attempts < 6 AND next_attempt <= ? ORDER BY created_at LIMIT 1', now());
      if (!job) return;
      try {
        const message = JSON.parse(decryptSecret(job.payload, config.secretKey));
        await sendSmtp(config, message);
        db.run('UPDATE mail_jobs SET sent_at=?,payload=?,last_error=NULL WHERE id=?', now(), '', job.id);
      } catch {
        db.run('UPDATE mail_jobs SET attempts=attempts+1,next_attempt=?,last_error=? WHERE id=?', now() + Math.min(300_000, 5_000 * 2 ** job.attempts), 'SMTP delivery failed', job.id);
      }
    })().finally(() => { running = undefined; });
    return running;
  };
  return {
    async send(to, subject, body) {
      if (config.mailTransport === 'smtp') {
        db.run('INSERT INTO mail_jobs(id,payload,next_attempt,created_at) VALUES(?,?,?,?)', randomToken(18), encryptSecret(JSON.stringify({to,subject,body}),config.secretKey), now(), now());
      } else if (config.demo && config.mailTransport === 'outbox') {
        db.run('INSERT INTO mail_messages(id,recipient,subject,body,created_at) VALUES(?,?,?,?,?)', randomToken(18), to, subject, body, now());
      } else throw new Error('Поштовий транспорт не налаштовано.');
    },
    start() { if (config.mailTransport === 'smtp') { timer = setInterval(() => { void processQueue(); }, 2_000);timer.unref(); } },
    async stop() { clearInterval(timer);if (running) await running; },
    processQueue,
  };
}
