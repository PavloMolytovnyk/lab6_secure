import { sendSmtp } from '../src/mailer.mjs';
await sendSmtp({smtpHost:'localhost',smtpPort:Number(process.env.TEST_SMTP_PORT),smtpSecurity:'tls',smtpUser:'test-user',smtpPassword:'test-password',mailFrom:'no-reply@example.test'}, {to:'student@example.test',subject:'Тест SMTP',body:'Перевірка доставки листа через TLS.'});
console.log('SMTP sent');
