import { readEnvironment, loadConfig } from './config.mjs';
import { createApplication } from './app.mjs';
import { startDemoProvider } from './demo-provider.mjs';

if (Number(process.versions.node.split('.')[0]) < 24) {
  console.error('Потрібен Node.js 24 або новіший.');process.exit(1);
}
readEnvironment();
const config = loadConfig();
let provider, application;
try {
  if (config.demo) provider = await startDemoProvider(config);
  application = await createApplication({ config });
  await application.listen();
  console.log(`\nSecureSpace · лабораторна 6\nЗастосунок: ${config.appUrl}\nАдміністратор: ${config.adminEmail}\n${config.demo ? 'Навчальний пароль адміністратора першого запуску: ' + config.adminPassword + '\nЛокальна пошта: меню адміністратора → Листи\nТестовий OIDC: ' + provider.issuer : 'Production: використовується SMTP та Secure cookie.'}\n`);
  const shutdown = async () => { await application.close();await provider?.close();process.exit(0); };
  process.once('SIGINT', shutdown);process.once('SIGTERM', shutdown);
} catch (error) {
  console.error('Не вдалося запустити застосунок:', error.message);
  await application?.close();await provider?.close();process.exit(1);
}
