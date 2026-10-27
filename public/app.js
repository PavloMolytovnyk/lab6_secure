const state = { csrf: '', user: null, demo: false, providers: [], captcha: null };
const app = document.querySelector('#app');
const esc = value => String(value ?? '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]);
const date = value => value ? new Date(value).toLocaleString('uk-UA', { dateStyle: 'short', timeStyle: 'short' }) : '—';
const initials = name => String(name ?? '?').trim().split(/\s+/).slice(0,2).map(s => s[0]).join('').toUpperCase();
const paths = {
 shield:'M12 3 4 6v6c0 5 3.5 8 8 10 4.5-2 8-5 8-10V6ZM8 12l3 3 5-6',
 user:'M20 21v-2a7 7 0 0 0-14 0v2M16 7a4 4 0 1 1-8 0 4 4 0 0 1 8 0Z',
 users:'M16 21v-2a6 6 0 0 0-12 0v2M14 7a4 4 0 1 1-8 0 4 4 0 0 1 8 0ZM22 21v-2a6 6 0 0 0-4-5.65M17 3.15a4 4 0 0 1 0 7.7',
 lock:'M5 11h14v10H5ZM8 11V7a4 4 0 0 1 8 0v4M12 15v2',
 mail:'M3 5h18v14H3ZM3 5l9 8 9-8',
 clock:'M21 12a9 9 0 1 1-18 0 9 9 0 0 1 18 0ZM12 7v5l3 2',
 check:'m5 12 4 4L19 6',
 refresh:'M20 7v5h-5M4 17v-5h5M6 7a7 7 0 0 1 12-2l2 2M4 17l2 2a7 7 0 0 0 12-2',
 eye:'M2 12s4-7 10-7 10 7 10 7-4 7-10 7S2 12 2 12ZM15 12a3 3 0 1 1-6 0 3 3 0 0 1 6 0Z',
 arrow:'M5 12h14m-6-6 6 6-6 6',
 logout:'M9 5H4v14h5M10 12h11m-5-5 5 5-5 5',
};
const icon = name => `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="${paths[name] ?? paths.shield}"/></svg>`;
const brand = () => `<div class="brand"><span class="brand-mark">${icon('shield')}</span>SecureSpace</div>`;
const field = (id, label, type = 'text', placeholder = '', extra = '') => `<div class="field"><label for="${id}">${label}</label>${type === 'password' ? `<div class="password-wrap"><input id="${id}" name="${id}" type="password" placeholder="${placeholder}" required ${extra}><button type="button" class="eye" data-eye="${id}" aria-label="Показати пароль">${icon('eye')}</button></div>` : `<input id="${id}" name="${id}" type="${type}" placeholder="${placeholder}" required ${extra}>`}</div>`;

async function api(path, body) {
  const response = await fetch(path, { method: body === undefined ? 'GET' : 'POST', credentials: 'same-origin', headers: body === undefined ? {} : { 'content-type': 'application/json', 'x-csrf-token': state.csrf }, ...(body === undefined ? {} : { body: JSON.stringify(body) }) });
  const data = await response.json();
  if (data.csrf) state.csrf = data.csrf;
  if (!response.ok) { const error = new Error(data.error ?? 'Помилка запиту.');Object.assign(error, { code: data.code, status: response.status, details: data.details });throw error; }
  return data;
}
function toast(message, error = false) {
  const element = document.querySelector('#toast');element.textContent = message;element.className = 'visible' + (error ? ' error' : '');
  clearTimeout(toast.timer);toast.timer = setTimeout(() => { element.className = ''; }, 5000);
}
async function navigate(path) { history.pushState({}, '', path);await refresh();window.scrollTo(0,0); }
async function refresh() {
  Object.assign(state, await api('/api/session'));await render();
}
function bindForm(id, action) {
  const form = document.getElementById(id);if (!form) return;
  form.addEventListener('submit', async event => {
    event.preventDefault();const button = form.querySelector('[type=submit]'), error = form.querySelector('.form-error');
    if (error) error.textContent = '';if (button) button.disabled = true;
    try { await action(Object.fromEntries(new FormData(form)), form); }
    catch (failure) {
      const text = failure.details?.length ? failure.message + ' ' + failure.details.join(' ') : failure.message;
      if (error) error.textContent = text;else toast(text, true);
      if (failure.code === 'captcha_invalid' && document.querySelector('#captcha-image')) await loadCaptcha();
    } finally { if (button) button.disabled = false; }
  });
}
function authShell(content, wide = false) {
  app.innerHTML = `<main class="auth-layout"><aside class="auth-story">${brand()}<div class="story-main"><div class="eyebrow">ВАШ ПРОСТІР БЕЗПЕКИ</div><h1>Доступ під вашим контролем.</h1><p>Облікові записи, захищений вхід і прозора історія дій — в одному застосунку.</p><div class="story-features"><div class="story-feature"><span class="ico">${icon('lock')}</span><div><strong>Надійний захист паролів</strong><small>scrypt та індивідуальна сіль</small></div></div><div class="story-feature"><span class="ico">${icon('shield')}</span><div><strong>Додатковий рівень довіри</strong><small>CAPTCHA, 2FA та OpenID Connect</small></div></div><div class="story-feature"><span class="ico">${icon('clock')}</span><div><strong>Кожна спроба має значення</strong><small>Захист входу та журнал подій</small></div></div></div></div><div class="story-footer">Лабораторна робота 6 · JavaScript + SQLite</div></aside><section class="auth-content"><div class="auth-card ${wide ? 'wide' : ''}">${content}<div class="auth-meta">${icon('shield')} Сесія захищена HttpOnly cookie</div></div></section></main>`;
}
function oauthButtons() {
  return `<div class="divider">або увійдіть через провайдера</div><div class="oauth-actions">${state.providers.map(p => `<a class="btn secondary full" href="/auth/oidc/start/${p.id}">${p.id === 'google' ? '<strong>G</strong>' : icon('shield')} ${p.id === 'google' ? 'Продовжити з Google' : 'Увійти через тестовий OIDC'}</a>`).join('')}${!state.googleConfigured ? '<button class="btn secondary full" disabled title="Потрібні GOOGLE_CLIENT_ID та GOOGLE_CLIENT_SECRET">Google — потрібні налаштування</button>' : ''}</div>${state.demo ? '<p class="oauth-note">Локальний провайдер — для перевірки OIDC без зовнішніх ключів.</p>' : ''}`;
}
function layout(title, subtitle, content, action = '') {
  const admin = state.user.role === 'admin', path = location.pathname;
  const link = (href, name, ico) => `<a class="nav-link ${path === href ? 'active' : ''}" href="${href}" data-nav>${icon(ico)}${name}</a>`;
  app.innerHTML = `<div class="layout"><aside class="sidebar">${brand()}<nav><div class="nav-label">Мій простір</div>${link('/profile','Мій профіль','user')}${admin ? `<div class="nav-label">Адміністрування</div>${link('/admin/users','Користувачі','users')}${link('/admin/audit','Журнал входів','clock')}${state.demo && state.mailTransport === 'outbox' ? link('/admin/mail','Листи','mail') : ''}` : ''}</nav><div class="sidebar-bottom"><div class="mini-user"><div class="avatar">${esc(initials(state.user.name))}</div><div><strong>${esc(state.user.name)}</strong><small>${admin ? 'Адміністратор' : 'Користувач'}</small></div></div><button class="signout" data-logout>${icon('logout')} Вийти з системи</button></div></aside><div class="workspace"><header class="topbar"><div class="breadcrumb">SecureSpace &nbsp; / &nbsp; <strong>${esc(title)}</strong></div><div class="top-user"><span>Захищений простір</span><div class="avatar">${esc(initials(state.user.name))}</div></div></header><main class="content"><div class="page-heading"><div><h1>${esc(title)}</h1><p>${esc(subtitle)}</p></div>${action}</div>${content}<div class="footer-note"><span>SecureSpace © 2026</span><span>Контроль доступу на основі ролей</span><span>Node.js · SQLite</span></div></main></div></div>`;
}
async function loadCaptcha() {
  state.captcha = await api('/api/captcha');
  const image = document.querySelector('#captcha-image');if (image) image.src = state.captcha.imageUrl;
  const input = document.querySelector('#captchaAnswer');if (input) input.value = '';
}
function updateStrength() {
  const input = document.querySelector('#password'), list = document.querySelector('#requirements');if (!input || !list) return;
  const password = input.value, checks = [[...password].length >= 8, /\p{Lu}/u.test(password), /\p{Ll}/u.test(password), /[0-9]/.test(password), /[\p{P}\p{S}]/u.test(password)];
  const names = ['8 або більше символів','Велика літера','Мала літера','Цифра','Спеціальний символ'];
  list.innerHTML = names.map((name,i) => `<li class="${checks[i] ? 'ok' : ''}">${name}</li>`).join('');
  const bar = document.querySelector('.strength>span');bar.style.width = checks.filter(Boolean).length * 20 + '%';bar.classList.toggle('good', checks.every(Boolean));
}
async function render() {
  const path = location.pathname, query = new URLSearchParams(location.search);
  if (path.startsWith('/admin/') && (!state.user || state.user.role !== 'admin')) {
    if (!state.user) return navigate('/login');
    layout('Доступ заборонено','Цей розділ призначений для адміністратора.', '<div class="notice warning">Ваша роль дозволяє працювати лише з власним профілем.</div>');return;
  }
  if (path === '/profile' && !state.user) return navigate('/login');
  if (path === '/' || path === '/login') {
    if (path === '/' && state.user) return navigate('/profile');
    authShell(`<div class="eyebrow">З ПОВЕРНЕННЯМ</div><h1>Увійдіть до свого простору</h1><p class="subtitle">Керуйте профілем і налаштуваннями безпеки.</p><form id="login-form" class="stack">${field('email','Електронна пошта','email','you@example.com','autocomplete="username"')}${field('password','Пароль','password','Введіть пароль','autocomplete="current-password"')}<div class="link-row"><span class="muted">Лише захищений доступ</span><a href="/forgot" data-nav>Забули пароль?</a></div><p class="form-error" role="alert">${esc(query.get('error') ?? '')}</p><button class="btn full" type="submit">Увійти ${icon('arrow')}</button></form>${oauthButtons()}<p class="auth-bottom">Ще немає профілю? <a href="/register" data-nav>Створити обліковий запис</a></p>`);
    bindForm('login-form', async data => { const result = await api('/api/auth/login',data);if (result.mfaRequired) return navigate('/mfa?challenge=' + result.challengeId);state.user = result.user;await navigate(result.user.role === 'admin' ? '/admin/users' : '/profile'); });return;
  }
  if (path === '/register') {
    authShell(`<div class="eyebrow">ПОЧНІМО З БЕЗПЕКИ</div><h1>Створіть обліковий запис</h1><p class="subtitle">Після реєстрації підтвердьте свою електронну пошту.</p><form id="register-form" class="stack">${field('name','Ваше ім’я','text','Ім’я та прізвище','maxlength="80" autocomplete="name"')}${field('email','Електронна пошта','email','you@example.com','autocomplete="username"')}${field('password','Пароль','password','Придумайте надійний пароль','autocomplete="new-password" maxlength="128"')}<div class="strength"><span></span></div><ul class="requirements" id="requirements"></ul><div class="field"><label for="captchaAnswer">Підтвердіть, що ви людина</label><div class="captcha-row"><img id="captcha-image" class="captcha-image" alt="Шість символів CAPTCHA"><button class="btn secondary captcha-refresh" type="button" data-refresh-captcha aria-label="Оновити CAPTCHA">${icon('refresh')}</button></div><input id="captchaAnswer" name="captchaAnswer" placeholder="Символи із зображення" maxlength="6" autocomplete="off" required></div><p class="form-error" role="alert"></p><button class="btn full" type="submit">Зареєструватися ${icon('arrow')}</button></form><p class="auth-bottom">Уже зареєстровані? <a href="/login" data-nav>Увійти</a></p>`,true);
    updateStrength();document.querySelector('#password').addEventListener('input', updateStrength);await loadCaptcha();
    bindForm('register-form', async data => { await api('/api/auth/register',{...data,captchaId:state.captcha.id});authShell(`<div class="success-icon">${icon('mail')}</div><h1>Перевірте свою пошту</h1><p class="subtitle">Якщо адресу можна зареєструвати, ми надіслали лист із посиланням для активації. Воно діє 30 хвилин.</p><div class="notice">${state.demo ? 'У локальній демонстрації лист доступний адміністратору в розділі «Листи».' : 'Перевірте також папку «Спам».'}</div><p></p><a class="btn full" href="/login" data-nav>Перейти до входу</a><p class="auth-bottom"><a href="/forgot?activation=1" data-nav>Надіслати посилання повторно</a></p>`); });return;
  }
  if (path === '/forgot') {
    const activation = query.has('activation');
    authShell(`<div class="success-icon">${icon('mail')}</div><h1>${activation ? 'Повторна активація' : 'Забули пароль?'}</h1><p class="subtitle">Введіть email, щоб отримати одноразове посилання.</p><form id="forgot-form" class="stack">${field('email','Електронна пошта','email','you@example.com')}<p class="form-error" role="alert"></p><button class="btn full" type="submit">Надіслати посилання</button></form><p class="auth-bottom"><a href="/login" data-nav>Повернутися до входу</a></p>`);
    bindForm('forgot-form', async data => { const result = await api(activation ? '/api/auth/resend-activation' : '/api/auth/forgot',data);document.querySelector('#forgot-form').innerHTML = `<div class="notice success">${esc(result.message)}</div>`; });return;
  }
  if (path === '/activate') {
    const token = query.get('token') ?? '';
    authShell(`<div class="success-icon">${icon('check')}</div><h1>Підтвердьте свій email</h1><p class="subtitle">Після активації ви отримаєте доступ до власного профілю.</p><form id="activate-form" class="stack"><p class="form-error" role="alert"></p><button class="btn full" type="submit">Активувати обліковий запис</button></form><p class="auth-bottom"><a href="/login" data-nav>До сторінки входу</a></p>`);
    bindForm('activate-form', async () => { const result = await api('/api/auth/activate',{token});history.replaceState({},'','/activate');document.querySelector('#activate-form').innerHTML = `<div class="notice success">${esc(result.message)}</div><a href="/login" class="btn full" data-nav>Увійти до профілю</a>`; });return;
  }
  if (path === '/reset') {
    const token = query.get('token') ?? '';
    authShell(`<div class="success-icon">${icon('lock')}</div><h1>Новий пароль</h1><p class="subtitle">Придумайте пароль, який ви не використовували раніше.</p><form id="reset-form" class="stack">${field('password','Новий пароль','password','Новий надійний пароль','autocomplete="new-password" maxlength="128"')}<div class="strength"><span></span></div><ul class="requirements" id="requirements"></ul>${field('confirmPassword','Повторіть пароль','password','Введіть пароль ще раз','autocomplete="new-password"')}<p class="form-error" role="alert"></p><button class="btn full" type="submit">Зберегти новий пароль</button></form>`);
    updateStrength();document.querySelector('#password').addEventListener('input', updateStrength);
    bindForm('reset-form', async data => { if (data.password !== data.confirmPassword) throw new Error('Паролі не збігаються.');const result = await api('/api/auth/reset',{token,password:data.password});history.replaceState({},'','/reset');document.querySelector('#reset-form').innerHTML = `<div class="notice success">${esc(result.message)}</div><a href="/login" class="btn full" data-nav>Увійти з новим паролем</a>`; });return;
  }
  if (path === '/mfa') {
    const challengeId = query.get('challenge') ?? '';
    authShell(`<div class="success-icon">${icon('shield')}</div><h1>Ще один крок до входу</h1><p class="subtitle">Введіть шестизначний код, надісланий на вашу пошту. Він діє 5 хвилин.</p><form id="mfa-form" class="stack">${field('code','Код підтвердження','text','000000','class="otp-input" inputmode="numeric" pattern="[0-9]{6}" maxlength="6" autocomplete="one-time-code"')}<p class="form-error" role="alert"></p><button class="btn full" type="submit">Підтвердити вхід</button></form><p class="auth-bottom"><a href="/login" data-nav>Почати вхід знову</a></p>`);
    bindForm('mfa-form', async data => { const result = await api('/api/auth/mfa/verify',{challengeId,code:data.code});state.user = result.user;await navigate('/profile'); });return;
  }
  if (path === '/profile') {
    const user = (await api('/api/profile')).user;state.user = user;
    layout('Мій профіль','Ваші особисті дані та налаштування захисту.',`<div class="grid-two"><section class="panel"><div class="panel-head"><h2>Особисті дані</h2><span class="tag">Профіль активний</span></div><div class="panel-body"><div class="profile-summary"><div class="avatar">${esc(initials(user.name))}</div><div><h2>${esc(user.name)}</h2><span class="muted">${esc(user.email)}</span></div></div><dl class="details"><dt>Роль у системі</dt><dd>${user.role === 'admin' ? 'Адміністратор' : 'Користувач'}</dd><dt>Активація email</dt><dd><span class="tag">Підтверджено</span></dd><dt>Дата реєстрації</dt><dd>${date(user.createdAt)}</dd><dt>Спосіб входу</dt><dd>${user.hasPassword ? 'Email та пароль' : user.providers.includes('https://accounts.google.com') ? 'Google OpenID Connect' : 'Тестовий OpenID Connect'}</dd></dl></div><div class="panel-foot">Ви маєте доступ лише до власних персональних даних.</div></section><section class="panel"><div class="panel-head"><h2>Двофакторна автентифікація</h2>${icon('shield')}</div><div class="panel-body"><div class="security-icon">${icon('lock')}</div><h3>Додаткове підтвердження входу</h3><p class="security-text">Окрім пароля, система запитає одноразовий код із вашої пошти. Змінити це налаштування також можна лише після підтвердження кодом.</p><div class="security-status"><span>Статус захисту</span><span class="tag ${user.mfaEnabled ? '' : 'amber'}">${user.mfaEnabled ? '2FA увімкнено' : '2FA вимкнено'}</span></div><button class="btn ${user.mfaEnabled ? 'secondary' : ''} full" data-mfa>${user.mfaEnabled ? 'Вимкнути 2FA' : 'Увімкнути 2FA'}</button></div></section><section class="panel"><div class="panel-head"><h2>Редагувати ім’я</h2></div><div class="panel-body"><form id="name-form" class="stack">${field('name','Ім’я','text','','maxlength="80"')}<p class="form-error" role="alert"></p><button class="btn" type="submit">Зберегти зміни</button></form></div></section><section class="panel"><div class="panel-head"><h2>Безпека сесії</h2></div><div class="panel-body"><p class="security-text">Сесія зберігається на сервері. Паролі хешуються через scrypt; токени активації й відновлення одноразові та мають обмежений строк дії.</p><a href="/forgot" class="btn secondary" data-nav>Відновити пароль через email</a></div></section></div>`);
    document.querySelector('#name').value = user.name;
    bindForm('name-form',async data => { const result = await api('/api/profile/name',data);toast(result.message);await refresh(); });return;
  }
  if (path === '/admin/users') {
    const data = await api('/api/admin/users');
    const stat = (label,value,ico) => `<div class="stat"><div><span>${label}</span><strong>${value}</strong></div><div class="ico">${icon(ico)}</div></div>`;
    const rows = data.users.map(user => {
      const locked = user.lockedUntil > Date.now(), status = user.blocked ? ['red','Заблоковано'] : locked ? ['amber','Тимчасове блокування'] : user.activated ? ['','Активний'] : ['amber','Очікує активації'];
      return `<tr><td><div class="table-user"><div class="avatar">${esc(initials(user.name))}</div><div><strong>${esc(user.name)}</strong><small>${esc(user.email)}</small></div></div></td><td><span class="tag blue">${user.role === 'admin' ? 'Адміністратор' : 'Користувач'}</span></td><td><span class="tag ${status[0]}">${status[1]}</span></td><td>${user.mfaEnabled ? '<span class="tag">Увімкнено</span>' : '<span class="muted">Вимкнено</span>'}</td><td>${user.failedAttempts}</td><td>${date(user.createdAt)}</td><td>${user.id === state.user.id ? '<span class="muted">Ваш профіль</span>' : `<button class="btn small ${user.blocked || locked ? 'subtle' : 'danger'}" data-moderate="${user.id}" data-operation="${user.blocked || locked ? 'unblock' : 'block'}">${user.blocked || locked ? 'Розблокувати' : 'Заблокувати'}</button>`}</td></tr>`;
    }).join('');
    layout('Користувачі','Керуйте доступом та відстежуйте стан облікових записів.',`<div class="stats">${stat('Усього користувачів',data.stats.total,'users')}${stat('Активні профілі',data.stats.active,'check')}${stat('З обмеженим доступом',data.stats.blocked,'lock')}${stat('Із захистом 2FA',data.stats.mfa,'shield')}</div><section class="panel"><div class="panel-head"><h2>Облікові записи</h2><span class="muted">${data.users.length} записів</span></div><div class="table-scroll"><table><thead><tr><th>Користувач</th><th>Роль</th><th>Статус</th><th>2FA</th><th>Невдалі спроби</th><th>Зареєстровано</th><th>Дії</th></tr></thead><tbody>${rows}</tbody></table></div><div class="panel-foot">Після блокування активні сесії користувача одразу завершуються. Розблокування скидає лічильник невдалих спроб.</div></section>`,`<button class="btn secondary" data-reload>${icon('refresh')} Оновити</button>`);return;
  }
  if (path === '/admin/audit') {
    const search = query.get('search') ?? '', result = query.get('result') ?? '', data = await api('/api/admin/audit?' + new URLSearchParams({search,result}));
    const names = { success:['','Успішно'],failure:['red','Невдало'],blocked:['amber','Заблоковано'],mfa_required:['blue','Потрібен 2FA'],activation_required:['amber','Потрібна активація'],accepted:['blue','Прийнято'],requested:['blue','Запит'] };
    const rows = data.logs.map(log => { const label = names[log.result] ?? ['blue',log.result];return `<tr><td>${date(log.created_at)}</td><td>${esc(log.email || '—')}</td><td><span class="audit-event">${esc(log.event)}</span><small class="audit-detail">${esc(log.detail)}</small></td><td><span class="tag ${label[0]}">${esc(label[1])}</span></td><td><code>${esc(log.ip)}</code></td><td><small class="audit-detail">${esc(log.user_agent)}</small></td></tr>`; }).join('');
    layout('Журнал входів','Історія автентифікації, обмежень доступу та дій адміністратора.',`<section class="panel"><div class="panel-head"><form id="audit-filter" class="toolbar"><div class="field"><label for="search">Пошук за email</label><input id="search" name="search" placeholder="Email користувача" value="${esc(search)}"></div><div class="field"><label for="result">Результат</label><select id="result" name="result"><option value="">Усі результати</option><option value="failure">Невдалі спроби</option><option value="blocked">Блокування</option><option value="success">Успішні події</option></select></div><button class="btn" type="submit">Застосувати</button></form></div><div class="table-scroll"><table><thead><tr><th>Час</th><th>Email</th><th>Подія</th><th>Результат</th><th>IP адреса</th><th>Браузер</th></tr></thead><tbody>${rows || '<tr><td colspan="6" class="empty">Подій за цим фільтром немає.</td></tr>'}</tbody></table></div><div class="panel-foot">Показано до 200 останніх подій. Паролі, коди та секретні токени до журналу не записуються.</div></section>`,`<button class="btn secondary" data-reload>${icon('refresh')} Оновити</button>`);
    document.querySelector('#result').value = result;bindForm('audit-filter', data => navigate('/admin/audit?' + new URLSearchParams(data)));return;
  }
  if (path === '/admin/mail') {
    const data = await api('/api/admin/mail');
    const messages = data.messages.map(message => {
      const links = [...message.body.matchAll(/https?:\/\/[^\s]+/g)].map(m => m[0]).filter(value => { try {const u = new URL(value);return u.origin === location.origin && ['/activate','/reset'].includes(u.pathname);} catch {return false;} });
      const code = /Код підтвердження: ([0-9]{6})/.exec(message.body)?.[1];
      return `<article class="mail-item" data-mail-id="${esc(message.id)}"><div class="mail-head"><div><h3>${icon('mail')} ${esc(message.subject)}</h3><small>Кому: ${esc(message.recipient)}</small></div><small>${date(message.created_at)}</small></div><div class="mail-body">${code ? `<div class="mail-code" data-otp="${code}">${code}</div>` : ''}<pre>${esc(message.body)}</pre>${links.map(link => `<a class="btn small" href="${esc(link)}">${new URL(link).pathname === '/activate' ? 'Відкрити активацію' : 'Встановити новий пароль'} ${icon('arrow')}</a>`).join('')}</div></article>`;
    }).join('');
    layout('Листи','Поштова скринька локальної демонстрації.',`<div class="demo-strip">Навчальний режим. Ці листи збережено локально, без надсилання в інтернет. Для реальної пошти налаштуйте SMTP; у production цей розділ вимкнений.</div><div class="mail-list">${messages || '<section class="panel empty">Листів поки немає. Зареєструйте користувача або надішліть запит на відновлення.</section>'}</div>`,`<button class="btn secondary" data-reload>${icon('refresh')} Оновити листи</button>`);return;
  }
  authShell('<h1>Сторінку не знайдено</h1><a href="/login" data-nav>До входу</a>');
}

async function showMfaDialog() {
  const data = await api('/api/profile/mfa/start', {}), enabled = data.purpose === 'enable';
  const overlay = document.createElement('div');overlay.className = 'modal-backdrop';
  overlay.innerHTML = `<section class="modal" role="dialog" aria-modal="true" aria-labelledby="mfa-title"><div class="security-icon">${icon('shield')}</div><h2 id="mfa-title">${enabled ? 'Увімкнення' : 'Вимкнення'} 2FA</h2><p>Для підтвердження зміни введіть код із листа. Код діє 5 хвилин.</p><form id="mfa-setting-form" class="stack">${field('settingsCode','Код із листа','text','000000','class="otp-input" inputmode="numeric" pattern="[0-9]{6}" maxlength="6" autocomplete="one-time-code"')}<p class="form-error" role="alert"></p><div class="modal-actions"><button class="btn full" type="submit">Підтвердити</button><button class="btn secondary" type="button" data-close-modal>Скасувати</button></div></form></section>`;
  document.body.append(overlay);overlay.querySelector('input').focus();
  bindForm('mfa-setting-form', async values => { const result = await api('/api/profile/mfa/confirm',{challengeId:data.challengeId,code:values.settingsCode});overlay.remove();toast(result.message);await refresh(); });
}

document.addEventListener('click', async event => {
  const link = event.target.closest('a[data-nav]');
  if (link && !event.ctrlKey && !event.metaKey) { event.preventDefault();try { await navigate(link.getAttribute('href')); } catch (error) {toast(error.message,true);}return; }
  const target = event.target.closest('button');if (!target) return;
  try {
    if (target.dataset.eye) { const input = document.getElementById(target.dataset.eye);input.type = input.type === 'password' ? 'text' : 'password';return; }
    if (target.hasAttribute('data-refresh-captcha')) { await loadCaptcha();return; }
    if (target.hasAttribute('data-close-modal')) { target.closest('.modal-backdrop').remove();return; }
    if (target.hasAttribute('data-logout')) { await api('/api/auth/logout',{});state.user = null;await navigate('/login');return; }
    if (target.hasAttribute('data-reload')) { await refresh();return; }
    target.disabled = true;
    if (target.hasAttribute('data-mfa')) await showMfaDialog();
    if (target.dataset.moderate) { const result = await api(`/api/admin/users/${target.dataset.moderate}/${target.dataset.operation}`,{});toast(result.message);await refresh(); }
  } catch (error) { toast(error.message,true); }
  finally { target.disabled = false; }
});
window.addEventListener('popstate', () => { refresh().catch(error => toast(error.message,true)); });
refresh().catch(error => { app.innerHTML = `<div class="loading">${esc(error.message)} Перевірте, чи запущений сервер.</div>`; });
