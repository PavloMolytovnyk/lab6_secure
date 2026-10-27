# HTTP API

Базова адреса: `http://127.0.0.1:3000`. Вхідні дані POST — JSON.
Спочатку виконайте `GET /api/session`, збережіть cookie і поле `csrf`.
Усі POST `/api/*` вимагають заголовок `X-CSRF-Token`; за наявності `Origin`
він має точно відповідати `APP_URL`. Після входу, виходу та зміни 2FA cookie
і CSRF змінюються. Значення `csrf` повертається у відповіді.

| Метод і шлях | Призначення | Доступ |
| --- | --- | --- |
| GET `/health` | Стан сервера | Публічний |
| GET `/api/session` | Поточний профіль, CSRF, доступні провайдери | Власна сесія |
| GET `/api/captcha` | Створити одноразову CAPTCHA | Власна сесія |
| GET `/api/captcha/:id.png` | PNG CAPTCHA | Лише сесія-власник |
| POST `/api/auth/register` | Реєстрація | Публічний + CSRF + CAPTCHA |
| POST `/api/auth/activate` | Активація за токеном | Публічний + CSRF |
| POST `/api/auth/resend-activation` | Повторний лист активації | Публічний + CSRF + ліміти |
| POST `/api/auth/login` | Вхід або початок 2FA | Публічний + CSRF + ліміти |
| POST `/api/auth/mfa/verify` | Завершити вхід за OTP | Сесія-власник challenge |
| POST `/api/auth/logout` | Анулювати сесію | Власна сесія + CSRF |
| POST `/api/auth/forgot` | Запит відновлення | Публічний + CSRF + ліміти |
| POST `/api/auth/reset` | Новий пароль за токеном | Публічний + CSRF |
| GET `/api/profile` | Власний профіль | Активний користувач |
| POST `/api/profile/name` | Зміна власного імені | Активний користувач + CSRF |
| POST `/api/profile/mfa/start` | Надіслати код зміни 2FA | Активний користувач + CSRF |
| POST `/api/profile/mfa/confirm` | Підтвердити зміну 2FA | Власний challenge + CSRF |
| GET `/api/admin/users` | Статуси користувачів і статистика | Адміністратор |
| POST `/api/admin/users/:id/block` | Блокування + анулювання сесій | Адміністратор + CSRF |
| POST `/api/admin/users/:id/unblock` | Розблокування та скидання спроб | Адміністратор + CSRF |
| GET `/api/admin/audit?search=&result=` | До 200 останніх подій | Адміністратор |
| GET `/api/admin/mail` | Локальна навчальна пошта | Адміністратор, лише demo/outbox |
| GET `/auth/oidc/start/:provider` | Початок OIDC | Сесія + state/nonce/PKCE |
| GET `/auth/oidc/callback/:provider` | Callback OIDC | Прив’язаний одноразовий state |

Приклади тіл:

```json
{"name":"Павло Студент","email":"student@example.test","password":"Student2026!Secure","captchaId":"ID_FROM_API","captchaAnswer":"IMAGE_TEXT"}
```

```json
{"email":"student@example.test","password":"Student2026!Secure"}
```

```json
{"challengeId":"ID_FROM_LOGIN_OR_SETTINGS","code":"123456"}
```

```json
{"token":"TOKEN_FROM_EMAIL","password":"New2026!SecurePass"}
```

Реєстрація повертає `202` із нейтральним повідомленням. Вхід — `200`
із профілем та новим CSRF або `mfaRequired:true` із challenge ID.
Помилка має формат `{ "error": "Опис", "code": "код" }`.
Основні статуси: `400` — неправильні дані/токен, `401` — немає входу,
`403` — роль або CSRF, `423` — блокування, `429` — ліміт запитів.

Детальний опис захисту та налаштування Google/SMTP — у README.md.
