import { randomInt } from 'node:crypto';
import { deflateSync } from 'node:zlib';
import { randomToken, hmac, safeEqual, HttpError } from './security.mjs';

const FONT = {
 '2':['01110','10001','00001','00010','00100','01000','11111'],
 '3':['11110','00001','00001','01110','00001','00001','11110'],
 '4':['00010','00110','01010','10010','11111','00010','00010'],
 '5':['11111','10000','10000','11110','00001','00001','11110'],
 '6':['01110','10000','10000','11110','10001','10001','01110'],
 '7':['11111','00001','00010','00100','01000','01000','01000'],
 '8':['01110','10001','10001','01110','10001','10001','01110'],
 '9':['01110','10001','10001','01111','00001','00001','01110'],
 A:['01110','10001','10001','11111','10001','10001','10001'],
 B:['11110','10001','10001','11110','10001','10001','11110'],
 C:['01111','10000','10000','10000','10000','10000','01111'],
 D:['11110','10001','10001','10001','10001','10001','11110'],
 E:['11111','10000','10000','11110','10000','10000','11111'],
 F:['11111','10000','10000','11110','10000','10000','10000'],
 G:['01111','10000','10000','10111','10001','10001','01111'],
 H:['10001','10001','10001','11111','10001','10001','10001'],
 J:['00111','00010','00010','00010','10010','10010','01100'],
 K:['10001','10010','10100','11000','10100','10010','10001'],
 M:['10001','11011','10101','10101','10001','10001','10001'],
 N:['10001','11001','10101','10011','10001','10001','10001'],
 P:['11110','10001','10001','11110','10000','10000','10000'],
 Q:['01110','10001','10001','10001','10101','10010','01101'],
 R:['11110','10001','10001','11110','10100','10010','10001'],
 S:['01111','10000','10000','01110','00001','00001','11110'],
 T:['11111','00100','00100','00100','00100','00100','00100'],
 U:['10001','10001','10001','10001','10001','10001','01110'],
 V:['10001','10001','10001','10001','10001','01010','00100'],
 W:['10001','10001','10001','10101','10101','10101','01010'],
 X:['10001','10001','01010','00100','01010','10001','10001'],
 Y:['10001','10001','01010','00100','00100','00100','00100'],
 Z:['11111','00001','00010','00100','01000','10000','11111'],
};
export function generateCaptchaText() {
  const alphabet = Object.keys(FONT);
  return Array.from({ length: 6 }, () => alphabet[randomInt(alphabet.length)]).join('');
}

function crc32(bytes) {
  let crc = 0xffffffff;
  for (const byte of bytes) {
    crc ^= byte;
    for (let i = 0; i < 8; i++) crc = (crc >>> 1) ^ (0xedb88320 & -(crc & 1));
  }
  return (crc ^ 0xffffffff) >>> 0;
}
function chunk(type, data) {
  const label = Buffer.from(type), header = Buffer.alloc(4), crc = Buffer.alloc(4);
  header.writeUInt32BE(data.length);crc.writeUInt32BE(crc32(Buffer.concat([label, data])));
  return Buffer.concat([header, label, data, crc]);
}
export function renderCaptchaPng(text) {
  const width = 232, height = 80, rgba = Buffer.alloc(width * height * 4);
  const pixel = (x, y, color) => {
    x = Math.round(x);y = Math.round(y);
    if (x < 0 || y < 0 || x >= width || y >= height) return;
    const offset = (y * width + x) * 4;
    rgba[offset] = color[0];rgba[offset + 1] = color[1];rgba[offset + 2] = color[2];rgba[offset + 3] = 255;
  };
  for (let y = 0; y < height; y++) for (let x = 0; x < width; x++) pixel(x, y, [242, 246, 252]);
  for (let i = 0; i < 600; i++) pixel(randomInt(width), randomInt(height), [185, 202, 220]);
  for (let c = 0; c < text.length; c++) {
    const glyph = FONT[text[c]], angle = (randomInt(31) - 15) / 100;
    const x0 = 18 + c * 34, y0 = randomInt(22, 34), color = [randomInt(20, 65), randomInt(35, 85), randomInt(80, 135)];
    if (!glyph) throw new Error('Unsupported CAPTCHA glyph');
    for (let gy = 0; gy < 7; gy++) for (let gx = 0; gx < 5; gx++) if (glyph[gy][gx] === '1') {
      for (let py = 0; py < 4; py++) for (let px = 0; px < 4; px++) {
        const x = gx * 4 + px, y = gy * 4 + py;
        pixel(x0 + x * Math.cos(angle) - y * Math.sin(angle), y0 + x * Math.sin(angle) + y * Math.cos(angle), color);
      }
    }
  }
  for (let i = 0; i < 4; i++) {
    const y0 = randomInt(12, 68), slope = (randomInt(31) - 15) / 100;
    for (let x = 0; x < width; x++) pixel(x, y0 + x * slope + 3 * Math.sin(x / 13), [145, 165, 190]);
  }
  const raw = Buffer.alloc(height * (1 + width * 4));
  for (let y = 0; y < height; y++) rgba.copy(raw, y * (1 + width * 4) + 1, y * width * 4, (y + 1) * width * 4);
  const ihdr = Buffer.alloc(13);ihdr.writeUInt32BE(width);ihdr.writeUInt32BE(height, 4);ihdr[8] = 8;ihdr[9] = 6;
  return Buffer.concat([Buffer.from([137, 80, 78, 71, 13, 10, 26, 10]), chunk('IHDR', ihdr), chunk('IDAT', deflateSync(raw)), chunk('IEND', Buffer.alloc(0))]);
}

export function createCaptchaService(db, config, now, textFactory = generateCaptchaText) {
  return {
    create(sessionHash) {
      const text = textFactory(), id = randomToken(18), expiresAt = now() + config.captchaTtlMs;
      db.run('DELETE FROM captchas WHERE expires_at < ? OR session_hash = ?', now(), sessionHash);
      db.run('INSERT INTO captchas(id,session_hash,answer_hash,image,expires_at) VALUES(?,?,?,?,?)', id, sessionHash, hmac(config.secretKey, id + ':' + text), renderCaptchaPng(text), expiresAt);
      return { id, imageUrl: '/api/captcha/' + id + '.png', expiresAt };
    },
    image(id, sessionHash) {
      const item = db.get('SELECT * FROM captchas WHERE id=? AND session_hash=? AND consumed_at IS NULL AND expires_at>?', id, sessionHash, now());
      if (!item) throw new HttpError(404, 'CAPTCHA застаріла. Оновіть зображення.');
      return Buffer.from(item.image);
    },
    consume(id, answer, sessionHash) {
      if (typeof id !== 'string' || typeof answer !== 'string' || answer.length > 32) throw new HttpError(400, 'Некоректні параметри CAPTCHA.', 'captcha_invalid');
      return db.transaction(() => {
        const item = db.get('SELECT * FROM captchas WHERE id=? AND session_hash=?', String(id ?? ''), sessionHash);
        if (!item || item.consumed_at || item.expires_at <= now()) throw new HttpError(400, 'CAPTCHA застаріла або вже використана.', 'captcha_invalid');
        db.run('UPDATE captchas SET consumed_at=? WHERE id=?', now(), item.id);
        const actual = hmac(config.secretKey, item.id + ':' + String(answer ?? '').trim().toUpperCase());
        return safeEqual(item.answer_hash, actual);
      });
    },
  };
}
