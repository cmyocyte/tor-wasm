#!/usr/bin/env node

/**
 * Bridge Telegram Distribution Bot
 *
 * Distributes Tor bridge URLs to users in censored countries via Telegram.
 * Telegram is the #1 messaging platform in Iran and widely used in Russia,
 * making it an effective distribution channel for bridge information.
 *
 * Zero external dependencies — uses only Node.js built-in https module
 * for Telegram Bot API calls. Long polling (getUpdates) for simplicity.
 *
 * Rate limited: 1 bridge per Telegram user ID per hour.
 * Does not store raw user IDs — only SHA-256 hashes for rate limiting.
 *
 * Usage:
 *   TELEGRAM_BOT_TOKEN=<token> BRIDGE_URL=wss://bridge.example.com node telegram-bot.js
 *
 * Env vars:
 *   TELEGRAM_BOT_TOKEN  — Bot token from @BotFather (required)
 *   BRIDGE_URL          — Bridge WebSocket URL (required)
 *   WEBTUNNEL_URL       — WebTunnel bridge URL (optional)
 *   WEBTUNNEL_PATH      — WebTunnel secret path (optional)
 *   LOX_AUTHORITY_URL   — Lox credential server for enumeration-resistant distribution (optional)
 *   MEEK_URL            — meek fallback bridge URL (optional)
 *   RATE_LIMIT_MINUTES  — Minutes between responses to same user (default: 60)
 */

const https = require('https');
const crypto = require('crypto');

// --- Configuration ---
const BOT_TOKEN = process.env.TELEGRAM_BOT_TOKEN;
const BRIDGE_URL = process.env.BRIDGE_URL;
const WEBTUNNEL_URL = process.env.WEBTUNNEL_URL || null;
const WEBTUNNEL_PATH = process.env.WEBTUNNEL_PATH || null;
const LOX_AUTHORITY_URL = process.env.LOX_AUTHORITY_URL || null;
const MEEK_URL = process.env.MEEK_URL || null;
const RATE_LIMIT_MS = (parseInt(process.env.RATE_LIMIT_MINUTES) || 60) * 60 * 1000;

if (!BOT_TOKEN) {
  console.error('Error: TELEGRAM_BOT_TOKEN environment variable is required');
  process.exit(1);
}
if (!BRIDGE_URL) {
  console.error('Error: BRIDGE_URL environment variable is required');
  process.exit(1);
}

// --- Translations ---
const i18n = {
  en: {
    welcome: 'Welcome to the Bridge Distribution Bot.\nUse /start to receive a bridge connection URL.',
    bridge_header: 'Bridge Connection Info',
    setup: 'To connect:\n1. Open the privacy browser\n2. Go to Settings > Bridge\n3. Paste the config below or scan the QR code in-app',
    config_label: 'Config (QR-compatible):',
    webtunnel_label: 'WebTunnel bridge:',
    meek_label: 'Meek fallback:',
    lox_header: 'Lox Invitation Token',
    lox_setup: 'This is a one-time invitation for enumeration-resistant bridge access.\nYour trust level improves over time.',
    lox_authority: 'Authority:',
    lox_token: 'Token ID:',
    rate_limited: 'You already received a bridge recently. Please wait before requesting again.',
    status_checking: 'Checking bridge status...',
    status_reachable: 'Bridge is reachable.',
    status_unreachable: 'Bridge is unreachable. Try the meek fallback if available.',
    help: 'Commands:\n/start - Get bridge connection info\n/status - Check bridge health\n/help - Show this message',
  },
  fa: {
    welcome: 'به ربات توزیع پل خوش آمدید.\nبرای دریافت آدرس اتصال پل از /start استفاده کنید.',
    bridge_header: 'اطلاعات اتصال پل',
    setup: 'برای اتصال:\n۱. مرورگر حریم خصوصی را باز کنید\n۲. به تنظیمات > پل بروید\n۳. پیکربندی زیر را وارد کنید یا کد QR را اسکن کنید',
    config_label: 'پیکربندی (سازگار با QR):',
    webtunnel_label: 'پل WebTunnel:',
    meek_label: 'پشتیبان meek:',
    lox_header: 'توکن دعوت Lox',
    lox_setup: 'این یک دعوتنامه یکبار مصرف برای دسترسی مقاوم در برابر شمارش است.\nسطح اعتماد شما با گذشت زمان بهبود می‌یابد.',
    lox_authority: 'مرجع:',
    lox_token: 'شناسه توکن:',
    rate_limited: 'شما اخیرا یک پل دریافت کرده‌اید. لطفا قبل از درخواست مجدد صبر کنید.',
    status_checking: 'در حال بررسی وضعیت پل...',
    status_reachable: 'پل در دسترس است.',
    status_unreachable: 'پل در دسترس نیست. در صورت موجود بودن از پشتیبان meek استفاده کنید.',
    help: 'دستورات:\n/start - دریافت اطلاعات اتصال پل\n/status - بررسی سلامت پل\n/help - نمایش این پیام',
  },
  ru: {
    welcome: 'Добро пожаловать в бот раздачи мостов.\nИспользуйте /start для получения URL моста.',
    bridge_header: 'Информация о подключении к мосту',
    setup: 'Для подключения:\n1. Откройте браузер конфиденциальности\n2. Перейдите в Настройки > Мост\n3. Вставьте конфигурацию ниже или отсканируйте QR-код',
    config_label: 'Конфигурация (для QR):',
    webtunnel_label: 'Мост WebTunnel:',
    meek_label: 'Запасной meek:',
    lox_header: 'Токен приглашения Lox',
    lox_setup: 'Это одноразовое приглашение для устойчивой к перебору раздачи мостов.\nУровень доверия повышается со временем.',
    lox_authority: 'Сервер:',
    lox_token: 'ID токена:',
    rate_limited: 'Вы уже получили мост недавно. Подождите перед повторным запросом.',
    status_checking: 'Проверка состояния моста...',
    status_reachable: 'Мост доступен.',
    status_unreachable: 'Мост недоступен. Попробуйте запасной meek, если он настроен.',
    help: 'Команды:\n/start - Получить информацию о подключении\n/status - Проверить доступность моста\n/help - Показать это сообщение',
  },
  zh: {
    welcome: '欢迎使用网桥分发机器人。\n使用 /start 获取网桥连接地址。',
    bridge_header: '网桥连接信息',
    setup: '连接步骤：\n1. 打开隐私浏览器\n2. 进入 设置 > 网桥\n3. 粘贴以下配置或在应用中扫描二维码',
    config_label: '配置（二维码兼容）：',
    webtunnel_label: 'WebTunnel 网桥：',
    meek_label: 'meek 备用：',
    lox_header: 'Lox 邀请令牌',
    lox_setup: '这是一次性邀请，用于抗枚举的网桥分发。\n您的信任级别会随时间提升。',
    lox_authority: '授权服务器：',
    lox_token: '令牌 ID：',
    rate_limited: '您最近已获取过网桥，请稍后再试。',
    status_checking: '正在检查网桥状态...',
    status_reachable: '网桥可用。',
    status_unreachable: '网桥不可用。如果可用，请尝试 meek 备用方案。',
    help: '命令：\n/start - 获取网桥连接信息\n/status - 检查网桥健康状态\n/help - 显示此消息',
  },
};

/**
 * Get translated string for a user's language.
 * Falls back to English for unsupported languages.
 * @param {string} langCode - Telegram language_code (e.g. 'fa', 'ru', 'zh-hans')
 * @param {string} key - Translation key
 * @returns {string}
 */
function t(langCode, key) {
  const lang = (langCode || 'en').slice(0, 2).toLowerCase();
  const strings = i18n[lang] || i18n.en;
  return strings[key] || i18n.en[key] || key;
}

// --- Rate Limiting ---
// Store SHA-256 hashes of user IDs (not raw IDs)
const userHistory = new Map();

/** @param {number} userId */
function hashUserId(userId) {
  return crypto.createHash('sha256').update(String(userId)).digest('hex').slice(0, 16);
}

/** @param {number} userId */
function isRateLimited(userId) {
  const hash = hashUserId(userId);
  const lastSent = userHistory.get(hash);
  return lastSent && Date.now() - lastSent < RATE_LIMIT_MS;
}

/** @param {number} userId */
function recordSend(userId) {
  userHistory.set(hashUserId(userId), Date.now());
}

// Cleanup expired entries every 30 minutes
setInterval(() => {
  const cutoff = Date.now() - RATE_LIMIT_MS;
  for (const [hash, time] of userHistory) {
    if (time < cutoff) userHistory.delete(hash);
  }
}, 30 * 60 * 1000);

// --- Telegram Bot API ---

/**
 * Call the Telegram Bot API using only the built-in https module.
 * @param {string} method - API method (e.g. 'sendMessage', 'getUpdates')
 * @param {object} body - JSON request body
 * @returns {Promise<object>}
 */
function telegramApi(method, body) {
  return new Promise((resolve, reject) => {
    const data = JSON.stringify(body);
    const req = https.request({
      hostname: 'api.telegram.org',
      path: `/bot${BOT_TOKEN}/${method}`,
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Content-Length': Buffer.byteLength(data),
      },
    }, (res) => {
      let buf = '';
      res.on('data', (c) => buf += c);
      res.on('end', () => {
        try { resolve(JSON.parse(buf)); } catch (e) { reject(e); }
      });
    });
    req.on('error', reject);
    req.write(data);
    req.end();
  });
}

/**
 * Send a text message to a Telegram chat.
 * @param {number} chatId
 * @param {string} text
 */
async function sendMessage(chatId, text) {
  return telegramApi('sendMessage', { chat_id: chatId, text, parse_mode: 'Markdown' });
}

// --- Lox Invitation Token ---

/**
 * Fetch a one-time Lox invitation token from the authority server.
 * Returns null if LOX_AUTHORITY_URL is not configured or the request fails.
 * @returns {Promise<{id: string, credential: string}|null>}
 */
async function fetchLoxInviteToken() {
  if (!LOX_AUTHORITY_URL) return null;

  try {
    const http = require(LOX_AUTHORITY_URL.startsWith('https') ? 'https' : 'http');
    const url = `${LOX_AUTHORITY_URL}/lox/open-invite`;

    return new Promise((resolve) => {
      const req = http.request(url, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
      }, (res) => {
        let data = '';
        res.on('data', (chunk) => { data += chunk; });
        res.on('end', () => {
          try {
            const parsed = JSON.parse(data);
            resolve({ id: parsed.id, credential: parsed.credential });
          } catch {
            resolve(null);
          }
        });
      });
      req.on('error', () => resolve(null));
      req.write('{}');
      req.end();
    });
  } catch {
    return null;
  }
}

// --- Bridge Status Check ---

/**
 * Attempt a TLS connection to the bridge host to check reachability.
 * Resolves true if the connection succeeds within 5 seconds.
 * @returns {Promise<boolean>}
 */
function checkBridgeHealth() {
  return new Promise((resolve) => {
    try {
      const url = new URL(BRIDGE_URL);
      const hostname = url.hostname;
      const port = url.port || (url.protocol === 'wss:' ? 443 : 80);

      const req = https.request({
        hostname,
        port,
        path: '/',
        method: 'GET',
        timeout: 5000,
      }, (res) => {
        res.resume(); // drain
        resolve(true);
      });
      req.on('error', () => resolve(false));
      req.on('timeout', () => { req.destroy(); resolve(false); });
      req.end();
    } catch {
      resolve(false);
    }
  });
}

// --- Message Handler ---

/**
 * Handle an incoming Telegram message.
 * Routes /start, /help, /status commands. Ignores everything else.
 * @param {object} msg - Telegram message object
 */
async function handleMessage(msg) {
  const chatId = msg.chat.id;
  const userId = msg.from?.id;
  const lang = msg.from?.language_code || 'en';
  const text = (msg.text || '').trim();
  const command = text.split(/\s+/)[0].toLowerCase().replace(/@\w+$/, ''); // strip @botname

  if (command === '/start') {
    // Rate limit check
    if (userId && isRateLimited(userId)) {
      await sendMessage(chatId, t(lang, 'rate_limited'));
      return;
    }

    // Try Lox invitation first (enumeration-resistant distribution)
    const loxToken = await fetchLoxInviteToken();

    let reply = '';
    if (loxToken) {
      reply += `*${t(lang, 'lox_header')}*\n\n`;
      reply += `${t(lang, 'lox_setup')}\n\n`;
      reply += `${t(lang, 'lox_authority')} \`${LOX_AUTHORITY_URL}\`\n`;
      reply += `${t(lang, 'lox_token')} \`${loxToken.id}\`\n`;
    } else {
      reply += `*${t(lang, 'bridge_header')}*\n\n`;
      reply += `${t(lang, 'setup')}\n\n`;

      // QR-compatible JSON config (matches qr-generator.js encodeBridgeConfig)
      const config = { u: BRIDGE_URL, k: '', m: MEEK_URL || '' };
      reply += `${t(lang, 'config_label')}\n\`${JSON.stringify(config)}\`\n`;

      if (WEBTUNNEL_URL) {
        const wtDisplay = WEBTUNNEL_PATH
          ? `${WEBTUNNEL_URL} (path: ${WEBTUNNEL_PATH})`
          : WEBTUNNEL_URL;
        reply += `\n${t(lang, 'webtunnel_label')} \`${wtDisplay}\`\n`;
      }
      if (MEEK_URL) {
        reply += `${t(lang, 'meek_label')} \`${MEEK_URL}\`\n`;
      }
    }

    await sendMessage(chatId, reply);
    if (userId) recordSend(userId);
    console.log(`[BOT] Bridge sent to user ${hashUserId(userId)}`);

  } else if (command === '/status') {
    await sendMessage(chatId, t(lang, 'status_checking'));
    const reachable = await checkBridgeHealth();
    const statusKey = reachable ? 'status_reachable' : 'status_unreachable';
    await sendMessage(chatId, `${t(lang, statusKey)}\n\nBridge: \`${BRIDGE_URL}\``);

  } else if (command === '/help') {
    await sendMessage(chatId, t(lang, 'help'));
  }
  // Silently ignore non-command messages for privacy
}

// --- Long Polling Loop ---

let offset = 0;

/** Poll Telegram for new updates using long polling. */
async function poll() {
  try {
    const resp = await telegramApi('getUpdates', { offset, timeout: 30 });
    if (resp.ok && resp.result) {
      for (const update of resp.result) {
        offset = update.update_id + 1;
        if (update.message?.text) {
          await handleMessage(update.message);
        }
      }
    }
  } catch (e) {
    console.error('[BOT] Poll error:', e.message);
    await new Promise((r) => setTimeout(r, 5000)); // backoff on error
  }
  poll(); // recurse — keeps polling indefinitely
}

// --- Startup ---

console.log('\nBridge Telegram Distribution Bot');
console.log('================================');
console.log(`Bridge:     ${BRIDGE_URL}`);
if (WEBTUNNEL_URL) console.log(`WebTunnel:  ${WEBTUNNEL_URL}`);
if (MEEK_URL)      console.log(`Meek:       ${MEEK_URL}`);
if (LOX_AUTHORITY_URL) console.log(`Lox:        ${LOX_AUTHORITY_URL}`);
console.log(`Rate limit: ${RATE_LIMIT_MS / 60000} min per user`);
console.log('Polling for messages...\n');

poll();
