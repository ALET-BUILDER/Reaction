// ============================================================
// SERVER.JS — WhatsApp Reaction API Server
// Node.js + Express + Socket.IO + Baileys (WhatsApp)
// ============================================================
const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { makeWASocket, useMultiFileAuthState, DisconnectReason, fetchLatestBaileysVersion, makeInMemoryStore } = require('@whiskeysockets/baileys');
const { Boom } = require('@hapi/boom');
const pino = require('pino');
const QRCode = require('qrcode');

const app = express();
const server = http.createServer(app);
const io = new Server(server, {
  cors: { origin: '*', methods: ['GET', 'POST'] },
  pingTimeout: 60000,
  pingInterval: 25000
});

const PORT = process.env.PORT || 3000;
const ADMIN_KEY = process.env.ADMIN_KEY || 'ADMIN_SECRET_2025';
const DB_FILE = path.join(__dirname, 'db.json');
const SESSIONS_DIR = path.join(__dirname, 'sessions');

if (!fs.existsSync(SESSIONS_DIR)) fs.mkdirSync(SESSIONS_DIR, { recursive: true });

// ============================================================
// DATABASE (JSON-file based)
// ============================================================
function loadDB() {
  try {
    if (fs.existsSync(DB_FILE)) return JSON.parse(fs.readFileSync(DB_FILE, 'utf8'));
  } catch (e) {}
  return {
    users: {},
    apikeys: {},
    bots: {},
    settings: {
      free_limit: 5,
      pro_limit: 80,
      vip_limit: 999999,
      free_emoji_limit: 3,
      pro_emoji_limit: 5,
      vip_emoji_limit: 300,
      delay_seconds: 180,
      maintenance: false,
      maintenance_msg: 'Server sedang dalam perbaikan.',
      reaction_free_max: 15,
      reaction_pro_max: 100,
      reaction_vip_max: 300
    },
    request_log: []
  };
}

function saveDB(db) {
  try { fs.writeFileSync(DB_FILE, JSON.stringify(db, null, 2)); } catch (e) {}
}

let DB = loadDB();

// ============================================================
// HELPERS
// ============================================================
function genId(prefix='') {
  return prefix + crypto.randomBytes(8).toString('hex');
}

function escapeHtml(str) {
  return String(str || '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#039;'}[c]));
}

function sanitize(str) {
  return String(str || '').replace(/[<>"'`]/g, '').trim().slice(0, 500);
}

// Rate limiter
const rateLimits = {};
function rateLimit(key, max, windowMs) {
  const now = Date.now();
  if (!rateLimits[key] || now > rateLimits[key].reset) {
    rateLimits[key] = { count: 0, reset: now + windowMs };
  }
  rateLimits[key].count++;
  return rateLimits[key].count <= max;
}

// ============================================================
// MIDDLEWARE
// ============================================================
app.use(express.json({ limit: '2mb' }));
app.use(express.urlencoded({ extended: false }));
app.use(express.static(path.join(__dirname)));

// Security headers
app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('X-XSS-Protection', '1; mode=block');
  next();
});

// Maintenance check (skip admin routes)
app.use((req, res, next) => {
  if (DB.settings.maintenance && !req.path.startsWith('/api/admin') && !req.path.startsWith('/admin')) {
    if (req.path.startsWith('/api/')) {
      return res.status(503).json({ success: false, error: 'maintenance', message: DB.settings.maintenance_msg });
    }
  }
  next();
});

// ============================================================
// AUTH MIDDLEWARE
// ============================================================
function requireAdmin(req, res, next) {
  const key = req.headers['x-admin-key'] || req.body?.adminKey;
  if (key !== ADMIN_KEY) return res.status(403).json({ success: false, error: 'Unauthorized' });
  next();
}

function getUser(phone) {
  return DB.users[phone] || null;
}

// ============================================================
// AUTH ROUTES
// ============================================================
app.post('/api/auth/login', (req, res) => {
  const ip = req.ip || req.connection.remoteAddress;
  if (!rateLimit('login:'+ip, 5, 60000)) {
    return res.status(429).json({ success: false, error: 'Terlalu banyak percobaan. Tunggu 1 menit.' });
  }

  const { phone, password } = req.body;
  if (!phone || !password) return res.status(400).json({ success: false, error: 'Nomor dan password wajib diisi.' });

  const cleanPhone = sanitize(String(phone)).replace(/\D/g, '');
  if (!cleanPhone || cleanPhone.length < 6) return res.status(400).json({ success: false, error: 'Nomor tidak valid.' });

  if (password !== '043011') return res.status(401).json({ success: false, error: 'Password salah.' });

  let user = DB.users[cleanPhone];
  if (!user) {
    user = {
      id: genId('u'),
      phone: cleanPhone,
      status: 'free',
      banned: false,
      limit_used: 0,
      limit_reset: Date.now() + 86400000,
      created_at: Date.now(),
      apikeys: {}
    };
    DB.users[cleanPhone] = user;
    saveDB(DB);
  }

  if (user.banned) return res.status(403).json({ success: false, error: 'Akun Anda dibanned.' });

  const token = genId('tok');
  user.token = token;
  user.last_login = Date.now();
  saveDB(DB);

  res.json({
    success: true,
    token,
    user: {
      id: user.id,
      phone: user.phone,
      status: user.status,
      limit_used: user.limit_used,
      limit_reset: user.limit_reset,
      apikeys: user.apikeys
    }
  });
});

app.post('/api/auth/verify', (req, res) => {
  const { token } = req.body;
  if (!token) return res.status(401).json({ success: false, error: 'Token tidak ada.' });
  const user = Object.values(DB.users).find(u => u.token === token);
  if (!user) return res.status(401).json({ success: false, error: 'Token tidak valid.' });
  if (user.banned) return res.status(403).json({ success: false, error: 'Akun dibanned.' });
  res.json({
    success: true,
    user: {
      id: user.id,
      phone: user.phone,
      status: user.status,
      limit_used: user.limit_used,
      limit_reset: user.limit_reset,
      apikeys: user.apikeys
    }
  });
});

// ============================================================
// API KEY ROUTES
// ============================================================
app.post('/api/apikey/generate', (req, res) => {
  const { token, type } = req.body;
  if (!token || !type) return res.status(400).json({ success: false, error: 'Token dan type wajib.' });
  
  const validTypes = ['reaction', 'downloader', 'hd'];
  if (!validTypes.includes(type)) return res.status(400).json({ success: false, error: 'Tipe tidak valid.' });
  
  const user = Object.values(DB.users).find(u => u.token === token);
  if (!user) return res.status(401).json({ success: false, error: 'Token tidak valid.' });
  if (user.banned) return res.status(403).json({ success: false, error: 'Akun dibanned.' });

  const apikey = 'ak_' + type + '_' + crypto.randomBytes(16).toString('hex');
  
  if (!DB.apikeys[apikey]) {
    DB.apikeys[apikey] = {
      key: apikey,
      type,
      owner: user.id,
      owner_phone: user.phone,
      created_at: Date.now(),
      used: 0,
      limit: getLimit(user.status),
      status: user.status
    };
    
    if (!user.apikeys) user.apikeys = {};
    user.apikeys[type] = apikey;
    saveDB(DB);
  }

  res.json({ success: true, apikey, type, limit: DB.apikeys[apikey].limit });
});

function getLimit(status) {
  if (status === 'vip') return DB.settings.vip_limit;
  if (status === 'pro') return DB.settings.pro_limit;
  return DB.settings.free_limit;
}

function getEmojiLimit(status) {
  if (status === 'vip') return DB.settings.vip_emoji_limit;
  if (status === 'pro') return DB.settings.pro_emoji_limit;
  return DB.settings.free_emoji_limit;
}

function getReactionMax(status) {
  if (status === 'vip') return DB.settings.reaction_vip_max;
  if (status === 'pro') return DB.settings.reaction_pro_max;
  return DB.settings.reaction_free_max;
}

// ============================================================
// REACTION API
// ============================================================
app.post('/api/reaction', async (req, res) => {
  const { apikey, channel_link, emojis } = req.body;
  if (!apikey || !channel_link || !emojis) {
    return res.status(400).json({ success: false, error: 'apikey, channel_link, emojis wajib.' });
  }

  const keyData = DB.apikeys[sanitize(apikey)];
  if (!keyData) return res.status(401).json({ success: false, error: 'API Key tidak valid.' });
  if (keyData.type !== 'reaction') return res.status(403).json({ success: false, error: 'API Key bukan tipe reaction.' });

  const owner = Object.values(DB.users).find(u => u.id === keyData.owner);
  if (!owner || owner.banned) return res.status(403).json({ success: false, error: 'Akun tidak aktif atau dibanned.' });

  // Limit check
  const now = Date.now();
  if (owner.limit_reset < now) {
    owner.limit_used = 0;
    owner.limit_reset = now + 86400000;
  }

  const maxLimit = getLimit(owner.status);
  if (owner.limit_used >= maxLimit) {
    return res.status(429).json({ success: false, error: `Limit habis (${owner.limit_used}/${maxLimit}). Reset: ${new Date(owner.limit_reset).toLocaleString('id-ID')}` });
  }

  // Emoji limit check
  const emojiArr = Array.isArray(emojis) ? emojis : [emojis];
  const maxEmojis = getEmojiLimit(owner.status);
  if (emojiArr.length > maxEmojis) {
    return res.status(400).json({ success: false, error: `Maksimal ${maxEmojis} emoji untuk status ${owner.status}.` });
  }

  // Max reaction per request
  const maxReaction = getReactionMax(owner.status);

  // Find available bot
  const availableBot = Object.values(DB.bots).find(b => b.connected && b.active);
  if (!availableBot) {
    return res.status(503).json({ success: false, error: 'Tidak ada bot aktif. Hubungi admin.' });
  }

  // Process reaction
  const botInstance = activeBots[availableBot.number];
  if (!botInstance || !botInstance.sock) {
    return res.status(503).json({ success: false, error: 'Bot tidak tersedia saat ini.' });
  }

  try {
    // Extract channel JID from link
    let channelJid = sanitize(channel_link);
    // Convert link to JID format if needed: https://whatsapp.com/channel/XXXX -> newsletter JID
    if (channelJid.includes('whatsapp.com/channel/')) {
      const code = channelJid.split('/channel/')[1]?.split('?')[0];
      channelJid = code + '@newsletter';
    } else if (!channelJid.includes('@newsletter')) {
      channelJid = channelJid + '@newsletter';
    }

    owner.limit_used++;
    keyData.used++;
    DB.request_log.unshift({
      id: genId('req'),
      time: Date.now(),
      type: 'reaction',
      owner_phone: owner.phone,
      channel: channel_link,
      emojis: emojiArr,
      bot: availableBot.number,
      status: 'success'
    });
    if (DB.request_log.length > 500) DB.request_log = DB.request_log.slice(0, 500);
    saveDB(DB);

    // Emit real-time update
    io.emit('stats:update', getStatsData());

    res.json({
      success: true,
      message: 'Reaction berhasil dikirim.',
      detail: {
        channel: channel_link,
        emojis: emojiArr,
        bot: availableBot.number,
        limit: `${owner.limit_used}/${maxLimit}`,
        remaining: maxLimit - owner.limit_used
      }
    });

    // Send reaction async (after response)
    setImmediate(async () => {
      try {
        const sock = botInstance.sock;
        // Get latest message in channel
        const msgs = await sock.fetchMessagesFromWA(channelJid, 1);
        if (msgs && msgs.length > 0) {
          const msg = msgs[0];
          for (const emoji of emojiArr.slice(0, maxReaction)) {
            await sock.sendMessage(channelJid, { react: { text: emoji, key: msg.key } });
            await new Promise(r => setTimeout(r, 500));
          }
        }
      } catch (e) {
        console.error('Reaction error:', e.message);
      }
    });

  } catch (e) {
    DB.request_log.unshift({
      id: genId('req'),
      time: Date.now(),
      type: 'reaction',
      owner_phone: owner.phone,
      channel: channel_link,
      status: 'failed',
      error: e.message
    });
    saveDB(DB);
    res.status(500).json({ success: false, error: 'Gagal memproses reaction: ' + e.message });
  }
});

// ============================================================
// DOWNLOADER API
// ============================================================
app.post('/api/download', async (req, res) => {
  const { apikey, url } = req.body;
  if (!apikey || !url) return res.status(400).json({ success: false, error: 'apikey dan url wajib.' });

  const keyData = DB.apikeys[sanitize(apikey)];
  if (!keyData || keyData.type !== 'downloader') return res.status(401).json({ success: false, error: 'API Key tidak valid atau bukan tipe downloader.' });

  const owner = Object.values(DB.users).find(u => u.id === keyData.owner);
  if (!owner || owner.banned) return res.status(403).json({ success: false, error: 'Akun tidak aktif.' });

  const now = Date.now();
  if (owner.limit_reset < now) { owner.limit_used = 0; owner.limit_reset = now + 86400000; }
  const maxLimit = getLimit(owner.status);
  if (owner.limit_used >= maxLimit) return res.status(429).json({ success: false, error: `Limit habis (${owner.limit_used}/${maxLimit}).` });

  owner.limit_used++;
  keyData.used++;
  saveDB(DB);

  // Mock download response (real integration: use yt-dlp or similar)
  res.json({
    success: true,
    message: 'Download berhasil diproses.',
    data: {
      url: sanitize(url),
      title: 'Video dari ' + new URL(sanitize(url)).hostname,
      download_url: sanitize(url),
      quality: '720p',
      limit: `${owner.limit_used}/${maxLimit}`
    }
  });
});

// ============================================================
// HD IMAGE API
// ============================================================
app.post('/api/hd', async (req, res) => {
  const { apikey, image_url } = req.body;
  if (!apikey || !image_url) return res.status(400).json({ success: false, error: 'apikey dan image_url wajib.' });

  const keyData = DB.apikeys[sanitize(apikey)];
  if (!keyData || keyData.type !== 'hd') return res.status(401).json({ success: false, error: 'API Key tidak valid atau bukan tipe hd.' });

  const owner = Object.values(DB.users).find(u => u.id === keyData.owner);
  if (!owner || owner.banned) return res.status(403).json({ success: false, error: 'Akun tidak aktif.' });

  const now = Date.now();
  if (owner.limit_reset < now) { owner.limit_used = 0; owner.limit_reset = now + 86400000; }
  const maxLimit = getLimit(owner.status);
  if (owner.limit_used >= maxLimit) return res.status(429).json({ success: false, error: `Limit habis (${owner.limit_used}/${maxLimit}).` });

  owner.limit_used++;
  keyData.used++;
  saveDB(DB);

  res.json({
    success: true,
    message: 'Gambar HD berhasil diproses.',
    data: {
      original: sanitize(image_url),
      hd_url: sanitize(image_url) + '?upscale=4x',
      resolution: '4K',
      limit: `${owner.limit_used}/${maxLimit}`
    }
  });
});

// ============================================================
// STATUS / INFO
// ============================================================
app.get('/api/status', (req, res) => {
  const totalBots = Object.keys(DB.bots).length;
  const activeBotCount = Object.values(DB.bots).filter(b => b.connected && b.active).length;
  res.json({
    success: true,
    maintenance: DB.settings.maintenance,
    maintenance_msg: DB.settings.maintenance_msg,
    bots: { total: totalBots, active: activeBotCount },
    timestamp: Date.now()
  });
});

app.get('/api/user/info', (req, res) => {
  const token = req.headers['x-token'] || req.query.token;
  if (!token) return res.status(401).json({ success: false, error: 'Token wajib.' });
  const user = Object.values(DB.users).find(u => u.token === token);
  if (!user) return res.status(401).json({ success: false, error: 'Token tidak valid.' });
  
  const now = Date.now();
  if (user.limit_reset < now) { user.limit_used = 0; user.limit_reset = now + 86400000; saveDB(DB); }
  
  res.json({
    success: true,
    user: {
      id: user.id,
      phone: user.phone,
      status: user.status,
      banned: user.banned,
      limit_used: user.limit_used,
      limit_max: getLimit(user.status),
      limit_reset: user.limit_reset,
      emoji_limit: getEmojiLimit(user.status),
      reaction_max: getReactionMax(user.status),
      apikeys: user.apikeys || {},
      delay_seconds: DB.settings.delay_seconds
    }
  });
});

// ============================================================
// ADMIN ROUTES
// ============================================================
app.post('/api/admin/login', (req, res) => {
  const { key } = req.body;
  if (key !== ADMIN_KEY) return res.status(403).json({ success: false, error: 'Admin key salah.' });
  res.json({ success: true, token: ADMIN_KEY });
});

app.get('/api/admin/stats', requireAdmin, (req, res) => {
  res.json({ success: true, data: getStatsData() });
});

function getStatsData() {
  const totalUsers = Object.keys(DB.users).length;
  const bannedUsers = Object.values(DB.users).filter(u => u.banned).length;
  const totalBots = Object.keys(DB.bots).length;
  const activeBots2 = Object.values(DB.bots).filter(b => b.connected && b.active).length;
  const reactionRequests = DB.request_log.filter(r => r.type === 'reaction').length;
  return {
    users: { total: totalUsers, banned: bannedUsers },
    bots: { total: totalBots, active: activeBots2 },
    requests: { reaction: reactionRequests, total: DB.request_log.length },
    settings: DB.settings,
    recent_logs: DB.request_log.slice(0, 20)
  };
}

app.get('/api/admin/users', requireAdmin, (req, res) => {
  res.json({ success: true, users: Object.values(DB.users).map(u => ({
    id: u.id, phone: u.phone, status: u.status, banned: u.banned,
    limit_used: u.limit_used, limit_reset: u.limit_reset, created_at: u.created_at,
    last_login: u.last_login
  }))});
});

app.post('/api/admin/user/status', requireAdmin, (req, res) => {
  const { phone, status } = req.body;
  const validStatuses = ['free', 'pro', 'vip'];
  if (!phone || !validStatuses.includes(status)) return res.status(400).json({ success: false, error: 'Data tidak valid.' });
  const user = DB.users[sanitize(phone)];
  if (!user) return res.status(404).json({ success: false, error: 'User tidak ditemukan.' });
  user.status = status;
  saveDB(DB);
  io.emit('user:status_changed', { phone, status });
  res.json({ success: true, message: `Status user berhasil diubah ke ${status}.` });
});

app.post('/api/admin/user/ban', requireAdmin, (req, res) => {
  const { phone, ban } = req.body;
  if (!phone) return res.status(400).json({ success: false, error: 'Nomor wajib.' });
  const user = DB.users[sanitize(phone)];
  if (!user) return res.status(404).json({ success: false, error: 'User tidak ditemukan.' });
  user.banned = !!ban;
  saveDB(DB);
  if (ban) io.emit('force:banned', { phone });
  else io.emit('force:unbanned', { phone });
  res.json({ success: true, message: ban ? 'User dibanned.' : 'User di-unban.' });
});

app.post('/api/admin/user/limit', requireAdmin, (req, res) => {
  const { phone, limit } = req.body;
  if (!phone || limit === undefined) return res.status(400).json({ success: false, error: 'Data tidak valid.' });
  const user = DB.users[sanitize(phone)];
  if (!user) return res.status(404).json({ success: false, error: 'User tidak ditemukan.' });
  user.limit_used = parseInt(limit) || 0;
  saveDB(DB);
  res.json({ success: true, message: 'Limit user berhasil diatur.' });
});

app.post('/api/admin/settings', requireAdmin, (req, res) => {
  const allowed = ['free_limit','pro_limit','vip_limit','free_emoji_limit','pro_emoji_limit',
    'vip_emoji_limit','delay_seconds','maintenance','maintenance_msg',
    'reaction_free_max','reaction_pro_max','reaction_vip_max'];
  const { key, value } = req.body;
  if (!allowed.includes(key)) return res.status(400).json({ success: false, error: 'Key tidak valid.' });
  DB.settings[key] = value;
  saveDB(DB);
  io.emit('settings:updated', DB.settings);
  if (key === 'maintenance') {
    io.emit('system:maintenance', { enabled: value, message: DB.settings.maintenance_msg });
  }
  res.json({ success: true, message: 'Setting disimpan.' });
});

app.get('/api/admin/bots', requireAdmin, (req, res) => {
  res.json({ success: true, bots: Object.values(DB.bots) });
});

app.post('/api/admin/bot/delete', requireAdmin, (req, res) => {
  const { number } = req.body;
  if (!number) return res.status(400).json({ success: false, error: 'Nomor wajib.' });
  const cleanNumber = sanitize(number);
  
  // Disconnect bot
  if (activeBots[cleanNumber]) {
    try { activeBots[cleanNumber].sock?.end(); } catch(e) {}
    delete activeBots[cleanNumber];
  }
  
  // Remove session
  const sessionPath = path.join(SESSIONS_DIR, cleanNumber);
  if (fs.existsSync(sessionPath)) {
    try { fs.rmSync(sessionPath, { recursive: true }); } catch(e) {}
  }
  
  delete DB.bots[cleanNumber];
  saveDB(DB);
  io.emit('bot:disconnected', { number: cleanNumber });
  io.emit('stats:update', getStatsData());
  res.json({ success: true, message: 'Bot dihapus.' });
});

app.post('/api/admin/bot/toggle', requireAdmin, (req, res) => {
  const { number, active } = req.body;
  if (!number) return res.status(400).json({ success: false, error: 'Nomor wajib.' });
  const bot = DB.bots[sanitize(number)];
  if (!bot) return res.status(404).json({ success: false, error: 'Bot tidak ditemukan.' });
  bot.active = !!active;
  saveDB(DB);
  io.emit('bot:status', { number: bot.number, active: bot.active, connected: bot.connected });
  res.json({ success: true, message: active ? 'Bot diaktifkan.' : 'Bot dinonaktifkan.' });
});

// ============================================================
// BOT CONNECTION — WhatsApp Baileys
// ============================================================
const activeBots = {};
const pendingConnections = {};

app.post('/api/bot/connect', async (req, res) => {
  const adminKey = req.headers['x-admin-key'];
  if (adminKey !== ADMIN_KEY) return res.status(403).json({ success: false, error: 'Unauthorized.' });

  const { number, method } = req.body; // method: 'qr' or 'pairing'
  if (!number) return res.status(400).json({ success: false, error: 'Nomor wajib.' });
  
  const cleanNumber = sanitize(number).replace(/\D/g, '');
  if (!cleanNumber || cleanNumber.length < 8) return res.status(400).json({ success: false, error: 'Nomor tidak valid.' });

  // If already connecting, return pending
  if (pendingConnections[cleanNumber]) {
    return res.json({ success: true, status: 'connecting', message: 'Koneksi sedang diproses.' });
  }

  pendingConnections[cleanNumber] = true;
  
  try {
    await startBot(cleanNumber, method || 'qr', res);
  } catch (e) {
    delete pendingConnections[cleanNumber];
    res.status(500).json({ success: false, error: 'Gagal memulai bot: ' + e.message });
  }
});

async function startBot(number, method, res) {
  const sessionPath = path.join(SESSIONS_DIR, number);
  if (!fs.existsSync(sessionPath)) fs.mkdirSync(sessionPath, { recursive: true });

  const { state, saveCreds } = await useMultiFileAuthState(sessionPath);
  const { version } = await fetchLatestBaileysVersion();

  const sock = makeWASocket({
    version,
    auth: state,
    logger: pino({ level: 'silent' }),
    printQRInTerminal: false,
    browser: ['WA Bot', 'Chrome', '1.0.0'],
    syncFullHistory: false,
    generateHighQualityLinkPreview: false
  });

  let responseSent = false;

  // QR Code handler
  sock.ev.on('connection.update', async (update) => {
    const { connection, lastDisconnect, qr } = update;

    if (qr && method === 'qr') {
      try {
        const qrDataUrl = await QRCode.toDataURL(qr, { width: 280, margin: 2 });
        if (!responseSent) {
          responseSent = true;
          res.json({ success: true, status: 'qr', qr: qrDataUrl, number });
        }
        // Also emit via socket for real-time
        io.emit('bot:qr', { number, qr: qrDataUrl });
      } catch(e) {}
    }

    if (qr && method === 'pairing' && !responseSent) {
      // Request pairing code
      try {
        const code = await sock.requestPairingCode(number);
        responseSent = true;
        res.json({ success: true, status: 'pairing', code, number });
        io.emit('bot:pairing_code', { number, code });
      } catch(e) {
        if (!responseSent) {
          responseSent = true;
          res.status(500).json({ success: false, error: 'Gagal mendapat pairing code.' });
        }
      }
    }

    if (connection === 'close') {
      delete pendingConnections[number];
      const shouldReconnect = (lastDisconnect?.error instanceof Boom) &&
        lastDisconnect.error.output?.statusCode !== DisconnectReason.loggedOut;

      if (DB.bots[number]) {
        DB.bots[number].connected = false;
        saveDB(DB);
      }
      io.emit('bot:status', { number, connected: false, active: false });
      io.emit('stats:update', getStatsData());

      if (shouldReconnect && activeBots[number]) {
        setTimeout(() => startBotSilent(number), 5000);
      } else {
        delete activeBots[number];
      }
    }

    if (connection === 'open') {
      delete pendingConnections[number];
      activeBots[number] = { sock, number };

      if (!DB.bots[number]) {
        DB.bots[number] = { number, connected: true, active: true, added_at: Date.now() };
      } else {
        DB.bots[number].connected = true;
      }
      saveDB(DB);

      io.emit('bot:connected', { number, connected: true });
      io.emit('stats:update', getStatsData());

      if (!responseSent) {
        responseSent = true;
        res.json({ success: true, status: 'connected', number });
      }
    }
  });

  sock.ev.on('creds.update', saveCreds);
  sock.ev.on('messages.upsert', () => {}); // placeholder
}

async function startBotSilent(number) {
  try {
    const sessionPath = path.join(SESSIONS_DIR, number);
    if (!fs.existsSync(sessionPath)) return;

    const { state, saveCreds } = await useMultiFileAuthState(sessionPath);
    const { version } = await fetchLatestBaileysVersion();

    const sock = makeWASocket({
      version, auth: state,
      logger: pino({ level: 'silent' }),
      printQRInTerminal: false,
      browser: ['WA Bot', 'Chrome', '1.0.0']
    });

    sock.ev.on('connection.update', (update) => {
      const { connection, lastDisconnect } = update;
      if (connection === 'close') {
        if (DB.bots[number]) { DB.bots[number].connected = false; saveDB(DB); }
        io.emit('bot:status', { number, connected: false });
        delete activeBots[number];
      }
      if (connection === 'open') {
        activeBots[number] = { sock, number };
        if (DB.bots[number]) { DB.bots[number].connected = true; saveDB(DB); }
        io.emit('bot:status', { number, connected: true });
        io.emit('stats:update', getStatsData());
      }
    });
    sock.ev.on('creds.update', saveCreds);
  } catch(e) {}
}

// Restore bots on startup
(async function restoreBotsOnStart() {
  await new Promise(r => setTimeout(r, 2000));
  for (const [number, botData] of Object.entries(DB.bots)) {
    if (botData.active) {
      const sessionPath = path.join(SESSIONS_DIR, number);
      if (fs.existsSync(sessionPath)) {
        try { await startBotSilent(number); } catch(e) {}
        await new Promise(r => setTimeout(r, 1000));
      }
    }
  }
})();

// ============================================================
// SOCKET.IO
// ============================================================
io.on('connection', (socket) => {
  // Send current status on connect
  socket.emit('stats:update', getStatsData());
  socket.emit('settings:updated', DB.settings);
  socket.emit('system:maintenance', {
    enabled: DB.settings.maintenance,
    message: DB.settings.maintenance_msg
  });

  // Bot list for dashboard
  socket.emit('bot:list', Object.values(DB.bots));

  socket.on('admin:join', (key) => {
    if (key === ADMIN_KEY) socket.join('admins');
  });
});

// Broadcast admin events only to admin room
function emitAdmin(event, data) {
  io.to('admins').emit(event, data);
}

// ============================================================
// SERVE HTML FILES
// ============================================================
app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'index.html')));
app.get('/admin', (req, res) => res.sendFile(path.join(__dirname, 'admin.html')));

// ============================================================
// START
// ============================================================
server.listen(PORT, () => {
  console.log(`✅ Server berjalan di port ${PORT}`);
  console.log(`🔑 Admin Key: ${ADMIN_KEY}`);
});
