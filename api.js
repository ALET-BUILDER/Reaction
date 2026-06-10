// ============================================================
// api.js — Client-side API handler
// ============================================================

const API_BASE = window.location.origin;

async function apiRequest(endpoint, method = 'GET', body = null, headers = {}) {
  const opts = {
    method,
    headers: { 'Content-Type': 'application/json', ...headers }
  };
  if (body) opts.body = JSON.stringify(body);
  try {
    const res = await fetch(API_BASE + endpoint, opts);
    const data = await res.json();
    return { ok: res.ok, status: res.status, data };
  } catch (e) {
    return { ok: false, status: 0, data: { success: false, error: 'Koneksi gagal: ' + e.message } };
  }
}

// ─── Auth ───────────────────────────────────────────────────
async function login(phone, password) {
  return apiRequest('/api/auth/login', 'POST', { phone, password });
}

async function verifyToken(token) {
  return apiRequest('/api/auth/verify', 'POST', { token });
}

async function getUserInfo(token) {
  return apiRequest('/api/user/info', 'GET', null, { 'x-token': token });
}

// ─── API Key ─────────────────────────────────────────────────
async function generateApiKey(token, type) {
  return apiRequest('/api/apikey/generate', 'POST', { token, type });
}

// ─── Reaction ────────────────────────────────────────────────
async function sendReaction(apikey, channel_link, emojis) {
  return apiRequest('/api/reaction', 'POST', { apikey, channel_link, emojis });
}

// ─── Downloader ──────────────────────────────────────────────
async function downloadMedia(apikey, url) {
  return apiRequest('/api/download', 'POST', { apikey, url });
}

// ─── HD Image ────────────────────────────────────────────────
async function enhanceHD(apikey, image_url) {
  return apiRequest('/api/hd', 'POST', { apikey, image_url });
}

// ─── Status ──────────────────────────────────────────────────
async function getStatus() {
  return apiRequest('/api/status', 'GET');
}

// ─── Admin ───────────────────────────────────────────────────
async function adminLogin(key) {
  return apiRequest('/api/admin/login', 'POST', { key });
}

async function adminGetStats(key) {
  return apiRequest('/api/admin/stats', 'GET', null, { 'x-admin-key': key });
}

async function adminGetUsers(key) {
  return apiRequest('/api/admin/users', 'GET', null, { 'x-admin-key': key });
}

async function adminSetUserStatus(key, phone, status) {
  return apiRequest('/api/admin/user/status', 'POST', { phone, status }, { 'x-admin-key': key });
}

async function adminBanUser(key, phone, ban) {
  return apiRequest('/api/admin/user/ban', 'POST', { phone, ban }, { 'x-admin-key': key });
}

async function adminSetLimit(key, phone, limit) {
  return apiRequest('/api/admin/user/limit', 'POST', { phone, limit }, { 'x-admin-key': key });
}

async function adminSaveSetting(key, settingKey, value) {
  return apiRequest('/api/admin/settings', 'POST', { key: settingKey, value }, { 'x-admin-key': key });
}

async function adminGetBots(key) {
  return apiRequest('/api/admin/bots', 'GET', null, { 'x-admin-key': key });
}

async function adminConnectBot(key, number, method) {
  return apiRequest('/api/bot/connect', 'POST', { number, method }, { 'x-admin-key': key });
}

async function adminDeleteBot(key, number) {
  return apiRequest('/api/admin/bot/delete', 'POST', { number }, { 'x-admin-key': key });
}

async function adminToggleBot(key, number, active) {
  return apiRequest('/api/admin/bot/toggle', 'POST', { number, active }, { 'x-admin-key': key });
}

// ─── Export ───────────────────────────────────────────────────
window.API = {
  login, verifyToken, getUserInfo,
  generateApiKey,
  sendReaction, downloadMedia, enhanceHD,
  getStatus,
  admin: {
    login: adminLogin,
    getStats: adminGetStats,
    getUsers: adminGetUsers,
    setUserStatus: adminSetUserStatus,
    banUser: adminBanUser,
    setLimit: adminSetLimit,
    saveSetting: adminSaveSetting,
    getBots: adminGetBots,
    connectBot: adminConnectBot,
    deleteBot: adminDeleteBot,
    toggleBot: adminToggleBot
  }
};
