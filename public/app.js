// ── KarlShop Shared JS ──
const API = '';
const DISCORD_URL = 'https://discord.gg/karlshop';

const POPULAR_CRYPTOS = [
  { id:'btc',  label:'BTC',  icon:'₿' },
  { id:'eth',  label:'ETH',  icon:'Ξ' },
  { id:'usdt', label:'USDT', icon:'₮' },
  { id:'ltc',  label:'LTC',  icon:'Ł' },
  { id:'sol',  label:'SOL',  icon:'◎' },
  { id:'bnb',  label:'BNB',  icon:'⬡' },
  { id:'trx',  label:'TRX',  icon:'◈' },
  { id:'doge', label:'DOGE', icon:'Ð' },
];

const BG = [
  'linear-gradient(135deg,#0d1520,#0a1a2e)',
  'linear-gradient(135deg,#150d20,#1a0a2e)',
  'linear-gradient(135deg,#0d1520,#112010)',
  'linear-gradient(135deg,#201510,#2e1a0a)',
  'linear-gradient(135deg,#0a1020,#102030)',
  'linear-gradient(135deg,#1a0a1a,#2e0a2e)',
];

const BADGE = {
  available: { cls:'green',  label:'In stock' },
  new:       { cls:'purple', label:'New' },
  limited:   { cls:'cyan',   label:'Limited' },
  sold:      { cls:'red',    label:'Sold out' }
};

// ── UTILS ──
function esc(s) { return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;'); }

function showToast(msg, type = '') {
  const t = document.getElementById('toast');
  if (!t) return;
  t.textContent = msg;
  t.className = 'toast' + (type ? ' ' + type : '');
  t.classList.add('show');
  clearTimeout(t._timer);
  t._timer = setTimeout(() => t.classList.remove('show'), 3200);
}

function openOverlay(id) { document.getElementById(id)?.classList.add('open'); }
function closeOverlay(id) { document.getElementById(id)?.classList.remove('open'); }

// ── AUTH (JWT) ──
let adminToken = null;

function getToken() { return adminToken || sessionStorage.getItem('ks_token'); }
function setToken(t) { adminToken = t; sessionStorage.setItem('ks_token', t); }
function clearToken() { adminToken = null; sessionStorage.removeItem('ks_token'); }
function authHeaders() { return { 'Authorization': `Bearer ${getToken()}`, 'Content-Type': 'application/json' }; }

function openLogin() {
  openOverlay('login-overlay');
  setTimeout(() => document.getElementById('pwd-input')?.focus(), 200);
}

async function tryLogin() {
  const pwd = document.getElementById('pwd-input').value;
  if (!pwd) return;
  const btn = document.querySelector('#login-overlay .btn-primary');
  if (btn) { btn.disabled = true; btn.textContent = 'Signing in...'; }
  try {
    const res = await fetch(`${API}/api/admin/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ password: pwd })
    });
    const data = await res.json();
    if (res.ok && data.token) {
      setToken(data.token);
      closeOverlay('login-overlay');
      document.getElementById('pwd-input').value = '';
      window.location.href = '/admin.html';
    } else {
      document.getElementById('pwd-input').value = '';
      showToast('⚠ ' + (data.error || 'Wrong password'), 'error');
    }
  } catch { showToast('⚠ Server error', 'error'); }
  finally { if (btn) { btn.disabled = false; btn.textContent = 'Sign in'; } }
}

function logout() {
  clearToken();
  window.location.href = '/';
}

// ── PAYMENT STATE ──
let pollInterval = null;
let timerInterval = null;
let selectedCrypto = null;
let currentProductId = null;

function openPayment(productId, productName) {
  currentProductId = productId;
  selectedCrypto = null;
  document.getElementById('pm-product').textContent = productName;
  document.getElementById('pm-step-currency').style.display = 'block';
  document.getElementById('pm-step-pay').style.display = 'none';
  document.getElementById('pm-step-done').style.display = 'none';
  document.getElementById('pm-pay-btn').disabled = true;
  openOverlay('payment-overlay');
  renderCryptoGrid();
}

function renderCryptoGrid() {
  const grid = document.getElementById('crypto-grid');
  if (!grid) return;
  grid.innerHTML = POPULAR_CRYPTOS.map(c => `
    <div class="crypto-btn" id="crypto-${c.id}" onclick="selectCrypto('${c.id}')">
      <span class="crypto-icon">${c.icon}</span>${c.label}
    </div>`).join('');
}

function selectCrypto(id) {
  selectedCrypto = id;
  document.querySelectorAll('.crypto-btn').forEach(b => b.classList.remove('selected'));
  document.getElementById(`crypto-${id}`)?.classList.add('selected');
  document.getElementById('pm-pay-btn').disabled = false;
}

async function createPayment() {
  if (!selectedCrypto || !currentProductId) return;
  const btn = document.getElementById('pm-pay-btn');
  btn.disabled = true; btn.textContent = 'Creating...';
  try {
    const res = await fetch(`${API}/api/payment`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ productId: currentProductId, currency: selectedCrypto })
    });
    const data = await res.json();
    if (!res.ok) { showToast('⚠ ' + (data.error || 'Error'), 'error'); btn.disabled = false; btn.textContent = 'Pay now'; return; }
    showPayStep(data);
  } catch { showToast('⚠ Server error', 'error'); btn.disabled = false; btn.textContent = 'Pay now'; }
}

function showPayStep(data) {
  document.getElementById('pm-step-currency').style.display = 'none';
  document.getElementById('pm-step-pay').style.display = 'block';
  document.getElementById('pm-amount').textContent = `${data.payAmount} ${data.payCurrency.toUpperCase()}`;
  document.getElementById('pm-address').textContent = data.payAddress;
  document.getElementById('pm-dot').className = 'status-dot waiting';
  document.getElementById('pm-status-text').textContent = 'Waiting for payment...';
  let seconds = 20 * 60;
  clearInterval(timerInterval);
  timerInterval = setInterval(() => { seconds--; const el = document.getElementById('pm-timer'); if (el) el.style.width = (seconds / 1200 * 100) + '%'; if (seconds <= 0) clearInterval(timerInterval); }, 1000);
  clearInterval(pollInterval);
  pollInterval = setInterval(() => pollPayment(data.paymentId), 8000);
}

async function pollPayment(paymentId) {
  try {
    const res = await fetch(`${API}/api/order/${paymentId}`);
    const data = await res.json();
    const dot = document.getElementById('pm-dot');
    const txt = document.getElementById('pm-status-text');
    if (data.status === 'confirming') { dot.className = 'status-dot waiting'; txt.textContent = 'Confirming on blockchain...'; }
    else if (data.status === 'finished' || data.status === 'confirmed') { clearInterval(pollInterval); clearInterval(timerInterval); showDelivery(data); }
    else if (data.status === 'failed' || data.status === 'expired') { clearInterval(pollInterval); clearInterval(timerInterval); dot.className = 'status-dot failed'; txt.textContent = 'Payment failed or expired.'; }
  } catch {}
}

function showDelivery(data) {
  document.getElementById('pm-step-pay').style.display = 'none';
  document.getElementById('pm-step-done').style.display = 'block';
  document.getElementById('pm-key').textContent = data.deliveredKey;
  const instBox = document.getElementById('pm-inst-box');
  if (data.instructions) { document.getElementById('pm-inst-text').textContent = data.instructions; instBox.style.display = 'block'; }
  else { instBox.style.display = 'none'; }
}

function copyAddress() { navigator.clipboard.writeText(document.getElementById('pm-address').textContent).then(() => showToast('✓ Address copied!', 'success')); }
function copyKey() { navigator.clipboard.writeText(document.getElementById('pm-key').textContent).then(() => showToast('✓ Key copied!', 'success')); }
function cancelPayment() { clearInterval(pollInterval); clearInterval(timerInterval); closeOverlay('payment-overlay'); }
