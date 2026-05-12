require('dotenv').config();
const express = require('express');
const cors = require('cors');
const crypto = require('crypto');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;

// ── MIDDLEWARE ──
app.use(cors());
app.use(express.static(path.join(__dirname, '../public')));

// Raw body for IPN signature verification
app.use('/webhook', express.raw({ type: '*/*' }));
app.use(express.json());

// ── IN-MEMORY STORE (remplace par une DB plus tard) ──
// Structure: { products: [], keys: {}, orders: [], nextId: N }
let store = {
  products: [
    {
      id: 1,
      name: 'Windows 11 Pro',
      cat: 'Operating System',
      price: 9.99,
      status: 'available',
      icon: '🪟',
      instructions: '1. Open Settings → System → Activation\n2. Click "Change product key"\n3. Enter your key and click Next\n4. Follow on-screen instructions to activate.'
    },
    {
      id: 2,
      name: 'Microsoft Office 365',
      cat: 'Productivity',
      price: 14.99,
      status: 'new',
      icon: '📦',
      instructions: '1. Visit office.com/setup\n2. Sign in or create a Microsoft account\n3. Enter your product key\n4. Download and install Office.'
    },
    {
      id: 3,
      name: 'Malwarebytes Premium',
      cat: 'Security',
      price: 7.99,
      status: 'limited',
      icon: '🛡️',
      instructions: '1. Download Malwarebytes from malwarebytes.com\n2. Install and open the app\n3. Go to Settings → Account\n4. Enter your license key to activate.'
    }
  ],
  keys: {
    1: [],
    2: [],
    3: []
  },
  orders: [],
  nextId: 4
};

// ── HELPERS ──
function availableKeys(pid) {
  return (store.keys[pid] || []).filter(k => !k.used);
}

function verifyIPN(body, signature) {
  const secret = process.env.NOWPAYMENTS_IPN_SECRET;
  const hmac = crypto.createHmac('sha512', secret);
  hmac.update(Buffer.isBuffer(body) ? body : Buffer.from(body));
  const computed = hmac.digest('hex');
  return computed === signature;
}

// ── AUTH MIDDLEWARE ──
function adminAuth(req, res, next) {
  const pwd = req.headers['x-admin-password'];
  if (pwd !== process.env.ADMIN_PASSWORD) {
    return res.status(401).json({ error: 'Unauthorized' });
  }
  next();
}

// ══════════════════════════════
//  SHOP API
// ══════════════════════════════

// GET /api/products — liste des produits avec stock dispo
app.get('/api/products', (req, res) => {
  const products = store.products.map(p => ({
    ...p,
    stock: availableKeys(p.id).length
  }));
  res.json(products);
});

// POST /api/payment — créer un paiement NOWPayments
app.post('/api/payment', async (req, res) => {
  const { productId, currency } = req.body;
  if (!productId || !currency) {
    return res.status(400).json({ error: 'Missing productId or currency' });
  }

  const product = store.products.find(p => p.id === parseInt(productId));
  if (!product) return res.status(404).json({ error: 'Product not found' });

  const keys = availableKeys(product.id);
  if (keys.length === 0) return res.status(400).json({ error: 'Out of stock' });

  try {
    const response = await fetch('https://api.nowpayments.io/v1/payment', {
      method: 'POST',
      headers: {
        'x-api-key': process.env.NOWPAYMENTS_API_KEY,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        price_amount: product.price,
        price_currency: 'usd',
        pay_currency: currency.toLowerCase(),
        order_id: `karlshop-${product.id}-${Date.now()}`,
        order_description: product.name,
        ipn_callback_url: `${process.env.FRONTEND_URL}/webhook/nowpayments`
      })
    });

    const data = await response.json();
    if (!response.ok) {
      console.error('NOWPayments error:', data);
      return res.status(500).json({ error: data.message || 'Payment creation failed' });
    }

    // Stocker la commande en attente
    store.orders.push({
      paymentId: data.payment_id,
      productId: product.id,
      status: 'waiting',
      createdAt: new Date().toISOString()
    });

    res.json({
      paymentId: data.payment_id,
      payAddress: data.pay_address,
      payAmount: data.pay_amount,
      payCurrency: data.pay_currency,
      paymentStatus: data.payment_status,
      expiresAt: data.expiration_estimate_date
    });

  } catch (err) {
    console.error('Payment error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// GET /api/payment/:id — vérifier statut d'un paiement
app.get('/api/payment/:id', async (req, res) => {
  try {
    const response = await fetch(`https://api.nowpayments.io/v1/payment/${req.params.id}`, {
      headers: { 'x-api-key': process.env.NOWPAYMENTS_API_KEY }
    });
    const data = await response.json();
    res.json(data);
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

// GET /api/currencies — liste des cryptos disponibles
app.get('/api/currencies', async (req, res) => {
  try {
    const response = await fetch('https://api.nowpayments.io/v1/currencies?fixed_rate=true', {
      headers: { 'x-api-key': process.env.NOWPAYMENTS_API_KEY }
    });
    const data = await response.json();
    // Filtrer les plus populaires en premier
    const popular = ['btc', 'eth', 'usdt', 'usdc', 'ltc', 'bnb', 'trx', 'doge', 'sol'];
    const currencies = (data.currencies || []);
    const sorted = [
      ...popular.filter(c => currencies.includes(c)),
      ...currencies.filter(c => !popular.includes(c)).slice(0, 20)
    ];
    res.json(sorted);
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

// ══════════════════════════════
//  WEBHOOK NOWPayments
// ══════════════════════════════
app.post('/webhook/nowpayments', (req, res) => {
  const signature = req.headers['x-nowpayments-sig'];
  if (!signature) return res.status(400).send('Missing signature');

  if (!verifyIPN(req.body, signature)) {
    console.warn('Invalid IPN signature');
    return res.status(400).send('Invalid signature');
  }

  let payload;
  try {
    payload = JSON.parse(req.body.toString());
  } catch {
    return res.status(400).send('Invalid JSON');
  }

  const { payment_id, payment_status, order_id } = payload;
  console.log(`[Webhook] Payment ${payment_id} → ${payment_status}`);

  // Mettre à jour la commande
  const order = store.orders.find(o => o.paymentId == payment_id);
  if (!order) return res.status(200).send('OK');

  order.status = payment_status;

  // Paiement confirmé → livrer la clé
  if (payment_status === 'finished' || payment_status === 'confirmed') {
    if (order.deliveredKey) {
      return res.status(200).send('OK'); // Déjà livré
    }

    const keyObj = availableKeys(order.productId)[0];
    if (!keyObj) {
      console.error(`No key available for product ${order.productId}`);
      return res.status(200).send('OK');
    }

    keyObj.used = true;
    keyObj.usedAt = new Date().toISOString();
    keyObj.orderId = payment_id;
    order.deliveredKey = keyObj.key;
    order.deliveredAt = new Date().toISOString();

    console.log(`[Delivery] Key delivered for payment ${payment_id}: ${keyObj.key}`);
  }

  res.status(200).send('OK');
});

// GET /api/order/:paymentId — récupérer la clé livrée après paiement
app.get('/api/order/:paymentId', (req, res) => {
  const order = store.orders.find(o => o.paymentId == req.params.paymentId);
  if (!order) return res.status(404).json({ error: 'Order not found' });

  const product = store.products.find(p => p.id === order.productId);

  res.json({
    status: order.status,
    deliveredKey: order.deliveredKey || null,
    instructions: order.deliveredKey ? product?.instructions : null,
    productName: product?.name
  });
});

// ══════════════════════════════
//  ADMIN API
// ══════════════════════════════

// GET /api/admin/products
app.get('/api/admin/products', adminAuth, (req, res) => {
  const products = store.products.map(p => ({
    ...p,
    totalKeys: (store.keys[p.id] || []).length,
    availableKeys: availableKeys(p.id).length,
    usedKeys: (store.keys[p.id] || []).filter(k => k.used).length
  }));
  res.json(products);
});

// POST /api/admin/products
app.post('/api/admin/products', adminAuth, (req, res) => {
  const { name, cat, price, status, icon, instructions } = req.body;
  if (!name || !price) return res.status(400).json({ error: 'Missing fields' });
  const id = store.nextId++;
  const product = { id, name, cat: cat || 'General', price: parseFloat(price), status: status || 'available', icon: icon || '🔑', instructions: instructions || '' };
  store.products.push(product);
  store.keys[id] = [];
  res.json(product);
});

// PUT /api/admin/products/:id
app.put('/api/admin/products/:id', adminAuth, (req, res) => {
  const id = parseInt(req.params.id);
  const p = store.products.find(x => x.id === id);
  if (!p) return res.status(404).json({ error: 'Not found' });
  const { name, cat, price, status, icon, instructions } = req.body;
  if (name) p.name = name;
  if (cat) p.cat = cat;
  if (price) p.price = parseFloat(price);
  if (status) p.status = status;
  if (icon) p.icon = icon;
  if (instructions !== undefined) p.instructions = instructions;
  res.json(p);
});

// DELETE /api/admin/products/:id
app.delete('/api/admin/products/:id', adminAuth, (req, res) => {
  const id = parseInt(req.params.id);
  store.products = store.products.filter(p => p.id !== id);
  delete store.keys[id];
  res.json({ ok: true });
});

// GET /api/admin/keys/:productId
app.get('/api/admin/keys/:productId', adminAuth, (req, res) => {
  const pid = parseInt(req.params.productId);
  res.json(store.keys[pid] || []);
});

// POST /api/admin/keys/:productId
app.post('/api/admin/keys/:productId', adminAuth, (req, res) => {
  const pid = parseInt(req.params.productId);
  const { keys } = req.body;
  if (!store.keys[pid]) store.keys[pid] = [];
  const existing = new Set(store.keys[pid].map(k => k.key));
  let added = 0, dupes = 0;
  (keys || []).forEach(k => {
    const trimmed = k.trim();
    if (!trimmed) return;
    if (existing.has(trimmed)) { dupes++; return; }
    store.keys[pid].push({ key: trimmed, used: false });
    existing.add(trimmed);
    added++;
  });
  res.json({ added, dupes });
});

// DELETE /api/admin/keys/:productId/:index
app.delete('/api/admin/keys/:productId/:index', adminAuth, (req, res) => {
  const pid = parseInt(req.params.productId);
  const idx = parseInt(req.params.index);
  if (!store.keys[pid]) return res.status(404).json({ error: 'Not found' });
  store.keys[pid].splice(idx, 1);
  res.json({ ok: true });
});

// GET /api/admin/orders
app.get('/api/admin/orders', adminAuth, (req, res) => {
  const orders = store.orders.map(o => ({
    ...o,
    productName: store.products.find(p => p.id === o.productId)?.name || 'Unknown'
  }));
  res.json(orders.reverse());
});

// ── START ──
app.listen(PORT, () => {
  console.log(`✅ KarlShop backend running on port ${PORT}`);
});
