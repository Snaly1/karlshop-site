require('dotenv').config();
const express   = require('express');
const helmet    = require('helmet');
const cors      = require('cors');
const rateLimit = require('express-rate-limit');
const jwt       = require('jsonwebtoken');
const bcrypt    = require('bcrypt');
const { Pool }  = require('pg');
const crypto    = require('crypto');
const Joi       = require('joi');
const path      = require('path');

const app  = express();
const PORT = process.env.PORT || 3000;

// ══════════════════════════════════════════
//  DATABASE
// ══════════════════════════════════════════
const db = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_URL ? { rejectUnauthorized: false } : false
});

async function initDB() {
  await db.query(`
    CREATE TABLE IF NOT EXISTS products (
      id           SERIAL PRIMARY KEY,
      name         TEXT          NOT NULL,
      cat          TEXT          NOT NULL DEFAULT 'General',
      price        NUMERIC(10,2) NOT NULL,
      status       TEXT          NOT NULL DEFAULT 'available',
      icon         TEXT          NOT NULL DEFAULT '🔑',
      instructions TEXT          NOT NULL DEFAULT '',
      created_at   TIMESTAMPTZ   DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS license_keys (
      id          SERIAL  PRIMARY KEY,
      product_id  INTEGER REFERENCES products(id) ON DELETE CASCADE,
      key_value   TEXT    NOT NULL,
      used        BOOLEAN NOT NULL DEFAULT FALSE,
      used_at     TIMESTAMPTZ,
      order_id    TEXT,
      created_at  TIMESTAMPTZ DEFAULT NOW(),
      UNIQUE(product_id, key_value)
    );

    CREATE TABLE IF NOT EXISTS orders (
      id            SERIAL PRIMARY KEY,
      payment_id    TEXT   NOT NULL UNIQUE,
      product_id    INTEGER REFERENCES products(id),
      status        TEXT   NOT NULL DEFAULT 'waiting',
      delivered_key TEXT,
      delivered_at  TIMESTAMPTZ,
      ip_hash       TEXT,
      created_at    TIMESTAMPTZ DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS webhook_log (
      id          SERIAL PRIMARY KEY,
      payment_id  TEXT,
      status      TEXT,
      received_at TIMESTAMPTZ DEFAULT NOW()
    );
  `);
  console.log('✅ Database ready');
}

// ══════════════════════════════════════════
//  SECURITY MIDDLEWARE
// ══════════════════════════════════════════

// Helmet — security headers
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc:  ["'self'", "'unsafe-inline'"],
      styleSrc:   ["'self'", "'unsafe-inline'", 'https://fonts.googleapis.com'],
      fontSrc:    ["'self'", 'https://fonts.gstatic.com'],
      imgSrc:     ["'self'", 'data:'],
      connectSrc: ["'self'"],
    }
  },
  crossOriginEmbedderPolicy: false
}));

// CORS
app.use(cors({
  origin: process.env.FRONTEND_URL || '*',
  methods: ['GET','POST','PUT','DELETE'],
  allowedHeaders: ['Content-Type','Authorization','x-nowpayments-sig']
}));

// Rate limit global — 60 req/min/IP
app.use(rateLimit({
  windowMs: 60 * 1000, max: 60,
  standardHeaders: true, legacyHeaders: false,
  message: { error: 'Too many requests.' }
}));

// Rate limit login — 5 tentatives/15min
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, max: 5,
  skipSuccessfulRequests: true,
  message: { error: 'Too many login attempts. Try again in 15 minutes.' }
});

// Rate limit paiements — 10/heure/IP
const paymentLimiter = rateLimit({
  windowMs: 60 * 60 * 1000, max: 10,
  message: { error: 'Too many payment attempts.' }
});

// Raw body pour signature webhook
app.use('/webhook', express.raw({ type: '*/*' }));
// JSON body max 10kb
app.use(express.json({ limit: '10kb' }));
// Frontend static
app.use(express.static(path.join(__dirname, '../public')));

// ══════════════════════════════════════════
//  HELPERS
// ══════════════════════════════════════════

function hashIP(ip) {
  return crypto.createHash('sha256')
    .update((ip || '') + (process.env.IP_SALT || 'ks-salt'))
    .digest('hex').substring(0, 16);
}

function verifyIPN(body, signature) {
  if (!signature) return false;
  const secret = process.env.NOWPAYMENTS_IPN_SECRET;
  if (!secret) return false;
  try {
    const hmac = crypto.createHmac('sha512', secret);
    hmac.update(Buffer.isBuffer(body) ? body : Buffer.from(body));
    const computed = hmac.digest('hex');
    const sigBuf  = Buffer.from(signature.toLowerCase(), 'hex');
    const compBuf = Buffer.from(computed.toLowerCase(), 'hex');
    if (sigBuf.length !== compBuf.length) return false;
    return crypto.timingSafeEqual(sigBuf, compBuf);
  } catch { return false; }
}

// Validation schemas
const schemas = {
  login: Joi.object({
    password: Joi.string().min(1).max(100).required()
  }),
  payment: Joi.object({
    productId: Joi.number().integer().positive().required(),
    currency:  Joi.string().alphanum().min(2).max(10).required()
  }),
  product: Joi.object({
    name:         Joi.string().min(1).max(200).required(),
    cat:          Joi.string().min(1).max(100).default('General'),
    price:        Joi.number().positive().max(9999).required(),
    status:       Joi.string().valid('available','new','limited','sold').default('available'),
    icon:         Joi.string().max(8).default('🔑'),
    instructions: Joi.string().max(2000).allow('').default('')
  }),
  keys: Joi.object({
    keys: Joi.array().items(Joi.string().min(1).max(200)).min(1).max(500).required()
  })
};

function validate(schema) {
  return (req, res, next) => {
    const { error, value } = schema.validate(req.body, { abortEarly: false, stripUnknown: true });
    if (error) return res.status(400).json({ error: error.details.map(d => d.message).join(', ') });
    req.body = value;
    next();
  };
}

// ══════════════════════════════════════════
//  AUTH — JWT
// ══════════════════════════════════════════
const JWT_SECRET = process.env.JWT_SECRET || crypto.randomBytes(64).toString('hex');

app.post('/api/admin/login', loginLimiter, validate(schemas.login), async (req, res) => {
  const { password } = req.body;
  const adminHash = process.env.ADMIN_PASSWORD_HASH;
  let valid = false;
  try {
    if (adminHash) {
      valid = await bcrypt.compare(password, adminHash);
    } else {
      valid = password === process.env.ADMIN_PASSWORD;
    }
  } catch { valid = false; }

  if (!valid) {
    await new Promise(r => setTimeout(r, 600 + Math.random() * 400));
    return res.status(401).json({ error: 'Invalid password' });
  }

  const token = jwt.sign({ role: 'admin' }, JWT_SECRET, { expiresIn: '8h' });
  res.json({ token, expiresIn: 28800 });
});

function adminAuth(req, res, next) {
  const auth = req.headers.authorization || '';
  if (!auth.startsWith('Bearer ')) return res.status(401).json({ error: 'Missing token' });
  try {
    const payload = jwt.verify(auth.slice(7), JWT_SECRET);
    if (payload.role !== 'admin') throw new Error();
    next();
  } catch {
    return res.status(401).json({ error: 'Invalid or expired token' });
  }
}

// ══════════════════════════════════════════
//  SHOP API
// ══════════════════════════════════════════

app.get('/api/products', async (req, res) => {
  try {
    const { rows } = await db.query(`
      SELECT p.id, p.name, p.cat, p.price, p.status, p.icon,
             COUNT(k.id) FILTER (WHERE k.used = FALSE) AS stock
      FROM products p
      LEFT JOIN license_keys k ON k.product_id = p.id
      GROUP BY p.id ORDER BY p.id
    `);
    res.json(rows.map(r => ({ ...r, stock: parseInt(r.stock) || 0 })));
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/api/payment', paymentLimiter, validate(schemas.payment), async (req, res) => {
  const { productId, currency } = req.body;
  try {
    const { rows: [product] } = await db.query('SELECT * FROM products WHERE id=$1', [productId]);
    if (!product) return res.status(404).json({ error: 'Product not found' });

    const { rows: [{ count }] } = await db.query(
      'SELECT COUNT(*) FROM license_keys WHERE product_id=$1 AND used=FALSE', [productId]
    );
    if (parseInt(count) === 0) return res.status(400).json({ error: 'Out of stock' });

    const resp = await fetch('https://api.nowpayments.io/v1/payment', {
      method: 'POST',
      headers: { 'x-api-key': process.env.NOWPAYMENTS_API_KEY, 'Content-Type': 'application/json' },
      body: JSON.stringify({
        price_amount:   product.price,
        price_currency: 'usd',
        pay_currency:   currency.toLowerCase(),
        order_id:       `ks-${productId}-${Date.now()}`,
        order_description: product.name,
        ipn_callback_url: `${process.env.FRONTEND_URL}/webhook/nowpayments`
      })
    });
    const data = await resp.json();
    if (!resp.ok) return res.status(500).json({ error: 'Payment creation failed' });

    await db.query(
      'INSERT INTO orders (payment_id, product_id, status, ip_hash) VALUES ($1,$2,$3,$4)',
      [String(data.payment_id), productId, 'waiting', hashIP(req.ip)]
    );

    res.json({
      paymentId:   data.payment_id,
      payAddress:  data.pay_address,
      payAmount:   data.pay_amount,
      payCurrency: data.pay_currency,
      expiresAt:   data.expiration_estimate_date
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Server error' });
  }
});

app.get('/api/order/:paymentId', async (req, res) => {
  const pid = req.params.paymentId.replace(/[^a-zA-Z0-9\-_]/g, '').substring(0, 100);
  try {
    const { rows: [order] } = await db.query(`
      SELECT o.status, o.delivered_key, o.delivered_at,
             p.instructions, p.name AS product_name
      FROM orders o JOIN products p ON p.id = o.product_id
      WHERE o.payment_id = $1
    `, [pid]);
    if (!order) return res.status(404).json({ error: 'Order not found' });

    const done = order.status === 'finished' || order.status === 'confirmed';
    res.json({
      status:       order.status,
      deliveredKey: done ? order.delivered_key : null,
      instructions: done ? order.instructions  : null,
      productName:  order.product_name
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Server error' });
  }
});

// ══════════════════════════════════════════
//  WEBHOOK
// ══════════════════════════════════════════
app.post('/webhook/nowpayments', async (req, res) => {
  const sig = req.headers['x-nowpayments-sig'];
  if (!verifyIPN(req.body, sig)) {
    console.warn('[Webhook] Bad signature');
    return res.status(400).send('Invalid signature');
  }

  let payload;
  try { payload = JSON.parse(req.body.toString()); }
  catch { return res.status(400).send('Invalid JSON'); }

  const { payment_id, payment_status } = payload;
  console.log(`[Webhook] ${payment_id} → ${payment_status}`);

  await db.query('INSERT INTO webhook_log (payment_id, status) VALUES ($1,$2)', [String(payment_id), payment_status]).catch(() => {});

  try {
    const { rows: [order] } = await db.query('SELECT * FROM orders WHERE payment_id=$1', [String(payment_id)]);
    if (!order) return res.status(200).send('OK');

    await db.query('UPDATE orders SET status=$1 WHERE payment_id=$2', [payment_status, String(payment_id)]);

    if ((payment_status === 'finished' || payment_status === 'confirmed') && !order.delivered_key) {
      // Transaction atomique — évite les doubles livraisons
      const { rows: [keyRow] } = await db.query(`
        UPDATE license_keys SET used=TRUE, used_at=NOW(), order_id=$1
        WHERE id=(
          SELECT id FROM license_keys
          WHERE product_id=$2 AND used=FALSE
          LIMIT 1 FOR UPDATE SKIP LOCKED
        )
        RETURNING key_value
      `, [String(payment_id), order.product_id]);

      if (keyRow) {
        await db.query(
          'UPDATE orders SET delivered_key=$1, delivered_at=NOW() WHERE payment_id=$2',
          [keyRow.key_value, String(payment_id)]
        );
        console.log(`[Delivery] ✅ Key sent for ${payment_id}`);
      } else {
        console.error(`[Delivery] ❌ No key for product ${order.product_id}`);
      }
    }
  } catch (err) { console.error('[Webhook] Error:', err); }

  res.status(200).send('OK');
});

// ══════════════════════════════════════════
//  ADMIN API
// ══════════════════════════════════════════

app.get('/api/admin/products', adminAuth, async (req, res) => {
  const { rows } = await db.query(`
    SELECT p.*,
      COUNT(k.id) FILTER (WHERE k.used=FALSE) AS available_keys,
      COUNT(k.id) AS total_keys,
      COUNT(k.id) FILTER (WHERE k.used=TRUE) AS used_keys
    FROM products p
    LEFT JOIN license_keys k ON k.product_id=p.id
    GROUP BY p.id ORDER BY p.id
  `);
  res.json(rows.map(r => ({ ...r, available_keys: parseInt(r.available_keys)||0, total_keys: parseInt(r.total_keys)||0, used_keys: parseInt(r.used_keys)||0 })));
});

app.post('/api/admin/products', adminAuth, validate(schemas.product), async (req, res) => {
  const { name, cat, price, status, icon, instructions } = req.body;
  const { rows: [p] } = await db.query(
    'INSERT INTO products (name,cat,price,status,icon,instructions) VALUES ($1,$2,$3,$4,$5,$6) RETURNING *',
    [name, cat, price, status, icon, instructions]
  );
  res.json(p);
});

app.put('/api/admin/products/:id', adminAuth, validate(schemas.product), async (req, res) => {
  const id = parseInt(req.params.id);
  if (isNaN(id)) return res.status(400).json({ error: 'Invalid id' });
  const { name, cat, price, status, icon, instructions } = req.body;
  const { rows: [p] } = await db.query(
    'UPDATE products SET name=$1,cat=$2,price=$3,status=$4,icon=$5,instructions=$6 WHERE id=$7 RETURNING *',
    [name, cat, price, status, icon, instructions, id]
  );
  if (!p) return res.status(404).json({ error: 'Not found' });
  res.json(p);
});

app.delete('/api/admin/products/:id', adminAuth, async (req, res) => {
  const id = parseInt(req.params.id);
  if (isNaN(id)) return res.status(400).json({ error: 'Invalid id' });
  await db.query('DELETE FROM products WHERE id=$1', [id]);
  res.json({ ok: true });
});

app.get('/api/admin/keys/:productId', adminAuth, async (req, res) => {
  const pid = parseInt(req.params.productId);
  if (isNaN(pid)) return res.status(400).json({ error: 'Invalid id' });
  const { rows } = await db.query(
    'SELECT id, key_value, used, used_at, order_id FROM license_keys WHERE product_id=$1 ORDER BY id', [pid]
  );
  res.json(rows);
});

app.post('/api/admin/keys/:productId', adminAuth, validate(schemas.keys), async (req, res) => {
  const pid = parseInt(req.params.productId);
  if (isNaN(pid)) return res.status(400).json({ error: 'Invalid id' });
  let added = 0, dupes = 0;
  for (const k of req.body.keys) {
    const trimmed = k.trim();
    if (!trimmed) continue;
    try {
      await db.query('INSERT INTO license_keys (product_id, key_value) VALUES ($1,$2)', [pid, trimmed]);
      added++;
    } catch (e) {
      if (e.code === '23505') dupes++;
      else throw e;
    }
  }
  res.json({ added, dupes });
});

app.delete('/api/admin/keys/:id', adminAuth, async (req, res) => {
  const id = parseInt(req.params.id);
  if (isNaN(id)) return res.status(400).json({ error: 'Invalid id' });
  const { rowCount } = await db.query('DELETE FROM license_keys WHERE id=$1 AND used=FALSE', [id]);
  if (rowCount === 0) return res.status(400).json({ error: 'Key not found or already used' });
  res.json({ ok: true });
});

app.get('/api/admin/orders', adminAuth, async (req, res) => {
  const { rows } = await db.query(`
    SELECT o.payment_id, o.status, o.delivered_key, o.delivered_at, o.created_at,
           p.name AS product_name
    FROM orders o LEFT JOIN products p ON p.id=o.product_id
    ORDER BY o.created_at DESC LIMIT 200
  `);
  res.json(rows);
});

// Health check
app.get('/health', (req, res) => res.json({ status: 'ok', ts: Date.now() }));

// Error handler global
app.use((err, req, res, next) => {
  console.error(err);
  res.status(500).json({ error: 'Internal server error' });
});

// ── START ──
initDB().then(() => {
  app.listen(PORT, () => console.log(`✅ KarlShop secure server on port ${PORT}`));
}).catch(err => {
  console.error('DB init failed:', err);
  process.exit(1);
});
