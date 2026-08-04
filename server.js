const express = require('express');
const cors = require('cors');
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const cloudinary = require('cloudinary').v2;

const app = express();

// ═══ SECURITY ═══
// Helmet — HTTP security headers
const helmet = require('helmet');
app.use(helmet({ crossOriginResourcePolicy: { policy: 'cross-origin' } }));

// CORS — restrict to your domains only
const ALLOWED_ORIGINS = (process.env.ALLOWED_ORIGINS || '').split(',').filter(Boolean);
app.use(cors({
  origin: (origin, cb) => {
    if (!origin || ALLOWED_ORIGINS.length === 0 || ALLOWED_ORIGINS.includes(origin)) cb(null, true);
    else cb(null, true); // permisivo por ahora, cambiar a cb(new Error('CORS')) cuando configures
  },
  credentials: true
}));

app.use(express.json({ limit: '10mb' }));

// Rate limiting — prevent brute force + DDoS
const rateLimit = require('express-rate-limit');
app.use('/api/auth', rateLimit({ windowMs: 15 * 60 * 1000, max: 20, message: { error: 'Demasiados intentos, esperá 15 minutos' } }));
app.use('/api/', rateLimit({ windowMs: 1 * 60 * 1000, max: 200, message: { error: 'Demasiadas solicitudes, esperá un momento' } }));

// Trust proxy (Railway runs behind proxy)
app.set('trust proxy', 1);

const pool = new Pool({ connectionString: process.env.DATABASE_URL, ssl: { rejectUnauthorized: false } });
const SECRET = process.env.JWT_SECRET || 'su_secret_2025';

// Cloudinary config (falls back to local if not configured)
const useCloudinary = !!(process.env.CLOUDINARY_CLOUD_NAME && process.env.CLOUDINARY_API_KEY);
if (useCloudinary) {
  cloudinary.config({ cloud_name: process.env.CLOUDINARY_CLOUD_NAME, api_key: process.env.CLOUDINARY_API_KEY, api_secret: process.env.CLOUDINARY_API_SECRET });
  console.log('☁️ Cloudinary configured');
}

// Local fallback uploads directory
const uploadsDir = path.join(__dirname, 'uploads');
if (!fs.existsSync(uploadsDir)) fs.mkdirSync(uploadsDir, { recursive: true });
app.use('/uploads', express.static(uploadsDir));
const upload = multer({ storage: multer.memoryStorage(), limits: { fileSize: 5 * 1024 * 1024 } });

// Auth middleware — verifies JWT, checks token not revoked, verifies current role from DB
const crypto = require('crypto');
const hashToken = (t) => crypto.createHash('sha256').update(t).digest('hex').slice(0, 64);

const auth = (role) => async (req, res, next) => {
  try {
    const t = req.headers.authorization?.split(' ')[1];
    if (!t) return res.status(401).json({ error: 'Token requerido' });
    // Check if token is revoked
    const revoked = await pool.query('SELECT 1 FROM tokens_revocados WHERE token_hash=$1', [hashToken(t)]).catch(() => ({ rows: [] }));
    if (revoked.rows.length) return res.status(401).json({ error: 'Sesión cerrada. Ingresá de nuevo.' });
    const d = jwt.verify(t, SECRET);
    // Verify current role from DB (not just from token)
    if (role) {
      const { rows } = await pool.query('SELECT rol, activo FROM usuarios WHERE id=$1', [d.id]).catch(() => ({ rows: [] }));
      if (!rows[0] || !rows[0].activo) return res.status(401).json({ error: 'Cuenta desactivada' });
      if (role === 'admin' && rows[0].rol !== 'admin') return res.status(403).json({ error: 'Sin permiso' });
    }
    req.user = d; req._token = t; next();
  } catch { res.status(401).json({ error: 'Token inválido' }); }
};
const optionalAuth = (req, res, next) => {
  try { const t = req.headers.authorization?.split(' ')[1]; if (t) req.user = jwt.verify(t, SECRET); } catch {} next();
};

// ═══ AUTO-MIGRATE ═══
async function migrate() {
  const queries = [
    // Core tables (idempotent)
    `CREATE TABLE IF NOT EXISTS configuracion (clave VARCHAR(100) PRIMARY KEY, valor TEXT DEFAULT '')`,
    `CREATE TABLE IF NOT EXISTS secciones (id SERIAL PRIMARY KEY, nombre VARCHAR(200), slug VARCHAR(100) UNIQUE, descripcion TEXT DEFAULT '', imagen TEXT DEFAULT '', requiere_aprobacion BOOLEAN DEFAULT false, visible BOOLEAN DEFAULT true, orden INT DEFAULT 0)`,
    `CREATE TABLE IF NOT EXISTS listas_precio (id VARCHAR(50) PRIMARY KEY, nombre VARCHAR(200), multiplicador NUMERIC(10,4) DEFAULT 1, modo VARCHAR(20) DEFAULT 'porcentaje', color VARCHAR(20) DEFAULT '#2563eb', compra_minima NUMERIC(12,2) DEFAULT 0, promo_msg TEXT DEFAULT '')`,
    `CREATE TABLE IF NOT EXISTS usuarios (id SERIAL PRIMARY KEY, nombre VARCHAR(200), usuario VARCHAR(100) UNIQUE, password VARCHAR(200), rol VARCHAR(20) DEFAULT 'cliente', telefono VARCHAR(50) DEFAULT '', email VARCHAR(200) DEFAULT '', direccion TEXT DEFAULT '', nombre_fantasia VARCHAR(200) DEFAULT '', lista_precio_id VARCHAR(50) DEFAULT '', aprobado BOOLEAN DEFAULT false, activo BOOLEAN DEFAULT true, permisos TEXT DEFAULT '', notas_admin TEXT DEFAULT '', es_revendedor BOOLEAN DEFAULT false, descuento_revendedor NUMERIC(5,2) DEFAULT 0, created_at TIMESTAMP DEFAULT NOW())`,
    `CREATE TABLE IF NOT EXISTS productos (id SERIAL PRIMARY KEY, seccion_id INT, categoria VARCHAR(200) DEFAULT '', modelo VARCHAR(200) DEFAULT '', nombre VARCHAR(300) DEFAULT '', precio_base NUMERIC(12,2) DEFAULT 0, precio_original NUMERIC(12,2) DEFAULT 0, stock INT DEFAULT 0, stock_minimo INT DEFAULT 0, imagen TEXT DEFAULT '', notas TEXT DEFAULT '', compatibilidad TEXT DEFAULT '', descripcion TEXT DEFAULT '', sku VARCHAR(100) DEFAULT '', tipo VARCHAR(20) DEFAULT 'fisico', moneda VARCHAR(10) DEFAULT 'ARS', precio_oferta NUMERIC(12,2) DEFAULT 0, envio_gratis BOOLEAN DEFAULT false, visible BOOLEAN DEFAULT true, peso NUMERIC(8,2) DEFAULT 0, alto NUMERIC(8,2) DEFAULT 0, ancho NUMERIC(8,2) DEFAULT 0, largo NUMERIC(8,2) DEFAULT 0, created_at TIMESTAMP DEFAULT NOW())`,
    `CREATE TABLE IF NOT EXISTS precios_fijos (id SERIAL PRIMARY KEY, producto_id INT, lista_precio_id VARCHAR(50), precio_fijo NUMERIC(12,2), UNIQUE(producto_id, lista_precio_id))`,
    `CREATE TABLE IF NOT EXISTS historial_precios (id SERIAL PRIMARY KEY, producto_id INT, precio_anterior NUMERIC(12,2), precio_nuevo NUMERIC(12,2), usuario VARCHAR(100), created_at TIMESTAMP DEFAULT NOW())`,
    `CREATE TABLE IF NOT EXISTS pedidos (id SERIAL PRIMARY KEY, usuario_id INT, seccion_id INT, tipo VARCHAR(20) DEFAULT 'pedido', estado VARCHAR(30) DEFAULT 'pendiente', total NUMERIC(12,2) DEFAULT 0, subtotal NUMERIC(12,2) DEFAULT 0, descuento NUMERIC(12,2) DEFAULT 0, cupon_codigo VARCHAR(50) DEFAULT '', metodo_pago VARCHAR(100) DEFAULT '', notas TEXT DEFAULT '', datos_envio TEXT DEFAULT '', archivado BOOLEAN DEFAULT false, notificar_wa BOOLEAN DEFAULT true, created_at TIMESTAMP DEFAULT NOW(), updated_at TIMESTAMP DEFAULT NOW())`,
    `CREATE TABLE IF NOT EXISTS pedido_items (id SERIAL PRIMARY KEY, pedido_id INT REFERENCES pedidos(id), producto_id INT, categoria VARCHAR(200) DEFAULT '', modelo VARCHAR(200) DEFAULT '', nombre_producto VARCHAR(300) DEFAULT '', cantidad INT DEFAULT 1, precio_unitario NUMERIC(12,2) DEFAULT 0, precio_base NUMERIC(12,2) DEFAULT 0)`,
    `CREATE TABLE IF NOT EXISTS cupones (id SERIAL PRIMARY KEY, codigo VARCHAR(50) UNIQUE, tipo VARCHAR(20) DEFAULT 'porcentaje', valor NUMERIC(12,2) DEFAULT 0, secciones_ids TEXT DEFAULT '', categoria VARCHAR(200) DEFAULT '', uso_maximo INT DEFAULT 0, usos_actuales INT DEFAULT 0, monto_minimo NUMERIC(12,2) DEFAULT 0, metodo_pago VARCHAR(100) DEFAULT '', activo BOOLEAN DEFAULT true, fecha_desde DATE, fecha_hasta DATE, created_at TIMESTAMP DEFAULT NOW())`,
    `CREATE TABLE IF NOT EXISTS cupon_productos (id SERIAL PRIMARY KEY, cupon_id INT REFERENCES cupones(id) ON DELETE CASCADE, producto_id INT REFERENCES productos(id) ON DELETE CASCADE)`,
    `CREATE TABLE IF NOT EXISTS paginas_info (id SERIAL PRIMARY KEY, titulo VARCHAR(300), slug VARCHAR(100), contenido TEXT DEFAULT '', seccion_id INT, visible BOOLEAN DEFAULT true, orden INT DEFAULT 0, created_at TIMESTAMP DEFAULT NOW())`,
    `CREATE TABLE IF NOT EXISTS badges (id SERIAL PRIMARY KEY, icono VARCHAR(50) DEFAULT '⭐', texto VARCHAR(200), color VARCHAR(20) DEFAULT '#2563eb', visible BOOLEAN DEFAULT true, secciones_ids TEXT DEFAULT '', orden INT DEFAULT 0)`,
    `CREATE TABLE IF NOT EXISTS config_envio (id SERIAL PRIMARY KEY, seccion_id INT UNIQUE, metodo VARCHAR(30) DEFAULT 'manual', costo_fijo NUMERIC(12,2) DEFAULT 0, gratis_desde NUMERIC(12,2) DEFAULT 0, zonas JSONB DEFAULT '[]')`,
    `CREATE TABLE IF NOT EXISTS promociones (id SERIAL PRIMARY KEY, nombre VARCHAR(200), tipo VARCHAR(20) DEFAULT 'porcentaje', valor NUMERIC(12,2) DEFAULT 0, secciones_ids TEXT DEFAULT '', categoria VARCHAR(200) DEFAULT '', productos_ids TEXT DEFAULT '', activo BOOLEAN DEFAULT true, fecha_desde DATE, fecha_hasta DATE, created_at TIMESTAMP DEFAULT NOW())`,
    `CREATE TABLE IF NOT EXISTS popups (id SERIAL PRIMARY KEY, titulo VARCHAR(200), imagen TEXT DEFAULT '', url_destino TEXT DEFAULT '', secciones_ids TEXT DEFAULT '', activo BOOLEAN DEFAULT true, created_at TIMESTAMP DEFAULT NOW())`,
    `CREATE TABLE IF NOT EXISTS redes_sociales (id SERIAL PRIMARY KEY, tipo VARCHAR(50), url TEXT DEFAULT '', activo BOOLEAN DEFAULT true, orden INT DEFAULT 0)`,
    `CREATE TABLE IF NOT EXISTS menu_items (id SERIAL PRIMARY KEY, titulo VARCHAR(200), url TEXT DEFAULT '', tipo VARCHAR(30) DEFAULT 'link', visible BOOLEAN DEFAULT true, orden INT DEFAULT 0, seccion_id INT)`,
    `CREATE TABLE IF NOT EXISTS design_config (id SERIAL PRIMARY KEY, clave VARCHAR(100) UNIQUE, valor TEXT DEFAULT '')`,
    `CREATE TABLE IF NOT EXISTS metodos_pago (id SERIAL PRIMARY KEY, nombre VARCHAR(200), descripcion TEXT DEFAULT '', instrucciones TEXT DEFAULT '', icono VARCHAR(50) DEFAULT '💳', seccion_id INT, activo BOOLEAN DEFAULT true, orden INT DEFAULT 0)`,
    `CREATE TABLE IF NOT EXISTS producto_imagenes (id SERIAL PRIMARY KEY, producto_id INT REFERENCES productos(id) ON DELETE CASCADE, url TEXT NOT NULL, orden INT DEFAULT 0)`,
    `CREATE TABLE IF NOT EXISTS variantes (id SERIAL PRIMARY KEY, producto_id INT REFERENCES productos(id) ON DELETE CASCADE, nombre VARCHAR(200) DEFAULT '', valor VARCHAR(200) DEFAULT '', stock INT DEFAULT 0, precio_extra NUMERIC(12,2) DEFAULT 0)`,
    `CREATE TABLE IF NOT EXISTS slider_banners (id SERIAL PRIMARY KEY, titulo VARCHAR(300) DEFAULT '', imagen TEXT DEFAULT '', url_destino TEXT DEFAULT '', orden INT DEFAULT 0, activo BOOLEAN DEFAULT true)`,
    `CREATE TABLE IF NOT EXISTS favoritos (id SERIAL PRIMARY KEY, usuario_id INT REFERENCES usuarios(id) ON DELETE CASCADE, producto_id INT REFERENCES productos(id) ON DELETE CASCADE, created_at TIMESTAMP DEFAULT NOW(), UNIQUE(usuario_id, producto_id))`,
    `CREATE TABLE IF NOT EXISTS notificaciones_stock (id SERIAL PRIMARY KEY, producto_id INT REFERENCES productos(id) ON DELETE CASCADE, email VARCHAR(200), notificado BOOLEAN DEFAULT false, created_at TIMESTAMP DEFAULT NOW())`,
    `CREATE TABLE IF NOT EXISTS otp_codes (id SERIAL PRIMARY KEY, usuario_id INT REFERENCES usuarios(id) ON DELETE CASCADE, codigo VARCHAR(10), expira TIMESTAMP, usado BOOLEAN DEFAULT false)`,
    `CREATE TABLE IF NOT EXISTS tokens_revocados (id SERIAL PRIMARY KEY, token_hash VARCHAR(64) UNIQUE, expira TIMESTAMP, created_at TIMESTAMP DEFAULT NOW())`,
    `DO $$ BEGIN ALTER TABLE usuarios ADD COLUMN IF NOT EXISTS otp_activo BOOLEAN DEFAULT false; EXCEPTION WHEN OTHERS THEN NULL; END $$`,
    `CREATE INDEX IF NOT EXISTS idx_prod_img ON producto_imagenes(producto_id)`,
    `CREATE INDEX IF NOT EXISTS idx_variantes ON variantes(producto_id)`,
    `CREATE INDEX IF NOT EXISTS idx_favoritos ON favoritos(usuario_id)`,
    // Columns that might be missing on existing installations
    `DO $$ BEGIN ALTER TABLE productos ADD COLUMN IF NOT EXISTS descripcion TEXT DEFAULT ''; EXCEPTION WHEN OTHERS THEN NULL; END $$`,
    `DO $$ BEGIN ALTER TABLE productos ADD COLUMN IF NOT EXISTS sku VARCHAR(100) DEFAULT ''; EXCEPTION WHEN OTHERS THEN NULL; END $$`,
    `DO $$ BEGIN ALTER TABLE productos ADD COLUMN IF NOT EXISTS tipo VARCHAR(20) DEFAULT 'fisico'; EXCEPTION WHEN OTHERS THEN NULL; END $$`,
    `DO $$ BEGIN ALTER TABLE productos ADD COLUMN IF NOT EXISTS moneda VARCHAR(10) DEFAULT 'ARS'; EXCEPTION WHEN OTHERS THEN NULL; END $$`,
    `DO $$ BEGIN ALTER TABLE productos ADD COLUMN IF NOT EXISTS precio_oferta NUMERIC(12,2) DEFAULT 0; EXCEPTION WHEN OTHERS THEN NULL; END $$`,
    `DO $$ BEGIN ALTER TABLE productos ADD COLUMN IF NOT EXISTS envio_gratis BOOLEAN DEFAULT false; EXCEPTION WHEN OTHERS THEN NULL; END $$`,
    `DO $$ BEGIN ALTER TABLE productos ADD COLUMN IF NOT EXISTS visible BOOLEAN DEFAULT true; EXCEPTION WHEN OTHERS THEN NULL; END $$`,
    `DO $$ BEGIN ALTER TABLE productos ADD COLUMN IF NOT EXISTS peso NUMERIC(8,2) DEFAULT 0; EXCEPTION WHEN OTHERS THEN NULL; END $$`,
    `DO $$ BEGIN ALTER TABLE productos ADD COLUMN IF NOT EXISTS alto NUMERIC(8,2) DEFAULT 0; EXCEPTION WHEN OTHERS THEN NULL; END $$`,
    `DO $$ BEGIN ALTER TABLE productos ADD COLUMN IF NOT EXISTS ancho NUMERIC(8,2) DEFAULT 0; EXCEPTION WHEN OTHERS THEN NULL; END $$`,
    `DO $$ BEGIN ALTER TABLE productos ADD COLUMN IF NOT EXISTS largo NUMERIC(8,2) DEFAULT 0; EXCEPTION WHEN OTHERS THEN NULL; END $$`,
    `DO $$ BEGIN ALTER TABLE usuarios ADD COLUMN IF NOT EXISTS es_revendedor BOOLEAN DEFAULT false; EXCEPTION WHEN OTHERS THEN NULL; END $$`,
    `DO $$ BEGIN ALTER TABLE usuarios ADD COLUMN IF NOT EXISTS descuento_revendedor NUMERIC(5,2) DEFAULT 0; EXCEPTION WHEN OTHERS THEN NULL; END $$`,
    `DO $$ BEGIN ALTER TABLE badges ADD COLUMN IF NOT EXISTS secciones_ids TEXT DEFAULT ''; EXCEPTION WHEN OTHERS THEN NULL; END $$`,
    `DO $$ BEGIN ALTER TABLE pedidos ADD COLUMN IF NOT EXISTS notificar_wa BOOLEAN DEFAULT true; EXCEPTION WHEN OTHERS THEN NULL; END $$`,
    `DO $$ BEGIN ALTER TABLE pedidos ADD COLUMN IF NOT EXISTS subtotal NUMERIC(12,2) DEFAULT 0; EXCEPTION WHEN OTHERS THEN NULL; END $$`,
    `DO $$ BEGIN ALTER TABLE pedidos ADD COLUMN IF NOT EXISTS descuento NUMERIC(12,2) DEFAULT 0; EXCEPTION WHEN OTHERS THEN NULL; END $$`,
    `DO $$ BEGIN ALTER TABLE pedidos ADD COLUMN IF NOT EXISTS cupon_codigo VARCHAR(50) DEFAULT ''; EXCEPTION WHEN OTHERS THEN NULL; END $$`,
    `DO $$ BEGIN ALTER TABLE pedidos ADD COLUMN IF NOT EXISTS metodo_pago VARCHAR(100) DEFAULT ''; EXCEPTION WHEN OTHERS THEN NULL; END $$`,
    `DO $$ BEGIN ALTER TABLE pedidos ADD COLUMN IF NOT EXISTS datos_envio TEXT DEFAULT ''; EXCEPTION WHEN OTHERS THEN NULL; END $$`,
    // Missing columns that cause red errors on existing DBs
    `DO $$ BEGIN ALTER TABLE badges ADD COLUMN IF NOT EXISTS color VARCHAR(20) DEFAULT '#2563eb'; EXCEPTION WHEN OTHERS THEN NULL; END $$`,
    `DO $$ BEGIN ALTER TABLE cupones ADD COLUMN IF NOT EXISTS monto_minimo NUMERIC(12,2) DEFAULT 0; EXCEPTION WHEN OTHERS THEN NULL; END $$`,
    `DO $$ BEGIN ALTER TABLE cupones ADD COLUMN IF NOT EXISTS secciones_ids TEXT DEFAULT ''; EXCEPTION WHEN OTHERS THEN NULL; END $$`,
    `DO $$ BEGIN ALTER TABLE cupones ADD COLUMN IF NOT EXISTS productos_ids TEXT DEFAULT ''; EXCEPTION WHEN OTHERS THEN NULL; END $$`,
    `DO $$ BEGIN ALTER TABLE promociones ADD COLUMN IF NOT EXISTS activo BOOLEAN DEFAULT true; EXCEPTION WHEN OTHERS THEN NULL; END $$`,
    `DO $$ BEGIN ALTER TABLE promociones ADD COLUMN IF NOT EXISTS secciones_ids TEXT DEFAULT ''; EXCEPTION WHEN OTHERS THEN NULL; END $$`,
    `DO $$ BEGIN ALTER TABLE promociones ADD COLUMN IF NOT EXISTS productos_ids TEXT DEFAULT ''; EXCEPTION WHEN OTHERS THEN NULL; END $$`,
    `DO $$ BEGIN ALTER TABLE pedido_items ADD COLUMN IF NOT EXISTS categoria VARCHAR(200) DEFAULT ''; EXCEPTION WHEN OTHERS THEN NULL; END $$`,
    `DO $$ BEGIN ALTER TABLE pedido_items ADD COLUMN IF NOT EXISTS imagen TEXT DEFAULT ''; EXCEPTION WHEN OTHERS THEN NULL; END $$`,
    `DO $$ BEGIN ALTER TABLE pedido_items ADD COLUMN IF NOT EXISTS seccion_nombre VARCHAR(200) DEFAULT ''; EXCEPTION WHEN OTHERS THEN NULL; END $$`,
    `DO $$ BEGIN ALTER TABLE productos ADD COLUMN IF NOT EXISTS notas TEXT DEFAULT ''; EXCEPTION WHEN OTHERS THEN NULL; END $$`,
    `DO $$ BEGIN ALTER TABLE productos ADD COLUMN IF NOT EXISTS compatibilidad TEXT DEFAULT ''; EXCEPTION WHEN OTHERS THEN NULL; END $$`,
    `DO $$ BEGIN ALTER TABLE productos ADD COLUMN IF NOT EXISTS marca VARCHAR(200) DEFAULT ''; EXCEPTION WHEN OTHERS THEN NULL; END $$`,
    `DO $$ BEGIN ALTER TABLE productos ADD COLUMN IF NOT EXISTS modelo VARCHAR(200) DEFAULT ''; EXCEPTION WHEN OTHERS THEN NULL; END $$`,
    // Default social networks
    `INSERT INTO redes_sociales (tipo, url, activo, orden) VALUES ('facebook','',false,1),('instagram','',false,2),('tiktok','',false,3),('whatsapp_canal','',false,4),('whatsapp_grupo','',false,5) ON CONFLICT DO NOTHING`,
    // Default design config
    `INSERT INTO design_config (clave, valor) VALUES ('nombre_tienda','Mi Tienda'),('logo_url',''),('favicon_url',''),('plantilla','kicks'),('color_primario','#4A69E2'),('color_secundario','#232321'),('color_acento','#FFA52F'),('fuente','Archivo'),('footer_texto',''),('css_custom',''),('hero_titulo',''),('hero_subtitulo',''),('promo_banner',''),('whatsapp_numero',''),('whatsapp_mensaje','Hola, quiero consultar sobre un producto'),('confianza_1_icono','🚚'),('confianza_1_titulo','Envío a todo el país'),('confianza_1_sub','Andreani y más'),('confianza_2_icono','🔧'),('confianza_2_titulo','Repuestos de calidad'),('confianza_2_sub','Garantía incluida'),('confianza_3_icono','💬'),('confianza_3_titulo','Atención directa'),('confianza_3_sub','WhatsApp') ON CONFLICT (clave) DO NOTHING`,
    // Default badges (marketing pre-loaded)
    `INSERT INTO badges (icono, texto, visible, secciones_ids, orden) SELECT '🚚', 'Envío gratis en compras +$50.000', true, '', 1 WHERE NOT EXISTS (SELECT 1 FROM badges WHERE texto LIKE '%nvío gratis%')`,
    `INSERT INTO badges (icono, texto, visible, secciones_ids, orden) SELECT '🏪', 'Retiro por sucursal', true, '', 2 WHERE NOT EXISTS (SELECT 1 FROM badges WHERE texto LIKE '%etiro%')`,
    `INSERT INTO badges (icono, texto, visible, secciones_ids, orden) SELECT '💳', 'Hasta 6 cuotas sin interés', true, '', 3 WHERE NOT EXISTS (SELECT 1 FROM badges WHERE texto LIKE '%cuotas%')`,
    `INSERT INTO badges (icono, texto, visible, secciones_ids, orden) SELECT '🔒', 'Compra segura', true, '', 4 WHERE NOT EXISTS (SELECT 1 FROM badges WHERE texto LIKE '%segura%')`,
    `INSERT INTO badges (icono, texto, visible, secciones_ids, orden) SELECT '⚡', 'Despacho en 24hs', true, '', 5 WHERE NOT EXISTS (SELECT 1 FROM badges WHERE texto LIKE '%espacho%')`,
    // Indexes
    `CREATE INDEX IF NOT EXISTS idx_productos_seccion ON productos(seccion_id)`,
    `CREATE INDEX IF NOT EXISTS idx_productos_cat ON productos(categoria)`,
    `CREATE INDEX IF NOT EXISTS idx_pedidos_usuario ON pedidos(usuario_id)`,
    `CREATE INDEX IF NOT EXISTS idx_pedidos_seccion ON pedidos(seccion_id)`,
  ];
  for (const q of queries) { try { await pool.query(q); } catch (e) { console.log('Migration skip:', e.message.slice(0,80)); } }
  // Default admin
  const { rows } = await pool.query("SELECT 1 FROM usuarios WHERE usuario='admin'");
  if (!rows.length) {
    const hash = await bcrypt.hash('admin', 10);
    await pool.query("INSERT INTO usuarios (nombre,usuario,password,rol,aprobado,activo) VALUES ('Administrador','admin',$1,'admin',true,true)", [hash]);
  }
  console.log('✅ Migrations complete');
}

// ═══ HEALTH ═══
app.get('/api/health', (req, res) => res.json({ ok: true, ts: new Date().toISOString() }));

// ═══ DOLAR BLUE (auto from API) ═══
let dolarBlueCache = { valor: null, ts: 0 };
app.get('/api/dolar-blue', async (req, res) => {
  try {
    // Cache 15 min
    if (dolarBlueCache.valor && Date.now() - dolarBlueCache.ts < 15 * 60 * 1000) return res.json({ venta: dolarBlueCache.valor });
    const r = await fetch('https://dolarapi.com/v1/dolares/blue');
    if (r.ok) { const d = await r.json(); dolarBlueCache = { valor: d.venta, ts: Date.now() }; return res.json({ venta: d.venta }); }
    // Fallback: manual config
    const { rows } = await pool.query("SELECT valor FROM configuracion WHERE clave='dolar_blue'");
    res.json({ venta: rows[0]?.valor ? Number(rows[0].valor) : null });
  } catch (e) {
    const { rows } = await pool.query("SELECT valor FROM configuracion WHERE clave='dolar_blue'").catch(() => ({ rows: [] }));
    res.json({ venta: rows[0]?.valor ? Number(rows[0].valor) : null });
  }
});

// ═══ MAINTENANCE ═══
app.get('/api/maintenance-status', async (req, res) => {
  try {
    const { rows } = await pool.query("SELECT clave, valor FROM configuracion WHERE clave IN ('mantenimiento_activo','mantenimiento_mensaje','mantenimiento_countdown')");
    const cfg = {}; rows.forEach(r => cfg[r.clave] = r.valor);
    res.json({ activo: cfg.mantenimiento_activo === 'true', mensaje: cfg.mantenimiento_mensaje || '', countdown: cfg.mantenimiento_countdown || '' });
  } catch (e) { res.json({ activo: false }); }
});
app.post('/api/maintenance-mode', auth('admin'), async (req, res) => {
  try {
    const { activo, mensaje, countdown } = req.body;
    await pool.query("INSERT INTO configuracion (clave,valor) VALUES ('mantenimiento_activo',$1) ON CONFLICT (clave) DO UPDATE SET valor=$1", [activo ? 'true' : 'false']);
    await pool.query("INSERT INTO configuracion (clave,valor) VALUES ('mantenimiento_mensaje',$1) ON CONFLICT (clave) DO UPDATE SET valor=$1", [mensaje || '']);
    await pool.query("INSERT INTO configuracion (clave,valor) VALUES ('mantenimiento_countdown',$1) ON CONFLICT (clave) DO UPDATE SET valor=$1", [countdown || '']);
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ═══ AUTH ═══
// Resend for OTP emails
let resend = null;
if (process.env.RESEND_API_KEY) {
  const { Resend } = require('resend');
  resend = new Resend(process.env.RESEND_API_KEY);
  console.log('📧 Resend configured for OTP');
}

// Password strength validation
const validatePassword = (pw) => {
  if (!pw || pw.length < 8) return 'La contraseña debe tener al menos 8 caracteres';
  if (!/[A-Z]/.test(pw)) return 'La contraseña debe tener al menos una mayúscula';
  if (!/[0-9]/.test(pw)) return 'La contraseña debe tener al menos un número';
  return null;
};

// Login brute force tracking
const loginAttempts = {};
app.post('/api/login', async (req, res) => {
  try {
    const { usuario, password, otp_code } = req.body;
    if (!usuario || !password) return res.status(400).json({ error: 'Usuario y contraseña requeridos' });
    const ip = req.ip;
    const key = `${ip}_${usuario.toLowerCase()}`;
    if (loginAttempts[key] && loginAttempts[key].count >= 5 && Date.now() - loginAttempts[key].last < 15 * 60 * 1000) {
      return res.status(429).json({ error: 'Cuenta temporalmente bloqueada. Intentá en 15 minutos.' });
    }
    const { rows } = await pool.query('SELECT * FROM usuarios WHERE LOWER(usuario)=LOWER($1) AND activo=true', [usuario]);
    if (!rows[0]) {
      const { rows: pend } = await pool.query('SELECT * FROM usuarios WHERE LOWER(usuario)=LOWER($1) AND aprobado=false', [usuario]);
      if (pend[0]) return res.status(403).json({ error: 'Tu cuenta está pendiente de aprobación' });
      loginAttempts[key] = { count: (loginAttempts[key]?.count || 0) + 1, last: Date.now() };
      return res.status(401).json({ error: 'Usuario o contraseña incorrectos' });
    }
    const valid = await bcrypt.compare(password, rows[0].password);
    if (!valid) {
      loginAttempts[key] = { count: (loginAttempts[key]?.count || 0) + 1, last: Date.now() };
      return res.status(401).json({ error: 'Usuario o contraseña incorrectos' });
    }
    // 2FA check
    if (rows[0].otp_activo && resend) {
      if (!otp_code) {
        // Send OTP
        const code = Math.floor(100000 + Math.random() * 900000).toString();
        await pool.query('INSERT INTO otp_codes (usuario_id, codigo, expira) VALUES ($1,$2, NOW() + INTERVAL \'10 minutes\')', [rows[0].id, code]);
        const emailTo = rows[0].email;
        if (emailTo) {
          await resend.emails.send({ from: process.env.RESEND_FROM || 'noreply@resend.dev', to: emailTo, subject: 'Código de verificación', html: `<h2>Tu código: <strong>${code}</strong></h2><p>Expira en 10 minutos.</p>` });
        }
        return res.json({ requires_otp: true, message: 'Código enviado a tu email' });
      }
      // Verify OTP
      const { rows: otps } = await pool.query('SELECT * FROM otp_codes WHERE usuario_id=$1 AND codigo=$2 AND expira > NOW() AND usado=false ORDER BY id DESC LIMIT 1', [rows[0].id, otp_code]);
      if (!otps[0]) return res.status(401).json({ error: 'Código incorrecto o expirado' });
      await pool.query('UPDATE otp_codes SET usado=true WHERE id=$1', [otps[0].id]);
    }
    delete loginAttempts[key];
    const token = jwt.sign({ id: rows[0].id, rol: rows[0].rol, usuario: rows[0].usuario }, SECRET, { expiresIn: '7d' });
    res.json({ token, user: { ...rows[0], password: undefined } });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// Logout — revoke token
app.post('/api/logout', auth(), async (req, res) => {
  try {
    const decoded = jwt.decode(req._token);
    const expira = new Date(decoded.exp * 1000);
    await pool.query('INSERT INTO tokens_revocados (token_hash, expira) VALUES ($1,$2) ON CONFLICT DO NOTHING', [hashToken(req._token), expira]);
    // Cleanup expired revocations
    await pool.query('DELETE FROM tokens_revocados WHERE expira < NOW()').catch(() => {});
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// Refresh token
app.post('/api/refresh-token', auth(), async (req, res) => {
  try {
    const { rows } = await pool.query('SELECT id, rol, usuario, activo FROM usuarios WHERE id=$1', [req.user.id]);
    if (!rows[0] || !rows[0].activo) return res.status(401).json({ error: 'Cuenta desactivada' });
    // Revoke old token
    const decoded = jwt.decode(req._token);
    await pool.query('INSERT INTO tokens_revocados (token_hash, expira) VALUES ($1,$2) ON CONFLICT DO NOTHING', [hashToken(req._token), new Date(decoded.exp * 1000)]);
    const newToken = jwt.sign({ id: rows[0].id, rol: rows[0].rol, usuario: rows[0].usuario }, SECRET, { expiresIn: '7d' });
    res.json({ token: newToken });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// Toggle 2FA
app.put('/api/me/otp', auth(), async (req, res) => {
  try {
    const { activo } = req.body;
    await pool.query('UPDATE usuarios SET otp_activo=$1 WHERE id=$2', [activo, req.user.id]);
    res.json({ ok: true, otp_activo: activo });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/register', async (req, res) => {
  try { const { nombre, usuario, password, telefono, email, direccion, nombre_fantasia } = req.body;
    if (!usuario || usuario.length < 3) return res.status(400).json({ error: 'El usuario debe tener al menos 3 caracteres' });
    const pwError = validatePassword(password);
    if (pwError) return res.status(400).json({ error: pwError });
    const hash = await bcrypt.hash(password, 12);
    const { rows } = await pool.query('INSERT INTO usuarios (nombre,usuario,password,telefono,email,direccion,nombre_fantasia,aprobado,activo) VALUES ($1,$2,$3,$4,$5,$6,$7,false,false) RETURNING *',
      [nombre, usuario, hash, telefono || '', email || '', direccion || '', nombre_fantasia || '']);
    res.json(rows[0]);
  } catch (e) { res.status(400).json({ error: e.message.includes('duplicate') ? 'Ese usuario ya existe' : e.message }); }
});
app.get('/api/me', auth(), async (req, res) => {
  try { const { rows } = await pool.query('SELECT * FROM usuarios WHERE id=$1', [req.user.id]); res.json({ ...rows[0], password: undefined }); } catch (e) { res.status(500).json({ error: e.message }); }
});
app.put('/api/me', auth(), async (req, res) => {
  try { const { nombre, telefono, email, direccion, nombre_fantasia, password } = req.body;
    if (password) { const hash = await bcrypt.hash(password, 10); await pool.query('UPDATE usuarios SET nombre=$1,telefono=$2,email=$3,direccion=$4,nombre_fantasia=$5,password=$6,updated_at=NOW() WHERE id=$7', [nombre, telefono, email, direccion, nombre_fantasia || '', hash, req.user.id]); }
    else { await pool.query('UPDATE usuarios SET nombre=$1,telefono=$2,email=$3,direccion=$4,nombre_fantasia=$5,updated_at=NOW() WHERE id=$6', [nombre, telefono, email, direccion, nombre_fantasia || '', req.user.id]); }
    const { rows } = await pool.query('SELECT * FROM usuarios WHERE id=$1', [req.user.id]);
    res.json({ ...rows[0], password: undefined });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ═══ CONFIG ═══
app.get('/api/config', async (req, res) => { try { const { rows } = await pool.query('SELECT * FROM configuracion'); const cfg = {}; rows.forEach(r => cfg[r.clave] = r.valor); res.json(cfg); } catch (e) { res.status(500).json({ error: e.message }); } });
app.put('/api/config', auth('admin'), async (req, res) => {
  try { for (const [k, v] of Object.entries(req.body)) { await pool.query("INSERT INTO configuracion (clave,valor) VALUES ($1,$2) ON CONFLICT (clave) DO UPDATE SET valor=$2", [k, v]); } res.json({ ok: true }); } catch (e) { res.status(500).json({ error: e.message }); }
});

// ═══ LISTAS PRECIO ═══
app.get('/api/listas', async (req, res) => { try { const { rows } = await pool.query('SELECT * FROM listas_precio ORDER BY multiplicador'); res.json(rows); } catch (e) { res.status(500).json({ error: e.message }); } });
app.put('/api/listas', auth('admin'), async (req, res) => {
  try { const { listas } = req.body; for (const l of listas) { await pool.query('INSERT INTO listas_precio (id,nombre,multiplicador,modo,color,compra_minima,promo_msg) VALUES ($1,$2,$3,$4,$5,$6,$7) ON CONFLICT (id) DO UPDATE SET nombre=$2,multiplicador=$3,modo=$4,color=$5,compra_minima=$6,promo_msg=$7', [l.id, l.nombre, l.multiplicador, l.modo || 'porcentaje', l.color || '#2563eb', l.compra_minima || 0, l.promo_msg || '']); }
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});
app.post('/api/listas', auth('admin'), async (req, res) => {
  try { const l = req.body; const { rows } = await pool.query('INSERT INTO listas_precio (id,nombre,multiplicador,modo,color,compra_minima,promo_msg) VALUES ($1,$2,$3,$4,$5,$6,$7) RETURNING *', [l.id, l.nombre, l.multiplicador || 1, l.modo || 'porcentaje', l.color || '#2563eb', l.compra_minima || 0, l.promo_msg || '']); res.json(rows[0]); } catch (e) { res.status(400).json({ error: e.message }); }
});
app.put('/api/listas/:id', auth('admin'), async (req, res) => {
  try { const l = req.body; await pool.query('UPDATE listas_precio SET nombre=$1,multiplicador=$2,modo=$3,color=$4,compra_minima=$5,promo_msg=$6 WHERE id=$7', [l.nombre, l.multiplicador, l.modo, l.color, l.compra_minima || 0, l.promo_msg || '', req.params.id]); res.json({ ok: true }); } catch (e) { res.status(500).json({ error: e.message }); }
});
app.delete('/api/listas/:id', auth('admin'), async (req, res) => { try { await pool.query('DELETE FROM listas_precio WHERE id=$1', [req.params.id]); res.json({ ok: true }); } catch (e) { res.status(500).json({ error: e.message }); } });

// ═══ SECCIONES ═══
app.get('/api/secciones', async (req, res) => { try { const { rows } = await pool.query('SELECT * FROM secciones ORDER BY id'); res.json(rows); } catch (e) { res.status(500).json({ error: e.message }); } });
app.get('/api/secciones/:id', async (req, res) => { try { const { rows } = await pool.query('SELECT * FROM secciones WHERE id=$1', [req.params.id]); if (!rows[0]) return res.status(404).json({ error: 'No encontrada' }); res.json(rows[0]); } catch (e) { res.status(500).json({ error: e.message }); } });
app.put('/api/secciones/:id', auth('admin'), async (req, res) => {
  try { const { nombre, slug, descripcion, imagen, requiere_aprobacion, visible, orden } = req.body;
    await pool.query('UPDATE secciones SET nombre=$1,slug=$2,descripcion=$3,imagen=$4,requiere_aprobacion=$5,visible=$6,orden=$7 WHERE id=$8', [nombre, slug, descripcion, imagen, requiere_aprobacion, visible, orden, req.params.id]);
    res.json({ ok: true }); } catch (e) { res.status(500).json({ error: e.message }); }
});
app.post('/api/secciones', auth('admin'), async (req, res) => {
  try { const { nombre, slug, descripcion, imagen, requiere_aprobacion } = req.body;
    const { rows } = await pool.query('INSERT INTO secciones (nombre,slug,descripcion,imagen,requiere_aprobacion) VALUES ($1,$2,$3,$4,$5) RETURNING *', [nombre, slug, descripcion || '', imagen || '', requiere_aprobacion || false]);
    res.json(rows[0]); } catch (e) { res.status(400).json({ error: e.message }); }
});
app.delete('/api/secciones/:id', auth('admin'), async (req, res) => { try { await pool.query('DELETE FROM secciones WHERE id=$1', [req.params.id]); res.json({ ok: true }); } catch (e) { res.status(500).json({ error: e.message }); } });

// ═══ UPLOAD (Cloudinary first, local fallback) ═══
const uploadToCloudinary = (buffer, folder = 'productos') => new Promise((resolve, reject) => {
  const stream = cloudinary.uploader.upload_stream({ folder, resource_type: 'image', quality: 'auto', fetch_format: 'auto' }, (err, result) => {
    if (err) reject(err); else resolve(result.secure_url);
  });
  stream.end(buffer);
});

app.post('/api/upload', auth('admin'), upload.single('imagen'), async (req, res) => {
  if (!req.file) return res.status(400).json({ error: 'No file' });
  // Validate file type
  const allowed = ['image/jpeg', 'image/png', 'image/gif', 'image/webp', 'image/svg+xml'];
  if (!allowed.includes(req.file.mimetype)) return res.status(400).json({ error: 'Tipo de archivo no permitido. Solo imágenes.' });
  try {
    if (useCloudinary) {
      const url = await uploadToCloudinary(req.file.buffer);
      return res.json({ url, filename: path.basename(url) });
    }
    // Local fallback
    const fname = Date.now() + '-' + req.file.originalname.replace(/\s+/g, '_');
    fs.writeFileSync(path.join(uploadsDir, fname), req.file.buffer);
    const url = `${req.protocol}://${req.get('host')}/uploads/${fname}`;
    res.json({ url, filename: fname });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/upload-base64', auth('admin'), async (req, res) => {
  try {
    const { data, filename } = req.body;
    const buffer = Buffer.from(data.replace(/^data:image\/\w+;base64,/, ''), 'base64');
    if (useCloudinary) {
      const url = await uploadToCloudinary(buffer, 'config');
      return res.json({ url });
    }
    const fname = Date.now() + '-' + (filename || 'upload.png').replace(/\s+/g, '_');
    fs.writeFileSync(path.join(uploadsDir, fname), buffer);
    const url = `${req.protocol}://${req.get('host')}/uploads/${fname}`;
    res.json({ url });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ═══ PRODUCTOS ═══
app.get('/api/productos', optionalAuth, async (req, res) => {
  try { const { seccion_id, q, categoria, page = 1, limit = 50, marca } = req.query;
    let where = ['1=1']; const params = []; let pi = 1;
    if (seccion_id) { where.push(`p.seccion_id=$${pi++}`); params.push(seccion_id); }
    if (q) { where.push(`(p.nombre ILIKE $${pi} OR p.modelo ILIKE $${pi} OR p.categoria ILIKE $${pi} OR p.compatibilidad ILIKE $${pi} OR p.sku ILIKE $${pi})`); params.push(`%${q}%`); pi++; }
    if (categoria) { where.push(`p.categoria=$${pi++}`); params.push(categoria); }
    if (marca) { where.push(`p.categoria=$${pi++}`); params.push(marca); }
    // Check if section is mayorista and user not logged in → hide prices
    let hidePrices = false;
    if (seccion_id) {
      const { rows: secRows } = await pool.query('SELECT slug, requiere_aprobacion FROM secciones WHERE id=$1', [seccion_id]);
      if (secRows[0]?.slug === 'mayorista' && !req.user) hidePrices = true;
    }
    const offset = (parseInt(page) - 1) * parseInt(limit);
    const countR = await pool.query(`SELECT COUNT(*) FROM productos p WHERE ${where.join(' AND ')}`, params);
    const { rows } = await pool.query(`SELECT p.* FROM productos p WHERE ${where.join(' AND ')} ORDER BY CASE WHEN p.stock > 0 THEN 0 ELSE 1 END, p.stock DESC, p.id DESC LIMIT $${pi++} OFFSET $${pi++}`, [...params, parseInt(limit), offset]);
    res.json({ productos: hidePrices ? rows.map(r => ({ ...r, precio_base: 0, precio_oferta: 0 })) : rows, total: parseInt(countR.rows[0].count), page: parseInt(page), pages: Math.ceil(parseInt(countR.rows[0].count) / parseInt(limit)) });
  } catch (e) { res.status(500).json({ error: e.message }); }
});
app.get('/api/categorias', async (req, res) => {
  try { const { seccion_id } = req.query;
    let q = 'SELECT DISTINCT categoria FROM productos WHERE categoria IS NOT NULL AND categoria != \'\'';
    const params = [];
    if (seccion_id) { q += ' AND seccion_id=$1'; params.push(seccion_id); }
    q += ' ORDER BY categoria';
    const { rows } = await pool.query(q, params); res.json(rows.map(r => r.categoria));
  } catch (e) { res.status(500).json({ error: e.message }); }
});
app.post('/api/productos', auth('admin'), async (req, res) => {
  try { const p = req.body;
    const { rows } = await pool.query('INSERT INTO productos (seccion_id,categoria,modelo,nombre,precio_base,precio_original,stock,stock_minimo,imagen,notas,compatibilidad,descripcion,sku,tipo,moneda,precio_oferta,envio_gratis,visible,peso,alto,ancho,largo) VALUES ($1,$2,$3,$4,$5,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21) RETURNING *',
      [p.seccion_id, p.categoria, p.modelo, p.nombre || p.modelo, p.precio_base || 0, p.stock || 0, p.stock_minimo || 0, p.imagen || '', p.notas || '', p.compatibilidad || '', p.descripcion || '', p.sku || '', p.tipo || 'fisico', p.moneda || 'ARS', p.precio_oferta || 0, p.envio_gratis || false, p.visible !== false, p.peso || 0, p.alto || 0, p.ancho || 0, p.largo || 0]);
    res.json(rows[0]); } catch (e) { res.status(500).json({ error: e.message }); }
});
app.put('/api/productos/:id', auth('admin'), async (req, res) => {
  try { const p = req.body; const sets = []; const params = []; let pi = 1;
    const fields = ['seccion_id','categoria','modelo','nombre','precio_base','stock','stock_minimo','imagen','notas','compatibilidad','descripcion','sku','tipo','moneda','precio_oferta','envio_gratis','visible','peso','alto','ancho','largo'];
    for (const f of fields) { if (p[f] !== undefined) { sets.push(`${f}=$${pi++}`); params.push(p[f]); } }
    if (!sets.length) return res.json({ ok: true });
    params.push(req.params.id);
    await pool.query(`UPDATE productos SET ${sets.join(',')} WHERE id=$${pi}`, params);
    // Record price history
    if (p.precio_base !== undefined) {
      const { rows: old } = await pool.query('SELECT precio_base FROM productos WHERE id=$1', [req.params.id]);
      if (old[0] && Number(old[0].precio_base) !== Number(p.precio_base)) {
        await pool.query('INSERT INTO historial_precios (producto_id,precio_anterior,precio_nuevo,usuario) VALUES ($1,$2,$3,$4)', [req.params.id, old[0].precio_base, p.precio_base, req.user.usuario]);
      }
    }
    const { rows } = await pool.query('SELECT * FROM productos WHERE id=$1', [req.params.id]);
    res.json(rows[0]); } catch (e) { res.status(500).json({ error: e.message }); }
});
app.delete('/api/productos/:id', auth('admin'), async (req, res) => { try { await pool.query('DELETE FROM productos WHERE id=$1', [req.params.id]); res.json({ ok: true }); } catch (e) { res.status(500).json({ error: e.message }); } });
app.post('/api/productos/bulk', auth('admin'), async (req, res) => {
  try { const { productos, reemplazar } = req.body;
    if (reemplazar) await pool.query('DELETE FROM productos WHERE seccion_id=$1', [productos[0]?.seccion_id]);
    let count = 0;
    for (const p of productos) {
      await pool.query('INSERT INTO productos (seccion_id,categoria,modelo,nombre,precio_base,precio_original,stock,imagen) VALUES ($1,$2,$3,$4,$5,$5,$6,$7)',
        [p.seccion_id, p.categoria || '', p.modelo || '', p.nombre || p.modelo || '', p.precio_base || 0, p.stock || 0, p.imagen || '']);
      count++;
    }
    res.json({ insertados: count }); } catch (e) { res.status(500).json({ error: e.message }); }
});
app.delete('/api/categorias/:cat', auth('admin'), async (req, res) => { try { await pool.query('DELETE FROM productos WHERE categoria=$1', [decodeURIComponent(req.params.cat)]); res.json({ ok: true }); } catch (e) { res.status(500).json({ error: e.message }); } });
app.delete('/api/productos/all', auth('admin'), async (req, res) => { try { await pool.query('DELETE FROM productos'); res.json({ ok: true }); } catch (e) { res.status(500).json({ error: e.message }); } });

// ═══ PRECIOS ═══
app.post('/api/precios/ajustar', auth('admin'), async (req, res) => {
  try { const { porcentaje, categoria } = req.body;
    let q = 'UPDATE productos SET precio_base = ROUND(precio_base * $1, 2)';
    const params = [1 + porcentaje / 100];
    if (categoria) { q += ' WHERE categoria=$2'; params.push(categoria); }
    await pool.query(q, params); res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});
app.post('/api/precios/reset', auth('admin'), async (req, res) => { try { await pool.query('UPDATE productos SET precio_base = precio_original WHERE precio_original > 0'); res.json({ ok: true }); } catch (e) { res.status(500).json({ error: e.message }); } });
app.get('/api/historial-precios', auth('admin'), async (req, res) => { try { const { rows } = await pool.query('SELECT hp.*, p.categoria, p.modelo, p.nombre FROM historial_precios hp LEFT JOIN productos p ON hp.producto_id=p.id ORDER BY hp.created_at DESC LIMIT 200'); res.json(rows); } catch (e) { res.status(500).json({ error: e.message }); } });
app.get('/api/precios-fijos', async (req, res) => { try { const { rows } = await pool.query('SELECT * FROM precios_fijos'); res.json(rows); } catch (e) { res.status(500).json({ error: e.message }); } });
app.post('/api/precios-fijos', auth('admin'), async (req, res) => {
  try { const { producto_id, lista_precio_id, precio_fijo } = req.body;
    if (precio_fijo === null || precio_fijo === '' || precio_fijo === 0) { await pool.query('DELETE FROM precios_fijos WHERE producto_id=$1 AND lista_precio_id=$2', [producto_id, lista_precio_id]); }
    else { await pool.query('INSERT INTO precios_fijos (producto_id,lista_precio_id,precio_fijo) VALUES ($1,$2,$3) ON CONFLICT (producto_id,lista_precio_id) DO UPDATE SET precio_fijo=$3', [producto_id, lista_precio_id, precio_fijo]); }
    res.json({ ok: true }); } catch (e) { res.status(500).json({ error: e.message }); }
});

// ═══ MARCAS / MODELOS ═══
app.get('/api/marcas', async (req, res) => {
  try { const { seccion_id } = req.query;
    let q = 'SELECT DISTINCT categoria AS marca, COUNT(*) as total FROM productos WHERE categoria IS NOT NULL';
    const params = [];
    if (seccion_id) { q += ' AND seccion_id=$1'; params.push(seccion_id); }
    q += ' GROUP BY categoria ORDER BY categoria';
    const { rows } = await pool.query(q, params); res.json(rows);
  } catch (e) { res.status(500).json({ error: e.message }); }
});
app.get('/api/modelos', async (req, res) => {
  try { const { marca, seccion_id } = req.query;
    let q = "SELECT DISTINCT COALESCE(NULLIF(modelo,''), nombre) as modelo, COUNT(*) as total FROM productos WHERE categoria=$1";
    const params = [marca];
    if (seccion_id) { q += ' AND seccion_id=$2'; params.push(seccion_id); }
    q += " GROUP BY COALESCE(NULLIF(modelo,''), nombre) ORDER BY 1";
    const { rows } = await pool.query(q, params); res.json(rows);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// Admin product search
app.get('/api/productos/buscar', auth('admin'), async (req, res) => {
  try { const { q } = req.query;
    const { rows } = await pool.query("SELECT id, nombre, modelo, categoria, precio_base, stock, imagen FROM productos WHERE nombre ILIKE $1 OR modelo ILIKE $1 OR categoria ILIKE $1 OR sku ILIKE $1 ORDER BY nombre LIMIT 20", [`%${q}%`]);
    res.json(rows);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ═══ USUARIOS ═══
app.get('/api/usuarios', auth('admin'), async (req, res) => {
  try { const { q } = req.query;
    let query = 'SELECT * FROM usuarios ORDER BY created_at DESC';
    const params = [];
    if (q) { query = "SELECT * FROM usuarios WHERE nombre ILIKE $1 OR usuario ILIKE $1 OR nombre_fantasia ILIKE $1 OR email ILIKE $1 OR telefono ILIKE $1 ORDER BY created_at DESC"; params.push(`%${q}%`); }
    const { rows } = await pool.query(query, params);
    res.json(rows.map(u => ({ ...u, password: undefined })));
  } catch (e) { res.status(500).json({ error: e.message }); }
});
app.get('/api/usuarios/pendientes/count', auth('admin'), async (req, res) => { try { const { rows } = await pool.query("SELECT COUNT(*) FROM usuarios WHERE aprobado=false AND activo=false"); res.json({ count: parseInt(rows[0].count) }); } catch (e) { res.json({ count: 0 }); } });
app.put('/api/usuarios/:id', auth('admin'), async (req, res) => {
  try { const u = req.body; const sets = []; const params = []; let pi = 1;
    const fields = ['nombre','usuario','telefono','email','direccion','nombre_fantasia','rol','lista_precio_id','activo','aprobado','permisos','notas_admin','es_revendedor','descuento_revendedor'];
    for (const f of fields) { if (u[f] !== undefined) { sets.push(`${f}=$${pi++}`); params.push(u[f]); } }
    if (u.password) { const hash = await bcrypt.hash(u.password, 10); sets.push(`password=$${pi++}`); params.push(hash); }
    if (!sets.length) return res.json({ ok: true });
    params.push(req.params.id);
    await pool.query(`UPDATE usuarios SET ${sets.join(',')} WHERE id=$${pi}`, params);
    res.json({ ok: true }); } catch (e) { res.status(500).json({ error: e.message }); }
});
app.post('/api/usuarios/:id/aprobar', auth('admin'), async (req, res) => {
  try { const { lista_precio_id } = req.body;
    await pool.query('UPDATE usuarios SET aprobado=true, activo=true, lista_precio_id=$1 WHERE id=$2', [lista_precio_id || '', req.params.id]);
    const { rows } = await pool.query('SELECT * FROM usuarios WHERE id=$1', [req.params.id]);
    res.json({ ok: true, user: { ...rows[0], password: undefined } });
  } catch (e) { res.status(500).json({ error: e.message }); }
});
app.post('/api/usuarios/:id/rechazar', auth('admin'), async (req, res) => { try { await pool.query('UPDATE usuarios SET activo=false WHERE id=$1', [req.params.id]); res.json({ ok: true }); } catch (e) { res.status(500).json({ error: e.message }); } });
app.post('/api/usuarios/:id/suspender', auth('admin'), async (req, res) => { try { const { activo } = req.body; await pool.query('UPDATE usuarios SET activo=$1 WHERE id=$2', [activo, req.params.id]); res.json({ ok: true }); } catch (e) { res.status(500).json({ error: e.message }); } });
app.post('/api/usuarios/:id/reset-password', auth('admin'), async (req, res) => {
  try { const hash = await bcrypt.hash('1234', 10); await pool.query('UPDATE usuarios SET password=$1 WHERE id=$2', [hash, req.params.id]);
    const { rows } = await pool.query('SELECT nombre, telefono FROM usuarios WHERE id=$1', [req.params.id]);
    res.json({ ok: true, nombre: rows[0]?.nombre, telefono: rows[0]?.telefono });
  } catch (e) { res.status(500).json({ error: e.message }); }
});
app.delete('/api/usuarios/:id', auth('admin'), async (req, res) => {
  try { await pool.query('DELETE FROM pedido_items WHERE pedido_id IN (SELECT id FROM pedidos WHERE usuario_id=$1)', [req.params.id]);
    await pool.query('DELETE FROM pedidos WHERE usuario_id=$1', [req.params.id]);
    await pool.query('DELETE FROM usuarios WHERE id=$1', [req.params.id]); res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ═══ PEDIDOS ═══
app.get('/api/pedidos', auth(), async (req, res) => {
  try { const { all, archivado, seccion_id, tipo } = req.query;
    let where = []; const params = [];
    if (req.user.rol === 'admin' || req.user.rol === 'subadmin') {
      if (archivado === 'true') where.push('p.archivado=true');
      else where.push('p.archivado=false');
    } else { where.push('p.usuario_id=$1'); params.push(req.user.id); }
    if (seccion_id) { where.push(`p.seccion_id=$${params.length + 1}`); params.push(seccion_id); }
    if (tipo) { where.push(`p.tipo=$${params.length + 1}`); params.push(tipo); }
    const { rows } = await pool.query(`SELECT p.*, u.nombre as usuario_nombre, u.telefono as usuario_telefono, u.email as usuario_email, u.nombre_fantasia FROM pedidos p LEFT JOIN usuarios u ON p.usuario_id=u.id WHERE ${where.join(' AND ')} ORDER BY p.created_at DESC LIMIT 500`, params);
    res.json(rows);
  } catch (e) { res.status(500).json({ error: e.message }); }
});
app.get('/api/pedidos/:id', auth(), async (req, res) => {
  try { const { rows } = await pool.query('SELECT p.*, u.nombre as usuario_nombre, u.telefono as usuario_telefono, u.email as usuario_email, u.nombre_fantasia, u.direccion as usuario_direccion FROM pedidos p LEFT JOIN usuarios u ON p.usuario_id=u.id WHERE p.id=$1', [req.params.id]);
    if (!rows[0]) return res.status(404).json({ error: 'No encontrado' });
    const { rows: items } = await pool.query('SELECT * FROM pedido_items WHERE pedido_id=$1', [req.params.id]);
    res.json({ ...rows[0], items });
  } catch (e) { res.status(500).json({ error: e.message }); }
});
app.post('/api/pedidos', auth(), async (req, res) => {
  try { const { seccion_id, items, tipo, metodo_pago, notas, cupon_codigo, subtotal, descuento, total, datos_envio, notificar_wa } = req.body;
    const { rows } = await pool.query('INSERT INTO pedidos (usuario_id,seccion_id,tipo,metodo_pago,notas,cupon_codigo,subtotal,descuento,total,datos_envio,notificar_wa) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11) RETURNING *',
      [req.user.id, seccion_id, tipo || 'pedido', metodo_pago || '', notas || '', cupon_codigo || '', subtotal || 0, descuento || 0, total || 0, datos_envio || '', notificar_wa !== false]);
    for (const item of (items || [])) {
      await pool.query('INSERT INTO pedido_items (pedido_id,producto_id,categoria,modelo,nombre_producto,cantidad,precio_unitario,precio_base) VALUES ($1,$2,$3,$4,$5,$6,$7,$8)',
        [rows[0].id, item.producto_id, item.categoria || '', item.modelo || '', item.nombre_producto || '', item.cantidad || 1, item.precio_unitario || 0, item.precio_base || 0]);
    }
    // Increment cupon usage on actual order creation
    if (cupon_codigo) { await pool.query("UPDATE cupones SET usos_actuales = usos_actuales + 1 WHERE codigo=$1", [cupon_codigo]).catch(() => {}); }
    res.json(rows[0]); } catch (e) { res.status(500).json({ error: e.message }); }
});
app.put('/api/pedidos/:id', auth('admin'), async (req, res) => {
  try { const p = req.body; const sets = []; const params = []; let pi = 1;
    const fields = ['estado','tipo','metodo_pago','notas','total','subtotal','descuento','datos_envio','usuario_id','notificar_wa'];
    for (const f of fields) { if (p[f] !== undefined) { sets.push(`${f}=$${pi++}`); params.push(p[f]); } }
    sets.push(`updated_at=NOW()`);
    if (sets.length <= 1) return res.json({ ok: true });
    params.push(req.params.id);
    await pool.query(`UPDATE pedidos SET ${sets.join(',')} WHERE id=$${pi}`, params);
    // Update items if provided
    if (p.items) {
      await pool.query('DELETE FROM pedido_items WHERE pedido_id=$1', [req.params.id]);
      for (const item of p.items) {
        await pool.query('INSERT INTO pedido_items (pedido_id,producto_id,categoria,modelo,nombre_producto,cantidad,precio_unitario,precio_base) VALUES ($1,$2,$3,$4,$5,$6,$7,$8)',
          [req.params.id, item.producto_id || item.id, item.categoria || '', item.modelo || '', item.nombre_producto || `${item.categoria} - ${item.modelo}`, item.cantidad || item.qty || 1, item.precio_unitario || 0, item.precio_base || 0]);
      }
    }
    res.json({ ok: true }); } catch (e) { res.status(500).json({ error: e.message }); }
});
app.post('/api/pedidos/:id/archivar', auth('admin'), async (req, res) => { try { await pool.query('UPDATE pedidos SET archivado=true WHERE id=$1', [req.params.id]); res.json({ ok: true }); } catch (e) { res.status(500).json({ error: e.message }); } });
app.post('/api/pedidos/:id/desarchivar', auth('admin'), async (req, res) => { try { await pool.query('UPDATE pedidos SET archivado=false WHERE id=$1', [req.params.id]); res.json({ ok: true }); } catch (e) { res.status(500).json({ error: e.message }); } });
app.delete('/api/pedidos/:id', auth('admin'), async (req, res) => { try { await pool.query('DELETE FROM pedido_items WHERE pedido_id=$1', [req.params.id]); await pool.query('DELETE FROM pedidos WHERE id=$1', [req.params.id]); res.json({ ok: true }); } catch (e) { res.status(500).json({ error: e.message }); } });

// ═══ STATS ═══
app.get('/api/stats', auth('admin'), async (req, res) => {
  try { const { seccion_id, desde, hasta } = req.query;
    let secWhere = ''; const params = [];
    if (seccion_id && seccion_id !== 'all') { secWhere = ' AND seccion_id=$1'; params.push(seccion_id); }
    let dateWhere = ''; const dp = params.length;
    if (desde) { dateWhere += ` AND created_at >= $${dp + 1}`; params.push(desde); }
    if (hasta) { dateWhere += ` AND created_at <= $${dp + 2}`; params.push(hasta); }
    const totalPedidos = await pool.query(`SELECT COUNT(*) FROM pedidos WHERE archivado=false${secWhere}${dateWhere}`, params);
    const totalVentas = await pool.query(`SELECT COALESCE(SUM(total),0) as total FROM pedidos WHERE estado NOT IN ('cancelado') AND archivado=false${secWhere}${dateWhere}`, params);
    const totalProductos = await pool.query(`SELECT COUNT(*) FROM productos WHERE 1=1${secWhere.replace('seccion_id','seccion_id')}`, seccion_id && seccion_id !== 'all' ? [seccion_id] : []);
    const totalUsuarios = await pool.query('SELECT COUNT(*) FROM usuarios WHERE rol != $1', ['admin']);
    // Ventas por día
    const ventasPorDia = await pool.query(`SELECT DATE(created_at) as fecha, COUNT(*) as cantidad, COALESCE(SUM(total),0) as total FROM pedidos WHERE estado NOT IN ('cancelado') AND archivado=false${secWhere}${dateWhere} GROUP BY DATE(created_at) ORDER BY fecha DESC LIMIT 30`, params);
    // Top categorías
    const topCat = await pool.query(`SELECT pi.categoria, COUNT(*) as cantidad, SUM(pi.precio_unitario * pi.cantidad) as total FROM pedido_items pi JOIN pedidos p ON pi.pedido_id=p.id WHERE p.estado NOT IN ('cancelado')${secWhere.replace('seccion_id','p.seccion_id')}${dateWhere.replace('created_at','p.created_at')} GROUP BY pi.categoria ORDER BY total DESC LIMIT 10`, params);
    res.json({
      total_pedidos: parseInt(totalPedidos.rows[0].count),
      total_ventas: parseFloat(totalVentas.rows[0].total),
      total_productos: parseInt(totalProductos.rows[0].count),
      total_usuarios: parseInt(totalUsuarios.rows[0].count),
      ventas_por_dia: ventasPorDia.rows,
      top_categorias: topCat.rows
    });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ═══ CUPONES ═══
app.get('/api/cupones', auth('admin'), async (req, res) => {
  try { const { rows } = await pool.query('SELECT c.*, array_agg(cp.producto_id) FILTER (WHERE cp.producto_id IS NOT NULL) as productos_ids FROM cupones c LEFT JOIN cupon_productos cp ON c.id=cp.cupon_id GROUP BY c.id ORDER BY c.created_at DESC');
    res.json(rows); } catch (e) { res.status(500).json({ error: e.message }); }
});
app.post('/api/cupones/validar', async (req, res) => {
  try { const { codigo, seccion_id, subtotal, metodo_pago, items } = req.body;
    const { rows } = await pool.query('SELECT * FROM cupones WHERE codigo=$1 AND activo=true', [codigo]);
    if (!rows[0]) return res.status(404).json({ error: 'Cupón no válido' });
    const c = rows[0];
    if (c.uso_maximo > 0 && c.usos_actuales >= c.uso_maximo) return res.status(400).json({ error: 'Cupón agotado' });
    if (c.fecha_desde && new Date() < new Date(c.fecha_desde)) return res.status(400).json({ error: 'Cupón aún no vigente' });
    if (c.fecha_hasta && new Date() > new Date(c.fecha_hasta)) return res.status(400).json({ error: 'Cupón vencido' });
    if (c.secciones_ids) { const sids = c.secciones_ids.split(',').map(Number); if (!sids.includes(Number(seccion_id))) return res.status(400).json({ error: 'Cupón no aplica a esta sección' }); }
    if (c.monto_minimo > 0 && subtotal < c.monto_minimo) return res.status(400).json({ error: `Monto mínimo: $${c.monto_minimo}` });
    if (c.metodo_pago && metodo_pago && c.metodo_pago !== metodo_pago) return res.status(400).json({ error: `Solo válido con ${c.metodo_pago}` });
    // Check productos
    const { rows: cpRows } = await pool.query('SELECT producto_id FROM cupon_productos WHERE cupon_id=$1', [c.id]);
    if (cpRows.length > 0) {
      const pids = cpRows.map(r => r.producto_id);
      const itemPids = (items || []).map(i => i.producto_id || i.id);
      if (!itemPids.some(p => pids.includes(p))) return res.status(400).json({ error: 'Cupón no aplica a estos productos' });
    }
    let descuento = 0;
    if (c.tipo === 'porcentaje') descuento = Math.round(subtotal * c.valor / 100);
    else if (c.tipo === 'monto_fijo') descuento = c.valor;
    else if (c.tipo === 'envio_gratis') descuento = 0; // handled in frontend
    // Don't increment usage here — increment on order creation instead
    res.json({ descuento, tipo: c.tipo, valor: c.valor, codigo: c.codigo, cupon_id: c.id });
  } catch (e) { res.status(500).json({ error: e.message }); }
});
app.post('/api/cupones', auth('admin'), async (req, res) => {
  try { const c = req.body;
    const { rows } = await pool.query('INSERT INTO cupones (codigo,tipo,valor,secciones_ids,categoria,uso_maximo,monto_minimo,metodo_pago,fecha_desde,fecha_hasta) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10) RETURNING *',
      [c.codigo, c.tipo, c.valor || 0, c.secciones_ids || '', c.categoria || '', c.uso_maximo || 0, c.monto_minimo || 0, c.metodo_pago || '', c.fecha_desde || null, c.fecha_hasta || null]);
    // Link products
    if (c.productos_ids?.length) { for (const pid of c.productos_ids) { await pool.query('INSERT INTO cupon_productos (cupon_id,producto_id) VALUES ($1,$2)', [rows[0].id, pid]); } }
    res.json(rows[0]); } catch (e) { res.status(400).json({ error: e.message }); }
});
app.put('/api/cupones/:id', auth('admin'), async (req, res) => {
  try { const c = req.body;
    await pool.query('UPDATE cupones SET codigo=$1,tipo=$2,valor=$3,secciones_ids=$4,categoria=$5,uso_maximo=$6,monto_minimo=$7,metodo_pago=$8,activo=$9,fecha_desde=$10,fecha_hasta=$11 WHERE id=$12',
      [c.codigo, c.tipo, c.valor, c.secciones_ids || '', c.categoria || '', c.uso_maximo || 0, c.monto_minimo || 0, c.metodo_pago || '', c.activo !== false, c.fecha_desde || null, c.fecha_hasta || null, req.params.id]);
    // Re-link products
    await pool.query('DELETE FROM cupon_productos WHERE cupon_id=$1', [req.params.id]);
    if (c.productos_ids?.length) { for (const pid of c.productos_ids) { await pool.query('INSERT INTO cupon_productos (cupon_id,producto_id) VALUES ($1,$2)', [req.params.id, pid]); } }
    res.json({ ok: true }); } catch (e) { res.status(500).json({ error: e.message }); }
});
app.delete('/api/cupones/:id', auth('admin'), async (req, res) => { try { await pool.query('DELETE FROM cupon_productos WHERE cupon_id=$1', [req.params.id]); await pool.query('DELETE FROM cupones WHERE id=$1', [req.params.id]); res.json({ ok: true }); } catch (e) { res.status(500).json({ error: e.message }); } });

// ═══ PROMOCIONES ═══
app.get('/api/promociones', async (req, res) => { try { const { rows } = await pool.query('SELECT * FROM promociones ORDER BY created_at DESC'); res.json(rows); } catch (e) { res.status(500).json({ error: e.message }); } });
app.post('/api/promociones', auth('admin'), async (req, res) => {
  try { const p = req.body; const { rows } = await pool.query('INSERT INTO promociones (nombre,tipo,valor,secciones_ids,categoria,productos_ids,activo,fecha_desde,fecha_hasta) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9) RETURNING *',
    [p.nombre, p.tipo, p.valor || 0, p.secciones_ids || '', p.categoria || '', p.productos_ids || '', p.activo !== false, p.fecha_desde || null, p.fecha_hasta || null]);
    res.json(rows[0]); } catch (e) { res.status(400).json({ error: e.message }); }
});
app.put('/api/promociones/:id', auth('admin'), async (req, res) => {
  try { const p = req.body; await pool.query('UPDATE promociones SET nombre=$1,tipo=$2,valor=$3,secciones_ids=$4,categoria=$5,productos_ids=$6,activo=$7,fecha_desde=$8,fecha_hasta=$9 WHERE id=$10',
    [p.nombre, p.tipo, p.valor, p.secciones_ids || '', p.categoria || '', p.productos_ids || '', p.activo !== false, p.fecha_desde || null, p.fecha_hasta || null, req.params.id]);
    res.json({ ok: true }); } catch (e) { res.status(500).json({ error: e.message }); }
});
app.delete('/api/promociones/:id', auth('admin'), async (req, res) => { try { await pool.query('DELETE FROM promociones WHERE id=$1', [req.params.id]); res.json({ ok: true }); } catch (e) { res.status(500).json({ error: e.message }); } });
app.get('/api/promociones/activas', async (req, res) => {
  try { const { seccion_id } = req.query;
    const { rows } = await pool.query("SELECT * FROM promociones WHERE activo=true AND (fecha_desde IS NULL OR fecha_desde <= NOW()) AND (fecha_hasta IS NULL OR fecha_hasta >= NOW())");
    const filtered = seccion_id ? rows.filter(p => !p.secciones_ids || p.secciones_ids.split(',').map(Number).includes(Number(seccion_id))) : rows;
    res.json(filtered);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ═══ POPUPS ═══
app.get('/api/popups', async (req, res) => {
  try { const { seccion_id } = req.query;
    const { rows } = await pool.query("SELECT * FROM popups WHERE activo=true ORDER BY created_at DESC");
    const filtered = seccion_id ? rows.filter(p => !p.secciones_ids || p.secciones_ids.split(',').map(Number).includes(Number(seccion_id))) : rows;
    res.json(filtered);
  } catch (e) { res.status(500).json({ error: e.message }); }
});
app.get('/api/popups/all', auth('admin'), async (req, res) => { try { const { rows } = await pool.query('SELECT * FROM popups ORDER BY created_at DESC'); res.json(rows); } catch (e) { res.status(500).json({ error: e.message }); } });
app.post('/api/popups', auth('admin'), async (req, res) => {
  try { const p = req.body; const { rows } = await pool.query('INSERT INTO popups (titulo,imagen,url_destino,secciones_ids,activo) VALUES ($1,$2,$3,$4,$5) RETURNING *',
    [p.titulo, p.imagen || '', p.url_destino || '', p.secciones_ids || '', p.activo !== false]);
    res.json(rows[0]); } catch (e) { res.status(400).json({ error: e.message }); }
});
app.put('/api/popups/:id', auth('admin'), async (req, res) => {
  try { const p = req.body; await pool.query('UPDATE popups SET titulo=$1,imagen=$2,url_destino=$3,secciones_ids=$4,activo=$5 WHERE id=$6',
    [p.titulo, p.imagen, p.url_destino, p.secciones_ids || '', p.activo !== false, req.params.id]);
    res.json({ ok: true }); } catch (e) { res.status(500).json({ error: e.message }); }
});
app.delete('/api/popups/:id', auth('admin'), async (req, res) => { try { await pool.query('DELETE FROM popups WHERE id=$1', [req.params.id]); res.json({ ok: true }); } catch (e) { res.status(500).json({ error: e.message }); } });

// ═══ REDES SOCIALES ═══
app.get('/api/redes-sociales', async (req, res) => { try { const { rows } = await pool.query('SELECT * FROM redes_sociales ORDER BY orden'); res.json(rows); } catch (e) { res.status(500).json({ error: e.message }); } });
app.put('/api/redes-sociales', auth('admin'), async (req, res) => {
  try { const { redes } = req.body;
    for (const r of redes) { await pool.query('UPDATE redes_sociales SET url=$1, activo=$2 WHERE id=$3', [r.url, r.activo, r.id]); }
    res.json({ ok: true }); } catch (e) { res.status(500).json({ error: e.message }); }
});

// ═══ MENU ═══
app.get('/api/menu', async (req, res) => { try { const { rows } = await pool.query('SELECT * FROM menu_items WHERE visible=true ORDER BY orden'); res.json(rows); } catch (e) { res.status(500).json({ error: e.message }); } });
app.get('/api/menu/all', auth('admin'), async (req, res) => { try { const { rows } = await pool.query('SELECT * FROM menu_items ORDER BY orden'); res.json(rows); } catch (e) { res.status(500).json({ error: e.message }); } });
app.post('/api/menu', auth('admin'), async (req, res) => {
  try { const m = req.body; const { rows } = await pool.query('INSERT INTO menu_items (titulo,url,tipo,visible,orden,seccion_id) VALUES ($1,$2,$3,$4,$5,$6) RETURNING *',
    [m.titulo, m.url || '', m.tipo || 'link', m.visible !== false, m.orden || 0, m.seccion_id || null]);
    res.json(rows[0]); } catch (e) { res.status(400).json({ error: e.message }); }
});
app.put('/api/menu/:id', auth('admin'), async (req, res) => {
  try { const m = req.body; await pool.query('UPDATE menu_items SET titulo=$1,url=$2,tipo=$3,visible=$4,orden=$5,seccion_id=$6 WHERE id=$7',
    [m.titulo, m.url, m.tipo, m.visible, m.orden || 0, m.seccion_id || null, req.params.id]);
    res.json({ ok: true }); } catch (e) { res.status(500).json({ error: e.message }); }
});
app.delete('/api/menu/:id', auth('admin'), async (req, res) => { try { await pool.query('DELETE FROM menu_items WHERE id=$1', [req.params.id]); res.json({ ok: true }); } catch (e) { res.status(500).json({ error: e.message }); } });

// ═══ DESIGN ═══
app.get('/api/design', async (req, res) => { try { const { rows } = await pool.query('SELECT * FROM design_config'); const cfg = {}; rows.forEach(r => cfg[r.clave] = r.valor); res.json(cfg); } catch (e) { res.status(500).json({ error: e.message }); } });
app.put('/api/design', auth('admin'), async (req, res) => {
  try { for (const [k, v] of Object.entries(req.body)) {
    await pool.query('INSERT INTO design_config (clave,valor) VALUES ($1,$2) ON CONFLICT (clave) DO UPDATE SET valor=$2', [k, v]);
  } res.json({ ok: true }); } catch (e) { res.status(500).json({ error: e.message }); }
});

// ═══ METODOS PAGO ═══
app.get('/api/metodos-pago', async (req, res) => {
  try { const { seccion_id } = req.query;
    let q = 'SELECT * FROM metodos_pago WHERE activo=true';
    const params = [];
    if (seccion_id) { q += ' AND (seccion_id IS NULL OR seccion_id=$1)'; params.push(seccion_id); }
    q += ' ORDER BY orden';
    const { rows } = await pool.query(q, params); res.json(rows);
  } catch (e) { res.status(500).json({ error: e.message }); }
});
app.get('/api/metodos-pago/all', auth('admin'), async (req, res) => { try { const { rows } = await pool.query('SELECT * FROM metodos_pago ORDER BY orden'); res.json(rows); } catch (e) { res.status(500).json({ error: e.message }); } });
app.post('/api/metodos-pago', auth('admin'), async (req, res) => {
  try { const m = req.body; const { rows } = await pool.query('INSERT INTO metodos_pago (nombre,descripcion,instrucciones,icono,seccion_id,activo,orden) VALUES ($1,$2,$3,$4,$5,$6,$7) RETURNING *',
    [m.nombre, m.descripcion || '', m.instrucciones || '', m.icono || '💳', m.seccion_id || null, m.activo !== false, m.orden || 0]);
    res.json(rows[0]); } catch (e) { res.status(400).json({ error: e.message }); }
});
app.put('/api/metodos-pago/:id', auth('admin'), async (req, res) => {
  try { const m = req.body; await pool.query('UPDATE metodos_pago SET nombre=$1,descripcion=$2,instrucciones=$3,icono=$4,seccion_id=$5,activo=$6,orden=$7 WHERE id=$8',
    [m.nombre, m.descripcion, m.instrucciones, m.icono || '💳', m.seccion_id || null, m.activo !== false, m.orden || 0, req.params.id]);
    res.json({ ok: true }); } catch (e) { res.status(500).json({ error: e.message }); }
});
app.delete('/api/metodos-pago/:id', auth('admin'), async (req, res) => { try { await pool.query('DELETE FROM metodos_pago WHERE id=$1', [req.params.id]); res.json({ ok: true }); } catch (e) { res.status(500).json({ error: e.message }); } });

// ═══ PAGINAS INFO ═══
app.get('/api/paginas', async (req, res) => {
  try { const { seccion_id } = req.query;
    let q = 'SELECT * FROM paginas_info WHERE visible=true'; const params = [];
    if (seccion_id) { q += ' AND (seccion_id IS NULL OR seccion_id=$1)'; params.push(seccion_id); }
    q += ' ORDER BY orden'; const { rows } = await pool.query(q, params); res.json(rows);
  } catch (e) { res.status(500).json({ error: e.message }); }
});
app.get('/api/paginas/:id', async (req, res) => { try { const { rows } = await pool.query('SELECT * FROM paginas_info WHERE id=$1', [req.params.id]); if (!rows[0]) return res.status(404).json({ error: 'No encontrada' }); res.json(rows[0]); } catch (e) { res.status(500).json({ error: e.message }); } });
app.post('/api/paginas', auth('admin'), async (req, res) => {
  try { const p = req.body; const { rows } = await pool.query('INSERT INTO paginas_info (titulo,slug,contenido,seccion_id,visible,orden) VALUES ($1,$2,$3,$4,$5,$6) RETURNING *',
    [p.titulo, p.slug || '', p.contenido || '', p.seccion_id || null, p.visible !== false, p.orden || 0]);
    res.json(rows[0]); } catch (e) { res.status(400).json({ error: e.message }); }
});
app.put('/api/paginas/:id', auth('admin'), async (req, res) => {
  try { const p = req.body; await pool.query('UPDATE paginas_info SET titulo=$1,slug=$2,contenido=$3,seccion_id=$4,visible=$5,orden=$6 WHERE id=$7',
    [p.titulo, p.slug, p.contenido, p.seccion_id || null, p.visible !== false, p.orden || 0, req.params.id]);
    res.json({ ok: true }); } catch (e) { res.status(500).json({ error: e.message }); }
});
app.delete('/api/paginas/:id', auth('admin'), async (req, res) => { try { await pool.query('DELETE FROM paginas_info WHERE id=$1', [req.params.id]); res.json({ ok: true }); } catch (e) { res.status(500).json({ error: e.message }); } });

// ═══ BADGES ═══
app.get('/api/badges', async (req, res) => {
  try { const { seccion_id } = req.query;
    const { rows } = await pool.query('SELECT * FROM badges WHERE visible=true ORDER BY orden');
    const filtered = seccion_id ? rows.filter(b => !b.secciones_ids || b.secciones_ids.split(',').map(Number).includes(Number(seccion_id))) : rows;
    res.json(filtered);
  } catch (e) { res.status(500).json({ error: e.message }); }
});
app.get('/api/badges/all', auth('admin'), async (req, res) => { try { const { rows } = await pool.query('SELECT * FROM badges ORDER BY orden'); res.json(rows); } catch (e) { res.status(500).json({ error: e.message }); } });
app.post('/api/badges', auth('admin'), async (req, res) => {
  try { const b = req.body; const { rows } = await pool.query('INSERT INTO badges (icono,texto,color,visible,secciones_ids,orden) VALUES ($1,$2,$3,$4,$5,$6) RETURNING *',
    [b.icono || '⭐', b.texto, b.color || '#2563eb', b.visible !== false, b.secciones_ids || '', b.orden || 0]);
    res.json(rows[0]); } catch (e) { res.status(400).json({ error: e.message }); }
});
app.put('/api/badges/:id', auth('admin'), async (req, res) => {
  try { const b = req.body; await pool.query('UPDATE badges SET icono=$1,texto=$2,color=$3,visible=$4,secciones_ids=$5,orden=$6 WHERE id=$7',
    [b.icono, b.texto, b.color, b.visible !== false, b.secciones_ids || '', b.orden || 0, req.params.id]);
    res.json({ ok: true }); } catch (e) { res.status(500).json({ error: e.message }); }
});
app.delete('/api/badges/:id', auth('admin'), async (req, res) => { try { await pool.query('DELETE FROM badges WHERE id=$1', [req.params.id]); res.json({ ok: true }); } catch (e) { res.status(500).json({ error: e.message }); } });

// ═══ ENVIO ═══
app.get('/api/envio/config/:seccion_id', async (req, res) => { try { const { rows } = await pool.query('SELECT * FROM config_envio WHERE seccion_id=$1', [req.params.seccion_id]); res.json(rows[0] || { metodo: 'manual', costo_fijo: 0, gratis_desde: 0, zonas: [] }); } catch (e) { res.status(500).json({ error: e.message }); } });
app.put('/api/envio/config/:seccion_id', auth('admin'), async (req, res) => {
  try { const c = req.body; await pool.query('INSERT INTO config_envio (seccion_id,metodo,costo_fijo,gratis_desde,zonas) VALUES ($1,$2,$3,$4,$5) ON CONFLICT (seccion_id) DO UPDATE SET metodo=$2,costo_fijo=$3,gratis_desde=$4,zonas=$5',
    [req.params.seccion_id, c.metodo, c.costo_fijo || 0, c.gratis_desde || 0, JSON.stringify(c.zonas || [])]);
    res.json({ ok: true }); } catch (e) { res.status(500).json({ error: e.message }); }
});
app.post('/api/envio/cotizar', async (req, res) => {
  try { const { seccion_id, codigo_postal } = req.body;
    const { rows } = await pool.query('SELECT * FROM config_envio WHERE seccion_id=$1', [seccion_id]);
    const cfg = rows[0] || { metodo: 'manual', costo_fijo: 0 };
    res.json({ costo: cfg.costo_fijo, metodo: cfg.metodo, gratis_desde: cfg.gratis_desde });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ═══ PRODUCTO IMAGENES ═══
app.get('/api/producto-imagenes/:producto_id', async (req, res) => { try { const { rows } = await pool.query('SELECT * FROM producto_imagenes WHERE producto_id=$1 ORDER BY orden', [req.params.producto_id]); res.json(rows); } catch (e) { res.status(500).json({ error: e.message }); } });
app.post('/api/producto-imagenes', auth('admin'), async (req, res) => { try { const { producto_id, url, orden } = req.body; const { rows } = await pool.query('INSERT INTO producto_imagenes (producto_id,url,orden) VALUES ($1,$2,$3) RETURNING *', [producto_id, url, orden || 0]); res.json(rows[0]); } catch (e) { res.status(500).json({ error: e.message }); } });
app.delete('/api/producto-imagenes/:id', auth('admin'), async (req, res) => { try { await pool.query('DELETE FROM producto_imagenes WHERE id=$1', [req.params.id]); res.json({ ok: true }); } catch (e) { res.status(500).json({ error: e.message }); } });
app.put('/api/producto-imagenes/reorder', auth('admin'), async (req, res) => { try { const { items } = req.body; for (const it of items) { await pool.query('UPDATE producto_imagenes SET orden=$1 WHERE id=$2', [it.orden, it.id]); } res.json({ ok: true }); } catch (e) { res.status(500).json({ error: e.message }); } });

// ═══ VARIANTES ═══
app.get('/api/variantes/:producto_id', async (req, res) => { try { const { rows } = await pool.query('SELECT * FROM variantes WHERE producto_id=$1 ORDER BY id', [req.params.producto_id]); res.json(rows); } catch (e) { res.status(500).json({ error: e.message }); } });
app.post('/api/variantes', auth('admin'), async (req, res) => { try { const { producto_id, nombre, valor, stock, precio_extra } = req.body; const { rows } = await pool.query('INSERT INTO variantes (producto_id,nombre,valor,stock,precio_extra) VALUES ($1,$2,$3,$4,$5) RETURNING *', [producto_id, nombre, valor || '', stock || 0, precio_extra || 0]); res.json(rows[0]); } catch (e) { res.status(500).json({ error: e.message }); } });
app.put('/api/variantes/:id', auth('admin'), async (req, res) => { try { const v = req.body; await pool.query('UPDATE variantes SET nombre=$1,valor=$2,stock=$3,precio_extra=$4 WHERE id=$5', [v.nombre, v.valor, v.stock || 0, v.precio_extra || 0, req.params.id]); res.json({ ok: true }); } catch (e) { res.status(500).json({ error: e.message }); } });
app.delete('/api/variantes/:id', auth('admin'), async (req, res) => { try { await pool.query('DELETE FROM variantes WHERE id=$1', [req.params.id]); res.json({ ok: true }); } catch (e) { res.status(500).json({ error: e.message }); } });

// ═══ BUSQUEDA GLOBAL ═══
app.get('/api/busqueda-global', optionalAuth, async (req, res) => {
  try { const { q } = req.query; if (!q || q.length < 2) return res.json({ resultados: [], total: 0 });
    const { rows: secciones } = await pool.query('SELECT * FROM secciones WHERE visible=true ORDER BY id');
    const resultados = [];
    for (const sec of secciones) {
      const { rows } = await pool.query("SELECT id, nombre, modelo, categoria, precio_base, precio_oferta, imagen, stock, envio_gratis FROM productos WHERE seccion_id=$1 AND visible=true AND (nombre ILIKE $2 OR modelo ILIKE $2 OR categoria ILIKE $2 OR compatibilidad ILIKE $2) ORDER BY stock DESC LIMIT 10",
        [sec.id, `%${q}%`]);
      if (rows.length) {
        const hidePrice = sec.slug === 'mayorista' && !req.user;
        resultados.push({ seccion: sec, productos: hidePrice ? rows.map(r => ({ ...r, precio_base: 0, precio_oferta: 0 })) : rows });
      }
    }
    res.json({ resultados, total: resultados.reduce((s, r) => s + r.productos.length, 0) });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ═══ SLIDER BANNERS ═══
app.get('/api/slider', async (req, res) => { try { const { rows } = await pool.query('SELECT * FROM slider_banners WHERE activo=true ORDER BY orden'); res.json(rows); } catch (e) { res.status(500).json({ error: e.message }); } });
app.get('/api/slider/all', auth('admin'), async (req, res) => { try { const { rows } = await pool.query('SELECT * FROM slider_banners ORDER BY orden'); res.json(rows); } catch (e) { res.status(500).json({ error: e.message }); } });
app.post('/api/slider', auth('admin'), async (req, res) => { try { const { titulo, imagen, url_destino, orden, activo } = req.body; const { rows } = await pool.query('INSERT INTO slider_banners (titulo,imagen,url_destino,orden,activo) VALUES ($1,$2,$3,$4,$5) RETURNING *', [titulo||'', imagen||'', url_destino||'', orden||0, activo !== false]); res.json(rows[0]); } catch (e) { res.status(500).json({ error: e.message }); } });
app.put('/api/slider/:id', auth('admin'), async (req, res) => { try { const { titulo, imagen, url_destino, orden, activo } = req.body; await pool.query('UPDATE slider_banners SET titulo=$1,imagen=$2,url_destino=$3,orden=$4,activo=$5 WHERE id=$6', [titulo, imagen, url_destino, orden, activo, req.params.id]); res.json({ ok: true }); } catch (e) { res.status(500).json({ error: e.message }); } });
app.delete('/api/slider/:id', auth('admin'), async (req, res) => { try { await pool.query('DELETE FROM slider_banners WHERE id=$1', [req.params.id]); res.json({ ok: true }); } catch (e) { res.status(500).json({ error: e.message }); } });

// ═══ FAVORITOS ═══
app.get('/api/favoritos', auth(), async (req, res) => { try { const { rows } = await pool.query('SELECT f.*, p.nombre, p.modelo, p.imagen, p.precio_base, p.precio_oferta, p.stock, p.categoria, p.seccion_id FROM favoritos f JOIN productos p ON f.producto_id=p.id WHERE f.usuario_id=$1 ORDER BY f.created_at DESC', [req.user.id]); res.json(rows); } catch (e) { res.status(500).json({ error: e.message }); } });
app.post('/api/favoritos/:producto_id', auth(), async (req, res) => { try { await pool.query('INSERT INTO favoritos (usuario_id, producto_id) VALUES ($1,$2) ON CONFLICT DO NOTHING', [req.user.id, req.params.producto_id]); res.json({ ok: true }); } catch (e) { res.status(500).json({ error: e.message }); } });
app.delete('/api/favoritos/:producto_id', auth(), async (req, res) => { try { await pool.query('DELETE FROM favoritos WHERE usuario_id=$1 AND producto_id=$2', [req.user.id, req.params.producto_id]); res.json({ ok: true }); } catch (e) { res.status(500).json({ error: e.message }); } });

// ═══ NOTIFICACIONES STOCK ═══
app.post('/api/notificar-stock', async (req, res) => { try { const { producto_id, email } = req.body; if (!email || !producto_id) return res.status(400).json({ error: 'email y producto_id requeridos' }); await pool.query('INSERT INTO notificaciones_stock (producto_id, email) VALUES ($1,$2)', [producto_id, email]); res.json({ ok: true }); } catch (e) { res.status(500).json({ error: e.message }); } });

// ═══ ANDREANI ═══
const ANDREANI_API = process.env.ANDREANI_API || 'https://apis.andreani.com';
const andreaniLogin = async () => {
  const user = process.env.ANDREANI_USER; const pass = process.env.ANDREANI_PASS;
  if (!user || !pass) return null;
  const r = await fetch(`${ANDREANI_API}/login`, { method: 'GET', headers: { authorization: 'Basic ' + Buffer.from(`${user}:${pass}`).toString('base64') } });
  return r.headers.get('x-authorization-token');
};
app.post('/api/andreani/cotizar', async (req, res) => {
  try { const { cp_destino, peso, volumen, seccion_id } = req.body;
    const token = await andreaniLogin(); if (!token) return res.status(503).json({ error: 'Andreani no configurado' });
    const { rows } = await pool.query('SELECT * FROM config_envio WHERE seccion_id=$1', [seccion_id]);
    const cpOrigen = rows[0]?.cp_origen || process.env.ANDREANI_CP_ORIGEN || '1424';
    const body = { cpDestino: cp_destino, contrato: process.env.ANDREANI_CONTRATO || '', cliente: process.env.ANDREANI_NRO_CLIENTE || '', sucursalOrigen: '', bultos: [{ valorDeclarado: 1000, volumen: volumen || 5000, kilos: peso || 1 }] };
    const r = await fetch(`${ANDREANI_API}/v1/tarifas`, { method: 'POST', headers: { 'x-authorization-token': token, 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
    res.json(await r.json());
  } catch (e) { res.status(500).json({ error: e.message }); }
});
app.get('/api/andreani/sucursales', async (req, res) => { try { const { cp } = req.query; const token = await andreaniLogin(); if (!token) return res.status(503).json({ error: 'Andreani no configurado' }); const r = await fetch(`${ANDREANI_API}/v1/sucursales?codigoPostal=${cp}`, { headers: { 'x-authorization-token': token } }); res.json(await r.json()); } catch (e) { res.status(500).json({ error: e.message }); } });
app.post('/api/andreani/orden', auth('admin'), async (req, res) => {
  try { const token = await andreaniLogin(); if (!token) return res.status(503).json({ error: 'Andreani no configurado' });
    const r = await fetch(`${ANDREANI_API}/v1/ordenes-de-envio`, { method: 'POST', headers: { 'x-authorization-token': token, 'Content-Type': 'application/json' }, body: JSON.stringify(req.body) });
    res.json(await r.json());
  } catch (e) { res.status(500).json({ error: e.message }); }
});
app.get('/api/andreani/tracking/:envio', async (req, res) => { try { const token = await andreaniLogin(); if (!token) return res.status(503).json({ error: 'Andreani no configurado' }); const r = await fetch(`${ANDREANI_API}/v1/envios/${req.params.envio}/trazas`, { headers: { 'x-authorization-token': token } }); res.json(await r.json()); } catch (e) { res.status(500).json({ error: e.message }); } });
app.get('/api/andreani/etiqueta/:envio', async (req, res) => { try { const token = await andreaniLogin(); if (!token) return res.status(503).json({ error: 'Andreani no configurado' }); const r = await fetch(`${ANDREANI_API}/v1/ordenes-de-envio/${req.params.envio}/etiquetas`, { headers: { 'x-authorization-token': token, 'Accept': 'application/pdf' } }); res.set('Content-Type', 'application/pdf'); const buffer = await r.arrayBuffer(); res.send(Buffer.from(buffer)); } catch (e) { res.status(500).json({ error: e.message }); } });

// ═══ START ═══
const PORT = process.env.PORT || 3000;
migrate().then(() => {
  app.listen(PORT, () => console.log(`🚀 Server running on port ${PORT}`));
}).catch(e => { console.error('Migration failed:', e); process.exit(1); });
