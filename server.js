const express = require('express');
const cors = require('cors');
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const path = require('path');
const fs = require('fs');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'sistema-unificado-secret-key';
const FRONTEND_URL = process.env.FRONTEND_URL || 'http://localhost:5173';

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false,
});

app.use(cors({ origin: [FRONTEND_URL, /\.vercel\.app$/, /\.lean-droidgremio\.com$/, 'http://localhost:5173', 'http://localhost:4173'], credentials: true }));
app.use(express.json({ limit: '10mb' }));

// Servir uploads estáticos
const uploadsDir = path.join(__dirname, 'uploads');
if (!fs.existsSync(uploadsDir)) fs.mkdirSync(uploadsDir, { recursive: true });
app.use('/uploads', express.static(uploadsDir));

// Multer para subir imágenes
const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, uploadsDir),
  filename: (req, file, cb) => cb(null, Date.now() + '-' + file.originalname.replace(/[^a-zA-Z0-9.]/g, '_'))
});
const upload = multer({ storage, limits: { fileSize: 5 * 1024 * 1024 }, fileTypes: /jpeg|jpg|png|gif|webp/ });

// ══════════════════════════════════════════════════════════
// MIGRACIONES AUTOMÁTICAS
// ══════════════════════════════════════════════════════════
async function runMigrations() {
  const migs = [
    `CREATE TABLE IF NOT EXISTS configuracion (clave VARCHAR(100) PRIMARY KEY, valor TEXT NOT NULL DEFAULT '')`,
    `CREATE TABLE IF NOT EXISTS listas_precio (id VARCHAR(50) PRIMARY KEY, nombre VARCHAR(100) NOT NULL, multiplicador NUMERIC(6,4) NOT NULL DEFAULT 1, porcentaje NUMERIC(6,2) NOT NULL DEFAULT 0, color VARCHAR(20) NOT NULL DEFAULT '#2563eb', compra_minima NUMERIC(12,2) NOT NULL DEFAULT 0, promo_msg TEXT NOT NULL DEFAULT '')`,
    `CREATE TABLE IF NOT EXISTS usuarios (id SERIAL PRIMARY KEY, nombre VARCHAR(200) NOT NULL, usuario VARCHAR(100) UNIQUE NOT NULL, password VARCHAR(200) NOT NULL, telefono VARCHAR(50) NOT NULL DEFAULT '', email VARCHAR(200) NOT NULL DEFAULT '', direccion TEXT NOT NULL DEFAULT '', nombre_fantasia TEXT NOT NULL DEFAULT '', rol VARCHAR(20) NOT NULL DEFAULT 'cliente', lista_precio_id VARCHAR(50) REFERENCES listas_precio(id), aprobado BOOLEAN NOT NULL DEFAULT false, activo BOOLEAN NOT NULL DEFAULT true, notas_admin TEXT NOT NULL DEFAULT '', permisos TEXT NOT NULL DEFAULT '', secciones_permitidas TEXT NOT NULL DEFAULT '', es_revendedor BOOLEAN NOT NULL DEFAULT false, descuento_revendedor NUMERIC(5,2) NOT NULL DEFAULT 0, created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW())`,
    `CREATE TABLE IF NOT EXISTS secciones (id SERIAL PRIMARY KEY, nombre VARCHAR(100) NOT NULL, slug VARCHAR(50) UNIQUE NOT NULL, descripcion TEXT NOT NULL DEFAULT '', color VARCHAR(20) NOT NULL DEFAULT '#2563eb', whatsapp VARCHAR(30) NOT NULL DEFAULT '', cbu TEXT NOT NULL DEFAULT '', direccion_despacho TEXT NOT NULL DEFAULT '', metodos_pago TEXT NOT NULL DEFAULT '', activa BOOLEAN NOT NULL DEFAULT true, requiere_aprobacion BOOLEAN NOT NULL DEFAULT false, created_at TIMESTAMPTZ NOT NULL DEFAULT NOW())`,
    `INSERT INTO secciones (nombre,slug,descripcion,color,requiere_aprobacion) VALUES ('Local','local','Venta presencial','#2563eb',false),('Dropshipping','dropshipping','Envío directo','#7c3aed',false),('Mayorista','mayorista','Venta por mayor','#059669',true) ON CONFLICT (slug) DO NOTHING`,
    `CREATE TABLE IF NOT EXISTS productos (id SERIAL PRIMARY KEY, nombre VARCHAR(300) NOT NULL DEFAULT '', categoria VARCHAR(200) NOT NULL DEFAULT '', modelo VARCHAR(300) NOT NULL DEFAULT '', precio_base NUMERIC(12,2) NOT NULL DEFAULT 0, precio_original NUMERIC(12,2) NOT NULL DEFAULT 0, precio_oferta NUMERIC(12,2) NOT NULL DEFAULT 0, stock INT NOT NULL DEFAULT 0, stock_minimo INT NOT NULL DEFAULT 0, imagen TEXT NOT NULL DEFAULT '', notas TEXT NOT NULL DEFAULT '', descripcion TEXT NOT NULL DEFAULT '', sku VARCHAR(100) NOT NULL DEFAULT '', tipo VARCHAR(20) NOT NULL DEFAULT 'fisico', moneda VARCHAR(10) NOT NULL DEFAULT 'ARS', envio_gratis BOOLEAN NOT NULL DEFAULT false, visible BOOLEAN NOT NULL DEFAULT true, compatibilidad TEXT NOT NULL DEFAULT '', seccion_id INT REFERENCES secciones(id) DEFAULT 1, marca VARCHAR(100) NOT NULL DEFAULT '', compra_minima_unidades INT NOT NULL DEFAULT 1, peso INT NOT NULL DEFAULT 0, alto INT NOT NULL DEFAULT 0, ancho INT NOT NULL DEFAULT 0, largo INT NOT NULL DEFAULT 0, created_at TIMESTAMPTZ NOT NULL DEFAULT NOW())`,
    `CREATE TABLE IF NOT EXISTS precios_fijos (id SERIAL PRIMARY KEY, producto_id INT NOT NULL REFERENCES productos(id) ON DELETE CASCADE, lista_precio_id VARCHAR(50) NOT NULL REFERENCES listas_precio(id), precio_fijo NUMERIC(12,2) NOT NULL DEFAULT 0, UNIQUE(producto_id, lista_precio_id))`,
    `CREATE TABLE IF NOT EXISTS pedidos (id SERIAL PRIMARY KEY, usuario_id INT REFERENCES usuarios(id), cliente_nombre VARCHAR(200) NOT NULL DEFAULT '', cliente_telefono VARCHAR(50) NOT NULL DEFAULT '', tipo_entrega VARCHAR(20) NOT NULL DEFAULT 'retiro', direccion_envio TEXT NOT NULL DEFAULT '', estado VARCHAR(30) NOT NULL DEFAULT 'pendiente', estado_pago VARCHAR(30) NOT NULL DEFAULT 'pendiente', notas TEXT NOT NULL DEFAULT '', total NUMERIC(12,2) NOT NULL DEFAULT 0, lista_precio_nombre VARCHAR(50) NOT NULL DEFAULT '', metodo_pago VARCHAR(50) NOT NULL DEFAULT '', tipo VARCHAR(20) NOT NULL DEFAULT 'pedido', archivado BOOLEAN NOT NULL DEFAULT false, asignado_usuario_id INT REFERENCES usuarios(id), seccion_id INT REFERENCES secciones(id), costo_envio NUMERIC(12,2) NOT NULL DEFAULT 0, cupon_codigo VARCHAR(50) NOT NULL DEFAULT '', cupon_descuento NUMERIC(12,2) NOT NULL DEFAULT 0, created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW())`,
    `CREATE TABLE IF NOT EXISTS pedido_items (id SERIAL PRIMARY KEY, pedido_id INT NOT NULL REFERENCES pedidos(id) ON DELETE CASCADE, producto_id INT REFERENCES productos(id), nombre_producto VARCHAR(300) NOT NULL, cantidad INT NOT NULL DEFAULT 1, precio_unitario NUMERIC(12,2) NOT NULL DEFAULT 0, subtotal NUMERIC(12,2) NOT NULL DEFAULT 0)`,
    `CREATE TABLE IF NOT EXISTS historial_precios (id SERIAL PRIMARY KEY, producto_id INT REFERENCES productos(id) ON DELETE CASCADE, precio_anterior NUMERIC(12,2), precio_nuevo NUMERIC(12,2), usuario_id INT REFERENCES usuarios(id), usuario_nombre VARCHAR(200) NOT NULL DEFAULT '', tipo VARCHAR(30) NOT NULL DEFAULT 'manual', created_at TIMESTAMPTZ NOT NULL DEFAULT NOW())`,
    `CREATE TABLE IF NOT EXISTS cupones (id SERIAL PRIMARY KEY, codigo VARCHAR(50) UNIQUE NOT NULL, tipo VARCHAR(30) NOT NULL DEFAULT 'porcentaje', valor NUMERIC(12,2) NOT NULL DEFAULT 0, compra_minima NUMERIC(12,2) NOT NULL DEFAULT 0, uso_maximo INT NOT NULL DEFAULT 0, usos_actuales INT NOT NULL DEFAULT 0, fecha_inicio DATE, fecha_fin DATE, secciones_ids TEXT NOT NULL DEFAULT '', categoria VARCHAR(200) NOT NULL DEFAULT '', producto_id INT, medio_pago VARCHAR(100) NOT NULL DEFAULT '', activo BOOLEAN NOT NULL DEFAULT true, created_at TIMESTAMPTZ NOT NULL DEFAULT NOW())`,
    `CREATE TABLE IF NOT EXISTS cupon_productos (id SERIAL PRIMARY KEY, cupon_id INT NOT NULL REFERENCES cupones(id) ON DELETE CASCADE, producto_id INT NOT NULL REFERENCES productos(id) ON DELETE CASCADE, UNIQUE(cupon_id, producto_id))`,
    `CREATE TABLE IF NOT EXISTS paginas_info (id SERIAL PRIMARY KEY, titulo VARCHAR(200) NOT NULL, slug VARCHAR(100) NOT NULL, contenido TEXT NOT NULL DEFAULT '', seccion_id INT REFERENCES secciones(id), orden INT NOT NULL DEFAULT 0, visible BOOLEAN NOT NULL DEFAULT true, created_at TIMESTAMPTZ NOT NULL DEFAULT NOW())`,
    `CREATE TABLE IF NOT EXISTS badges (id SERIAL PRIMARY KEY, icono VARCHAR(10) NOT NULL DEFAULT '⭐', texto VARCHAR(200) NOT NULL DEFAULT '', orden INT NOT NULL DEFAULT 0, visible BOOLEAN NOT NULL DEFAULT true, secciones_ids TEXT NOT NULL DEFAULT '')`,
    `CREATE TABLE IF NOT EXISTS config_envio (id SERIAL PRIMARY KEY, seccion_id INT REFERENCES secciones(id) UNIQUE, metodo VARCHAR(30) NOT NULL DEFAULT 'manual', costo_fijo NUMERIC(12,2) NOT NULL DEFAULT 0, gratis_desde NUMERIC(12,2) NOT NULL DEFAULT 0, zonas JSONB NOT NULL DEFAULT '[]')`,
    `CREATE TABLE IF NOT EXISTS promociones (id SERIAL PRIMARY KEY, nombre VARCHAR(200) NOT NULL DEFAULT '', tipo VARCHAR(30) NOT NULL DEFAULT 'porcentaje', valor NUMERIC(12,2) NOT NULL DEFAULT 0, secciones_ids TEXT NOT NULL DEFAULT '', categoria VARCHAR(200) NOT NULL DEFAULT '', productos_ids TEXT NOT NULL DEFAULT '', fecha_inicio DATE, fecha_fin DATE, activa BOOLEAN NOT NULL DEFAULT true, created_at TIMESTAMPTZ NOT NULL DEFAULT NOW())`,
    `CREATE TABLE IF NOT EXISTS popups (id SERIAL PRIMARY KEY, titulo VARCHAR(200) NOT NULL DEFAULT '', imagen TEXT NOT NULL DEFAULT '', url_destino TEXT NOT NULL DEFAULT '', secciones_ids TEXT NOT NULL DEFAULT '', activo BOOLEAN NOT NULL DEFAULT true, mostrar_una_vez BOOLEAN NOT NULL DEFAULT true, created_at TIMESTAMPTZ NOT NULL DEFAULT NOW())`,
    `CREATE TABLE IF NOT EXISTS redes_sociales (id SERIAL PRIMARY KEY, tipo VARCHAR(50) NOT NULL, url TEXT NOT NULL DEFAULT '', activo BOOLEAN NOT NULL DEFAULT true, orden INT NOT NULL DEFAULT 0)`,
    `CREATE TABLE IF NOT EXISTS menu_items (id SERIAL PRIMARY KEY, titulo VARCHAR(100) NOT NULL, url TEXT NOT NULL DEFAULT '', tipo VARCHAR(30) NOT NULL DEFAULT 'link', seccion_id INT REFERENCES secciones(id), orden INT NOT NULL DEFAULT 0, visible BOOLEAN NOT NULL DEFAULT true)`,
    `CREATE TABLE IF NOT EXISTS design_config (clave VARCHAR(100) PRIMARY KEY, valor TEXT NOT NULL DEFAULT '')`,
    `CREATE TABLE IF NOT EXISTS metodos_pago (id SERIAL PRIMARY KEY, nombre VARCHAR(100) NOT NULL, descripcion TEXT NOT NULL DEFAULT '', instrucciones TEXT NOT NULL DEFAULT '', seccion_id INT REFERENCES secciones(id), activo BOOLEAN NOT NULL DEFAULT true, orden INT NOT NULL DEFAULT 0)`,
    // Columnas que podrían faltar en instalaciones previas
    "ALTER TABLE productos ADD COLUMN IF NOT EXISTS descripcion TEXT NOT NULL DEFAULT ''",
    "ALTER TABLE productos ADD COLUMN IF NOT EXISTS sku VARCHAR(100) NOT NULL DEFAULT ''",
    "ALTER TABLE productos ADD COLUMN IF NOT EXISTS tipo VARCHAR(20) NOT NULL DEFAULT 'fisico'",
    "ALTER TABLE productos ADD COLUMN IF NOT EXISTS moneda VARCHAR(10) NOT NULL DEFAULT 'ARS'",
    "ALTER TABLE productos ADD COLUMN IF NOT EXISTS precio_oferta NUMERIC(12,2) NOT NULL DEFAULT 0",
    "ALTER TABLE productos ADD COLUMN IF NOT EXISTS envio_gratis BOOLEAN NOT NULL DEFAULT false",
    "ALTER TABLE productos ADD COLUMN IF NOT EXISTS visible BOOLEAN NOT NULL DEFAULT true",
    "ALTER TABLE productos ADD COLUMN IF NOT EXISTS peso INT NOT NULL DEFAULT 0",
    "ALTER TABLE productos ADD COLUMN IF NOT EXISTS alto INT NOT NULL DEFAULT 0",
    "ALTER TABLE productos ADD COLUMN IF NOT EXISTS ancho INT NOT NULL DEFAULT 0",
    "ALTER TABLE productos ADD COLUMN IF NOT EXISTS largo INT NOT NULL DEFAULT 0",
    "ALTER TABLE badges ADD COLUMN IF NOT EXISTS secciones_ids TEXT NOT NULL DEFAULT ''",
    "ALTER TABLE usuarios ADD COLUMN IF NOT EXISTS es_revendedor BOOLEAN NOT NULL DEFAULT false",
    "ALTER TABLE usuarios ADD COLUMN IF NOT EXISTS descuento_revendedor NUMERIC(5,2) NOT NULL DEFAULT 0",
    // Indexes
    "CREATE INDEX IF NOT EXISTS idx_productos_categoria ON productos(categoria)",
    "CREATE INDEX IF NOT EXISTS idx_productos_seccion ON productos(seccion_id)",
    "CREATE INDEX IF NOT EXISTS idx_productos_marca ON productos(marca)",
    "CREATE INDEX IF NOT EXISTS idx_productos_visible ON productos(visible)",
    "CREATE INDEX IF NOT EXISTS idx_pedidos_usuario ON pedidos(usuario_id)",
    "CREATE INDEX IF NOT EXISTS idx_pedidos_estado ON pedidos(estado)",
    "CREATE INDEX IF NOT EXISTS idx_pedidos_seccion ON pedidos(seccion_id)",
    "CREATE INDEX IF NOT EXISTS idx_cupones_codigo ON cupones(codigo)",
    "CREATE INDEX IF NOT EXISTS idx_promociones_activa ON promociones(activa)",
    // Design defaults
    "INSERT INTO design_config (clave,valor) VALUES ('color_primario','#2563eb') ON CONFLICT DO NOTHING",
    "INSERT INTO design_config (clave,valor) VALUES ('color_secundario','#1e40af') ON CONFLICT DO NOTHING",
    "INSERT INTO design_config (clave,valor) VALUES ('color_acento','#f59e0b') ON CONFLICT DO NOTHING",
    "INSERT INTO design_config (clave,valor) VALUES ('font_familia','Inter, sans-serif') ON CONFLICT DO NOTHING",
    "INSERT INTO design_config (clave,valor) VALUES ('logo_url','') ON CONFLICT DO NOTHING",
    "INSERT INTO design_config (clave,valor) VALUES ('favicon_url','') ON CONFLICT DO NOTHING",
    "INSERT INTO design_config (clave,valor) VALUES ('nombre_tienda','Mi Tienda') ON CONFLICT DO NOTHING",
    "INSERT INTO design_config (clave,valor) VALUES ('plantilla','moderna') ON CONFLICT DO NOTHING",
    "INSERT INTO design_config (clave,valor) VALUES ('footer_texto','') ON CONFLICT DO NOTHING",
    // Config defaults
    "INSERT INTO configuracion (clave,valor) VALUES ('metodos_pago','') ON CONFLICT (clave) DO NOTHING",
    "INSERT INTO configuracion (clave,valor) VALUES ('alertas_stock','false') ON CONFLICT (clave) DO NOTHING",
    "INSERT INTO configuracion (clave,valor) VALUES ('whatsapp_flotante','') ON CONFLICT (clave) DO NOTHING",
  ];
  for (const m of migs) await pool.query(m).catch(e => { if (!e.message.includes('already exists') && !e.message.includes('duplicate')) console.log('[MIG]', e.message.slice(0,80)); });
  console.log('[DB] Migrations OK');
}

// ══════════════════════════════════════════════════════════
// MIDDLEWARE
// ══════════════════════════════════════════════════════════
function auth(requiredRole) {
  return async (req, res, next) => {
    const token = req.headers.authorization?.replace('Bearer ', '');
    if (!token) return res.status(401).json({ error: 'Token requerido' });
    try {
      const decoded = jwt.verify(token, JWT_SECRET);
      const { rows } = await pool.query('SELECT * FROM usuarios WHERE id=$1 AND activo=true', [decoded.id]);
      if (!rows[0]) return res.status(401).json({ error: 'Token inválido' });
      req.user = rows[0];
      if (requiredRole === 'admin' && !['admin','subadmin'].includes(req.user.rol)) return res.status(403).json({ error: 'Admin requerido' });
      next();
    } catch (e) { res.status(401).json({ error: 'Token expirado' }); }
  };
}
const optionalAuth = async (req, res, next) => {
  const token = req.headers.authorization?.replace('Bearer ', '');
  if (token) { try { const d = jwt.verify(token, JWT_SECRET); const { rows } = await pool.query('SELECT * FROM usuarios WHERE id=$1 AND activo=true', [d.id]); req.user = rows[0] || null; } catch {} }
  next();
};

app.get('/api/health', (req, res) => res.json({ ok: true, ts: new Date().toISOString() }));

// ══════════════════════════════════════════════════════════
// AUTH + MANTENIMIENTO
// ══════════════════════════════════════════════════════════

app.get('/api/maintenance-status', async (req, res) => {
  try {
    const { rows } = await pool.query("SELECT clave, valor FROM configuracion WHERE clave LIKE 'mantenimiento%'");
    const m = {}; rows.forEach(r => m[r.clave] = r.valor);
    res.json({ activo: m.mantenimiento_activo === 'true', mensaje: m.mantenimiento_mensaje || '', countdown: m.mantenimiento_countdown || '' });
  } catch (e) { res.json({ activo: false }); }
});

app.post('/api/maintenance-mode', auth('admin'), async (req, res) => {
  try { const { activo, mensaje, countdown } = req.body;
    for (const [k,v] of [['mantenimiento_activo', activo?'true':'false'],['mantenimiento_mensaje',mensaje||''],['mantenimiento_countdown',countdown||'']]) {
      await pool.query("INSERT INTO configuracion (clave,valor) VALUES ($1,$2) ON CONFLICT (clave) DO UPDATE SET valor=$2", [k, v]);
    } res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/login', async (req, res) => {
  try { const { usuario, password } = req.body;
    const { rows } = await pool.query('SELECT * FROM usuarios WHERE usuario=$1 AND activo=true', [usuario]);
    if (!rows[0]) {
      const { rows: pend } = await pool.query('SELECT * FROM usuarios WHERE usuario=$1 AND aprobado=false', [usuario]);
      if (pend[0]) return res.status(403).json({ error: 'Pendiente de aprobación', pendiente: true });
      return res.status(401).json({ error: 'Usuario o contraseña incorrectos' });
    }
    if (!await bcrypt.compare(password, rows[0].password)) return res.status(401).json({ error: 'Usuario o contraseña incorrectos' });
    const u = rows[0]; const token = jwt.sign({ id: u.id, rol: u.rol }, JWT_SECRET, { expiresIn: '30d' });
    res.json({ token, id: u.id, nombre: u.nombre, rol: u.rol, lista_precio_id: u.lista_precio_id, nombre_fantasia: u.nombre_fantasia || '', es_revendedor: u.es_revendedor, descuento_revendedor: Number(u.descuento_revendedor) });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/register', async (req, res) => {
  try { const { nombre, usuario, password, telefono, email, direccion, nombre_fantasia } = req.body;
    const hash = await bcrypt.hash(password, 10);
    const { rows: existing } = await pool.query('SELECT id FROM usuarios WHERE usuario=$1', [usuario.toLowerCase()]);
    if (existing.length) return res.status(400).json({ error: 'Usuario ya existe' });
    const { rows: listas } = await pool.query('SELECT id FROM listas_precio ORDER BY id LIMIT 1');
    await pool.query('INSERT INTO usuarios (nombre,usuario,password,telefono,email,direccion,nombre_fantasia,rol,aprobado,activo,lista_precio_id) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,false,false,$9)',
      [nombre, usuario.toLowerCase(), hash, telefono||'', email||'', direccion||'', nombre_fantasia||'', 'cliente', listas[0]?.id || 'may_aaa']);
    res.json({ ok: true, mensaje: 'Registrado. Esperando aprobación del administrador.' });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/me', auth(), async (req, res) => {
  const u = req.user;
  res.json({ id: u.id, nombre: u.nombre, usuario: u.usuario, rol: u.rol, lista_precio_id: u.lista_precio_id, telefono: u.telefono, email: u.email, direccion: u.direccion, nombre_fantasia: u.nombre_fantasia || '', es_revendedor: u.es_revendedor, descuento_revendedor: Number(u.descuento_revendedor) });
});

app.put('/api/me', auth(), async (req, res) => {
  try { const { nombre, telefono, email, direccion, password, nombre_fantasia } = req.body;
    if (password) { const hash = await bcrypt.hash(password, 10); await pool.query('UPDATE usuarios SET password=$1 WHERE id=$2', [hash, req.user.id]); }
    await pool.query('UPDATE usuarios SET nombre=COALESCE($1,nombre),telefono=COALESCE($2,telefono),email=COALESCE($3,email),direccion=COALESCE($4,direccion),nombre_fantasia=COALESCE($5,nombre_fantasia),updated_at=NOW() WHERE id=$6',
      [nombre, telefono, email, direccion, nombre_fantasia, req.user.id]);
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ══════════════════════════════════════════════════════════
// CONFIG + LISTAS + SECCIONES
// ══════════════════════════════════════════════════════════

app.get('/api/config', async (req, res) => {
  try { const { rows } = await pool.query('SELECT clave, valor FROM configuracion'); const cfg = {}; rows.forEach(r => cfg[r.clave] = r.valor); res.json(cfg); } catch (e) { res.status(500).json({ error: e.message }); }
});
app.put('/api/config', auth('admin'), async (req, res) => {
  try { for (const [k, v] of Object.entries(req.body)) { await pool.query('INSERT INTO configuracion (clave,valor) VALUES ($1,$2) ON CONFLICT (clave) DO UPDATE SET valor=$2', [k, String(v)]); } res.json({ ok: true }); } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/listas', async (req, res) => {
  try { const { rows } = await pool.query('SELECT * FROM listas_precio ORDER BY multiplicador');
    res.json(rows.map(l => ({ ...l, multiplicador: Number(l.multiplicador), porcentaje: Math.round((Number(l.multiplicador)-1)*10000)/100 })));
  } catch (e) { res.status(500).json({ error: e.message }); }
});
app.put('/api/listas', auth('admin'), async (req, res) => {
  try { for (const l of req.body.listas) {
    await pool.query(`INSERT INTO listas_precio (id,nombre,multiplicador,porcentaje,color,compra_minima,promo_msg) VALUES ($1,$2,$3,$4,$5,$6,$7) ON CONFLICT (id) DO UPDATE SET nombre=$2,multiplicador=$3,porcentaje=$4,color=$5,compra_minima=$6,promo_msg=$7`,
      [l.id, l.nombre, l.multiplicador, l.porcentaje||0, l.color||'#2563eb', l.compra_minima||0, l.promo_msg||'']);
  } res.json({ ok: true }); } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/secciones', async (req, res) => { try { const { rows } = await pool.query('SELECT * FROM secciones ORDER BY id'); res.json(rows); } catch (e) { res.status(500).json({ error: e.message }); } });
app.get('/api/secciones/:id', async (req, res) => { try { const { rows } = await pool.query('SELECT * FROM secciones WHERE id=$1', [req.params.id]); if (!rows[0]) return res.status(404).json({ error: 'No encontrada' }); res.json(rows[0]); } catch (e) { res.status(500).json({ error: e.message }); } });
app.put('/api/secciones/:id', auth('admin'), async (req, res) => {
  try { const { nombre, descripcion, color, whatsapp, cbu, direccion_despacho, metodos_pago, activa, requiere_aprobacion } = req.body;
    await pool.query(`UPDATE secciones SET nombre=COALESCE($1,nombre),descripcion=COALESCE($2,descripcion),color=COALESCE($3,color),whatsapp=COALESCE($4,whatsapp),cbu=COALESCE($5,cbu),direccion_despacho=COALESCE($6,direccion_despacho),metodos_pago=COALESCE($7,metodos_pago),activa=COALESCE($8,activa),requiere_aprobacion=COALESCE($9,requiere_aprobacion) WHERE id=$10`,
      [nombre, descripcion, color, whatsapp, cbu, direccion_despacho, metodos_pago, activa, requiere_aprobacion, req.params.id]);
    res.json({ ok: true }); } catch (e) { res.status(500).json({ error: e.message }); }
});
app.post('/api/secciones', auth('admin'), async (req, res) => {
  try { const { nombre, slug, descripcion, color } = req.body;
    const { rows } = await pool.query('INSERT INTO secciones (nombre,slug,descripcion,color) VALUES ($1,$2,$3,$4) RETURNING *', [nombre, slug, descripcion||'', color||'#64748b']);
    res.json(rows[0]); } catch (e) { res.status(500).json({ error: e.message }); }
});
app.delete('/api/secciones/:id', auth('admin'), async (req, res) => { try { await pool.query('DELETE FROM secciones WHERE id=$1', [req.params.id]); res.json({ ok: true }); } catch (e) { res.status(500).json({ error: e.message }); } });

// ══════════════════════════════════════════════════════════
// UPLOAD IMAGEN
// ══════════════════════════════════════════════════════════
app.post('/api/upload', auth('admin'), upload.single('imagen'), (req, res) => {
  if (!req.file) return res.status(400).json({ error: 'No se recibió archivo' });
  const url = `${req.protocol}://${req.get('host')}/uploads/${req.file.filename}`;
  res.json({ url, filename: req.file.filename });
});

// ══════════════════════════════════════════════════════════
// PRODUCTOS (con filtro por sección + visible + stock order)
// ══════════════════════════════════════════════════════════

app.get('/api/productos', optionalAuth, async (req, res) => {
  try { const { q, categoria, page = 1, limit = 50, seccion_id, marca } = req.query;
    let where = []; const params = []; let i = 1;
    if (seccion_id) { where.push(`p.seccion_id=$${i++}`); params.push(seccion_id); }
    if (categoria) { where.push(`p.categoria=$${i++}`); params.push(categoria); }
    if (marca) { where.push(`p.marca=$${i++}`); params.push(marca); }
    if (q) { where.push(`(p.modelo ILIKE $${i} OR p.categoria ILIKE $${i} OR p.compatibilidad ILIKE $${i} OR p.nombre ILIKE $${i} OR p.sku ILIKE $${i})`); params.push(`%${q}%`); i++; }
    // Solo mostrar visibles para no-admin
    const isAdmin = req.user && ['admin','subadmin'].includes(req.user.rol);
    if (!isAdmin) { where.push('p.visible=true'); }
    const wc = where.length ? 'WHERE ' + where.join(' AND ') : '';
    const countQ = await pool.query(`SELECT COUNT(*) FROM productos p ${wc}`, params);
    const total = parseInt(countQ.rows[0].count);
    params.push(parseInt(limit)); params.push((parseInt(page)-1)*parseInt(limit));
    const { rows } = await pool.query(`SELECT p.*, s.nombre as seccion_nombre, s.slug as seccion_slug FROM productos p LEFT JOIN secciones s ON p.seccion_id=s.id ${wc} ORDER BY (CASE WHEN p.stock > 0 THEN 0 ELSE 1 END), p.categoria, p.nombre LIMIT $${i++} OFFSET $${i++}`, params);
    const isAuth = !!req.user;
    res.json({ productos: rows.map(r => ({ ...r, precio_base: isAuth || !r.seccion_slug || r.seccion_slug !== 'mayorista' ? r.precio_base : undefined })), total, page: parseInt(page) });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/categorias', async (req, res) => {
  try { const { seccion_id } = req.query;
    const q = seccion_id ? 'SELECT DISTINCT categoria FROM productos WHERE seccion_id=$1 ORDER BY categoria' : 'SELECT DISTINCT categoria FROM productos ORDER BY categoria';
    const { rows } = await pool.query(q, seccion_id ? [seccion_id] : []);
    res.json(rows.map(r => r.categoria));
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/productos', auth('admin'), async (req, res) => {
  try { const { nombre, categoria, modelo, precio_base, precio_oferta, stock, stock_minimo, imagen, notas, descripcion, sku, tipo, moneda, envio_gratis, visible, compatibilidad, seccion_id, marca, compra_minima_unidades, peso, alto, ancho, largo } = req.body;
    const { rows } = await pool.query(
      `INSERT INTO productos (nombre,categoria,modelo,precio_base,precio_original,precio_oferta,stock,stock_minimo,imagen,notas,descripcion,sku,tipo,moneda,envio_gratis,visible,compatibilidad,seccion_id,marca,compra_minima_unidades,peso,alto,ancho,largo) VALUES ($1,$2,$3,$4,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,$23) RETURNING *`,
      [nombre||modelo||'', categoria||'', modelo||'', precio_base||0, precio_oferta||0, stock||0, stock_minimo||0, imagen||'', notas||'', descripcion||'', sku||'', tipo||'fisico', moneda||'ARS', envio_gratis||false, visible!==false, compatibilidad||'', seccion_id||1, marca||'', compra_minima_unidades||1, peso||0, alto||0, ancho||0, largo||0]);
    res.json(rows[0]); } catch (e) { res.status(500).json({ error: e.message }); }
});

app.put('/api/productos/:id', auth('admin'), async (req, res) => {
  try { const { nombre, categoria, modelo, precio_base, precio_oferta, stock, stock_minimo, imagen, notas, descripcion, sku, tipo, moneda, envio_gratis, visible, compatibilidad, seccion_id, marca, compra_minima_unidades, peso, alto, ancho, largo } = req.body;
    if (precio_base !== undefined) {
      const { rows: old } = await pool.query('SELECT precio_base FROM productos WHERE id=$1', [req.params.id]);
      if (old[0] && Number(old[0].precio_base) !== Number(precio_base)) {
        await pool.query('INSERT INTO historial_precios (producto_id,precio_anterior,precio_nuevo,usuario_id,usuario_nombre,tipo) VALUES ($1,$2,$3,$4,$5,$6)',
          [req.params.id, old[0].precio_base, precio_base, req.user.id, req.user.nombre, 'manual']);
      }
    }
    await pool.query(`UPDATE productos SET nombre=COALESCE($1,nombre),categoria=COALESCE($2,categoria),modelo=COALESCE($3,modelo),precio_base=COALESCE($4,precio_base),precio_oferta=COALESCE($5,precio_oferta),stock=COALESCE($6,stock),stock_minimo=COALESCE($7,stock_minimo),imagen=COALESCE($8,imagen),notas=COALESCE($9,notas),descripcion=COALESCE($10,descripcion),sku=COALESCE($11,sku),tipo=COALESCE($12,tipo),moneda=COALESCE($13,moneda),envio_gratis=COALESCE($14,envio_gratis),visible=COALESCE($15,visible),compatibilidad=COALESCE($16,compatibilidad),seccion_id=COALESCE($17,seccion_id),marca=COALESCE($18,marca),compra_minima_unidades=COALESCE($19,compra_minima_unidades),peso=COALESCE($20,peso),alto=COALESCE($21,alto),ancho=COALESCE($22,ancho),largo=COALESCE($23,largo) WHERE id=$24`,
      [nombre, categoria, modelo, precio_base, precio_oferta, stock, stock_minimo, imagen, notas, descripcion, sku, tipo, moneda, envio_gratis, visible, compatibilidad, seccion_id, marca, compra_minima_unidades, peso, alto, ancho, largo, req.params.id]);
    res.json({ ok: true }); } catch (e) { res.status(500).json({ error: e.message }); }
});

app.delete('/api/productos/:id', auth('admin'), async (req, res) => { try { await pool.query('DELETE FROM productos WHERE id=$1', [req.params.id]); res.json({ ok: true }); } catch (e) { res.status(500).json({ error: e.message }); } });

app.post('/api/productos/bulk', auth('admin'), async (req, res) => {
  try { const { productos, reemplazar } = req.body;
    if (reemplazar) await pool.query('DELETE FROM productos');
    let count = 0;
    for (const p of productos) {
      await pool.query('INSERT INTO productos (nombre,categoria,modelo,precio_base,precio_original,seccion_id,marca,stock,imagen,sku) VALUES ($1,$2,$3,$4,$4,$5,$6,$7,$8,$9)',
        [p.nombre||p.modelo||'', p.categoria||'', p.modelo||'', p.precio_base||0, p.seccion_id||1, p.marca||'', p.stock||0, p.imagen||'', p.sku||'']);
      count++;
    }
    res.json({ insertados: count }); } catch (e) { res.status(500).json({ error: e.message }); }
});

app.delete('/api/categorias/:cat', auth('admin'), async (req, res) => { try { await pool.query('DELETE FROM productos WHERE categoria=$1', [decodeURIComponent(req.params.cat)]); res.json({ ok: true }); } catch (e) { res.status(500).json({ error: e.message }); } });
app.delete('/api/productos/all', auth('admin'), async (req, res) => { try { await pool.query('DELETE FROM productos'); res.json({ ok: true }); } catch (e) { res.status(500).json({ error: e.message }); } });

app.post('/api/precios/ajustar', auth('admin'), async (req, res) => {
  try { const { porcentaje, categoria } = req.body; const mult = 1 + Number(porcentaje)/100;
    const wh = categoria ? 'WHERE categoria=$1' : ''; const prms = categoria ? [categoria] : [];
    const { rows: before } = await pool.query(`SELECT id, precio_base FROM productos ${wh}`, prms);
    await pool.query(`UPDATE productos SET precio_base = ROUND(precio_base * ${mult}, 2) ${wh}`, prms);
    for (const b of before) { await pool.query('INSERT INTO historial_precios (producto_id,precio_anterior,precio_nuevo,usuario_id,usuario_nombre,tipo) VALUES ($1,$2,$3,$4,$5,$6)', [b.id, b.precio_base, Math.round(b.precio_base*mult*100)/100, req.user.id, req.user.nombre, 'ajuste']); }
    res.json({ ok: true }); } catch (e) { res.status(500).json({ error: e.message }); }
});
app.post('/api/precios/reset', auth('admin'), async (req, res) => { try { await pool.query('UPDATE productos SET precio_base = precio_original WHERE precio_original > 0'); res.json({ ok: true }); } catch (e) { res.status(500).json({ error: e.message }); } });
app.get('/api/historial-precios', auth('admin'), async (req, res) => { try { const { rows } = await pool.query(`SELECT hp.*, p.categoria, p.modelo, p.nombre FROM historial_precios hp LEFT JOIN productos p ON hp.producto_id=p.id ORDER BY hp.created_at DESC LIMIT 200`); res.json(rows); } catch (e) { res.status(500).json({ error: e.message }); } });
app.get('/api/precios-fijos', async (req, res) => { try { const { rows } = await pool.query('SELECT * FROM precios_fijos'); res.json(rows); } catch (e) { res.status(500).json({ error: e.message }); } });
app.post('/api/precios-fijos', auth('admin'), async (req, res) => {
  try { const { producto_id, lista_precio_id, precio_fijo } = req.body;
    if (!precio_fijo || precio_fijo <= 0) { await pool.query('DELETE FROM precios_fijos WHERE producto_id=$1 AND lista_precio_id=$2', [producto_id, lista_precio_id]); }
    else { await pool.query('INSERT INTO precios_fijos (producto_id,lista_precio_id,precio_fijo) VALUES ($1,$2,$3) ON CONFLICT (producto_id,lista_precio_id) DO UPDATE SET precio_fijo=$3', [producto_id, lista_precio_id, precio_fijo]); }
    res.json({ ok: true }); } catch (e) { res.status(500).json({ error: e.message }); }
});

// Marcas y modelos para wizard
app.get('/api/marcas', async (req, res) => {
  try { const { seccion_id } = req.query;
    const q = seccion_id ? "SELECT DISTINCT marca FROM productos WHERE marca != '' AND seccion_id=$1 ORDER BY marca" : "SELECT DISTINCT marca FROM productos WHERE marca != '' ORDER BY marca";
    const { rows } = await pool.query(q, seccion_id ? [seccion_id] : []);
    res.json({ marcas: rows.map(r => r.marca) });
  } catch (e) { res.status(500).json({ error: e.message }); }
});
app.get('/api/modelos', async (req, res) => {
  try { const { marca, seccion_id } = req.query;
    let q = "SELECT DISTINCT modelo FROM productos WHERE marca=$1"; const p = [marca];
    if (seccion_id) { q += " AND seccion_id=$2"; p.push(seccion_id); }
    q += " ORDER BY modelo";
    const { rows } = await pool.query(q, p); res.json({ modelos: rows.map(r => r.modelo) });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// Búsqueda de productos para admin (cupones, promociones)
app.get('/api/productos/buscar', auth('admin'), async (req, res) => {
  try { const { q } = req.query; if (!q) return res.json([]);
    const { rows } = await pool.query("SELECT id, nombre, modelo, categoria, precio_base, imagen FROM productos WHERE nombre ILIKE $1 OR modelo ILIKE $1 OR categoria ILIKE $1 LIMIT 20", [`%${q}%`]);
    res.json(rows);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ══════════════════════════════════════════════════════════
// USUARIOS
// ══════════════════════════════════════════════════════════

app.get('/api/usuarios', auth('admin'), async (req, res) => {
  try { const { q } = req.query;
    let query = "SELECT id,nombre,usuario,telefono,email,direccion,rol,lista_precio_id,aprobado,activo,created_at,nombre_fantasia,notas_admin,permisos,es_revendedor,descuento_revendedor, CASE WHEN aprobado=false THEN 'pendiente' WHEN activo=false THEN 'suspendido' ELSE 'activo' END as estado FROM usuarios";
    const params = [];
    if (q) { query += " WHERE nombre ILIKE $1 OR usuario ILIKE $1 OR nombre_fantasia ILIKE $1"; params.push(`%${q}%`); }
    query += " ORDER BY created_at DESC";
    const { rows } = await pool.query(query, params); res.json(rows);
  } catch (e) { res.status(500).json({ error: e.message }); }
});
app.get('/api/usuarios/pendientes/count', auth('admin'), async (req, res) => { try { const { rows } = await pool.query('SELECT COUNT(*) FROM usuarios WHERE aprobado=false'); res.json({ count: parseInt(rows[0].count) }); } catch (e) { res.json({ count: 0 }); } });

app.put('/api/usuarios/:id', auth('admin'), async (req, res) => {
  try { const { nombre, usuario, password, telefono, email, direccion, rol, lista_precio_id, activo, nombre_fantasia, notas_admin, permisos, es_revendedor, descuento_revendedor } = req.body;
    if (password) { const hash = await bcrypt.hash(password, 10); await pool.query('UPDATE usuarios SET password=$1 WHERE id=$2', [hash, req.params.id]); }
    await pool.query(`UPDATE usuarios SET nombre=COALESCE($1,nombre),usuario=COALESCE($2,usuario),telefono=COALESCE($3,telefono),email=COALESCE($4,email),direccion=COALESCE($5,direccion),rol=COALESCE($6,rol),lista_precio_id=COALESCE($7,lista_precio_id),activo=COALESCE($8,activo),nombre_fantasia=COALESCE($9,nombre_fantasia),notas_admin=COALESCE($10,notas_admin),permisos=COALESCE($11,permisos),es_revendedor=COALESCE($12,es_revendedor),descuento_revendedor=COALESCE($13,descuento_revendedor),updated_at=NOW() WHERE id=$14`,
      [nombre, usuario, telefono, email, direccion, rol, lista_precio_id, activo, nombre_fantasia, notas_admin, permisos, es_revendedor, descuento_revendedor, req.params.id]);
    res.json({ ok: true }); } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/usuarios/:id/aprobar', auth('admin'), async (req, res) => {
  try { const { lista_precio_id } = req.body;
    await pool.query('UPDATE usuarios SET aprobado=true, activo=true, lista_precio_id=COALESCE($1,lista_precio_id) WHERE id=$2', [lista_precio_id, req.params.id]);
    const { rows } = await pool.query('SELECT * FROM usuarios WHERE id=$1', [req.params.id]); res.json(rows[0]);
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

// ══════════════════════════════════════════════════════════
// PEDIDOS
// ══════════════════════════════════════════════════════════

app.get('/api/pedidos', auth(), async (req, res) => {
  try { const { archivado, seccion_id } = req.query;
    let where = []; const params = []; let i = 1;
    if (!['admin','subadmin'].includes(req.user.rol)) { where.push(`p.usuario_id=$${i++}`); params.push(req.user.id); }
    if (archivado === 'true') where.push('p.archivado=true'); else where.push('p.archivado=false');
    if (seccion_id) { where.push(`p.seccion_id=$${i++}`); params.push(seccion_id); }
    const wc = where.length ? 'WHERE ' + where.join(' AND ') : '';
    const { rows } = await pool.query(`SELECT p.*, u.nombre as usuario_nombre, u.telefono as usuario_telefono, u.nombre_fantasia, (SELECT COUNT(*) FROM pedido_items WHERE pedido_id=p.id) as item_count, au.nombre as asignado_nombre FROM pedidos p LEFT JOIN usuarios u ON p.usuario_id=u.id LEFT JOIN usuarios au ON p.asignado_usuario_id=au.id ${wc} ORDER BY p.created_at DESC`, params);
    res.json(rows); } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/pedidos/:id', auth(), async (req, res) => {
  try { const { rows: [order] } = await pool.query(`SELECT p.*, u.nombre as usuario_nombre, u.telefono as usuario_telefono, u.email as usuario_email, u.nombre_fantasia FROM pedidos p LEFT JOIN usuarios u ON p.usuario_id=u.id WHERE p.id=$1`, [req.params.id]);
    if (!order) return res.status(404).json({ error: 'No encontrado' });
    const { rows: items } = await pool.query(`SELECT pi.*, pr.categoria, pr.modelo, pr.nombre as prod_nombre FROM pedido_items pi LEFT JOIN productos pr ON pi.producto_id=pr.id WHERE pi.pedido_id=$1`, [req.params.id]);
    res.json({ ...order, items }); } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/pedidos', auth(), async (req, res) => {
  try { const { items, total, tipo_entrega, direccion, notas, estado_pago, metodo_pago, tipo, seccion_id, cupon_codigo, cupon_descuento } = req.body;
    const u = req.user;
    const { rows: [order] } = await pool.query(
      `INSERT INTO pedidos (usuario_id,cliente_nombre,cliente_telefono,tipo_entrega,direccion_envio,notas,total,lista_precio_nombre,estado_pago,metodo_pago,tipo,seccion_id,cupon_codigo,cupon_descuento) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14) RETURNING *`,
      [u.id, u.nombre, u.telefono||'', tipo_entrega||'retiro', direccion||'', notas||'', total||0, '', estado_pago||'pendiente', metodo_pago||'', tipo||'pedido', seccion_id||null, cupon_codigo||'', cupon_descuento||0]);
    if (items?.length) { for (const it of items) {
      await pool.query('INSERT INTO pedido_items (pedido_id,producto_id,nombre_producto,cantidad,precio_unitario,subtotal) VALUES ($1,$2,$3,$4,$5,$6)',
        [order.id, it.producto_id, it.nombre_producto||it.nombre||`${it.categoria} - ${it.modelo}`, it.cantidad||it.qty||1, it.precio_unitario||0, (it.precio_unitario||0)*(it.cantidad||it.qty||1)]);
    }}
    if (cupon_codigo) await pool.query("UPDATE cupones SET usos_actuales=usos_actuales+1 WHERE codigo=$1", [cupon_codigo]);
    res.json(order); } catch (e) { res.status(500).json({ error: e.message }); }
});

app.put('/api/pedidos/:id', auth('admin'), async (req, res) => {
  try { const { estado, estado_pago, metodo_pago, notas, tipo, asignado_usuario_id, items, total } = req.body;
    if (items) {
      await pool.query('DELETE FROM pedido_items WHERE pedido_id=$1', [req.params.id]);
      for (const it of items) { await pool.query('INSERT INTO pedido_items (pedido_id,producto_id,nombre_producto,cantidad,precio_unitario,subtotal) VALUES ($1,$2,$3,$4,$5,$6)',
        [req.params.id, it.producto_id, it.nombre_producto||`${it.categoria} - ${it.modelo}`, it.cantidad||it.qty||1, it.precio_unitario||0, (it.precio_unitario||0)*(it.cantidad||it.qty||1)]); }
      if (total !== undefined) await pool.query('UPDATE pedidos SET total=$1,updated_at=NOW() WHERE id=$2', [total, req.params.id]);
    }
    const sets = []; const vals = []; let i = 1;
    if (estado !== undefined) { sets.push(`estado=$${i++}`); vals.push(estado); }
    if (estado_pago !== undefined) { sets.push(`estado_pago=$${i++}`); vals.push(estado_pago); }
    if (metodo_pago !== undefined) { sets.push(`metodo_pago=$${i++}`); vals.push(metodo_pago); }
    if (notas !== undefined) { sets.push(`notas=$${i++}`); vals.push(notas); }
    if (tipo !== undefined) { sets.push(`tipo=$${i++}`); vals.push(tipo); }
    if (asignado_usuario_id !== undefined) { sets.push(`asignado_usuario_id=$${i++}`); vals.push(asignado_usuario_id); }
    if (sets.length) { sets.push('updated_at=NOW()'); vals.push(req.params.id); await pool.query(`UPDATE pedidos SET ${sets.join(',')} WHERE id=$${i}`, vals); }
    res.json({ ok: true }); } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/pedidos/:id/archivar', auth('admin'), async (req, res) => { try { await pool.query('UPDATE pedidos SET archivado=true WHERE id=$1', [req.params.id]); res.json({ ok: true }); } catch (e) { res.status(500).json({ error: e.message }); } });
app.post('/api/pedidos/:id/desarchivar', auth('admin'), async (req, res) => { try { await pool.query('UPDATE pedidos SET archivado=false WHERE id=$1', [req.params.id]); res.json({ ok: true }); } catch (e) { res.status(500).json({ error: e.message }); } });
app.delete('/api/pedidos/:id', auth('admin'), async (req, res) => { try { await pool.query('DELETE FROM pedido_items WHERE pedido_id=$1', [req.params.id]); await pool.query('DELETE FROM pedidos WHERE id=$1', [req.params.id]); res.json({ ok: true }); } catch (e) { res.status(500).json({ error: e.message }); } });

// ══════════════════════════════════════════════════════════
// STATS MEJORADAS (con gráfico por período)
// ══════════════════════════════════════════════════════════

app.get('/api/stats', auth('admin'), async (req, res) => {
  try { const { seccion_id, desde, hasta } = req.query;
    const sf = seccion_id ? ` AND seccion_id=${parseInt(seccion_id)}` : '';
    const df = desde ? ` AND created_at >= '${desde}'` : '';
    const hf = hasta ? ` AND created_at <= '${hasta}'` : '';
    const [tp, to, tu, tv, tpd] = await Promise.all([
      pool.query(`SELECT COUNT(*) FROM productos WHERE true${seccion_id ? ` AND seccion_id=${parseInt(seccion_id)}` : ''}`),
      pool.query(`SELECT COUNT(*) FROM pedidos WHERE true${sf}${df}${hf}`),
      pool.query('SELECT COUNT(*) FROM usuarios'),
      pool.query(`SELECT COALESCE(SUM(total),0) as total FROM pedidos WHERE estado_pago='pagado'${sf}${df}${hf}`),
      pool.query(`SELECT DATE(created_at) as fecha, COUNT(*) as cantidad, COALESCE(SUM(total),0) as monto FROM pedidos WHERE true${sf}${df}${hf} GROUP BY DATE(created_at) ORDER BY fecha DESC LIMIT 30`),
    ]);
    res.json({
      total_productos: parseInt(tp.rows[0].count),
      total_pedidos: parseInt(to.rows[0].count),
      total_usuarios: parseInt(tu.rows[0].count),
      total_ventas: Number(tv.rows[0].total),
      por_dia: tpd.rows
    });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ══════════════════════════════════════════════════════════
// CUPONES (multi-producto con buscador)
// ══════════════════════════════════════════════════════════

app.get('/api/cupones', auth('admin'), async (req, res) => {
  try { const { rows } = await pool.query('SELECT * FROM cupones ORDER BY created_at DESC');
    // Cargar productos asociados
    for (const c of rows) {
      const { rows: prods } = await pool.query('SELECT cp.producto_id, p.nombre, p.modelo FROM cupon_productos cp LEFT JOIN productos p ON cp.producto_id=p.id WHERE cp.cupon_id=$1', [c.id]);
      c.productos_asociados = prods;
    }
    res.json(rows);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/cupones/validar', async (req, res) => {
  try { const { codigo, seccion_id, subtotal, metodo_pago, items } = req.body;
    const { rows } = await pool.query('SELECT * FROM cupones WHERE codigo=$1 AND activo=true', [codigo.toUpperCase()]);
    if (!rows[0]) return res.status(400).json({ error: 'Cupón no válido' });
    const c = rows[0];
    if (c.secciones_ids && c.secciones_ids.trim()) { const allowed = c.secciones_ids.split(',').map(Number); if (!allowed.includes(parseInt(seccion_id))) return res.status(400).json({ error: 'Cupón no aplica a esta sección' }); }
    // Multi-producto check
    const { rows: cpProds } = await pool.query('SELECT producto_id FROM cupon_productos WHERE cupon_id=$1', [c.id]);
    if (cpProds.length) { const prodIds = cpProds.map(p => p.producto_id); const itemIds = (items||[]).map(i => i.producto_id); if (!itemIds.some(id => prodIds.includes(id))) return res.status(400).json({ error: 'Cupón solo aplica a productos específicos' }); }
    else if (c.producto_id) { const itemIds = (items||[]).map(i => i.producto_id); if (!itemIds.includes(c.producto_id)) return res.status(400).json({ error: 'Cupón solo aplica a un producto específico' }); }
    if (c.categoria && c.categoria.trim()) { const itemCats = (items||[]).map(i => i.categoria); if (!itemCats.some(cat => cat === c.categoria)) return res.status(400).json({ error: `Cupón solo aplica a categoría: ${c.categoria}` }); }
    if (c.fecha_inicio && new Date(c.fecha_inicio) > new Date()) return res.status(400).json({ error: 'Cupón aún no activo' });
    if (c.fecha_fin && new Date(c.fecha_fin) < new Date()) return res.status(400).json({ error: 'Cupón expirado' });
    if (c.uso_maximo > 0 && c.usos_actuales >= c.uso_maximo) return res.status(400).json({ error: 'Cupón agotado' });
    if (c.compra_minima > 0 && subtotal < c.compra_minima) return res.status(400).json({ error: `Compra mínima: $${c.compra_minima}` });
    if (c.tipo === 'por_medio_pago' && c.medio_pago && metodo_pago !== c.medio_pago) return res.status(400).json({ error: `Solo aplica para ${c.medio_pago}` });
    let descuento = 0; let base = subtotal;
    if (cpProds.length && items) { const prodIds = cpProds.map(p => p.producto_id); base = items.filter(i => prodIds.includes(i.producto_id)).reduce((s,i) => s + (i.precio_unitario||0)*(i.cantidad||1), 0); }
    else if (c.producto_id && items) { base = items.filter(i => i.producto_id === c.producto_id).reduce((s,i) => s + (i.precio_unitario||0)*(i.cantidad||1), 0); }
    else if (c.categoria && c.categoria.trim() && items) { base = items.filter(i => i.categoria === c.categoria).reduce((s,i) => s + (i.precio_unitario||0)*(i.cantidad||1), 0); }
    if (c.tipo === 'porcentaje' || c.tipo === 'por_medio_pago') descuento = base * (c.valor/100);
    else if (c.tipo === 'monto_fijo') descuento = Math.min(c.valor, base);
    res.json({ valido: true, cupon: c, descuento: Math.round(descuento*100)/100, tipo: c.tipo });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/cupones', auth('admin'), async (req, res) => {
  try { const { codigo, tipo, valor, compra_minima, uso_maximo, fecha_inicio, fecha_fin, secciones_ids, categoria, producto_id, medio_pago, productos_ids } = req.body;
    const { rows } = await pool.query(
      `INSERT INTO cupones (codigo,tipo,valor,compra_minima,uso_maximo,fecha_inicio,fecha_fin,secciones_ids,categoria,producto_id,medio_pago) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11) RETURNING *`,
      [codigo.toUpperCase(), tipo||'porcentaje', valor||0, compra_minima||0, uso_maximo||0, fecha_inicio||null, fecha_fin||null, secciones_ids||'', categoria||'', producto_id||null, medio_pago||'']);
    // Guardar productos asociados
    if (productos_ids?.length) { for (const pid of productos_ids) { await pool.query('INSERT INTO cupon_productos (cupon_id,producto_id) VALUES ($1,$2) ON CONFLICT DO NOTHING', [rows[0].id, pid]); } }
    res.json(rows[0]); } catch (e) { res.status(500).json({ error: e.message }); }
});

app.put('/api/cupones/:id', auth('admin'), async (req, res) => {
  try { const { codigo, tipo, valor, compra_minima, uso_maximo, fecha_inicio, fecha_fin, secciones_ids, categoria, producto_id, medio_pago, activo, productos_ids } = req.body;
    await pool.query(`UPDATE cupones SET codigo=COALESCE($1,codigo),tipo=COALESCE($2,tipo),valor=COALESCE($3,valor),compra_minima=COALESCE($4,compra_minima),uso_maximo=COALESCE($5,uso_maximo),fecha_inicio=$6,fecha_fin=$7,secciones_ids=COALESCE($8,secciones_ids),categoria=COALESCE($9,categoria),producto_id=$10,medio_pago=COALESCE($11,medio_pago),activo=COALESCE($12,activo) WHERE id=$13`,
      [codigo, tipo, valor, compra_minima, uso_maximo, fecha_inicio||null, fecha_fin||null, secciones_ids, categoria, producto_id||null, medio_pago, activo, req.params.id]);
    // Actualizar productos asociados
    if (productos_ids !== undefined) { await pool.query('DELETE FROM cupon_productos WHERE cupon_id=$1', [req.params.id]); if (productos_ids?.length) { for (const pid of productos_ids) { await pool.query('INSERT INTO cupon_productos (cupon_id,producto_id) VALUES ($1,$2) ON CONFLICT DO NOTHING', [req.params.id, pid]); } } }
    res.json({ ok: true }); } catch (e) { res.status(500).json({ error: e.message }); }
});

app.delete('/api/cupones/:id', auth('admin'), async (req, res) => { try { await pool.query('DELETE FROM cupones WHERE id=$1', [req.params.id]); res.json({ ok: true }); } catch (e) { res.status(500).json({ error: e.message }); } });

// ══════════════════════════════════════════════════════════
// PROMOCIONES AUTOMÁTICAS (sin código)
// ══════════════════════════════════════════════════════════

app.get('/api/promociones', async (req, res) => {
  try { const { rows } = await pool.query('SELECT * FROM promociones ORDER BY created_at DESC'); res.json(rows); } catch (e) { res.status(500).json({ error: e.message }); }
});
app.post('/api/promociones', auth('admin'), async (req, res) => {
  try { const { nombre, tipo, valor, secciones_ids, categoria, productos_ids, fecha_inicio, fecha_fin } = req.body;
    const { rows } = await pool.query('INSERT INTO promociones (nombre,tipo,valor,secciones_ids,categoria,productos_ids,fecha_inicio,fecha_fin) VALUES ($1,$2,$3,$4,$5,$6,$7,$8) RETURNING *',
      [nombre||'', tipo||'porcentaje', valor||0, secciones_ids||'', categoria||'', productos_ids||'', fecha_inicio||null, fecha_fin||null]);
    res.json(rows[0]); } catch (e) { res.status(500).json({ error: e.message }); }
});
app.put('/api/promociones/:id', auth('admin'), async (req, res) => {
  try { const { nombre, tipo, valor, secciones_ids, categoria, productos_ids, fecha_inicio, fecha_fin, activa } = req.body;
    await pool.query('UPDATE promociones SET nombre=COALESCE($1,nombre),tipo=COALESCE($2,tipo),valor=COALESCE($3,valor),secciones_ids=COALESCE($4,secciones_ids),categoria=COALESCE($5,categoria),productos_ids=COALESCE($6,productos_ids),fecha_inicio=$7,fecha_fin=$8,activa=COALESCE($9,activa) WHERE id=$10',
      [nombre, tipo, valor, secciones_ids, categoria, productos_ids, fecha_inicio||null, fecha_fin||null, activa, req.params.id]);
    res.json({ ok: true }); } catch (e) { res.status(500).json({ error: e.message }); }
});
app.delete('/api/promociones/:id', auth('admin'), async (req, res) => { try { await pool.query('DELETE FROM promociones WHERE id=$1', [req.params.id]); res.json({ ok: true }); } catch (e) { res.status(500).json({ error: e.message }); } });

// Obtener promociones activas para una sección (público)
app.get('/api/promociones/activas', async (req, res) => {
  try { const { seccion_id } = req.query;
    const { rows } = await pool.query("SELECT * FROM promociones WHERE activa=true AND (fecha_inicio IS NULL OR fecha_inicio <= NOW()) AND (fecha_fin IS NULL OR fecha_fin >= NOW())");
    const filtered = seccion_id ? rows.filter(p => !p.secciones_ids || p.secciones_ids.split(',').map(Number).includes(parseInt(seccion_id))) : rows;
    res.json(filtered);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ══════════════════════════════════════════════════════════
// POPUPS PROMOCIONALES
// ══════════════════════════════════════════════════════════

app.get('/api/popups', async (req, res) => {
  try { const { seccion_id } = req.query;
    const { rows } = await pool.query('SELECT * FROM popups WHERE activo=true ORDER BY created_at DESC');
    const filtered = seccion_id ? rows.filter(p => !p.secciones_ids || p.secciones_ids.split(',').map(Number).includes(parseInt(seccion_id))) : rows;
    res.json(filtered);
  } catch (e) { res.status(500).json({ error: e.message }); }
});
app.get('/api/popups/all', auth('admin'), async (req, res) => { try { const { rows } = await pool.query('SELECT * FROM popups ORDER BY created_at DESC'); res.json(rows); } catch (e) { res.status(500).json({ error: e.message }); } });
app.post('/api/popups', auth('admin'), async (req, res) => {
  try { const { titulo, imagen, url_destino, secciones_ids, mostrar_una_vez } = req.body;
    const { rows } = await pool.query('INSERT INTO popups (titulo,imagen,url_destino,secciones_ids,mostrar_una_vez) VALUES ($1,$2,$3,$4,$5) RETURNING *',
      [titulo||'', imagen||'', url_destino||'', secciones_ids||'', mostrar_una_vez!==false]);
    res.json(rows[0]); } catch (e) { res.status(500).json({ error: e.message }); }
});
app.put('/api/popups/:id', auth('admin'), async (req, res) => {
  try { const { titulo, imagen, url_destino, secciones_ids, activo, mostrar_una_vez } = req.body;
    await pool.query('UPDATE popups SET titulo=COALESCE($1,titulo),imagen=COALESCE($2,imagen),url_destino=COALESCE($3,url_destino),secciones_ids=COALESCE($4,secciones_ids),activo=COALESCE($5,activo),mostrar_una_vez=COALESCE($6,mostrar_una_vez) WHERE id=$7',
      [titulo, imagen, url_destino, secciones_ids, activo, mostrar_una_vez, req.params.id]);
    res.json({ ok: true }); } catch (e) { res.status(500).json({ error: e.message }); }
});
app.delete('/api/popups/:id', auth('admin'), async (req, res) => { try { await pool.query('DELETE FROM popups WHERE id=$1', [req.params.id]); res.json({ ok: true }); } catch (e) { res.status(500).json({ error: e.message }); } });

// ══════════════════════════════════════════════════════════
// REDES SOCIALES
// ══════════════════════════════════════════════════════════

app.get('/api/redes-sociales', async (req, res) => { try { const { rows } = await pool.query('SELECT * FROM redes_sociales ORDER BY orden'); res.json(rows); } catch (e) { res.status(500).json({ error: e.message }); } });
app.put('/api/redes-sociales', auth('admin'), async (req, res) => {
  try { for (const r of req.body.redes) {
    if (r.id) { await pool.query('UPDATE redes_sociales SET url=$1,activo=$2 WHERE id=$3', [r.url||'', r.activo, r.id]); }
    else { await pool.query('INSERT INTO redes_sociales (tipo,url,activo,orden) VALUES ($1,$2,$3,$4)', [r.tipo, r.url||'', r.activo!==false, r.orden||0]); }
  } res.json({ ok: true }); } catch (e) { res.status(500).json({ error: e.message }); }
});

// ══════════════════════════════════════════════════════════
// MENÚ EDITABLE
// ══════════════════════════════════════════════════════════

app.get('/api/menu', async (req, res) => { try { const { rows } = await pool.query('SELECT * FROM menu_items WHERE visible=true ORDER BY orden'); res.json(rows); } catch (e) { res.status(500).json({ error: e.message }); } });
app.get('/api/menu/all', auth('admin'), async (req, res) => { try { const { rows } = await pool.query('SELECT * FROM menu_items ORDER BY orden'); res.json(rows); } catch (e) { res.status(500).json({ error: e.message }); } });
app.post('/api/menu', auth('admin'), async (req, res) => {
  try { const { titulo, url, tipo, seccion_id, orden } = req.body;
    const { rows } = await pool.query('INSERT INTO menu_items (titulo,url,tipo,seccion_id,orden) VALUES ($1,$2,$3,$4,$5) RETURNING *',
      [titulo, url||'', tipo||'link', seccion_id||null, orden||0]);
    res.json(rows[0]); } catch (e) { res.status(500).json({ error: e.message }); }
});
app.put('/api/menu/:id', auth('admin'), async (req, res) => {
  try { const { titulo, url, tipo, seccion_id, orden, visible } = req.body;
    await pool.query('UPDATE menu_items SET titulo=COALESCE($1,titulo),url=COALESCE($2,url),tipo=COALESCE($3,tipo),seccion_id=$4,orden=COALESCE($5,orden),visible=COALESCE($6,visible) WHERE id=$7',
      [titulo, url, tipo, seccion_id||null, orden, visible, req.params.id]);
    res.json({ ok: true }); } catch (e) { res.status(500).json({ error: e.message }); }
});
app.delete('/api/menu/:id', auth('admin'), async (req, res) => { try { await pool.query('DELETE FROM menu_items WHERE id=$1', [req.params.id]); res.json({ ok: true }); } catch (e) { res.status(500).json({ error: e.message }); } });

// ══════════════════════════════════════════════════════════
// DISEÑO / PLANTILLAS
// ══════════════════════════════════════════════════════════

app.get('/api/design', async (req, res) => { try { const { rows } = await pool.query('SELECT * FROM design_config'); const cfg = {}; rows.forEach(r => cfg[r.clave] = r.valor); res.json(cfg); } catch (e) { res.status(500).json({ error: e.message }); } });
app.put('/api/design', auth('admin'), async (req, res) => {
  try { for (const [k,v] of Object.entries(req.body)) { await pool.query('INSERT INTO design_config (clave,valor) VALUES ($1,$2) ON CONFLICT (clave) DO UPDATE SET valor=$2', [k, String(v)]); } res.json({ ok: true }); } catch (e) { res.status(500).json({ error: e.message }); }
});

// ══════════════════════════════════════════════════════════
// MÉTODOS DE PAGO (con descripción)
// ══════════════════════════════════════════════════════════

app.get('/api/metodos-pago', async (req, res) => {
  try { const { seccion_id } = req.query;
    let q = 'SELECT * FROM metodos_pago WHERE activo=true'; const p = [];
    if (seccion_id) { q += ' AND (seccion_id=$1 OR seccion_id IS NULL)'; p.push(seccion_id); }
    q += ' ORDER BY orden';
    const { rows } = await pool.query(q, p); res.json(rows);
  } catch (e) { res.status(500).json({ error: e.message }); }
});
app.get('/api/metodos-pago/all', auth('admin'), async (req, res) => { try { const { rows } = await pool.query('SELECT * FROM metodos_pago ORDER BY orden'); res.json(rows); } catch (e) { res.status(500).json({ error: e.message }); } });
app.post('/api/metodos-pago', auth('admin'), async (req, res) => {
  try { const { nombre, descripcion, instrucciones, seccion_id, orden } = req.body;
    const { rows } = await pool.query('INSERT INTO metodos_pago (nombre,descripcion,instrucciones,seccion_id,orden) VALUES ($1,$2,$3,$4,$5) RETURNING *',
      [nombre, descripcion||'', instrucciones||'', seccion_id||null, orden||0]);
    res.json(rows[0]); } catch (e) { res.status(500).json({ error: e.message }); }
});
app.put('/api/metodos-pago/:id', auth('admin'), async (req, res) => {
  try { const { nombre, descripcion, instrucciones, seccion_id, activo, orden } = req.body;
    await pool.query('UPDATE metodos_pago SET nombre=COALESCE($1,nombre),descripcion=COALESCE($2,descripcion),instrucciones=COALESCE($3,instrucciones),seccion_id=$4,activo=COALESCE($5,activo),orden=COALESCE($6,orden) WHERE id=$7',
      [nombre, descripcion, instrucciones, seccion_id||null, activo, orden, req.params.id]);
    res.json({ ok: true }); } catch (e) { res.status(500).json({ error: e.message }); }
});
app.delete('/api/metodos-pago/:id', auth('admin'), async (req, res) => { try { await pool.query('DELETE FROM metodos_pago WHERE id=$1', [req.params.id]); res.json({ ok: true }); } catch (e) { res.status(500).json({ error: e.message }); } });

// ══════════════════════════════════════════════════════════
// PÁGINAS INFORMATIVAS
// ══════════════════════════════════════════════════════════

app.get('/api/paginas', async (req, res) => {
  try { const { seccion_id } = req.query;
    let q = 'SELECT * FROM paginas_info'; const p = [];
    if (seccion_id) { q += ' WHERE (seccion_id=$1 OR seccion_id IS NULL) AND visible=true'; p.push(seccion_id); }
    else { q += ' WHERE visible=true'; } q += ' ORDER BY orden';
    const { rows } = await pool.query(q, p); res.json(rows);
  } catch (e) { res.status(500).json({ error: e.message }); }
});
app.get('/api/paginas/:id', async (req, res) => { try { const { rows } = await pool.query('SELECT * FROM paginas_info WHERE id=$1', [req.params.id]); if (!rows[0]) return res.status(404).json({ error: 'No encontrada' }); res.json(rows[0]); } catch (e) { res.status(500).json({ error: e.message }); } });
app.post('/api/paginas', auth('admin'), async (req, res) => {
  try { const { titulo, slug, contenido, seccion_id, orden, visible } = req.body;
    const { rows } = await pool.query('INSERT INTO paginas_info (titulo,slug,contenido,seccion_id,orden,visible) VALUES ($1,$2,$3,$4,$5,$6) RETURNING *', [titulo, slug, contenido||'', seccion_id||null, orden||0, visible!==false]);
    res.json(rows[0]); } catch (e) { res.status(500).json({ error: e.message }); }
});
app.put('/api/paginas/:id', auth('admin'), async (req, res) => {
  try { const { titulo, slug, contenido, seccion_id, orden, visible } = req.body;
    await pool.query('UPDATE paginas_info SET titulo=COALESCE($1,titulo),slug=COALESCE($2,slug),contenido=COALESCE($3,contenido),seccion_id=$4,orden=COALESCE($5,orden),visible=COALESCE($6,visible) WHERE id=$7',
      [titulo, slug, contenido, seccion_id||null, orden, visible, req.params.id]);
    res.json({ ok: true }); } catch (e) { res.status(500).json({ error: e.message }); }
});
app.delete('/api/paginas/:id', auth('admin'), async (req, res) => { try { await pool.query('DELETE FROM paginas_info WHERE id=$1', [req.params.id]); res.json({ ok: true }); } catch (e) { res.status(500).json({ error: e.message }); } });

// ══════════════════════════════════════════════════════════
// BADGES (con secciones_ids)
// ══════════════════════════════════════════════════════════

app.get('/api/badges', async (req, res) => {
  try { const { seccion_id } = req.query;
    const { rows } = await pool.query('SELECT * FROM badges WHERE visible=true ORDER BY orden');
    const filtered = seccion_id ? rows.filter(b => !b.secciones_ids || b.secciones_ids.split(',').map(Number).includes(parseInt(seccion_id))) : rows;
    res.json(filtered);
  } catch (e) { res.status(500).json({ error: e.message }); }
});
app.get('/api/badges/all', auth('admin'), async (req, res) => { try { const { rows } = await pool.query('SELECT * FROM badges ORDER BY orden'); res.json(rows); } catch (e) { res.status(500).json({ error: e.message }); } });
app.post('/api/badges', auth('admin'), async (req, res) => {
  try { const { icono, texto, orden, visible, secciones_ids } = req.body;
    const { rows } = await pool.query('INSERT INTO badges (icono,texto,orden,visible,secciones_ids) VALUES ($1,$2,$3,$4,$5) RETURNING *', [icono||'⭐', texto||'', orden||0, visible!==false, secciones_ids||'']);
    res.json(rows[0]); } catch (e) { res.status(500).json({ error: e.message }); }
});
app.put('/api/badges/:id', auth('admin'), async (req, res) => {
  try { const { icono, texto, orden, visible, secciones_ids } = req.body;
    await pool.query('UPDATE badges SET icono=COALESCE($1,icono),texto=COALESCE($2,texto),orden=COALESCE($3,orden),visible=COALESCE($4,visible),secciones_ids=COALESCE($5,secciones_ids) WHERE id=$6',
      [icono, texto, orden, visible, secciones_ids, req.params.id]);
    res.json({ ok: true }); } catch (e) { res.status(500).json({ error: e.message }); }
});
app.delete('/api/badges/:id', auth('admin'), async (req, res) => { try { await pool.query('DELETE FROM badges WHERE id=$1', [req.params.id]); res.json({ ok: true }); } catch (e) { res.status(500).json({ error: e.message }); } });

// ══════════════════════════════════════════════════════════
// CONFIG ENVÍO + BÚSQUEDA GLOBAL
// ══════════════════════════════════════════════════════════

app.get('/api/envio/config/:seccion_id', async (req, res) => { try { const { rows } = await pool.query('SELECT * FROM config_envio WHERE seccion_id=$1', [req.params.seccion_id]); res.json(rows[0] || { metodo: 'manual', costo_fijo: 0, gratis_desde: 0, zonas: [] }); } catch (e) { res.status(500).json({ error: e.message }); } });
app.put('/api/envio/config/:seccion_id', auth('admin'), async (req, res) => {
  try { const { metodo, costo_fijo, gratis_desde, zonas } = req.body;
    await pool.query(`INSERT INTO config_envio (seccion_id,metodo,costo_fijo,gratis_desde,zonas) VALUES ($1,$2,$3,$4,$5) ON CONFLICT (seccion_id) DO UPDATE SET metodo=$2,costo_fijo=$3,gratis_desde=$4,zonas=$5`,
      [req.params.seccion_id, metodo||'manual', costo_fijo||0, gratis_desde||0, JSON.stringify(zonas||[])]);
    res.json({ ok: true }); } catch (e) { res.status(500).json({ error: e.message }); }
});
app.post('/api/envio/cotizar', async (req, res) => {
  try { const { seccion_id, codigo_postal } = req.body;
    const { rows } = await pool.query('SELECT * FROM config_envio WHERE seccion_id=$1', [seccion_id]);
    const cfg = rows[0] || { metodo: 'manual', costo_fijo: 0 };
    res.json({ costo: cfg.costo_fijo, metodo: cfg.metodo, mensaje: cfg.metodo === 'manual' ? 'Consultar costo de envío' : '' });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/busqueda-global', optionalAuth, async (req, res) => {
  try { const { q } = req.query; if (!q || q.length < 2) return res.json({ resultados: [], porSeccion: {}, total: 0 });
    const { rows } = await pool.query(
      `SELECT p.*, s.nombre as seccion_nombre, s.slug as seccion_slug, s.color as seccion_color FROM productos p LEFT JOIN secciones s ON p.seccion_id=s.id WHERE p.visible=true AND (p.modelo ILIKE $1 OR p.categoria ILIKE $1 OR p.compatibilidad ILIKE $1 OR p.nombre ILIKE $1) ORDER BY p.categoria, p.nombre LIMIT 50`, [`%${q}%`]);
    const isAuth = !!req.user;
    const resultados = rows.map(r => ({ ...r, precio_base: (isAuth || r.seccion_slug !== 'mayorista') ? r.precio_base : undefined, enStock: r.stock > 0 }));
    const porSeccion = {};
    resultados.forEach(r => { if (!porSeccion[r.seccion_slug]) porSeccion[r.seccion_slug] = { nombre: r.seccion_nombre, color: r.seccion_color, productos: [] }; porSeccion[r.seccion_slug].productos.push(r); });
    res.json({ resultados, porSeccion, total: resultados.length });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ══════════════════════════════════════════════════════════
// ANDREANI
// ══════════════════════════════════════════════════════════

const ANDREANI_API = process.env.ANDREANI_DEBUG === 'true' ? 'https://apisqa.andreani.com' : 'https://apis.andreani.com';
async function andreaniLogin() {
  const user = process.env.ANDREANI_USER, pass = process.env.ANDREANI_PASS;
  if (!user || !pass) return null;
  try { const r = await fetch(`${ANDREANI_API}/login`, { method: 'GET', headers: { Authorization: 'Basic ' + Buffer.from(`${user}:${pass}`).toString('base64') } }); const data = await r.json(); return data.token || null; } catch (e) { return null; }
}

app.post('/api/andreani/cotizar', async (req, res) => {
  try { const { cp_destino, peso, volumen, seccion_id } = req.body;
    const token = await andreaniLogin(); if (!token) return res.status(503).json({ error: 'Andreani no configurado' });
    const { rows: [sec] } = await pool.query('SELECT * FROM config_envio WHERE seccion_id=$1', [seccion_id]);
    const cpOrigen = sec?.cp_origen || process.env.ANDREANI_CP_ORIGEN || '1888';
    const contrato = process.env.ANDREANI_CONTRATO || 'AND00EST';
    const rDom = await fetch(`${ANDREANI_API}/v1/tarifas`, { method: 'POST', headers: { 'Content-Type': 'application/json', 'x-authorization-token': token }, body: JSON.stringify({ cpDestino: cp_destino, contrato, cliente: process.env.ANDREANI_CLIENTE, sucursalOrigen: cpOrigen, bultos: [{ valorDeclarado: 0, volumen: volumen||2000, kilos: (peso||500)/1000 }] }) });
    const domicilio = await rDom.json();
    let sucursal = null;
    try { const rSuc = await fetch(`${ANDREANI_API}/v1/tarifas`, { method: 'POST', headers: { 'Content-Type': 'application/json', 'x-authorization-token': token }, body: JSON.stringify({ cpDestino: cp_destino, contrato: 'AND00SUC', cliente: process.env.ANDREANI_CLIENTE, sucursalOrigen: cpOrigen, bultos: [{ valorDeclarado: 0, volumen: volumen||2000, kilos: (peso||500)/1000 }] }) }); sucursal = await rSuc.json(); } catch {}
    res.json({ domicilio: { tarifa: domicilio?.tarifaConIva?.total || domicilio?.tarifa || 0, detalle: domicilio }, sucursal: sucursal ? { tarifa: sucursal?.tarifaConIva?.total || sucursal?.tarifa || 0, detalle: sucursal } : null, cp_origen: cpOrigen });
  } catch (e) { res.status(500).json({ error: e.message }); }
});
app.get('/api/andreani/sucursales', async (req, res) => { try { const { cp } = req.query; const token = await andreaniLogin(); if (!token) return res.status(503).json({ error: 'Andreani no configurado' }); const r = await fetch(`${ANDREANI_API}/v1/sucursales?codigoPostal=${cp}`, { headers: { 'x-authorization-token': token } }); res.json(await r.json()); } catch (e) { res.status(500).json({ error: e.message }); } });
app.post('/api/andreani/orden', auth('admin'), async (req, res) => {
  try { const { pedido_id, tipo, cp_destino, provincia, localidad, calle, numero, piso, depto, nombre, dni, telefono, email, peso, volumen, seccion_id } = req.body;
    const token = await andreaniLogin(); if (!token) return res.status(503).json({ error: 'Andreani no configurado' });
    const { rows: [sec] } = await pool.query('SELECT * FROM config_envio WHERE seccion_id=$1', [seccion_id]);
    const { rows: [secInfo] } = await pool.query('SELECT * FROM secciones WHERE id=$1', [seccion_id]);
    const contrato = tipo === 'sucursal' ? 'AND00SUC' : (process.env.ANDREANI_CONTRATO || 'AND00EST');
    const orden = { contrato, origen: { postal: { codigoPostal: sec?.cp_origen || process.env.ANDREANI_CP_ORIGEN || '1888', calle: secInfo?.direccion_despacho || '' } }, destino: { postal: { codigoPostal: cp_destino, calle: calle||'', numero: numero||'', piso: piso||'', departamento: depto||'', localidad: localidad||'', region: provincia||'' } }, remitente: { nombreCompleto: secInfo?.nombre || 'Remitente', email: '' }, destinatario: { nombreCompleto: nombre, email: email||'', documentoTipo: 'DNI', documentoNumero: dni||'', telefonos: [{ tipo: 1, numero: telefono||'' }] }, bultos: [{ kilos: (peso||500)/1000, volumenCm: volumen||2000, valorDeclaradoSinImpuestos: 0, referencias: [{ meta: 'pedido', contenido: `PED-${pedido_id}` }] }], idCliente: process.env.ANDREANI_CLIENTE };
    const r = await fetch(`${ANDREANI_API}/v1/ordenes-de-envio`, { method: 'POST', headers: { 'Content-Type': 'application/json', 'x-authorization-token': token }, body: JSON.stringify(orden) });
    const data = await r.json();
    if (data.numeroDeEnvio) await pool.query('UPDATE pedidos SET notas = notas || $1 WHERE id=$2', [`\n[Andreani] Envío: ${data.numeroDeEnvio}`, pedido_id]);
    res.json(data);
  } catch (e) { res.status(500).json({ error: e.message }); }
});
app.get('/api/andreani/tracking/:envio', async (req, res) => { try { const token = await andreaniLogin(); if (!token) return res.status(503).json({ error: 'Andreani no configurado' }); const r = await fetch(`${ANDREANI_API}/v1/envios/${req.params.envio}/trazas`, { headers: { 'x-authorization-token': token } }); res.json(await r.json()); } catch (e) { res.status(500).json({ error: e.message }); } });
app.get('/api/andreani/etiqueta/:envio', async (req, res) => { try { const token = await andreaniLogin(); if (!token) return res.status(503).json({ error: 'Andreani no configurado' }); const r = await fetch(`${ANDREANI_API}/v1/ordenes-de-envio/${req.params.envio}/etiquetas`, { headers: { 'x-authorization-token': token, 'Accept': 'application/pdf' } }); res.set('Content-Type', 'application/pdf'); const buffer = await r.arrayBuffer(); res.send(Buffer.from(buffer)); } catch (e) { res.status(500).json({ error: e.message }); } });

// INICIAR SERVIDOR
runMigrations().then(() => {
  app.listen(PORT, () => console.log(`🚀 Servidor en puerto ${PORT}`));
});
