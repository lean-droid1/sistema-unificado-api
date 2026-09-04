const express = require('express');
const cors = require('cors');
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const cloudinary = require('cloudinary').v2;
const crypto = require('crypto');
const { v4: uuidv4 } = require('uuid');

const app = express();

// === SECURITY ===
const helmet = require('helmet');
app.use(helmet({ crossOriginResourcePolicy: { policy: 'cross-origin' } }));

// CORS - V5 FIX: permite header X-Tenant (multi-tenant) y dominios propios de clientes
const ALLOWED_ORIGINS = (process.env.ALLOWED_ORIGINS || '').split(',').map(s=>s.trim()).filter(Boolean);
app.use(cors({
  origin: (origin, cb) => {
    if (!origin) return cb(null, true);
    if (ALLOWED_ORIGINS.length === 0) return cb(null, true);
    if (ALLOWED_ORIGINS.includes('*')) return cb(null, true);
    if (ALLOWED_ORIGINS.includes(origin)) return cb(null, true);
    for(const a of ALLOWED_ORIGINS){
      if(a.startsWith('*.') && origin.endsWith(a.slice(1))) return cb(null, true);
      if(a === '*.vercel.app' && origin.endsWith('.vercel.app')) return cb(null, true);
    }
    if (ALLOWED_ORIGINS.some(a=>a.includes('vercel.app')) && origin.includes('vercel.app')) return cb(null, true);
    // Multi-tenant: las tiendas cliente usan sus PROPIOS dominios (comerciapp.com.ar, subdominios, y dominios propios).
    // El tenant se resuelve por el header X-Tenant / dominio_propio en la DB, así que aceptamos cualquier origen http(s).
    // (No es un riesgo: la autorización real la dan el JWT y el filtrado por tenant, no el origin.)
    if (/^https?:\/\//.test(origin)) return cb(null, true);
    console.log('CORS blocked:', origin, 'allowed:', ALLOWED_ORIGINS);
    return cb(null, false);
  },
  credentials: true,
  methods: ['GET','POST','PUT','DELETE','PATCH','OPTIONS'],
  allowedHeaders: ['Content-Type','Authorization','X-Tenant']
}));

app.use(express.json({ limit: '10mb' }));

const rateLimit = require('express-rate-limit');
app.use('/api/auth', rateLimit({ windowMs: 15 * 60 * 1000, max: 30 }));
// Límite estricto para login/registro (anti fuerza bruta): 10 intentos cada 15 min por IP
const authLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 10, message: { error: 'Demasiados intentos. Esperá unos minutos e intentá de nuevo.' }, standardHeaders: true, legacyHeaders: false });
app.use('/api/login', authLimiter);
app.use('/api/register', authLimiter);
app.use('/api/', rateLimit({ windowMs: 1 * 60 * 1000, max: 300 }));
app.use('/api/', (req,res,next)=>resolveTenant(req,res,next));
app.set('trust proxy', 1);

const pool = new Pool({ connectionString: process.env.DATABASE_URL, ssl: { rejectUnauthorized: false } });
// Recalcula preventa_reservado de un producto desde los pedidos reales (activos)
async function recalcReservado(productoId){
  try{
    if(!productoId) return;
    await pool.query(`UPDATE productos SET preventa_reservado = (
      SELECT COALESCE(SUM(pi.cantidad),0) FROM pedido_items pi JOIN pedidos p ON pi.pedido_id=p.id
      WHERE pi.producto_id=$1 AND p.tipo='pedido' AND LOWER(COALESCE(p.estado,'')) NOT IN ('cancelado','anulado','rechazado')
    ) WHERE id=$1 AND es_preventa=true`, [productoId]);
  }catch(e){ /* noop */ }
}
const SECRET = process.env.JWT_SECRET;
if (!SECRET) {
  console.error('❌ JWT_SECRET no configurado - usando fallback solo para dev');
}
const JWT_SECRET = SECRET || 'dev-only-secret-cambiar-en-prod-2026';

// Cloudinary - obligatorio
const useCloudinary = !!(process.env.CLOUDINARY_CLOUD_NAME && process.env.CLOUDINARY_API_KEY && process.env.CLOUDINARY_API_SECRET);
if (useCloudinary) {
  cloudinary.config({ cloud_name: process.env.CLOUDINARY_CLOUD_NAME, api_key: process.env.CLOUDINARY_API_KEY, api_secret: process.env.CLOUDINARY_API_SECRET });
  console.log('☁️ Cloudinary OK');
} else {
  console.warn('⚠️ Cloudinary no configurado - imagenes se perderan en Railway');
}
const uploadsDir = path.join(__dirname, 'uploads');
if (!fs.existsSync(uploadsDir)) fs.mkdirSync(uploadsDir, { recursive: true });
app.use('/uploads', express.static(uploadsDir));
const upload = multer({ storage: multer.memoryStorage(), limits: { fileSize: 5 * 1024 * 1024 }, fileFilter: (req,file,cb)=>{ if(file.mimetype.startsWith('image/')) cb(null,true); else cb(new Error('Solo imagenes'), false);} });

const hashToken = (t) => crypto.createHash('sha256').update(t).digest('hex').slice(0,64);

const auth = (role) => async (req,res,next)=>{
  try{
    const t = req.headers.authorization?.split(' ')[1];
    if(!t) return res.status(401).json({error:'Token requerido'});
    const revoked = await pool.query('SELECT 1 FROM tokens_revocados WHERE token_hash=$1', [hashToken(t)]).catch(()=>({rows:[]}));
    if(revoked.rows.length) return res.status(401).json({error:'Sesión cerrada'});
    const d = jwt.verify(t, JWT_SECRET);
    if(role){
      const {rows} = await pool.query('SELECT rol, activo FROM usuarios WHERE id=$1 AND tenant_id=$2', [d.id, req.tenantId]).catch(()=>({rows:[]}));
      if(!rows[0] || !rows[0].activo) return res.status(401).json({error:'Cuenta desactivada'});
      if(role==='admin' && rows[0].rol!=='admin') return res.status(403).json({error:'Sin permiso'});
      req._rol = rows[0].rol;
    }
    req.user=d; req._token=t; next();
  }catch{ res.status(401).json({error:'Token inválido'}); }
};
// Middleware que exige un permiso específico: admin pasa siempre; subadmin solo si tiene el permiso; cliente NO
const authPerm = (permiso) => async (req,res,next)=>{
  try{
    const t = req.headers.authorization?.split(' ')[1];
    if(!t) return res.status(401).json({error:'Token requerido'});
    const revoked = await pool.query('SELECT 1 FROM tokens_revocados WHERE token_hash=$1', [hashToken(t)]).catch(()=>({rows:[]}));
    if(revoked.rows.length) return res.status(401).json({error:'Sesión cerrada'});
    const d = jwt.verify(t, JWT_SECRET);
    const {rows} = await pool.query('SELECT rol, activo, permisos FROM usuarios WHERE id=$1 AND tenant_id=$2', [d.id, req.tenantId]).catch(()=>({rows:[]}));
    if(!rows[0] || !rows[0].activo) return res.status(401).json({error:'Cuenta desactivada'});
    const rol = rows[0].rol;
    if(rol === 'admin'){ req.user=d; req._token=t; req._rol=rol; return next(); }
    if(rol === 'subadmin'){
      const perms = String(rows[0].permisos||'').split(',').filter(Boolean);
      if(perms.includes(permiso)){ req.user=d; req._token=t; req._rol=rol; return next(); }
      return res.status(403).json({error:`Sin permiso: ${permiso}`});
    }
    return res.status(403).json({error:'Sin permiso'});
  }catch{ res.status(401).json({error:'Token inválido'}); }
};
// Middleware: exige que el tenant tenga habilitada una feature del plan. Uso: requiereFeature('marketing')
const requiereFeature = (feature) => async (req,res,next)=>{
  try{
    const d=await getTenantData(req.tenantId);
    const v=d.features?.[feature];
    if(v===false || v==='no' || v===undefined || v===null) return res.status(403).json({error:'Esta función no está incluida en tu plan', feature, upgrade:true});
    next();
  }catch{ next(); } // ante error, no bloquear (fail-open, para no romper por un bug)
};
const optionalAuth = (req,res,next)=>{ try{ const t=req.headers.authorization?.split(' ')[1]; if(t) req.user=jwt.verify(t,JWT_SECRET);}catch{} next(); };

// Middleware DUEÑO de la plataforma: solo el owner (Leandro) puede administrar tenants. NO filtra por tenant.
const authOwner = async (req,res,next)=>{
  try{
    const t = req.headers.authorization?.split(' ')[1];
    if(!t) return res.status(401).json({error:'Token requerido'});
    const revoked = await pool.query('SELECT 1 FROM tokens_revocados WHERE token_hash=$1', [hashToken(t)]).catch(()=>({rows:[]}));
    if(revoked.rows.length) return res.status(401).json({error:'Sesión cerrada'});
    const d = jwt.verify(t, JWT_SECRET);
    const {rows} = await pool.query('SELECT es_owner, activo FROM usuarios WHERE id=$1', [d.id]).catch(()=>({rows:[]}));
    if(!rows[0] || !rows[0].activo || !rows[0].es_owner) return res.status(403).json({error:'Solo el dueño de la plataforma'});
    req.user=d; req._token=t; next();
  }catch{ res.status(401).json({error:'Token inválido'}); }
};

// ═══ MULTI-TENANT: resolución del inquilino (etapa 2) ═══
// Determina a qué tienda pertenece cada request. Orden: header X-Tenant (slug o id) → tenant del user logueado → 1 (default).
// Cachea slug→id en memoria para no consultar la DB en cada request.
const tenantCache = new Map();

// Precios mensuales de cada plan (ARS). Editables acá sin tocar nada más.
const PLAN_PRECIOS = { basic: 30000, pro: 45000, full: 60000 };
// Lee los precios de los planes desde la config de la plataforma (tenant 1). Si no están cargados, usa los defaults de arriba.
async function getPlanPrecios(){
  try{
    const {rows}=await pool.query("SELECT clave, valor FROM configuracion WHERE tenant_id=1 AND clave IN ('precio_basic','precio_pro','precio_full')");
    const p={...PLAN_PRECIOS};
    for(const r of rows){
      const plan=r.clave.replace('precio_','');
      const val=parseInt(r.valor);
      if(!isNaN(val) && val>=0) p[plan]=val;
    }
    return p;
  }catch{ return {...PLAN_PRECIOS}; }
}
// ═══════════ PLANES: qué funciones trae cada plan ═══════════
// Siempre en TODOS los planes (no son llaves): editor visual+temas, contacto+QR, checkout, pagos, envíos, favoritos, buscador, WhatsApp flotante, notificación de venta por mail.
// Llaves (on/off) por plan. Se pueden sobreescribir por tienda con la columna features (JSON).
const PLAN_FEATURES = {
  basic: {
    pdv: 'no',            // punto de venta: 'no' | 'buscador' | 'lector'
    marketing: false,     // cupones, promos, carritos abandonados, leads
    caja: false,
    presupuestos: false,
    reportes: false,
    analytics: false,
    ordenes_compra: false,
    mayorista: false,     // secciones mayoristas con aprobación de clientes
    listas_precio: false,
    cuenta_corriente: false,
    dropshipping: false,
    catalogo_pdf: false,
    max_tiendas: 1,
    max_subadmins: 0,
  },
  pro: {
    pdv: 'buscador',
    marketing: true,
    caja: true,
    presupuestos: true,
    reportes: true,
    analytics: true,
    ordenes_compra: true,
    mayorista: false,
    listas_precio: false,
    cuenta_corriente: false,
    dropshipping: false,
    catalogo_pdf: false,
    max_tiendas: 3,
    max_subadmins: 3,
  },
  full: {
    pdv: 'lector',
    marketing: true,
    caja: true,
    presupuestos: true,
    reportes: true,
    analytics: true,
    ordenes_compra: true,
    mayorista: true,
    listas_precio: true,
    cuenta_corriente: true,
    dropshipping: true,
    catalogo_pdf: true,
    max_tiendas: 999,
    max_subadmins: 999,
  },
};
// Cache de datos del tenant (plan, estado, features) para no consultar en cada request
const tenantDataCache = new Map();
async function getTenantData(tenantId){
  const key=String(tenantId);
  if(tenantDataCache.has(key)) return tenantDataCache.get(key);
  const {rows}=await pool.query('SELECT plan, estado, features, fecha_fin_trial FROM tenants WHERE id=$1', [tenantId]).catch(()=>({rows:[]}));
  const t=rows[0]||{plan:'full', estado:'activo', features:null};
  const base=PLAN_FEATURES[t.plan]||PLAN_FEATURES.full;
  let overrides={}; try{ overrides = t.features ? (typeof t.features==='string'?JSON.parse(t.features):t.features) : {}; }catch{}
  const features={...base, ...overrides};
  // Estado efectivo: la tienda 1 (dueño) nunca se bloquea. Si es trial y venció la fecha → vencido.
  let estado=t.estado||'activo';
  let diasRestantes=null;
  if(t.fecha_fin_trial){
    diasRestantes=Math.ceil((new Date(t.fecha_fin_trial)-new Date())/86400000);
    if(estado==='trial' && diasRestantes<0) estado='vencido';
  }
  if(Number(tenantId)===1) estado='activo';
  const data={plan:t.plan||'full', estado, features, dias_restantes:diasRestantes};
  tenantDataCache.set(key, data);
  return data;
}

async function slugToTenantId(slug){
  if(!slug) return null;
  if(tenantCache.has(slug)) return tenantCache.get(slug);
  const {rows} = await pool.query('SELECT id, estado FROM tenants WHERE slug=$1 OR dominio_propio=$1 LIMIT 1', [slug]).catch(()=>({rows:[]}));
  const id = rows[0] ? rows[0].id : null;
  if(id) tenantCache.set(slug, id);
  return id;
}
const resolveTenant = async (req,res,next)=>{
  try{
    let tid = null;
    // 1) header explícito del frontend (según subdominio de la tienda)
    const h = req.headers['x-tenant'];
    if(h){
      if(/^\d+$/.test(h)) tid = Number(h);
      else tid = await slugToTenantId(String(h).toLowerCase().trim());
    }
    // 2) tenant del usuario logueado (si el token lo trae)
    if(!tid){
      try{ const t=req.headers.authorization?.split(' ')[1]; if(t){ const d=jwt.verify(t,JWT_SECRET); if(d && d.tenant_id) tid=d.tenant_id; } }catch{}
    }
    // 3) default: tienda principal
    req.tenantId = tid || 1;
  }catch{ req.tenantId = 1; }
  next();
};


// === MIGRATE V4 ===
async function migrate(){
  const queries = [
    `CREATE TABLE IF NOT EXISTS configuracion (clave VARCHAR(100) PRIMARY KEY, valor TEXT DEFAULT '')`,
    `CREATE TABLE IF NOT EXISTS secciones (id SERIAL PRIMARY KEY, nombre VARCHAR(200), slug VARCHAR(100) UNIQUE, descripcion TEXT DEFAULT '', imagen TEXT DEFAULT '', requiere_aprobacion BOOLEAN DEFAULT false, visible BOOLEAN DEFAULT true, orden INT DEFAULT 0, ignorar_stock BOOLEAN DEFAULT false, cp_origen VARCHAR(20) DEFAULT '1888', permitir_sin_stock BOOLEAN DEFAULT false)`,
    `CREATE TABLE IF NOT EXISTS listas_precio (id VARCHAR(50) PRIMARY KEY, nombre VARCHAR(200), multiplicador NUMERIC(10,4) DEFAULT 1, modo VARCHAR(20) DEFAULT 'porcentaje', color VARCHAR(20) DEFAULT '#2563eb', compra_minima NUMERIC(12,2) DEFAULT 0, promo_msg TEXT DEFAULT '')`,
    `CREATE TABLE IF NOT EXISTS usuarios (id SERIAL PRIMARY KEY, nombre VARCHAR(200), usuario VARCHAR(100) UNIQUE, password VARCHAR(200), rol VARCHAR(20) DEFAULT 'cliente', telefono VARCHAR(50) DEFAULT '', email VARCHAR(200) DEFAULT '', direccion TEXT DEFAULT '', nombre_fantasia VARCHAR(200) DEFAULT '', lista_precio_id VARCHAR(50) DEFAULT '', aprobado BOOLEAN DEFAULT false, activo BOOLEAN DEFAULT true, permisos TEXT DEFAULT '', notas_admin TEXT DEFAULT '', es_revendedor BOOLEAN DEFAULT false, descuento_revendedor NUMERIC(5,2) DEFAULT 0, created_at TIMESTAMP DEFAULT NOW(), reset_codigo VARCHAR(20) DEFAULT '', reset_expira TIMESTAMP, otp_activo BOOLEAN DEFAULT false)`,
    `CREATE TABLE IF NOT EXISTS productos (id SERIAL PRIMARY KEY, seccion_id INT, categoria VARCHAR(200) DEFAULT '', modelo VARCHAR(200) DEFAULT '', nombre VARCHAR(300) DEFAULT '', precio_base NUMERIC(12,2) DEFAULT 0, precio_original NUMERIC(12,2) DEFAULT 0, stock INT DEFAULT 0, stock_minimo INT DEFAULT 0, imagen TEXT DEFAULT '', notas TEXT DEFAULT '', compatibilidad TEXT DEFAULT '', descripcion TEXT DEFAULT '', sku VARCHAR(100) DEFAULT '', tipo VARCHAR(20) DEFAULT 'fisico', moneda VARCHAR(10) DEFAULT 'ARS', precio_oferta NUMERIC(12,2) DEFAULT 0, envio_gratis BOOLEAN DEFAULT false, visible BOOLEAN DEFAULT true, peso NUMERIC(8,2) DEFAULT 0, alto NUMERIC(8,2) DEFAULT 0, ancho NUMERIC(8,2) DEFAULT 0, largo NUMERIC(8,2) DEFAULT 0, permitir_sin_stock BOOLEAN DEFAULT false, es_digital BOOLEAN DEFAULT false, created_at TIMESTAMP DEFAULT NOW())`,
    `CREATE TABLE IF NOT EXISTS precios_fijos (id SERIAL PRIMARY KEY, producto_id INT, lista_precio_id VARCHAR(50), precio_fijo NUMERIC(12,2), UNIQUE(producto_id, lista_precio_id))`,
    `CREATE TABLE IF NOT EXISTS historial_precios (id SERIAL PRIMARY KEY, producto_id INT, precio_anterior NUMERIC(12,2), precio_nuevo NUMERIC(12,2), usuario VARCHAR(100), created_at TIMESTAMP DEFAULT NOW())`,
    `CREATE TABLE IF NOT EXISTS pedido_historial (id SERIAL PRIMARY KEY, tenant_id INT DEFAULT 1, pedido_id INT, tipo VARCHAR(30), detalle TEXT, usuario_id INT, usuario_nombre VARCHAR(100), created_at TIMESTAMP DEFAULT NOW())`,
    `CREATE TABLE IF NOT EXISTS pedidos (id SERIAL PRIMARY KEY, usuario_id INT, seccion_id INT, tipo VARCHAR(20) DEFAULT 'pedido', estado VARCHAR(30) DEFAULT 'pendiente', total NUMERIC(12,2) DEFAULT 0, subtotal NUMERIC(12,2) DEFAULT 0, descuento NUMERIC(12,2) DEFAULT 0, cupon_codigo VARCHAR(50) DEFAULT '', metodo_pago VARCHAR(100) DEFAULT '', notas TEXT DEFAULT '', datos_envio TEXT DEFAULT '', archivado BOOLEAN DEFAULT false, notificar_wa BOOLEAN DEFAULT true, is_test BOOLEAN DEFAULT false, costo_envio NUMERIC(12,2) DEFAULT 0, metodo_envio VARCHAR(100) DEFAULT '', cp_destino VARCHAR(20) DEFAULT '', created_at TIMESTAMP DEFAULT NOW(), updated_at TIMESTAMP DEFAULT NOW())`,
    `CREATE TABLE IF NOT EXISTS pedido_items (id SERIAL PRIMARY KEY, pedido_id INT REFERENCES pedidos(id), producto_id INT, categoria VARCHAR(200) DEFAULT '', modelo VARCHAR(200) DEFAULT '', nombre_producto VARCHAR(300) DEFAULT '', cantidad INT DEFAULT 1, precio_unitario NUMERIC(12,2) DEFAULT 0, precio_base NUMERIC(12,2) DEFAULT 0)`,
    `CREATE TABLE IF NOT EXISTS cupones (id SERIAL PRIMARY KEY, codigo VARCHAR(50) UNIQUE, tipo VARCHAR(20) DEFAULT 'porcentaje', valor NUMERIC(12,2) DEFAULT 0, secciones_ids TEXT DEFAULT '', categoria VARCHAR(200) DEFAULT '', uso_maximo INT DEFAULT 0, usos_actuales INT DEFAULT 0, monto_minimo NUMERIC(12,2) DEFAULT 0, metodo_pago VARCHAR(100) DEFAULT '', activo BOOLEAN DEFAULT true, fecha_desde DATE, fecha_hasta DATE, created_at TIMESTAMP DEFAULT NOW())`,
    `CREATE TABLE IF NOT EXISTS cupon_productos (id SERIAL PRIMARY KEY, cupon_id INT REFERENCES cupones(id) ON DELETE CASCADE, producto_id INT REFERENCES productos(id) ON DELETE CASCADE)`,
    `CREATE TABLE IF NOT EXISTS paginas_info (id SERIAL PRIMARY KEY, titulo VARCHAR(300), slug VARCHAR(100), contenido TEXT DEFAULT '', seccion_id INT, visible BOOLEAN DEFAULT true, orden INT DEFAULT 0, created_at TIMESTAMP DEFAULT NOW())`,
    `CREATE TABLE IF NOT EXISTS badges (id SERIAL PRIMARY KEY, icono VARCHAR(50) DEFAULT '⭐', texto VARCHAR(200), color VARCHAR(20) DEFAULT '#2563eb', visible BOOLEAN DEFAULT true, secciones_ids TEXT DEFAULT '', orden INT DEFAULT 0)`,
    `CREATE TABLE IF NOT EXISTS config_envio (id SERIAL PRIMARY KEY, seccion_id INT UNIQUE, metodo VARCHAR(30) DEFAULT 'manual', costo_fijo NUMERIC(12,2) DEFAULT 0, gratis_desde NUMERIC(12,2) DEFAULT 0, zonas JSONB DEFAULT '[]', cp_origen VARCHAR(20) DEFAULT '1888')`,
    `CREATE TABLE IF NOT EXISTS promociones (id SERIAL PRIMARY KEY, nombre VARCHAR(200), tipo VARCHAR(20) DEFAULT 'porcentaje', valor NUMERIC(12,2) DEFAULT 0, secciones_ids TEXT DEFAULT '', categoria VARCHAR(200) DEFAULT '', productos_ids TEXT DEFAULT '', activo BOOLEAN DEFAULT true, fecha_desde DATE, fecha_hasta DATE, created_at TIMESTAMP DEFAULT NOW())`,
    `CREATE TABLE IF NOT EXISTS popups (id SERIAL PRIMARY KEY, titulo VARCHAR(200), imagen TEXT DEFAULT '', url_destino TEXT DEFAULT '', secciones_ids TEXT DEFAULT '', activo BOOLEAN DEFAULT true, created_at TIMESTAMP DEFAULT NOW())`,
    `CREATE TABLE IF NOT EXISTS redes_sociales (id SERIAL PRIMARY KEY, tipo VARCHAR(50), url TEXT DEFAULT '', activo BOOLEAN DEFAULT true, orden INT DEFAULT 0)`,
    `CREATE TABLE IF NOT EXISTS menu_items (id SERIAL PRIMARY KEY, titulo VARCHAR(200), url TEXT DEFAULT '', tipo VARCHAR(30) DEFAULT 'link', visible BOOLEAN DEFAULT true, orden INT DEFAULT 0, seccion_id INT)`,
    `CREATE TABLE IF NOT EXISTS design_config (id SERIAL PRIMARY KEY, clave VARCHAR(100) UNIQUE, valor TEXT DEFAULT '')`,
    `CREATE TABLE IF NOT EXISTS metodos_pago (id SERIAL PRIMARY KEY, nombre VARCHAR(200), descripcion TEXT DEFAULT '', instrucciones TEXT DEFAULT '', icono VARCHAR(50) DEFAULT '💳', seccion_id INT, activo BOOLEAN DEFAULT true, orden INT DEFAULT 0)`,
    `CREATE TABLE IF NOT EXISTS producto_imagenes (id SERIAL PRIMARY KEY, producto_id INT REFERENCES productos(id) ON DELETE CASCADE, url TEXT NOT NULL, orden INT DEFAULT 0)`,
    `CREATE TABLE IF NOT EXISTS variantes (id SERIAL PRIMARY KEY, producto_id INT REFERENCES productos(id) ON DELETE CASCADE, nombre VARCHAR(200) DEFAULT '', valor VARCHAR(200) DEFAULT '', stock INT DEFAULT 0, precio_extra NUMERIC(12,2) DEFAULT 0)`,
    `CREATE TABLE IF NOT EXISTS slider_banners (id SERIAL PRIMARY KEY, titulo VARCHAR(300) DEFAULT '', imagen TEXT DEFAULT '', url_destino TEXT DEFAULT '', orden INT DEFAULT 0, activo BOOLEAN DEFAULT true)`,
    `CREATE TABLE IF NOT EXISTS barras_texto (id SERIAL PRIMARY KEY, posicion VARCHAR(20) DEFAULT 'top', frases TEXT DEFAULT '', estilo VARCHAR(20) DEFAULT 'negro', color_fondo VARCHAR(20) DEFAULT '', color_texto VARCHAR(20) DEFAULT '', velocidad INT DEFAULT 25, activo BOOLEAN DEFAULT true)`,
    `CREATE TABLE IF NOT EXISTS contactos (id SERIAL PRIMARY KEY, nombre VARCHAR(120) DEFAULT '', rol VARCHAR(120) DEFAULT '', telefono VARCHAR(40) DEFAULT '', avatar TEXT DEFAULT '', seccion_id INT, online BOOLEAN DEFAULT true, mensaje_default TEXT DEFAULT '', orden INT DEFAULT 0, activo BOOLEAN DEFAULT true)`,
    `CREATE TABLE IF NOT EXISTS leads (id SERIAL PRIMARY KEY, nombre VARCHAR(160) DEFAULT '', telefono VARCHAR(40) DEFAULT '', contacto_id INT, contacto_nombre VARCHAR(120) DEFAULT '', usuario_id INT, contactado BOOLEAN DEFAULT false, created_at TIMESTAMP DEFAULT NOW())`,
    `CREATE TABLE IF NOT EXISTS favoritos (id SERIAL PRIMARY KEY, usuario_id INT REFERENCES usuarios(id) ON DELETE CASCADE, producto_id INT REFERENCES productos(id) ON DELETE CASCADE, created_at TIMESTAMP DEFAULT NOW(), UNIQUE(usuario_id, producto_id))`,
    `CREATE TABLE IF NOT EXISTS notificaciones_stock (id SERIAL PRIMARY KEY, producto_id INT REFERENCES productos(id) ON DELETE CASCADE, email VARCHAR(200), notificado BOOLEAN DEFAULT false, created_at TIMESTAMP DEFAULT NOW())`,
    `CREATE TABLE IF NOT EXISTS tokens_revocados (token_hash VARCHAR(100) PRIMARY KEY, expira TIMESTAMP DEFAULT NOW())`,
    `CREATE TABLE IF NOT EXISTS otp_codes (id SERIAL PRIMARY KEY, usuario_id INT REFERENCES usuarios(id), codigo VARCHAR(10), expira TIMESTAMP, usado BOOLEAN DEFAULT false)`,
    `CREATE TABLE IF NOT EXISTS metodos_envio_custom (id SERIAL PRIMARY KEY, seccion_id INT, nombre VARCHAR(200), descripcion TEXT DEFAULT '', precio NUMERIC(12,2) DEFAULT 0, tipo VARCHAR(30) DEFAULT 'fijo', activo BOOLEAN DEFAULT true, gratis_desde NUMERIC(12,2) DEFAULT 0, tiempo_estimado VARCHAR(100) DEFAULT '', icono VARCHAR(50) DEFAULT '🚚', orden INT DEFAULT 0, created_at TIMESTAMP DEFAULT NOW())`,
    `CREATE TABLE IF NOT EXISTS carritos_abandonados (id SERIAL PRIMARY KEY, usuario_id INT, email VARCHAR(200) DEFAULT '', telefono VARCHAR(50) DEFAULT '', items JSONB DEFAULT '[]', total NUMERIC(12,2) DEFAULT 0, seccion_id INT, created_at TIMESTAMP DEFAULT NOW(), recuperado BOOLEAN DEFAULT false)`,
    `ALTER TABLE cupones ADD COLUMN IF NOT EXISTS solo_primera_compra BOOLEAN DEFAULT false`,
  ];
  for(const q of queries) await pool.query(q).catch(e=>console.log('migrate warn', e.message.slice(0,100)));
  // Alter columns if not exists
  const alters = [
    `ALTER TABLE secciones ADD COLUMN IF NOT EXISTS ignorar_stock BOOLEAN DEFAULT false`,
    `ALTER TABLE secciones ADD COLUMN IF NOT EXISTS cp_origen VARCHAR(20) DEFAULT '1888'`,
    `ALTER TABLE historial_precios ADD COLUMN IF NOT EXISTS usuario VARCHAR(100) DEFAULT ''`,
    `ALTER TABLE variantes ADD COLUMN IF NOT EXISTS precio NUMERIC(12,2) DEFAULT 0`,
    // ── Atributos + variantes combinadas de N dimensiones (modelo Empretienda) ──
    `CREATE TABLE IF NOT EXISTS producto_atributos (id SERIAL PRIMARY KEY, tenant_id INT DEFAULT 1, producto_id INT REFERENCES productos(id) ON DELETE CASCADE, nombre VARCHAR(120) DEFAULT '', orden INT DEFAULT 0)`,
    `CREATE TABLE IF NOT EXISTS producto_atributo_valores (id SERIAL PRIMARY KEY, tenant_id INT DEFAULT 1, atributo_id INT REFERENCES producto_atributos(id) ON DELETE CASCADE, valor VARCHAR(120) DEFAULT '', orden INT DEFAULT 0)`,
    `ALTER TABLE variantes ADD COLUMN IF NOT EXISTS combinacion JSONB DEFAULT '{}'::jsonb`,
    `ALTER TABLE variantes ADD COLUMN IF NOT EXISTS precio_oferta NUMERIC(12,2) DEFAULT 0`,
    `ALTER TABLE variantes ADD COLUMN IF NOT EXISTS moneda VARCHAR(10) DEFAULT 'ARS'`,
    `ALTER TABLE variantes ADD COLUMN IF NOT EXISTS orden INT DEFAULT 0`,
    `ALTER TABLE variantes ADD COLUMN IF NOT EXISTS sku VARCHAR(120) DEFAULT ''`,
    `ALTER TABLE productos ADD COLUMN IF NOT EXISTS usa_variantes BOOLEAN DEFAULT false`,
    `ALTER TABLE pedido_items ADD COLUMN IF NOT EXISTS variante_id INT`,
    `ALTER TABLE pedido_items ADD COLUMN IF NOT EXISTS variante_combinacion TEXT DEFAULT ''`,
    `CREATE INDEX IF NOT EXISTS idx_prod_atrib_prod ON producto_atributos(producto_id)`,
    `CREATE INDEX IF NOT EXISTS idx_prod_atrib_val_atrib ON producto_atributo_valores(atributo_id)`,
    `CREATE INDEX IF NOT EXISTS idx_variantes_prod ON variantes(producto_id)`,
    `CREATE TABLE IF NOT EXISTS categorias_meta (categoria VARCHAR(200) PRIMARY KEY, orden INT DEFAULT 0, visible BOOLEAN DEFAULT true)`,
    `ALTER TABLE pedidos ADD COLUMN IF NOT EXISTS estado_pago VARCHAR(20) DEFAULT 'impago'`,
    `ALTER TABLE pedidos ADD COLUMN IF NOT EXISTS sena NUMERIC(12,2) DEFAULT 0`,
    `ALTER TABLE pedidos ADD COLUMN IF NOT EXISTS es_reserva BOOLEAN DEFAULT false`,
    `CREATE TABLE IF NOT EXISTS cuenta_corriente (id SERIAL PRIMARY KEY, usuario_id INT, tipo VARCHAR(20), monto NUMERIC(12,2) DEFAULT 0, concepto TEXT DEFAULT '', pedido_id INT, created_at TIMESTAMP DEFAULT NOW())`,
    `CREATE TABLE IF NOT EXISTS pedido_pagos (id SERIAL PRIMARY KEY, pedido_id INT, metodo VARCHAR(100) DEFAULT '', monto NUMERIC(12,2) DEFAULT 0, ajuste_pct NUMERIC(6,2) DEFAULT 0, ajuste_monto NUMERIC(12,2) DEFAULT 0, nota TEXT DEFAULT '', created_at TIMESTAMP DEFAULT NOW())`,
    `ALTER TABLE pedido_pagos ADD COLUMN IF NOT EXISTS recibido NUMERIC(12,2) DEFAULT 0`,
    `ALTER TABLE pedido_pagos ADD COLUMN IF NOT EXISTS cuenta_como NUMERIC(12,2) DEFAULT 0`,
    `UPDATE pedido_pagos SET recibido=monto, cuenta_como=monto WHERE recibido=0 AND cuenta_como=0 AND monto>0`,
    `UPDATE pedidos SET estado_pago='impago' WHERE estado_pago='pendiente' OR estado_pago IS NULL OR estado_pago=''`,
    `CREATE TABLE IF NOT EXISTS ordenes_compra (id SERIAL PRIMARY KEY, proveedor VARCHAR(200), seccion_id INT, estado VARCHAR(20) DEFAULT 'pendiente', total NUMERIC(12,2) DEFAULT 0, notas TEXT, recibida BOOLEAN DEFAULT false, created_at TIMESTAMP DEFAULT NOW())`,
    `CREATE TABLE IF NOT EXISTS orden_compra_items (id SERIAL PRIMARY KEY, orden_id INT REFERENCES ordenes_compra(id) ON DELETE CASCADE, producto_id INT, nombre_producto VARCHAR(300), cantidad INT DEFAULT 1, costo_unitario NUMERIC(12,2) DEFAULT 0)`,
    `ALTER TABLE secciones ADD COLUMN IF NOT EXISTS permitir_sin_stock BOOLEAN DEFAULT false`,
    `ALTER TABLE productos ADD COLUMN IF NOT EXISTS permitir_sin_stock BOOLEAN DEFAULT false`,
    `ALTER TABLE productos ADD COLUMN IF NOT EXISTS es_digital BOOLEAN DEFAULT false`,
    `ALTER TABLE pedidos ADD COLUMN IF NOT EXISTS is_test BOOLEAN DEFAULT false`,
    `ALTER TABLE pedidos ADD COLUMN IF NOT EXISTS costo_envio NUMERIC(12,2) DEFAULT 0`,
    `ALTER TABLE pedidos ADD COLUMN IF NOT EXISTS metodo_envio VARCHAR(100) DEFAULT ''`,
    `ALTER TABLE pedidos ADD COLUMN IF NOT EXISTS cp_destino VARCHAR(20) DEFAULT ''`,
    `ALTER TABLE usuarios ADD COLUMN IF NOT EXISTS reset_codigo VARCHAR(20) DEFAULT ''`,
    `ALTER TABLE usuarios ADD COLUMN IF NOT EXISTS reset_expira TIMESTAMP`,
    `ALTER TABLE usuarios ADD COLUMN IF NOT EXISTS otp_activo BOOLEAN DEFAULT false`,
    `ALTER TABLE config_envio ADD COLUMN IF NOT EXISTS cp_origen VARCHAR(20) DEFAULT '1888'`,
    // === ALL MISSING ALTERS FOR EXISTING DBS ===
    // secciones
    `ALTER TABLE secciones ADD COLUMN IF NOT EXISTS orden INT DEFAULT 0`,
    `ALTER TABLE secciones ADD COLUMN IF NOT EXISTS slug VARCHAR(100) DEFAULT ''`,
    `ALTER TABLE secciones ADD COLUMN IF NOT EXISTS visible BOOLEAN DEFAULT true`,
    `ALTER TABLE secciones ADD COLUMN IF NOT EXISTS requiere_aprobacion BOOLEAN DEFAULT false`,
    `ALTER TABLE secciones ADD COLUMN IF NOT EXISTS ignorar_stock BOOLEAN DEFAULT false`,
    `ALTER TABLE secciones ADD COLUMN IF NOT EXISTS permitir_sin_stock BOOLEAN DEFAULT false`,
    `ALTER TABLE secciones ADD COLUMN IF NOT EXISTS cp_origen VARCHAR(20) DEFAULT '1888'`,
    `ALTER TABLE secciones ADD COLUMN IF NOT EXISTS imagen TEXT DEFAULT ''`,
    `ALTER TABLE secciones ADD COLUMN IF NOT EXISTS color VARCHAR(20) DEFAULT '#2563eb'`,
    `ALTER TABLE secciones ADD COLUMN IF NOT EXISTS whatsapp VARCHAR(50) DEFAULT ''`,
    `ALTER TABLE secciones ADD COLUMN IF NOT EXISTS cbu VARCHAR(100) DEFAULT ''`,
    `ALTER TABLE secciones ADD COLUMN IF NOT EXISTS direccion_despacho TEXT DEFAULT ''`,
    `ALTER TABLE secciones ADD COLUMN IF NOT EXISTS metodos_pago TEXT DEFAULT ''`,
    `ALTER TABLE secciones ADD COLUMN IF NOT EXISTS activa BOOLEAN DEFAULT true`,
    `ALTER TABLE secciones ADD COLUMN IF NOT EXISTS created_at TIMESTAMP DEFAULT NOW()`,
    // badges
    `ALTER TABLE badges ADD COLUMN IF NOT EXISTS color VARCHAR(20) DEFAULT '#2563eb'`,
    `ALTER TABLE badges ADD COLUMN IF NOT EXISTS secciones_ids TEXT DEFAULT ''`,
    `ALTER TABLE badges ADD COLUMN IF NOT EXISTS orden INT DEFAULT 0`,
    `ALTER TABLE slider_banners ADD COLUMN IF NOT EXISTS subtitulo VARCHAR(500) DEFAULT ''`,
    `ALTER TABLE slider_banners ADD COLUMN IF NOT EXISTS etiqueta VARCHAR(100) DEFAULT ''`,
    // cupones
    `ALTER TABLE cupones ADD COLUMN IF NOT EXISTS monto_minimo NUMERIC(12,2) DEFAULT 0`,
    `ALTER TABLE cupones ADD COLUMN IF NOT EXISTS secciones_ids TEXT DEFAULT ''`,
    `ALTER TABLE cupones ADD COLUMN IF NOT EXISTS productos_ids TEXT DEFAULT ''`,
    `ALTER TABLE cupones ADD COLUMN IF NOT EXISTS activo BOOLEAN DEFAULT true`,
    `ALTER TABLE cupones ADD COLUMN IF NOT EXISTS metodo_pago VARCHAR(100) DEFAULT ''`,
    `ALTER TABLE cupones ADD COLUMN IF NOT EXISTS categoria VARCHAR(200) DEFAULT ''`,
    `ALTER TABLE cupones ADD COLUMN IF NOT EXISTS fecha_desde DATE`,
    `ALTER TABLE cupones ADD COLUMN IF NOT EXISTS fecha_hasta DATE`,
    `ALTER TABLE cupones ADD COLUMN IF NOT EXISTS tipo VARCHAR(20) DEFAULT 'porcentaje'`,
    `ALTER TABLE cupones ADD COLUMN IF NOT EXISTS valor NUMERIC(12,2) DEFAULT 0`,
    `ALTER TABLE cupones ADD COLUMN IF NOT EXISTS uso_maximo INT DEFAULT 0`,
    `ALTER TABLE cupones ADD COLUMN IF NOT EXISTS usos_actuales INT DEFAULT 0`,
    `ALTER TABLE cupones ADD COLUMN IF NOT EXISTS created_at TIMESTAMP DEFAULT NOW()`,
    // promociones
    `ALTER TABLE promociones ADD COLUMN IF NOT EXISTS activo BOOLEAN DEFAULT true`,
    `ALTER TABLE promociones ADD COLUMN IF NOT EXISTS secciones_ids TEXT DEFAULT ''`,
    `ALTER TABLE promociones ADD COLUMN IF NOT EXISTS productos_ids TEXT DEFAULT ''`,
    `ALTER TABLE promociones ADD COLUMN IF NOT EXISTS fecha_desde DATE`,
    `ALTER TABLE promociones ADD COLUMN IF NOT EXISTS fecha_hasta DATE`,
    `ALTER TABLE promociones ADD COLUMN IF NOT EXISTS categoria VARCHAR(200) DEFAULT ''`,
    `ALTER TABLE promociones ADD COLUMN IF NOT EXISTS tipo VARCHAR(20) DEFAULT 'porcentaje'`,
    `ALTER TABLE promociones ADD COLUMN IF NOT EXISTS valor NUMERIC(12,2) DEFAULT 0`,
    `ALTER TABLE promociones ADD COLUMN IF NOT EXISTS created_at TIMESTAMP DEFAULT NOW()`,
    // pedido_items - EVERY column
    `ALTER TABLE pedido_items ADD COLUMN IF NOT EXISTS categoria VARCHAR(200) DEFAULT ''`,
    `ALTER TABLE pedido_items ADD COLUMN IF NOT EXISTS modelo VARCHAR(200) DEFAULT ''`,
    `ALTER TABLE pedido_items ADD COLUMN IF NOT EXISTS imagen TEXT DEFAULT ''`,
    `ALTER TABLE pedido_items ADD COLUMN IF NOT EXISTS seccion_nombre VARCHAR(200) DEFAULT ''`,
    `ALTER TABLE pedido_items ADD COLUMN IF NOT EXISTS nombre_producto VARCHAR(300) DEFAULT ''`,
    `ALTER TABLE pedido_items ADD COLUMN IF NOT EXISTS cantidad INT DEFAULT 1`,
    `ALTER TABLE pedido_items ADD COLUMN IF NOT EXISTS precio_unitario NUMERIC(12,2) DEFAULT 0`,
    `ALTER TABLE pedido_items ADD COLUMN IF NOT EXISTS precio_base NUMERIC(12,2) DEFAULT 0`,
    // pedidos - EVERY column
    `ALTER TABLE pedidos ADD COLUMN IF NOT EXISTS datos_envio TEXT DEFAULT ''`,
    `ALTER TABLE pedidos ADD COLUMN IF NOT EXISTS datos_facturacion TEXT DEFAULT ''`,
    `ALTER TABLE pedidos ADD COLUMN IF NOT EXISTS archivado BOOLEAN DEFAULT false`,
    `ALTER TABLE pedidos ADD COLUMN IF NOT EXISTS is_test BOOLEAN DEFAULT false`,
    `ALTER TABLE pedidos ADD COLUMN IF NOT EXISTS costo_envio NUMERIC(12,2) DEFAULT 0`,
    `ALTER TABLE pedidos ADD COLUMN IF NOT EXISTS metodo_envio VARCHAR(100) DEFAULT ''`,
    `ALTER TABLE pedidos ADD COLUMN IF NOT EXISTS cp_destino VARCHAR(20) DEFAULT ''`,
    `ALTER TABLE pedidos ADD COLUMN IF NOT EXISTS estado VARCHAR(30) DEFAULT 'pendiente'`,
    `ALTER TABLE pedidos ADD COLUMN IF NOT EXISTS subtotal NUMERIC(12,2) DEFAULT 0`,
    `ALTER TABLE pedidos ADD COLUMN IF NOT EXISTS descuento NUMERIC(12,2) DEFAULT 0`,
    `ALTER TABLE pedidos ADD COLUMN IF NOT EXISTS cupon_codigo VARCHAR(50) DEFAULT ''`,
    `ALTER TABLE pedidos ADD COLUMN IF NOT EXISTS metodo_pago VARCHAR(100) DEFAULT ''`,
    `ALTER TABLE pedidos ADD COLUMN IF NOT EXISTS notas TEXT DEFAULT ''`,
    `ALTER TABLE pedidos ADD COLUMN IF NOT EXISTS notificar_wa BOOLEAN DEFAULT true`,
    `ALTER TABLE pedidos ADD COLUMN IF NOT EXISTS updated_at TIMESTAMP DEFAULT NOW()`,
    `ALTER TABLE pedidos ADD COLUMN IF NOT EXISTS created_at TIMESTAMP DEFAULT NOW()`,
    // productos - EVERY column
    `ALTER TABLE productos ADD COLUMN IF NOT EXISTS notas TEXT DEFAULT ''`,
    `ALTER TABLE productos ADD COLUMN IF NOT EXISTS compatibilidad TEXT DEFAULT ''`,
    `ALTER TABLE productos ADD COLUMN IF NOT EXISTS marca VARCHAR(200) DEFAULT ''`,
    `ALTER TABLE productos ADD COLUMN IF NOT EXISTS es_preventa BOOLEAN DEFAULT false`,
    `ALTER TABLE productos ADD COLUMN IF NOT EXISTS preventa_precio NUMERIC(12,2) DEFAULT 0`,
    `ALTER TABLE productos ADD COLUMN IF NOT EXISTS preventa_cupo INT DEFAULT 0`,
    `ALTER TABLE productos ADD COLUMN IF NOT EXISTS preventa_reservado INT DEFAULT 0`,
    `ALTER TABLE productos ADD COLUMN IF NOT EXISTS preventa_descuento_pct NUMERIC(5,2) DEFAULT 0`,
    `ALTER TABLE productos ADD COLUMN IF NOT EXISTS preventa_fecha DATE`,
    `ALTER TABLE productos ADD COLUMN IF NOT EXISTS preventa_mostrar_fecha BOOLEAN DEFAULT false`,
    `ALTER TABLE notificaciones_stock ADD COLUMN IF NOT EXISTS telefono VARCHAR(50) DEFAULT ''`,
    `ALTER TABLE notificaciones_stock ADD COLUMN IF NOT EXISTS canal VARCHAR(20) DEFAULT 'email'`,
    `ALTER TABLE productos ADD COLUMN IF NOT EXISTS modelo VARCHAR(200) DEFAULT ''`,
    `ALTER TABLE productos ADD COLUMN IF NOT EXISTS nombre VARCHAR(300) DEFAULT ''`,
    `ALTER TABLE productos ADD COLUMN IF NOT EXISTS envio_gratis BOOLEAN DEFAULT false`,
    `ALTER TABLE productos ADD COLUMN IF NOT EXISTS permitir_sin_stock BOOLEAN DEFAULT false`,
    `ALTER TABLE productos ADD COLUMN IF NOT EXISTS es_digital BOOLEAN DEFAULT false`,
    `ALTER TABLE productos ADD COLUMN IF NOT EXISTS peso NUMERIC(8,2) DEFAULT 0`,
    `ALTER TABLE productos ADD COLUMN IF NOT EXISTS alto NUMERIC(8,2) DEFAULT 0`,
    `ALTER TABLE productos ADD COLUMN IF NOT EXISTS ancho NUMERIC(8,2) DEFAULT 0`,
    `ALTER TABLE productos ADD COLUMN IF NOT EXISTS largo NUMERIC(8,2) DEFAULT 0`,
    `ALTER TABLE productos ADD COLUMN IF NOT EXISTS descripcion TEXT DEFAULT ''`,
    `ALTER TABLE productos ADD COLUMN IF NOT EXISTS sku VARCHAR(100) DEFAULT ''`,
    `ALTER TABLE productos ADD COLUMN IF NOT EXISTS codigo_barras VARCHAR(60) DEFAULT ''`,
    `ALTER TABLE productos ADD COLUMN IF NOT EXISTS tipo VARCHAR(20) DEFAULT 'fisico'`,
    `ALTER TABLE productos ADD COLUMN IF NOT EXISTS moneda VARCHAR(10) DEFAULT 'ARS'`,
    `ALTER TABLE productos ADD COLUMN IF NOT EXISTS precio_oferta NUMERIC(12,2) DEFAULT 0`,
    `ALTER TABLE productos ADD COLUMN IF NOT EXISTS precio_original NUMERIC(12,2) DEFAULT 0`,
    `ALTER TABLE productos ADD COLUMN IF NOT EXISTS stock_minimo INT DEFAULT 0`,
    `ALTER TABLE productos ADD COLUMN IF NOT EXISTS visible BOOLEAN DEFAULT true`,
    `ALTER TABLE productos ADD COLUMN IF NOT EXISTS created_at TIMESTAMP DEFAULT NOW()`,
    // usuarios
    `ALTER TABLE usuarios ADD COLUMN IF NOT EXISTS reset_codigo VARCHAR(20) DEFAULT ''`,
    `ALTER TABLE usuarios ADD COLUMN IF NOT EXISTS reset_expira TIMESTAMP`,
    `ALTER TABLE usuarios ADD COLUMN IF NOT EXISTS otp_activo BOOLEAN DEFAULT false`,
    `ALTER TABLE usuarios ADD COLUMN IF NOT EXISTS nombre_fantasia VARCHAR(200) DEFAULT ''`,
    `ALTER TABLE usuarios ADD COLUMN IF NOT EXISTS lista_precio_id VARCHAR(50) DEFAULT ''`,
    // listas_precio
    `ALTER TABLE listas_precio ADD COLUMN IF NOT EXISTS color VARCHAR(20) DEFAULT '#2563eb'`,
    `ALTER TABLE listas_precio ADD COLUMN IF NOT EXISTS compra_minima NUMERIC(12,2) DEFAULT 0`,
    `ALTER TABLE listas_precio ADD COLUMN IF NOT EXISTS promo_msg TEXT DEFAULT ''`,
    `ALTER TABLE listas_precio ADD COLUMN IF NOT EXISTS modo VARCHAR(20) DEFAULT 'porcentaje'`,
    // popups
    `ALTER TABLE popups ADD COLUMN IF NOT EXISTS secciones_ids TEXT DEFAULT ''`,
    // menu_items
    `ALTER TABLE menu_items ADD COLUMN IF NOT EXISTS seccion_id INT`,
    `ALTER TABLE menu_items ADD COLUMN IF NOT EXISTS orden INT DEFAULT 0`,
    // metodos_pago
    `ALTER TABLE metodos_pago ADD COLUMN IF NOT EXISTS seccion_id INT`,
    `ALTER TABLE metodos_pago ADD COLUMN IF NOT EXISTS orden INT DEFAULT 0`,
    `ALTER TABLE metodos_pago ADD COLUMN IF NOT EXISTS instrucciones TEXT DEFAULT ''`,
    `ALTER TABLE metodos_pago ADD COLUMN IF NOT EXISTS icono VARCHAR(50) DEFAULT '💳'`,
    `ALTER TABLE metodos_pago ALTER COLUMN icono TYPE TEXT`,
    `ALTER TABLE metodos_envio_custom ADD COLUMN IF NOT EXISTS icono VARCHAR(50) DEFAULT '🚚'`,
    `ALTER TABLE metodos_envio_custom ALTER COLUMN icono TYPE TEXT`,
    `ALTER TABLE badges ALTER COLUMN icono TYPE TEXT`,
    `ALTER TABLE metodos_pago ADD COLUMN IF NOT EXISTS descripcion TEXT DEFAULT ''`,
    // redes_sociales
    `ALTER TABLE redes_sociales ADD COLUMN IF NOT EXISTS orden INT DEFAULT 0`,
    // paginas_info
    `ALTER TABLE paginas_info ADD COLUMN IF NOT EXISTS slug VARCHAR(100) DEFAULT ''`,
    `ALTER TABLE paginas_info ADD COLUMN IF NOT EXISTS seccion_id INT`,
    `ALTER TABLE paginas_info ADD COLUMN IF NOT EXISTS visible BOOLEAN DEFAULT true`,
    `ALTER TABLE paginas_info ADD COLUMN IF NOT EXISTS orden INT DEFAULT 0`,
  ];
  for(const a of alters) await pool.query(a).catch(()=>{});
  // Índices para performance (se crean solos, no bloquean ni borran datos)
  const indices = [
    `CREATE INDEX IF NOT EXISTS idx_productos_seccion ON productos(seccion_id)`,
    `CREATE INDEX IF NOT EXISTS idx_productos_categoria ON productos(categoria)`,
    `CREATE INDEX IF NOT EXISTS idx_productos_visible ON productos(visible)`,
    `CREATE INDEX IF NOT EXISTS idx_productos_created ON productos(created_at DESC)`,
    `CREATE INDEX IF NOT EXISTS idx_productos_sku ON productos(sku)`,
    `CREATE INDEX IF NOT EXISTS idx_productos_codigo ON productos(codigo_barras)`,
    `CREATE INDEX IF NOT EXISTS idx_pedidos_usuario ON pedidos(usuario_id)`,
    `CREATE INDEX IF NOT EXISTS idx_pedidos_seccion ON pedidos(seccion_id)`,
    `CREATE INDEX IF NOT EXISTS idx_pedidos_created ON pedidos(created_at DESC)`,
    `CREATE INDEX IF NOT EXISTS idx_pedido_items_pedido ON pedido_items(pedido_id)`,
    `CREATE INDEX IF NOT EXISTS idx_pedido_pagos_pedido ON pedido_pagos(pedido_id)`,
    `CREATE INDEX IF NOT EXISTS idx_usuarios_usuario ON usuarios(usuario)`,
    `CREATE INDEX IF NOT EXISTS idx_usuarios_email ON usuarios(email)`,
    `CREATE INDEX IF NOT EXISTS idx_usuarios_rol ON usuarios(rol)`,
    `CREATE INDEX IF NOT EXISTS idx_precios_fijos_prod ON precios_fijos(producto_id)`,
  ];
  for(const ix of indices) await pool.query(ix).catch(()=>{});
  // ═══ MULTI-TENANT: base additiva (etapa 1) ═══
  // Tabla de inquilinos (cada cliente que alquila = 1 tenant). tenant 1 = tienda actual (Leandro)
  await pool.query(`CREATE TABLE IF NOT EXISTS tenants (
    id SERIAL PRIMARY KEY,
    nombre VARCHAR(200) DEFAULT 'Mi Tienda',
    slug VARCHAR(100) UNIQUE,
    dominio_propio VARCHAR(200) DEFAULT '',
    plan VARCHAR(20) DEFAULT 'full',
    estado VARCHAR(20) DEFAULT 'activo',
    fecha_fin_trial TIMESTAMP,
    descuento_hasta TIMESTAMP,
    notas TEXT DEFAULT '',
    features JSONB,
    created_at TIMESTAMP DEFAULT NOW()
  )`).catch(e=>console.log('tenants warn', e.message.slice(0,80)));
  await pool.query(`ALTER TABLE tenants ADD COLUMN IF NOT EXISTS features JSONB`).catch(()=>{});
  // Asegurar tenant 1 (la tienda actual) — dueño, plan full, activo para siempre
  await pool.query(`INSERT INTO tenants (id, nombre, slug, plan, estado) VALUES (1, 'Tienda principal', 'principal', 'full', 'activo') ON CONFLICT (id) DO NOTHING`).catch(()=>{});
  // Pagos de suscripción de las tiendas cliente (para el panel de dueño)
  await pool.query(`CREATE TABLE IF NOT EXISTS pagos_suscripcion (
    id SERIAL PRIMARY KEY,
    tenant_id INT NOT NULL,
    monto NUMERIC(12,2) DEFAULT 0,
    metodo VARCHAR(50) DEFAULT '',
    periodo VARCHAR(20) DEFAULT '',
    notas TEXT DEFAULT '',
    pagado_en TIMESTAMP DEFAULT NOW(),
    proximo_venc TIMESTAMP,
    created_at TIMESTAMP DEFAULT NOW()
  )`).catch(e=>console.log('pagos_suscripcion warn', e.message.slice(0,80)));
  await pool.query(`CREATE INDEX IF NOT EXISTS idx_pagos_susc_tenant ON pagos_suscripcion(tenant_id)`).catch(()=>{});
  // Que el próximo tenant creado sea id 2+ (no pisar el 1)
  await pool.query(`SELECT setval(pg_get_serial_sequence('tenants','id'), GREATEST((SELECT MAX(id) FROM tenants), 1))`).catch(()=>{});
  // Agregar tenant_id DEFAULT 1 a todas las tablas con datos por tienda.
  // DEFAULT 1 = todo lo existente y todo lo nuevo (que no especifique) pertenece a la tienda actual. Nada se rompe.
  const tenantTables = ['productos','pedidos','pedido_items','pedido_pagos','usuarios','secciones','categorias_meta','configuracion','design_config','cupones','cupon_productos','promociones','listas_precio','precios_fijos','ordenes_compra','orden_compra_items','cuenta_corriente','leads','carritos_abandonados','badges','barras_texto','menu_items','metodos_pago','metodos_envio_custom','config_envio','notificaciones_stock','paginas_info','popups','redes_sociales','slider_banners','contactos','favoritos','historial_precios','producto_imagenes','variantes'];
  for(const t of tenantTables){
    await pool.query(`ALTER TABLE ${t} ADD COLUMN IF NOT EXISTS tenant_id INT DEFAULT 1`).catch(()=>{});
    await pool.query(`CREATE INDEX IF NOT EXISTS idx_${t}_tenant ON ${t}(tenant_id)`).catch(()=>{});
  }
  console.log('✅ Multi-tenant base OK (tenant_id en todas las tablas)');
  // Key-value tables: la clave ya no es única global, sino por tenant. Cambiar constraint a (tenant_id, clave).
  await pool.query(`ALTER TABLE configuracion DROP CONSTRAINT IF EXISTS configuracion_pkey`).catch(()=>{});
  await pool.query(`ALTER TABLE configuracion DROP CONSTRAINT IF EXISTS configuracion_clave_key`).catch(()=>{});
  await pool.query(`CREATE UNIQUE INDEX IF NOT EXISTS uq_configuracion_tenant_clave ON configuracion(tenant_id, clave)`).catch(e=>console.log('uq config warn', e.message.slice(0,80)));
  await pool.query(`ALTER TABLE design_config DROP CONSTRAINT IF EXISTS design_config_clave_key`).catch(()=>{});
  await pool.query(`ALTER TABLE design_config DROP CONSTRAINT IF EXISTS design_config_pkey`).catch(()=>{});
  await pool.query(`CREATE UNIQUE INDEX IF NOT EXISTS uq_design_config_tenant_clave ON design_config(tenant_id, clave)`).catch(e=>console.log('uq design warn', e.message.slice(0,80)));
  // usuario único por tenant (dos tiendas pueden tener el mismo nombre de usuario)
  await pool.query(`ALTER TABLE usuarios DROP CONSTRAINT IF EXISTS usuarios_usuario_key`).catch(()=>{});
  await pool.query(`CREATE UNIQUE INDEX IF NOT EXISTS uq_usuarios_tenant_usuario ON usuarios(tenant_id, usuario)`).catch(e=>console.log('uq usuarios warn', e.message.slice(0,80)));
  // Dueño de la plataforma (Leandro): puede administrar TODOS los tenants. El admin de tenant 1 es el dueño.
  await pool.query(`ALTER TABLE usuarios ADD COLUMN IF NOT EXISTS es_owner BOOLEAN DEFAULT false`).catch(()=>{});
  await pool.query(`UPDATE usuarios SET es_owner=true WHERE tenant_id=1 AND rol='admin' AND usuario='admin'`).catch(()=>{});
  // Design defaults
  const defs = {nombre_tienda:'Mi Tienda',logo_url:'',favicon_url:'',color_primario:'#4A69E2',color_secundario:'#232321',color_acento:'#FFA52F',fuente:'Archivo',footer_texto:'',css_custom:'',hero_titulo:'',hero_subtitulo:'',promo_banner:'',whatsapp_numero:'',whatsapp_mensaje:'Hola, quiero consultar sobre un producto',confianza_1_icono:'truck',confianza_1_titulo:'Envío a todo el país',confianza_1_sub:'Andreani y más',confianza_2_icono:'shield',confianza_2_titulo:'Compra segura',confianza_2_sub:'Garantía incluida',confianza_3_icono:'message-circle',confianza_3_titulo:'Atención directa',confianza_3_sub:'WhatsApp'};
  for(const [k,v] of Object.entries(defs)){ await pool.query("INSERT INTO design_config (tenant_id,clave,valor) VALUES (1,$1,$2) ON CONFLICT (tenant_id,clave) DO NOTHING", [k,v]).catch(()=>{}); }
  // FIX #5: seed admin si no existe ninguno
  try{
    const {rows:admins}=await pool.query("SELECT id FROM usuarios WHERE rol='admin' AND tenant_id=1 LIMIT 1");
    if(!admins.length){
      const adminPass=process.env.ADMIN_PASSWORD||'Admin1234';
      const hash=await bcrypt.hash(adminPass,12);
      await pool.query("INSERT INTO usuarios (tenant_id,nombre,usuario,password,rol,aprobado,activo) VALUES (1,'Administrador','admin',$1,'admin',true,true) ON CONFLICT (tenant_id,usuario) DO NOTHING", [hash]);
      console.log('✅ Admin creado -> usuario: admin  password: '+adminPass+'  (cambialo en Mi Cuenta)');
    }
  }catch(e){ console.log('seed admin warn', e.message); }
  // Numeración de pedidos: continuar la correlatividad histórica (arrancar en 6000).
  // Idempotente y SIN retroceso: si ya hay pedidos >= 6000 usa MAX(id)+1, así nunca pisa un número existente.
  await pool.query(`SELECT setval(pg_get_serial_sequence('pedidos','id'), GREATEST(6000, (SELECT COALESCE(MAX(id),0)+1 FROM pedidos)), false)`).catch(e=>console.log('seq pedidos warn', e.message.slice(0,80)));
  // Reparar productos que tienen fotos en la galería pero quedaron con imagen vacía (bug viejo): ponerles la primera de la galería. Idempotente.
  await pool.query(`UPDATE productos p SET imagen = (SELECT url FROM producto_imagenes pi WHERE pi.producto_id=p.id AND pi.tenant_id=p.tenant_id ORDER BY orden ASC, id ASC LIMIT 1) WHERE (p.imagen IS NULL OR p.imagen='') AND EXISTS (SELECT 1 FROM producto_imagenes pi WHERE pi.producto_id=p.id AND pi.tenant_id=p.tenant_id)`).catch(e=>console.log('repair img warn', e.message.slice(0,80)));
  console.log('✅ Migrate V4 OK');
}

// === UTILS ===
const validatePassword = (pw)=>{
  if(!pw || pw.length<8) return 'Min 8 caracteres';
  if(!/[A-Z]/.test(pw)) return 'Una mayuscula requerida';
  if(!/[0-9]/.test(pw)) return 'Un numero requerido';
  return null;
};
let dolarBlueCache={valor:null, ts:0};

// === HEALTH ===
app.get('/api/health', (req,res)=>res.json({ok:true, v:'4.4.0', cloudinary: !!process.env.CLOUDINARY_CLOUD_NAME}));

// ═══════════ PANEL DUEÑO: administración de tenants (solo owner) ═══════════
// Listar todos los tenants con métricas básicas
app.get('/api/tenants', authOwner, async (req,res)=>{
  try{
    const {rows}=await pool.query(`
      SELECT t.*,
        (SELECT COUNT(*)::int FROM productos WHERE tenant_id=t.id) as productos,
        (SELECT COUNT(*)::int FROM pedidos WHERE tenant_id=t.id AND tipo='pedido') as pedidos,
        (SELECT COUNT(*)::int FROM usuarios WHERE tenant_id=t.id AND rol='cliente') as clientes
      FROM tenants t ORDER BY t.id`);
    res.json(rows);
  }catch(e){ res.status(500).json({error:e.message}); }
});
// Estadísticas de negocio de la plataforma (para el panel de dueño)
app.get('/api/plataforma/stats', authOwner, async (req,res)=>{
  try{
    const PRECIOS=await getPlanPrecios();
    const {rows:tenants}=await pool.query('SELECT id, plan, estado, fecha_fin_trial, descuento_hasta, created_at FROM tenants');
    // conteos por estado y por plan
    const porEstado={activo:0, trial:0, suspendido:0, vencido:0};
    const porPlan={basic:0, pro:0, full:0};
    let facturacionMensual=0; // solo tiendas activas (no trial, no suspendida) que pagan
    const hoy=new Date();
    for(const t of tenants){
      if(t.id===1) continue; // la tienda propia de Leandro no cuenta como cliente que paga
      porEstado[t.estado]=(porEstado[t.estado]||0)+1;
      porPlan[t.plan]=(porPlan[t.plan]||0)+1;
      if(t.estado==='activo'){
        let precio=PRECIOS[t.plan]||0;
        // aplicar descuento si está vigente
        if(t.descuento_hasta && new Date(t.descuento_hasta)>hoy) precio=Math.round(precio*0.75);
        facturacionMensual+=precio;
      }
    }
    // próximos vencimientos de prueba (trial que vence en <=7 días) y tiendas por vencer
    const proximosTrials=tenants
      .filter(t=>t.id!==1 && t.estado==='trial' && t.fecha_fin_trial)
      .map(t=>({id:t.id, dias: Math.ceil((new Date(t.fecha_fin_trial)-hoy)/86400000)}))
      .filter(t=>t.dias<=7)
      .sort((a,b)=>a.dias-b.dias);
    // tiendas nuevas por mes (últimos 6 meses)
    const {rows:porMes}=await pool.query(`
      SELECT to_char(date_trunc('month', created_at),'YYYY-MM') as mes, COUNT(*)::int as nuevas
      FROM tenants WHERE id!=1 AND created_at >= NOW() - INTERVAL '6 months'
      GROUP BY 1 ORDER BY 1`);
    // uso total de la plataforma
    const {rows:uso}=await pool.query(`SELECT
      (SELECT COUNT(*)::int FROM productos) as productos,
      (SELECT COUNT(*)::int FROM pedidos WHERE tipo='pedido') as pedidos,
      (SELECT COUNT(*)::int FROM usuarios WHERE rol='cliente') as clientes`);
    res.json({
      total_tiendas: tenants.filter(t=>t.id!==1).length,
      por_estado: porEstado,
      por_plan: porPlan,
      facturacion_mensual: facturacionMensual,
      precios: PRECIOS,
      proximos_trials: proximosTrials,
      nuevas_por_mes: porMes,
      uso_total: uso[0],
    });
  }catch(e){ res.status(500).json({error:e.message}); }
});
// Leer precios de planes (owner)
// Precios + oferta públicos (para el landing de ComerciApp, sin login)
async function getOfertaLanzamiento(){
  try{
    const {rows}=await pool.query("SELECT clave, valor FROM configuracion WHERE tenant_id=1 AND clave IN ('oferta_descuento_pct','oferta_meses')");
    let pct=25, meses=3;
    for(const r of rows){
      if(r.clave==='oferta_descuento_pct'){ const v=parseInt(r.valor); if(!isNaN(v)&&v>=0&&v<=100) pct=v; }
      if(r.clave==='oferta_meses'){ const v=parseInt(r.valor); if(!isNaN(v)&&v>=0) meses=v; }
    }
    return { descuento_pct:pct, meses };
  }catch{ return { descuento_pct:25, meses:3 }; }
}
app.get('/api/planes-publicos', async (req,res)=>{
  try{
    const precios=await getPlanPrecios();
    const oferta=await getOfertaLanzamiento();
    res.json({ ...precios, ...oferta });
  }catch(e){ res.json({ ...PLAN_PRECIOS, descuento_pct:25, meses:3 }); }
});
// Registro self-service (público, con rate limit): crea una tienda nueva con 15 días gratis Full + su admin
app.post('/api/registro-tienda', authLimiter, async (req,res)=>{
  const client=await pool.connect();
  try{
    const {nombre_tienda, slug, nombre, usuario, password, email, telefono}=req.body;
    if(!nombre_tienda || !slug || !usuario || !password) return res.status(400).json({error:'Faltan datos obligatorios'});
    if(String(password).length<6) return res.status(400).json({error:'La contraseña debe tener al menos 6 caracteres'});
    const slugClean=String(slug).toLowerCase().trim().replace(/[^a-z0-9-]/g,'');
    if(!slugClean || slugClean.length<3) return res.status(400).json({error:'La dirección web debe tener al menos 3 letras (solo letras, números y guiones)'});
    const admUser=String(usuario).toLowerCase().trim();
    if(admUser.length<3) return res.status(400).json({error:'El usuario debe tener al menos 3 letras'});
    await client.query('BEGIN');
    const {rows:ex}=await client.query('SELECT id FROM tenants WHERE slug=$1', [slugClean]);
    if(ex[0]){ await client.query('ROLLBACK'); return res.status(400).json({error:'Esa dirección web ya está en uso, probá con otra'}); }
    // 15 días de prueba Full
    const dias=15;
    const finTrial=new Date(Date.now()+dias*24*60*60*1000);
    const {rows:tRows}=await client.query(
      `INSERT INTO tenants (nombre,slug,plan,estado,fecha_fin_trial) VALUES ($1,$2,'full','trial',$3) RETURNING *`,
      [nombre_tienda, slugClean, finTrial]);
    const tid=tRows[0].id;
    const hash=await bcrypt.hash(password, 12);
    await client.query(
      `INSERT INTO usuarios (tenant_id,nombre,usuario,password,rol,aprobado,activo,email,telefono) VALUES ($1,$2,$3,$4,'admin',true,true,$5,$6)`,
      [tid, nombre||'Administrador', admUser, hash, email||null, telefono||null]);
    const seedDesign={nombre_tienda:nombre_tienda, color_primario:'#4A69E2', color_secundario:'#232321', color_acento:'#FFA52F', fuente:'Archivo'};
    for(const [k,v] of Object.entries(seedDesign)){
      await client.query('INSERT INTO design_config (tenant_id,clave,valor) VALUES ($1,$2,$3) ON CONFLICT (tenant_id,clave) DO NOTHING', [tid,k,v]);
    }
    await client.query('COMMIT');
    tenantCache.clear(); tenantDataCache.clear();
    res.json({ ok:true, slug:slugClean, usuario:admUser, dias });
  }catch(e){ await client.query('ROLLBACK').catch(()=>{}); res.status(500).json({error:e.message}); }
  finally{ client.release(); }
});
app.get('/api/plataforma/precios', authOwner, async (req,res)=>{
  try{ res.json(await getPlanPrecios()); }catch(e){ res.status(500).json({error:e.message}); }
});
// Guardar precios de planes (owner) — se guardan en la config de la plataforma (tenant 1)
app.put('/api/plataforma/precios', authOwner, async (req,res)=>{
  try{
    const {basic, pro, full}=req.body;
    const vals={precio_basic:basic, precio_pro:pro, precio_full:full};
    for(const [clave,val] of Object.entries(vals)){
      if(val===undefined || val===null || val==='') continue;
      const num=parseInt(val);
      if(isNaN(num) || num<0) continue;
      await pool.query("INSERT INTO configuracion (tenant_id,clave,valor) VALUES (1,$1,$2) ON CONFLICT (tenant_id,clave) DO UPDATE SET valor=$2", [clave, String(num)]);
    }
    res.json(await getPlanPrecios());
  }catch(e){ res.status(500).json({error:e.message}); }
});
// Oferta de lanzamiento (owner): leer / guardar descuento_pct y meses
app.get('/api/plataforma/oferta', authOwner, async (req,res)=>{
  try{ res.json(await getOfertaLanzamiento()); }catch(e){ res.status(500).json({error:e.message}); }
});
app.put('/api/plataforma/oferta', authOwner, async (req,res)=>{
  try{
    const {descuento_pct, meses}=req.body;
    if(descuento_pct!==undefined && descuento_pct!==null && descuento_pct!==''){
      const p=parseInt(descuento_pct);
      if(!isNaN(p) && p>=0 && p<=100) await pool.query("INSERT INTO configuracion (tenant_id,clave,valor) VALUES (1,'oferta_descuento_pct',$1) ON CONFLICT (tenant_id,clave) DO UPDATE SET valor=$1", [String(p)]);
    }
    if(meses!==undefined && meses!==null && meses!==''){
      const m=parseInt(meses);
      if(!isNaN(m) && m>=0) await pool.query("INSERT INTO configuracion (tenant_id,clave,valor) VALUES (1,'oferta_meses',$1) ON CONFLICT (tenant_id,clave) DO UPDATE SET valor=$1", [String(m)]);
    }
    res.json(await getOfertaLanzamiento());
  }catch(e){ res.status(500).json({error:e.message}); }
});
// Pagos de suscripción (owner)
app.get('/api/plataforma/pagos/:tenantId', authOwner, async (req,res)=>{
  try{ const {rows}=await pool.query('SELECT * FROM pagos_suscripcion WHERE tenant_id=$1 ORDER BY pagado_en DESC', [req.params.tenantId]); res.json(rows); }
  catch(e){ res.status(500).json({error:e.message}); }
});
app.post('/api/plataforma/pagos', authOwner, async (req,res)=>{
  try{
    const {tenant_id, monto, metodo, periodo, notas, proximo_venc}=req.body;
    if(!tenant_id || monto===undefined) return res.status(400).json({error:'Faltan datos'});
    const {rows}=await pool.query(
      `INSERT INTO pagos_suscripcion (tenant_id, monto, metodo, periodo, notas, proximo_venc) VALUES ($1,$2,$3,$4,$5,$6) RETURNING *`,
      [tenant_id, parseFloat(monto)||0, metodo||'', periodo||'', notas||'', proximo_venc||null]);
    res.json(rows[0]);
  }catch(e){ res.status(500).json({error:e.message}); }
});
app.delete('/api/plataforma/pagos/:id', authOwner, async (req,res)=>{
  try{ await pool.query('DELETE FROM pagos_suscripcion WHERE id=$1', [req.params.id]); res.json({ok:true}); }
  catch(e){ res.status(500).json({error:e.message}); }
});
// Resumen de cobros del mes en curso (owner)
app.get('/api/plataforma/cobros', authOwner, async (req,res)=>{
  try{
    const {rows:mes}=await pool.query(`SELECT COALESCE(SUM(monto),0)::float as total, COUNT(*)::int as cant FROM pagos_suscripcion WHERE date_trunc('month', pagado_en)=date_trunc('month', NOW())`);
    const {rows:ult}=await pool.query(`
      SELECT p.id, p.tenant_id, p.monto, p.metodo, p.periodo, p.pagado_en, t.nombre as tienda
      FROM pagos_suscripcion p LEFT JOIN tenants t ON t.id=p.tenant_id
      ORDER BY p.pagado_en DESC LIMIT 10`);
    res.json({ mes_total: mes[0].total, mes_cant: mes[0].cant, ultimos: ult });
  }catch(e){ res.status(500).json({error:e.message}); }
});
app.get('/api/tenants/:id', authOwner, async (req,res)=>{
  try{ const {rows}=await pool.query('SELECT * FROM tenants WHERE id=$1', [req.params.id]); if(!rows[0]) return res.status(404).json({error:'No encontrado'}); res.json(rows[0]); }
  catch(e){ res.status(500).json({error:e.message}); }
});
// Crear tenant nuevo (+ su admin + seed de diseño mínimo)
app.post('/api/tenants', authOwner, async (req,res)=>{
  const client=await pool.connect();
  try{
    const {nombre, slug, plan, admin_usuario, admin_password, dias_trial}=req.body;
    if(!nombre || !slug) return res.status(400).json({error:'Falta nombre o slug'});
    const slugClean=String(slug).toLowerCase().trim().replace(/[^a-z0-9-]/g,'');
    if(!slugClean) return res.status(400).json({error:'Slug inválido'});
    await client.query('BEGIN');
    // slug único
    const {rows:ex}=await client.query('SELECT id FROM tenants WHERE slug=$1', [slugClean]);
    if(ex[0]){ await client.query('ROLLBACK'); return res.status(400).json({error:'Ese slug ya existe'}); }
    const estado = dias_trial>0 ? 'trial' : 'activo';
    const finTrial = dias_trial>0 ? new Date(Date.now()+dias_trial*24*60*60*1000) : null;
    const {rows:tRows}=await client.query(
      `INSERT INTO tenants (nombre,slug,plan,estado,fecha_fin_trial) VALUES ($1,$2,$3,$4,$5) RETURNING *`,
      [nombre, slugClean, plan||'full', estado, finTrial]);
    const tid=tRows[0].id;
    // admin del nuevo tenant
    const admUser=(admin_usuario||'admin').toLowerCase().trim();
    const admPass=admin_password||Math.random().toString(36).slice(2,10);
    const hash=await bcrypt.hash(admPass, 12);
    await client.query(
      `INSERT INTO usuarios (tenant_id,nombre,usuario,password,rol,aprobado,activo) VALUES ($1,'Administrador',$2,$3,'admin',true,true)`,
      [tid, admUser, hash]);
    // seed diseño mínimo para el nuevo tenant
    const seedDesign={nombre_tienda:nombre, color_primario:'#4A69E2', color_secundario:'#232321', color_acento:'#FFA52F', fuente:'Archivo'};
    for(const [k,v] of Object.entries(seedDesign)){
      await client.query('INSERT INTO design_config (tenant_id,clave,valor) VALUES ($1,$2,$3) ON CONFLICT (tenant_id,clave) DO NOTHING', [tid,k,v]);
    }
    await client.query('COMMIT');
    tenantCache.clear(); tenantDataCache.clear(); // refrescar caches del tenant
    res.json({ ...tRows[0], admin_usuario:admUser, admin_password:admPass });
  }catch(e){ await client.query('ROLLBACK').catch(()=>{}); res.status(500).json({error:e.message}); }
  finally{ client.release(); }
});
// Actualizar tenant (plan, estado, fechas, dominio, notas)
app.put('/api/tenants/:id', authOwner, async (req,res)=>{
  try{
    const campos=['nombre','slug','plan','estado','dominio_propio','notas'];
    const sets=[]; const params=[]; let pi=1;
    for(const k of campos){ if(req.body[k]!==undefined){ sets.push(`${k}=$${pi}`); params.push(req.body[k]); pi++; } }
    if(req.body.fecha_fin_trial!==undefined){ sets.push(`fecha_fin_trial=$${pi}`); params.push(req.body.fecha_fin_trial||null); pi++; }
    if(req.body.descuento_hasta!==undefined){ sets.push(`descuento_hasta=$${pi}`); params.push(req.body.descuento_hasta||null); pi++; }
    if(!sets.length) return res.json({ok:true});
    params.push(req.params.id);
    await pool.query(`UPDATE tenants SET ${sets.join(',')} WHERE id=$${pi}`, params);
    tenantCache.clear(); tenantDataCache.clear();
    res.json({ok:true});
  }catch(e){ res.status(500).json({error:e.message}); }
});
// Activar / suspender rápido
app.post('/api/tenants/:id/estado', authOwner, async (req,res)=>{
  try{
    const {estado}=req.body; // 'activo' | 'suspendido' | 'vencido'
    if(req.params.id==='1') return res.status(400).json({error:'No podés cambiar el estado de la tienda principal'});
    await pool.query('UPDATE tenants SET estado=$1 WHERE id=$2', [estado||'activo', req.params.id]);
    tenantCache.clear(); tenantDataCache.clear();
    res.json({ok:true});
  }catch(e){ res.status(500).json({error:e.message}); }
});
// Borrar tenant (y TODOS sus datos) — peligroso, nunca el 1
app.delete('/api/tenants/:id', authOwner, async (req,res)=>{
  const client=await pool.connect();
  try{
    const tid=Number(req.params.id);
    if(tid===1) return res.status(400).json({error:'No se puede borrar la tienda principal'});
    await client.query('BEGIN');
    const tablas=['productos','pedidos','pedido_items','pedido_pagos','usuarios','secciones','categorias_meta','configuracion','design_config','cupones','cupon_productos','promociones','listas_precio','precios_fijos','ordenes_compra','orden_compra_items','cuenta_corriente','leads','carritos_abandonados','badges','barras_texto','menu_items','metodos_pago','metodos_envio_custom','config_envio','notificaciones_stock','paginas_info','popups','redes_sociales','slider_banners','contactos','favoritos','historial_precios','producto_imagenes','variantes'];
    for(const t of tablas){ await client.query(`DELETE FROM ${t} WHERE tenant_id=$1`, [tid]).catch(()=>{}); }
    await client.query('DELETE FROM tenants WHERE id=$1', [tid]);
    await client.query('COMMIT');
    tenantCache.clear(); tenantDataCache.clear();
    res.json({ok:true});
  }catch(e){ await client.query('ROLLBACK').catch(()=>{}); res.status(500).json({error:e.message}); }
  finally{ client.release(); }
});


// Dolar blue
app.get('/api/dolar-blue', async (req,res)=>{
  try{
    if(dolarBlueCache.valor && Date.now()-dolarBlueCache.ts<15*60*1000) return res.json({venta:dolarBlueCache.valor});
    const r = await fetch('https://dolarapi.com/v1/dolares/blue');
    if(r.ok){ const d=await r.json(); dolarBlueCache={valor:d.venta, ts:Date.now()}; return res.json({venta:d.venta}); }
    const {rows}=await pool.query("SELECT valor FROM configuracion WHERE clave='dolar_blue'");
    res.json({venta: rows[0]?.valor?Number(rows[0].valor):null});
  }catch(e){ const {rows}=await pool.query("SELECT valor FROM configuracion WHERE clave='dolar_blue'").catch(()=>({rows:[]})); res.json({venta: rows[0]?.valor?Number(rows[0].valor):null}); }
});

// Maintenance
app.get('/api/maintenance-status', async (req,res)=>{
  try{ const {rows}=await pool.query("SELECT clave,valor FROM configuracion WHERE tenant_id=$1 AND clave IN ('mantenimiento_activo','mantenimiento_mensaje','mantenimiento_countdown')", [req.tenantId]); const cfg={}; rows.forEach(r=>cfg[r.clave]=r.valor); res.json({activo:cfg.mantenimiento_activo==='true', mensaje:cfg.mantenimiento_mensaje||'', countdown:cfg.mantenimiento_countdown||''}); }catch{ res.json({activo:false}); }
});
app.post('/api/maintenance-mode', authPerm('config'), async (req,res)=>{
  try{ const {activo,mensaje,countdown}=req.body; await pool.query("INSERT INTO configuracion (tenant_id,clave,valor) VALUES ($2,'mantenimiento_activo',$1) ON CONFLICT (tenant_id,clave) DO UPDATE SET valor=$1", [activo?'true':'false', req.tenantId]); await pool.query("INSERT INTO configuracion (tenant_id,clave,valor) VALUES ($2,'mantenimiento_mensaje',$1) ON CONFLICT (tenant_id,clave) DO UPDATE SET valor=$1", [mensaje||'', req.tenantId]); await pool.query("INSERT INTO configuracion (tenant_id,clave,valor) VALUES ($2,'mantenimiento_countdown',$1) ON CONFLICT (tenant_id,clave) DO UPDATE SET valor=$1", [countdown||'', req.tenantId]); res.json({ok:true}); }catch(e){ res.status(500).json({error:e.message}); }
});

// === AUTH ===
let resend=null;
if(process.env.RESEND_API_KEY){ const {Resend}=require('resend'); resend=new Resend(process.env.RESEND_API_KEY); console.log('📧 Resend OK'); }

// Notificar al admin por email cuando entra una venta online
async function notificarVentaAdmin(pedidos, comprador){
  try{
    if(!resend || !pedidos || !pedidos.length){ console.log('[venta-mail] sin resend o sin pedidos'); return; }
    const tid = pedidos[0].tenant_id || 1;
    // Email destino: config 'email_ventas' del tenant → RESEND_TO → primer admin del tenant
    const {rows:cfg}=await pool.query("SELECT valor FROM configuracion WHERE clave='email_ventas' AND tenant_id=$1", [tid]).catch(()=>({rows:[]}));
    let destino = (cfg[0] && cfg[0].valor) || process.env.RESEND_TO || '';
    if(!destino){
      const {rows:adm}=await pool.query("SELECT email FROM usuarios WHERE rol='admin' AND email<>'' AND tenant_id=$1 ORDER BY id LIMIT 1", [tid]).catch(()=>({rows:[]}));
      destino = adm[0] && adm[0].email;
    }
    if(!destino){ console.log('[venta-mail] no hay email destino (configurá email_ventas en General)'); return; }
    const {rows:dc}=await pool.query("SELECT valor FROM design_config WHERE clave='nombre_tienda' AND tenant_id=$1", [tid]).catch(()=>({rows:[]}));
    const tienda = (dc[0] && dc[0].valor) || 'Tu tienda';
    const baseUrl = process.env.PUBLIC_URL || process.env.FRONTEND_URL || '';
    const total = pedidos.reduce((s,p)=>s+Number(p.total||0),0);
    const nombreCliente = (comprador && (comprador.nombre||comprador.usuario)) || 'Cliente';
    const filas = pedidos.map(p=>{
      const link = baseUrl ? `${baseUrl}/?pedido=${p.id}` : '';
      const num = String(p.id).padStart(4,'0');
      return `<tr><td style="padding:8px 12px;border-bottom:1px solid #eee">#${num}</td><td style="padding:8px 12px;border-bottom:1px solid #eee">$${Number(p.total||0).toLocaleString('es-AR')}</td><td style="padding:8px 12px;border-bottom:1px solid #eee">${link?`<a href="${link}">Ver orden →</a>`:''}</td></tr>`;
    }).join('');
    const html = `
      <div style="font-family:system-ui,sans-serif;max-width:520px;margin:0 auto">
        <h2 style="color:#16a34a">🛒 Nueva venta en ${tienda}</h2>
        <p>Cliente: <strong>${nombreCliente}</strong></p>
        <p>Total: <strong style="font-size:20px">$${total.toLocaleString('es-AR')}</strong></p>
        <table style="width:100%;border-collapse:collapse;margin-top:12px">
          <thead><tr><th style="text-align:left;padding:8px 12px;border-bottom:2px solid #333">Pedido</th><th style="text-align:left;padding:8px 12px;border-bottom:2px solid #333">Total</th><th style="text-align:left;padding:8px 12px;border-bottom:2px solid #333"></th></tr></thead>
          <tbody>${filas}</tbody>
        </table>
        <p style="color:#888;font-size:12px;margin-top:20px">Entró recién a tu tienda. Ingresá al panel para gestionarla.</p>
      </div>`;
    const r = await resend.emails.send({
      from: process.env.RESEND_FROM || 'onboarding@resend.dev',
      to: destino,
      subject: `🛒 Nueva venta $${total.toLocaleString('es-AR')} — ${tienda}`,
      html,
    });
    if(r && r.error){ console.log('[venta-mail] Resend error:', JSON.stringify(r.error)); }
    else { console.log('[venta-mail] enviado a', destino); }
  }catch(e){ console.log('[venta-mail] excepción:', e.message); }
}
const loginAttempts={};
app.post('/api/login', async (req,res)=>{
  try{
    const {usuario,password,otp_code}=req.body;
    if(!usuario||!password) return res.status(400).json({error:'Usuario y contraseña requeridos'});
    const ip=req.ip; const key=`${ip}_${usuario.toLowerCase()}`;
    if(loginAttempts[key] && loginAttempts[key].count>=5 && Date.now()-loginAttempts[key].last<15*60*1000) return res.status(429).json({error:'Bloqueado 15min'});
    const {rows}=await pool.query('SELECT * FROM usuarios WHERE LOWER(usuario)=LOWER($1) AND activo=true AND tenant_id=$2', [usuario, req.tenantId]);
    if(!rows[0]){ const {rows:pend}=await pool.query('SELECT * FROM usuarios WHERE LOWER(usuario)=LOWER($1) AND aprobado=false AND tenant_id=$2', [usuario, req.tenantId]); if(pend[0]) return res.status(403).json({error:'Pendiente aprobación'}); loginAttempts[key]={count:(loginAttempts[key]?.count||0)+1, last:Date.now()}; return res.status(401).json({error:'Usuario o contraseña incorrectos'}); }
    const valid=await bcrypt.compare(password, rows[0].password);
    if(!valid){ loginAttempts[key]={count:(loginAttempts[key]?.count||0)+1, last:Date.now()}; return res.status(401).json({error:'Usuario o contraseña incorrectos'}); }
    if(rows[0].otp_activo && resend){
      if(!otp_code){
        const code=Math.floor(100000+Math.random()*900000).toString();
        await pool.query('INSERT INTO otp_codes (usuario_id,codigo,expira) VALUES ($1,$2,NOW()+INTERVAL \'10 minutes\')', [rows[0].id, code]);
        if(rows[0].email) await resend.emails.send({from:process.env.RESEND_FROM||'noreply@resend.dev', to:rows[0].email, subject:'Código verificación', html:`<h2>Código: <strong>${code}</strong></h2>`}).catch(()=>{});
        return res.json({requires_otp:true, message:'Código enviado'});
      }
      const {rows:otps}=await pool.query('SELECT * FROM otp_codes WHERE usuario_id=$1 AND codigo=$2 AND expira>NOW() AND usado=false ORDER BY id DESC LIMIT 1', [rows[0].id, otp_code]);
      if(!otps[0]) return res.status(401).json({error:'Código incorrecto o expirado'});
      await pool.query('UPDATE otp_codes SET usado=true WHERE id=$1', [otps[0].id]);
    }
    delete loginAttempts[key];
    const token=jwt.sign({id:rows[0].id, rol:rows[0].rol, usuario:rows[0].usuario, tenant_id:rows[0].tenant_id||1, es_owner:rows[0].es_owner||false}, JWT_SECRET, {expiresIn:'7d'});
    res.json({token, user:{...rows[0], password:undefined}});
  }catch(e){ res.status(500).json({error:e.message}); }
});
app.post('/api/logout', auth(), async (req,res)=>{
  try{ const decoded=jwt.decode(req._token); const expira=new Date(decoded.exp*1000); await pool.query('INSERT INTO tokens_revocados (token_hash,expira) VALUES ($1,$2) ON CONFLICT DO NOTHING', [hashToken(req._token), expira]); await pool.query('DELETE FROM tokens_revocados WHERE expira<NOW()').catch(()=>{}); res.json({ok:true}); }catch(e){ res.status(500).json({error:e.message}); }
});
app.post('/api/refresh-token', auth(), async (req,res)=>{
  try{ const {rows}=await pool.query('SELECT id,rol,usuario,activo,tenant_id,es_owner FROM usuarios WHERE id=$1', [req.user.id]); if(!rows[0]||!rows[0].activo) return res.status(401).json({error:'Cuenta desactivada'}); const decoded=jwt.decode(req._token); await pool.query('INSERT INTO tokens_revocados (token_hash,expira) VALUES ($1,$2) ON CONFLICT DO NOTHING', [hashToken(req._token), new Date(decoded.exp*1000)]); const newToken=jwt.sign({id:rows[0].id, rol:rows[0].rol, usuario:rows[0].usuario, tenant_id:rows[0].tenant_id||1, es_owner:rows[0].es_owner||false}, JWT_SECRET, {expiresIn:'7d'}); res.json({token:newToken}); }catch(e){ res.status(500).json({error:e.message}); }
});
app.put('/api/me/otp', auth(), async (req,res)=>{ try{ const {activo}=req.body; await pool.query('UPDATE usuarios SET otp_activo=$1 WHERE id=$2 AND tenant_id=$3', [activo, req.user.id, req.tenantId]); res.json({ok:true}); }catch(e){ res.status(500).json({error:e.message}); } });

// Password reset mejorado
app.post('/api/forgot-password', async (req,res)=>{
  try{
    const {usuario, email} = req.body;
    if(!usuario && !email) return res.status(400).json({error:'Usuario o email requerido'});
    const {rows} = await pool.query('SELECT * FROM usuarios WHERE (LOWER(usuario)=LOWER($1) OR LOWER(email)=LOWER($1)) AND tenant_id=$2 LIMIT 1', [usuario||email, req.tenantId]);
    if(!rows[0]) return res.status(404).json({error:'Usuario no encontrado'});
    const codigo = 'KICKS-'+crypto.randomBytes(3).toString('hex').toUpperCase(); // ej KICKS-A3F9B2
    await pool.query('UPDATE usuarios SET reset_codigo=$1, reset_expira=NOW()+INTERVAL \'24 hours\' WHERE id=$2', [codigo, rows[0].id]);
    // Enviar por mail si hay resend
    if(resend && rows[0].email){
      await resend.emails.send({from:process.env.RESEND_FROM||'noreply@resend.dev', to:rows[0].email, subject:'Recuperar contraseña', html:`<h2>Tu código: ${codigo}</h2><p>Expira en 24hs. Usalo para entrar y luego cambiala en Mi Cuenta.</p>`}).catch(()=>{});
    }
    res.json({ok:true, codigo, telefono: rows[0].telefono, mensaje:'Código generado. Si tenés email configurado te llega por mail, sino usalo directo.'});
  }catch(e){ res.status(500).json({error:e.message}); }
});
app.post('/api/reset-password', async (req,res)=>{
  try{
    const {codigo, nueva_password} = req.body;
    if(!codigo||!nueva_password) return res.status(400).json({error:'Código y nueva contraseña requeridos'});
    const pwError=validatePassword(nueva_password);
    if(pwError) return res.status(400).json({error:pwError});
    const {rows}=await pool.query('SELECT * FROM usuarios WHERE reset_codigo=$1 AND reset_expira>NOW() AND tenant_id=$2', [codigo, req.tenantId]);
    if(!rows[0]) return res.status(400).json({error:'Código inválido o expirado'});
    const hash=await bcrypt.hash(nueva_password,12);
    await pool.query('UPDATE usuarios SET password=$1, reset_codigo=\'\', reset_expira=NULL WHERE id=$2', [hash, rows[0].id]);
    res.json({ok:true});
  }catch(e){ res.status(500).json({error:e.message}); }
});

app.post('/api/register', async (req,res)=>{
  try{
    const {nombre,usuario,password,telefono,email,direccion,nombre_fantasia}=req.body;
    if(!usuario||usuario.length<3) return res.status(400).json({error:'Min 3 caracteres'});
    const pwError=validatePassword(password); if(pwError) return res.status(400).json({error:pwError});
    const hash=await bcrypt.hash(password,12);
    const {rows:cfgAprob}=await pool.query("SELECT valor FROM configuracion WHERE tenant_id=$1 AND clave='registro_requiere_aprobacion'", [req.tenantId]);
    const requiereAprob = cfgAprob[0] && cfgAprob[0].valor==='true';
    const aprobado = !requiereAprob; // por defecto (sin config) el registro entra DIRECTO
    const {rows}=await pool.query('INSERT INTO usuarios (tenant_id,nombre,usuario,password,telefono,email,direccion,nombre_fantasia,aprobado,activo) VALUES ($8,$1,$2,$3,$4,$5,$6,$7,$9,$9) RETURNING id,nombre,usuario,telefono,email,aprobado,activo', [nombre,usuario,hash,telefono||'',email||'',direccion||'',nombre_fantasia||'', req.tenantId, aprobado]);
    res.json(rows[0]);
  }catch(e){ res.status(400).json({error:e.message.includes('duplicate')?'Usuario ya existe':e.message}); }
});
app.get('/api/me', auth(), async (req,res)=>{ try{ const {rows}=await pool.query('SELECT * FROM usuarios WHERE id=$1 AND tenant_id=$2', [req.user.id, req.tenantId]); res.json({...rows[0], password:undefined}); }catch(e){ res.status(500).json({error:e.message}); } });
// Crear cliente rápido desde el panel (venta de mostrador). Genera usuario auto si no se pasa.
app.post('/api/usuarios/rapido', authPerm('usuarios'), async (req,res)=>{
  try{
    const {nombre,telefono,email,direccion}=req.body;
    if(!nombre) return res.status(400).json({error:'Falta el nombre'});
    // usuario auto: nombre sin espacios + numero corto, único
    let base=(nombre||'cliente').toLowerCase().replace(/[^a-z0-9]/g,'').slice(0,12)||'cliente';
    let usuario=base+Math.floor(Math.random()*9000+1000);
    // password simple legible para darle al cliente (ej: "tienda4821"). Puede cambiarla después.
    const passPlano='cliente'+Math.floor(Math.random()*9000+1000);
    const hash=await bcrypt.hash(passPlano,10);
    const {rows}=await pool.query('INSERT INTO usuarios (tenant_id,nombre,usuario,password,telefono,email,direccion,aprobado,activo) VALUES ($7,$1,$2,$3,$4,$5,$6,true,true) RETURNING id,nombre,usuario,telefono,email', [nombre,usuario,hash,telefono||'',email||'',direccion||'', req.tenantId]);
    // Devolvemos la password en texto SOLO acá (para que el admin la imprima/pase al cliente). No se guarda en texto.
    res.json({...rows[0], password_temporal:passPlano});
  }catch(e){ res.status(400).json({error:e.message.includes('duplicate')?'Ese usuario ya existe, probá otro nombre':e.message}); }
});
app.put('/api/me', auth(), async (req,res)=>{
  try{
    const {nombre,telefono,email,direccion,nombre_fantasia,password}=req.body;
    if(password){ const hash=await bcrypt.hash(password,10); await pool.query('UPDATE usuarios SET nombre=$1,telefono=$2,email=$3,direccion=$4,nombre_fantasia=$5,password=$6 WHERE id=$7 AND tenant_id=$8', [nombre,telefono,email,direccion,nombre_fantasia||'',hash,req.user.id, req.tenantId]); }
    else{ await pool.query('UPDATE usuarios SET nombre=$1,telefono=$2,email=$3,direccion=$4,nombre_fantasia=$5 WHERE id=$6 AND tenant_id=$7', [nombre,telefono,email,direccion,nombre_fantasia||'',req.user.id, req.tenantId]); }
    const {rows}=await pool.query('SELECT * FROM usuarios WHERE id=$1 AND tenant_id=$2', [req.user.id, req.tenantId]);
    res.json({...rows[0], password:undefined});
  }catch(e){ res.status(500).json({error:e.message}); }
});

// CONFIG
app.get('/api/config', async (req,res)=>{ try{ const {rows}=await pool.query('SELECT * FROM configuracion WHERE tenant_id=$1', [req.tenantId]); const cfg={}; rows.forEach(r=>cfg[r.clave]=r.valor); res.json(cfg); }catch(e){ res.status(500).json({error:e.message}); } });
// Plan y funciones habilitadas del tenant actual (para que el frontend muestre/oculte)
app.get('/api/mi-plan', async (req,res)=>{
  try{ const d=await getTenantData(req.tenantId); res.json({ plan:d.plan, estado:d.estado, features:d.features, dias_restantes:d.dias_restantes }); }
  catch(e){ res.status(500).json({error:e.message}); }
});
app.put('/api/config', authPerm('config'), async (req,res)=>{ try{ for(const [k,v] of Object.entries(req.body)){ await pool.query("INSERT INTO configuracion (tenant_id,clave,valor) VALUES ($1,$2,$3) ON CONFLICT (tenant_id,clave) DO UPDATE SET valor=$3", [req.tenantId,k,v]); } res.json({ok:true}); }catch(e){ res.status(500).json({error:e.message}); } });

// LISTAS
app.get('/api/listas', async (req,res)=>{ try{ const {rows}=await pool.query('SELECT * FROM listas_precio WHERE tenant_id=$1 ORDER BY multiplicador', [req.tenantId]); res.json(rows); }catch(e){ res.status(500).json({error:e.message}); } });
app.put('/api/listas', authPerm('listas'), async (req,res)=>{ try{ const {listas}=req.body; for(const l of listas){ await pool.query('INSERT INTO listas_precio (id,nombre,multiplicador,modo,color,compra_minima,promo_msg,tenant_id) VALUES ($1,$2,$3,$4,$5,$6,$7,$8) ON CONFLICT (id) DO UPDATE SET nombre=$2,multiplicador=$3,modo=$4,color=$5,compra_minima=$6,promo_msg=$7', [l.id,l.nombre,l.multiplicador,l.modo||'porcentaje',l.color||'#2563eb',l.compra_minima||0,l.promo_msg||'', req.tenantId]); } res.json({ok:true}); }catch(e){ res.status(500).json({error:e.message}); } });
app.post('/api/listas', authPerm('listas'), async (req,res)=>{ try{ const l=req.body; const {rows}=await pool.query('INSERT INTO listas_precio (id,nombre,multiplicador,modo,color,compra_minima,promo_msg,tenant_id) VALUES ($1,$2,$3,$4,$5,$6,$7,$8) RETURNING *', [l.id,l.nombre,l.multiplicador||1,l.modo||'porcentaje',l.color||'#2563eb',l.compra_minima||0,l.promo_msg||'', req.tenantId]); res.json(rows[0]); }catch(e){ res.status(400).json({error:e.message}); } });
app.put('/api/listas/:id', authPerm('listas'), async (req,res)=>{ try{ const l=req.body; await pool.query('UPDATE listas_precio SET nombre=$1,multiplicador=$2,modo=$3,color=$4,compra_minima=$5,promo_msg=$6 WHERE id=$7 AND tenant_id=$8', [l.nombre,l.multiplicador,l.modo,l.color,l.compra_minima||0,l.promo_msg||'',req.params.id, req.tenantId]); res.json({ok:true}); }catch(e){ res.status(500).json({error:e.message}); } });
app.delete('/api/listas/:id', authPerm('listas'), async (req,res)=>{ try{ await pool.query('DELETE FROM listas_precio WHERE id=$1 AND tenant_id=$2', [req.params.id, req.tenantId]); res.json({ok:true}); }catch(e){ res.status(500).json({error:e.message}); } });

// SECCIONES V4 con ignorar_stock
app.get('/api/secciones', async (req,res)=>{ try{ const {rows}=await pool.query('SELECT * FROM secciones WHERE tenant_id=$1 ORDER BY orden, id', [req.tenantId]); res.json(rows); }catch(e){ res.status(500).json({error:e.message}); } });
app.get('/api/secciones/:id', async (req,res)=>{ try{ const {rows}=await pool.query('SELECT * FROM secciones WHERE id=$1 AND tenant_id=$2', [req.params.id, req.tenantId]); if(!rows[0]) return res.status(404).json({error:'No encontrada'}); res.json(rows[0]); }catch(e){ res.status(500).json({error:e.message}); } });
app.put('/api/secciones/:id', authPerm('config'), async (req,res)=>{
  try{
    const {nombre,slug,descripcion,imagen,requiere_aprobacion,visible,orden,ignorar_stock,cp_origen,permitir_sin_stock}=req.body;
    await pool.query('UPDATE secciones SET nombre=$1,slug=$2,descripcion=$3,imagen=$4,requiere_aprobacion=$5,visible=$6,orden=$7,ignorar_stock=$8,cp_origen=$9,permitir_sin_stock=$10 WHERE id=$11 AND tenant_id=$12', [nombre,slug,descripcion,imagen,requiere_aprobacion,visible,orden||0,ignorar_stock||false,cp_origen||'1888',permitir_sin_stock||false,req.params.id, req.tenantId]);
    res.json({ok:true});
  }catch(e){ res.status(500).json({error:e.message}); }
});
app.post('/api/secciones', authPerm('config'), async (req,res)=>{
  try{
    const {nombre,slug,descripcion,imagen,requiere_aprobacion,ignorar_stock,cp_origen}=req.body;
    const {rows}=await pool.query('INSERT INTO secciones (tenant_id,nombre,slug,descripcion,imagen,requiere_aprobacion,ignorar_stock,cp_origen) VALUES ($8,$1,$2,$3,$4,$5,$6,$7) RETURNING *', [nombre,slug,descripcion||'',imagen||'',requiere_aprobacion||false,ignorar_stock||false,cp_origen||'1888', req.tenantId]);
    res.json(rows[0]);
  }catch(e){ res.status(400).json({error:e.message}); }
});
// Productos con stock bajo el mínimo (para alertas en dashboard)
app.get('/api/stock-bajo', authPerm('productos'), async (req,res)=>{
  try{
    const {rows}=await pool.query(`SELECT p.id, p.nombre, p.modelo, p.categoria, p.stock, p.stock_minimo, s.nombre as seccion_nombre
      FROM productos p LEFT JOIN secciones s ON p.seccion_id=s.id
      WHERE p.tenant_id=$1 AND p.stock_minimo>0 AND p.stock<=p.stock_minimo AND p.permitir_sin_stock=false AND p.es_digital=false
      ORDER BY p.stock ASC LIMIT 100`, [req.tenantId]);
    res.json(rows);
  }catch(e){ res.status(500).json({error:e.message}); }
});
// Contar productos/pedidos de una sección (para borrado seguro)
app.get('/api/secciones/:id/stats', authPerm('config'), async (req,res)=>{
  try{
    const {rows:prod}=await pool.query('SELECT COUNT(*)::int as n FROM productos WHERE seccion_id=$1 AND tenant_id=$2', [req.params.id, req.tenantId]);
    const {rows:ped}=await pool.query('SELECT COUNT(*)::int as n FROM pedidos WHERE seccion_id=$1 AND tenant_id=$2', [req.params.id, req.tenantId]);
    res.json({ productos: prod[0].n, pedidos: ped[0].n });
  }catch(e){ res.status(500).json({error:e.message}); }
});
// Borrado SEGURO: opción mover_a (mueve productos/pedidos a otra sección) o borrar_productos
app.delete('/api/secciones/:id', authPerm('config'), async (req,res)=>{
  try{
    const {mover_a, borrar_productos}=req.query;
    const {rows:total}=await pool.query('SELECT COUNT(*)::int as n FROM secciones WHERE tenant_id=$1', [req.tenantId]);
    if(total[0].n<=1) return res.status(400).json({error:'No podés eliminar la única tienda que queda'});
    if(mover_a){
      await pool.query('UPDATE productos SET seccion_id=$1 WHERE seccion_id=$2 AND tenant_id=$3', [mover_a, req.params.id, req.tenantId]);
      await pool.query('UPDATE pedidos SET seccion_id=$1 WHERE seccion_id=$2 AND tenant_id=$3', [mover_a, req.params.id, req.tenantId]);
    } else if(borrar_productos==='true'){
      await pool.query('DELETE FROM productos WHERE seccion_id=$1 AND tenant_id=$2', [req.params.id, req.tenantId]);
      // pedidos quedan pero sin sección (histórico)
      await pool.query('UPDATE pedidos SET seccion_id=NULL WHERE seccion_id=$1 AND tenant_id=$2', [req.params.id, req.tenantId]);
    } else {
      // Sin instrucción: solo permitir si está vacía
      const {rows:p}=await pool.query('SELECT COUNT(*)::int as n FROM productos WHERE seccion_id=$1 AND tenant_id=$2', [req.params.id, req.tenantId]);
      if(p[0].n>0) return res.status(400).json({error:'La tienda tiene productos. Elegí mover o borrar.'});
    }
    await pool.query('DELETE FROM secciones WHERE id=$1 AND tenant_id=$2', [req.params.id, req.tenantId]);
    res.json({ok:true});
  }catch(e){ res.status(500).json({error:e.message}); }
});

// UPLOAD
const uploadToCloudinary = (buffer, folder='productos')=> new Promise((resolve,reject)=>{
  const stream=cloudinary.uploader.upload_stream({folder, resource_type:'image', quality:'auto', fetch_format:'auto'}, (err,result)=>{ if(err) reject(err); else resolve(result); });
  stream.end(buffer);
});
app.post('/api/upload', authPerm('config'), upload.single('imagen'), async (req,res)=>{
  try{
    if(!req.file) return res.status(400).json({error:'No file'});
    if(useCloudinary){
      try{ const r=await uploadToCloudinary(req.file.buffer); return res.json({url:r.secure_url}); }
      catch(ce){ console.error('Cloudinary falló, guardo en disco:', ce.message); }
    }
    const ext=path.extname(req.file.originalname)||'.jpg';
    const name=uuidv4()+ext;
    fs.writeFileSync(path.join(uploadsDir,name), req.file.buffer);
    return res.json({url:`/uploads/${name}`});
  }catch(e){ res.status(500).json({error:e.message}); }
});
app.post('/api/upload-base64', authPerm('config'), async (req,res)=>{
  try{
    const {data, filename} = req.body;
    if(!data) return res.status(400).json({error:'No data'});
    const matches=data.match(/^data:(.+);base64,(.+)$/);
    if(!matches) return res.status(400).json({error:'Invalid base64'});
    const buffer=Buffer.from(matches[2],'base64');
    if(useCloudinary){
      const r=await uploadToCloudinary(buffer);
      return res.json({url:r.secure_url});
    }else{
      const name=(filename||uuidv4())+'.jpg';
      fs.writeFileSync(path.join(uploadsDir,name), buffer);
      return res.json({url:`/uploads/${name}`});
    }
  }catch(e){ res.status(500).json({error:e.message}); }
});

// PRODUCTOS V4 con permitir_sin_stock y es_digital
app.get('/api/productos/relacionados/:id', async (req,res)=>{
  try{
    const {rows:base}=await pool.query('SELECT categoria, seccion_id, marca FROM productos WHERE id=$1 AND tenant_id=$2', [req.params.id, req.tenantId]);
    if(!base[0]) return res.json([]);
    const b=base[0];
    // Primero misma categoría/marca en la sección
    let {rows}=await pool.query(`SELECT p.*, s.nombre as seccion_nombre, s.color as seccion_color FROM productos p LEFT JOIN secciones s ON p.seccion_id=s.id
      WHERE p.visible=true AND p.tenant_id=$5 AND p.id!=$1 AND p.seccion_id=$2 AND (p.categoria=$3 OR ($4<>'' AND p.marca=$4))
      ORDER BY (p.categoria=$3) DESC, RANDOM() LIMIT 8`, [req.params.id, b.seccion_id, b.categoria||'', b.marca||'', req.tenantId]);
    // Si no hay suficientes, completar con otros de la misma sección
    if(rows.length < 4){
      const ids=[req.params.id, ...rows.map(r=>r.id)];
      const {rows:extra}=await pool.query(`SELECT p.*, s.nombre as seccion_nombre, s.color as seccion_color FROM productos p LEFT JOIN secciones s ON p.seccion_id=s.id
        WHERE p.visible=true AND p.tenant_id=$4 AND p.seccion_id=$1 AND p.id != ALL($2::int[]) ORDER BY RANDOM() LIMIT $3`, [b.seccion_id, ids, 8-rows.length, req.tenantId]);
      rows=[...rows, ...extra];
    }
    res.json(rows);
  }catch(e){ res.status(500).json({error:e.message}); }
});
// Recibir la preventa: pasa el cupo al stock físico, descuenta lo reservado, desactiva preventa
app.post('/api/productos/:id/recibir-preventa', authPerm('productos'), async (req,res)=>{
  try{
    const {rows}=await pool.query('SELECT stock, preventa_cupo, preventa_reservado FROM productos WHERE id=$1 AND tenant_id=$2', [req.params.id, req.tenantId]);
    if(!rows[0]) return res.status(404).json({error:'Producto no encontrado'});
    const cupo=Number(rows[0].preventa_cupo)||0;
    // RESERVADO REAL: cuenta las unidades pedidas de este producto en pedidos activos (no cancelados)
    const {rows:resv}=await pool.query(`SELECT COALESCE(SUM(pi.cantidad),0)::int as reservado
      FROM pedido_items pi JOIN pedidos p ON pi.pedido_id=p.id
      WHERE pi.producto_id=$1 AND p.tipo='pedido' AND LOWER(COALESCE(p.estado,'')) NOT IN ('cancelado','anulado','rechazado')`, [req.params.id]);
    const reservado=Number(resv[0].reservado)||0;
    const cantidadRecibida = req.body.cantidad!==undefined ? Number(req.body.cantidad) : cupo;
    // stock nuevo = stock actual + (recibido - reservado). Lo reservado ya se vendió.
    const aStock = Math.max(0, cantidadRecibida - reservado);
    await pool.query('UPDATE productos SET stock = stock + $1, es_preventa=false, preventa_cupo=0, preventa_reservado=0, preventa_descuento_pct=0 WHERE id=$2', [aStock, req.params.id]);
    res.json({ ok:true, sumado_a_stock: aStock, reservas_tomadas: reservado, recibido: cantidadRecibida });
  }catch(e){ res.status(500).json({error:e.message}); }
});
// Consultar reservado real (para mostrar en el form antes de recibir)
app.get('/api/productos/:id/reservado-real', authPerm('productos'), async (req,res)=>{
  try{
    const {rows}=await pool.query(`SELECT COALESCE(SUM(pi.cantidad),0)::int as reservado
      FROM pedido_items pi JOIN pedidos p ON pi.pedido_id=p.id
      WHERE pi.producto_id=$1 AND p.tipo='pedido' AND LOWER(COALESCE(p.estado,'')) NOT IN ('cancelado','anulado','rechazado')`, [req.params.id]);
    res.json({ reservado: Number(rows[0].reservado)||0 });
  }catch(e){ res.status(500).json({error:e.message}); }
});
app.get('/api/productos/preventa', async (req,res)=>{
  try{
    const {seccion_id}=req.query;
    let q='SELECT p.*, s.nombre as seccion_nombre, s.color as seccion_color FROM productos p LEFT JOIN secciones s ON p.seccion_id=s.id WHERE p.visible=true AND p.es_preventa=true AND p.tenant_id=$1';
    const params=[req.tenantId];
    if(seccion_id && seccion_id!=='all'){ params.push(seccion_id); q+=` AND p.seccion_id=$${params.length}`; }
    q+=' ORDER BY p.preventa_fecha ASC NULLS LAST, p.created_at DESC LIMIT 30';
    const {rows}=await pool.query(q, params);
    res.json(rows);
  }catch(e){ res.status(500).json({error:e.message}); }
});
app.get('/api/productos/novedades', async (req,res)=>{
  try{
    const {seccion_id, limit}=req.query;
    let q='SELECT p.*, s.nombre as seccion_nombre, s.color as seccion_color FROM productos p LEFT JOIN secciones s ON p.seccion_id=s.id WHERE p.visible=true AND p.tenant_id=$1';
    const params=[req.tenantId];
    if(seccion_id && seccion_id!=='all'){ params.push(seccion_id); q+=` AND p.seccion_id=$${params.length}`; }
    q+=` ORDER BY p.created_at DESC LIMIT ${Math.min(Number(limit)||12, 30)}`;
    const {rows}=await pool.query(q, params);
    res.json(rows);
  }catch(e){ res.status(500).json({error:e.message}); }
});
app.get('/api/productos', optionalAuth, async (req,res)=>{
  try{
    const {q,categoria,page=1,limit=50,seccion_id,marca}=req.query;
    const esAdminReq = req.user && ['admin', 'subadmin'].includes(req.user.rol);
    const incluirOcultos = esAdminReq && (req.query.incluir_ocultos === '1' || req.query.incluir_ocultos === 'true');
    let where = [`tenant_id=$1`]; if (!incluirOcultos) where.push('visible=true');
    const params = [req.tenantId]; let pi = 2;
    if(q){
      const toks = String(q).trim().split(/\s+/).filter(Boolean).slice(0,8);
      const campos = `(coalesce(nombre,'')||' '||coalesce(modelo,'')||' '||coalesce(categoria,'')||' '||coalesce(marca,'')||' '||coalesce(sku,'')||' '||coalesce(compatibilidad,'')||' '||coalesce(descripcion,''))`;
      for(const tk of toks){ where.push(`${campos} ILIKE $${pi}`); params.push(`%${tk}%`); pi++; }
    }
    if(categoria){ where.push(`categoria=$${pi}`); params.push(categoria); pi++; }
    if(seccion_id){ where.push(`seccion_id=$${pi}`); params.push(seccion_id); pi++; }
    if(marca){ where.push(`marca ILIKE $${pi}`); params.push(`%${marca}%`); pi++; }
    const offset=(parseInt(page)-1)*parseInt(limit);
    const countQ=`SELECT COUNT(*) FROM productos WHERE ${where.join(' AND ')}`;
    const {rows:cRows}=await pool.query(countQ, params);
    const total=parseInt(cRows[0].count);
    const query=`SELECT *, (SELECT MIN(CASE WHEN v.precio_oferta>0 AND v.precio_oferta<v.precio THEN v.precio_oferta ELSE v.precio END) FROM variantes v WHERE v.producto_id=productos.id AND v.tenant_id=productos.tenant_id AND v.precio>0) AS precio_desde, (SELECT v.moneda FROM variantes v WHERE v.producto_id=productos.id AND v.tenant_id=productos.tenant_id AND v.precio>0 ORDER BY (CASE WHEN v.precio_oferta>0 AND v.precio_oferta<v.precio THEN v.precio_oferta ELSE v.precio END) ASC LIMIT 1) AS moneda_desde FROM productos WHERE ${where.join(' AND ')} ORDER BY created_at DESC LIMIT $${pi} OFFSET $${pi+1}`;
    const {rows}=await pool.query(query, [...params, parseInt(limit), offset]);
    // hide price mayorista sin login
    let result=rows;
    if(!req.user){
      const {rows:secs}=await pool.query('SELECT id FROM secciones WHERE slug=$1 AND tenant_id=$2', ['mayorista', req.tenantId]).catch(()=>({rows:[]}));
      const mayId=secs[0]?.id;
      if(mayId) result=rows.map(r=> r.seccion_id==mayId ? {...r, precio_base:0, precio_oferta:0} : r);
    }
    res.json({productos:result, total, page:parseInt(page), totalPages:Math.ceil(total/parseInt(limit))});
  }catch(e){ res.status(500).json({error:e.message}); }
});
app.get('/api/categorias', async (req,res)=>{ try{ const {seccion_id}=req.query; let q='SELECT DISTINCT categoria FROM productos WHERE visible=true AND tenant_id=$1'; const params=[req.tenantId]; if(seccion_id){ q+=' AND seccion_id=$2'; params.push(seccion_id); } q+=' ORDER BY categoria'; const {rows}=await pool.query(q, params); res.json(rows.map(r=>r.categoria).filter(Boolean)); }catch(e){ res.status(500).json({error:e.message}); } });

// Categorías con metadata (orden, visible, conteo) — para el ABM del panel
app.get('/api/categorias/admin', authPerm('productos'), async (req,res)=>{
  try{
    const {seccion_id}=req.query;
    let q='SELECT categoria, COUNT(*)::int as cantidad FROM productos WHERE tenant_id=$1'; const params=[req.tenantId];
    if(seccion_id && seccion_id!=='all'){ q+=' AND seccion_id=$2'; params.push(seccion_id); }
    q+=' GROUP BY categoria ORDER BY categoria';
    const {rows:cats}=await pool.query(q, params);
    const {rows:meta}=await pool.query('SELECT * FROM categorias_meta WHERE tenant_id=$1', [req.tenantId]).catch(()=>({rows:[]}));
    const metaMap={}; meta.forEach(m=>metaMap[m.categoria]=m);
    const catSet=new Set(cats.map(c=>c.categoria).filter(Boolean));
    const result=cats.filter(c=>c.categoria).map(c=>({ nombre:c.categoria, cantidad:c.cantidad, orden:(metaMap[c.categoria]?.orden??999), visible:(metaMap[c.categoria]?.visible!==false) }));
    // Categorías creadas manualmente (en meta) que todavía no tienen productos
    meta.forEach(m=>{ if(!catSet.has(m.categoria)) result.push({ nombre:m.categoria, cantidad:0, orden:(m.orden??999), visible:(m.visible!==false) }); });
    result.sort((a,b)=> a.orden-b.orden || a.nombre.localeCompare(b.nombre));
    res.json(result);
  }catch(e){ res.status(500).json({error:e.message}); }
});
// Crear categoría manual (queda en meta hasta que se le asignen productos)
app.post('/api/categorias/crear', authPerm('productos'), async (req,res)=>{
  try{
    const {nombre}=req.body;
    if(!nombre || !nombre.trim()) return res.status(400).json({error:'Falta el nombre'});
    const n=nombre.trim();
    const {rows:ex}=await pool.query('SELECT 1 FROM productos WHERE categoria=$1 AND tenant_id=$2 LIMIT 1', [n, req.tenantId]);
    const {rows:exM}=await pool.query('SELECT 1 FROM categorias_meta WHERE categoria=$1', [n]);
    if(ex.length || exM.length) return res.status(400).json({error:'Esa categoría ya existe'});
    await pool.query('INSERT INTO categorias_meta (categoria, orden, visible) VALUES ($1, 0, true) ON CONFLICT DO NOTHING', [n]);
    res.json({ok:true, nombre:n});
  }catch(e){ res.status(500).json({error:e.message}); }
});
// Renombrar / reasignar en masa: mueve todos los productos de una categoría a otra
app.post('/api/categorias/renombrar', authPerm('productos'), async (req,res)=>{
  try{
    const {desde, hasta, seccion_id}=req.body;
    if(!desde || !hasta) return res.status(400).json({error:'Faltan datos'});
    let q='UPDATE productos SET categoria=$1 WHERE categoria=$2 AND tenant_id=$3'; const params=[hasta, desde, req.tenantId];
    if(seccion_id && seccion_id!=='all'){ q+=' AND seccion_id=$4'; params.push(seccion_id); }
    const r=await pool.query(q, params);
    await pool.query('UPDATE categorias_meta SET categoria=$1 WHERE categoria=$2 AND tenant_id=$3', [hasta, desde, req.tenantId]).catch(()=>{});
    res.json({ok:true, afectados:r.rowCount});
  }catch(e){ res.status(500).json({error:e.message}); }
});
// Reasignar en masa un conjunto de productos a una categoría
app.post('/api/categorias/reasignar', authPerm('productos'), async (req,res)=>{
  try{
    const {producto_ids, categoria}=req.body;
    if(!Array.isArray(producto_ids) || !producto_ids.length || !categoria) return res.status(400).json({error:'Faltan datos'});
    const r=await pool.query('UPDATE productos SET categoria=$1 WHERE id = ANY($2) AND tenant_id=$3', [categoria, producto_ids, req.tenantId]);
    res.json({ok:true, afectados:r.rowCount});
  }catch(e){ res.status(500).json({error:e.message}); }
});
// Guardar orden y visibilidad de categorías
app.post('/api/categorias/meta', authPerm('productos'), async (req,res)=>{
  try{
    const {categorias}=req.body; // [{nombre, orden, visible}]
    for(const c of (categorias||[])){
      await pool.query(`INSERT INTO categorias_meta (categoria, orden, visible) VALUES ($1,$2,$3)
        ON CONFLICT (categoria) DO UPDATE SET orden=$2, visible=$3`, [c.nombre, c.orden||0, c.visible!==false]);
    }
    res.json({ok:true});
  }catch(e){ res.status(500).json({error:e.message}); }
});
app.post('/api/productos', authPerm('productos'), async (req,res)=>{
  try{
    const p=req.body;
    const {rows}=await pool.query(`INSERT INTO productos (tenant_id,seccion_id,categoria,modelo,nombre,precio_base,precio_original,stock,stock_minimo,imagen,notas,compatibilidad,descripcion,sku,tipo,moneda,precio_oferta,envio_gratis,visible,peso,alto,ancho,largo,permitir_sin_stock,es_digital,marca,es_preventa,preventa_precio,preventa_fecha,preventa_mostrar_fecha,preventa_descuento_pct,preventa_cupo) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,$23,$24,$25,$26,$27,$28,$29,$30,$31,$32) RETURNING *`,
      [req.tenantId, p.seccion_id, p.categoria||'', p.modelo||'', p.nombre||'', p.precio_base||0, p.precio_original||0, p.stock||0, p.stock_minimo||0, p.imagen||'', p.notas||'', p.compatibilidad||'', p.descripcion||'', p.sku||'', p.tipo||'fisico', p.moneda||'ARS', p.precio_oferta||0, p.envio_gratis||false, p.visible!==false, p.peso||0, p.alto||0, p.ancho||0, p.largo||0, p.permitir_sin_stock||false, p.es_digital||false, p.marca||'', p.es_preventa||false, p.preventa_precio||0, p.preventa_fecha||null, p.preventa_mostrar_fecha||false, p.preventa_descuento_pct||0, p.preventa_cupo||0]);
    res.json(rows[0]);
  }catch(e){ res.status(500).json({error:e.message}); }
});
app.post('/api/productos/:id/duplicar', authPerm('productos'), async (req,res)=>{
  const client=await pool.connect();
  try{
    const t=req.tenantId;
    const {rows:orig}=await client.query('SELECT * FROM productos WHERE id=$1 AND tenant_id=$2', [req.params.id, t]);
    if(!orig[0]){ client.release(); return res.status(404).json({error:'No encontrado'}); }
    const p=orig[0];
    await client.query('BEGIN');
    const {rows}=await client.query(`INSERT INTO productos (tenant_id,seccion_id,categoria,modelo,nombre,precio_base,precio_original,stock,stock_minimo,imagen,notas,compatibilidad,descripcion,sku,tipo,moneda,precio_oferta,envio_gratis,visible,peso,alto,ancho,largo,permitir_sin_stock,es_digital,marca,usa_variantes) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,$23,$24,$25,$26,$27) RETURNING *`,
      [t, p.seccion_id, p.categoria, p.modelo, (p.nombre||p.modelo||'')+' (copia)', p.precio_base, p.precio_original, 0, p.stock_minimo, p.imagen, p.notas, p.compatibilidad, p.descripcion, p.sku?p.sku+'-copia':'', p.tipo, p.moneda, p.precio_oferta, p.envio_gratis, false, p.peso, p.alto, p.ancho, p.largo, p.permitir_sin_stock, p.es_digital, p.marca, p.usa_variantes]);
    const nuevo=rows[0];
    // Atributos + sus valores (mapeando al nuevo producto)
    const {rows:atrs}=await client.query('SELECT * FROM producto_atributos WHERE producto_id=$1 AND tenant_id=$2 ORDER BY orden,id', [p.id, t]);
    for(const a of atrs){
      const {rows:na}=await client.query('INSERT INTO producto_atributos (tenant_id,producto_id,nombre,orden) VALUES ($1,$2,$3,$4) RETURNING id', [t, nuevo.id, a.nombre, a.orden||0]);
      const {rows:vals}=await client.query('SELECT valor,orden FROM producto_atributo_valores WHERE atributo_id=$1 AND tenant_id=$2 ORDER BY orden,id', [a.id, t]);
      for(const v of vals){ await client.query('INSERT INTO producto_atributo_valores (tenant_id,atributo_id,valor,orden) VALUES ($1,$2,$3,$4)', [t, na[0].id, v.valor, v.orden||0]); }
    }
    // Variantes (combinaciones con precio/stock/moneda)
    const {rows:vars}=await client.query('SELECT * FROM variantes WHERE producto_id=$1 AND tenant_id=$2 ORDER BY orden,id', [p.id, t]);
    for(const v of vars){
      await client.query('INSERT INTO variantes (tenant_id,producto_id,combinacion,precio,precio_oferta,stock,moneda,sku,orden,nombre,valor) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)',
        [t, nuevo.id, JSON.stringify(v.combinacion||{}), v.precio||0, v.precio_oferta||0, v.stock||0, v.moneda||'ARS', v.sku||'', v.orden||0, v.nombre||'', v.valor||'']);
    }
    // Galería de fotos
    const {rows:imgs}=await client.query('SELECT url,orden FROM producto_imagenes WHERE producto_id=$1 AND tenant_id=$2 ORDER BY orden,id', [p.id, t]);
    for(const im of imgs){ await client.query('INSERT INTO producto_imagenes (tenant_id,producto_id,url,orden) VALUES ($1,$2,$3,$4)', [t, nuevo.id, im.url, im.orden||0]); }
    // Precios por lista
    const {rows:pf}=await client.query('SELECT lista_precio_id,precio_fijo FROM precios_fijos WHERE producto_id=$1 AND tenant_id=$2', [p.id, t]);
    for(const f of pf){ await client.query('INSERT INTO precios_fijos (tenant_id,producto_id,lista_precio_id,precio_fijo) VALUES ($1,$2,$3,$4) ON CONFLICT (producto_id,lista_precio_id) DO NOTHING', [t, nuevo.id, f.lista_precio_id, f.precio_fijo]); }
    await client.query('COMMIT');
    res.json(nuevo);
  }catch(e){ await client.query('ROLLBACK').catch(()=>{}); res.status(500).json({error:e.message}); }
  finally{ client.release(); }
});
app.put('/api/productos/:id', authPerm('productos'), async (req,res)=>{
  try{
    const p=req.body;
    const fields=['seccion_id','categoria','modelo','nombre','precio_base','precio_original','stock','stock_minimo','imagen','notas','compatibilidad','descripcion','sku','codigo_barras','tipo','moneda','precio_oferta','envio_gratis','visible','peso','alto','ancho','largo','permitir_sin_stock','es_digital','marca','es_preventa','preventa_precio','preventa_fecha','preventa_mostrar_fecha','preventa_descuento_pct','preventa_cupo','preventa_reservado'];
    const sets=[]; const params=[]; let pi=1;
    for(const f of fields){ if(p[f]!==undefined){ sets.push(`${f}=$${pi++}`); params.push(p[f]); } }
    if(!sets.length) return res.json({ok:true});
    // historial precios si cambia precio_base
    if(p.precio_base!==undefined){
      const {rows:old}=await pool.query('SELECT precio_base FROM productos WHERE id=$1 AND tenant_id=$2', [req.params.id, req.tenantId]);
      if(old[0] && old[0].precio_base!=p.precio_base){
        await pool.query('INSERT INTO historial_precios (tenant_id,producto_id,precio_anterior,precio_nuevo,usuario) VALUES ($1,$2,$3,$4,$5)', [req.tenantId, req.params.id, old[0].precio_base, p.precio_base, req.user.usuario||'']).catch(()=>{});
      }
    }
    params.push(req.params.id); params.push(req.tenantId);
    await pool.query(`UPDATE productos SET ${sets.join(',')} WHERE id=$${pi} AND tenant_id=$${pi+1}`, params);
    // La galería manda: si el producto tiene fotos en la galería, la principal (primera) es la imagen visible.
    // Evita que un guardado con imagen vacía (en edición se oculta el recuadro viejo) borre la foto.
    await syncImagenPrincipal(req.params.id, req.tenantId);
    res.json({ok:true});
  }catch(e){ res.status(500).json({error:e.message}); }
});
app.delete('/api/productos/:id', authPerm('productos'), async (req,res)=>{
  try{
    const id=req.params.id, tid=req.tenantId;
    // Limpiar referencias que NO tienen ON DELETE CASCADE (evita que el borrado falle o deje huérfanos)
    await pool.query('DELETE FROM precios_fijos WHERE producto_id=$1', [id]).catch(()=>{});
    await pool.query('DELETE FROM historial_precios WHERE producto_id=$1', [id]).catch(()=>{});
    await pool.query('DELETE FROM notificaciones_stock WHERE producto_id=$1', [id]).catch(()=>{});
    // pedido_items y orden_compra_items: desvincular (dejar el histórico del pedido, sin el id)
    await pool.query('UPDATE pedido_items SET producto_id=NULL WHERE producto_id=$1', [id]).catch(()=>{});
    await pool.query('UPDATE orden_compra_items SET producto_id=NULL WHERE producto_id=$1', [id]).catch(()=>{});
    const r=await pool.query('DELETE FROM productos WHERE id=$1 AND tenant_id=$2', [id, tid]);
    if(r.rowCount===0) return res.status(404).json({error:'Producto no encontrado'});
    res.json({ok:true});
  }catch(e){ res.status(500).json({error:e.message}); }
});
app.post('/api/productos/bulk', authPerm('productos'), async (req,res)=>{
  try{
    const {productos, reemplazar, modo, faltantes, seccion_id} = req.body;
    // MODO "solo_categorias": actualiza SOLO la categoría matcheando por SKU (si tiene) o por nombre. No duplica, no toca precio/stock.
    if(modo==='solo_categorias'){
      let actualizados=0, noEncontrados=0;
      for(const p of (productos||[])){
        if(!p.categoria || p.categoria==='Sin categoría') continue;
        let r;
        if(p.sku && p.sku.trim()){
          r=await pool.query('UPDATE productos SET categoria=$1 WHERE sku=$2 AND tenant_id=$3', [p.categoria, p.sku.trim(), req.tenantId]);
        }
        if((!r || r.rowCount===0) && (p.nombre||p.modelo)){
          r=await pool.query('UPDATE productos SET categoria=$1 WHERE tenant_id=$3 AND (LOWER(TRIM(nombre))=LOWER(TRIM($2)) OR LOWER(TRIM(modelo))=LOWER(TRIM($2)))', [p.categoria, (p.nombre||p.modelo).trim(), req.tenantId]);
        }
        if(r && r.rowCount>0){ actualizados+=r.rowCount; await pool.query('INSERT INTO categorias_meta (tenant_id, categoria, orden, visible) VALUES ($2,$1,0,true) ON CONFLICT DO NOTHING', [p.categoria, req.tenantId]).catch(()=>{}); }
        else noEncontrados++;
      }
      return res.json({ok:true, modo:'solo_categorias', actualizados, noEncontrados, saltados:noEncontrados});
    }
    // MODO "crear_actualizar": si existe (por SKU o nombre) actualiza, si no inserta
    if(modo==='crear_actualizar' || modo==='actualizar'){
      let insertados=0, actualizados=0;
      for(const p of (productos||[])){
        let existe=null;
        if(p.sku && p.sku.trim()){ const {rows}=await pool.query('SELECT id FROM productos WHERE sku=$1 AND tenant_id=$2 LIMIT 1', [p.sku.trim(), req.tenantId]); existe=rows[0]; }
        if(!existe && (p.nombre||p.modelo)){ const {rows}=await pool.query('SELECT id FROM productos WHERE LOWER(TRIM(nombre))=LOWER(TRIM($1)) AND tenant_id=$2 LIMIT 1', [(p.nombre||p.modelo).trim(), req.tenantId]); existe=rows[0]; }
        if(existe){
          // Actualiza precio/stock/categoría y también peso/medidas (COALESCE: si el Excel trae 0/vacío, conserva el valor actual)
          await pool.query(`UPDATE productos SET categoria=$1, precio_base=$2, stock=$3, precio_oferta=$4,
            peso=CASE WHEN $5>0 THEN $5 ELSE peso END,
            alto=CASE WHEN $6>0 THEN $6 ELSE alto END,
            ancho=CASE WHEN $7>0 THEN $7 ELSE ancho END,
            largo=CASE WHEN $8>0 THEN $8 ELSE largo END
            WHERE id=$9 AND tenant_id=$10`,
            [p.categoria||'', p.precio_base||0, p.stock||0, p.precio_oferta||0, p.peso||0, p.alto||0, p.ancho||0, p.largo||0, existe.id, req.tenantId]);
          actualizados++;
        } else {
          await pool.query(`INSERT INTO productos (tenant_id,seccion_id,categoria,modelo,nombre,precio_base,stock,imagen,sku,descripcion,peso,alto,ancho,largo,visible) VALUES ($14,$1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,true)`, [p.seccion_id||seccion_id||1, p.categoria||'', p.modelo||'', p.nombre||p.modelo||'', p.precio_base||0, p.stock||0, p.imagen||'', p.sku||'', p.descripcion||'', p.peso||0, p.alto||0, p.ancho||0, p.largo||0, req.tenantId]);
          insertados++;
        }
      }
      return res.json({ok:true, modo:'crear_actualizar', insertados, actualizados});
    }
    // MODO "solo_nuevos": inserta solo los que no existen (por SKU o nombre)
    if(modo==='solo_nuevos'){
      let insertados=0, saltados=0;
      for(const p of (productos||[])){
        let existe=null;
        if(p.sku && p.sku.trim()){ const {rows}=await pool.query('SELECT id FROM productos WHERE sku=$1 AND tenant_id=$2 LIMIT 1', [p.sku.trim(), req.tenantId]); existe=rows[0]; }
        if(!existe && (p.nombre||p.modelo)){ const {rows}=await pool.query('SELECT id FROM productos WHERE LOWER(TRIM(nombre))=LOWER(TRIM($1)) AND tenant_id=$2 LIMIT 1', [(p.nombre||p.modelo).trim(), req.tenantId]); existe=rows[0]; }
        if(existe){ saltados++; continue; }
        await pool.query(`INSERT INTO productos (tenant_id,seccion_id,categoria,modelo,nombre,precio_base,stock,imagen,sku,descripcion,peso,alto,ancho,largo,visible) VALUES ($14,$1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,true)`, [p.seccion_id||seccion_id||1, p.categoria||'', p.modelo||'', p.nombre||p.modelo||'', p.precio_base||0, p.stock||0, p.imagen||'', p.sku||'', p.descripcion||'', p.peso||0, p.alto||0, p.ancho||0, p.largo||0, req.tenantId]);
        insertados++;
      }
      return res.json({ok:true, modo:'solo_nuevos', insertados, saltados});
    }
    // MODO por defecto / "reemplazar": insertar (con reemplazar opcional)
    if(reemplazar || modo==='reemplazar'){ await pool.query('DELETE FROM producto_imagenes WHERE tenant_id=$1', [req.tenantId]); await pool.query('DELETE FROM pedido_items WHERE tenant_id=$1', [req.tenantId]); await pool.query('DELETE FROM productos WHERE seccion_id=$1 AND tenant_id=$2', [seccion_id||1, req.tenantId]); }
    for(const p of (productos||[])){
      await pool.query(`INSERT INTO productos (tenant_id,seccion_id,categoria,modelo,nombre,precio_base,stock,imagen,sku,descripcion,compatibilidad,peso,alto,ancho,largo,visible,permitir_sin_stock,es_digital) VALUES ($18,$1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17) ON CONFLICT DO NOTHING`, [p.seccion_id||seccion_id||1, p.categoria||'', p.modelo||'', p.nombre||p.modelo||'', p.precio_base||0, p.stock||0, p.imagen||'', p.sku||'', p.descripcion||'', p.compatibilidad||'', p.peso||0, p.alto||0, p.ancho||0, p.largo||0, true, p.permitir_sin_stock||false, p.es_digital||false, req.tenantId]);
    }
    res.json({ok:true, count: productos.length, insertados: productos.length});
  }catch(e){ res.status(500).json({error:e.message}); }
});
app.delete('/api/categorias/:categoria', authPerm('productos'), async (req,res)=>{ try{ const {mover_a}=req.query; const destino = mover_a || 'Sin categoría'; const r=await pool.query('UPDATE productos SET categoria=$1 WHERE categoria=$2 AND tenant_id=$3', [destino, req.params.categoria, req.tenantId]); await pool.query('DELETE FROM categorias_meta WHERE categoria=$1 AND tenant_id=$2', [req.params.categoria, req.tenantId]).catch(()=>{}); res.json({ok:true, movidos:r.rowCount, destino}); }catch(e){ res.status(500).json({error:e.message}); } });
app.delete('/api/productos/all', authPerm('productos'), async (req,res)=>{ try{ await pool.query('DELETE FROM productos WHERE tenant_id=$1', [req.tenantId]); res.json({ok:true}); }catch(e){ res.status(500).json({error:e.message}); } });

// ═══════════════════════════════════════════════════════════════
// BOT DE DROPSHIPPING — sync desde el proveedor (rxzweb)
// Auth por API key fija (header X-Bot-Key). El bot NO usa login de usuario.
// Tenant fijo por env BOT_TENANT_ID (default 1 = tienda de Leandro).
// Match por SKU = "RXZ-{woo_id}". Los productos que se caen del proveedor
// quedan en stock 0 (siguen visibles como "sin stock").
// ═══════════════════════════════════════════════════════════════
const botAuth = (req, res, next) => {
  const key = req.headers['x-bot-key'] || '';
  if (!process.env.BOT_API_KEY) return res.status(503).json({ error: 'BOT_API_KEY no configurada en el servidor' });
  if (key !== process.env.BOT_API_KEY) return res.status(401).json({ error: 'X-Bot-Key inválida' });
  req.botTenantId = parseInt(process.env.BOT_TENANT_ID || '1', 10);
  next();
};

// POST /api/bot/sync — recibe un lote de productos del proveedor y hace upsert por SKU.
// Body: { productos: [ { sku, nombre, precio_base, precio_oferta, stock, imagen, categoria, envio_gratis, variantes:[{nombre,valor,stock,precio}] } ], seccion_id? }
app.post('/api/bot/sync', botAuth, async (req, res) => {
  const t = req.botTenantId;
  try {
    const { productos, seccion_id } = req.body;
    if (!Array.isArray(productos)) return res.status(400).json({ error: 'productos debe ser un array' });

    // Sección destino: la que mande el bot, o la primera que tenga slug/nombre DEPOSITO, o la primera que exista.
    let secId = seccion_id;
    if (!secId) {
      const { rows } = await pool.query(
        "SELECT id FROM secciones WHERE tenant_id=$1 AND (LOWER(slug)='deposito' OR LOWER(nombre)='deposito' OR UPPER(nombre)='DEPOSITO' OR LOWER(nombre) LIKE '%deposito%') ORDER BY id LIMIT 1", [t]);
      secId = rows[0]?.id;
      if (!secId) { const { rows: r2 } = await pool.query('SELECT id FROM secciones WHERE tenant_id=$1 ORDER BY orden, id LIMIT 1', [t]); secId = r2[0]?.id; }
    }
    if (!secId) {
      return res.status(400).json({ error: 'No se encontró ninguna sección en la tienda. Creá al menos una sección (ej. DEPOSITO) antes de sincronizar.' });
    }

    let insertados = 0, actualizados = 0, errores = 0;
    const detalles = [];
    let primerError = null;

    for (const p of productos) {
      const sku = String(p.sku || '').trim();
      if (!sku) { errores++; continue; }
      try {
        // Truncar campos de texto para no exceder los límites de VARCHAR
        const nombre = String(p.nombre || '').slice(0, 300);
        const categoria = String(p.categoria || '').slice(0, 200);
        const skuT = sku.slice(0, 100);
        const imagen = String(p.imagen || '');
        const descripcion = String(p.descripcion || '');
        const peso = Number(p.peso) || 0;
        const alto = Number(p.alto) || 0;
        const ancho = Number(p.ancho) || 0;
        const largo = Number(p.largo) || 0;
        const precioBase = Number(p.precio_base) || 0;
        const precioOferta = Number(p.precio_oferta) || 0;
        const stock = parseInt(p.stock) || 0;
        const envioGratis = !!p.envio_gratis;

        const { rows } = await pool.query('SELECT id FROM productos WHERE sku=$1 AND tenant_id=$2 LIMIT 1', [skuT, t]);
        let prodId;
        if (rows[0]) {
          // Existe → actualiza SOLO precio/stock/oferta/envío gratis. NO pisa nombre/imagen/categoría (por si Leandro las editó a mano).
          prodId = rows[0].id;
          await pool.query(
            `UPDATE productos SET precio_base=$1, precio_oferta=$2, stock=$3, envio_gratis=$4 WHERE id=$5 AND tenant_id=$6`,
            [precioBase, precioOferta, stock, envioGratis, prodId, t]);
          actualizados++;
        } else {
          // Nuevo → inserta completo en la sección destino.
          const { rows: ins } = await pool.query(
            `INSERT INTO productos (tenant_id,seccion_id,categoria,modelo,nombre,descripcion,precio_base,precio_oferta,stock,imagen,sku,envio_gratis,peso,alto,ancho,largo,visible)
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,true) RETURNING id`,
            [t, secId, categoria, nombre, nombre, descripcion, precioBase, precioOferta, stock, imagen, skuT, envioGratis, peso, alto, ancho, largo]);
          prodId = ins[0].id;
          // Galería completa: todas las imágenes del proveedor
          const galeria = Array.isArray(p.imagenes) && p.imagenes.length ? p.imagenes : (imagen ? [imagen] : []);
          for (let gi = 0; gi < galeria.length; gi++) {
            await pool.query('INSERT INTO producto_imagenes (tenant_id,producto_id,url,orden) VALUES ($1,$2,$3,$4) ON CONFLICT DO NOTHING', [t, prodId, galeria[gi], gi]).catch(()=>{});
          }
          insertados++;
        }

        // Variantes: si el proveedor manda variantes, sincronizarlas (borra las que no vengan y upsert por nombre+valor).
        if (Array.isArray(p.variantes) && p.variantes.length) {
          const { rows: existentes } = await pool.query('SELECT id,nombre,valor FROM variantes WHERE producto_id=$1 AND tenant_id=$2', [prodId, t]);
          const vistos = new Set();
          for (const v of p.variantes) {
            const vnom = String(v.nombre || 'Opción').trim();
            const vval = String(v.valor || v.nombre || '').trim();
            const key = (vnom + '|' + vval).toLowerCase();
            vistos.add(key);
            const ya = existentes.find(e => (String(e.nombre||'')+'|'+String(e.valor||'')).toLowerCase() === key);
            if (ya) {
              await pool.query('UPDATE variantes SET stock=$1, precio=$2 WHERE id=$3 AND tenant_id=$4', [v.stock || 0, v.precio || 0, ya.id, t]);
            } else {
              await pool.query('INSERT INTO variantes (tenant_id,producto_id,nombre,valor,stock,precio_extra,precio) VALUES ($1,$2,$3,$4,$5,0,$6)', [t, prodId, vnom, vval, v.stock || 0, v.precio || 0]);
            }
          }
          // Borra variantes que ya no vienen del proveedor
          for (const e of existentes) {
            const key = (String(e.nombre||'')+'|'+String(e.valor||'')).toLowerCase();
            if (!vistos.has(key)) await pool.query('DELETE FROM variantes WHERE id=$1 AND tenant_id=$2', [e.id, t]).catch(()=>{});
          }
        }
      } catch (ep) {
        errores++;
        const msg = String(ep.message || ep).slice(0, 160);
        if (!primerError) primerError = msg;
        if (detalles.length < 10) detalles.push({ sku, error: msg });
      }
    }

    res.json({ ok: true, seccion_id: secId, total: productos.length, insertados, actualizados, errores, primer_error: primerError || undefined, detalles: detalles.length ? detalles : undefined });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// GET /api/bot/skus — lista los SKU RXZ- que existen (para que el bot sepa qué poner en stock 0 si se cayeron del proveedor)
// POST /api/bot/limpiar-deposito — borra TODOS los productos de la sección DEPOSITO (para recarga limpia)
// Úsalo UNA vez para eliminar duplicados del catálogo viejo antes de resincronizar desde cero.
app.post('/api/bot/limpiar-deposito', botAuth, async (req, res) => {
  const t = req.botTenantId;
  try {
    // Resolver sección DEPOSITO
    let secId = req.body?.seccion_id;
    if (!secId) {
      const { rows } = await pool.query(
        "SELECT id FROM secciones WHERE tenant_id=$1 AND (LOWER(slug)='deposito' OR LOWER(nombre)='deposito' OR UPPER(nombre)='DEPOSITO' OR LOWER(nombre) LIKE '%deposito%') ORDER BY id LIMIT 1", [t]);
      secId = rows[0]?.id;
    }
    if (!secId) return res.status(400).json({ error: 'No se encontró la sección DEPOSITO' });

    // Contar antes de borrar
    const { rows: cnt } = await pool.query('SELECT COUNT(*)::int as n FROM productos WHERE seccion_id=$1 AND tenant_id=$2', [secId, t]);
    const total = cnt[0]?.n || 0;

    // Borrar imágenes y variantes primero (por si no hay ON DELETE CASCADE), después productos
    await pool.query('DELETE FROM producto_imagenes WHERE tenant_id=$1 AND producto_id IN (SELECT id FROM productos WHERE seccion_id=$2 AND tenant_id=$1)', [t, secId]).catch(()=>{});
    await pool.query('DELETE FROM variantes WHERE tenant_id=$1 AND producto_id IN (SELECT id FROM productos WHERE seccion_id=$2 AND tenant_id=$1)', [t, secId]).catch(()=>{});
    await pool.query('DELETE FROM favoritos WHERE producto_id IN (SELECT id FROM productos WHERE seccion_id=$1 AND tenant_id=$2)', [secId, t]).catch(()=>{});
    const r = await pool.query('DELETE FROM productos WHERE seccion_id=$1 AND tenant_id=$2', [secId, t]);

    res.json({ ok: true, seccion_id: secId, borrados: r.rowCount, total_previo: total });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// POST /api/bot/fotos-por-nombre — matchea fotos por nombre y las agrega SOLO a productos sin imagen
// Body: { fotos: [ { nombre, imagenes: [url, ...] } ], modo: 'reportar' | 'aplicar' }
app.post('/api/bot/fotos-por-nombre', botAuth, async (req, res) => {
  const t = req.botTenantId;
  try {
    const { fotos, modo } = req.body;
    if (!Array.isArray(fotos)) return res.status(400).json({ error: 'fotos debe ser un array' });
    const soloReportar = (modo === 'reportar');

    const norm = (s) => String(s || '')
      .toLowerCase().trim()
      .normalize('NFD').replace(/[\u0300-\u036f]/g, '')  // sin tildes
      .replace(/[^a-z0-9 ]/g, ' ')                        // sin puntuación
      .replace(/\s+/g, ' ').trim();

    // Traer TODOS los productos de la tienda con su estado de imagen
    const { rows: prods } = await pool.query(
      `SELECT p.id, p.nombre, p.modelo, p.imagen,
              (SELECT COUNT(*)::int FROM producto_imagenes pi WHERE pi.producto_id=p.id AND pi.tenant_id=p.tenant_id) as n_imgs
       FROM productos p WHERE p.tenant_id=$1`, [t]);

    // Indexar productos por nombre normalizado
    const idx = {};
    for (const p of prods) {
      const k = norm(p.nombre || p.modelo);
      if (k && !idx[k]) idx[k] = p;
    }

    let matcheados = 0, sinFoto = 0, yaConFoto = 0, sinMatch = 0, aplicados = 0;
    const noMatch = [];

    for (const f of fotos) {
      const k = norm(f.nombre);
      const prod = idx[k];
      if (!prod) { sinMatch++; if (noMatch.length < 50) noMatch.push(f.nombre); continue; }
      matcheados++;
      const tieneFoto = (prod.imagen && prod.imagen.trim()) || (prod.n_imgs > 0);
      if (tieneFoto) { yaConFoto++; continue; }
      sinFoto++;
      // Aplicar solo si no es modo reportar
      if (!soloReportar) {
        const imgs = Array.isArray(f.imagenes) && f.imagenes.length ? f.imagenes : (f.imagen ? [f.imagen] : []);
        if (imgs.length) {
          for (let gi = 0; gi < imgs.length; gi++) {
            await pool.query('INSERT INTO producto_imagenes (tenant_id,producto_id,url,orden) VALUES ($1,$2,$3,$4) ON CONFLICT DO NOTHING', [t, prod.id, imgs[gi], gi]).catch(()=>{});
          }
          await pool.query("UPDATE productos SET imagen=$1 WHERE id=$2 AND tenant_id=$3 AND (imagen IS NULL OR imagen='')", [imgs[0], prod.id, t]);
          aplicados++;
        }
      }
    }

    res.json({
      ok: true, modo: soloReportar ? 'reportar' : 'aplicar',
      total_fotos: fotos.length, total_productos: prods.length,
      matcheados, ya_con_foto: yaConFoto, sin_foto_matcheados: sinFoto,
      sin_match: sinMatch, aplicados,
      ejemplos_sin_match: noMatch.length ? noMatch.slice(0, 30) : undefined
    });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/bot/skus', botAuth, async (req, res) => {
  const t = req.botTenantId;
  try {
    const { rows } = await pool.query("SELECT sku, stock FROM productos WHERE tenant_id=$1 AND sku LIKE 'RXZ-%'", [t]);
    res.json({ ok: true, skus: rows });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// POST /api/bot/stock-cero — pone stock 0 a una lista de SKU (los que se cayeron del proveedor)
app.post('/api/bot/stock-cero', botAuth, async (req, res) => {
  const t = req.botTenantId;
  try {
    const { skus } = req.body;
    if (!Array.isArray(skus) || !skus.length) return res.json({ ok: true, afectados: 0 });
    const r = await pool.query("UPDATE productos SET stock=0 WHERE tenant_id=$1 AND sku = ANY($2)", [t, skus]);
    res.json({ ok: true, afectados: r.rowCount });
  } catch (e) { res.status(500).json({ error: e.message }); }
});
app.get('/api/productos/buscar', async (req,res)=>{ try{ const {q}=req.query; if(!q) return res.json([]); const toks=String(q).trim().split(/\s+/).filter(Boolean).slice(0,8); const campos=`(coalesce(p.nombre,'')||' '||coalesce(p.modelo,'')||' '||coalesce(p.categoria,'')||' '||coalesce(p.marca,'')||' '||coalesce(p.sku,'')||' '||coalesce(p.compatibilidad,''))`; const cond=[]; const params=[req.tenantId]; let pi=2; for(const tk of toks){ cond.push(`${campos} ILIKE $${pi}`); params.push(`%${tk}%`); pi++; } const whereTok=cond.length?(' AND '+cond.join(' AND ')):''; const {rows}=await pool.query(`SELECT p.id,p.nombre,p.modelo,p.categoria,p.precio_base,p.precio_oferta,p.stock,p.imagen,p.sku,p.codigo_barras,p.seccion_id,p.permitir_sin_stock,p.es_digital,p.usa_variantes,(SELECT MIN(CASE WHEN v.precio_oferta>0 AND v.precio_oferta<v.precio THEN v.precio_oferta ELSE v.precio END) FROM variantes v WHERE v.producto_id=p.id AND v.tenant_id=p.tenant_id AND v.precio>0) AS precio_desde,s.nombre as seccion_nombre,s.color as seccion_color FROM productos p LEFT JOIN secciones s ON p.seccion_id=s.id WHERE p.tenant_id=$1${whereTok} ORDER BY p.nombre LIMIT 20`, params); res.json(rows); }catch(e){ res.status(500).json({error:e.message}); } });
// Buscar producto por código de barras/SKU exacto (para el escáner). Devuelve 1 producto.
app.get('/api/productos/por-codigo/:codigo', async (req,res)=>{
  try{
    const c=(req.params.codigo||'').trim();
    if(!c) return res.status(404).json({error:'Código vacío'});
    const {rows}=await pool.query(`SELECT p.*, s.nombre as seccion_nombre FROM productos p LEFT JOIN secciones s ON p.seccion_id=s.id
      WHERE p.tenant_id=$2 AND (p.codigo_barras=$1 OR p.sku=$1 OR CAST(p.id AS TEXT)=$1) LIMIT 1`, [c, req.tenantId]);
    if(!rows[0]) return res.status(404).json({error:'No se encontró ningún producto con ese código'});
    res.json(rows[0]);
  }catch(e){ res.status(500).json({error:e.message}); }
});
// Generar código de barras automático para productos que no tienen (basado en ID). Opcional: seccion_id
app.post('/api/productos/generar-codigos', authPerm('productos'), async (req,res)=>{
  try{
    const {seccion_id}=req.body;
    const cond = seccion_id && seccion_id!=='all' ? 'AND seccion_id=$2' : '';
    const params = seccion_id && seccion_id!=='all' ? [req.tenantId, seccion_id] : [req.tenantId];
    // Genera código tipo "P" + id con padding (ej P000123) para los que están vacíos
    const {rows}=await pool.query(`SELECT id FROM productos WHERE tenant_id=$1 AND (codigo_barras IS NULL OR codigo_barras='') ${cond}`, params);
    let generados=0;
    for(const r of rows){
      const codigo='P'+String(r.id).padStart(6,'0');
      await pool.query('UPDATE productos SET codigo_barras=$1 WHERE id=$2 AND tenant_id=$3', [codigo, r.id, req.tenantId]);
      generados++;
    }
    res.json({ok:true, generados});
  }catch(e){ res.status(500).json({error:e.message}); }
});
app.get('/api/productos/id/:id', async (req,res)=>{ try{ const {rows}=await pool.query('SELECT * FROM productos WHERE id=$1 AND tenant_id=$2', [req.params.id, req.tenantId]); if(!rows[0]) return res.status(404).json({error:'No encontrado'}); res.json(rows[0]); }catch(e){ res.status(500).json({error:e.message}); } });

// Validar presupuesto antes de convertir: chequear stock y precios actuales
app.post('/api/pedidos/:id/validar-conversion', authPerm('pedidos'), async (req,res)=>{
  try{
    const {rows:items}=await pool.query('SELECT * FROM pedido_items WHERE pedido_id=$1 AND tenant_id=$2', [req.params.id, req.tenantId]);
    if(!items.length) return res.status(400).json({error:'Sin items'});
    const prodIds=items.map(i=>i.producto_id).filter(Boolean);
    const {rows:prods}=await pool.query(`SELECT id,nombre,modelo,precio_base,stock FROM productos WHERE id = ANY($1) AND tenant_id=$2`, [prodIds, req.tenantId]);
    const prodMap={}; prods.forEach(p=>prodMap[p.id]=p);
    const cambios=[];
    items.forEach(it=>{
      const prod=prodMap[it.producto_id];
      if(!prod){ cambios.push({item:it.nombre_producto, tipo:'eliminado', detalle:'Producto ya no existe'}); return; }
      if(prod.stock<it.cantidad) cambios.push({item:it.nombre_producto, tipo:'stock', detalle:`Stock actual: ${prod.stock}, pedido: ${it.cantidad}`, stock_actual:prod.stock});
      if(Number(prod.precio_base)!==Number(it.precio_unitario)) cambios.push({item:it.nombre_producto, tipo:'precio', detalle:`Precio actual: ${prod.precio_base}, presupuesto: ${it.precio_unitario}`, precio_actual:prod.precio_base, precio_presup:it.precio_unitario});
    });
    res.json({ok:true, cambios, tiene_cambios:cambios.length>0});
  }catch(e){ res.status(500).json({error:e.message}); }
});

// IMAGENES y VARIANTES (igual que antes)
// Sincroniza productos.imagen con la PRIMERA foto de la galería (la principal). Si la galería queda vacía, conserva la imagen actual.
async function syncImagenPrincipal(productoId, tenantId){
  try{
    await pool.query(`UPDATE productos SET imagen = COALESCE((SELECT url FROM producto_imagenes WHERE producto_id=$1 AND tenant_id=$2 ORDER BY orden ASC, id ASC LIMIT 1), imagen) WHERE id=$1 AND tenant_id=$2`, [productoId, tenantId]);
  }catch(e){ console.log('sync img principal warn', e.message.slice(0,80)); }
}
app.get('/api/producto-imagenes/:producto_id', async (req,res)=>{ try{ const {rows}=await pool.query('SELECT * FROM producto_imagenes WHERE producto_id=$1 AND tenant_id=$2 ORDER BY orden', [req.params.producto_id, req.tenantId]); res.json(rows); }catch(e){ res.status(500).json({error:e.message}); } });
app.post('/api/producto-imagenes', authPerm('productos'), async (req,res)=>{ try{ const {producto_id,url,orden}=req.body; const {rows}=await pool.query('INSERT INTO producto_imagenes (tenant_id,producto_id,url,orden) VALUES ($4,$1,$2,$3) RETURNING *', [producto_id,url,orden||0, req.tenantId]); await syncImagenPrincipal(producto_id, req.tenantId); res.json(rows[0]); }catch(e){ res.status(500).json({error:e.message}); } });
app.delete('/api/producto-imagenes/:id', authPerm('productos'), async (req,res)=>{ try{ const {rows:pv}=await pool.query('SELECT producto_id FROM producto_imagenes WHERE id=$1 AND tenant_id=$2', [req.params.id, req.tenantId]); await pool.query('DELETE FROM producto_imagenes WHERE id=$1 AND tenant_id=$2', [req.params.id, req.tenantId]); if(pv[0]) await syncImagenPrincipal(pv[0].producto_id, req.tenantId); res.json({ok:true}); }catch(e){ res.status(500).json({error:e.message}); } });
app.put('/api/producto-imagenes/reorder', authPerm('productos'), async (req,res)=>{ try{ const {items}=req.body; for(const it of items){ await pool.query('UPDATE producto_imagenes SET orden=$1 WHERE id=$2 AND tenant_id=$3', [it.orden,it.id, req.tenantId]); } if(items&&items[0]){ const {rows:pv}=await pool.query('SELECT producto_id FROM producto_imagenes WHERE id=$1 AND tenant_id=$2', [items[0].id, req.tenantId]); if(pv[0]) await syncImagenPrincipal(pv[0].producto_id, req.tenantId); } res.json({ok:true}); }catch(e){ res.status(500).json({error:e.message}); } });
app.get('/api/variantes/:producto_id', async (req,res)=>{ try{ const {rows}=await pool.query('SELECT * FROM variantes WHERE producto_id=$1 AND tenant_id=$2 ORDER BY id', [req.params.producto_id, req.tenantId]); res.json(rows); }catch(e){ res.status(500).json({error:e.message}); } });
app.post('/api/variantes', authPerm('productos'), async (req,res)=>{ try{ const {producto_id,nombre,valor,stock,precio_extra,precio}=req.body; const {rows}=await pool.query('INSERT INTO variantes (tenant_id,producto_id,nombre,valor,stock,precio_extra,precio) VALUES ($7,$1,$2,$3,$4,$5,$6) RETURNING *', [producto_id,nombre,valor||'',stock||0,precio_extra||0,precio||0, req.tenantId]); res.json(rows[0]); }catch(e){ res.status(500).json({error:e.message}); } });
app.put('/api/variantes/:id', authPerm('productos'), async (req,res)=>{ try{ const v=req.body; await pool.query('UPDATE variantes SET nombre=$1,valor=$2,stock=$3,precio_extra=$4,precio=$5 WHERE id=$6', [v.nombre,v.valor,v.stock||0,v.precio_extra||0,v.precio||0,req.params.id]); res.json({ok:true}); }catch(e){ res.status(500).json({error:e.message}); } });
app.delete('/api/variantes/:id', authPerm('productos'), async (req,res)=>{ try{ await pool.query('DELETE FROM variantes WHERE id=$1 AND tenant_id=$2', [req.params.id, req.tenantId]); res.json({ok:true}); }catch(e){ res.status(500).json({error:e.message}); } });

// ── ATRIBUTOS + VARIANTES COMBINADAS (modelo Empretienda) ──
// Lee atributos + valores + variantes (combinaciones) de un producto en una sola llamada
app.get('/api/productos/:id/variantes-full', async (req,res)=>{
  try{
    const t=req.tenantId; const pid=req.params.id;
    const {rows:prod}=await pool.query('SELECT usa_variantes FROM productos WHERE id=$1 AND tenant_id=$2',[pid,t]);
    if(!prod[0]) return res.status(404).json({error:'Producto no encontrado'});
    const {rows:atrs}=await pool.query('SELECT id,nombre,orden FROM producto_atributos WHERE producto_id=$1 AND tenant_id=$2 ORDER BY orden,id',[pid,t]);
    const atributos=[];
    for(const a of atrs){
      const {rows:vals}=await pool.query('SELECT valor FROM producto_atributo_valores WHERE atributo_id=$1 AND tenant_id=$2 ORDER BY orden,id',[a.id,t]);
      atributos.push({ nombre:a.nombre, orden:a.orden, valores: vals.map(v=>v.valor) });
    }
    const {rows:variantes}=await pool.query('SELECT id,combinacion,precio,precio_oferta,stock,moneda,sku,orden FROM variantes WHERE producto_id=$1 AND tenant_id=$2 ORDER BY orden,id',[pid,t]);
    res.json({ usa_variantes: !!prod[0].usa_variantes, atributos, variantes });
  }catch(e){ res.status(500).json({error:e.message}); }
});

// Guarda TODO junto: reemplaza atributos, valores y variantes del producto (transaccional)
app.put('/api/productos/:id/variantes-full', authPerm('productos'), async (req,res)=>{
  const client=await pool.connect();
  try{
    const t=req.tenantId; const pid=req.params.id;
    const { usa_variantes, atributos=[], variantes=[] } = req.body;
    await client.query('BEGIN');
    await client.query('UPDATE productos SET usa_variantes=$1 WHERE id=$2 AND tenant_id=$3',[!!usa_variantes, pid, t]);
    await client.query('DELETE FROM producto_atributos WHERE producto_id=$1 AND tenant_id=$2',[pid,t]); // cascade borra valores
    await client.query('DELETE FROM variantes WHERE producto_id=$1 AND tenant_id=$2',[pid,t]);
    let ao=0;
    for(const a of atributos){
      const nom=(a.nombre||'').trim(); if(!nom) continue;
      const {rows:ar}=await client.query('INSERT INTO producto_atributos (tenant_id,producto_id,nombre,orden) VALUES ($1,$2,$3,$4) RETURNING id',[t,pid,nom,ao++]);
      let vo=0;
      for(const v of (a.valores||[])){ const val=(''+v).trim(); if(!val) continue; await client.query('INSERT INTO producto_atributo_valores (tenant_id,atributo_id,valor,orden) VALUES ($1,$2,$3,$4)',[t,ar[0].id,val,vo++]); }
    }
    let vo2=0;
    for(const v of variantes){
      await client.query('INSERT INTO variantes (tenant_id,producto_id,combinacion,precio,precio_oferta,stock,moneda,sku,orden,nombre,valor) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)',
        [t,pid, JSON.stringify(v.combinacion||{}), v.precio||0, v.precio_oferta||0, v.stock||0, v.moneda||'ARS', v.sku||'', vo2++, '', '']);
    }
    await client.query('COMMIT');
    res.json({ok:true});
  }catch(e){ await client.query('ROLLBACK').catch(()=>{}); res.status(500).json({error:e.message}); }
  finally{ client.release(); }
});

// PRECIOS
app.post('/api/precios/ajustar', authPerm('productos'), async (req,res)=>{
  try{
    const {porcentaje,categoria}=req.body;
    // Capturar precios anteriores para el historial
    const selQ = categoria ? 'SELECT id, precio_base FROM productos WHERE categoria=$1 AND tenant_id=$2' : 'SELECT id, precio_base FROM productos WHERE tenant_id=$1';
    const {rows:antes} = await pool.query(selQ, categoria ? [categoria, req.tenantId] : [req.tenantId]);
    if(categoria) await pool.query('UPDATE productos SET precio_base = precio_base * $1 WHERE categoria=$2 AND tenant_id=$3', [1+porcentaje/100, categoria, req.tenantId]);
    else await pool.query('UPDATE productos SET precio_base = precio_base * (1+$1/100) WHERE tenant_id=$2', [porcentaje, req.tenantId]);
    // Registrar historial (masivo)
    const usr = (req.user.usuario||'admin') + ' (ajuste masivo ' + (porcentaje>0?'+':'') + porcentaje + '%' + (categoria?' '+categoria:'') + ')';
    for(const a of antes){ const nuevo = Number(a.precio_base) * (1+porcentaje/100); if(Number(a.precio_base)!==nuevo) await pool.query('INSERT INTO historial_precios (producto_id,precio_anterior,precio_nuevo,usuario) VALUES ($1,$2,$3,$4)', [a.id, a.precio_base, nuevo.toFixed(2), usr]).catch(()=>{}); }
    res.json({ok:true, ajustados:antes.length});
  }catch(e){ res.status(500).json({error:e.message}); }
});
app.post('/api/precios/reset', authPerm('productos'), async (req,res)=>{ try{ const {rows}=await pool.query('SELECT * FROM historial_precios ORDER BY created_at DESC'); res.json({ok:true}); }catch(e){ res.status(500).json({error:e.message}); } });
app.get('/api/historial-precios', authPerm('productos'), async (req,res)=>{ try{ const {rows}=await pool.query('SELECT h.*, p.nombre, p.modelo, p.categoria FROM historial_precios h LEFT JOIN productos p ON h.producto_id=p.id ORDER BY h.created_at DESC LIMIT 200'); res.json(rows); }catch(e){ res.status(500).json({error:e.message}); } });

// ── ÓRDENES DE COMPRA (compras a proveedores) ──
app.get('/api/ordenes-compra', authPerm('pedidos'), async (req,res)=>{
  try{ const {rows}=await pool.query('SELECT o.*, s.nombre as seccion_nombre FROM ordenes_compra o LEFT JOIN secciones s ON o.seccion_id=s.id WHERE o.tenant_id=$1 ORDER BY o.created_at DESC LIMIT 200', [req.tenantId]); res.json(rows); }
  catch(e){ res.status(500).json({error:e.message}); }
});
app.get('/api/ordenes-compra/:id', authPerm('pedidos'), async (req,res)=>{
  try{
    const {rows:o}=await pool.query('SELECT o.*, s.nombre as seccion_nombre FROM ordenes_compra o LEFT JOIN secciones s ON o.seccion_id=s.id WHERE o.id=$1 AND o.tenant_id=$2', [req.params.id, req.tenantId]);
    if(!o[0]) return res.status(404).json({error:'No encontrada'});
    const {rows:items}=await pool.query('SELECT * FROM orden_compra_items WHERE orden_id=$1', [req.params.id]);
    res.json({ ...o[0], items });
  }catch(e){ res.status(500).json({error:e.message}); }
});
app.post('/api/ordenes-compra', authPerm('pedidos'), async (req,res)=>{
  try{
    const {proveedor, seccion_id, notas, items, total}=req.body;
    const {rows}=await pool.query('INSERT INTO ordenes_compra (proveedor,seccion_id,notas,total,estado,recibida,tenant_id) VALUES ($1,$2,$3,$4,$5,$6,$7) RETURNING *', [proveedor||'', seccion_id||null, notas||'', total||0, 'pendiente', false, req.tenantId]);
    for(const it of (items||[])){
      await pool.query('INSERT INTO orden_compra_items (orden_id,producto_id,nombre_producto,cantidad,costo_unitario,tenant_id) VALUES ($1,$2,$3,$4,$5,$6)', [rows[0].id, it.producto_id||null, it.nombre_producto||'', it.cantidad||1, it.costo_unitario||0, req.tenantId]);
    }
    res.json(rows[0]);
  }catch(e){ res.status(500).json({error:e.message}); }
});
// Marcar recibida: SUMA el stock de cada item a los productos
app.post('/api/ordenes-compra/:id/recibir', authPerm('pedidos'), async (req,res)=>{
  try{
    const {rows:o}=await pool.query('SELECT recibida FROM ordenes_compra WHERE id=$1 AND tenant_id=$2', [req.params.id, req.tenantId]);
    if(!o[0]) return res.status(404).json({error:'No encontrada'});
    if(o[0].recibida) return res.status(400).json({error:'Ya fue recibida'});
    const {rows:items}=await pool.query('SELECT * FROM orden_compra_items WHERE orden_id=$1', [req.params.id]);
    for(const it of items){
      if(it.producto_id){
        await pool.query('UPDATE productos SET stock=stock+$1 WHERE id=$2 AND tenant_id=$3', [it.cantidad||0, it.producto_id, req.tenantId]);
        // Opcional: actualizar costo si vino
        if(it.costo_unitario>0) await pool.query('UPDATE productos SET precio_original=$1 WHERE id=$2 AND tenant_id=$3 AND (precio_original IS NULL OR precio_original=0)', [it.costo_unitario, it.producto_id, req.tenantId]).catch(()=>{});
      }
    }
    await pool.query('UPDATE ordenes_compra SET recibida=true, estado=$1 WHERE id=$2 AND tenant_id=$3', ['recibida', req.params.id, req.tenantId]);
    res.json({ok:true, items_recibidos:items.length});
  }catch(e){ res.status(500).json({error:e.message}); }
});
app.delete('/api/ordenes-compra/:id', authPerm('pedidos'), async (req,res)=>{
  try{ await pool.query('DELETE FROM ordenes_compra WHERE id=$1 AND tenant_id=$2', [req.params.id, req.tenantId]); res.json({ok:true}); }
  catch(e){ res.status(500).json({error:e.message}); }
});
app.get('/api/precios-fijos', authPerm('productos'), async (req,res)=>{ try{ const {rows}=await pool.query('SELECT * FROM precios_fijos WHERE tenant_id=$1', [req.tenantId]); res.json(rows); }catch(e){ res.status(500).json({error:e.message}); } });
app.post('/api/precios-fijos', authPerm('productos'), async (req,res)=>{ try{ const {producto_id,lista_precio_id,precio_fijo}=req.body; await pool.query('INSERT INTO precios_fijos (tenant_id,producto_id,lista_precio_id,precio_fijo) VALUES ($4,$1,$2,$3) ON CONFLICT (producto_id,lista_precio_id) DO UPDATE SET precio_fijo=$3', [producto_id,lista_precio_id,precio_fijo, req.tenantId]); res.json({ok:true}); }catch(e){ res.status(500).json({error:e.message}); } });

// USUARIOS
app.get('/api/usuarios/:id/cuenta', authPerm('usuarios'), async (req,res)=>{
  try{
    const {rows:movs}=await pool.query('SELECT cc.*, p.tipo as pedido_tipo FROM cuenta_corriente cc LEFT JOIN pedidos p ON cc.pedido_id=p.id WHERE cc.usuario_id=$1 AND cc.tenant_id=$2 ORDER BY cc.created_at DESC LIMIT 200', [req.params.id, req.tenantId]);
    const saldo=movs.reduce((s,m)=> s + (m.tipo==='cargo' ? Number(m.monto) : -Number(m.monto)), 0);
    res.json({ movimientos: movs, saldo });
  }catch(e){ res.status(500).json({error:e.message}); }
});
app.post('/api/usuarios/:id/cuenta', authPerm('usuarios'), async (req,res)=>{
  try{
    const {tipo, monto, concepto}=req.body;
    if(!['cargo','pago'].includes(tipo) || !monto) return res.status(400).json({error:'Datos inválidos'});
    const {rows}=await pool.query('INSERT INTO cuenta_corriente (tenant_id,usuario_id,tipo,monto,concepto) VALUES ($5,$1,$2,$3,$4) RETURNING *', [req.params.id, tipo, monto, concepto||'', req.tenantId]);
    res.json(rows[0]);
  }catch(e){ res.status(500).json({error:e.message}); }
});
app.delete('/api/cuenta-corriente/:id', authPerm('usuarios'), async (req,res)=>{
  try{ await pool.query('DELETE FROM cuenta_corriente WHERE id=$1 AND tenant_id=$2', [req.params.id, req.tenantId]); res.json({ok:true}); }
  catch(e){ res.status(500).json({error:e.message}); }
});
app.get('/api/usuarios/:id/historial', authPerm('usuarios'), async (req,res)=>{
  try{
    const {rows:pedidos}=await pool.query(`SELECT p.*, s.nombre as seccion_nombre, s.color as seccion_color FROM pedidos p LEFT JOIN secciones s ON p.seccion_id=s.id WHERE p.usuario_id=$1 AND p.tenant_id=$2 ORDER BY p.created_at DESC LIMIT 100`, [req.params.id, req.tenantId]);
    const activos=pedidos.filter(p=>p.tipo==='pedido' && !['cancelado','anulado','rechazado'].includes(String(p.estado).toLowerCase()));
    const totalGastado=activos.reduce((s,p)=>s+Number(p.total||0),0);
    const cantPedidos=pedidos.filter(p=>p.tipo==='pedido').length;
    const cantPresup=pedidos.filter(p=>p.tipo==='presupuesto').length;
    res.json({ pedidos, resumen:{ totalGastado, cantPedidos, cantPresup, ultimaCompra: pedidos.find(p=>p.tipo==='pedido')?.created_at || null } });
  }catch(e){ res.status(500).json({error:e.message}); }
});
app.get('/api/usuarios', authPerm('usuarios'), async (req,res)=>{
  try{ const {q}=req.query; let query='SELECT * FROM usuarios WHERE tenant_id=$1 ORDER BY created_at DESC'; const params=[req.tenantId]; if(q){ query="SELECT * FROM usuarios WHERE tenant_id=$1 AND (nombre ILIKE $2 OR usuario ILIKE $2 OR nombre_fantasia ILIKE $2 OR email ILIKE $2 OR telefono ILIKE $2) ORDER BY created_at DESC"; params.push(`%${q}%`); } const {rows}=await pool.query(query, params); res.json(rows.map(u=>({...u,password:undefined}))); }catch(e){ res.status(500).json({error:e.message}); }
});
app.get('/api/usuarios/pendientes/count', authPerm('usuarios'), async (req,res)=>{ try{ const {rows}=await pool.query("SELECT COUNT(*) FROM usuarios WHERE aprobado=false AND activo=false AND tenant_id=$1", [req.tenantId]); res.json({count:parseInt(rows[0].count)}); }catch{ res.json({count:0}); } });
app.put('/api/usuarios/:id', authPerm('usuarios'), async (req,res)=>{
  try{
    const u=req.body; const sets=[]; const params=[]; let pi=1;
    const fields=['nombre','usuario','telefono','email','direccion','nombre_fantasia','rol','lista_precio_id','activo','aprobado','permisos','notas_admin','es_revendedor','descuento_revendedor'];
    for(const f of fields){ if(u[f]!==undefined){ sets.push(`${f}=$${pi++}`); params.push(u[f]); } }
    if(u.password){ const hash=await bcrypt.hash(u.password,10); sets.push(`password=$${pi++}`); params.push(hash); }
    if(!sets.length) return res.json({ok:true});
    params.push(req.params.id); params.push(req.tenantId);
    await pool.query(`UPDATE usuarios SET ${sets.join(',')} WHERE id=$${pi} AND tenant_id=$${pi+1}`, params);
    res.json({ok:true});
  }catch(e){ res.status(500).json({error:e.message}); }
});
app.post('/api/usuarios/:id/aprobar', authPerm('usuarios'), async (req,res)=>{ try{ const {lista_precio_id}=req.body; await pool.query('UPDATE usuarios SET aprobado=true, activo=true, lista_precio_id=$1 WHERE id=$2 AND tenant_id=$3', [lista_precio_id||'', req.params.id, req.tenantId]); const {rows}=await pool.query('SELECT * FROM usuarios WHERE id=$1 AND tenant_id=$2', [req.params.id, req.tenantId]); res.json({ok:true, user:{...rows[0], password:undefined}}); }catch(e){ res.status(500).json({error:e.message}); } });
app.post('/api/usuarios/:id/rechazar', authPerm('usuarios'), async (req,res)=>{ try{ await pool.query('UPDATE usuarios SET activo=false WHERE id=$1 AND tenant_id=$2', [req.params.id, req.tenantId]); res.json({ok:true}); }catch(e){ res.status(500).json({error:e.message}); } });
app.post('/api/usuarios/:id/suspender', authPerm('usuarios'), async (req,res)=>{ try{ const {activo}=req.body; await pool.query('UPDATE usuarios SET activo=$1 WHERE id=$2 AND tenant_id=$3', [activo, req.params.id, req.tenantId]); res.json({ok:true}); }catch(e){ res.status(500).json({error:e.message}); } });
// RESET MEJORADO - codigo largo
app.post('/api/usuarios/:id/reset-password', authPerm('usuarios'), async (req,res)=>{
  try{
    const codigo='KICKS-'+crypto.randomBytes(4).toString('hex').toUpperCase();
    const hash=await bcrypt.hash(codigo,10);
    await pool.query('UPDATE usuarios SET password=$1, reset_codigo=$2, reset_expira=NOW()+INTERVAL \'24 hours\' WHERE id=$3 AND tenant_id=$4', [hash, codigo, req.params.id, req.tenantId]);
    const {rows}=await pool.query('SELECT nombre,telefono,email FROM usuarios WHERE id=$1 AND tenant_id=$2', [req.params.id, req.tenantId]);
    res.json({ok:true, codigo, nombre:rows[0]?.nombre, telefono:rows[0]?.telefono, email:rows[0]?.email});
  }catch(e){ res.status(500).json({error:e.message}); }
});
app.delete('/api/usuarios/:id', authPerm('usuarios'), async (req,res)=>{ try{ await pool.query('DELETE FROM pedido_items WHERE pedido_id IN (SELECT id FROM pedidos WHERE usuario_id=$1 AND tenant_id=$2)', [req.params.id, req.tenantId]); await pool.query('DELETE FROM pedidos WHERE usuario_id=$1 AND tenant_id=$2', [req.params.id, req.tenantId]); await pool.query('DELETE FROM usuarios WHERE id=$1 AND tenant_id=$2', [req.params.id, req.tenantId]); res.json({ok:true}); }catch(e){ res.status(500).json({error:e.message}); } });

// PEDIDOS V4 - transaccion + is_test + costo_envio
app.get('/api/pedidos', auth(), async (req,res)=>{
  try{
    const {all,archivado,seccion_id,tipo,is_test}=req.query;
    let where=['p.tenant_id=$1']; const params=[req.tenantId];
    // Leer rol+permisos SIEMPRE de la DB (no del token, que puede estar viejo)
    const {rows:ur}=await pool.query('SELECT rol, permisos FROM usuarios WHERE id=$1 AND tenant_id=$2',[req.user.id, req.tenantId]).catch(()=>({rows:[]}));
    const rolActual=String((ur[0]||{}).rol||req.user.rol||'');
    const permsActual=String((ur[0]||{}).permisos||'').split(',').filter(Boolean);
    // admin ve todo; subadmin con permiso 'pedidos' también; el resto solo lo suyo
    const esStaff = rolActual==='admin' || (rolActual==='subadmin' && permsActual.includes('pedidos'));
    if(esStaff){ if(archivado==='true') where.push('p.archivado=true'); else where.push('p.archivado=false'); if(is_test==='false') where.push('p.is_test=false'); }
    else{ where.push(`p.usuario_id=$${params.length+1}`); params.push(req.user.id); }
    if(seccion_id){ where.push(`p.seccion_id=$${params.length+1}`); params.push(seccion_id); }
    if(tipo){ where.push(`p.tipo=$${params.length+1}`); params.push(tipo); }
    const {rows}=await pool.query(`SELECT p.*, u.nombre as usuario_nombre, u.telefono as usuario_telefono, u.email as usuario_email, u.nombre_fantasia, s.nombre as seccion_nombre, s.color as seccion_color FROM pedidos p LEFT JOIN usuarios u ON p.usuario_id=u.id LEFT JOIN secciones s ON p.seccion_id=s.id WHERE ${where.join(' AND ')} ORDER BY p.created_at DESC LIMIT 500`, params);
    res.json(rows);
  }catch(e){ res.status(500).json({error:e.message}); }
});
app.get('/api/pedidos/:id', auth(), async (req,res)=>{ try{ const {rows}=await pool.query('SELECT p.*, u.nombre as usuario_nombre, u.telefono as usuario_telefono, u.email as usuario_email, u.nombre_fantasia, u.direccion as usuario_direccion, s.nombre as seccion_nombre, s.color as seccion_color FROM pedidos p LEFT JOIN usuarios u ON p.usuario_id=u.id LEFT JOIN secciones s ON p.seccion_id=s.id WHERE p.id=$1 AND p.tenant_id=$2', [req.params.id, req.tenantId]); if(!rows[0]) return res.status(404).json({error:'No encontrado'}); const {rows:items}=await pool.query('SELECT * FROM pedido_items WHERE pedido_id=$1', [req.params.id]); const {rows:pagos}=await pool.query('SELECT * FROM pedido_pagos WHERE pedido_id=$1 ORDER BY created_at', [req.params.id]); res.json({...rows[0], items, pagos}); }catch(e){ res.status(500).json({error:e.message}); } });

// Pedido simple + pedido multi-tienda con transaccion
app.post('/api/pedidos', auth(), async (req,res)=>{
  const client=await pool.connect();
  try{
    const {seccion_id,items,tipo,metodo_pago,notas,cupon_codigo,subtotal,descuento,total,datos_envio,notificar_wa,costo_envio,metodo_envio,cp_destino,is_test,usuario_id}=req.body;
    await client.query('BEGIN');
    const esPresupuesto = tipo === 'presupuesto';
    // Si es admin/subadmin y manda usuario_id (ej presupuesto para un cliente), usarlo; si no, el usuario logueado
    const esAdmin = ['admin','subadmin'].includes(req.user.rol);
    const pedidoUserId = (esAdmin && usuario_id !== undefined) ? usuario_id : req.user.id;
    // Validar stock solo si NO es presupuesto
    if (!esPresupuesto) {
    for(const item of (items||[])){
      const {rows:prod}=await client.query('SELECT stock, permitir_sin_stock, es_digital, seccion_id, es_preventa, preventa_cupo, preventa_reservado FROM productos WHERE id=$1', [item.producto_id]);
      if(!prod[0]) continue;
      // Preventa: validar contra cupo (si cupo>0). Cupo 0 = ilimitado
      if(item._preventa || prod[0].es_preventa){
        const cupo=Number(prod[0].preventa_cupo)||0;
        const reservado=Number(prod[0].preventa_reservado)||0;
        if(cupo>0 && (reservado + (item.cantidad||1)) > cupo){
          await client.query('ROLLBACK');
          return res.status(400).json({error:`Preventa agotada: ${item.nombre_producto||''} (quedan ${Math.max(0,cupo-reservado)} de ${cupo})`});
        }
        continue;
      }
      const sec=await client.query('SELECT ignorar_stock, permitir_sin_stock FROM secciones WHERE id=$1', [prod[0].seccion_id]).then(r=>r.rows[0]).catch(()=>null);
      const puedeSinStock = prod[0].permitir_sin_stock || prod[0].es_digital || sec?.permitir_sin_stock || sec?.ignorar_stock;
      if(!puedeSinStock && prod[0].stock < (item.cantidad||1)){
        await client.query('ROLLBACK');
        return res.status(400).json({error:`Sin stock: ${item.nombre_producto||''} stock:${prod[0].stock}`});
      }
    }
    }
    const esReserva = (items||[]).some(it => it._preventa === true);
    const {rows}=await client.query('INSERT INTO pedidos (tenant_id,usuario_id,seccion_id,tipo,metodo_pago,notas,cupon_codigo,subtotal,descuento,total,datos_envio,notificar_wa,costo_envio,metodo_envio,cp_destino,is_test,estado,estado_pago,sena,es_reserva) VALUES ($20,$1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19) RETURNING *',
      [pedidoUserId, seccion_id, tipo||'pedido', metodo_pago||'', notas||'', cupon_codigo||'', subtotal||0, descuento||0, total||0, datos_envio||'', notificar_wa!==false, costo_envio||0, metodo_envio||'', cp_destino||'', is_test||false, req.body.estado||'pendiente', req.body.estado_pago||'impago', req.body.sena||0, esReserva, req.tenantId]);
    for(const item of (items||[])){
      await client.query('INSERT INTO pedido_items (tenant_id,pedido_id,producto_id,categoria,modelo,nombre_producto,cantidad,precio_unitario,precio_base,variante_id,variante_combinacion) VALUES ($9,$1,$2,$3,$4,$5,$6,$7,$8,$10,$11)',
        [rows[0].id, item.producto_id, item.categoria||'', item.modelo||'', item.nombre_producto||'', item.cantidad||1, item.precio_unitario||0, item.precio_base||0, req.tenantId, item.variante_id||null, item.variante_label||item.variante_combinacion||'']);
      // Descontar stock solo si NO es presupuesto
      if (!esPresupuesto) {
      if(item.variante_id){
        // Variante: descontar stock de la combinación elegida
        await client.query('UPDATE variantes SET stock = GREATEST(0, stock - $1) WHERE id=$2 AND tenant_id=$3', [item.cantidad||1, item.variante_id, req.tenantId]);
      } else {
      const {rows:prod}=await client.query('SELECT permitir_sin_stock, es_digital, es_preventa FROM productos WHERE id=$1', [item.producto_id]);
      if(prod[0] && (prod[0].es_preventa || item._preventa)){
        // Preventa: aumentar reservado, NO tocar stock físico
        await client.query('UPDATE productos SET preventa_reservado = COALESCE(preventa_reservado,0) + $1 WHERE id=$2', [item.cantidad||1, item.producto_id]);
      } else if(prod[0] && !prod[0].permitir_sin_stock && !prod[0].es_digital){
        await client.query('UPDATE productos SET stock = GREATEST(0, stock - $1) WHERE id=$2 AND permitir_sin_stock=false AND es_digital=false', [item.cantidad||1, item.producto_id]);
      }
      }
      }
    }
    if(cupon_codigo) await client.query("UPDATE cupones SET usos_actuales = usos_actuales + 1 WHERE codigo=$1 AND tenant_id=$2", [cupon_codigo, req.tenantId]).catch(()=>{});
    // Cuenta corriente automática: SOLO si el pedido se marca como "debe" (fiado). Impago normal no genera deuda de cuenta corriente.
    const ep=String(req.body.estado_pago||'impago');
    const senaMonto=Number(req.body.sena)||0;
    if(pedidoUserId && ep==='debe'){
      const deuda = Number(total||0) - senaMonto;
      if(deuda>0){
        await client.query('INSERT INTO cuenta_corriente (tenant_id,usuario_id,tipo,monto,concepto,pedido_id) VALUES ($6,$1,$2,$3,$4,$5)',
          [pedidoUserId, 'cargo', deuda, `Pedido #${String(rows[0].id).padStart(4,'0')}`, rows[0].id, req.tenantId]).catch(()=>{});
      }
    }
    // Pagos iniciales (venta de mostrador con pagos mixtos)
    if(Array.isArray(req.body.pagos) && req.body.pagos.length){
      for(const pg of req.body.pagos){
        const rec=Number(pg.recibido)||0, cta=Number(pg.cuenta_como)||0;
        if(rec>0 || cta>0){
          await client.query('INSERT INTO pedido_pagos (tenant_id,pedido_id,metodo,monto,recibido,cuenta_como,ajuste_pct,ajuste_monto,nota) VALUES ($9,$1,$2,$3,$4,$5,$6,$7,$8)',
            [rows[0].id, pg.metodo||'', rec, rec, cta, Number(pg.ajuste_pct)||0, cta-rec, pg.nota||'', req.tenantId]);
        }
      }
    }
    await client.query('COMMIT');
    res.json(rows[0]);
  }catch(e){ await client.query('ROLLBACK').catch(()=>{}); res.status(500).json({error:e.message}); }
  finally{ client.release(); }
});

// Multi-tienda: crea N pedidos (uno por tienda)
app.post('/api/pedidos/multi', auth(), async (req,res)=>{
  const client=await pool.connect();
  try{
    const {pedidos, is_test} = req.body; // pedidos = [{seccion_id, items, subtotal, costo_envio, metodo_envio, cp_destino, ...}]
    if(!Array.isArray(pedidos)||!pedidos.length) return res.status(400).json({error:'pedidos requerido'});
    await client.query('BEGIN');
    const creados=[];
    for(const ped of pedidos){
      const {seccion_id, items, subtotal, descuento, total, metodo_pago, notas, cupon_codigo, datos_envio, costo_envio, metodo_envio, cp_destino}=ped;
      // Validar stock por seccion antes de crear (transaccional)
      for(const item of (items||[])){
        const {rows:prod}=await client.query('SELECT stock, permitir_sin_stock, es_digital, seccion_id, es_preventa, preventa_cupo, preventa_reservado FROM productos WHERE id=$1', [item.producto_id]);
        if(!prod[0]) continue;
        // Variante: validar stock de la combinación elegida
        if(item.variante_id){
          const {rows:vr}=await client.query('SELECT stock FROM variantes WHERE id=$1 AND tenant_id=$2', [item.variante_id, req.tenantId]);
          const vsec=await client.query('SELECT ignorar_stock, permitir_sin_stock FROM secciones WHERE id=$1', [prod[0].seccion_id]).then(r=>r.rows[0]).catch(()=>null);
          const vSinStock = prod[0].permitir_sin_stock || prod[0].es_digital || vsec?.permitir_sin_stock || vsec?.ignorar_stock;
          if(vr[0] && !vSinStock && Number(vr[0].stock) < (item.cantidad||1)){
            await client.query('ROLLBACK');
            return res.status(400).json({error:`Sin stock: ${item.nombre_producto||''} (disponible: ${vr[0].stock})`});
          }
          continue;
        }
        // Preventa: validar contra cupo (si cupo>0). Cupo 0 = ilimitado
        if(item._preventa || prod[0].es_preventa){
          const cupo=Number(prod[0].preventa_cupo)||0;
          const reservado=Number(prod[0].preventa_reservado)||0;
          if(cupo>0 && (reservado + (item.cantidad||1)) > cupo){
            await client.query('ROLLBACK');
            return res.status(400).json({error:`Preventa agotada: ${item.nombre_producto||''} (quedan ${Math.max(0,cupo-reservado)} de ${cupo})`});
          }
          continue;
        }
        const sec=await client.query('SELECT ignorar_stock, permitir_sin_stock FROM secciones WHERE id=$1', [prod[0].seccion_id]).then(r=>r.rows[0]).catch(()=>null);
        const puedeSinStock = prod[0].permitir_sin_stock || prod[0].es_digital || sec?.permitir_sin_stock || sec?.ignorar_stock;
        if(!puedeSinStock && prod[0].stock < (item.cantidad||1)){
          await client.query('ROLLBACK');
          return res.status(400).json({error:`Sin stock: ${item.nombre_producto||''} (disponible: ${prod[0].stock})`});
        }
      }
      const {rows}=await client.query('INSERT INTO pedidos (tenant_id,usuario_id,seccion_id,tipo,metodo_pago,notas,cupon_codigo,subtotal,descuento,total,datos_envio,costo_envio,metodo_envio,cp_destino,is_test,datos_facturacion,estado_pago) VALUES ($17,$1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16) RETURNING *',
        [req.user.id, seccion_id, 'pedido', metodo_pago||'', notas||'', cupon_codigo||'', subtotal||0, descuento||0, total||0, datos_envio||'', costo_envio||0, metodo_envio||'', cp_destino||'', is_test||false, ped.datos_facturacion||'', ped.estado_pago||'impago', req.tenantId]);
      for(const item of (items||[])){
        await client.query('INSERT INTO pedido_items (tenant_id,pedido_id,producto_id,categoria,modelo,nombre_producto,cantidad,precio_unitario,precio_base,variante_id,variante_combinacion) VALUES ($9,$1,$2,$3,$4,$5,$6,$7,$8,$10,$11)',
          [rows[0].id, item.producto_id, item.categoria||'', item.modelo||'', item.nombre_producto||'', item.cantidad||1, item.precio_unitario||0, item.precio_base||0, req.tenantId, item.variante_id||null, item.variante_label||item.variante_combinacion||'']);
        if(item.variante_id){
          await client.query('UPDATE variantes SET stock = GREATEST(0, stock - $1) WHERE id=$2 AND tenant_id=$3', [item.cantidad||1, item.variante_id, req.tenantId]);
        } else {
        const {rows:pr}=await client.query('SELECT permitir_sin_stock, es_digital, es_preventa FROM productos WHERE id=$1', [item.producto_id]);
        if(pr[0] && (pr[0].es_preventa || item._preventa)){
          await client.query('UPDATE productos SET preventa_reservado = COALESCE(preventa_reservado,0) + $1 WHERE id=$2', [item.cantidad||1, item.producto_id]);
        } else if(pr[0] && !pr[0].permitir_sin_stock && !pr[0].es_digital){
          await client.query('UPDATE productos SET stock = GREATEST(0, stock - $1) WHERE id=$2 AND permitir_sin_stock=false AND es_digital=false', [item.cantidad||1, item.producto_id]);
        }
        }
      }
      creados.push(rows[0]);
    }
    if(creados[0]?.cupon_codigo) await client.query("UPDATE cupones SET usos_actuales = usos_actuales + 1 WHERE codigo=$1 AND tenant_id=$2", [creados[0].cupon_codigo, req.tenantId]).catch(()=>{});
    await client.query('COMMIT');
    // Notificar al admin por email (nueva venta online)
    notificarVentaAdmin(creados, req.user).catch(()=>{});
    res.json({ok:true, pedidos: creados});
  }catch(e){ await client.query('ROLLBACK').catch(()=>{}); res.status(500).json({error:e.message}); }
  finally{ client.release(); }
});

// ==== PAGOS MIXTOS DE UN PEDIDO ====
// Recalcula estado_pago según la suma de "cuenta_como" (lo que tacha de la deuda)
async function recalcularEstadoPago(pedidoId){
  const {rows:ped}=await pool.query('SELECT total FROM pedidos WHERE id=$1',[pedidoId]);
  if(!ped[0]) return;
  const total=Number(ped[0].total)||0;
  const {rows:pg}=await pool.query('SELECT COALESCE(SUM(cuenta_como),0) as saldado, COALESCE(SUM(recibido),0) as recibido FROM pedido_pagos WHERE pedido_id=$1',[pedidoId]);
  const saldado=Number(pg[0].saldado)||0;
  let estado='impago';
  if(saldado<=0) estado='impago';
  else if(saldado>=total-0.01) estado='pagado';
  else estado='senado';
  await pool.query('UPDATE pedidos SET estado_pago=$1, sena=$2, updated_at=NOW() WHERE id=$3',[estado, saldado>=total?0:saldado, pedidoId]);
  return {estado, saldado, total, recibido:Number(pg[0].recibido)||0};
}
app.get('/api/pedidos/:id/pagos', auth(), async (req,res)=>{
  try{ const {rows}=await pool.query('SELECT * FROM pedido_pagos WHERE pedido_id=$1 ORDER BY created_at',[req.params.id]); res.json(rows); }
  catch(e){ res.status(500).json({error:e.message}); }
});

// Historial de cambios del pedido (estado de pago, quién y cuándo) — para auditoría
app.get('/api/pedidos/:id/historial', authPerm('pedidos'), async (req,res)=>{
  try{ const {rows}=await pool.query('SELECT * FROM pedido_historial WHERE pedido_id=$1 AND tenant_id=$2 ORDER BY created_at DESC',[req.params.id, req.tenantId]); res.json(rows); }
  catch(e){ res.status(500).json({error:e.message}); }
});
app.post('/api/pedidos/:id/pagos', authPerm('pedidos'), async (req,res)=>{
  try{
    const {metodo,recibido,cuenta_como,ajuste_pct,nota}=req.body;
    const rec=Number(recibido)||0, cta=Number(cuenta_como)||0;
    if(!(rec>0) && !(cta>0)) return res.status(400).json({error:'El monto debe ser mayor a 0'});
    const ajusteMonto=cta-rec;
    await pool.query('INSERT INTO pedido_pagos (tenant_id,pedido_id,metodo,monto,recibido,cuenta_como,ajuste_pct,ajuste_monto,nota) SELECT $9,$1,$2,$3,$4,$5,$6,$7,$8 WHERE EXISTS(SELECT 1 FROM pedidos WHERE id=$1 AND tenant_id=$9)',
      [req.params.id, metodo||'', rec, rec, cta, Number(ajuste_pct)||0, ajusteMonto, nota||'', req.tenantId]);
    const r=await recalcularEstadoPago(req.params.id);
    res.json({ok:true, ...r});
  }catch(e){ res.status(500).json({error:e.message}); }
});
app.delete('/api/pedidos/:id/pagos/:pagoId', authPerm('pedidos'), async (req,res)=>{
  try{
    await pool.query('DELETE FROM pedido_pagos WHERE id=$1 AND pedido_id=$2',[req.params.pagoId, req.params.id]);
    const r=await recalcularEstadoPago(req.params.id);
    res.json({ok:true, ...r});
  }catch(e){ res.status(500).json({error:e.message}); }
});

app.put('/api/pedidos/:id', authPerm('pedidos'), async (req,res)=>{  try{
    const p=req.body; const sets=[]; const params=[]; let pi=1;
    // Capturar estado + tipo + items ANTES de cambios
    const {rows:oldItemsRows}=await pool.query('SELECT producto_id, cantidad FROM pedido_items WHERE pedido_id=$1', [req.params.id]);
    const oldMap={}; for(const it of oldItemsRows){ if(it.producto_id) oldMap[it.producto_id]=(oldMap[it.producto_id]||0)+(it.cantidad||0); }
    const {rows:oldPedRows}=await pool.query('SELECT estado, tipo, estado_pago, usuario_id, total, sena FROM pedidos WHERE id=$1 AND tenant_id=$2', [req.params.id, req.tenantId]);
    if(!oldPedRows[0]) return res.status(404).json({error:'No encontrado'});
    const oldEstado=String((oldPedRows[0]||{}).estado||'').toLowerCase();
    const oldTipo=String((oldPedRows[0]||{}).tipo||'');
    const oldEstadoPago=String((oldPedRows[0]||{}).estado_pago||'');
    const pedUsuarioId=(oldPedRows[0]||{}).usuario_id;
    const fields=['estado','tipo','metodo_pago','notas','total','subtotal','descuento','datos_envio','usuario_id','notificar_wa','is_test','costo_envio','metodo_envio','cp_destino','estado_pago','sena'];
    for(const f of fields){ if(p[f]!==undefined){ sets.push(`${f}=$${pi++}`); params.push(p[f]); } }
    sets.push(`updated_at=NOW()`);
    if(sets.length<=1) return res.json({ok:true});
    params.push(req.params.id);
    params.push(req.tenantId); await pool.query(`UPDATE pedidos SET ${sets.join(',')} WHERE id=$${pi} AND tenant_id=$${pi+1}`, params);

    // ── CUENTA CORRIENTE automática al cambiar estado de pago ──
    const nuevoEstadoPago = (p.estado_pago!==undefined) ? String(p.estado_pago) : oldEstadoPago;
    if(pedUsuarioId && nuevoEstadoPago !== oldEstadoPago){
      // ── HISTORIAL: registrar quién cambió el estado y cuándo ──
      try {
        const labels = { impago:'Impago', senado:'Señado', pagado:'Pagado', debe:'Debe', pendiente:'Impago' };
        const de = labels[oldEstadoPago] || oldEstadoPago || 'Impago';
        const a = labels[nuevoEstadoPago] || nuevoEstadoPago;
        const rolLabel = req.user?.rol === 'admin' ? 'dueño' : (req.user?.rol === 'subadmin' ? 'empleado' : (req.user?.rol || ''));
        const quien = (req.user?.usuario || 'sistema') + (rolLabel ? ` (${rolLabel})` : '');
        await pool.query(
          'INSERT INTO pedido_historial (tenant_id,pedido_id,tipo,detalle,usuario_id,usuario_nombre) VALUES ($1,$2,$3,$4,$5,$6)',
          [req.tenantId, req.params.id, 'estado_pago', `Estado de pago: ${de} → ${a}`, req.user?.id || null, quien]
        );
      } catch(e){}
      // ── AUTO-PAGO: si pasa a "pagado", registrar un pago por el total (si no hay pagos ya) ──
      if(nuevoEstadoPago==='pagado'){
        try {
          const {rows:pagosYa}=await pool.query('SELECT COALESCE(SUM(cuenta_como),0) as saldado FROM pedido_pagos WHERE pedido_id=$1', [req.params.id]);
          const yaSaldado=Number(pagosYa[0]?.saldado||0);
          const totalPed=(p.total!==undefined)?Number(p.total):Number((oldPedRows[0]||{}).total||0);
          const falta=totalPed-yaSaldado;
          if(falta>0.01){
            await pool.query(
              'INSERT INTO pedido_pagos (tenant_id,pedido_id,metodo,monto,recibido,cuenta_como,ajuste_pct,ajuste_monto,nota) VALUES ($1,$2,$3,$4,$5,$6,0,0,$7)',
              [req.tenantId, req.params.id, (p.metodo_pago||'efectivo'), falta, falta, falta, 'Marcado como pagado']
            ).catch(()=>{});
          }
        } catch(e){}
      }
      if(nuevoEstadoPago==='debe' && oldEstadoPago!=='debe'){
        // Pasó a "debe" (fiado): registrar cargo si no existe ya para este pedido
        const {rows:ya}=await pool.query("SELECT id FROM cuenta_corriente WHERE pedido_id=$1 AND tipo='cargo'", [req.params.id]);
        if(!ya.length){
          const totalPed=(p.total!==undefined)?Number(p.total):Number((oldPedRows[0]||{}).total||0);
          const senaPed=(p.sena!==undefined)?Number(p.sena):Number((oldPedRows[0]||{}).sena||0);
          const deuda=totalPed-senaPed;
          if(deuda>0) await pool.query('INSERT INTO cuenta_corriente (usuario_id,tipo,monto,concepto,pedido_id) VALUES ($1,$2,$3,$4,$5)', [pedUsuarioId,'cargo',deuda,`Pedido #${String(req.params.id).padStart(4,'0')}`,req.params.id]).catch(()=>{});
        }
      } else if(oldEstadoPago==='debe' && nuevoEstadoPago!=='debe'){
        // Salió de "debe" (se pagó): quitar el cargo automático de este pedido
        await pool.query("DELETE FROM cuenta_corriente WHERE pedido_id=$1 AND tipo='cargo'", [req.params.id]).catch(()=>{});
      }
    }
    if(p.items){
      // Capturar productos afectados (viejos + nuevos) para recalcular preventa
      const {rows:viejos}=await pool.query('SELECT DISTINCT producto_id FROM pedido_items WHERE pedido_id=$1', [req.params.id]);
      await pool.query('DELETE FROM pedido_items WHERE pedido_id=$1', [req.params.id]);
      for(const item of p.items){ await pool.query('INSERT INTO pedido_items (pedido_id,producto_id,categoria,modelo,nombre_producto,cantidad,precio_unitario,precio_base) VALUES ($1,$2,$3,$4,$5,$6,$7,$8)', [req.params.id, item.producto_id||item.id, item.categoria||'', item.modelo||'', item.nombre_producto||`${item.categoria} - ${item.modelo}`, item.cantidad||item.qty||1, item.precio_unitario||0, item.precio_base||0]); }
      // Recalcular reservado de preventa para todos los productos tocados
      const afectados=new Set([...viejos.map(v=>v.producto_id), ...p.items.map(it=>it.producto_id||it.id)].filter(Boolean));
      for(const pid of afectados) await recalcReservado(pid);
    }

    // ── RECONCILIACIÓN DE STOCK ──
    // Regla: el stock SOLO lo afectan PEDIDOS reales activos (no presupuestos, no cancelados).
    // "afectaStock" = es pedido Y no está cancelado. Comparamos estado ANTES vs DESPUÉS.
    const nuevoEstado=(p.estado!==undefined)?String(p.estado).toLowerCase():oldEstado;
    const nuevoTipo=(p.tipo!==undefined)?String(p.tipo):oldTipo;
    const cancelSt=['cancelado','anulado','rechazado'];
    const afectabaStock = oldTipo==='pedido' && !cancelSt.includes(oldEstado);   // antes descontaba
    const afectaStock   = nuevoTipo==='pedido' && !cancelSt.includes(nuevoEstado); // ahora descuenta
    // items nuevos (si se editaron) o los viejos
    const itemsNuevos = p.items ? p.items.map(it=>({pid:it.producto_id||it.id, qty:it.cantidad||it.qty||0})) : oldItemsRows.map(it=>({pid:it.producto_id, qty:it.cantidad||0}));
    const newMap={}; for(const it of itemsNuevos){ if(it.pid) newMap[it.pid]=(newMap[it.pid]||0)+it.qty; }
    const stockAdd={};
    if(!afectabaStock && afectaStock){
      // Pasó a descontar (presupuesto→pedido, o reactivación de cancelado): restar todo el nuevo
      for(const pid in newMap) stockAdd[pid]=(stockAdd[pid]||0)-newMap[pid];
    } else if(afectabaStock && !afectaStock){
      // Dejó de descontar (pedido→presupuesto, o se canceló): devolver todo lo viejo
      for(const pid in oldMap) stockAdd[pid]=(stockAdd[pid]||0)+oldMap[pid];
    } else if(afectabaStock && afectaStock && p.items){
      // Sigue siendo pedido activo pero cambiaron items: ajustar delta (viejo - nuevo)
      const pids=new Set([...Object.keys(oldMap),...Object.keys(newMap)]);
      for(const pid of pids){ const d=(oldMap[pid]||0)-(newMap[pid]||0); if(d!==0) stockAdd[pid]=(stockAdd[pid]||0)+d; }
    }
    // Si no afectaba ni afecta (presupuesto→presupuesto), no se toca nada.
    for(const pid in stockAdd){
      const q=stockAdd[pid]; if(!q) continue;
      // No tocar stock de productos en preventa (su cupo se maneja aparte con preventa_reservado)
      const {rows:esPre}=await pool.query('SELECT es_preventa FROM productos WHERE id=$1', [pid]);
      if(esPre[0] && esPre[0].es_preventa){ await recalcReservado(pid); continue; }
      await pool.query('UPDATE productos SET stock=GREATEST(0, stock + $1) WHERE id=$2 AND permitir_sin_stock=false AND es_digital=false', [q, pid]);
    }
    // Recalcular reservado si cambió el estado (cancelación/reactivación) para productos del pedido
    if(p.estado!==undefined && !p.items){
      for(const it of oldItemsRows){ if(it.producto_id) await recalcReservado(it.producto_id); }
    }
    res.json({ok:true});
  }catch(e){ res.status(500).json({error:e.message}); }
});
app.post('/api/pedidos/:id/archivar', authPerm('pedidos'), async (req,res)=>{ try{ await pool.query('UPDATE pedidos SET archivado=true WHERE id=$1 AND tenant_id=$2', [req.params.id, req.tenantId]); res.json({ok:true}); }catch(e){ res.status(500).json({error:e.message}); } });
app.post('/api/pedidos/:id/desarchivar', authPerm('pedidos'), async (req,res)=>{ try{ await pool.query('UPDATE pedidos SET archivado=false WHERE id=$1 AND tenant_id=$2', [req.params.id, req.tenantId]); res.json({ok:true}); }catch(e){ res.status(500).json({error:e.message}); } });
app.delete('/api/pedidos/:id', authPerm('pedidos'), async (req,res)=>{ try{ const {rows:oep}=await pool.query('SELECT estado, tipo FROM pedidos WHERE id=$1 AND tenant_id=$2',[req.params.id, req.tenantId]); if(!oep[0]) return res.status(404).json({error:'No encontrado'}); const oe=String((oep[0]||{}).estado||'').toLowerCase(); const ot=String((oep[0]||{}).tipo||''); const afectabaStock = ot==='pedido' && !['cancelado','anulado','rechazado'].includes(oe); const {rows:its}=await pool.query('SELECT producto_id, cantidad, variante_id FROM pedido_items WHERE pedido_id=$1',[req.params.id]); const preIds=[]; if(afectabaStock){ for(const it of its){ if(it.variante_id){ await pool.query('UPDATE variantes SET stock=GREATEST(0, stock + $1) WHERE id=$2 AND tenant_id=$3',[it.cantidad||0, it.variante_id, req.tenantId]); continue; } if(!it.producto_id) continue; const {rows:pp}=await pool.query('SELECT es_preventa FROM productos WHERE id=$1',[it.producto_id]); if(pp[0] && pp[0].es_preventa){ preIds.push(it.producto_id); } else { await pool.query('UPDATE productos SET stock=GREATEST(0, stock + $1) WHERE id=$2 AND permitir_sin_stock=false AND es_digital=false',[it.cantidad||0, it.producto_id]); } } } await pool.query('DELETE FROM pedido_items WHERE pedido_id=$1', [req.params.id]); await pool.query('DELETE FROM pedidos WHERE id=$1 AND tenant_id=$2', [req.params.id, req.tenantId]); for(const pid of preIds) await recalcReservado(pid); res.json({ok:true}); }catch(e){ res.status(500).json({error:e.message}); } });

// STATS
// REPORTES: más vendidos, ventas por sección, por mes, ganancias
// ==== CAJA / ARQUEO ==== (plata real cobrada, online + presencial)
app.get('/api/caja', authPerm('stats'), async (req,res)=>{
  try{
    const {desde,hasta}=req.query;
    const cond=['pp.tenant_id=$1']; const params=[req.tenantId];
    if(desde){ params.push(desde); cond.push(`pp.created_at >= $${params.length}`); }
    if(hasta){ params.push(hasta); cond.push(`pp.created_at <= $${params.length}`); }
    const where=`WHERE ${cond.join(' AND ')}`;
    const {rows:porMetodo}=await pool.query(
      `SELECT COALESCE(NULLIF(pp.metodo,''),'sin método') as metodo,
              COALESCE(SUM(pp.recibido),0) as recibido,
              COALESCE(SUM(pp.cuenta_como),0) as saldado
       FROM pedido_pagos pp ${where}
       GROUP BY pp.metodo ORDER BY recibido DESC`, params);
    const {rows:aj}=await pool.query(
      `SELECT COALESCE(SUM(CASE WHEN pp.ajuste_monto<0 THEN -pp.ajuste_monto ELSE 0 END),0) as descuentos,
              COALESCE(SUM(CASE WHEN pp.ajuste_monto>0 THEN pp.ajuste_monto ELSE 0 END),0) as recargos,
              COALESCE(SUM(pp.recibido),0) as total_recibido,
              COALESCE(SUM(pp.cuenta_como),0) as total_saldado
       FROM pedido_pagos pp ${where}`, params);
    res.json({ porMetodo, ...aj[0] });
  }catch(e){ res.status(500).json({error:e.message}); }
});
app.get('/api/reportes', authPerm('stats'), async (req,res)=>{
  try{
    const {desde, hasta, seccion_id}=req.query;
    const cond=["p.tenant_id=$1", "p.tipo='pedido'", "LOWER(p.estado) NOT IN ('cancelado','anulado','rechazado')"]; const params=[req.tenantId]; let pi=2;
    if(desde){ cond.push(`p.created_at >= $${pi}`); params.push(desde); pi++; }
    if(hasta){ cond.push(`p.created_at <= $${pi}`); params.push(hasta+' 23:59:59'); pi++; }
    if(seccion_id && seccion_id!=='all'){ cond.push(`p.seccion_id = $${pi}`); params.push(seccion_id); pi++; }
    const where='WHERE '+cond.join(' AND ');

    // Más vendidos (por cantidad)
    const masVendidos=await pool.query(`SELECT pi.producto_id, pi.nombre_producto, SUM(pi.cantidad)::int as unidades, SUM(pi.cantidad*pi.precio_unitario)::numeric as facturado
      FROM pedido_items pi JOIN pedidos p ON pi.pedido_id=p.id ${where} GROUP BY pi.producto_id, pi.nombre_producto ORDER BY unidades DESC LIMIT 20`, params);

    // Ventas por sección (con ganancias por tienda)
    const porSeccion=await pool.query(`SELECT s.id as seccion_id, s.nombre as seccion, COUNT(DISTINCT p.id)::int as pedidos, COALESCE(SUM(p.total),0)::numeric as total
      FROM pedidos p LEFT JOIN secciones s ON p.seccion_id=s.id ${where} GROUP BY s.id, s.nombre ORDER BY total DESC`, params);

    // Ganancia por sección (facturado - costo por tienda)
    const gananciaPorSeccion=await pool.query(`SELECT p.seccion_id,
      COALESCE(SUM(pi.cantidad*pi.precio_unitario),0)::numeric as facturado,
      COALESCE(SUM(pi.cantidad*COALESCE(NULLIF(pr.precio_original,0),0)),0)::numeric as costo
      FROM pedido_items pi JOIN pedidos p ON pi.pedido_id=p.id LEFT JOIN productos pr ON pi.producto_id=pr.id ${where} GROUP BY p.seccion_id`, params);
    const gxs={}; gananciaPorSeccion.rows.forEach(r=>{ gxs[r.seccion_id]={ facturado:Number(r.facturado), costo:Number(r.costo), ganancia:Number(r.facturado)-Number(r.costo) }; });
    const porSeccionConGanancia = porSeccion.rows.map(s=>({ ...s, facturado: gxs[s.seccion_id]?.facturado||0, costo: gxs[s.seccion_id]?.costo||0, ganancia: gxs[s.seccion_id]?.ganancia||0 }));

    // Ventas por mes
    const porMes=await pool.query(`SELECT TO_CHAR(DATE_TRUNC('month', p.created_at),'YYYY-MM') as mes, COUNT(*)::int as pedidos, COALESCE(SUM(p.total),0)::numeric as total
      FROM pedidos p ${where} GROUP BY mes ORDER BY mes DESC LIMIT 12`, params);

    // Ganancias (facturado - costo, usando precio_original del producto)
    const ganancias=await pool.query(`SELECT COALESCE(SUM(pi.cantidad*pi.precio_unitario),0)::numeric as facturado,
      COALESCE(SUM(pi.cantidad*COALESCE(NULLIF(pr.precio_original,0), 0)),0)::numeric as costo
      FROM pedido_items pi JOIN pedidos p ON pi.pedido_id=p.id LEFT JOIN productos pr ON pi.producto_id=pr.id ${where}`, params);

    const g=ganancias.rows[0]||{facturado:0,costo:0};
    res.json({
      masVendidos: masVendidos.rows,
      porSeccion: porSeccionConGanancia,
      porMes: porMes.rows,
      ganancias: { facturado: Number(g.facturado), costo: Number(g.costo), ganancia: Number(g.facturado)-Number(g.costo) }
    });
  }catch(e){ res.status(500).json({error:e.message}); }
});
app.get('/api/stats', authPerm('stats'), async (req,res)=>{
  try{
    const {seccion_id,desde,hasta,is_test}=req.query;
    // tenant_id siempre es $1; el resto se agrega después
    const params=[req.tenantId];
    let secWhere=''; if(seccion_id && seccion_id!=='all'){ params.push(seccion_id); secWhere=` AND seccion_id=$${params.length}`; }
    let dateWhere='';
    if(desde){ params.push(desde); dateWhere+=` AND created_at >= $${params.length}`; }
    if(hasta){ params.push(hasta); dateWhere+=` AND created_at <= $${params.length}`; }
    let testWhere=''; if(is_test==='false') testWhere=' AND is_test=false';
    const totalPedidos=await pool.query(`SELECT COUNT(*) FROM pedidos WHERE tenant_id=$1 AND archivado=false${secWhere}${dateWhere}${testWhere}`, params);
    const totalVentas=await pool.query(`SELECT COALESCE(SUM(total),0) as total FROM pedidos WHERE tenant_id=$1 AND estado NOT IN ('cancelado') AND archivado=false${secWhere}${dateWhere}${testWhere}`, params);
    const totalProductos=await pool.query(`SELECT COUNT(*) FROM productos WHERE tenant_id=$1${seccion_id && seccion_id!=='all' ? ' AND seccion_id=$2' : ''}`, seccion_id && seccion_id!=='all' ? [req.tenantId, seccion_id] : [req.tenantId]);
    const totalUsuarios=await pool.query('SELECT COUNT(*) FROM usuarios WHERE rol != $1 AND tenant_id=$2', ['admin', req.tenantId]);
    const ventasPorDia=await pool.query(`SELECT DATE(created_at) as fecha, COUNT(*) as cantidad, COALESCE(SUM(total),0) as total FROM pedidos WHERE tenant_id=$1 AND estado NOT IN ('cancelado') AND archivado=false${secWhere}${dateWhere}${testWhere} GROUP BY DATE(created_at) ORDER BY fecha DESC LIMIT 30`, params);
    const topCat=await pool.query(`SELECT pi.categoria, COUNT(*) as cantidad, SUM(pi.precio_unitario * pi.cantidad) as total FROM pedido_items pi JOIN pedidos p ON pi.pedido_id=p.id WHERE p.tenant_id=$1 AND p.estado NOT IN ('cancelado')${secWhere.replace('seccion_id','p.seccion_id')}${dateWhere.replace('created_at','p.created_at')}${testWhere} GROUP BY pi.categoria ORDER BY total DESC LIMIT 10`, params);
    const abandonados=await pool.query('SELECT COUNT(*) FROM carritos_abandonados WHERE recuperado=false AND tenant_id=$1', [req.tenantId]).catch(()=>({rows:[{count:0}]}));
    res.json({ total_pedidos: parseInt(totalPedidos.rows[0].count), total_ventas: parseFloat(totalVentas.rows[0].total), total_productos: parseInt(totalProductos.rows[0].count), total_usuarios: parseInt(totalUsuarios.rows[0].count), ventas_por_dia: ventasPorDia.rows, top_categorias: topCat.rows, carritos_abandonados: parseInt(abandonados.rows[0].count) });
  }catch(e){ res.status(500).json({error:e.message}); }
});

// CUPONES, PROMOS, POPUPS, REDES, MENU, DESIGN, PAGOS, PAGINAS, BADGES, ENVIO, BUSQUEDA, SLIDER, FAVORITOS, STOCK, ANDREANI (se mantienen igual + fixes Andreani env)
app.get('/api/cupones', authPerm('config'), async (req,res)=>{ try{ const {rows}=await pool.query('SELECT c.*, array_agg(cp.producto_id) FILTER (WHERE cp.producto_id IS NOT NULL) as productos_ids FROM cupones c LEFT JOIN cupon_productos cp ON c.id=cp.cupon_id WHERE c.tenant_id=$1 GROUP BY c.id ORDER BY c.created_at DESC', [req.tenantId]); res.json(rows); }catch(e){ res.status(500).json({error:e.message}); } });
app.post('/api/cupones/validar', async (req,res)=>{
  try{
    const {codigo,seccion_id,subtotal,metodo_pago,items,usuario_id}=req.body;
    const {rows}=await pool.query('SELECT * FROM cupones WHERE codigo=$1 AND activo=true AND tenant_id=$2', [codigo, req.tenantId]);
    if(!rows[0]) return res.status(404).json({error:'Cupón no válido'});
    const c=rows[0];
    if(c.uso_maximo>0 && c.usos_actuales>=c.uso_maximo) return res.status(400).json({error:'Cupón agotado'});
    if(c.solo_primera_compra){
      if(!usuario_id) return res.status(400).json({error:'Iniciá sesión para usar este cupón'});
      const {rows:prev}=await pool.query("SELECT COUNT(*)::int as n FROM pedidos WHERE usuario_id=$1 AND tipo='pedido' AND tenant_id=$2", [usuario_id, req.tenantId]);
      if(prev[0].n>0) return res.status(400).json({error:'Cupón solo para la primera compra'});
    }
    if(c.fecha_desde && new Date()<new Date(c.fecha_desde)) return res.status(400).json({error:'Aún no vigente'});
    if(c.fecha_hasta && new Date()>new Date(c.fecha_hasta)) return res.status(400).json({error:'Vencido'});
    if(c.secciones_ids){ const sids=c.secciones_ids.split(',').map(Number).filter(Boolean); if(sids.length && !sids.includes(Number(seccion_id))) return res.status(400).json({error:'No aplica a esta sección'}); }
    if(c.monto_minimo>0 && subtotal<c.monto_minimo) return res.status(400).json({error:`Monto mínimo: $${c.monto_minimo}`});
    if(c.metodo_pago && metodo_pago && c.metodo_pago!==metodo_pago) return res.status(400).json({error:`Solo válido con ${c.metodo_pago}`});
    const {rows:cpRows}=await pool.query('SELECT producto_id FROM cupon_productos WHERE cupon_id=$1', [c.id]);
    if(cpRows.length>0){ const pids=cpRows.map(r=>r.producto_id); const itemPids=(items||[]).map(i=>i.producto_id||i.id); if(!itemPids.some(p=>pids.includes(p))) return res.status(400).json({error:'No aplica a estos productos'}); }
    let descuento=0;
    if(c.tipo==='porcentaje') descuento=Math.round(subtotal*c.valor/100);
    else if(c.tipo==='monto_fijo') descuento=c.valor;
    res.json({descuento, tipo:c.tipo, valor:c.valor, codigo:c.codigo, cupon_id:c.id});
  }catch(e){ res.status(500).json({error:e.message}); }
});
app.post('/api/cupones', authPerm('config'), async (req,res)=>{ try{ const c=req.body; const {rows}=await pool.query('INSERT INTO cupones (codigo,tipo,valor,secciones_ids,categoria,uso_maximo,monto_minimo,metodo_pago,activo,fecha_desde,fecha_hasta,solo_primera_compra,tenant_id) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13) RETURNING *', [c.codigo,c.tipo||'porcentaje',c.valor||0,c.secciones_ids||'',c.categoria||'',c.uso_maximo||0,c.monto_minimo||0,c.metodo_pago||'',c.activo!==false,c.fecha_desde||null,c.fecha_hasta||null,c.solo_primera_compra||false, req.tenantId]); if(c.productos_ids){ for(const pid of c.productos_ids){ await pool.query('INSERT INTO cupon_productos (cupon_id,producto_id,tenant_id) VALUES ($1,$2,$3) ON CONFLICT DO NOTHING', [rows[0].id,pid, req.tenantId]); } } res.json(rows[0]); }catch(e){ res.status(500).json({error:e.message}); } });
app.put('/api/cupones/:id', authPerm('config'), async (req,res)=>{ try{ const c=req.body; await pool.query('UPDATE cupones SET codigo=$1,tipo=$2,valor=$3,secciones_ids=$4,categoria=$5,uso_maximo=$6,monto_minimo=$7,metodo_pago=$8,activo=$9,fecha_desde=$10,fecha_hasta=$11,solo_primera_compra=$12 WHERE id=$13 AND tenant_id=$14', [c.codigo,c.tipo,c.valor,c.secciones_ids||'',c.categoria||'',c.uso_maximo||0,c.monto_minimo||0,c.metodo_pago||'',c.activo!==false,c.fecha_desde||null,c.fecha_hasta||null,c.solo_primera_compra||false,req.params.id, req.tenantId]); await pool.query('DELETE FROM cupon_productos WHERE cupon_id=$1', [req.params.id]); if(c.productos_ids){ for(const pid of c.productos_ids){ await pool.query('INSERT INTO cupon_productos (cupon_id,producto_id,tenant_id) VALUES ($1,$2,$3)', [req.params.id,pid, req.tenantId]); } } res.json({ok:true}); }catch(e){ res.status(500).json({error:e.message}); } });
app.delete('/api/cupones/:id', authPerm('config'), async (req,res)=>{ try{ await pool.query('DELETE FROM cupones WHERE id=$1 AND tenant_id=$2', [req.params.id, req.tenantId]); res.json({ok:true}); }catch(e){ res.status(500).json({error:e.message}); } });

// PROMOCIONES
app.get('/api/promociones', authPerm('config'), async (req,res)=>{ try{ const {rows}=await pool.query('SELECT * FROM promociones WHERE tenant_id=$1 ORDER BY created_at DESC', [req.tenantId]); res.json(rows); }catch(e){ res.status(500).json({error:e.message}); } });
app.get('/api/promociones/activas', async (req,res)=>{ try{ const {rows}=await pool.query('SELECT * FROM promociones WHERE tenant_id=$1 AND activo=true AND (fecha_desde IS NULL OR fecha_desde<=NOW()) AND (fecha_hasta IS NULL OR fecha_hasta>=NOW())', [req.tenantId]); res.json(rows); }catch(e){ res.status(500).json({error:e.message}); } });
app.post('/api/promociones', authPerm('config'), async (req,res)=>{ try{ const p=req.body; const {rows}=await pool.query('INSERT INTO promociones (nombre,tipo,valor,secciones_ids,categoria,productos_ids,activo,fecha_desde,fecha_hasta,tenant_id) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10) RETURNING *', [p.nombre,p.tipo,p.valor,p.secciones_ids||'',p.categoria||'',p.productos_ids||'',p.activo!==false,p.fecha_desde||null,p.fecha_hasta||null, req.tenantId]); res.json(rows[0]); }catch(e){ res.status(500).json({error:e.message}); } });
app.put('/api/promociones/:id', authPerm('config'), async (req,res)=>{ try{ const p=req.body; await pool.query('UPDATE promociones SET nombre=$1,tipo=$2,valor=$3,secciones_ids=$4,categoria=$5,productos_ids=$6,activo=$7,fecha_desde=$8,fecha_hasta=$9 WHERE id=$10 AND tenant_id=$11', [p.nombre,p.tipo,p.valor,p.secciones_ids||'',p.categoria||'',p.productos_ids||'',p.activo!==false,p.fecha_desde||null,p.fecha_hasta||null,req.params.id, req.tenantId]); res.json({ok:true}); }catch(e){ res.status(500).json({error:e.message}); } });
app.delete('/api/promociones/:id', authPerm('config'), async (req,res)=>{ try{ await pool.query('DELETE FROM promociones WHERE id=$1 AND tenant_id=$2', [req.params.id, req.tenantId]); res.json({ok:true}); }catch(e){ res.status(500).json({error:e.message}); } });

// POPUPS, REDES, MENU, DESIGN, METODOS PAGO, PAGINAS, BADGES, ENVIO CONFIG
app.get('/api/popups', async (req,res)=>{ try{ const {rows}=await pool.query('SELECT * FROM popups WHERE activo=true AND tenant_id=$1 ORDER BY created_at DESC', [req.tenantId]); res.json(rows); }catch(e){ res.status(500).json({error:e.message}); } });
app.get('/api/popups/all', authPerm('config'), async (req,res)=>{ try{ const {rows}=await pool.query('SELECT * FROM popups WHERE tenant_id=$1 ORDER BY created_at DESC', [req.tenantId]); res.json(rows); }catch(e){ res.status(500).json({error:e.message}); } });
app.post('/api/popups', authPerm('config'), async (req,res)=>{ try{ const p=req.body; const {rows}=await pool.query('INSERT INTO popups (titulo,imagen,url_destino,secciones_ids,activo,tenant_id) VALUES ($1,$2,$3,$4,$5,$6) RETURNING *', [p.titulo||'',p.imagen||'',p.url_destino||'',p.secciones_ids||'',p.activo!==false, req.tenantId]); res.json(rows[0]); }catch(e){ res.status(500).json({error:e.message}); } });
app.put('/api/popups/:id', authPerm('config'), async (req,res)=>{ try{ const p=req.body; await pool.query('UPDATE popups SET titulo=$1,imagen=$2,url_destino=$3,secciones_ids=$4,activo=$5 WHERE id=$6 AND tenant_id=$7', [p.titulo,p.imagen,p.url_destino,p.secciones_ids||'',p.activo!==false,req.params.id, req.tenantId]); res.json({ok:true}); }catch(e){ res.status(500).json({error:e.message}); } });
app.delete('/api/popups/:id', authPerm('config'), async (req,res)=>{ try{ await pool.query('DELETE FROM popups WHERE id=$1 AND tenant_id=$2', [req.params.id, req.tenantId]); res.json({ok:true}); }catch(e){ res.status(500).json({error:e.message}); } });

app.get('/api/redes-sociales', async (req,res)=>{ try{ const {rows}=await pool.query('SELECT * FROM redes_sociales WHERE tenant_id=$1 ORDER BY orden', [req.tenantId]); res.json(rows); }catch(e){ res.status(500).json({error:e.message}); } });
app.put('/api/redes-sociales', authPerm('config'), async (req,res)=>{ const client=await pool.connect(); try{ const {redes}=req.body; await client.query('BEGIN'); await client.query('DELETE FROM redes_sociales WHERE tenant_id=$1', [req.tenantId]); let orden=0; for(const r of (redes||[])){ if(!r.url || !r.url.trim()) continue; await client.query('INSERT INTO redes_sociales (tipo,url,activo,orden,tenant_id) VALUES ($1,$2,$3,$4,$5)', [r.tipo, r.url.trim(), r.activo!==false, orden++, req.tenantId]); } await client.query('COMMIT'); res.json({ok:true}); }catch(e){ await client.query('ROLLBACK').catch(()=>{}); res.status(500).json({error:e.message}); } finally{ client.release(); } });

app.get('/api/menu', async (req,res)=>{ try{ const {rows}=await pool.query('SELECT * FROM menu_items WHERE visible=true AND tenant_id=$1 ORDER BY orden', [req.tenantId]); res.json(rows); }catch(e){ res.status(500).json({error:e.message}); } });
app.get('/api/menu/all', authPerm('config'), async (req,res)=>{ try{ const {rows}=await pool.query('SELECT * FROM menu_items WHERE tenant_id=$1 ORDER BY orden', [req.tenantId]); res.json(rows); }catch(e){ res.status(500).json({error:e.message}); } });
app.post('/api/menu', authPerm('config'), async (req,res)=>{ try{ const m=req.body; const {rows}=await pool.query('INSERT INTO menu_items (titulo,url,tipo,visible,orden,seccion_id,tenant_id) VALUES ($1,$2,$3,$4,$5,$6,$7) RETURNING *', [m.titulo,m.url||'',m.tipo||'link',m.visible!==false,m.orden||0,m.seccion_id||null, req.tenantId]); res.json(rows[0]); }catch(e){ res.status(500).json({error:e.message}); } });
app.put('/api/menu/:id', authPerm('config'), async (req,res)=>{ try{ const m=req.body; await pool.query('UPDATE menu_items SET titulo=$1,url=$2,tipo=$3,visible=$4,orden=$5,seccion_id=$6 WHERE id=$7 AND tenant_id=$8', [m.titulo,m.url,m.tipo,m.visible!==false,m.orden||0,m.seccion_id||null,req.params.id, req.tenantId]); res.json({ok:true}); }catch(e){ res.status(500).json({error:e.message}); } });
app.delete('/api/menu/:id', authPerm('config'), async (req,res)=>{ try{ await pool.query('DELETE FROM menu_items WHERE id=$1 AND tenant_id=$2', [req.params.id, req.tenantId]); res.json({ok:true}); }catch(e){ res.status(500).json({error:e.message}); } });

app.get('/api/design', async (req,res)=>{ try{ const {rows}=await pool.query('SELECT * FROM design_config WHERE tenant_id=$1', [req.tenantId]); const cfg={}; rows.forEach(r=>cfg[r.clave]=r.valor); res.json(cfg); }catch(e){ res.status(500).json({error:e.message}); } });
app.put('/api/design', authPerm('config'), async (req,res)=>{ try{ for(const [k,v] of Object.entries(req.body)){ await pool.query("INSERT INTO design_config (tenant_id,clave,valor) VALUES ($1,$2,$3) ON CONFLICT (tenant_id,clave) DO UPDATE SET valor=$3", [req.tenantId,k,v]); } res.json({ok:true}); }catch(e){ res.status(500).json({error:e.message}); } });

app.get('/api/metodos-pago', async (req,res)=>{ try{ const {seccion_id}=req.query; let q='SELECT * FROM metodos_pago WHERE activo=true AND tenant_id=$1'; const params=[req.tenantId]; if(seccion_id){ q+=' AND (seccion_id=$2 OR seccion_id IS NULL)'; params.push(seccion_id); } q+=' ORDER BY orden'; const {rows}=await pool.query(q, params); res.json(rows); }catch(e){ res.status(500).json({error:e.message}); } });
app.get('/api/metodos-pago/all', authPerm('config'), async (req,res)=>{ try{ const {rows}=await pool.query('SELECT * FROM metodos_pago WHERE tenant_id=$1 ORDER BY orden', [req.tenantId]); res.json(rows); }catch(e){ res.status(500).json({error:e.message}); } });
app.post('/api/metodos-pago', authPerm('config'), async (req,res)=>{ try{ const m=req.body; const {rows}=await pool.query('INSERT INTO metodos_pago (nombre,descripcion,instrucciones,icono,seccion_id,activo,orden,tenant_id) VALUES ($1,$2,$3,$4,$5,$6,$7,$8) RETURNING *', [m.nombre,m.descripcion||'',m.instrucciones||'',m.icono||'',m.seccion_id||null,m.activo!==false,m.orden||0, req.tenantId]); res.json(rows[0]); }catch(e){ res.status(500).json({error:e.message}); } });
app.put('/api/metodos-pago/:id', authPerm('config'), async (req,res)=>{ try{ const m=req.body; await pool.query('UPDATE metodos_pago SET nombre=$1,descripcion=$2,instrucciones=$3,icono=$4,seccion_id=$5,activo=$6,orden=$7 WHERE id=$8 AND tenant_id=$9', [m.nombre,m.descripcion,m.instrucciones,m.icono,m.seccion_id,m.activo!==false,m.orden||0,req.params.id, req.tenantId]); res.json({ok:true}); }catch(e){ res.status(500).json({error:e.message}); } });
app.delete('/api/metodos-pago/:id', authPerm('config'), async (req,res)=>{ try{ await pool.query('DELETE FROM metodos_pago WHERE id=$1 AND tenant_id=$2', [req.params.id, req.tenantId]); res.json({ok:true}); }catch(e){ res.status(500).json({error:e.message}); } });

app.get('/api/paginas', async (req,res)=>{ try{ const {seccion_id}=req.query; let q='SELECT * FROM paginas_info WHERE visible=true AND tenant_id=$1'; const params=[req.tenantId]; if(seccion_id){ q+=' AND (seccion_id=$2 OR seccion_id IS NULL)'; params.push(seccion_id); } q+=' ORDER BY orden'; const {rows}=await pool.query(q, params); res.json(rows); }catch(e){ res.status(500).json({error:e.message}); } });
app.get('/api/paginas/:id', async (req,res)=>{ try{ const {rows}=await pool.query('SELECT * FROM paginas_info WHERE id=$1', [req.params.id]); res.json(rows[0]); }catch(e){ res.status(500).json({error:e.message}); } });
app.post('/api/paginas', authPerm('config'), async (req,res)=>{ try{ const p=req.body; const {rows}=await pool.query('INSERT INTO paginas_info (titulo,slug,contenido,seccion_id,visible,orden,tenant_id) VALUES ($1,$2,$3,$4,$5,$6,$7) RETURNING *', [p.titulo,p.slug,p.contenido||'',p.seccion_id||null,p.visible!==false,p.orden||0, req.tenantId]); res.json(rows[0]); }catch(e){ res.status(500).json({error:e.message}); } });
app.put('/api/paginas/:id', authPerm('config'), async (req,res)=>{ try{ const p=req.body; await pool.query('UPDATE paginas_info SET titulo=$1,slug=$2,contenido=$3,seccion_id=$4,visible=$5,orden=$6 WHERE id=$7 AND tenant_id=$8', [p.titulo,p.slug,p.contenido||'',p.seccion_id||null,p.visible!==false,p.orden||0,req.params.id, req.tenantId]); res.json({ok:true}); }catch(e){ res.status(500).json({error:e.message}); } });
app.delete('/api/paginas/:id', authPerm('config'), async (req,res)=>{ try{ await pool.query('DELETE FROM paginas_info WHERE id=$1 AND tenant_id=$2', [req.params.id, req.tenantId]); res.json({ok:true}); }catch(e){ res.status(500).json({error:e.message}); } });

app.get('/api/badges', async (req,res)=>{ try{ const {seccion_id}=req.query; let q='SELECT * FROM badges WHERE visible=true AND tenant_id=$1'; const params=[req.tenantId]; if(seccion_id){ q+=` AND (secciones_ids='' OR secciones_ids IS NULL OR ',' || secciones_ids || ',' LIKE $2)`; params.push(`%,${seccion_id},%`); } q+=' ORDER BY orden'; const {rows}=await pool.query(q, params); res.json(rows); }catch(e){ res.status(500).json({error:e.message}); } });
app.get('/api/badges/all', authPerm('config'), async (req,res)=>{ try{ const {rows}=await pool.query('SELECT * FROM badges WHERE tenant_id=$1 ORDER BY orden', [req.tenantId]); res.json(rows); }catch(e){ res.status(500).json({error:e.message}); } });
app.post('/api/badges', authPerm('config'), async (req,res)=>{ try{ const b=req.body; const {rows}=await pool.query('INSERT INTO badges (icono,texto,color,visible,secciones_ids,orden,tenant_id) VALUES ($1,$2,$3,$4,$5,$6,$7) RETURNING *', [b.icono||'',b.texto||'',b.color||'#2563eb',b.visible!==false,b.secciones_ids||'',b.orden||0, req.tenantId]); res.json(rows[0]); }catch(e){ res.status(500).json({error:e.message}); } });
app.put('/api/badges/:id', authPerm('config'), async (req,res)=>{ try{ const b=req.body; await pool.query('UPDATE badges SET icono=$1,texto=$2,color=$3,visible=$4,secciones_ids=$5,orden=$6 WHERE id=$7 AND tenant_id=$8', [b.icono,b.texto,b.color,b.visible!==false,b.secciones_ids||'',b.orden||0,req.params.id, req.tenantId]); res.json({ok:true}); }catch(e){ res.status(500).json({error:e.message}); } });
app.delete('/api/badges/:id', authPerm('config'), async (req,res)=>{ try{ await pool.query('DELETE FROM badges WHERE id=$1 AND tenant_id=$2', [req.params.id, req.tenantId]); res.json({ok:true}); }catch(e){ res.status(500).json({error:e.message}); } });

// ENVIO CONFIG + CUSTOM
app.get('/api/envio/config/:seccion_id', async (req,res)=>{ try{ const {rows}=await pool.query('SELECT * FROM config_envio WHERE seccion_id=$1 AND tenant_id=$2', [req.params.seccion_id, req.tenantId]); res.json(rows[0]||{metodo:'manual',costo_fijo:0,gratis_desde:0,cp_origen:'1888'}); }catch(e){ res.status(500).json({error:e.message}); } });
app.put('/api/envio/config/:seccion_id', authPerm('config'), async (req,res)=>{ try{ const c=req.body; await pool.query('INSERT INTO config_envio (seccion_id,metodo,costo_fijo,gratis_desde,zonas,cp_origen,tenant_id) VALUES ($1,$2,$3,$4,$5,$6,$7) ON CONFLICT (seccion_id) DO UPDATE SET metodo=$2,costo_fijo=$3,gratis_desde=$4,zonas=$5,cp_origen=$6', [req.params.seccion_id,c.metodo||'manual',c.costo_fijo||0,c.gratis_desde||0,JSON.stringify(c.zonas||[]),c.cp_origen||'1888', req.tenantId]); res.json({ok:true}); }catch(e){ res.status(500).json({error:e.message}); } });
app.post('/api/envio/cotizar', async (req,res)=>{ try{ const {seccion_id,codigo_postal}=req.body; const {rows}=await pool.query('SELECT * FROM config_envio WHERE seccion_id=$1 AND tenant_id=$2', [seccion_id, req.tenantId]); const cfg=rows[0]||{metodo:'manual',costo_fijo:0}; res.json({costo:cfg.costo_fijo, metodo:cfg.metodo, gratis_desde:cfg.gratis_desde}); }catch(e){ res.status(500).json({error:e.message}); } });

// METODOS ENVIO CUSTOM - Uber, Didi, etc
app.get('/api/envio/custom', async (req,res)=>{ try{ const {seccion_id}=req.query; let q='SELECT * FROM metodos_envio_custom WHERE activo=true AND tenant_id=$1'; const params=[req.tenantId]; if(seccion_id){ q+=' AND (seccion_id=$2 OR seccion_id IS NULL)'; params.push(seccion_id); } q+=' ORDER BY orden'; const {rows}=await pool.query(q, params); res.json(rows); }catch(e){ res.status(500).json({error:e.message}); } });
app.get('/api/envio/custom/all', authPerm('config'), async (req,res)=>{ try{ const {rows}=await pool.query('SELECT * FROM metodos_envio_custom WHERE tenant_id=$1 ORDER BY seccion_id, orden', [req.tenantId]); res.json(rows); }catch(e){ res.status(500).json({error:e.message}); } });
app.post('/api/envio/custom', authPerm('config'), async (req,res)=>{ try{ const m=req.body; const {rows}=await pool.query('INSERT INTO metodos_envio_custom (seccion_id,nombre,descripcion,precio,tipo,activo,gratis_desde,tiempo_estimado,icono,orden,tenant_id) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11) RETURNING *', [m.seccion_id||null,m.nombre,m.descripcion||'',m.precio||0,m.tipo||'fijo',m.activo!==false,m.gratis_desde||0,m.tiempo_estimado||'',m.icono||'',m.orden||0, req.tenantId]); res.json(rows[0]); }catch(e){ res.status(500).json({error:e.message}); } });
app.put('/api/envio/custom/:id', authPerm('config'), async (req,res)=>{ try{ const m=req.body; await pool.query('UPDATE metodos_envio_custom SET seccion_id=$1,nombre=$2,descripcion=$3,precio=$4,tipo=$5,activo=$6,gratis_desde=$7,tiempo_estimado=$8,icono=$9,orden=$10 WHERE id=$11 AND tenant_id=$12', [m.seccion_id||null,m.nombre,m.descripcion,m.precio,m.tipo,m.activo!==false,m.gratis_desde||0,m.tiempo_estimado||'',m.icono||'',m.orden||0,req.params.id, req.tenantId]); res.json({ok:true}); }catch(e){ res.status(500).json({error:e.message}); } });
app.delete('/api/envio/custom/:id', authPerm('config'), async (req,res)=>{ try{ await pool.query('DELETE FROM metodos_envio_custom WHERE id=$1 AND tenant_id=$2', [req.params.id, req.tenantId]); res.json({ok:true}); }catch(e){ res.status(500).json({error:e.message}); } });

// BUSQUEDA GLOBAL con debounce ready
app.get('/api/busqueda-global', optionalAuth, async (req,res)=>{
  try{
    const {q}=req.query; if(!q||q.length<2) return res.json({resultados:[], total:0});
    const {rows:secciones}=await pool.query('SELECT * FROM secciones WHERE visible=true AND tenant_id=$1 ORDER BY orden, id', [req.tenantId]);
    const resultados=[];
    const toks = String(q).trim().split(/\s+/).filter(Boolean).slice(0,8);
    const campos = `(coalesce(nombre,'')||' '||coalesce(modelo,'')||' '||coalesce(categoria,'')||' '||coalesce(marca,'')||' '||coalesce(sku,'')||' '||coalesce(compatibilidad,'')||' '||coalesce(descripcion,''))`;
    for(const sec of secciones){
      const params=[sec.id, req.tenantId]; let pi=3; const cond=[];
      for(const tk of toks){ cond.push(`${campos} ILIKE $${pi}`); params.push(`%${tk}%`); pi++; }
      const {rows}=await pool.query(`SELECT id,nombre,modelo,categoria,precio_base,precio_oferta,imagen,stock,envio_gratis,permitir_sin_stock,es_digital,usa_variantes,(SELECT MIN(CASE WHEN v.precio_oferta>0 AND v.precio_oferta<v.precio THEN v.precio_oferta ELSE v.precio END) FROM variantes v WHERE v.producto_id=productos.id AND v.tenant_id=productos.tenant_id AND v.precio>0) AS precio_desde,(SELECT v.moneda FROM variantes v WHERE v.producto_id=productos.id AND v.tenant_id=productos.tenant_id AND v.precio>0 ORDER BY (CASE WHEN v.precio_oferta>0 AND v.precio_oferta<v.precio THEN v.precio_oferta ELSE v.precio END) ASC LIMIT 1) AS moneda_desde FROM productos WHERE seccion_id=$1 AND tenant_id=$2 AND visible=true${cond.length?' AND '+cond.join(' AND '):''} ORDER BY stock DESC LIMIT 50`, params);
      if(rows.length){ const hidePrice=sec.slug==='mayorista' && !req.user; resultados.push({seccion:sec, productos: hidePrice? rows.map(r=>({...r, precio_base:0, precio_oferta:0})) : rows}); }
    }
    res.json({resultados, total: resultados.reduce((s,r)=>s+r.productos.length,0)});
  }catch(e){ res.status(500).json({error:e.message}); }
});

// SLIDER, FAVORITOS, NOTIF STOCK
app.get('/api/slider', async (req,res)=>{ try{ const {rows}=await pool.query('SELECT * FROM slider_banners WHERE activo=true AND tenant_id=$1 ORDER BY orden', [req.tenantId]); res.json(rows); }catch(e){ res.status(500).json({error:e.message}); } });
app.get('/api/slider/all', authPerm('config'), async (req,res)=>{ try{ const {rows}=await pool.query('SELECT * FROM slider_banners WHERE tenant_id=$1 ORDER BY orden', [req.tenantId]); res.json(rows); }catch(e){ res.status(500).json({error:e.message}); } });
app.post('/api/slider', authPerm('config'), async (req,res)=>{ try{ const {titulo,subtitulo,etiqueta,imagen,url_destino,orden,activo}=req.body; const {rows}=await pool.query('INSERT INTO slider_banners (titulo,subtitulo,etiqueta,imagen,url_destino,orden,activo,tenant_id) VALUES ($1,$2,$3,$4,$5,$6,$7,$8) RETURNING *', [titulo||'',subtitulo||'',etiqueta||'',imagen||'',url_destino||'',orden||0,activo!==false, req.tenantId]); res.json(rows[0]); }catch(e){ res.status(500).json({error:e.message}); } });
app.put('/api/slider/:id', authPerm('config'), async (req,res)=>{ try{ const {titulo,subtitulo,etiqueta,imagen,url_destino,orden,activo}=req.body; await pool.query('UPDATE slider_banners SET titulo=$1,subtitulo=$2,etiqueta=$3,imagen=$4,url_destino=$5,orden=$6,activo=$7 WHERE id=$8 AND tenant_id=$9', [titulo,subtitulo||'',etiqueta||'',imagen,url_destino,orden,activo,req.params.id, req.tenantId]); res.json({ok:true}); }catch(e){ res.status(500).json({error:e.message}); } });
app.delete('/api/slider/:id', authPerm('config'), async (req,res)=>{ try{ await pool.query('DELETE FROM slider_banners WHERE id=$1 AND tenant_id=$2', [req.params.id, req.tenantId]); res.json({ok:true}); }catch(e){ res.status(500).json({error:e.message}); } });
// ── BARRAS DE TEXTO DESLIZANTES ──
app.get('/api/barras', async (req,res)=>{ try{ const {rows}=await pool.query('SELECT * FROM barras_texto WHERE activo=true AND tenant_id=$1 ORDER BY id', [req.tenantId]); res.json(rows); }catch(e){ res.status(500).json({error:e.message}); } });
app.get('/api/barras/all', authPerm('config'), async (req,res)=>{ try{ const {rows}=await pool.query('SELECT * FROM barras_texto WHERE tenant_id=$1 ORDER BY id', [req.tenantId]); res.json(rows); }catch(e){ res.status(500).json({error:e.message}); } });
app.post('/api/barras', authPerm('config'), async (req,res)=>{ try{ const b=req.body; const {rows}=await pool.query('INSERT INTO barras_texto (posicion,frases,estilo,color_fondo,color_texto,velocidad,activo,tenant_id) VALUES ($1,$2,$3,$4,$5,$6,$7,$8) RETURNING *', [b.posicion||'top',b.frases||'',b.estilo||'negro',b.color_fondo||'',b.color_texto||'',b.velocidad||25,b.activo!==false, req.tenantId]); res.json(rows[0]); }catch(e){ res.status(500).json({error:e.message}); } });
app.put('/api/barras/:id', authPerm('config'), async (req,res)=>{ try{ const b=req.body; await pool.query('UPDATE barras_texto SET posicion=$1,frases=$2,estilo=$3,color_fondo=$4,color_texto=$5,velocidad=$6,activo=$7 WHERE id=$8 AND tenant_id=$9', [b.posicion||'top',b.frases||'',b.estilo||'negro',b.color_fondo||'',b.color_texto||'',b.velocidad||25,b.activo!==false,req.params.id, req.tenantId]); res.json({ok:true}); }catch(e){ res.status(500).json({error:e.message}); } });
app.delete('/api/barras/:id', authPerm('config'), async (req,res)=>{ try{ await pool.query('DELETE FROM barras_texto WHERE id=$1 AND tenant_id=$2', [req.params.id, req.tenantId]); res.json({ok:true}); }catch(e){ res.status(500).json({error:e.message}); } });
// ── CONTACTOS (widget WhatsApp multi-agente) ──
app.get('/api/contactos', async (req,res)=>{ try{ const {seccion_id}=req.query; let q='SELECT * FROM contactos WHERE activo=true AND tenant_id=$1'; const params=[req.tenantId]; if(seccion_id){ q+=' AND (seccion_id IS NULL OR seccion_id=$2)'; params.push(seccion_id); } q+=' ORDER BY orden, id'; const {rows}=await pool.query(q, params); res.json(rows); }catch(e){ res.status(500).json({error:e.message}); } });
app.get('/api/contactos/all', authPerm('config'), async (req,res)=>{ try{ const {rows}=await pool.query('SELECT * FROM contactos WHERE tenant_id=$1 ORDER BY orden, id', [req.tenantId]); res.json(rows); }catch(e){ res.status(500).json({error:e.message}); } });
app.post('/api/contactos', authPerm('config'), async (req,res)=>{ try{ const c=req.body; const {rows}=await pool.query('INSERT INTO contactos (nombre,rol,telefono,avatar,seccion_id,online,mensaje_default,orden,activo,tenant_id) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10) RETURNING *', [c.nombre||'',c.rol||'',c.telefono||'',c.avatar||'',c.seccion_id||null,c.online!==false,c.mensaje_default||'',c.orden||0,c.activo!==false, req.tenantId]); res.json(rows[0]); }catch(e){ res.status(500).json({error:e.message}); } });
app.put('/api/contactos/:id', authPerm('config'), async (req,res)=>{ try{ const c=req.body; await pool.query('UPDATE contactos SET nombre=$1,rol=$2,telefono=$3,avatar=$4,seccion_id=$5,online=$6,mensaje_default=$7,orden=$8,activo=$9 WHERE id=$10 AND tenant_id=$11', [c.nombre||'',c.rol||'',c.telefono||'',c.avatar||'',c.seccion_id||null,c.online!==false,c.mensaje_default||'',c.orden||0,c.activo!==false,req.params.id, req.tenantId]); res.json({ok:true}); }catch(e){ res.status(500).json({error:e.message}); } });
app.delete('/api/contactos/:id', authPerm('config'), async (req,res)=>{ try{ await pool.query('DELETE FROM contactos WHERE id=$1 AND tenant_id=$2', [req.params.id, req.tenantId]); res.json({ok:true}); }catch(e){ res.status(500).json({error:e.message}); } });
// ── LEADS (capturados por el widget de contacto) ──
app.post('/api/leads', async (req,res)=>{ try{ const l=req.body; const {rows}=await pool.query('INSERT INTO leads (nombre,telefono,contacto_id,contacto_nombre,usuario_id,tenant_id) VALUES ($1,$2,$3,$4,$5,$6) RETURNING *', [l.nombre||'',l.telefono||'',l.contacto_id||null,l.contacto_nombre||'',l.usuario_id||null, req.tenantId]); res.json(rows[0]); }catch(e){ res.status(500).json({error:e.message}); } });
app.get('/api/leads', authPerm('stats'), async (req,res)=>{ try{ const {rows}=await pool.query('SELECT * FROM leads WHERE tenant_id=$1 ORDER BY created_at DESC LIMIT 500', [req.tenantId]); res.json(rows); }catch(e){ res.status(500).json({error:e.message}); } });
app.put('/api/leads/:id', authPerm('stats'), async (req,res)=>{ try{ await pool.query('UPDATE leads SET contactado=$1 WHERE id=$2 AND tenant_id=$3', [req.body.contactado!==false, req.params.id, req.tenantId]); res.json({ok:true}); }catch(e){ res.status(500).json({error:e.message}); } });
app.delete('/api/leads/:id', authPerm('stats'), async (req,res)=>{ try{ await pool.query('DELETE FROM leads WHERE id=$1 AND tenant_id=$2', [req.params.id, req.tenantId]); res.json({ok:true}); }catch(e){ res.status(500).json({error:e.message}); } });

app.get('/api/favoritos', auth(), async (req,res)=>{ try{ const {rows}=await pool.query('SELECT f.*, p.nombre, p.modelo, p.imagen, p.precio_base, p.precio_oferta, p.stock, p.categoria, p.seccion_id, p.usa_variantes FROM favoritos f JOIN productos p ON f.producto_id=p.id WHERE f.usuario_id=$1 AND f.tenant_id=$2 ORDER BY f.created_at DESC', [req.user.id, req.tenantId]); res.json(rows); }catch(e){ res.status(500).json({error:e.message}); } });
app.post('/api/favoritos/:producto_id', auth(), async (req,res)=>{ try{ await pool.query('INSERT INTO favoritos (usuario_id,producto_id,tenant_id) VALUES ($1,$2,$3) ON CONFLICT DO NOTHING', [req.user.id, req.params.producto_id, req.tenantId]); res.json({ok:true}); }catch(e){ res.status(500).json({error:e.message}); } });
app.delete('/api/favoritos/:producto_id', auth(), async (req,res)=>{ try{ await pool.query('DELETE FROM favoritos WHERE usuario_id=$1 AND producto_id=$2 AND tenant_id=$3', [req.user.id, req.params.producto_id, req.tenantId]); res.json({ok:true}); }catch(e){ res.status(500).json({error:e.message}); } });

app.post('/api/notificar-stock', async (req,res)=>{ try{ const {producto_id,email,telefono,canal}=req.body; if(!producto_id||(!email&&!telefono)) return res.status(400).json({error:'Falta email o teléfono'}); await pool.query('INSERT INTO notificaciones_stock (producto_id,email,telefono,canal,tenant_id) VALUES ($1,$2,$3,$4,$5)', [producto_id,email||'',telefono||'',canal||(telefono?'whatsapp':'email'), req.tenantId]); res.json({ok:true}); }catch(e){ res.status(500).json({error:e.message}); } });
// Admin: ver quién espera stock de qué producto
app.get('/api/notificaciones-stock', authPerm('productos'), async (req,res)=>{
  try{ const {rows}=await pool.query(`SELECT n.*, p.nombre, p.modelo, p.stock FROM notificaciones_stock n LEFT JOIN productos p ON n.producto_id=p.id WHERE n.notificado=false AND n.tenant_id=$1 ORDER BY n.created_at DESC LIMIT 200`, [req.tenantId]); res.json(rows); }
  catch(e){ res.status(500).json({error:e.message}); }
});
// Admin: marcar una notificación como avisada
app.post('/api/notificaciones-stock/:id/avisar', authPerm('productos'), async (req,res)=>{
  try{ await pool.query('UPDATE notificaciones_stock SET notificado=true WHERE id=$1 AND tenant_id=$2', [req.params.id, req.tenantId]); res.json({ok:true}); }
  catch(e){ res.status(500).json({error:e.message}); }
});
app.delete('/api/notificaciones-stock/:id', authPerm('productos'), async (req,res)=>{
  try{ await pool.query('DELETE FROM notificaciones_stock WHERE id=$1 AND tenant_id=$2', [req.params.id, req.tenantId]); res.json({ok:true}); }
  catch(e){ res.status(500).json({error:e.message}); }
});

// CARRITOS ABANDONADOS
app.post('/api/carritos-abandonados', async (req,res)=>{ try{ const {usuario_id,email,telefono,items,total,seccion_id}=req.body; const {rows}=await pool.query('INSERT INTO carritos_abandonados (usuario_id,email,telefono,items,total,seccion_id,tenant_id) VALUES ($1,$2,$3,$4,$5,$6,$7) RETURNING *', [usuario_id||null,email||'',telefono||'',JSON.stringify(items||[]),total||0,seccion_id||null, req.tenantId]); res.json(rows[0]); }catch(e){ res.status(500).json({error:e.message}); } });
app.get('/api/carritos-abandonados', authPerm('stats'), async (req,res)=>{ try{ const {rows}=await pool.query("SELECT c.*, u.nombre as usuario_nombre, COALESCE(NULLIF(c.telefono,''), u.telefono) as telefono, COALESCE(NULLIF(c.email,''), u.email) as email, s.nombre as seccion_nombre FROM carritos_abandonados c LEFT JOIN usuarios u ON c.usuario_id=u.id LEFT JOIN secciones s ON c.seccion_id=s.id WHERE c.recuperado=false AND c.tenant_id=$1 ORDER BY c.created_at DESC LIMIT 100", [req.tenantId]); res.json(rows); }catch(e){ res.status(500).json({error:e.message}); } });
app.post('/api/carritos-abandonados/:id/recuperar', authPerm('stats'), async (req,res)=>{ try{ await pool.query('UPDATE carritos_abandonados SET recuperado=true WHERE id=$1 AND tenant_id=$2', [req.params.id, req.tenantId]); res.json({ok:true}); }catch(e){ res.status(500).json({error:e.message}); } });
app.delete('/api/carritos-abandonados/:id', authPerm('stats'), async (req,res)=>{ try{ await pool.query('DELETE FROM carritos_abandonados WHERE id=$1 AND tenant_id=$2', [req.params.id, req.tenantId]); res.json({ok:true}); }catch(e){ res.status(500).json({error:e.message}); } });

// ANDREANI V4 - fix env vars CLIENTE vs NRO_CLIENTE
const ANDREANI_API = process.env.ANDREANI_API || 'https://apis.andreani.com';
const andreaniLogin = async ()=>{
  const user=process.env.ANDREANI_USER; const pass=process.env.ANDREANI_PASS;
  if(!user||!pass) return null;
  try{
    const r=await fetch(`${ANDREANI_API}/login`, {method:'GET', headers:{authorization:'Basic '+Buffer.from(`${user}:${pass}`).toString('base64')}});
    return r.headers.get('x-authorization-token');
  }catch{ return null; }
};
app.post('/api/andreani/cotizar', async (req,res)=>{
  try{
    const {cp_destino,peso,volumen,seccion_id,cp_origen} = req.body;
    const token=await andreaniLogin(); if(!token) return res.status(503).json({error:'Andreani no configurado'});
    let origen=cp_origen || process.env.ANDREANI_CP_ORIGEN || '1888';
    if(seccion_id){
      const {rows}=await pool.query('SELECT cp_origen FROM secciones WHERE id=$1', [seccion_id]).catch(()=>({rows:[]}));
      if(rows[0]?.cp_origen) origen=rows[0].cp_origen;
      const {rows:cfg}=await pool.query('SELECT cp_origen FROM config_envio WHERE seccion_id=$1', [seccion_id]).catch(()=>({rows:[]}));
      if(cfg[0]?.cp_origen) origen=cfg[0].cp_origen;
    }
    const cliente=process.env.ANDREANI_CLIENTE || process.env.ANDREANI_NRO_CLIENTE || '';
    const contrato=process.env.ANDREANI_CONTRATO || 'AND00EST';
    const body={ cpDestino: cp_destino, contrato, cliente, sucursalOrigen:'', bultos:[{valorDeclarado:1000, volumen: volumen||5000, kilos: peso||1}] };
    const r=await fetch(`${ANDREANI_API}/v1/tarifas`, {method:'POST', headers:{'x-authorization-token':token, 'Content-Type':'application/json'}, body:JSON.stringify(body)});
    const data=await r.json();
    // Normalizar respuesta para frontend tipo imagen ejemplo
    // Andreani devuelve array de tarifas - lo mapeamos a domicilio y sucursal
    res.json({origen, destino: cp_destino, tarifas: data, domicilio: data?.tarifas?.[0]||data, sucursal: data?.tarifas?.[1]||null, raw:data});
  }catch(e){ res.status(500).json({error:e.message}); }
});
app.get('/api/andreani/sucursales', async (req,res)=>{ try{ const {cp}=req.query; const token=await andreaniLogin(); if(!token) return res.status(503).json({error:'Andreani no configurado'}); const r=await fetch(`${ANDREANI_API}/v1/sucursales?codigoPostal=${cp}`, {headers:{'x-authorization-token':token}}); res.json(await r.json()); }catch(e){ res.status(500).json({error:e.message}); } });
app.post('/api/andreani/orden', authPerm('config'), async (req,res)=>{ try{ const token=await andreaniLogin(); if(!token) return res.status(503).json({error:'Andreani no configurado'}); const r=await fetch(`${ANDREANI_API}/v1/ordenes-de-envio`, {method:'POST', headers:{'x-authorization-token':token, 'Content-Type':'application/json'}, body:JSON.stringify(req.body)}); res.json(await r.json()); }catch(e){ res.status(500).json({error:e.message}); } });
app.get('/api/andreani/tracking/:envio', async (req,res)=>{ try{ const token=await andreaniLogin(); if(!token) return res.status(503).json({error:'Andreani no configurado'}); const r=await fetch(`${ANDREANI_API}/v1/envios/${req.params.envio}/trazas`, {headers:{'x-authorization-token':token}}); res.json(await r.json()); }catch(e){ res.status(500).json({error:e.message}); } });
app.get('/api/andreani/etiqueta/:envio', async (req,res)=>{ try{ const token=await andreaniLogin(); if(!token) return res.status(503).json({error:'Andreani no configurado'}); const r=await fetch(`${ANDREANI_API}/v1/ordenes-de-envio/${req.params.envio}/etiquetas`, {headers:{'x-authorization-token':token, Accept:'application/pdf'}}); res.set('Content-Type','application/pdf'); const buffer=await r.arrayBuffer(); res.send(Buffer.from(buffer)); }catch(e){ res.status(500).json({error:e.message}); } });

// START
const PORT=process.env.PORT||3000;
migrate().then(()=>{ app.listen(PORT, ()=>console.log(`🚀 V4 running on ${PORT}`)); }).catch(e=>{ console.error('Migration failed', e); process.exit(1); });
