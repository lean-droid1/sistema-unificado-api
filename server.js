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
// Un error suelto en una ruta no debe tirar todo el servidor (mientras se reinicia, la web queda cargando en blanco)
process.on('unhandledRejection', (e) => { console.error('[error no manejado]', e && e.message ? e.message : e); });
process.on('uncaughtException', (e) => { console.error('[excepción no capturada]', e && e.message ? e.message : e); });

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
// Login: el límite es por conexión + usuario. Con datos móviles muchos clientes comparten la misma dirección IP
// y antes 10 intentos fallidos de cualquiera bloqueaban el ingreso de todos los demás.
const loginLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 10, standardHeaders: true, legacyHeaders: false,
  message: { error: 'Demasiados intentos con este usuario. Esperá unos minutos e intentá de nuevo.' },
  keyGenerator: (req) => `${req.ip}|${String((req.body && req.body.usuario) || '').toLowerCase().trim()}` });
app.use('/api/login', loginLimiter);
app.use('/api/register', rateLimit({ windowMs: 15 * 60 * 1000, max: 30, message: { error: 'Demasiados registros desde esta conexión. Probá más tarde.' }, standardHeaders: true, legacyHeaders: false }));
// Límite general por conexión: holgado porque una sola página hace ~20 pedidos y muchos clientes pueden compartir IP
app.use('/api/', rateLimit({ windowMs: 1 * 60 * 1000, max: 1500, standardHeaders: true, legacyHeaders: false, message: { error: 'Demasiados pedidos seguidos. Esperá unos segundos.' } }));
app.use('/api/', (req,res,next)=>resolveTenant(req,res,next));
app.set('trust proxy', 1);

const pool = new Pool({ connectionString: process.env.DATABASE_URL, ssl: { rejectUnauthorized: false } });
// Recalcula preventa_reservado de un producto desde los pedidos reales (activos)
async function recalcReservado(productoId, tenantId){
  try{
    if(!productoId || !tenantId) return;
    await pool.query(`UPDATE productos SET preventa_reservado = (
      SELECT COALESCE(SUM(pi.cantidad),0) FROM pedido_items pi JOIN pedidos p ON pi.pedido_id=p.id
      WHERE pi.producto_id=$1 AND p.tenant_id=$2 AND p.tipo='pedido' AND LOWER(COALESCE(p.estado,'')) NOT IN ('cancelado','anulado','rechazado')
    ) WHERE id=$1 AND tenant_id=$2 AND es_preventa=true`, [productoId, tenantId]);
  }catch(e){ /* noop */ }
}
// Aislamiento entre tiendas: de una lista de ids de producto, deja solo los que son de esta tienda
async function idsProductosDeTienda(db, tenantId, ids){
  const lista=[...new Set((ids||[]).map(x=>parseInt(x,10)).filter(n=>Number.isFinite(n)&&n>0))];
  if(!lista.length) return new Set();
  const {rows}=await db.query('SELECT id FROM productos WHERE tenant_id=$1 AND id = ANY($2::int[])', [tenantId, lista]);
  return new Set(rows.map(r=>r.id));
}
async function productoDeTienda(db, tenantId, id){ return (await idsProductosDeTienda(db, tenantId, [id])).has(parseInt(id,10)); }
const SECRET = process.env.JWT_SECRET;
if (!SECRET) {
  // En producción NO se arranca sin clave propia: con la de ejemplo cualquiera podría fabricar sesiones de admin.
  if (process.env.NODE_ENV === 'production') { console.error('JWT_SECRET no configurado. Cargalo en las variables de Railway.'); process.exit(1); }
  console.error('JWT_SECRET no configurado - usando clave de desarrollo (solo local)');
}
const JWT_SECRET = SECRET || crypto.randomBytes(32).toString('hex');
const { createCheckout, CheckoutError, cotizacionDolar } = require('./checkout');
const checkout = createCheckout(pool);

// Datos de usuario que nunca deben salir hacia el navegador
const sanitizeUser = (u) => { if (!u) return u; const { password, reset_codigo, reset_expira, notas_admin, ...rest } = u; return rest; };
// ¿Es personal de la tienda (admin, o subadmin con permiso de pedidos)? Siempre leído de la base, no del token.
async function esStaffPedidos(req){
  if(!req.user) return false;
  const {rows}=await pool.query('SELECT rol, permisos, activo FROM usuarios WHERE id=$1 AND tenant_id=$2', [req.user.id, req.tenantId]).catch(()=>({rows:[]}));
  const u=rows[0]; if(!u || !u.activo) return false;
  return u.rol==='admin' || (u.rol==='subadmin' && String(u.permisos||'').split(',').includes('pedidos'));
}
// El token pertenece a la tienda de este request (evita usar una sesión de la tienda A en la tienda B)
const tokenDeEstaTienda = (d, req) => Number(d.tenant_id || 1) === Number(req.tenantId);

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
    if(!tokenDeEstaTienda(d, req)) return res.status(401).json({error:'Tu sesión es de otra tienda. Iniciá sesión de nuevo.'});
    // Siempre se revisa en la base: un usuario borrado o suspendido no sigue entrando con un token viejo
    const {rows} = await pool.query('SELECT rol, activo FROM usuarios WHERE id=$1 AND tenant_id=$2', [d.id, req.tenantId]).catch(()=>({rows:[]}));
    if(!rows[0] || rows[0].activo===false) return res.status(401).json({error:'Cuenta desactivada'});
    if(role==='admin' && rows[0].rol!=='admin') return res.status(403).json({error:'Sin permiso'});
    req._rol = rows[0].rol;
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
// ═══ PLANES en el backend: las llaves del plan se validan acá (no solo ocultando pestañas en el panel) ═══
const featureActiva = (feats, f) => { const v = feats && feats[f]; return !(v === false || v === 'no' || v === undefined || v === null); };
// Middleware: exige que el tenant tenga habilitada una feature del plan. Uso: requiereFeature('marketing')
const requiereFeature = (feature) => async (req,res,next)=>{
  if(Number(req.tenantId)===1) return next(); // la tienda del dueño de la plataforma nunca se limita
  try{
    const d=await getTenantData(req.tenantId);
    if(!featureActiva(d.features, feature)) return res.status(403).json({error:'Esta función no está incluida en tu plan', feature, upgrade:true});
    next();
  }catch{ next(); } // ante error, no bloquear (fail-open, para no romper por un bug)
};
// Límite numérico del plan (max_tiendas, max_subadmins). Devuelve el máximo o Infinity.
const limitePlan = async (req, clave) => {
  if(Number(req.tenantId)===1) return Infinity;
  try{ const d=await getTenantData(req.tenantId); const n=Number(d.features && d.features[clave]); return Number.isFinite(n) && n>=0 ? n : Infinity; }catch{ return Infinity; }
};
const optionalAuth = async (req,res,next)=>{ try{ const t=req.headers.authorization?.split(' ')[1]; if(t){ const d=jwt.verify(t,JWT_SECRET); if(tokenDeEstaTienda(d, req)){ const revoked=await pool.query('SELECT 1 FROM tokens_revocados WHERE token_hash=$1', [hashToken(t)]).catch(()=>({rows:[]})); const {rows}=revoked.rows.length?{rows:[]}:await pool.query('SELECT activo FROM usuarios WHERE id=$1 AND tenant_id=$2', [d.id, req.tenantId]).catch(()=>({rows:[]})); if(rows[0] && rows[0].activo!==false) req.user=d; } } }catch{} next(); };

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
    dropshipping: false,  // el bot del proveedor es solo de la tienda del dueño (tienda 1), no se vende en los planes
    catalogo_pdf: true,
    max_tiendas: 999,
    max_subadmins: 999,
  },
};
// Cache de datos del tenant (plan, estado, features) para no consultar en cada request
const tenantDataCache = new Map();
async function getTenantData(tenantId){
  const key=String(tenantId);
  const hit=tenantDataCache.get(key);
  if(hit && Date.now()-hit._ts < 5*60*1000) return hit; // se refresca cada 5 min (antes no vencía nunca: una prueba gratis vencida seguía activa)
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
  const data={plan:t.plan||'full', estado, features, dias_restantes:diasRestantes, _ts:Date.now()};
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
// ── Marca a partir del nombre del producto (para Google: "brand" en los datos del producto) ──
// Solo marcas de herramientas/equipos. Nunca marcas de celulares (Samsung, iPhone…): en un repuesto
// indican compatibilidad, no el fabricante. "Tipo JBC" tampoco es la marca. Gana la que aparece primero.
const MARCAS_FUERTES = [
  ['RF4', /\bRF4\b/i], ['Luowei', /\bluo ?wei\b/i], ['Mijing', /\bmi ?jing\b/i], ['Kailiwei', /\bkai ?li ?wei\b/i],
  ['2UUL', /\b2uul\b/i], ['Aifen', /\baifen\b/i], ['Sugon', /\bsugon\b/i], ['Qianli', /\bqianli\b/i],
  ['iRepair', /\birepair\b/i], ['JCID', /\bjcid\b|\bjc\b/i], ['Z3X', /\bz3x\b|\beasy ?jtag\b/i], ['ICFriend', /\bic ?friend\b/i],
  ['Yaxun', /\byaxun\b/i], ['Relife', /\brelife\b/i], ['Mechanic', /\bmechanic\b/i], ['Jakemy', /\bjakemy\b/i],
  ['Amaoe', /\bamaoe\b/i], ['Youtools', /\byou ?tools\b/i], ['GTools', /\bgtools\b/i], ['Sunshine', /\bsunshine\b/i],
  ['Kaisi', /\bkaisi\b/i], ['Atten', /\batten\b/i], ['Yihua', /\byihua\b/i], ['Aixun', /\baixun\b/i], ['GVDA', /\bgvda\b/i],
  ['Baku', /\bbaku\b/i], ['Xinzhizao', /\bxinzhizao\b/i], ['Wylie', /\bwylie\b/i], ['Hakko', /\bhakko\b/i],
  ['UNI-T', /\buni-t\b/i], ['Naviplus', /\bnaviplus\b/i], ['EAB', /\bEAB\b/], ['Miechi', /\bmiechi\b/i], ['MaAnt', /\bma-?ant\b/i],
];
// Códigos de modelo que identifican la marca cuando el nombre no la dice (LW-301 → Luowei, MJ-F11 → Mijing…)
const MARCAS_CODIGO = [['Luowei', /\bLW-\d/i], ['Mijing', /\bMJ[- ]?[A-Z]?\d/i], ['Kailiwei', /\bKLW-/i], ['RF4', /\bRF-[A-Z]{0,4}\d/i]];
function marcaDeNombre(nombre){
  const n = String(nombre || '');
  let mejor = null, pos = Infinity;
  for (const [marca, re] of MARCAS_FUERTES) { const m = n.match(re); if (m && m.index < pos) { pos = m.index; mejor = marca; } }
  if (mejor) return mejor;
  for (const [marca, re] of MARCAS_CODIGO) { if (re.test(n)) return marca; }
  return '';
}

// Tareas de una sola vez para Google (tienda principal). Corren en segundo plano después de arrancar.
async function tareasSeo(){
  const hecho = async (clave) => { const {rows} = await pool.query('SELECT 1 FROM configuracion WHERE tenant_id=1 AND clave=$1', [clave]); return !!rows[0]; };
  const marcar = (clave, valor) => pool.query('INSERT INTO configuracion (tenant_id,clave,valor) VALUES (1,$1,$2) ON CONFLICT (tenant_id,clave) DO UPDATE SET valor=$2', [clave, String(valor)]);
  // 1) Marca automática en los productos que no la tienen
  if (!(await hecho('_marcas_auto_v1'))) {
    const {rows} = await pool.query("SELECT id,nombre FROM productos WHERE tenant_id=1 AND COALESCE(marca,'')=''");
    let n = 0;
    for (const p of rows) { const m = marcaDeNombre(p.nombre); if (m) { await pool.query("UPDATE productos SET marca=$1 WHERE id=$2 AND tenant_id=1 AND COALESCE(marca,'')=''", [m, p.id]); n++; } }
    await marcar('_marcas_auto_v1', n);
    console.log(`🏷️  Marcas automáticas: ${n} productos`);
  }
  // 2) Descripciones reescritas de los microscopios principales (venían en inglés/traducción automática)
  if (!(await hecho('_seo_desc_v1'))) {
    const desc = require('./seo-desc-v1.json');
    let n = 0;
    for (const [id, texto] of Object.entries(desc)) { const r = await pool.query('UPDATE productos SET descripcion=$1 WHERE id=$2 AND tenant_id=1', [texto, Number(id)]); n += r.rowCount; }
    await marcar('_seo_desc_v1', n);
    console.log(`📝 Descripciones SEO: ${n} productos`);
  }
}

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
    `ALTER TABLE producto_atributo_valores ADD COLUMN IF NOT EXISTS imagen TEXT DEFAULT ''`,
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
    `ALTER TABLE pedidos ADD COLUMN IF NOT EXISTS moneda VARCHAR(10) DEFAULT 'ARS'`,
    `ALTER TABLE pedidos ADD COLUMN IF NOT EXISTS codigo_seguimiento VARCHAR(120) DEFAULT ''`,
    `DELETE FROM carritos_abandonados c USING carritos_abandonados c2 WHERE c.recuperado=false AND c2.recuperado=false AND c.tenant_id=c2.tenant_id AND c.usuario_id=c2.usuario_id AND c.usuario_id IS NOT NULL AND (c.created_at < c2.created_at OR (c.created_at=c2.created_at AND c.id<c2.id))`,
    `UPDATE pedidos SET moneda='USDT' WHERE (moneda IS NULL OR moneda='ARS') AND EXISTS(SELECT 1 FROM pedido_items pi LEFT JOIN productos pr ON pr.id=pi.producto_id AND pr.tenant_id=(SELECT tenant_id FROM pedidos WHERE id=pi.pedido_id) LEFT JOIN variantes v ON v.id=pi.variante_id WHERE pi.pedido_id=pedidos.id AND COALESCE(v.moneda, pr.moneda,'ARS')='USDT')`,
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
    `ALTER TABLE slider_banners ADD COLUMN IF NOT EXISTS imagen_mobile TEXT DEFAULT ''`,
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
    // Forzar tipo decimal en columnas viejas creadas como entero (permite peso en gramos, ej 0.05 kg)
    `ALTER TABLE productos ALTER COLUMN peso TYPE NUMERIC(8,2) USING peso::numeric`,
    `ALTER TABLE productos ALTER COLUMN alto TYPE NUMERIC(8,2) USING alto::numeric`,
    `ALTER TABLE productos ALTER COLUMN ancho TYPE NUMERIC(8,2) USING ancho::numeric`,
    `ALTER TABLE productos ALTER COLUMN largo TYPE NUMERIC(8,2) USING largo::numeric`,
    // One-time: limpiar envío gratis que el bot había copiado del proveedor en productos RXZ (se ejecuta una sola vez)
    `DO $$ BEGIN IF NOT EXISTS (SELECT 1 FROM configuracion WHERE clave='_reset_eg_rxz_v1') THEN UPDATE productos SET envio_gratis=false WHERE sku LIKE 'RXZ-%'; INSERT INTO configuracion (tenant_id,clave,valor) VALUES (1,'_reset_eg_rxz_v1','1') ON CONFLICT (tenant_id,clave) DO NOTHING; END IF; END $$;`,
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
    `ALTER TABLE productos ADD COLUMN IF NOT EXISTS pendiente_aprobacion BOOLEAN DEFAULT false`,
    `ALTER TABLE productos ADD COLUMN IF NOT EXISTS posicion INT DEFAULT 0`,
    `ALTER TABLE usuarios ADD COLUMN IF NOT EXISTS mayorista BOOLEAN DEFAULT false`,
    `ALTER TABLE usuarios ADD COLUMN IF NOT EXISTS mayorista_solicitado_at TIMESTAMP`,
    // Seguridad multi-tienda: categorías y códigos de cupón únicos POR TIENDA (antes eran globales y una tienda pisaba a otra)
    `DO $$ DECLARE pk text; cols int; BEGIN
       SELECT conname, array_length(conkey,1) INTO pk, cols FROM pg_constraint WHERE conrelid='categorias_meta'::regclass AND contype='p';
       IF pk IS NOT NULL AND cols=1 THEN
         UPDATE categorias_meta SET tenant_id=1 WHERE tenant_id IS NULL;
         EXECUTE format('ALTER TABLE categorias_meta DROP CONSTRAINT %I', pk);
         ALTER TABLE categorias_meta ADD PRIMARY KEY (tenant_id, categoria);
       END IF;
     END $$`,
    `DO $$ BEGIN
       IF EXISTS (SELECT 1 FROM pg_constraint WHERE conrelid='cupones'::regclass AND conname='cupones_codigo_key') THEN
         ALTER TABLE cupones DROP CONSTRAINT cupones_codigo_key;
       END IF;
     END $$`,
    `CREATE UNIQUE INDEX IF NOT EXISTS uq_cupones_tenant_codigo ON cupones(tenant_id, UPPER(codigo))`,
    // Contador propio de visitas y búsquedas (sin Google)
    `CREATE TABLE IF NOT EXISTS visitas_eventos (id BIGSERIAL PRIMARY KEY, tenant_id INT NOT NULL DEFAULT 1, visitante VARCHAR(40) DEFAULT '', sesion VARCHAR(40) DEFAULT '', tipo VARCHAR(12) DEFAULT 'vista', path VARCHAR(300) DEFAULT '', origen VARCHAR(120) DEFAULT '', dispositivo VARCHAR(12) DEFAULT '', termino VARCHAR(120), resultados INT, created_at TIMESTAMP DEFAULT NOW())`,
    `CREATE INDEX IF NOT EXISTS idx_visitas_tenant_fecha ON visitas_eventos(tenant_id, created_at)`,
    `ALTER TABLE visitas_eventos ADD COLUMN IF NOT EXISTS bot_nombre VARCHAR(40) DEFAULT ''`,
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
    `ALTER TABLE popups ADD COLUMN IF NOT EXISTS imagenes JSONB DEFAULT '[]'::jsonb`,
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
    `CREATE INDEX IF NOT EXISTS idx_producto_imagenes_prod ON producto_imagenes(producto_id, orden)`,
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
      console.log('Admin inicial creado -> usuario: admin (contraseña: la de ADMIN_PASSWORD). Cambiala en Mi Cuenta.');
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
  if(!pw || String(pw).length<8) return 'La contraseña necesita al menos 8 caracteres';
  if(!/[A-Z]/.test(pw)) return 'La contraseña necesita al menos una mayúscula';
  if(!/[0-9]/.test(pw)) return 'La contraseña necesita al menos un número';
  return null;
};
let dolarBlueCache={valor:null, ts:0};

// === HEALTH ===
app.get('/api/health', (req,res)=>res.json({ok:true, v:'4.5.0', cloudinary: !!process.env.CLOUDINARY_CLOUD_NAME}));

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
    const pwErr=validatePassword(String(password)); if(pwErr) return res.status(400).json({error:'Contraseña: '+pwErr});
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
// Cotización del dólar que usa la tienda (blue, oficial o manual según Reglas de compra)
app.get('/api/dolar-blue', async (req,res)=>{
  try{ const c=await cotizacionDolar(pool, req.tenantId); res.json({ venta: c.valor || null, fuente: c.fuente, actualizado: c.actualizado || null }); }
  catch(e){ res.json({ venta: null }); }
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
    let compradorEmail = (comprador && comprador.email) || '';
    try{ const df=pedidos[0].datos_facturacion; const o=typeof df==='string'?JSON.parse(df):df; compradorEmail = compradorEmail || (o&&(o.email||o.mail))||''; }catch(e){}
    let filas = '';
    for(const p of pedidos){
      const link = baseUrl ? `${baseUrl}/?pedido=${p.id}` : '';
      const num = String(p.id).padStart(4,'0');
      const items = await _itemsPedidoHtml(p.id);
      filas += `<tr><td colspan="2" style="padding:10px 12px;border-top:2px solid #333;font-weight:700">Pedido #${num} — $${Number(p.total||0).toLocaleString('es-AR')} ${link?`· <a href="${link}">Ver orden →</a>`:''}</td></tr>${items}`;
    }
    const html = `
      <div style="font-family:system-ui,sans-serif;max-width:520px;margin:0 auto">
        <h2 style="color:#16a34a">Nueva venta en ${escMail(tienda)}</h2>
        <p>Cliente: <strong>${escMail(nombreCliente)}</strong></p>
        <p>Total: <strong style="font-size:20px">$${total.toLocaleString('es-AR')}</strong></p>
        <table style="width:100%;border-collapse:collapse;margin-top:12px">
          <tbody>${filas}</tbody>
        </table>
        <p style="color:#888;font-size:12px;margin-top:20px">Entró recién a tu tienda. Ingresá al panel para gestionarla.</p>
      </div>`;
    const r = await resend.emails.send({
      from: `${tienda} <${process.env.RESEND_FROM || 'onboarding@resend.dev'}>`,
      to: destino,
      reply_to: compradorEmail || undefined,
      subject: `Nueva venta $${total.toLocaleString('es-AR')} — ${tienda}`,
      html,
    });
    if(r && r.error){ console.log('[venta-mail] Resend error:', JSON.stringify(r.error)); }
    else { console.log('[venta-mail] enviado a', destino); }
  }catch(e){ console.log('[venta-mail] excepción:', e.message); }
}
// ── Helpers de mail reutilizables ──
// Escapa texto que viene de clientes antes de meterlo en el HTML de un mail
const escMail = (x) => String(x==null?'':x).replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
async function _itemsPedidoHtml(pedidoId){
  const {rows}=await pool.query('SELECT nombre_producto, cantidad, precio_unitario, variante_combinacion FROM pedido_items WHERE pedido_id=$1', [pedidoId]).catch(()=>({rows:[]}));
  return rows.map(i=>{
    const sub=Number(i.precio_unitario||0)*Number(i.cantidad||1);
    const varTxt=i.variante_combinacion?`<div style="color:#888;font-size:12px">${escMail(i.variante_combinacion)}</div>`:'';
    return `<tr><td style="padding:8px 12px;border-bottom:1px solid #eee">${escMail(i.cantidad||1)}× ${escMail(i.nombre_producto||'Producto')}${varTxt}</td><td style="padding:8px 12px;border-bottom:1px solid #eee;text-align:right;white-space:nowrap">$${sub.toLocaleString('es-AR')}</td></tr>`;
  }).join('');
}
async function _sendMail(to, subject, html, opts={}){
  if(!resend || !to) return;
  const addr = process.env.RESEND_FROM || 'onboarding@resend.dev';
  const from = opts.fromName ? `${opts.fromName} <${addr}>` : addr;
  const payload = { from, to, subject, html };
  if(opts.replyTo) payload.reply_to = opts.replyTo;
  try{ const r=await resend.emails.send(payload); if(r&&r.error) console.log('[mail] error:', JSON.stringify(r.error)); else console.log('[mail] enviado a', to); }catch(e){ console.log('[mail] exc:', e.message); }
}
async function _tiendaInfo(tenantId){
  const {rows:dc}=await pool.query("SELECT valor FROM design_config WHERE clave='nombre_tienda' AND tenant_id=$1", [tenantId]).catch(()=>({rows:[]}));
  const {rows:ev}=await pool.query("SELECT valor FROM configuracion WHERE clave='email_ventas' AND tenant_id=$1", [tenantId]).catch(()=>({rows:[]}));
  return { tienda:(dc[0]&&dc[0].valor)||'Tu tienda', baseUrl: process.env.PUBLIC_URL||process.env.FRONTEND_URL||'', email:(ev[0]&&ev[0].valor)||'' };
}
async function emailBienvenida(tenantId, email, nombre){
  if(!email) return;
  const {tienda, baseUrl, email:tiendaEmail}=await _tiendaInfo(tenantId);
  const html=`<div style="font-family:system-ui,sans-serif;max-width:520px;margin:0 auto">
    <h2 style="color:#111">¡Bienvenido/a a ${tienda}!</h2>
    <p>Hola ${escMail(nombre||'')}, tu cuenta ya está creada. Ya podés comprar y seguir tus pedidos.</p>
    ${baseUrl?`<p style="margin-top:16px"><a href="${baseUrl}" style="background:#111;color:#fff;padding:10px 18px;border-radius:8px;text-decoration:none">Ir a la tienda</a></p>`:''}
    <p style="color:#888;font-size:12px;margin-top:20px">${tienda}</p>
  </div>`;
  await _sendMail(email, `¡Bienvenido/a a ${tienda}!`, html, { fromName: tienda, replyTo: tiendaEmail || undefined });
}
async function emailCompraCliente(tenantId, pedidos, comprador){
  try{
    if(!pedidos || !pedidos.length) return;
    let email='';
    try{ const df=pedidos[0].datos_facturacion; const o=typeof df==='string'?JSON.parse(df):df; email=(o&&(o.email||o.mail))||''; }catch(e){}
    if(!email && comprador && comprador.id){ const {rows}=await pool.query('SELECT email FROM usuarios WHERE id=$1',[comprador.id]).catch(()=>({rows:[]})); email=rows[0]&&rows[0].email; }
    if(!email) return;
    const {tienda, baseUrl, email:tiendaEmail}=await _tiendaInfo(tenantId);
    const total=pedidos.reduce((s,p)=>s+Number(p.total||0),0);
    let bloques='';
    for(const p of pedidos){
      const filas=await _itemsPedidoHtml(p.id);
      const num=String(p.id).padStart(4,'0');
      bloques+=`<div style="margin-top:14px"><div style="font-weight:700;margin-bottom:6px">Pedido #${num}</div><table style="width:100%;border-collapse:collapse">${filas}<tr><td style="padding:8px 12px;font-weight:700">Total</td><td style="padding:8px 12px;text-align:right;font-weight:700">$${Number(p.total||0).toLocaleString('es-AR')}</td></tr></table></div>`;
    }
    const html=`<div style="font-family:system-ui,sans-serif;max-width:560px;margin:0 auto">
      <h2 style="color:#16a34a">¡Gracias por tu compra en ${tienda}!</h2>
      <p>Recibimos tu pedido. Este es el detalle:</p>
      ${bloques}
      <p style="font-size:18px;margin-top:14px">Total: <strong>$${total.toLocaleString('es-AR')}</strong></p>
      ${baseUrl?`<p style="margin-top:16px"><a href="${baseUrl}" style="background:#16a34a;color:#fff;padding:10px 18px;border-radius:8px;text-decoration:none">Ver la tienda</a></p>`:''}
      <p style="color:#888;font-size:12px;margin-top:20px">Cualquier duda, respondé este mail. ${tienda}</p>
    </div>`;
    await _sendMail(email, `Tu compra en ${tienda} — Pedido #${String(pedidos[0].id).padStart(4,'0')}`, html, { fromName: tienda, replyTo: tiendaEmail || undefined });
  }catch(e){ console.log('[mail-cliente] exc:', e.message); }
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
    res.json({token, user:sanitizeUser(rows[0])});
  }catch(e){ res.status(500).json({error:e.message}); }
});
app.post('/api/logout', auth(), async (req,res)=>{
  try{ const decoded=jwt.decode(req._token); const expira=new Date(decoded.exp*1000); await pool.query('INSERT INTO tokens_revocados (token_hash,expira) VALUES ($1,$2) ON CONFLICT DO NOTHING', [hashToken(req._token), expira]); await pool.query('DELETE FROM tokens_revocados WHERE expira<NOW()').catch(()=>{}); res.json({ok:true}); }catch(e){ res.status(500).json({error:e.message}); }
});
app.post('/api/refresh-token', auth(), async (req,res)=>{
  try{ const {rows}=await pool.query('SELECT id,rol,usuario,activo,tenant_id,es_owner FROM usuarios WHERE id=$1', [req.user.id]); if(!rows[0]||!rows[0].activo) return res.status(401).json({error:'Cuenta desactivada'}); const decoded=jwt.decode(req._token); await pool.query('INSERT INTO tokens_revocados (token_hash,expira) VALUES ($1,$2) ON CONFLICT DO NOTHING', [hashToken(req._token), new Date(decoded.exp*1000)]); const newToken=jwt.sign({id:rows[0].id, rol:rows[0].rol, usuario:rows[0].usuario, tenant_id:rows[0].tenant_id||1, es_owner:rows[0].es_owner||false}, JWT_SECRET, {expiresIn:'7d'}); res.json({token:newToken}); }catch(e){ res.status(500).json({error:e.message}); }
});
app.put('/api/me/otp', auth(), async (req,res)=>{ try{ const {activo}=req.body; await pool.query('UPDATE usuarios SET otp_activo=$1 WHERE id=$2 AND tenant_id=$3', [activo, req.user.id, req.tenantId]); res.json({ok:true}); }catch(e){ res.status(500).json({error:e.message}); } });

// Recuperar contraseña: el código va SOLO por email. La respuesta es siempre la misma
// (no confirma si el usuario existe ni devuelve el código: antes cualquiera podía tomar la cuenta del admin).
app.post('/api/forgot-password', authLimiter, async (req,res)=>{
  const generica={ok:true, mensaje:'Si los datos coinciden con una cuenta con email, te enviamos un código. Revisá tu correo (y el spam).'};
  try{
    const dato=String(req.body.usuario||req.body.email||'').trim();
    if(!dato) return res.status(400).json({error:'Escribí tu usuario o email'});
    const {rows}=await pool.query("SELECT id, email, nombre FROM usuarios WHERE (LOWER(usuario)=LOWER($1) OR LOWER(email)=LOWER($1)) AND tenant_id=$2 AND activo=true LIMIT 1", [dato, req.tenantId]);
    const u=rows[0];
    if(!u || !u.email || !resend) return res.json(generica);
    const codigo=crypto.randomBytes(5).toString('hex').toUpperCase(); // 10 caracteres, imposible de adivinar
    await pool.query("UPDATE usuarios SET reset_codigo=$1, reset_expira=NOW()+INTERVAL '1 hour' WHERE id=$2 AND tenant_id=$3", [codigo, u.id, req.tenantId]);
    const {tienda}=await _tiendaInfo(req.tenantId);
    await _sendMail(u.email, `Código para recuperar tu contraseña — ${tienda}`,
      `<div style="font-family:system-ui,sans-serif;max-width:480px;margin:0 auto"><h2>Recuperar contraseña</h2><p>Hola ${String(u.nombre||'').replace(/[<>&]/g,'')}, tu código es:</p><p style="font-size:26px;font-weight:800;letter-spacing:3px">${codigo}</p><p style="color:#666">Vence en 1 hora. Si no lo pediste, ignorá este mail.</p></div>`,
      { fromName: tienda });
    res.json(generica);
  }catch(e){ console.log('[forgot] ', e.message); res.json(generica); }
});
app.post('/api/reset-password', authLimiter, async (req,res)=>{
  try{
    const codigo=String(req.body.codigo||'').trim().toUpperCase();
    const {nueva_password}=req.body;
    if(!codigo||!nueva_password) return res.status(400).json({error:'Código y nueva contraseña requeridos'});
    const pwError=validatePassword(nueva_password);
    if(pwError) return res.status(400).json({error:pwError});
    const {rows}=await pool.query("SELECT id FROM usuarios WHERE reset_codigo<>'' AND UPPER(reset_codigo)=$1 AND reset_expira>NOW() AND tenant_id=$2", [codigo, req.tenantId]);
    if(!rows[0]) return res.status(400).json({error:'Código inválido o vencido. Pedí uno nuevo.'});
    const hash=await bcrypt.hash(nueva_password,12);
    await pool.query("UPDATE usuarios SET password=$1, reset_codigo='', reset_expira=NULL WHERE id=$2 AND tenant_id=$3", [hash, rows[0].id, req.tenantId]);
    res.json({ok:true});
  }catch(e){ res.status(500).json({error:'No se pudo cambiar la contraseña'}); }
});

app.post('/api/register', async (req,res)=>{
  try{
    const {nombre,usuario,password,telefono,email,direccion,nombre_fantasia}=req.body;
    if(!usuario||usuario.length<3) return res.status(400).json({error:'Min 3 caracteres'});
    if(!telefono||String(telefono).replace(/\D/g,'').length<8) return res.status(400).json({error:'Teléfono inválido (con característica)'});
    if(!email||!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(String(email).trim())) return res.status(400).json({error:'Email inválido'});
    const pwError=validatePassword(password); if(pwError) return res.status(400).json({error:pwError});
    // "ADMIN" y "admin" son el mismo usuario para el login: no dejar registrar variantes con mayúsculas
    const {rows:yaUs}=await pool.query('SELECT 1 FROM usuarios WHERE LOWER(usuario)=LOWER($1) AND tenant_id=$2', [String(usuario).trim(), req.tenantId]);
    if(yaUs[0]) return res.status(400).json({error:'Ese usuario ya existe. Elegí otro.'});
    const hash=await bcrypt.hash(password,12);
    const {rows:cfgAprob}=await pool.query("SELECT valor FROM configuracion WHERE tenant_id=$1 AND clave='registro_requiere_aprobacion'", [req.tenantId]);
    const requiereAprob = cfgAprob[0] && cfgAprob[0].valor==='true';
    const aprobado = !requiereAprob; // por defecto (sin config) el registro entra DIRECTO
    const {rows}=await pool.query('INSERT INTO usuarios (tenant_id,nombre,usuario,password,telefono,email,direccion,nombre_fantasia,aprobado,activo) VALUES ($8,$1,$2,$3,$4,$5,$6,$7,$9,$9) RETURNING id,nombre,usuario,telefono,email,aprobado,activo', [nombre,usuario,hash,telefono||'',email||'',direccion||'',nombre_fantasia||'', req.tenantId, aprobado]);
    if(email) emailBienvenida(req.tenantId, email, nombre).catch(()=>{});
    res.json(rows[0]);
  }catch(e){ res.status(400).json({error:e.message.includes('duplicate')?'Usuario ya existe':e.message}); }
});
// El cliente pide acceso a la lista mayorista (queda marcado para que el dueño lo apruebe en Clientes)
app.post('/api/me/solicitar-mayorista', auth(), async (req,res)=>{
  try{
    const { rows } = await pool.query('UPDATE usuarios SET mayorista_solicitado_at=COALESCE(mayorista_solicitado_at, NOW()) WHERE id=$1 AND tenant_id=$2 AND COALESCE(mayorista,false)=false RETURNING mayorista_solicitado_at', [req.user.id, req.tenantId]);
    res.json({ ok: true, solicitado: !!rows[0], ya_autorizado: !rows[0] });
  }catch(e){ res.status(500).json({error:e.message}); }
});
app.get('/api/me', auth(), async (req,res)=>{ try{ const {rows}=await pool.query('SELECT * FROM usuarios WHERE id=$1 AND tenant_id=$2', [req.user.id, req.tenantId]); res.json(sanitizeUser(rows[0])); }catch(e){ res.status(500).json({error:e.message}); } });
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
    const {nombre,telefono,email,direccion,nombre_fantasia,password,password_actual}=req.body;
    if(password){
      // Cambiar la contraseña exige la actual y una nueva segura
      const pwError=validatePassword(password); if(pwError) return res.status(400).json({error:pwError});
      const {rows:cur}=await pool.query('SELECT password FROM usuarios WHERE id=$1 AND tenant_id=$2', [req.user.id, req.tenantId]);
      if(!cur[0] || !password_actual || !(await bcrypt.compare(String(password_actual), cur[0].password))) return res.status(400).json({error:'La contraseña actual no es correcta'});
      const hash=await bcrypt.hash(password,12);
      await pool.query('UPDATE usuarios SET nombre=$1,telefono=$2,email=$3,direccion=$4,nombre_fantasia=$5,password=$6 WHERE id=$7 AND tenant_id=$8', [nombre,telefono,email,direccion,nombre_fantasia||'',hash,req.user.id, req.tenantId]);
    }
    else{ await pool.query('UPDATE usuarios SET nombre=$1,telefono=$2,email=$3,direccion=$4,nombre_fantasia=$5 WHERE id=$6 AND tenant_id=$7', [nombre,telefono,email,direccion,nombre_fantasia||'',req.user.id, req.tenantId]); }
    const {rows}=await pool.query('SELECT * FROM usuarios WHERE id=$1 AND tenant_id=$2', [req.user.id, req.tenantId]);
    res.json(sanitizeUser(rows[0]));
  }catch(e){ res.status(500).json({error:e.message}); }
});

// CONFIG
// Config pública: los visitantes no ven datos internos (mails de aviso, claves técnicas). El equipo ve todo.
const CONFIG_PRIVADA=/^(_|email_|smtp|resend)|token|secret|password|clave_api|api_?key/i;
app.get('/api/config', optionalAuth, async (req,res)=>{ try{ const {rows}=await pool.query('SELECT * FROM configuracion WHERE tenant_id=$1', [req.tenantId]); let staff=false; if(req.user){ const {rows:u}=await pool.query('SELECT rol FROM usuarios WHERE id=$1 AND tenant_id=$2', [req.user.id, req.tenantId]).catch(()=>({rows:[]})); staff=!!(u[0] && (u[0].rol==='admin'||u[0].rol==='subadmin')); } const cfg={}; rows.forEach(r=>{ if(staff || !CONFIG_PRIVADA.test(r.clave)) cfg[r.clave]=r.valor; }); res.json(cfg); }catch(e){ res.status(500).json({error:e.message}); } });
// Plan y funciones habilitadas del tenant actual (para que el frontend muestre/oculte)
app.get('/api/mi-plan', async (req,res)=>{
  try{ const d=await getTenantData(req.tenantId); res.json({ plan:d.plan, estado:d.estado, features:d.features, dias_restantes:d.dias_restantes }); }
  catch(e){ res.status(500).json({error:e.message}); }
});
app.put('/api/config', authPerm('config'), async (req,res)=>{ try{ for(const [k,v] of Object.entries(req.body)){ await pool.query("INSERT INTO configuracion (tenant_id,clave,valor) VALUES ($1,$2,$3) ON CONFLICT (tenant_id,clave) DO UPDATE SET valor=$3", [req.tenantId,k,v]); } res.json({ok:true}); }catch(e){ res.status(500).json({error:e.message}); } });

// LISTAS
app.get('/api/listas', async (req,res)=>{ try{ const {rows}=await pool.query('SELECT * FROM listas_precio WHERE tenant_id=$1 ORDER BY multiplicador', [req.tenantId]); res.json(rows); }catch(e){ res.status(500).json({error:e.message}); } });
app.put('/api/listas', authPerm('listas'), requiereFeature('listas_precio'), async (req,res)=>{ try{ const {listas}=req.body; if(!Array.isArray(listas)) return res.status(400).json({error:'Faltan las listas'});
  // El código de lista es único en toda la base: nunca pisar la lista de otra tienda
  const {rows:ajenas}=await pool.query('SELECT id FROM listas_precio WHERE id = ANY($1::text[]) AND tenant_id<>$2', [listas.map(l=>String(l&&l.id||'')), req.tenantId]);
  if(ajenas.length) return res.status(409).json({error:`El código de lista "${ajenas[0].id}" ya está en uso. Elegí otro.`});
  for(const l of listas){ await pool.query('INSERT INTO listas_precio (id,nombre,multiplicador,modo,color,compra_minima,promo_msg,tenant_id) VALUES ($1,$2,$3,$4,$5,$6,$7,$8) ON CONFLICT (id) DO UPDATE SET nombre=$2,multiplicador=$3,modo=$4,color=$5,compra_minima=$6,promo_msg=$7 WHERE listas_precio.tenant_id=EXCLUDED.tenant_id', [l.id,l.nombre,l.multiplicador,l.modo||'porcentaje',l.color||'#2563eb',l.compra_minima||0,l.promo_msg||'', req.tenantId]); } res.json({ok:true}); }catch(e){ res.status(500).json({error:e.message}); } });
app.post('/api/listas', authPerm('listas'), requiereFeature('listas_precio'), async (req,res)=>{ try{ const l=req.body; const {rows:ya}=await pool.query('SELECT 1 FROM listas_precio WHERE id=$1', [String(l.id||'')]); if(ya[0]) return res.status(409).json({error:'Ese código de lista ya está en uso. Elegí otro.'}); const {rows}=await pool.query('INSERT INTO listas_precio (id,nombre,multiplicador,modo,color,compra_minima,promo_msg,tenant_id) VALUES ($1,$2,$3,$4,$5,$6,$7,$8) RETURNING *', [l.id,l.nombre,l.multiplicador||1,l.modo||'porcentaje',l.color||'#2563eb',l.compra_minima||0,l.promo_msg||'', req.tenantId]); res.json(rows[0]); }catch(e){ res.status(400).json({error:e.message}); } });
app.put('/api/listas/:id', authPerm('listas'), requiereFeature('listas_precio'), async (req,res)=>{ try{ const l=req.body; await pool.query('UPDATE listas_precio SET nombre=$1,multiplicador=$2,modo=$3,color=$4,compra_minima=$5,promo_msg=$6 WHERE id=$7 AND tenant_id=$8', [l.nombre,l.multiplicador,l.modo,l.color,l.compra_minima||0,l.promo_msg||'',req.params.id, req.tenantId]); res.json({ok:true}); }catch(e){ res.status(500).json({error:e.message}); } });
app.delete('/api/listas/:id', authPerm('listas'), requiereFeature('listas_precio'), async (req,res)=>{ try{ await pool.query('DELETE FROM listas_precio WHERE id=$1 AND tenant_id=$2', [req.params.id, req.tenantId]); res.json({ok:true}); }catch(e){ res.status(500).json({error:e.message}); } });

// SECCIONES V4 con ignorar_stock
app.get('/api/secciones', async (req,res)=>{ try{ const {rows}=await pool.query('SELECT * FROM secciones WHERE tenant_id=$1 ORDER BY orden, id', [req.tenantId]); res.json(rows); }catch(e){ res.status(500).json({error:e.message}); } });
app.get('/api/secciones/:id', async (req,res)=>{ try{ const {rows}=await pool.query('SELECT * FROM secciones WHERE id=$1 AND tenant_id=$2', [req.params.id, req.tenantId]); if(!rows[0]) return res.status(404).json({error:'No encontrada'}); res.json(rows[0]); }catch(e){ res.status(500).json({error:e.message}); } });
app.put('/api/secciones/:id', authPerm('config'), async (req,res)=>{
  try{
    const {nombre,slug,descripcion,imagen,requiere_aprobacion,visible,orden,ignorar_stock,cp_origen,permitir_sin_stock}=req.body;
    if(requiere_aprobacion && Number(req.tenantId)!==1){
      const {rows:act}=await pool.query('SELECT requiere_aprobacion FROM secciones WHERE id=$1 AND tenant_id=$2', [req.params.id, req.tenantId]);
      const td=await getTenantData(req.tenantId).catch(()=>null);
      if(act[0] && !act[0].requiere_aprobacion && td && !featureActiva(td.features,'mayorista')) return res.status(403).json({error:'Las tiendas mayoristas con aprobación no están incluidas en tu plan', upgrade:true});
    }
    _secRestrCache.delete(String(req.tenantId));
    await pool.query('UPDATE secciones SET nombre=$1,slug=$2,descripcion=$3,imagen=$4,requiere_aprobacion=$5,visible=$6,orden=$7,ignorar_stock=$8,cp_origen=$9,permitir_sin_stock=$10 WHERE id=$11 AND tenant_id=$12', [nombre,slug,descripcion,imagen,requiere_aprobacion,visible,orden||0,ignorar_stock||false,cp_origen||'1888',permitir_sin_stock||false,req.params.id, req.tenantId]);
    res.json({ok:true});
  }catch(e){ res.status(500).json({error:e.message}); }
});
app.post('/api/secciones', authPerm('config'), async (req,res)=>{
  try{
    const {nombre,slug,descripcion,imagen,requiere_aprobacion,ignorar_stock,cp_origen}=req.body;
    const maxT = await limitePlan(req, 'max_tiendas');
    if(Number.isFinite(maxT)){
      const {rows:c}=await pool.query('SELECT COUNT(*)::int AS n FROM secciones WHERE tenant_id=$1', [req.tenantId]);
      if((c[0]?.n||0) >= maxT) return res.status(403).json({error:`Tu plan permite hasta ${maxT} ${maxT===1?'tienda':'tiendas'}. Pasate a un plan superior para sumar más.`, upgrade:true});
    }
    if(requiere_aprobacion && Number(req.tenantId)!==1){ const td=await getTenantData(req.tenantId).catch(()=>null); if(td && !featureActiva(td.features,'mayorista')) return res.status(403).json({error:'Las tiendas mayoristas con aprobación no están incluidas en tu plan', upgrade:true}); }
    _secRestrCache.delete(String(req.tenantId));
    const {rows}=await pool.query('INSERT INTO secciones (tenant_id,nombre,slug,descripcion,imagen,requiere_aprobacion,ignorar_stock,cp_origen) VALUES ($8,$1,$2,$3,$4,$5,$6,$7) RETURNING *', [nombre,slug,descripcion||'',imagen||'',requiere_aprobacion||false,ignorar_stock||false,cp_origen||'1888', req.tenantId]);
    res.json(rows[0]);
  }catch(e){ res.status(400).json({error:e.message}); }
});
// Productos con stock bajo el mínimo (para alertas en dashboard)
app.get('/api/stock-bajo', authPerm('productos'), async (req,res)=>{
  try{
    const {rows}=await pool.query(`SELECT p.id, p.nombre, p.modelo, p.imagen, p.categoria, p.stock, p.stock_minimo, s.nombre as seccion_nombre
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
// Re-hostea una imagen remota (ej. rxzweb.com) en Cloudinary. Cloudinary la baja desde SUS
// servidores (no Railway), así esquiva el bloqueo de Cloudflare. Si falla, devuelve la URL original.
const esCloudinaria = (u='') => /res\.cloudinary\.com|cloudinary/i.test(String(u));
const rehostImagen = async (url) => {
  const u = String(url || '').trim();
  if (!u || !/^https?:\/\//i.test(u) || esCloudinaria(u)) return u;
  if (!useCloudinary) return u;
  try {
    const r = await cloudinary.uploader.upload(u, { folder: 'productos/rxz', resource_type: 'image', quality: 'auto', fetch_format: 'auto' });
    return r.secure_url || u;
  } catch (e) {
    console.warn('rehostImagen falló:', u.slice(0,80), '-', String(e.message||e).slice(0,80));
    return u;
  }
};
// Tipo real de una imagen mirando sus primeros bytes (no confiar en el nombre ni en lo que dice el navegador)
function extImagenReal(buf){
  if(!buf || buf.length<12) return null;
  if(buf[0]===0xFF && buf[1]===0xD8 && buf[2]===0xFF) return '.jpg';
  if(buf.slice(0,8).equals(Buffer.from([0x89,0x50,0x4E,0x47,0x0D,0x0A,0x1A,0x0A]))) return '.png';
  if(buf.slice(0,4).toString('latin1')==='RIFF' && buf.slice(8,12).toString('latin1')==='WEBP') return '.webp';
  if(buf.slice(0,6).toString('latin1')==='GIF87a' || buf.slice(0,6).toString('latin1')==='GIF89a') return '.gif';
  if(buf.slice(4,12).toString('latin1')==='ftypavif') return '.avif';
  return null;
}
app.post('/api/upload', authPerm('config'), upload.single('imagen'), async (req,res)=>{
  try{
    if(!req.file) return res.status(400).json({error:'No file'});
    if(useCloudinary){
      try{ const r=await uploadToCloudinary(req.file.buffer); return res.json({url:r.secure_url}); }
      catch(ce){ console.error('Cloudinary falló, guardo en disco:', ce.message); }
    }
    // Respaldo en disco: solo imágenes de verdad, con extensión según su contenido (nunca .html/.svg/.js)
    const ext=extImagenReal(req.file.buffer);
    if(!ext) return res.status(400).json({error:'El archivo no es una imagen válida (jpg, png, webp, gif)'});
    const name=uuidv4()+ext;
    fs.writeFileSync(path.join(uploadsDir,name), req.file.buffer);
    return res.json({url:`/uploads/${name}`});
  }catch(e){ res.status(500).json({error:e.message}); }
});
app.post('/api/upload-base64', authPerm('config'), async (req,res)=>{
  try{
    const {data} = req.body;
    if(!data) return res.status(400).json({error:'No data'});
    const matches=String(data).match(/^data:(.+);base64,(.+)$/);
    if(!matches) return res.status(400).json({error:'Invalid base64'});
    const buffer=Buffer.from(matches[2],'base64');
    if(buffer.length > 8*1024*1024) return res.status(413).json({error:'La imagen es muy pesada (máx. 8 MB)'});
    const ext=extImagenReal(buffer);
    if(!ext) return res.status(400).json({error:'El archivo no es una imagen válida (jpg, png, webp, gif)'});
    if(useCloudinary){
      const r=await uploadToCloudinary(buffer);
      return res.json({url:r.secure_url});
    }else{
      const name=uuidv4()+ext; // el nombre lo elige el servidor (antes "filename" permitía escribir fuera de la carpeta)
      fs.writeFileSync(path.join(uploadsDir,name), buffer);
      return res.json({url:`/uploads/${name}`});
    }
  }catch(e){ res.status(500).json({error:e.message}); }
});

// POST /api/productos/rehost-imagenes — mueve a Cloudinary las imágenes que aún apuntan a rxzweb.com
// (Cloudinary las baja desde sus servidores, esquivando el bloqueo de Cloudflare). Procesa por lotes.
app.post('/api/productos/rehost-imagenes', authPerm('productos'), async (req,res)=>{
  const t = req.tenantId;
  try{
    if(Number(t)!==1) return res.status(403).json({error:'Disponible solo en la tienda del dueño'}); // el bot/proveedor es solo de la tienda propia
    if(!useCloudinary) return res.status(503).json({error:'Cloudinary no configurado'});
    if(process.env.REHOST_RXZ !== '1'){
      // Cloudflare de rxz bloquea a Cloudinary/Railway: estas fotos las sube el bot con su proxy.
      const { rows:rest } = await pool.query(
        `SELECT COUNT(DISTINCT p.id)::int AS n FROM productos p
         LEFT JOIN producto_imagenes pi ON pi.producto_id=p.id AND pi.tenant_id=p.tenant_id
         WHERE p.tenant_id=$1 AND (p.imagen ILIKE '%rxzweb%' OR pi.url ILIKE '%rxzweb%')`, [t]);
      return res.json({ ok:true, migradas:0, fallidas:0, restantes:(rest[0]&&rest[0].n)||0, via_bot:true });
    }
    const limit = Math.min(Math.max(parseInt(req.body && req.body.limit)||15, 1), 40);
    const { rows } = await pool.query(
      `SELECT DISTINCT p.id FROM productos p
       LEFT JOIN producto_imagenes pi ON pi.producto_id=p.id AND pi.tenant_id=p.tenant_id
       WHERE p.tenant_id=$1 AND (p.imagen ILIKE '%rxzweb%' OR pi.url ILIKE '%rxzweb%')
       ORDER BY p.id LIMIT $2`, [t, limit]);
    let migradas=0, fallidas=0; const detalle=[];
    for(const row of rows){
      try{
        const { rows:pr } = await pool.query('SELECT imagen FROM productos WHERE id=$1 AND tenant_id=$2', [row.id, t]);
        const img = (pr[0] && pr[0].imagen) || '';
        if(/rxzweb/i.test(img)){
          const nueva = await rehostImagen(img);
          if(nueva && nueva!==img){ await pool.query('UPDATE productos SET imagen=$1 WHERE id=$2 AND tenant_id=$3', [nueva, row.id, t]); migradas++; } else { fallidas++; }
        }
        const { rows:gi } = await pool.query("SELECT id,url FROM producto_imagenes WHERE producto_id=$1 AND tenant_id=$2 AND url ILIKE '%rxzweb%'", [row.id, t]);
        for(const g of gi){
          const nu = await rehostImagen(g.url);
          if(nu && nu!==g.url){ await pool.query('UPDATE producto_imagenes SET url=$1 WHERE id=$2', [nu, g.id]); migradas++; } else { fallidas++; }
        }
      }catch(ep){ fallidas++; if(detalle.length<10) detalle.push({id:row.id, error:String(ep.message||ep).slice(0,120)}); }
    }
    const { rows:rest } = await pool.query(
      `SELECT COUNT(DISTINCT p.id)::int AS n FROM productos p
       LEFT JOIN producto_imagenes pi ON pi.producto_id=p.id AND pi.tenant_id=p.tenant_id
       WHERE p.tenant_id=$1 AND (p.imagen ILIKE '%rxzweb%' OR pi.url ILIKE '%rxzweb%')`, [t]);
    res.json({ ok:true, migradas, fallidas, restantes: (rest[0] && rest[0].n) || 0, detalle: detalle.length?detalle:undefined });
  }catch(e){ res.status(500).json({error:e.message}); }
});

// PRODUCTOS V4 con permitir_sin_stock y es_digital
app.get('/api/productos/relacionados/:id', optionalAuth, async (req,res)=>{
  try{
    const {rows:base}=await pool.query('SELECT categoria, seccion_id, marca FROM productos WHERE id=$1 AND tenant_id=$2', [req.params.id, req.tenantId]);
    if(!base[0]) return res.json([]);
    const b=base[0];
    // Primero misma categoría/marca en la sección
    let {rows}=await pool.query(`SELECT p.*, s.nombre as seccion_nombre, s.color as seccion_color, ${IMG2('p')} FROM productos p LEFT JOIN secciones s ON p.seccion_id=s.id
      WHERE p.visible=true AND p.tenant_id=$5 AND p.id!=$1 AND p.seccion_id=$2 AND (p.categoria=$3 OR ($4<>'' AND p.marca=$4))
      ORDER BY (p.categoria=$3) DESC, RANDOM() LIMIT 8`, [req.params.id, b.seccion_id, b.categoria||'', b.marca||'', req.tenantId]);
    // Si no hay suficientes, completar con otros de la misma sección
    if(rows.length < 4){
      const ids=[req.params.id, ...rows.map(r=>r.id)];
      const {rows:extra}=await pool.query(`SELECT p.*, s.nombre as seccion_nombre, s.color as seccion_color, ${IMG2('p')} FROM productos p LEFT JOIN secciones s ON p.seccion_id=s.id
        WHERE p.visible=true AND p.tenant_id=$4 AND p.seccion_id=$1 AND p.id != ALL($2::int[]) ORDER BY RANDOM() LIMIT $3`, [b.seccion_id, ids, 8-rows.length, req.tenantId]);
      rows=[...rows, ...extra];
    }
    res.json(limpiarSiPublico(req, await sinRestringidas(req, await ocultarPreciosAprobacion(req, rows), { conservarConAcceso: true })));
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
    await pool.query('UPDATE productos SET stock = stock + $1, es_preventa=false, preventa_cupo=0, preventa_reservado=0, preventa_descuento_pct=0 WHERE id=$2 AND tenant_id=$3', [aStock, req.params.id, req.tenantId]);
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
// Búsqueda sin importar tildes ni mayúsculas ("estacion" encuentra "Estación")
const SQL_SIN_ACENTOS = (expr) => `translate(lower(${expr}), 'áàäâãéèëêíìïîóòöôõúùüûñç', 'aaaaaeeeeiiiiooooouuuunc')`;
const tokenBusqueda = (tk) => '%' + String(tk).toLowerCase().normalize('NFD').replace(/[\u0300-\u036f]/g, '').replace(/[%_]/g, '') + '%';

// ── Datos de producto que ven los clientes ──
// El precio de costo (ahora lo carga el bot con lo que cobra el proveedor) y las notas internas
// NO salen nunca al público: solo admin/sub-admin los reciben.
const CAMPOS_PRIVADOS_PROD = ['precio_original', 'notas', 'pendiente_aprobacion'];
const esStaffReq = (req) => !!(req.user && ['admin', 'subadmin'].includes(req.user.rol));
const limpiarProducto = (r) => { if (!r) return r; const o = { ...r }; for (const k of CAMPOS_PRIVADOS_PROD) delete o[k]; return o; };
const limpiarSiPublico = (req, rows) => esStaffReq(req) ? rows : rows.map(limpiarProducto);
// Tiendas con aprobación (mayorista): sin sesión no se ven precios (igual que en /api/productos)
// ── Tiendas con aprobación (mayorista): solo las ven y compran los clientes autorizados ──
// (marcados como "Cliente mayorista" en Clientes, o el equipo). Tampoco aparecen en el buscador
// general, novedades, ofertas ni preventa: es un catálogo aparte.
const _secRestrCache = new Map();
async function seccionesRestringidas(tenantId){
  const k = String(tenantId); const hit = _secRestrCache.get(k);
  if (hit && Date.now() - hit.ts < 30000) return hit.ids;
  const { rows } = await pool.query('SELECT id FROM secciones WHERE tenant_id=$1 AND requiere_aprobacion=true', [tenantId]).catch(()=>({rows:[]}));
  const ids = rows.map(r => r.id); _secRestrCache.set(k, { ids, ts: Date.now() }); return ids;
}
async function accesoMayorista(req){
  if (!req.user) return false;
  if (req._accMay !== undefined) return req._accMay;
  const { rows } = await pool.query('SELECT rol, mayorista, activo FROM usuarios WHERE id=$1 AND tenant_id=$2', [req.user.id, req.tenantId]).catch(()=>({rows:[]}));
  const u = rows[0];
  req._accMay = !!u && u.activo !== false && (u.rol === 'admin' || u.rol === 'subadmin' || !!u.mayorista);
  return req._accMay;
}
// Saca de un listado los productos de tiendas con aprobación (salvo que se pida conservarlos para quien tiene acceso)
async function sinRestringidas(req, rows, { conservarConAcceso = false } = {}){
  const restr = await seccionesRestringidas(req.tenantId);
  if (!restr.length || !rows.length) return rows;
  if (conservarConAcceso && await accesoMayorista(req)) return rows;
  const set = new Set(restr.map(String));
  return rows.filter(r => !set.has(String(r.seccion_id)));
}
async function ocultarPreciosAprobacion(req, rows){
  if (req.user || !rows.length) return rows;
  const { rows: secs } = await pool.query('SELECT id FROM secciones WHERE tenant_id=$1 AND (requiere_aprobacion=true OR slug=$2)', [req.tenantId, 'mayorista']).catch(()=>({rows:[]}));
  const ids = new Set(secs.map(x => String(x.id)));
  return ids.size ? rows.map(r => ids.has(String(r.seccion_id)) ? { ...r, precio_base: 0, precio_oferta: 0, precio_desde: null } : r) : rows;
}
// 2ª foto de la galería (la tarjeta la muestra al pasar el mouse)
const IMG2 = (a) => `(SELECT pi2.url FROM producto_imagenes pi2 WHERE pi2.producto_id=${a}.id AND pi2.tenant_id=${a}.tenant_id AND pi2.url<>COALESCE(${a}.imagen,'') ORDER BY pi2.orden, pi2.id LIMIT 1) AS imagen2`;

// GET /api/productos/ofertas — productos con descuento (oferta propia o promoción activa), el mayor % primero
app.get('/api/productos/ofertas', optionalAuth, async (req,res)=>{
  try{
    const lim = Math.min(Math.max(parseInt(req.query.limit)||16, 1), 40);
    const t = req.tenantId;
    const { rows: promos } = await pool.query(`SELECT productos_ids, categoria, secciones_ids FROM promociones WHERE tenant_id=$1 AND activo=true AND (fecha_desde IS NULL OR fecha_desde<=CURRENT_DATE) AND (fecha_hasta IS NULL OR fecha_hasta>=CURRENT_DATE)`, [t]).catch(()=>({rows:[]}));
    const ids = []; const cats = [];
    for (const pr of promos) {
      String(pr.productos_ids||'').split(',').map(x=>parseInt(x)).filter(Boolean).forEach(x=>ids.push(x));
      if (pr.categoria && !String(pr.productos_ids||'').trim()) cats.push(pr.categoria);
    }
    const { rows } = await pool.query(`SELECT p.*, s.nombre AS seccion_nombre, s.color AS seccion_color, ${IMG2('p')}
        FROM productos p LEFT JOIN secciones s ON s.id=p.seccion_id
        WHERE p.tenant_id=$1 AND p.visible=true AND COALESCE(s.visible,true)=true AND COALESCE(s.requiere_aprobacion,false)=false
          AND (p.stock>0 OR p.permitir_sin_stock=true OR p.es_digital=true)
          AND ((p.precio_oferta>0 AND p.precio_oferta<p.precio_base) OR p.id = ANY($2::int[]) OR p.categoria = ANY($3::text[]))
        ORDER BY CASE WHEN p.precio_oferta>0 AND p.precio_oferta<p.precio_base THEN 1 - p.precio_oferta/NULLIF(p.precio_base,0) ELSE 0 END DESC, p.created_at DESC
        LIMIT $4`, [t, ids, cats, lim]);
    res.json(limpiarSiPublico(req, await sinRestringidas(req, rows)));
  }catch(e){ res.status(500).json({error:e.message}); }
});
app.get('/api/productos/preventa', optionalAuth, async (req,res)=>{
  try{
    const {seccion_id}=req.query;
    let q=`SELECT p.*, s.nombre as seccion_nombre, s.color as seccion_color, ${IMG2('p')} FROM productos p LEFT JOIN secciones s ON p.seccion_id=s.id WHERE p.visible=true AND p.es_preventa=true AND p.tenant_id=$1`;
    const params=[req.tenantId];
    if(seccion_id && seccion_id!=='all'){ params.push(seccion_id); q+=` AND p.seccion_id=$${params.length}`; }
    q+=' ORDER BY p.preventa_fecha ASC NULLS LAST, p.created_at DESC LIMIT 30';
    const {rows}=await pool.query(q, params);
    res.json(limpiarSiPublico(req, await sinRestringidas(req, await ocultarPreciosAprobacion(req, rows))));
  }catch(e){ res.status(500).json({error:e.message}); }
});
app.get('/api/productos/novedades', optionalAuth, async (req,res)=>{
  try{
    const {seccion_id, limit}=req.query;
    let q=`SELECT p.*, s.nombre as seccion_nombre, s.color as seccion_color, ${IMG2('p')} FROM productos p LEFT JOIN secciones s ON p.seccion_id=s.id WHERE p.visible=true AND p.tenant_id=$1`;
    const params=[req.tenantId];
    if(seccion_id && seccion_id!=='all'){ params.push(seccion_id); q+=` AND p.seccion_id=$${params.length}`; }
    q+=` ORDER BY p.created_at DESC LIMIT ${Math.min(Number(limit)||12, 30)}`;
    const {rows}=await pool.query(q, params);
    res.json(limpiarSiPublico(req, await sinRestringidas(req, await ocultarPreciosAprobacion(req, rows))));
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
      for(const tk of toks){ where.push(`${SQL_SIN_ACENTOS(campos)} LIKE $${pi}`); params.push(tokenBusqueda(tk)); pi++; }
    }
    if(categoria){ where.push(`categoria=$${pi}`); params.push(categoria); pi++; }
    if(seccion_id){ where.push(`seccion_id=$${pi}`); params.push(seccion_id); pi++; }
    if(marca){ where.push(`marca ILIKE $${pi}`); params.push(`%${marca}%`); pi++; }
    // Mayorista / tiendas con aprobación: solo clientes autorizados; fuera de su tienda no aparecen nunca (salvo en el panel)
    const restr = await seccionesRestringidas(req.tenantId);
    if(restr.length){
      if(seccion_id && restr.includes(parseInt(seccion_id, 10))){
        if(!(await accesoMayorista(req))) return res.json({ productos: [], total: 0, page: 1, totalPages: 0, bloqueado: true });
      } else if(!seccion_id && !incluirOcultos){ where.push(`seccion_id <> ALL($${pi}::int[])`); params.push(restr); pi++; }
    }
    const limN=Math.min(Math.max(parseInt(limit)||50,1),10000), pagN=Math.max(parseInt(page)||1,1); // tope: no volcar sin límite ni romper con página negativa
    const offset=(pagN-1)*limN;
    const countQ=`SELECT COUNT(*) FROM productos WHERE ${where.join(' AND ')}`;
    const {rows:cRows}=await pool.query(countQ, params);
    const total=parseInt(cRows[0].count);
    const query=`SELECT *, (SELECT MIN(CASE WHEN v.precio_oferta>0 AND v.precio_oferta<v.precio THEN v.precio_oferta ELSE v.precio END) FROM variantes v WHERE v.producto_id=productos.id AND v.tenant_id=productos.tenant_id AND v.precio>0) AS precio_desde, (SELECT v.moneda FROM variantes v WHERE v.producto_id=productos.id AND v.tenant_id=productos.tenant_id AND v.precio>0 ORDER BY (CASE WHEN v.precio_oferta>0 AND v.precio_oferta<v.precio THEN v.precio_oferta ELSE v.precio END) ASC LIMIT 1) AS moneda_desde, ${IMG2('productos')} FROM productos WHERE ${where.join(' AND ')} ORDER BY ${req.query.orden === 'lista' ? 'posicion ASC, id ASC' : 'created_at DESC'} LIMIT $${pi} OFFSET $${pi+1}`;
    const {rows}=await pool.query(query, [...params, limN, offset]);
    // hide price mayorista sin login
    let result=rows;
    if(!req.user){
      const {rows:secs}=await pool.query('SELECT id FROM secciones WHERE slug=$1 AND tenant_id=$2', ['mayorista', req.tenantId]).catch(()=>({rows:[]}));
      const mayId=secs[0]?.id;
      if(mayId) result=rows.map(r=> r.seccion_id==mayId ? {...r, precio_base:0, precio_oferta:0} : r);
    }
    if(!esAdminReq) result=result.map(limpiarProducto);
    res.json({productos:result, total, page:pagN, totalPages:Math.ceil(total/limN)});
  }catch(e){ res.status(500).json({error:e.message}); }
});
app.get('/api/categorias', optionalAuth, async (req,res)=>{ try{ const {seccion_id}=req.query; if(seccion_id && (await seccionesRestringidas(req.tenantId)).includes(parseInt(seccion_id,10)) && !(await accesoMayorista(req))) return res.json([]); let q='SELECT DISTINCT categoria FROM productos WHERE visible=true AND tenant_id=$1'; const params=[req.tenantId]; if(seccion_id){ q+=' AND seccion_id=$2'; params.push(seccion_id); } q+=' ORDER BY categoria'; const {rows}=await pool.query(q, params); res.json(rows.map(r=>r.categoria).filter(Boolean)); }catch(e){ res.status(500).json({error:e.message}); } });

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
    const {rows:exM}=await pool.query('SELECT 1 FROM categorias_meta WHERE categoria=$1 AND tenant_id=$2', [n, req.tenantId]);
    if(ex.length || exM.length) return res.status(400).json({error:'Esa categoría ya existe'});
    await pool.query('INSERT INTO categorias_meta (tenant_id, categoria, orden, visible) VALUES ($2, $1, 0, true) ON CONFLICT DO NOTHING', [n, req.tenantId]);
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
      await pool.query(`INSERT INTO categorias_meta (tenant_id, categoria, orden, visible) VALUES ($4,$1,$2,$3)
        ON CONFLICT (tenant_id, categoria) DO UPDATE SET orden=$2, visible=$3`, [c.nombre, c.orden||0, c.visible!==false, req.tenantId]);
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
    if(!orig[0]){ return res.status(404).json({error:'No encontrado'}); } // el finally libera la conexión (antes se liberaba dos veces y podía tirar el servidor)
    const p=orig[0];
    await client.query('BEGIN');
    const {rows}=await client.query(`INSERT INTO productos (tenant_id,seccion_id,categoria,modelo,nombre,precio_base,precio_original,stock,stock_minimo,imagen,notas,compatibilidad,descripcion,sku,tipo,moneda,precio_oferta,envio_gratis,visible,peso,alto,ancho,largo,permitir_sin_stock,es_digital,marca,usa_variantes) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,$23,$24,$25,$26,$27) RETURNING *`,
      [t, p.seccion_id, p.categoria, p.modelo, (p.nombre||p.modelo||'')+' (copia)', p.precio_base, p.precio_original, 0, p.stock_minimo, p.imagen, p.notas, p.compatibilidad, p.descripcion, p.sku?p.sku+'-copia':'', p.tipo, p.moneda, p.precio_oferta, p.envio_gratis, false, p.peso, p.alto, p.ancho, p.largo, p.permitir_sin_stock, p.es_digital, p.marca, p.usa_variantes]);
    const nuevo=rows[0];
    // Atributos + sus valores (mapeando al nuevo producto)
    const {rows:atrs}=await client.query('SELECT * FROM producto_atributos WHERE producto_id=$1 AND tenant_id=$2 ORDER BY orden,id', [p.id, t]);
    for(const a of atrs){
      const {rows:na}=await client.query('INSERT INTO producto_atributos (tenant_id,producto_id,nombre,orden) VALUES ($1,$2,$3,$4) RETURNING id', [t, nuevo.id, a.nombre, a.orden||0]);
      const {rows:vals}=await client.query('SELECT valor,orden,imagen FROM producto_atributo_valores WHERE atributo_id=$1 AND tenant_id=$2 ORDER BY orden,id', [a.id, t]);
      for(const v of vals){ await client.query('INSERT INTO producto_atributo_valores (tenant_id,atributo_id,valor,orden,imagen) VALUES ($1,$2,$3,$4,$5)', [t, na[0].id, v.valor, v.orden||0, v.imagen||'']); }
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
    if(!(await productoDeTienda(pool, tid, id))) return res.status(404).json({error:'Producto no encontrado'});
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
// Importación masiva desde Excel. Se manda por partes (lotes) desde el panel.
// Los productos existentes se buscan SOLO dentro de la sección destino (antes buscaba en toda la tienda
// y un Excel del mayorista podía pisar el precio de un producto igual de otra sección).
app.post('/api/productos/bulk', authPerm('productos'), async (req,res)=>{
  try{
    const { productos, reemplazar, modo, seccion_id } = req.body || {};
    const t = req.tenantId;
    const S = (v, n=300) => (v===undefined || v===null) ? '' : String(v).replace(/\s+/g,' ').trim().slice(0, n);
    const N = (v) => { const n = Number(v); return Number.isFinite(n) ? n : 0; };
    const I = (v) => (v===undefined || v===null || v==='') ? null : Math.trunc(N(v));
    const lista = (Array.isArray(productos) ? productos : []).slice(0, 5000);
    const secDest = parseInt(seccion_id, 10) || null;
    if(secDest){ const {rows}=await pool.query('SELECT 1 FROM secciones WHERE id=$1 AND tenant_id=$2', [secDest, t]); if(!rows[0]) return res.status(400).json({error:'La sección elegida no es de esta tienda'}); }
    const secDe = (p) => secDest || parseInt(p.seccion_id, 10) || null;
    const buscar = async (p) => {
      const sec = secDe(p); const sku = S(p.sku, 100); const nom = S(p.nombre || p.modelo);
      if(sku){ const {rows}=await pool.query('SELECT id FROM productos WHERE sku=$1 AND tenant_id=$2 AND ($3::int IS NULL OR seccion_id=$3) LIMIT 1', [sku, t, sec]); if(rows[0]) return rows[0]; }
      if(nom){ const {rows}=await pool.query('SELECT id FROM productos WHERE LOWER(TRIM(nombre))=LOWER($1) AND tenant_id=$2 AND ($3::int IS NULL OR seccion_id=$3) LIMIT 1', [nom, t, sec]); if(rows[0]) return rows[0]; }
      return null;
    };
    const insertar = (p) => pool.query(`INSERT INTO productos (tenant_id,seccion_id,categoria,modelo,nombre,precio_base,precio_oferta,precio_original,stock,imagen,sku,descripcion,compatibilidad,peso,alto,ancho,largo,visible,permitir_sin_stock,posicion)
        VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,true,$18,$19)`,
      [t, secDe(p) || 1, S(p.categoria,200), S(p.modelo,200), S(p.nombre || p.modelo), N(p.precio_base), N(p.precio_oferta), N(p.precio_original), I(p.stock) ?? 0,
       S(p.imagen,2000), S(p.sku,100), S(p.descripcion,8000), S(p.compatibilidad,2000), N(p.peso), N(p.alto), N(p.ancho), N(p.largo), !!p.permitir_sin_stock, I(p.posicion) ?? 0]);
    const actualizar = (id, p) => pool.query(`UPDATE productos SET
        categoria=CASE WHEN $1<>'' THEN $1 ELSE categoria END, precio_base=$2, precio_oferta=$3,
        precio_original=CASE WHEN $4>0 THEN $4 ELSE precio_original END,
        stock=COALESCE($5::int, stock),
        compatibilidad=CASE WHEN $6<>'' THEN $6 ELSE compatibilidad END,
        posicion=COALESCE($7::int, posicion),
        permitir_sin_stock=COALESCE($8::boolean, permitir_sin_stock),
        peso=CASE WHEN $9>0 THEN $9 ELSE peso END, alto=CASE WHEN $10>0 THEN $10 ELSE alto END,
        ancho=CASE WHEN $11>0 THEN $11 ELSE ancho END, largo=CASE WHEN $12>0 THEN $12 ELSE largo END
      WHERE id=$13 AND tenant_id=$14`,
      [S(p.categoria,200), N(p.precio_base), N(p.precio_oferta), N(p.precio_original), I(p.stock), S(p.compatibilidad,2000), I(p.posicion),
       (p.permitir_sin_stock===undefined || p.permitir_sin_stock===null) ? null : !!p.permitir_sin_stock, N(p.peso), N(p.alto), N(p.ancho), N(p.largo), id, t]);
    let insertados=0, actualizados=0, saltados=0, errores=0, primerError=null;
    const fallo = (e, p) => { errores++; if(!primerError) primerError = `${S(p && (p.nombre || p.modelo), 80)}: ${String(e.message || e).slice(0,140)}`; };

    // Productos de la sección que ya NO vienen en el Excel → sin stock u ocultos (se llama una vez al final)
    if(modo==='marcar_faltantes'){
      if(!secDest) return res.status(400).json({error:'Falta la sección'});
      const presentes = Array.isArray(req.body.presentes) ? req.body.presentes : [];
      if(!presentes.length) return res.status(400).json({error:'El Excel vino vacío: no toco nada'});
      const skus = new Set(presentes.map(x => S(x && x.sku, 100)).filter(Boolean));
      const noms = new Set(presentes.map(x => S(x && x.nombre).toLowerCase()).filter(Boolean));
      const {rows} = await pool.query('SELECT id, sku, nombre FROM productos WHERE tenant_id=$1 AND seccion_id=$2', [t, secDest]);
      const faltan = rows.filter(r => !(r.sku && skus.has(String(r.sku).trim())) && !noms.has(S(r.nombre).toLowerCase())).map(r => r.id);
      if(faltan.length){
        if(req.body.accion==='borrar'){
          // Borrado seguro: el historial de pedidos queda intacto (solo se desvincula el producto)
          await pool.query('UPDATE pedido_items SET producto_id=NULL WHERE producto_id = ANY($1::int[])', [faltan]).catch(()=>{});
          await pool.query('UPDATE orden_compra_items SET producto_id=NULL WHERE producto_id = ANY($1::int[])', [faltan]).catch(()=>{});
          for(const tb of ['precios_fijos','historial_precios','notificaciones_stock','producto_imagenes','variantes','favoritos']) await pool.query(`DELETE FROM ${tb} WHERE producto_id = ANY($1::int[])`, [faltan]).catch(()=>{});
          await pool.query('DELETE FROM productos WHERE id = ANY($1::int[]) AND tenant_id=$2', [faltan, t]);
        }
        else if(req.body.accion==='ocultar') await pool.query('UPDATE productos SET visible=false WHERE id = ANY($1::int[]) AND tenant_id=$2', [faltan, t]);
        else await pool.query('UPDATE productos SET stock=0, permitir_sin_stock=false WHERE id = ANY($1::int[]) AND tenant_id=$2', [faltan, t]);
      }
      return res.json({ok:true, modo, marcados: faltan.length});
    }
    // Solo corregir categorías
    if(modo==='solo_categorias'){
      for(const p of lista){
        try{
          const cat = S(p.categoria,200); if(!cat || cat==='Sin categoría') { saltados++; continue; }
          const ex = await buscar(p);
          if(ex){ await pool.query('UPDATE productos SET categoria=$1 WHERE id=$2 AND tenant_id=$3', [cat, ex.id, t]); actualizados++; await pool.query('INSERT INTO categorias_meta (tenant_id, categoria, orden, visible) VALUES ($2,$1,0,true) ON CONFLICT DO NOTHING', [cat, t]).catch(()=>{}); }
          else saltados++;
        }catch(e){ fallo(e, p); }
      }
      return res.json({ok:true, modo, actualizados, saltados, noEncontrados: saltados, errores, primer_error: primerError || undefined});
    }
    // Borrar la sección y cargar de cero (solo el primer lote; los siguientes vienen como 'insertar')
    if(modo==='reemplazar' || reemplazar){
      const sec = secDest || 1;
      const {rows:ids} = await pool.query('SELECT id FROM productos WHERE tenant_id=$1 AND seccion_id=$2', [t, sec]);
      const lst = ids.map(r => r.id);
      if(lst.length){
        // El historial de pedidos queda intacto (solo se desvincula el producto). Antes se borraban TODOS los ítems de pedidos de la tienda.
        await pool.query('UPDATE pedido_items SET producto_id=NULL WHERE producto_id = ANY($1::int[])', [lst]).catch(()=>{});
        await pool.query('UPDATE orden_compra_items SET producto_id=NULL WHERE producto_id = ANY($1::int[])', [lst]).catch(()=>{});
        for(const tb of ['precios_fijos','historial_precios','notificaciones_stock','producto_imagenes','variantes','favoritos']) await pool.query(`DELETE FROM ${tb} WHERE producto_id = ANY($1::int[])`, [lst]).catch(()=>{});
        await pool.query('DELETE FROM productos WHERE id = ANY($1::int[]) AND tenant_id=$2', [lst, t]);
      }
    }
    for(const p of lista){
      try{
        if(!S(p.nombre || p.modelo)) { saltados++; continue; }
        if(modo==='reemplazar' || reemplazar || modo==='insertar'){ await insertar(p); insertados++; continue; }
        const ex = await buscar(p);
        if(modo==='solo_nuevos'){ if(ex){ saltados++; continue; } await insertar(p); insertados++; continue; }
        // crear_actualizar (por defecto)
        if(ex){ await actualizar(ex.id, p); actualizados++; } else { await insertar(p); insertados++; }
      }catch(e){ fallo(e, p); }
    }
    res.json({ok:true, modo: modo || 'crear_actualizar', insertados, actualizados, saltados, errores, primer_error: primerError || undefined});
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
  const kb=Buffer.from(String(key||'')), eb=Buffer.from(String(process.env.BOT_API_KEY));
  if (kb.length!==eb.length || !crypto.timingSafeEqual(kb, eb)) return res.status(401).json({ error: 'X-Bot-Key inválida' });
  // El bot es solo para la tienda del dueño (tienda 1). BOT_TENANT_ID existe solo para pruebas.
  req.botTenantId = parseInt(process.env.BOT_TENANT_ID || '1', 10);
  next();
};
// rxzweb está detrás de Cloudflare: ni Railway ni Cloudinary pueden bajar esas fotos (solo pierde tiempo).
// Las deja como vienen y el bot las sube después por /api/bot/foto (las baja con su proxy residencial).
const rehostBot = (u) => (/rxzweb\.com/i.test(String(u || '')) && process.env.REHOST_RXZ !== '1') ? String(u || '') : rehostImagen(u);
const uploadBot = multer({ storage: multer.memoryStorage(), limits: { fileSize: 12 * 1024 * 1024 },
  fileFilter: (req, file, cb) => cb(null, /^image\//i.test(file.mimetype || '')) });

// GET /api/bot/fotos-externas — URLs (distintas) de fotos que siguen apuntando al proveedor.
app.get('/api/bot/fotos-externas', botAuth, async (req, res) => {
  const t = req.botTenantId;
  try {
    const patron = '%rxzweb%';
    const { rows } = await pool.query(
      `SELECT url, COUNT(*)::int AS usos FROM (
         SELECT imagen AS url FROM productos WHERE tenant_id=$1 AND imagen ILIKE $2
         UNION ALL
         SELECT url FROM producto_imagenes WHERE tenant_id=$1 AND url ILIKE $2
       ) x GROUP BY url ORDER BY url`, [t, patron]);
    const { rows: np } = await pool.query(
      `SELECT COUNT(DISTINCT p.id)::int AS n FROM productos p
       LEFT JOIN producto_imagenes pi ON pi.producto_id=p.id AND pi.tenant_id=p.tenant_id
       WHERE p.tenant_id=$1 AND (p.imagen ILIKE $2 OR pi.url ILIKE $2)`, [t, patron]);
    res.json({ ok: true, total: rows.length, productos: (np[0] && np[0].n) || 0, urls: rows.map(r => r.url) });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// POST /api/bot/foto — el bot manda una foto que bajó del proveedor (multipart: imagen + origen).
// Se sube a Cloudinary y se reemplaza la URL de origen en TODOS los productos/galerías que la usen.
// También acepta JSON { origen, nueva } (nueva = URL de Cloudinary ya subida) para solo reemplazar.
app.post('/api/bot/foto', botAuth, (req, res, next) => uploadBot.single('imagen')(req, res, (err) => {
  if (err) return res.status(400).json({ error: err.code === 'LIMIT_FILE_SIZE' ? 'Imagen demasiado grande (máx. 12 MB)' : err.message });
  next();
}), async (req, res) => {
  const t = req.botTenantId;
  try {
    const origen = String((req.body && req.body.origen) || '').trim();
    if (!/^https?:\/\//i.test(origen)) return res.status(400).json({ error: 'origen inválido' });
    let nueva = String((req.body && req.body.nueva) || '').trim();
    if (req.file) {
      if (!useCloudinary) return res.status(503).json({ error: 'Cloudinary no configurado' });
      // public_id fijo por URL de origen: si se reintenta, pisa la misma foto (no duplica en Cloudinary).
      const publicId = 'rxz_' + crypto.createHash('sha1').update(origen).digest('hex').slice(0, 24);
      const r = await new Promise((resolve, reject) => {
        const s = cloudinary.uploader.upload_stream({
          folder: 'productos/rxz', public_id: publicId, overwrite: true, resource_type: 'image',
          transformation: [{ width: 1600, height: 1600, crop: 'limit', quality: 'auto' }],
        }, (e, out) => e ? reject(e) : resolve(out));
        s.end(req.file.buffer);
      });
      nueva = r.secure_url;
    }
    if (!req.file && !nueva && req.body && (req.body.remoto === true || req.body.remoto === 'true')) {
      // El bot no pudo bajarla: probamos que Cloudinary la baje directo (a veces Cloudflare lo deja pasar)
      const r = await rehostImagen(origen);
      if (r === origen) return res.status(422).json({ error: 'Cloudinary tampoco pudo bajarla' });
      nueva = r;
    }
    if (!nueva || !esCloudinaria(nueva)) return res.status(400).json({ error: 'Falta la imagen' });
    const a = await pool.query('UPDATE productos SET imagen=$1 WHERE tenant_id=$2 AND imagen=$3', [nueva, t, origen]);
    const b = await pool.query('UPDATE producto_imagenes SET url=$1 WHERE tenant_id=$2 AND url=$3', [nueva, t, origen]);
    res.json({ ok: true, url: nueva, reemplazos: a.rowCount + b.rowCount });
  } catch (e) { res.status(500).json({ error: String(e.message || e).slice(0, 200) }); }
});

// POST /api/bot/sync — recibe un lote de productos del proveedor y hace upsert por SKU.
// Body: { productos: [ { sku, nombre, precio_base, precio_oferta, stock, imagen, categoria, envio_gratis, variantes:[{nombre,valor,stock,precio}] } ], seccion_id? }
app.post('/api/bot/sync', botAuth, async (req, res) => {
  const t = req.botTenantId;
  try {
    const { productos, seccion_id } = req.body;
    const ocultarNuevos = !!req.body.ocultar_nuevos; // el bot pide aprobación por Telegram antes de publicar
    const nuevos = [];
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
        const costo = Math.max(0, Number(p.costo) || 0); // lo que cobra el proveedor → precio de costo (ganancia del dashboard)

        const { rows } = await pool.query('SELECT id FROM productos WHERE sku=$1 AND tenant_id=$2 LIMIT 1', [skuT, t]);
        let prodId;
        if (rows[0]) {
          // Existe → actualiza SOLO precio/stock/oferta/envío gratis. NO pisa nombre/imagen/categoría (por si Leandro las editó a mano).
          prodId = rows[0].id;
          await pool.query(
            `UPDATE productos SET precio_base=$1, precio_oferta=$2, stock=$3, precio_original=CASE WHEN $6>0 THEN $6 ELSE precio_original END WHERE id=$4 AND tenant_id=$5`,
            [precioBase, precioOferta, stock, prodId, t, costo]);
          actualizados++;
        } else {
          // Nuevo → inserta completo en la sección destino.
          // Re-hostear la imagen principal en Cloudinary (independiza de rxz/hotlink).
          const imagenRe = await rehostBot(imagen);
          const { rows: ins } = await pool.query(
            `INSERT INTO productos (tenant_id,seccion_id,categoria,modelo,nombre,descripcion,precio_base,precio_oferta,stock,imagen,sku,envio_gratis,peso,alto,ancho,largo,visible,pendiente_aprobacion,precio_original,marca)
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20) RETURNING id`,
            [t, secId, categoria, nombre, nombre, descripcion, precioBase, precioOferta, stock, imagenRe, skuT, false, peso, alto, ancho, largo, !ocultarNuevos, ocultarNuevos, costo, marcaDeNombre(nombre)]);
          prodId = ins[0].id;
          if (nuevos.length < 300) nuevos.push({ id: prodId, sku: skuT, nombre, precio: precioOferta > 0 ? precioOferta : precioBase, imagen: imagenRe, categoria });
          // Galería completa: todas las imágenes del proveedor (también re-hosteadas)
          const galeria = Array.isArray(p.imagenes) && p.imagenes.length ? p.imagenes : (imagen ? [imagen] : []);
          for (let gi = 0; gi < galeria.length; gi++) {
            const urlRe = await rehostBot(galeria[gi]);
            await pool.query('INSERT INTO producto_imagenes (tenant_id,producto_id,url,orden) VALUES ($1,$2,$3,$4) ON CONFLICT DO NOTHING', [t, prodId, urlRe, gi]).catch(()=>{});
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

    res.json({ ok: true, seccion_id: secId, total: productos.length, insertados, actualizados, errores, nuevos, ocultos: ocultarNuevos, primer_error: primerError || undefined, detalles: detalles.length ? detalles : undefined });
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

    // IDs de la sección DEPOSITO
    const { rows: idsRows } = await pool.query('SELECT id FROM productos WHERE seccion_id=$1 AND tenant_id=$2', [secId, t]);
    const allIds = idsRows.map(x => x.id);

    // Excluir los productos que ya están en pedidos (FK: no se pueden borrar, se conservan por historial)
    let usados = new Set();
    if (allIds.length) {
      const { rows: usadosRows } = await pool.query('SELECT DISTINCT producto_id FROM pedido_items WHERE producto_id = ANY($1::int[])', [allIds]);
      usados = new Set(usadosRows.map(x => x.producto_id));
    }
    const borrables = allIds.filter(id => !usados.has(id));

    let borrados = 0;
    if (borrables.length) {
      await pool.query('DELETE FROM producto_imagenes WHERE producto_id = ANY($1::int[])', [borrables]).catch(()=>{});
      await pool.query('DELETE FROM variantes WHERE producto_id = ANY($1::int[])', [borrables]).catch(()=>{});
      await pool.query('DELETE FROM favoritos WHERE producto_id = ANY($1::int[])', [borrables]).catch(()=>{});
      const r = await pool.query('DELETE FROM productos WHERE id = ANY($1::int[])', [borrables]);
      borrados = r.rowCount;
    }

    res.json({ ok: true, seccion_id: secId, borrados, total_previo: total, conservados_en_pedidos: usados.size });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// POST /api/bot/deduplicar — elimina productos duplicados por SKU (deja el de menor id).
// Reengancha pedidos y ordenes de compra al que queda (no rompe historial ni FK).
app.post('/api/bot/deduplicar', botAuth, async (req, res) => {
  const t = req.botTenantId;
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    // Grupos de SKU con mas de una fila
    const { rows: grupos } = await client.query(
      `SELECT sku, MIN(id) AS keep_id, COUNT(*)::int AS n
         FROM productos
        WHERE tenant_id=$1 AND sku IS NOT NULL AND sku<>''
        GROUP BY sku HAVING COUNT(*) > 1`, [t]);
    let borrados = 0, grupos_afectados = 0;
    for (const g of grupos) {
      const { rows: dups } = await client.query(
        'SELECT id FROM productos WHERE tenant_id=$1 AND sku=$2 AND id<>$3', [t, g.sku, g.keep_id]);
      const dupIds = dups.map(d => d.id);
      if (!dupIds.length) continue;
      grupos_afectados++;
      // Reenganchar historial de pedidos/compras al producto que se conserva
      await client.query('UPDATE pedido_items SET producto_id=$1 WHERE producto_id = ANY($2::int[])', [g.keep_id, dupIds]).catch(()=>{});
      await client.query('UPDATE orden_compra_items SET producto_id=$1 WHERE producto_id = ANY($2::int[])', [g.keep_id, dupIds]).catch(()=>{});
      // Tablas sin ON DELETE CASCADE: limpiar del duplicado
      await client.query('DELETE FROM precios_fijos WHERE producto_id = ANY($1::int[])', [dupIds]).catch(()=>{});
      await client.query('DELETE FROM historial_precios WHERE producto_id = ANY($1::int[])', [dupIds]).catch(()=>{});
      // Borrar duplicados (imagenes/variantes/favoritos/etc. caen por ON DELETE CASCADE)
      const r = await client.query('DELETE FROM productos WHERE id = ANY($1::int[]) AND tenant_id=$2', [dupIds, t]);
      borrados += r.rowCount;
    }
    await client.query('COMMIT');
    res.json({ ok: true, grupos_afectados, borrados });
  } catch (e) {
    await client.query('ROLLBACK').catch(()=>{});
    res.status(500).json({ error: e.message });
  } finally {
    client.release();
  }
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

// Productos nuevos del proveedor que esperan aprobación (ocultos hasta que Leandro los publique por Telegram)
app.get('/api/bot/pendientes', botAuth, async (req, res) => {
  const t = req.botTenantId;
  try {
    const { rows } = await pool.query(
      `SELECT id, sku, nombre, imagen, categoria, CASE WHEN precio_oferta>0 THEN precio_oferta ELSE precio_base END AS precio
         FROM productos WHERE tenant_id=$1 AND pendiente_aprobacion=true AND visible=false ORDER BY id DESC LIMIT 300`, [t]);
    res.json({ ok: true, total: rows.length, productos: rows });
  } catch (e) { res.status(500).json({ error: e.message }); }
});
// POST /api/bot/aprobar — { skus:[...] | todos:true, publicar:true|false }. publicar=false los deja ocultos y sale de pendientes.
app.post('/api/bot/aprobar', botAuth, async (req, res) => {
  const t = req.botTenantId;
  try {
    const publicar = req.body && req.body.publicar !== false;
    const todos = !!(req.body && req.body.todos);
    const skus = Array.isArray(req.body && req.body.skus) ? req.body.skus.map(x => String(x).toUpperCase().trim()).filter(Boolean).slice(0, 500) : [];
    if (!todos && !skus.length) return res.status(400).json({ error: 'Faltan skus' });
    const r = todos
      ? await pool.query('UPDATE productos SET visible=$1, pendiente_aprobacion=false WHERE tenant_id=$2 AND pendiente_aprobacion=true RETURNING sku, nombre', [publicar, t])
      : await pool.query('UPDATE productos SET visible=$1, pendiente_aprobacion=false WHERE tenant_id=$2 AND UPPER(sku) = ANY($3) RETURNING sku, nombre', [publicar, t, skus]);
    res.json({ ok: true, afectados: r.rowCount, productos: r.rows.slice(0, 50) });
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
app.get('/api/productos/buscar', optionalAuth, async (req,res)=>{ try{ const {q}=req.query; if(!q) return res.json([]); const toks=String(q).trim().split(/\s+/).filter(Boolean).slice(0,8); const campos=`(coalesce(p.nombre,'')||' '||coalesce(p.modelo,'')||' '||coalesce(p.categoria,'')||' '||coalesce(p.marca,'')||' '||coalesce(p.sku,'')||' '||coalesce(p.compatibilidad,''))`; const cond=[]; const params=[req.tenantId]; let pi=2; for(const tk of toks){ cond.push(`${SQL_SIN_ACENTOS(campos)} LIKE $${pi}`); params.push(tokenBusqueda(tk)); pi++; } const whereTok=cond.length?(' AND '+cond.join(' AND ')):''; const {rows}=await pool.query(`SELECT p.id,p.nombre,p.modelo,p.categoria,p.precio_base,p.precio_oferta,p.stock,p.imagen,p.sku,p.codigo_barras,p.seccion_id,p.permitir_sin_stock,p.es_digital,p.usa_variantes,(SELECT MIN(CASE WHEN v.precio_oferta>0 AND v.precio_oferta<v.precio THEN v.precio_oferta ELSE v.precio END) FROM variantes v WHERE v.producto_id=p.id AND v.tenant_id=p.tenant_id AND v.precio>0) AS precio_desde,s.nombre as seccion_nombre,s.color as seccion_color FROM productos p LEFT JOIN secciones s ON p.seccion_id=s.id WHERE p.tenant_id=$1${whereTok}${esStaffReq(req)?'':' AND p.visible=true'} ORDER BY p.nombre LIMIT 20`, params); res.json(esStaffReq(req) ? rows : await sinRestringidas(req, rows, { conservarConAcceso: true })); }catch(e){ res.status(500).json({error:e.message}); } });
// Buscar producto por código de barras/SKU exacto (para el escáner). Devuelve 1 producto.
app.get('/api/productos/por-codigo/:codigo', optionalAuth, async (req,res)=>{
  try{
    const c=(req.params.codigo||'').trim();
    if(!c) return res.status(404).json({error:'Código vacío'});
    const {rows}=await pool.query(`SELECT p.*, s.nombre as seccion_nombre FROM productos p LEFT JOIN secciones s ON p.seccion_id=s.id
      WHERE p.tenant_id=$2 AND (p.codigo_barras=$1 OR p.sku=$1 OR CAST(p.id AS TEXT)=$1) LIMIT 1`, [c, req.tenantId]);
    if(!rows[0] || (!esStaffReq(req) && rows[0].visible===false)) return res.status(404).json({error:'No se encontró ningún producto con ese código'});
    if(!esStaffReq(req) && (await sinRestringidas(req, rows, { conservarConAcceso: true })).length===0) return res.status(404).json({error:'No se encontró ningún producto con ese código'});
    res.json(esStaffReq(req) ? rows[0] : limpiarProducto(rows[0]));
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
app.get('/api/productos/id/:id', optionalAuth, async (req,res)=>{ try{ const {rows}=await pool.query('SELECT * FROM productos WHERE id=$1 AND tenant_id=$2', [req.params.id, req.tenantId]); if(!rows[0] || (!esStaffReq(req) && rows[0].visible===false)) return res.status(404).json({error:'No encontrado'}); if(!esStaffReq(req) && (await sinRestringidas(req, rows, { conservarConAcceso: true })).length===0) return res.status(404).json({error:'Este producto es solo para clientes mayoristas autorizados'}); if(esStaffReq(req)) return res.json(rows[0]); const [r]=await ocultarPreciosAprobacion(req, rows); res.json(limpiarProducto(r)); }catch(e){ res.status(500).json({error:e.message}); } });

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
app.post('/api/producto-imagenes', authPerm('productos'), async (req,res)=>{ try{ const {producto_id,url,orden}=req.body; if(!url||!String(url).trim()) return res.status(400).json({error:'Falta la URL de la imagen'}); const {rows:pp}=await pool.query('SELECT 1 FROM productos WHERE id=$1 AND tenant_id=$2', [producto_id, req.tenantId]); if(!pp[0]) return res.status(404).json({error:'Producto no encontrado'}); const {rows}=await pool.query('INSERT INTO producto_imagenes (tenant_id,producto_id,url,orden) VALUES ($4,$1,$2,$3) RETURNING *', [producto_id,url,orden||0, req.tenantId]); await syncImagenPrincipal(producto_id, req.tenantId); res.json(rows[0]); }catch(e){ res.status(500).json({error:e.message}); } });
app.delete('/api/producto-imagenes/:id', authPerm('productos'), async (req,res)=>{ try{ const {rows:pv}=await pool.query('SELECT producto_id FROM producto_imagenes WHERE id=$1 AND tenant_id=$2', [req.params.id, req.tenantId]); await pool.query('DELETE FROM producto_imagenes WHERE id=$1 AND tenant_id=$2', [req.params.id, req.tenantId]); if(pv[0]) await syncImagenPrincipal(pv[0].producto_id, req.tenantId); res.json({ok:true}); }catch(e){ res.status(500).json({error:e.message}); } });
app.put('/api/producto-imagenes/reorder', authPerm('productos'), async (req,res)=>{ try{ const {items}=req.body; for(const it of items){ await pool.query('UPDATE producto_imagenes SET orden=$1 WHERE id=$2 AND tenant_id=$3', [it.orden,it.id, req.tenantId]); } if(items&&items[0]){ const {rows:pv}=await pool.query('SELECT producto_id FROM producto_imagenes WHERE id=$1 AND tenant_id=$2', [items[0].id, req.tenantId]); if(pv[0]) await syncImagenPrincipal(pv[0].producto_id, req.tenantId); } res.json({ok:true}); }catch(e){ res.status(500).json({error:e.message}); } });
app.get('/api/variantes/:producto_id', async (req,res)=>{ try{ const {rows}=await pool.query('SELECT * FROM variantes WHERE producto_id=$1 AND tenant_id=$2 ORDER BY id', [req.params.producto_id, req.tenantId]); res.json(rows); }catch(e){ res.status(500).json({error:e.message}); } });
app.post('/api/variantes', authPerm('productos'), async (req,res)=>{ try{ const {producto_id,nombre,valor,stock,precio_extra,precio}=req.body; if(!(await productoDeTienda(pool, req.tenantId, producto_id))) return res.status(404).json({error:'Producto no encontrado'}); const {rows}=await pool.query('INSERT INTO variantes (tenant_id,producto_id,nombre,valor,stock,precio_extra,precio) VALUES ($7,$1,$2,$3,$4,$5,$6) RETURNING *', [producto_id,nombre,valor||'',stock||0,precio_extra||0,precio||0, req.tenantId]); res.json(rows[0]); }catch(e){ res.status(500).json({error:e.message}); } });
app.put('/api/variantes/:id', authPerm('productos'), async (req,res)=>{ try{ const v=req.body; const r=await pool.query('UPDATE variantes SET nombre=$1,valor=$2,stock=$3,precio_extra=$4,precio=$5 WHERE id=$6 AND tenant_id=$7', [v.nombre,v.valor,v.stock||0,v.precio_extra||0,v.precio||0,req.params.id, req.tenantId]); if(!r.rowCount) return res.status(404).json({error:'Variante no encontrada'}); res.json({ok:true}); }catch(e){ res.status(500).json({error:e.message}); } });
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
      const {rows:vals}=await pool.query('SELECT valor,imagen FROM producto_atributo_valores WHERE atributo_id=$1 AND tenant_id=$2 ORDER BY orden,id',[a.id,t]);
      atributos.push({ nombre:a.nombre, orden:a.orden, valores: vals.map(v=>({ valor:v.valor, imagen:v.imagen||'' })) });
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
    if(!(await productoDeTienda(client, t, pid))) return res.status(404).json({error:'Producto no encontrado'});
    await client.query('BEGIN');
    await client.query('UPDATE productos SET usa_variantes=$1 WHERE id=$2 AND tenant_id=$3',[!!usa_variantes, pid, t]);
    await client.query('DELETE FROM producto_atributos WHERE producto_id=$1 AND tenant_id=$2',[pid,t]); // cascade borra valores
    await client.query('DELETE FROM variantes WHERE producto_id=$1 AND tenant_id=$2',[pid,t]);
    let ao=0;
    for(const a of atributos){
      const nom=(a.nombre||'').trim(); if(!nom) continue;
      const {rows:ar}=await client.query('INSERT INTO producto_atributos (tenant_id,producto_id,nombre,orden) VALUES ($1,$2,$3,$4) RETURNING id',[t,pid,nom,ao++]);
      let vo=0;
      for(const v of (a.valores||[])){ const val=(typeof v==='string'?v:(v.valor||'')).trim(); if(!val) continue; const img=(typeof v==='object'&&v)?(v.imagen||''):''; await client.query('INSERT INTO producto_atributo_valores (tenant_id,atributo_id,valor,orden,imagen) VALUES ($1,$2,$3,$4,$5)',[t,ar[0].id,val,vo++,img]); }
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
app.get('/api/historial-precios', authPerm('productos'), async (req,res)=>{ try{ const {rows}=await pool.query('SELECT h.*, p.nombre, p.modelo, p.categoria FROM historial_precios h LEFT JOIN productos p ON h.producto_id=p.id AND p.tenant_id=h.tenant_id WHERE h.tenant_id=$1 ORDER BY h.created_at DESC LIMIT 200', [req.tenantId]); res.json(rows); }catch(e){ res.status(500).json({error:e.message}); } });

// ── ÓRDENES DE COMPRA (compras a proveedores) ──
app.get('/api/ordenes-compra', authPerm('pedidos'), requiereFeature('ordenes_compra'), async (req,res)=>{
  try{ const {rows}=await pool.query('SELECT o.*, s.nombre as seccion_nombre FROM ordenes_compra o LEFT JOIN secciones s ON o.seccion_id=s.id WHERE o.tenant_id=$1 ORDER BY o.created_at DESC LIMIT 200', [req.tenantId]); res.json(rows); }
  catch(e){ res.status(500).json({error:e.message}); }
});
app.get('/api/ordenes-compra/:id', authPerm('pedidos'), requiereFeature('ordenes_compra'), async (req,res)=>{
  try{
    const {rows:o}=await pool.query('SELECT o.*, s.nombre as seccion_nombre FROM ordenes_compra o LEFT JOIN secciones s ON o.seccion_id=s.id WHERE o.id=$1 AND o.tenant_id=$2', [req.params.id, req.tenantId]);
    if(!o[0]) return res.status(404).json({error:'No encontrada'});
    const {rows:items}=await pool.query("SELECT oi.*, COALESCE(pr.imagen,'') AS imagen FROM orden_compra_items oi LEFT JOIN productos pr ON pr.id=oi.producto_id AND pr.tenant_id=$2 WHERE oi.orden_id=$1 ORDER BY oi.id", [req.params.id, req.tenantId]);
    res.json({ ...o[0], items });
  }catch(e){ res.status(500).json({error:e.message}); }
});
app.post('/api/ordenes-compra', authPerm('pedidos'), requiereFeature('ordenes_compra'), async (req,res)=>{
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
app.post('/api/ordenes-compra/:id/recibir', authPerm('pedidos'), requiereFeature('ordenes_compra'), async (req,res)=>{
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
app.delete('/api/ordenes-compra/:id', authPerm('pedidos'), requiereFeature('ordenes_compra'), async (req,res)=>{
  try{ await pool.query('DELETE FROM ordenes_compra WHERE id=$1 AND tenant_id=$2', [req.params.id, req.tenantId]); res.json({ok:true}); }
  catch(e){ res.status(500).json({error:e.message}); }
});
// Precios fijos por lista: el personal ve todos; cada cliente solo los de SU lista (para que la tienda le muestre su precio real)
app.get('/api/precios-fijos', optionalAuth, async (req,res)=>{ try{ if(!req.user) return res.json([]); const {rows:u}=await pool.query('SELECT rol, permisos, lista_precio_id FROM usuarios WHERE id=$1 AND tenant_id=$2', [req.user.id, req.tenantId]); const me=u[0]; if(!me) return res.json([]); const staff=me.rol==='admin' || (me.rol==='subadmin' && String(me.permisos||'').split(',').includes('productos')); if(staff){ const {rows}=await pool.query('SELECT * FROM precios_fijos WHERE tenant_id=$1', [req.tenantId]); return res.json(rows); } if(!me.lista_precio_id) return res.json([]); const {rows}=await pool.query('SELECT producto_id, lista_precio_id, precio_fijo FROM precios_fijos WHERE tenant_id=$1 AND lista_precio_id=$2', [req.tenantId, me.lista_precio_id]); res.json(rows); }catch(e){ res.status(500).json({error:e.message}); } });
app.post('/api/precios-fijos', authPerm('productos'), requiereFeature('listas_precio'), async (req,res)=>{ try{ const {producto_id,lista_precio_id,precio_fijo}=req.body;
  if(!(await productoDeTienda(pool, req.tenantId, producto_id))) return res.status(404).json({error:'Producto no encontrado'});
  const {rows:lp}=await pool.query('SELECT 1 FROM listas_precio WHERE id=$1 AND tenant_id=$2', [lista_precio_id, req.tenantId]); if(!lp[0]) return res.status(404).json({error:'Lista no encontrada'});
  await pool.query('INSERT INTO precios_fijos (tenant_id,producto_id,lista_precio_id,precio_fijo) VALUES ($4,$1,$2,$3) ON CONFLICT (producto_id,lista_precio_id) DO UPDATE SET precio_fijo=$3 WHERE precios_fijos.tenant_id=EXCLUDED.tenant_id', [producto_id,lista_precio_id,precio_fijo, req.tenantId]); res.json({ok:true}); }catch(e){ res.status(500).json({error:e.message}); } });

// USUARIOS
app.get('/api/usuarios/:id/cuenta', authPerm('usuarios'), requiereFeature('cuenta_corriente'), async (req,res)=>{
  try{
    const {rows:movs}=await pool.query('SELECT cc.*, p.tipo as pedido_tipo FROM cuenta_corriente cc LEFT JOIN pedidos p ON cc.pedido_id=p.id WHERE cc.usuario_id=$1 AND cc.tenant_id=$2 ORDER BY cc.created_at DESC LIMIT 200', [req.params.id, req.tenantId]);
    const saldo=movs.reduce((s,m)=> s + (m.tipo==='cargo' ? Number(m.monto) : -Number(m.monto)), 0);
    res.json({ movimientos: movs, saldo });
  }catch(e){ res.status(500).json({error:e.message}); }
});
app.post('/api/usuarios/:id/cuenta', authPerm('usuarios'), requiereFeature('cuenta_corriente'), async (req,res)=>{
  try{
    const {tipo, monto, concepto}=req.body;
    if(!['cargo','pago'].includes(tipo) || !monto) return res.status(400).json({error:'Datos inválidos'});
    const {rows}=await pool.query('INSERT INTO cuenta_corriente (tenant_id,usuario_id,tipo,monto,concepto) VALUES ($5,$1,$2,$3,$4) RETURNING *', [req.params.id, tipo, monto, concepto||'', req.tenantId]);
    res.json(rows[0]);
  }catch(e){ res.status(500).json({error:e.message}); }
});
app.delete('/api/cuenta-corriente/:id', authPerm('usuarios'), requiereFeature('cuenta_corriente'), async (req,res)=>{
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
  try{
    const {q}=req.query; const params=[req.tenantId]; let filtro='';
    if(q){ filtro=" AND (u.nombre ILIKE $2 OR u.usuario ILIKE $2 OR u.nombre_fantasia ILIKE $2 OR u.email ILIKE $2 OR u.telefono ILIKE $2)"; params.push(`%${q}%`); }
    // Resumen de compras de cada cliente (solo pedidos reales, sin presupuestos, cancelados ni pruebas)
    const {rows}=await pool.query(`SELECT u.*, COALESCE(c.compras,0)::int AS compras, COALESCE(c.total_gastado,0)::float AS total_gastado, COALESCE(c.total_pagado,0)::float AS total_pagado, c.ultima_compra
      FROM usuarios u
      LEFT JOIN (
        SELECT usuario_id, COUNT(*) AS compras, SUM(total) AS total_gastado,
               SUM(CASE WHEN estado_pago='pagado' THEN total ELSE 0 END) AS total_pagado, MAX(created_at) AS ultima_compra
        FROM pedidos WHERE tenant_id=$1 AND tipo='pedido' AND COALESCE(is_test,false)=false AND LOWER(COALESCE(estado,''))<>'cancelado'
        GROUP BY usuario_id
      ) c ON c.usuario_id=u.id
      WHERE u.tenant_id=$1${filtro} ORDER BY u.created_at DESC`, params);
    res.json(rows.map(u=>({...u, password:undefined, reset_codigo:undefined, reset_expira:undefined})));
  }catch(e){ res.status(500).json({error:e.message}); }
});
app.get('/api/usuarios/pendientes/count', authPerm('usuarios'), async (req,res)=>{ try{ const {rows}=await pool.query("SELECT COUNT(*) FROM usuarios WHERE aprobado=false AND activo=false AND tenant_id=$1", [req.tenantId]); res.json({count:parseInt(rows[0].count)}); }catch{ res.json({count:0}); } });
// Un sub-admin con permiso "usuarios" puede gestionar clientes, pero NO al equipo (admin/sub-admins):
// si no, podría resetear la clave del dueño o darse rol admin.
async function staffProtegido(req, targetId){
  const {rows}=await pool.query('SELECT rol, es_owner FROM usuarios WHERE id=$1 AND tenant_id=$2', [targetId, req.tenantId]);
  const t=rows[0]; if(!t) return null;
  if(t.es_owner && String(targetId)!==String(req.user?.id)) return 'No se puede modificar la cuenta del dueño de la plataforma';
  if(req._rol!=='admin' && (t.rol==='admin' || t.rol==='subadmin') && String(targetId)!==String(req.user?.id)) return 'Solo el administrador puede modificar cuentas del equipo';
  return null;
}
// Lista de precios de un usuario: vacío → null; inexistente en la tienda → false
async function listaPrecioValida(tenantId, valor){
  const lp=String(valor==null?'':valor).trim();
  if(!lp || lp==='0' || lp==='null') return null;
  const {rows}=await pool.query('SELECT 1 FROM listas_precio WHERE id=$1 AND tenant_id=$2', [lp, tenantId]).catch(()=>({rows:[]}));
  return rows[0] ? lp : false;
}
app.put('/api/usuarios/:id', authPerm('usuarios'), async (req,res)=>{
  try{
    const u=req.body; const sets=[]; const params=[]; let pi=1;
    const bloqueo=await staffProtegido(req, req.params.id); if(bloqueo) return res.status(403).json({error:bloqueo});
    if((u.rol!==undefined || u.permisos!==undefined) && req._rol!=='admin') return res.status(403).json({error:'Solo el administrador puede cambiar roles y permisos'});
    if(u.rol!==undefined && !['cliente','subadmin','admin'].includes(String(u.rol))) return res.status(400).json({error:'Rol inválido'});
    if(u.rol==='subadmin' || u.rol==='admin'){
      const {rows:act}=await pool.query('SELECT rol FROM usuarios WHERE id=$1 AND tenant_id=$2', [req.params.id, req.tenantId]);
      const yaEsEquipo = act[0] && (act[0].rol==='subadmin' || act[0].rol==='admin');
      const maxS = await limitePlan(req, 'max_subadmins');
      if(!yaEsEquipo && Number.isFinite(maxS)){
        const {rows:c}=await pool.query("SELECT COUNT(*)::int AS n FROM usuarios WHERE tenant_id=$1 AND rol='subadmin'", [req.tenantId]);
        if((c[0]?.n||0) >= maxS) return res.status(403).json({error: maxS===0 ? 'Tu plan no incluye sub-administradores' : `Tu plan permite hasta ${maxS} sub-administradores`, upgrade:true});
      }
    }
    const fields=['nombre','usuario','telefono','email','direccion','nombre_fantasia','rol','lista_precio_id','activo','aprobado','permisos','notas_admin','es_revendedor','descuento_revendedor','mayorista'];
    // "Sin lista" llega vacío: en la base es NULL (la columna tiene clave foránea a listas_precio y '' no existe)
    if(u.lista_precio_id!==undefined){
      const lp=await listaPrecioValida(req.tenantId, u.lista_precio_id);
      if(lp===false) return res.status(400).json({error:'Esa lista de precios no existe más. Elegí otra o "Sin lista".'});
      u.lista_precio_id=lp;
    }
    if(u.mayorista===true){ sets.push(`mayorista_solicitado_at=NULL`); }
    for(const f of fields){ if(u[f]!==undefined){ sets.push(`${f}=$${pi++}`); params.push(u[f]); } }
    if(u.password){ const hash=await bcrypt.hash(u.password,10); sets.push(`password=$${pi++}`); params.push(hash); }
    if(!sets.length) return res.json({ok:true});
    params.push(req.params.id); params.push(req.tenantId);
    await pool.query(`UPDATE usuarios SET ${sets.join(',')} WHERE id=$${pi} AND tenant_id=$${pi+1}`, params);
    res.json({ok:true});
  }catch(e){ res.status(500).json({error:e.message}); }
});
app.post('/api/usuarios/:id/aprobar', authPerm('usuarios'), async (req,res)=>{ try{ const bloqueo=await staffProtegido(req, req.params.id); if(bloqueo) return res.status(403).json({error:bloqueo}); const lp=await listaPrecioValida(req.tenantId, req.body && req.body.lista_precio_id); await pool.query('UPDATE usuarios SET aprobado=true, activo=true, lista_precio_id=$1 WHERE id=$2 AND tenant_id=$3', [lp||null, req.params.id, req.tenantId]); const {rows}=await pool.query('SELECT * FROM usuarios WHERE id=$1 AND tenant_id=$2', [req.params.id, req.tenantId]); res.json({ok:true, user:{...rows[0], password:undefined}}); }catch(e){ res.status(500).json({error:e.message}); } });
app.post('/api/usuarios/:id/rechazar', authPerm('usuarios'), async (req,res)=>{ try{ const bloqueo=await staffProtegido(req, req.params.id); if(bloqueo) return res.status(403).json({error:bloqueo}); await pool.query('UPDATE usuarios SET activo=false WHERE id=$1 AND tenant_id=$2', [req.params.id, req.tenantId]); res.json({ok:true}); }catch(e){ res.status(500).json({error:e.message}); } });
app.post('/api/usuarios/:id/suspender', authPerm('usuarios'), async (req,res)=>{ try{ const bloqueo=await staffProtegido(req, req.params.id); if(bloqueo) return res.status(403).json({error:bloqueo}); if(String(req.params.id)===String(req.user?.id)) return res.status(400).json({error:'No podés suspender tu propia cuenta'}); const {activo}=req.body; await pool.query('UPDATE usuarios SET activo=$1 WHERE id=$2 AND tenant_id=$3', [activo, req.params.id, req.tenantId]); res.json({ok:true}); }catch(e){ res.status(500).json({error:e.message}); } });
// RESET MEJORADO - codigo largo
app.post('/api/usuarios/:id/reset-password', authPerm('usuarios'), async (req,res)=>{
  try{
    const bloqueo=await staffProtegido(req, req.params.id); if(bloqueo) return res.status(403).json({error:bloqueo});
    const codigo='KICKS-'+crypto.randomBytes(4).toString('hex').toUpperCase();
    const hash=await bcrypt.hash(codigo,10);
    await pool.query('UPDATE usuarios SET password=$1, reset_codigo=$2, reset_expira=NOW()+INTERVAL \'24 hours\' WHERE id=$3 AND tenant_id=$4', [hash, codigo, req.params.id, req.tenantId]);
    const {rows}=await pool.query('SELECT nombre,telefono,email FROM usuarios WHERE id=$1 AND tenant_id=$2', [req.params.id, req.tenantId]);
    res.json({ok:true, codigo, nombre:rows[0]?.nombre, telefono:rows[0]?.telefono, email:rows[0]?.email});
  }catch(e){ res.status(500).json({error:e.message}); }
});
app.delete('/api/usuarios/:id', authPerm('usuarios'), async (req,res)=>{ try{ { const bloqueo=await staffProtegido(req, req.params.id); if(bloqueo) return res.status(403).json({error:bloqueo}); if(String(req.params.id)===String(req.user?.id)) return res.status(400).json({error:'No podés borrar tu propia cuenta'}); } await pool.query('DELETE FROM pedido_items WHERE pedido_id IN (SELECT id FROM pedidos WHERE usuario_id=$1 AND tenant_id=$2)', [req.params.id, req.tenantId]); await pool.query('DELETE FROM pedidos WHERE usuario_id=$1 AND tenant_id=$2', [req.params.id, req.tenantId]); await pool.query('DELETE FROM usuarios WHERE id=$1 AND tenant_id=$2', [req.params.id, req.tenantId]); res.json({ok:true}); }catch(e){ res.status(500).json({error:e.message}); } });

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
app.get('/api/pedidos/:id', auth(), async (req,res)=>{ try{ const {rows}=await pool.query('SELECT p.*, u.nombre as usuario_nombre, u.telefono as usuario_telefono, u.email as usuario_email, u.nombre_fantasia, u.direccion as usuario_direccion, s.nombre as seccion_nombre, s.color as seccion_color FROM pedidos p LEFT JOIN usuarios u ON p.usuario_id=u.id LEFT JOIN secciones s ON p.seccion_id=s.id WHERE p.id=$1 AND p.tenant_id=$2', [req.params.id, req.tenantId]); if(!rows[0]) return res.status(404).json({error:'No encontrado'}); if(Number(rows[0].usuario_id)!==Number(req.user.id) && !(await esStaffPedidos(req))) return res.status(404).json({error:'No encontrado'}); const {rows:items}=await pool.query("SELECT pi.*, COALESCE(NULLIF(pi.imagen,''), pr.imagen, '') AS imagen, pr.sku AS producto_sku FROM pedido_items pi LEFT JOIN productos pr ON pr.id=pi.producto_id AND pr.tenant_id=pi.tenant_id WHERE pi.pedido_id=$1 AND pi.tenant_id=$2 ORDER BY pi.id", [req.params.id, req.tenantId]); const {rows:pagos}=await pool.query('SELECT * FROM pedido_pagos WHERE pedido_id=$1 AND tenant_id=$2 ORDER BY created_at', [req.params.id, req.tenantId]); res.json({...rows[0], items, pagos}); }catch(e){ res.status(500).json({error:e.message}); } });

// ═══ PEDIDOS ═══
// Helpers compartidos: stock (siempre filtrado por tienda) e inserción de ítems.
const TXT = (v, max) => String(v == null ? '' : v).slice(0, max);
async function validarStockItems(client, tenantId, items){
  for(const item of items){
    const pid=parseInt(item.producto_id,10); if(!pid) continue;
    const {rows:prod}=await client.query('SELECT stock, permitir_sin_stock, es_digital, seccion_id, es_preventa, preventa_cupo, preventa_reservado FROM productos WHERE id=$1 AND tenant_id=$2', [pid, tenantId]);
    if(!prod[0]) continue;
    const cant=Number(item.cantidad)||1;
    if(item.variante_id){
      // Variantes: las digitales/licencias suelen tener stock 0 y no deben frenar la venta
      continue;
    }
    if(item._preventa || prod[0].es_preventa){
      const cupo=Number(prod[0].preventa_cupo)||0, reservado=Number(prod[0].preventa_reservado)||0;
      if(cupo>0 && reservado+cant>cupo) throw new CheckoutError(`Preventa agotada: ${item.nombre_producto||''} (quedan ${Math.max(0,cupo-reservado)} de ${cupo})`);
      continue;
    }
    const {rows:sec}=await client.query('SELECT ignorar_stock, permitir_sin_stock FROM secciones WHERE id=$1 AND tenant_id=$2', [prod[0].seccion_id, tenantId]);
    const puedeSinStock = prod[0].permitir_sin_stock || prod[0].es_digital || sec[0]?.permitir_sin_stock || sec[0]?.ignorar_stock;
    if(!puedeSinStock && Number(prod[0].stock) < cant) throw new CheckoutError(`Sin stock suficiente: ${item.nombre_producto||''} (disponible: ${prod[0].stock})`);
  }
}
async function insertarItems(client, tenantId, pedidoId, items, descontarStock){
  const propios=await idsProductosDeTienda(client, tenantId, items.map(i=>i.producto_id));
  for(const item of items){
    // Un producto de otra tienda queda como línea de texto (sin id): no toca su stock ni sus datos
    const pid0=parseInt(item.producto_id,10)||null; const pid=pid0 && propios.has(pid0) ? pid0 : null;
    const cant=Number(item.cantidad)||1;
    await client.query("INSERT INTO pedido_items (tenant_id,pedido_id,producto_id,categoria,modelo,nombre_producto,cantidad,precio_unitario,precio_base,variante_id,variante_combinacion,imagen) VALUES ($9,$1,$2,$3,$4,$5,$6,$7,$8,$10,$11,COALESCE((SELECT imagen FROM productos WHERE id=$2 AND tenant_id=$9),''))",
      [pedidoId, pid, TXT(item.categoria,200), TXT(item.modelo,200), TXT(item.nombre_producto,300), cant, Number(item.precio_unitario)||0, Number(item.precio_base)||0, tenantId, item.variante_id||null, TXT(item.variante_label||item.variante_combinacion,500)]);
    if(!descontarStock || !pid) continue;
    if(item.variante_id){
      await client.query('UPDATE variantes SET stock = GREATEST(0, stock - $1) WHERE id=$2 AND tenant_id=$3', [cant, item.variante_id, tenantId]);
      continue;
    }
    const {rows:pr}=await client.query('SELECT permitir_sin_stock, es_digital, es_preventa FROM productos WHERE id=$1 AND tenant_id=$2', [pid, tenantId]);
    if(!pr[0]) continue;
    if(pr[0].es_preventa || item._preventa){
      await client.query('UPDATE productos SET preventa_reservado = COALESCE(preventa_reservado,0) + $1 WHERE id=$2 AND tenant_id=$3', [cant, pid, tenantId]);
    } else if(!pr[0].permitir_sin_stock && !pr[0].es_digital){
      await client.query('UPDATE productos SET stock = GREATEST(0, stock - $1) WHERE id=$2 AND tenant_id=$3 AND permitir_sin_stock=false AND es_digital=false', [cant, pid, tenantId]);
    }
  }
}
async function etiquetarMoneda(client, pedidoId){
  await client.query(`UPDATE pedidos SET moneda = CASE WHEN EXISTS(SELECT 1 FROM pedido_items pi LEFT JOIN productos pr ON pr.id=pi.producto_id AND pr.tenant_id=(SELECT tenant_id FROM pedidos WHERE id=pi.pedido_id) LEFT JOIN variantes v ON v.id=pi.variante_id WHERE pi.pedido_id=$1 AND COALESCE(v.moneda, pr.moneda,'ARS')='USDT') THEN 'USDT' ELSE 'ARS' END WHERE id=$1`, [pedidoId]).catch(()=>{});
}
// Lee {tipo, cp} de la entrega: del body nuevo o, si la web es vieja, del JSON datos_envio
function leerEntrega(body, peds){
  if(body && body.entrega && body.entrega.tipo) return { tipo: body.entrega.tipo, cp: body.entrega.cp || '' };
  for(const p of (peds||[])){
    try{ const de=typeof p.datos_envio==='string'?JSON.parse(p.datos_envio||'{}'):(p.datos_envio||{}); if(de && de.entrega && de.entrega.tipo) return { tipo: de.entrega.tipo, cp: de.entrega.cp || p.cp_destino || '' }; }catch{}
  }
  return { tipo:'envio', cp:(peds&&peds[0]&&peds[0].cp_destino)||'' };
}
function errorPedido(res, e){
  if(e instanceof CheckoutError) return res.status(e.status||400).json({error:e.message});
  console.log('[pedido] error:', e.message);
  return res.status(500).json({error:'No pudimos crear el pedido. Probá de nuevo en un momento.'});
}

// Cotiza el carrito: precios, envío por tienda, cupón y totales. Es lo que muestra el carrito y el checkout.
app.post('/api/carrito/cotizar', optionalAuth, async (req,res)=>{
  try{
    const cot=await checkout.cotizarCarrito(pool, req.tenantId, req.user?.id, req.body||{}, { cotizacion:true });
    res.json(checkout.publico(cot));
  }catch(e){
    if(e instanceof CheckoutError) return res.status(e.status||400).json({error:e.message});
    console.log('[cotizar] error:', e.message); res.status(500).json({error:'No pudimos calcular el carrito'});
  }
});

// Pedido simple. Personal de la tienda (venta de mostrador, presupuestos para clientes): carga libre.
// Cliente: solo puede guardar PRESUPUESTOS, con precios calculados por el servidor.
app.post('/api/pedidos', auth(), async (req,res)=>{
  const client=await pool.connect();
  try{
    const staff=await esStaffPedidos(req);
    const b=req.body||{};
    await client.query('BEGIN');
    let pedido;
    if(staff){
      const items=Array.isArray(b.items)?b.items:[];
      const esPresupuesto = b.tipo === 'presupuesto';
      if(Number(req.tenantId)!==1){
        const td=await getTenantData(req.tenantId).catch(()=>null);
        if(td && esPresupuesto && !featureActiva(td.features,'presupuestos')) throw new CheckoutError('Los presupuestos no están incluidos en tu plan', 403);
        if(td && !esPresupuesto && !featureActiva(td.features,'pdv')) throw new CheckoutError('La carga manual de ventas (punto de venta) no está incluida en tu plan', 403);
      }
      const pedidoUserId = (b.usuario_id !== undefined && b.usuario_id !== null && b.usuario_id !== '') ? b.usuario_id : req.user.id;
      if(pedidoUserId!==req.user.id){
        const {rows:uu}=await client.query('SELECT 1 FROM usuarios WHERE id=$1 AND tenant_id=$2', [pedidoUserId, req.tenantId]);
        if(!uu[0]) throw new CheckoutError('El cliente elegido no existe');
      }
      if(!esPresupuesto) await validarStockItems(client, req.tenantId, items);
      const esReserva = items.some(it => it._preventa === true);
      const {rows}=await client.query('INSERT INTO pedidos (tenant_id,usuario_id,seccion_id,tipo,metodo_pago,notas,cupon_codigo,subtotal,descuento,total,datos_envio,notificar_wa,costo_envio,metodo_envio,cp_destino,is_test,estado,estado_pago,sena,es_reserva) VALUES ($20,$1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19) RETURNING *',
        [pedidoUserId, b.seccion_id||null, b.tipo||'pedido', TXT(b.metodo_pago,100), TXT(b.notas,4000), TXT(b.cupon_codigo,50), Number(b.subtotal)||0, Number(b.descuento)||0, Number(b.total)||0, TXT(b.datos_envio,8000), b.notificar_wa!==false, Number(b.costo_envio)||0, TXT(b.metodo_envio,100), TXT(b.cp_destino,20), !!b.is_test, b.estado||'pendiente', b.estado_pago||'impago', Number(b.sena)||0, esReserva, req.tenantId]);
      pedido=rows[0];
      await insertarItems(client, req.tenantId, pedido.id, items, !esPresupuesto);
      await etiquetarMoneda(client, pedido.id);
      if(b.cupon_codigo) await client.query("UPDATE cupones SET usos_actuales = usos_actuales + 1 WHERE codigo=$1 AND tenant_id=$2", [b.cupon_codigo, req.tenantId]).catch(()=>{});
      // Cuenta corriente automática: SOLO si el pedido se marca como "debe" (fiado)
      const ep=String(b.estado_pago||'impago');
      if(pedidoUserId && ep==='debe'){
        const deuda = Number(b.total||0) - (Number(b.sena)||0);
        if(deuda>0) await client.query('INSERT INTO cuenta_corriente (tenant_id,usuario_id,tipo,monto,concepto,pedido_id) VALUES ($6,$1,$2,$3,$4,$5)', [pedidoUserId, 'cargo', deuda, `Pedido #${String(pedido.id).padStart(4,'0')}`, pedido.id, req.tenantId]).catch(()=>{});
      }
      // Pagos iniciales (venta de mostrador con pagos mixtos)
      if(Array.isArray(b.pagos)){
        for(const pg of b.pagos){
          const rec=Number(pg.recibido)||0, cta=Number(pg.cuenta_como)||0;
          if(rec>0 || cta>0) await client.query('INSERT INTO pedido_pagos (tenant_id,pedido_id,metodo,monto,recibido,cuenta_como,ajuste_pct,ajuste_monto,nota) VALUES ($9,$1,$2,$3,$4,$5,$6,$7,$8)', [pedido.id, TXT(pg.metodo,100), rec, rec, cta, Number(pg.ajuste_pct)||0, cta-rec, TXT(pg.nota,500), req.tenantId]);
        }
      }
    } else {
      // Cliente: presupuesto armado desde el carrito, precios del servidor, sin envío ni pagos
      const cot=await checkout.cotizarCarrito(client, req.tenantId, req.user.id, { secciones:[{ seccion_id:b.seccion_id, items:b.items }], entrega:{ tipo:'retiro' } });
      const s=cot.secciones[0];
      if(!s) throw new CheckoutError('El presupuesto no tiene productos');
      const soloUsdt = s.subtotal===0 && s.subtotal_usdt>0;
      const {rows}=await client.query("INSERT INTO pedidos (tenant_id,usuario_id,seccion_id,tipo,metodo_pago,notas,subtotal,descuento,total,estado,estado_pago) VALUES ($1,$2,$3,'presupuesto',$4,$5,$6,0,$6,'pendiente','impago') RETURNING *",
        [req.tenantId, req.user.id, s.seccion_id, TXT(b.metodo_pago,100), TXT(b.notas,4000), soloUsdt ? s.subtotal_usdt : s.subtotal]);
      pedido=rows[0];
      await insertarItems(client, req.tenantId, pedido.id, s._items, false);
      await etiquetarMoneda(client, pedido.id);
    }
    await client.query('COMMIT');
    res.json(pedido);
  }catch(e){ await client.query('ROLLBACK').catch(()=>{}); errorPedido(res, e); }
  finally{ client.release(); }
});

// Compra desde la tienda: crea un pedido por cada tienda (sección) del carrito.
// Precios, cupón, envío y totales los calcula el servidor; lo que mande el navegador no cuenta.
app.post('/api/pedidos/multi', auth(), async (req,res)=>{
  const client=await pool.connect();
  try{
    const b=req.body||{};
    const peds=Array.isArray(b.pedidos)?b.pedidos:[];
    if(!peds.length) return res.status(400).json({error:'El carrito está vacío'});
    const staff=await esStaffPedidos(req);
    const entrega=leerEntrega(b, peds);
    const cuponCodigo = b.cupon !== undefined ? b.cupon : ((peds.find(p=>p.cupon_codigo)||{}).cupon_codigo || '');
    await client.query('BEGIN');
    const cot=await checkout.cotizarCarrito(client, req.tenantId, req.user.id, {
      entrega, cupon: cuponCodigo, metodo_pago: peds[0].metodo_pago,
      secciones: peds.map(p=>({ seccion_id:p.seccion_id, items:p.items, envio_id:p.envio_id, metodo_envio:p.metodo_envio })),
    });
    if(!cot.secciones.length) throw new CheckoutError('El carrito está vacío');
    if(cot.errores.length) throw new CheckoutError(cot.errores[0].mensaje);
    if(cuponCodigo && cot.cupon && !cot.cupon.ok) throw new CheckoutError(cot.cupon.error || 'Cupón no válido');
    const creados=[];
    for(const s of cot.secciones){
      const ped=peds.find(p=>String(p.seccion_id)===String(s.seccion_id)) || peds[0];
      await validarStockItems(client, req.tenantId, s._items);
      const soloUsdt = s.subtotal===0 && s.subtotal_usdt>0;
      let notas=TXT(ped.notas,4000);
      if(s._items.some(i=>i._preventa)) notas=`${notas} [RESERVA/PREVENTA — requiere seña]`.trim();
      if(!soloUsdt && s.subtotal_usdt>0) notas=`${notas} [Además: USDT ${s.subtotal_usdt} a pagar aparte]`.trim();
      const metodoEnvio = (entrega.tipo==='retiro' ? 'Retiro en el local' : (s.envio.elegido ? (s.envio.elegido.a_cotizar ? `${s.envio.elegido.nombre} (envío a cotizar)` : s.envio.elegido.nombre) : (s.requiere_envio ? 'A coordinar' : ''))).slice(0,100);
      const {rows}=await client.query('INSERT INTO pedidos (tenant_id,usuario_id,seccion_id,tipo,metodo_pago,notas,cupon_codigo,subtotal,descuento,total,datos_envio,costo_envio,metodo_envio,cp_destino,is_test,datos_facturacion,estado_pago,es_reserva) VALUES ($17,$1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$18) RETURNING *',
        [req.user.id, s.seccion_id, 'pedido', TXT(ped.metodo_pago,100), notas, s.cupon||'', soloUsdt ? s.subtotal_usdt : s.subtotal, s.descuento, soloUsdt ? s.subtotal_usdt : s.total, TXT(ped.datos_envio,8000), s.envio.costo, metodoEnvio, TXT(entrega.cp,20), staff ? !!b.is_test : false, TXT(ped.datos_facturacion,4000), 'impago', req.tenantId, s._items.some(i=>i._preventa)]);
      await insertarItems(client, req.tenantId, rows[0].id, s._items, true);
      await etiquetarMoneda(client, rows[0].id);
      const {rows:fin}=await client.query('SELECT * FROM pedidos WHERE id=$1', [rows[0].id]);
      creados.push(fin[0]);
    }
    if(cot.cupon && cot.cupon.ok) await client.query("UPDATE cupones SET usos_actuales = usos_actuales + 1 WHERE UPPER(codigo)=UPPER($1) AND tenant_id=$2", [cot.cupon.codigo, req.tenantId]).catch(()=>{});
    await client.query('COMMIT');
    notificarVentaAdmin(creados, req.user).catch(()=>{});
    emailCompraCliente(req.tenantId, creados, req.user).catch(()=>{});
    res.json({ok:true, pedidos: creados, totales: cot.totales});
  }catch(e){ await client.query('ROLLBACK').catch(()=>{}); errorPedido(res, e); }
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
  try{
    const {rows:ped}=await pool.query('SELECT usuario_id FROM pedidos WHERE id=$1 AND tenant_id=$2',[req.params.id, req.tenantId]);
    if(!ped[0] || (Number(ped[0].usuario_id)!==Number(req.user.id) && !(await esStaffPedidos(req)))) return res.status(404).json({error:'No encontrado'});
    const {rows}=await pool.query('SELECT * FROM pedido_pagos WHERE pedido_id=$1 AND tenant_id=$2 ORDER BY created_at',[req.params.id, req.tenantId]); res.json(rows); }
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
    const {rows:own}=await pool.query('SELECT 1 FROM pedidos WHERE id=$1 AND tenant_id=$2',[req.params.id, req.tenantId]);
    if(!own[0]) return res.status(404).json({error:'No encontrado'});
    await pool.query('INSERT INTO pedido_pagos (tenant_id,pedido_id,metodo,monto,recibido,cuenta_como,ajuste_pct,ajuste_monto,nota) SELECT $9,$1,$2,$3,$4,$5,$6,$7,$8 WHERE EXISTS(SELECT 1 FROM pedidos WHERE id=$1 AND tenant_id=$9)',
      [req.params.id, metodo||'', rec, rec, cta, Number(ajuste_pct)||0, ajusteMonto, nota||'', req.tenantId]);
    const r=await recalcularEstadoPago(req.params.id);
    res.json({ok:true, ...r});
  }catch(e){ res.status(500).json({error:e.message}); }
});
app.delete('/api/pedidos/:id/pagos/:pagoId', authPerm('pedidos'), async (req,res)=>{
  try{
    const {rows:own}=await pool.query('SELECT 1 FROM pedidos WHERE id=$1 AND tenant_id=$2',[req.params.id, req.tenantId]);
    if(!own[0]) return res.status(404).json({error:'No encontrado'});
    await pool.query('DELETE FROM pedido_pagos WHERE id=$1 AND pedido_id=$2 AND tenant_id=$3',[req.params.pagoId, req.params.id, req.tenantId]);
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
    const fields=['estado','tipo','metodo_pago','notas','total','subtotal','descuento','datos_envio','usuario_id','notificar_wa','is_test','costo_envio','metodo_envio','cp_destino','estado_pago','sena','codigo_seguimiento'];
    for(const f of fields){ if(p[f]!==undefined){ sets.push(`${f}=$${pi++}`); params.push(p[f]); } }
    sets.push(`updated_at=NOW()`);
    if(sets.length<=1) return res.json({ok:true});
    params.push(req.params.id);
    params.push(req.tenantId); await pool.query(`UPDATE pedidos SET ${sets.join(',')} WHERE id=$${pi} AND tenant_id=$${pi+1}`, params);

    // ── CUENTA CORRIENTE automática al cambiar estado de pago ──
    const nuevoEstadoPago = (p.estado_pago!==undefined) ? String(p.estado_pago) : oldEstadoPago;
    // (antes esto solo corría si el pedido tenía cliente asignado, y usaba una conexión inexistente:
    //  marcar "pagado" no registraba el cobro en la caja y marcar "debe" daba error)
    if(nuevoEstadoPago !== oldEstadoPago){
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
          const {rows:pagosYa}=await pool.query('SELECT COALESCE(SUM(cuenta_como),0) as saldado FROM pedido_pagos WHERE pedido_id=$1 AND tenant_id=$2', [req.params.id, req.tenantId]);
          const yaSaldado=Number(pagosYa[0]?.saldado||0);
          const {rows:itPed}=await pool.query('SELECT precio_unitario, cantidad FROM pedido_items WHERE pedido_id=$1 AND tenant_id=$2',[req.params.id, req.tenantId]);
          const totItems=itPed.reduce((a,it)=>a+Number(it.precio_unitario||0)*Number(it.cantidad||1),0);
          const totalPed=totItems>0 ? (totItems - Number((oldPedRows[0]||{}).descuento||0) + Number((oldPedRows[0]||{}).costo_envio||0)) : ((p.total!==undefined)?Number(p.total):Number((oldPedRows[0]||{}).total||0));
          let falta=totalPed-yaSaldado;
          if(falta>totalPed) falta=totalPed; // nunca registrar un pago mayor al total del pedido
          if(falta>0.01 && totalPed>0){
            await pool.query(
              'INSERT INTO pedido_pagos (tenant_id,pedido_id,metodo,monto,recibido,cuenta_como,ajuste_pct,ajuste_monto,nota) VALUES ($1,$2,$3,$4,$5,$6,0,0,$7)',
              [req.tenantId, req.params.id, (p.metodo_pago||(oldPedRows[0]||{}).metodo_pago||'Efectivo'), falta, falta, falta, 'Marcado como pagado']
            ).catch(e=>console.log('[auto-pago]', e.message));
            await pool.query('UPDATE pedidos SET sena=0 WHERE id=$1 AND tenant_id=$2', [req.params.id, req.tenantId]).catch(()=>{});
          }
        } catch(e){ console.log('[auto-pago]', e.message); }
      }
      if(pedUsuarioId && nuevoEstadoPago==='debe' && oldEstadoPago!=='debe'){
        // Pasó a "debe" (fiado): registrar cargo si no existe ya para este pedido
        const {rows:ya}=await pool.query("SELECT id FROM cuenta_corriente WHERE pedido_id=$1 AND tipo='cargo' AND tenant_id=$2", [req.params.id, req.tenantId]);
        if(!ya.length){
          const {rows:itPed}=await pool.query('SELECT precio_unitario, cantidad FROM pedido_items WHERE pedido_id=$1 AND tenant_id=$2',[req.params.id, req.tenantId]);
          const totItems=itPed.reduce((a,it)=>a+Number(it.precio_unitario||0)*Number(it.cantidad||1),0);
          const totalPed=totItems>0 ? (totItems - Number((oldPedRows[0]||{}).descuento||0) + Number((oldPedRows[0]||{}).costo_envio||0)) : ((p.total!==undefined)?Number(p.total):Number((oldPedRows[0]||{}).total||0));
          const senaPed=(p.sena!==undefined)?Number(p.sena):Number((oldPedRows[0]||{}).sena||0);
          const deuda=totalPed-senaPed;
          if(deuda>0) await pool.query('INSERT INTO cuenta_corriente (tenant_id,usuario_id,tipo,monto,concepto,pedido_id) VALUES ($6,$1,$2,$3,$4,$5)', [pedUsuarioId,'cargo',deuda,`Pedido #${String(req.params.id).padStart(4,'0')}`,req.params.id, req.tenantId]).catch(()=>{});
        }
      } else if(oldEstadoPago==='debe' && nuevoEstadoPago!=='debe'){
        // Salió de "debe" (se pagó): quitar el cargo automático de este pedido
        await pool.query("DELETE FROM cuenta_corriente WHERE pedido_id=$1 AND tipo='cargo' AND tenant_id=$2", [req.params.id, req.tenantId]).catch(()=>{});
      }
    }
    if(p.items){
      // Capturar productos afectados (viejos + nuevos) para recalcular preventa
      const {rows:viejos}=await pool.query('SELECT DISTINCT producto_id FROM pedido_items WHERE pedido_id=$1 AND tenant_id=$2', [req.params.id, req.tenantId]);
      await pool.query('DELETE FROM pedido_items WHERE pedido_id=$1 AND tenant_id=$2', [req.params.id, req.tenantId]);
      // tenant_id explícito (antes quedaba en 1 por defecto y en otras tiendas el pedido editado se quedaba sin productos) + foto del producto
      // Solo productos de esta tienda: uno ajeno queda como línea de texto y no toca su stock
      const propios=await idsProductosDeTienda(pool, req.tenantId, p.items.map(it=>it.producto_id||it.id));
      p.items=p.items.map(it=>{ const id=parseInt(it.producto_id||it.id,10); return propios.has(id) ? it : { ...it, producto_id:null, id:null }; });
      for(const item of p.items){ await pool.query("INSERT INTO pedido_items (tenant_id,pedido_id,producto_id,categoria,modelo,nombre_producto,cantidad,precio_unitario,precio_base,variante_id,variante_combinacion,imagen) VALUES ($11,$1,$2,$3,$4,$5,$6,$7,$8,$9,$10,COALESCE((SELECT imagen FROM productos WHERE id=$2 AND tenant_id=$11),''))", [req.params.id, item.producto_id||item.id||null, item.categoria||'', item.modelo||'', item.nombre_producto||`${item.categoria} - ${item.modelo}`, item.cantidad||item.qty||1, item.precio_unitario||0, item.precio_base||0, item.variante_id||null, item.variante_label||item.variante_combinacion||'', req.tenantId]); }
      // Recalcular reservado de preventa para todos los productos tocados
      const afectados=new Set([...viejos.map(v=>v.producto_id), ...p.items.map(it=>it.producto_id||it.id)].filter(Boolean));
      for(const pid of afectados) await recalcReservado(pid, req.tenantId);
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
      const {rows:esPre}=await pool.query('SELECT es_preventa FROM productos WHERE id=$1 AND tenant_id=$2', [pid, req.tenantId]);
      if(!esPre[0]) continue; // producto de otra tienda o borrado: no se toca
      if(esPre[0].es_preventa){ await recalcReservado(pid, req.tenantId); continue; }
      await pool.query('UPDATE productos SET stock=GREATEST(0, stock + $1) WHERE id=$2 AND tenant_id=$3 AND permitir_sin_stock=false AND es_digital=false', [q, pid, req.tenantId]);
    }
    // Recalcular reservado si cambió el estado (cancelación/reactivación) para productos del pedido
    if(p.estado!==undefined && !p.items){
      for(const it of oldItemsRows){ if(it.producto_id) await recalcReservado(it.producto_id, req.tenantId); }
    }
    res.json({ok:true});
  }catch(e){ res.status(500).json({error:e.message}); }
});
app.post('/api/pedidos/:id/archivar', authPerm('pedidos'), async (req,res)=>{ try{ await pool.query('UPDATE pedidos SET archivado=true WHERE id=$1 AND tenant_id=$2', [req.params.id, req.tenantId]); res.json({ok:true}); }catch(e){ res.status(500).json({error:e.message}); } });
app.post('/api/pedidos/:id/desarchivar', authPerm('pedidos'), async (req,res)=>{ try{ await pool.query('UPDATE pedidos SET archivado=false WHERE id=$1 AND tenant_id=$2', [req.params.id, req.tenantId]); res.json({ok:true}); }catch(e){ res.status(500).json({error:e.message}); } });
app.delete('/api/pedidos/:id', authPerm('pedidos'), async (req,res)=>{ try{ const {rows:oep}=await pool.query('SELECT estado, tipo FROM pedidos WHERE id=$1 AND tenant_id=$2',[req.params.id, req.tenantId]); if(!oep[0]) return res.status(404).json({error:'No encontrado'}); const oe=String((oep[0]||{}).estado||'').toLowerCase(); const ot=String((oep[0]||{}).tipo||''); const afectabaStock = ot==='pedido' && !['cancelado','anulado','rechazado'].includes(oe); const {rows:its}=await pool.query('SELECT producto_id, cantidad, variante_id FROM pedido_items WHERE pedido_id=$1',[req.params.id]); const preIds=[]; if(afectabaStock){ for(const it of its){ if(it.variante_id){ await pool.query('UPDATE variantes SET stock=GREATEST(0, stock + $1) WHERE id=$2 AND tenant_id=$3',[it.cantidad||0, it.variante_id, req.tenantId]); continue; } if(!it.producto_id) continue; const {rows:pp}=await pool.query('SELECT es_preventa FROM productos WHERE id=$1 AND tenant_id=$2',[it.producto_id, req.tenantId]); if(!pp[0]) continue; if(pp[0].es_preventa){ preIds.push(it.producto_id); } else { await pool.query('UPDATE productos SET stock=GREATEST(0, stock + $1) WHERE id=$2 AND tenant_id=$3 AND permitir_sin_stock=false AND es_digital=false',[it.cantidad||0, it.producto_id, req.tenantId]); } } } await pool.query('DELETE FROM pedido_items WHERE pedido_id=$1', [req.params.id]); await pool.query('DELETE FROM pedidos WHERE id=$1 AND tenant_id=$2', [req.params.id, req.tenantId]); for(const pid of preIds) await recalcReservado(pid, req.tenantId); res.json({ok:true}); }catch(e){ res.status(500).json({error:e.message}); } });

// STATS
// REPORTES: más vendidos, ventas por sección, por mes, ganancias
// ==== CAJA / ARQUEO ==== (plata real cobrada, online + presencial)
app.get('/api/caja', authPerm('stats'), requiereFeature('caja'), async (req,res)=>{
  try{
    const {desde,hasta}=req.query;
    const cond=['pp.tenant_id=$1']; const params=[req.tenantId];
    if(desde){ params.push(desde); cond.push(`pp.created_at >= $${params.length}`); }
    if(hasta){ params.push(hasta); cond.push(`pp.created_at <= $${params.length}`); }
    const where=`WHERE ${cond.join(' AND ')}`;
    const J = `FROM pedido_pagos pp LEFT JOIN pedidos p ON p.id=pp.pedido_id ${where}`;
    const {rows:porMetodo}=await pool.query(`SELECT COALESCE(NULLIF(pp.metodo,''),'sin método') as metodo, COALESCE(SUM(pp.recibido),0) as recibido, COALESCE(SUM(pp.cuenta_como),0) as saldado ${J} AND COALESCE(p.moneda,'ARS')='ARS' GROUP BY pp.metodo ORDER BY recibido DESC`, params);
    const {rows:aj}=await pool.query(`SELECT COALESCE(SUM(CASE WHEN pp.ajuste_monto<0 THEN -pp.ajuste_monto ELSE 0 END),0) as descuentos, COALESCE(SUM(CASE WHEN pp.ajuste_monto>0 THEN pp.ajuste_monto ELSE 0 END),0) as recargos, COALESCE(SUM(pp.recibido),0) as total_recibido, COALESCE(SUM(pp.cuenta_como),0) as total_saldado ${J} AND COALESCE(p.moneda,'ARS')='ARS'`, params);
    const {rows:porMetodoU}=await pool.query(`SELECT COALESCE(NULLIF(pp.metodo,''),'sin método') as metodo, COALESCE(SUM(pp.recibido),0) as recibido, COALESCE(SUM(pp.cuenta_como),0) as saldado ${J} AND p.moneda='USDT' GROUP BY pp.metodo ORDER BY recibido DESC`, params);
    const {rows:ajU}=await pool.query(`SELECT COALESCE(SUM(pp.recibido),0) as total_recibido, COALESCE(SUM(pp.cuenta_como),0) as total_saldado ${J} AND p.moneda='USDT'`, params);
    res.json({ porMetodo, ...aj[0], usdt: { porMetodo: porMetodoU, total_recibido: Number(ajU[0].total_recibido), total_saldado: Number(ajU[0].total_saldado) } });
  }catch(e){ res.status(500).json({error:e.message}); }
});

app.get('/api/reportes', authPerm('stats'), requiereFeature('reportes'), async (req,res)=>{
  try{
    const {desde, hasta, seccion_id}=req.query;
    const cond=["p.tenant_id=$1", "p.tipo='pedido'", "LOWER(p.estado) NOT IN ('cancelado','anulado','rechazado')", "p.estado_pago IN ('pagado','senado')"]; const params=[req.tenantId]; let pi=2;
    if(desde){ cond.push(`p.created_at >= $${pi}`); params.push(desde); pi++; }
    if(hasta){ cond.push(`p.created_at <= $${pi}`); params.push(hasta+' 23:59:59'); pi++; }
    if(seccion_id && seccion_id!=='all'){ cond.push(`p.seccion_id = $${pi}`); params.push(seccion_id); pi++; }
    const where='WHERE '+cond.join(' AND ')+" AND p.moneda='ARS'";
    const whereU='WHERE '+cond.join(' AND ')+" AND p.moneda='USDT'";

    const masVendidos=await pool.query(`SELECT pi.producto_id, pi.nombre_producto, SUM(pi.cantidad)::int as unidades, SUM(pi.cantidad*pi.precio_unitario)::numeric as facturado FROM pedido_items pi JOIN pedidos p ON pi.pedido_id=p.id ${where} GROUP BY pi.producto_id, pi.nombre_producto ORDER BY unidades DESC LIMIT 20`, params);
    const porSeccion=await pool.query(`SELECT s.id as seccion_id, s.nombre as seccion, COUNT(DISTINCT p.id)::int as pedidos, COALESCE(SUM(p.total),0)::numeric as total FROM pedidos p LEFT JOIN secciones s ON p.seccion_id=s.id ${where} GROUP BY s.id, s.nombre ORDER BY total DESC`, params);
    const gananciaPorSeccion=await pool.query(`SELECT p.seccion_id, COALESCE(SUM(pi.cantidad*pi.precio_unitario),0)::numeric as facturado, COALESCE(SUM(pi.cantidad*COALESCE(NULLIF(pr.precio_original,0),0)),0)::numeric as costo FROM pedido_items pi JOIN pedidos p ON pi.pedido_id=p.id LEFT JOIN productos pr ON pi.producto_id=pr.id AND pr.tenant_id=p.tenant_id ${where} GROUP BY p.seccion_id`, params);
    const gxs={}; gananciaPorSeccion.rows.forEach(r=>{ gxs[r.seccion_id]={ facturado:Number(r.facturado), costo:Number(r.costo), ganancia:Number(r.facturado)-Number(r.costo) }; });
    const porSeccionConGanancia = porSeccion.rows.map(s=>({ ...s, facturado: gxs[s.seccion_id]?.facturado||0, costo: gxs[s.seccion_id]?.costo||0, ganancia: gxs[s.seccion_id]?.ganancia||0 }));
    const porMes=await pool.query(`SELECT TO_CHAR(DATE_TRUNC('month', p.created_at),'YYYY-MM') as mes, COUNT(*)::int as pedidos, COALESCE(SUM(p.total),0)::numeric as total FROM pedidos p ${where} GROUP BY mes ORDER BY mes DESC LIMIT 12`, params);
    const ganancias=await pool.query(`SELECT COALESCE(SUM(pi.cantidad*pi.precio_unitario),0)::numeric as facturado, COALESCE(SUM(pi.cantidad*COALESCE(NULLIF(pr.precio_original,0), 0)),0)::numeric as costo FROM pedido_items pi JOIN pedidos p ON pi.pedido_id=p.id LEFT JOIN productos pr ON pi.producto_id=pr.id AND pr.tenant_id=p.tenant_id ${where}`, params);
    const g=ganancias.rows[0]||{facturado:0,costo:0};
    const gU=await pool.query(`SELECT COALESCE(SUM(pi.cantidad*pi.precio_unitario),0)::numeric as facturado, COALESCE(SUM(pi.cantidad*COALESCE(NULLIF(pr.precio_original,0),0)),0)::numeric as costo, COALESCE(SUM(pi.cantidad),0)::int as unidades FROM pedido_items pi JOIN pedidos p ON pi.pedido_id=p.id LEFT JOIN productos pr ON pi.producto_id=pr.id AND pr.tenant_id=p.tenant_id ${whereU}`, params);
    const pedU=await pool.query(`SELECT COUNT(*)::int as pedidos FROM pedidos p ${whereU}`, params);
    const gu=gU.rows[0]||{facturado:0,costo:0,unidades:0};
    res.json({
      masVendidos: masVendidos.rows,
      porSeccion: porSeccionConGanancia,
      porMes: porMes.rows,
      ganancias: { facturado: Number(g.facturado), costo: Number(g.costo), ganancia: Number(g.facturado)-Number(g.costo) },
      usdt: { facturado: Number(gu.facturado), costo: Number(gu.costo), ganancia: Number(gu.facturado)-Number(gu.costo), unidades: Number(gu.unidades), pedidos: Number(pedU.rows[0].pedidos) }
    });
  }catch(e){ res.status(500).json({error:e.message}); }
});

// Fechas del dashboard en hora de Argentina (la base guarda en la zona del servidor, que en Railway es UTC):
// sin esto, un pedido de las 22 h caía en el día siguiente y "hoy" quedaba en 0 desde las 21 h.
const TZ_TIENDA = `'${(process.env.TZ_TIENDA || 'America/Argentina/Buenos_Aires').replace(/'/g, '')}'`;
const fLocal = (c) => `(${c} AT TIME ZONE current_setting('TimeZone') AT TIME ZONE ${TZ_TIENDA})`;
const HOY_LOCAL = `(now() AT TIME ZONE ${TZ_TIENDA})::date`;
// ─── CONTADOR PROPIO DE VISITAS Y BÚSQUEDAS ───
// Nombre legible del bot (null si es una persona). Los navegadores de adentro de Telegram/WhatsApp/Instagram son personas.
const BOTS_CONOCIDOS=[[/googlebot|google-inspectiontool|adsbot-google|googleother|google-read-aloud|mediapartners-google/i,'Google'],[/lighthouse|pagespeed|gtmetrix/i,'Pruebas de velocidad'],
  [/bingbot|bingpreview|msnbot/i,'Bing'],[/vercel/i,'Vercel'],[/facebookexternalhit|meta-externalagent|facebookbot/i,'Meta'],[/applebot/i,'Apple'],
  [/gptbot|chatgpt|oai-searchbot/i,'ChatGPT'],[/claudebot|claude-user|anthropic/i,'Claude'],[/perplexity/i,'Perplexity'],[/bytespider/i,'TikTok'],
  [/ahrefsbot/i,'Ahrefs'],[/semrushbot/i,'Semrush'],[/yandex/i,'Yandex'],[/duckduck/i,'DuckDuckGo'],[/headlesschrome|phantomjs|puppeteer|playwright|selenium/i,'Navegador automático']];
function botDe(ua){
  const u=String(ua||'');
  for(const [re,n] of BOTS_CONOCIDOS) if(re.test(u)) return n;
  if(/bot\b|bot\/|crawl|spider|slurp|scrap/i.test(u)) { const m=/([a-z0-9_-]*(?:bot|crawler|spider))/i.exec(u); return (m&&m[1]?m[1]:'Otro bot').slice(0,40); }
  if(!u.trim()) return 'Sin navegador';
  return null;
}
function dispositivoDe(ua){
  const u=String(ua||'');
  if(botDe(u)) return 'bot';
  if(/ipad|tablet|kindle|silk|playbook/i.test(u) || (/android/i.test(u) && !/mobile/i.test(u))) return 'tablet';
  if(/mobi|iphone|ipod|android|blackberry|opera mini|iemobile/i.test(u)) return 'mobile';
  return 'desktop';
}
const T = (x, n) => String(x==null?'':x).replace(/[\u0000-\u001F\u007F]/g,'').trim().slice(0, n);
app.post('/api/track', rateLimit({ windowMs: 60*1000, max: 120, standardHeaders: true, legacyHeaders: false, message: { ok:false } }), async (req,res)=>{
  try{
    const b=req.body||{};
    const tipo = b.t==='busqueda' ? 'busqueda' : b.t==='ping' ? 'ping' : 'vista'; // ping: el cliente sigue en la página (para el tiempo promedio)
    const visitante=T(b.v,40), sesion=T(b.s,40);
    if(!visitante || !sesion) return res.status(204).end();
    let origen=T(b.r,300);
    try{ if(origen){ const h=new URL(origen).hostname.replace(/^www\./,''); origen = h; } }catch{ origen=T(origen,120); }
    const termino = tipo==='busqueda' ? T(b.q,120).toLowerCase() : null;
    if(tipo==='busqueda' && (!termino || termino.length<2)) return res.status(204).end();
    const ua=req.headers['user-agent'];
    await pool.query('INSERT INTO visitas_eventos (tenant_id,visitante,sesion,tipo,path,origen,dispositivo,termino,resultados,bot_nombre) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)',
      [req.tenantId, visitante, sesion, tipo, T(b.p,300), T(origen,120), dispositivoDe(ua), termino, tipo==='busqueda' ? Math.max(0, parseInt(b.n,10)||0) : null, botDe(ua)||'']);
    if(Math.random()<0.002) pool.query("DELETE FROM visitas_eventos WHERE created_at < NOW() - INTERVAL '400 days'").catch(()=>{});
    res.status(204).end();
  }catch(e){ res.status(204).end(); }
});
app.get('/api/analytics/visitas', authPerm('stats'), async (req,res)=>{
  try{
    const t=req.tenantId; const params=[t]; let w='tenant_id=$1';
    const hoy=new Date(); const d0=new Date(hoy.getTime()-29*86400000);
    const desde=/^\d{4}-\d{2}-\d{2}$/.test(String(req.query.desde||'')) ? req.query.desde : d0.toISOString().slice(0,10);
    const hasta=/^\d{4}-\d{2}-\d{2}$/.test(String(req.query.hasta||'')) ? req.query.hasta : null;
    params.push(desde); w+=` AND ${fLocal('created_at')}::date >= $${params.length}`;
    if(hasta){ params.push(hasta); w+=` AND ${fLocal('created_at')}::date <= $${params.length}`; }
    const q=(sql)=>pool.query(sql, params).then(r=>r.rows);
    const [k] = await q(`SELECT COUNT(DISTINCT sesion) FILTER (WHERE tipo='vista' AND dispositivo<>'bot')::int AS visitas, COUNT(DISTINCT visitante) FILTER (WHERE tipo='vista' AND dispositivo<>'bot')::int AS visitantes, COUNT(*) FILTER (WHERE tipo='vista' AND dispositivo<>'bot')::int AS paginas, COUNT(*) FILTER (WHERE tipo='busqueda')::int AS busquedas FROM visitas_eventos WHERE ${w}`);
    const [tp] = await q(`SELECT COALESCE(ROUND(AVG(dur))::int,0) AS seg FROM (SELECT EXTRACT(EPOCH FROM MAX(created_at)-MIN(created_at)) AS dur FROM visitas_eventos WHERE ${w} AND dispositivo<>'bot' GROUP BY sesion) x`);
    const dias = await q(`SELECT to_char(${fLocal('created_at')}::date,'YYYY-MM-DD') AS fecha, COUNT(DISTINCT sesion)::int AS visitas, COUNT(*)::int AS paginas FROM visitas_eventos WHERE ${w} AND tipo='vista' AND dispositivo<>'bot' GROUP BY 1 ORDER BY 1`);
    const disp = await q(`SELECT dispositivo AS k, COUNT(DISTINCT sesion)::int AS n FROM visitas_eventos WHERE ${w} AND tipo='vista' GROUP BY 1 ORDER BY 2 DESC`);
    const bots = await q(`SELECT COALESCE(NULLIF(bot_nombre,''),'Sin identificar (de antes)') AS k, COUNT(DISTINCT sesion)::int AS n FROM visitas_eventos WHERE ${w} AND dispositivo='bot' GROUP BY 1 ORDER BY 2 DESC LIMIT 8`);
    const origenes = await q(`SELECT COALESCE(NULLIF(origen,''),'directo') AS k, COUNT(DISTINCT sesion)::int AS n FROM visitas_eventos WHERE ${w} AND tipo='vista' AND dispositivo<>'bot' GROUP BY 1 ORDER BY 2 DESC LIMIT 8`);
    const paginas = await q(`SELECT path AS k, COUNT(*)::int AS n FROM visitas_eventos WHERE ${w} AND tipo='vista' AND dispositivo<>'bot' GROUP BY 1 ORDER BY 2 DESC LIMIT 10`);
    const busq = await q(`SELECT termino AS k, COUNT(*)::int AS n, MIN(resultados)::int AS min_res, to_char(MAX(${fLocal('created_at')}),'YYYY-MM-DD HH24:MI') AS ultima FROM visitas_eventos WHERE ${w} AND tipo='busqueda' GROUP BY 1 ORDER BY 2 DESC LIMIT 15`);
    const sinRes = await q(`SELECT termino AS k, COUNT(*)::int AS n, to_char(MAX(${fLocal('created_at')}),'YYYY-MM-DD HH24:MI') AS ultima FROM visitas_eventos WHERE ${w} AND tipo='busqueda' AND resultados=0 GROUP BY 1 ORDER BY 2 DESC LIMIT 15`);
    // Nombre del producto para las páginas /producto/...-ID
    const ids=paginas.map(p=>{ const m=/^\/producto\/.*-(\d+)$/.exec(p.k||''); return m?parseInt(m[1],10):null; }).filter(Boolean);
    let nombres={}; if(ids.length){ const {rows}=await pool.query('SELECT id, nombre FROM productos WHERE tenant_id=$1 AND id = ANY($2::int[])', [t, ids]); rows.forEach(r=>nombres[r.id]=r.nombre); }
    paginas.forEach(p=>{ const m=/^\/producto\/.*-(\d+)$/.exec(p.k||''); if(m && nombres[m[1]]) p.nombre=nombres[m[1]]; });
    res.json({ desde, hasta, ...k, tiempo_promedio_seg: tp ? tp.seg : 0, dias, dispositivos: disp, bots, origenes, paginas_top: paginas, busquedas_top: busq, busquedas_sin_resultado: sinRes });
  }catch(e){ res.status(500).json({error:e.message}); }
});
app.get('/api/stats', authPerm('stats'), async (req,res)=>{
  try{
    const {seccion_id,desde,hasta,is_test}=req.query;
    const params=[req.tenantId];
    let secWhere=''; if(seccion_id && seccion_id!=='all'){ params.push(seccion_id); secWhere=` AND seccion_id=$${params.length}`; }
    let dateWhere='';
    if(desde){ params.push(desde); dateWhere+=` AND ${fLocal('created_at')} >= $${params.length}`; }
    if(hasta){ params.push(hasta); dateWhere+=` AND ${fLocal('created_at')} <= $${params.length}`; }
    let testWhere=''; if(is_test==='false') testWhere=' AND is_test=false';
    // COBRADO = pagado→total, señado→sena (lo efectivamente cobrado), impago→0
    const COBR = `CASE WHEN estado_pago='pagado' THEN total WHEN estado_pago='senado' THEN COALESCE(sena,0) ELSE 0 END`;
    // Base ARS: pedidos reales (no presupuestos), no archivados, moneda pesos
    const base = `tenant_id=$1 AND archivado=false AND tipo='pedido' AND moneda='ARS'${secWhere}${dateWhere}${testWhere}`;
    const vivos = `${base} AND estado NOT IN ('cancelado')`;

    const totalPedidos = await pool.query(`SELECT COUNT(*) FROM pedidos WHERE ${vivos}`, params);
    const ventas = await pool.query(`SELECT COALESCE(SUM(${COBR}),0) AS total, COUNT(*) FILTER (WHERE estado_pago='pagado') AS pagados FROM pedidos WHERE ${vivos}`, params);
    const aCobrar = await pool.query(`SELECT COALESCE(SUM(total - ${COBR}),0) AS total, COUNT(*) FILTER (WHERE estado_pago<>'pagado') AS cant FROM pedidos WHERE ${vivos}`, params);
    const totalProductos = await pool.query(`SELECT COUNT(*) FROM productos WHERE tenant_id=$1${seccion_id && seccion_id!=='all' ? ' AND seccion_id=$2' : ''}`, seccion_id && seccion_id!=='all' ? [req.tenantId, seccion_id] : [req.tenantId]);
    const totalUsuarios = await pool.query('SELECT COUNT(*) FROM usuarios WHERE rol <> $1 AND tenant_id=$2', ['admin', req.tenantId]);
    const ventasPorDia = await pool.query(`SELECT to_char(${fLocal('created_at')}::date,'YYYY-MM-DD') AS fecha, COUNT(*)::int AS pedidos, COUNT(*) FILTER (WHERE estado_pago<>'impago') AS cantidad, COALESCE(SUM(${COBR}),0) AS total, COALESCE(SUM(total),0) AS vendido FROM pedidos WHERE ${vivos} GROUP BY 1 ORDER BY 1 DESC LIMIT 60`, params);
    const porEstado = await pool.query(`SELECT LOWER(estado) AS estado, COUNT(*) AS cantidad FROM pedidos WHERE ${vivos} GROUP BY LOWER(estado)`, params);
    const porMetodo = await pool.query(`SELECT COALESCE(NULLIF(metodo_pago,''),'—') AS metodo, COUNT(*) AS cantidad, COALESCE(SUM(${COBR}),0) AS total FROM pedidos WHERE ${vivos} GROUP BY COALESCE(NULLIF(metodo_pago,''),'—') ORDER BY total DESC`, params);
    let porSeccion={rows:[]};
    if(!(seccion_id && seccion_id!=='all')){
      porSeccion = await pool.query(`SELECT s.id AS seccion_id, s.nombre AS seccion, COUNT(*)::int AS cantidad, COALESCE(SUM(${COBR}),0) AS total FROM pedidos p JOIN secciones s ON s.id=p.seccion_id WHERE p.tenant_id=$1 AND p.archivado=false AND p.tipo='pedido' AND p.moneda='ARS' AND p.estado NOT IN ('cancelado')${dateWhere.replace(/created_at/g,'p.created_at')}${testWhere.replace('is_test','p.is_test')} GROUP BY s.id, s.nombre ORDER BY total DESC LIMIT 10`, params);
    }
    const secP = secWhere.replace('seccion_id','p.seccion_id');
    const dateP = dateWhere.replace(/created_at/g,'p.created_at');
    const testP = testWhere.replace('is_test','p.is_test');
    const cobrRel = `p.moneda='ARS' AND p.estado NOT IN ('cancelado') AND p.estado_pago IN ('pagado','senado')`;
    const topCat = await pool.query(`SELECT COALESCE(NULLIF(pi.categoria,''),'Sin categoría') AS categoria, SUM(pi.cantidad) AS cantidad, COALESCE(SUM(pi.precio_unitario*pi.cantidad),0) AS total FROM pedido_items pi JOIN pedidos p ON pi.pedido_id=p.id WHERE p.tenant_id=$1 AND p.archivado=false AND p.tipo='pedido' AND ${cobrRel}${secP}${dateP}${testP} GROUP BY COALESCE(NULLIF(pi.categoria,''),'Sin categoría') ORDER BY total DESC LIMIT 8`, params);
    const topProd = await pool.query(`SELECT COALESCE(NULLIF(pi.nombre_producto,''),'—') AS nombre, SUM(pi.cantidad) AS cantidad, COALESCE(SUM(pi.precio_unitario*pi.cantidad),0) AS total FROM pedido_items pi JOIN pedidos p ON pi.pedido_id=p.id WHERE p.tenant_id=$1 AND p.archivado=false AND p.tipo='pedido' AND ${cobrRel}${secP}${dateP}${testP} GROUP BY COALESCE(NULLIF(pi.nombre_producto,''),'—') ORDER BY cantidad DESC LIMIT 10`, params);
    const mesParams=[req.tenantId]; let secMes=''; if(seccion_id && seccion_id!=='all'){ mesParams.push(seccion_id); secMes=' AND seccion_id=$2'; }
    const mesAct = await pool.query(`SELECT COALESCE(SUM(${COBR}),0) AS total FROM pedidos WHERE tenant_id=$1 AND archivado=false AND tipo='pedido' AND moneda='ARS' AND estado NOT IN ('cancelado')${secMes}${testWhere} AND ${fLocal('created_at')} >= date_trunc('month', ${HOY_LOCAL})`, mesParams);
    const mesAnt = await pool.query(`SELECT COALESCE(SUM(${COBR}),0) AS total FROM pedidos WHERE tenant_id=$1 AND archivado=false AND tipo='pedido' AND moneda='ARS' AND estado NOT IN ('cancelado')${secMes}${testWhere} AND ${fLocal('created_at')} >= date_trunc('month', ${HOY_LOCAL} - INTERVAL '1 month') AND ${fLocal('created_at')} < LEAST(date_trunc('month', ${HOY_LOCAL}), date_trunc('month', ${HOY_LOCAL} - INTERVAL '1 month') + ((${HOY_LOCAL} - date_trunc('month', ${HOY_LOCAL})::date) + 1) * INTERVAL '1 day')`, mesParams); // mismo tramo del mes pasado (del 1 al día de hoy)
    const abandonados = await pool.query('SELECT COUNT(*) FROM carritos_abandonados WHERE recuperado=false AND tenant_id=$1', [req.tenantId]).catch(()=>({rows:[{count:0}]}));
    // Hoy (no depende del filtro de fechas)
    const hoyQ = await pool.query(`SELECT COUNT(*)::int AS pedidos, COALESCE(SUM(total),0) AS total, COALESCE(SUM(${COBR}),0) AS cobrado FROM pedidos WHERE tenant_id=$1 AND archivado=false AND tipo='pedido' AND moneda='ARS' AND estado NOT IN ('cancelado')${secMes}${testWhere} AND ${fLocal('created_at')}::date = ${HOY_LOCAL}`, mesParams);
    // Ganancia estimada: lo cobrado de cada producto menos su precio de costo (solo productos con costo cargado)
    const ganQ = await pool.query(`SELECT COALESCE(SUM(pi.cantidad*pi.precio_unitario),0) AS facturado,
        COALESCE(SUM(pi.cantidad*pi.precio_unitario) FILTER (WHERE COALESCE(pr.precio_original,0)>0),0) AS facturado_con_costo,
        COALESCE(SUM(pi.cantidad*pr.precio_original) FILTER (WHERE COALESCE(pr.precio_original,0)>0),0) AS costo
      FROM pedido_items pi JOIN pedidos p ON pi.pedido_id=p.id LEFT JOIN productos pr ON pr.id=pi.producto_id AND pr.tenant_id=p.tenant_id
      WHERE p.tenant_id=$1 AND p.archivado=false AND p.tipo='pedido' AND ${cobrRel}${secP}${dateP}${testP}`, params);
    // Clientes nuevos: en el rango elegido, o en los últimos 30 días
    const cliParams=[req.tenantId]; let cliWhere='';
    if(desde||hasta){ if(desde){ cliParams.push(desde); cliWhere+=` AND ${fLocal('created_at')} >= $${cliParams.length}`; } if(hasta){ cliParams.push(hasta); cliWhere+=` AND ${fLocal('created_at')} <= $${cliParams.length}`; } }
    else cliWhere=` AND ${fLocal('created_at')} >= ${HOY_LOCAL} - INTERVAL '30 days'`;
    const cliNuevos = await pool.query(`SELECT COUNT(*)::int AS n FROM usuarios WHERE tenant_id=$1 AND rol='cliente'${cliWhere}`, cliParams).catch(()=>({rows:[{n:0}]}));
    const pendAprob = await pool.query(`SELECT COUNT(*)::int AS n FROM usuarios WHERE tenant_id=$1 AND rol='cliente' AND ((aprobado=false AND activo<>false) OR (mayorista_solicitado_at IS NOT NULL AND COALESCE(mayorista,false)=false))`, [req.tenantId]).catch(()=>({rows:[{n:0}]}));
    const sinStock = await pool.query(`SELECT COUNT(*)::int AS n FROM productos WHERE tenant_id=$1 AND visible=true AND stock<=0 AND COALESCE(permitir_sin_stock,false)=false AND COALESCE(es_digital,false)=false${seccion_id && seccion_id!=='all' ? ' AND seccion_id=$2' : ''}`, seccion_id && seccion_id!=='all' ? [req.tenantId, seccion_id] : [req.tenantId]).catch(()=>({rows:[{n:0}]}));

    // ── APARTADO USDT (mismo criterio: solo cobrado + seña) ──
    const baseU = `tenant_id=$1 AND archivado=false AND tipo='pedido' AND moneda='USDT'${secWhere}${dateWhere}${testWhere} AND estado NOT IN ('cancelado')`;
    const ventasU = await pool.query(`SELECT COALESCE(SUM(${COBR}),0) AS total, COUNT(*) FILTER (WHERE estado_pago='pagado') AS pagados, COUNT(*) AS pedidos, COALESCE(SUM(total - ${COBR}),0) AS a_cobrar FROM pedidos WHERE ${baseU}`, params);

    const estadoObj={}; porEstado.rows.forEach(r=>{ estadoObj[r.estado]=parseInt(r.cantidad); });
    const u=ventasU.rows[0]||{};
    res.json({
      total_pedidos: parseInt(totalPedidos.rows[0].count),
      total_ventas: parseFloat(ventas.rows[0].total),
      pedidos_pagados: parseInt(ventas.rows[0].pagados),
      total_a_cobrar: parseFloat(aCobrar.rows[0].total),
      pedidos_a_cobrar: parseInt(aCobrar.rows[0].cant),
      ticket_promedio: parseInt(ventas.rows[0].pagados)>0 ? parseFloat(ventas.rows[0].total)/parseInt(ventas.rows[0].pagados) : 0,
      total_productos: parseInt(totalProductos.rows[0].count),
      total_usuarios: parseInt(totalUsuarios.rows[0].count),
      ventas_por_dia: ventasPorDia.rows,
      pedidos_por_estado: estadoObj,
      ventas_por_metodo: porMetodo.rows,
      ventas_por_seccion: porSeccion.rows,
      top_categorias: topCat.rows,
      top_productos: topProd.rows,
      ventas_mes_actual: parseFloat(mesAct.rows[0].total),
      ventas_mes_anterior: parseFloat(mesAnt.rows[0].total),
      carritos_abandonados: parseInt(abandonados.rows[0].count),
      hoy: { pedidos: hoyQ.rows[0].pedidos, total: parseFloat(hoyQ.rows[0].total), cobrado: parseFloat(hoyQ.rows[0].cobrado) },
      ganancia: (()=>{ const g=ganQ.rows[0]||{}; const f=parseFloat(g.facturado||0), fc=parseFloat(g.facturado_con_costo||0), c=parseFloat(g.costo||0); return { ganancia: fc-c, facturado: f, facturado_con_costo: fc, costo: c, cobertura_pct: f>0 ? Math.round(fc/f*100) : 0, margen_pct: fc>0 ? Math.round((fc-c)/fc*100) : 0 }; })(),
      clientes_nuevos: cliNuevos.rows[0].n,
      clientes_por_aprobar: pendAprob.rows[0].n,
      productos_sin_stock: sinStock.rows[0].n,
      usdt: { total_ventas: parseFloat(u.total||0), pedidos: parseInt(u.pedidos||0), pedidos_pagados: parseInt(u.pagados||0), total_a_cobrar: parseFloat(u.a_cobrar||0) }
    });
  }catch(e){ res.status(500).json({error:e.message}); }
});

// GET /api/stats/detalle?tipo=…&valor=… — lo que hay detrás de cada número del dashboard (mismos filtros que /api/stats).
// tipo: pedidos | a_cobrar | cobrados | pagados | hoy | estado | metodo | seccion | dia | producto  → lista de pedidos
//       categoria | ganancia → lista de productos;  clientes_nuevos → lista de clientes
app.get('/api/stats/detalle', authPerm('stats'), async (req,res)=>{
  try{
    const {seccion_id,desde,hasta,is_test,tipo}=req.query;
    const valor=String(req.query.valor||'');
    const params=[req.tenantId];
    let w=`p.tenant_id=$1 AND p.archivado=false AND p.tipo='pedido' AND p.moneda='ARS' AND p.estado NOT IN ('cancelado')`;
    if(seccion_id && seccion_id!=='all'){ params.push(seccion_id); w+=` AND p.seccion_id=$${params.length}`; }
    const rango=(campo)=>{ let x=''; if(desde){ params.push(desde); x+=` AND ${fLocal(campo)} >= $${params.length}`; } if(hasta){ params.push(hasta); x+=` AND ${fLocal(campo)} <= $${params.length}`; } return x; };
    if(tipo!=='hoy') w+=rango('p.created_at');
    if(is_test==='false') w+=' AND p.is_test=false';
    const COBR=`CASE WHEN p.estado_pago='pagado' THEN p.total WHEN p.estado_pago='senado' THEN COALESCE(p.sena,0) ELSE 0 END`;
    const cobrRel=` AND p.estado_pago IN ('pagado','senado')`;

    if(tipo==='categoria' || tipo==='ganancia'){
      let extra=cobrRel;
      if(tipo==='categoria'){ params.push(valor); extra+=` AND COALESCE(NULLIF(pi.categoria,''),'Sin categoría')=$${params.length}`; }
      const {rows}=await pool.query(`SELECT COALESCE(NULLIF(pi.nombre_producto,''),'—') AS nombre, MAX(pi.producto_id) AS producto_id, MAX(COALESCE(NULLIF(pi.imagen,''), pr.imagen)) AS imagen, SUM(pi.cantidad)::int AS cantidad,
          COALESCE(SUM(pi.cantidad*pi.precio_unitario),0) AS total,
          CASE WHEN BOOL_AND(COALESCE(pr.precio_original,0)>0) THEN COALESCE(SUM(pi.cantidad*pr.precio_original),0) ELSE NULL END AS costo
        FROM pedido_items pi JOIN pedidos p ON pi.pedido_id=p.id LEFT JOIN productos pr ON pr.id=pi.producto_id AND pr.tenant_id=p.tenant_id
        WHERE ${w}${extra} GROUP BY COALESCE(NULLIF(pi.nombre_producto,''),'—') ORDER BY total DESC LIMIT 300`, params);
      const filas=rows.map(r=>({ ...r, total: parseFloat(r.total), costo: r.costo===null ? null : parseFloat(r.costo), ganancia: r.costo===null ? null : parseFloat(r.total)-parseFloat(r.costo) }));
      if(tipo==='ganancia') filas.sort((a,b)=> (a.ganancia===null) - (b.ganancia===null) || (b.ganancia||0)-(a.ganancia||0) || b.total-a.total);
      return res.json({ modo:'productos', filas, resumen:{ cantidad: filas.length, unidades: filas.reduce((a,r)=>a+r.cantidad,0), total: filas.reduce((a,r)=>a+r.total,0), ganancia: filas.reduce((a,r)=>a+(r.ganancia||0),0), sin_costo: filas.filter(r=>r.costo===null).length } });
    }
    if(tipo==='clientes_nuevos'){
      const cp=[req.tenantId]; let cw='';
      if(desde||hasta){ if(desde){ cp.push(desde); cw+=` AND ${fLocal('u.created_at')} >= $${cp.length}`; } if(hasta){ cp.push(hasta); cw+=` AND ${fLocal('u.created_at')} <= $${cp.length}`; } } else cw=` AND ${fLocal('u.created_at')} >= ${HOY_LOCAL} - INTERVAL '30 days'`;
      const {rows}=await pool.query(`SELECT u.id, u.nombre, u.usuario, u.telefono, u.email, u.created_at, u.aprobado,
          (SELECT COUNT(*)::int FROM pedidos p WHERE p.usuario_id=u.id AND p.tenant_id=u.tenant_id AND p.tipo='pedido' AND p.estado<>'cancelado') AS compras
        FROM usuarios u WHERE u.tenant_id=$1 AND u.rol='cliente'${cw} ORDER BY u.created_at DESC LIMIT 300`, cp);
      return res.json({ modo:'clientes', filas: rows, resumen:{ cantidad: rows.length, compraron: rows.filter(r=>r.compras>0).length } });
    }

    let extra='';
    switch(tipo){
      case 'pedidos': break;
      case 'a_cobrar': extra=` AND COALESCE(p.estado_pago,'impago')<>'pagado'`; break;
      case 'cobrados': extra=` AND (${COBR})>0`; break;
      case 'pagados': extra=` AND p.estado_pago='pagado'`; break;
      case 'hoy': extra=` AND ${fLocal('p.created_at')}::date = ${HOY_LOCAL}`; break;
      case 'estado': params.push(valor.toLowerCase()); extra=` AND LOWER(p.estado)=$${params.length}`; break;
      case 'metodo': params.push(valor); extra=` AND COALESCE(NULLIF(p.metodo_pago,''),'—')=$${params.length}`; break;
      case 'seccion': params.push(parseInt(valor)||0); extra=` AND p.seccion_id=$${params.length}`; break;
      case 'dia': if(!/^\d{4}-\d{2}-\d{2}$/.test(valor)) return res.status(400).json({error:'Fecha inválida'}); params.push(valor); extra=` AND ${fLocal('p.created_at')}::date=$${params.length}::date`; break;
      case 'producto': params.push(valor); extra=`${cobrRel} AND EXISTS (SELECT 1 FROM pedido_items pi WHERE pi.pedido_id=p.id AND COALESCE(NULLIF(pi.nombre_producto,''),'—')=$${params.length})`; break;
      default: return res.status(400).json({error:'Tipo de detalle desconocido'});
    }
    const cantProd = tipo==='producto' ? `, (SELECT COALESCE(SUM(pi.cantidad),0)::int FROM pedido_items pi WHERE pi.pedido_id=p.id AND COALESCE(NULLIF(pi.nombre_producto,''),'—')=$${params.length}) AS cantidad_producto` : '';
    const {rows}=await pool.query(`SELECT p.id, p.tipo, p.created_at, p.estado, COALESCE(NULLIF(p.estado_pago,''),'impago') AS estado_pago, p.total, p.metodo_pago, p.is_test,
        (${COBR}) AS cobrado, p.total-(${COBR}) AS saldo, p.seccion_id, s.nombre AS seccion_nombre, s.color AS seccion_color,
        u.nombre AS usuario_nombre, u.telefono AS usuario_telefono, u.nombre_fantasia${cantProd}
      FROM pedidos p LEFT JOIN usuarios u ON u.id=p.usuario_id LEFT JOIN secciones s ON s.id=p.seccion_id
      WHERE ${w}${extra} ORDER BY p.created_at DESC LIMIT 300`, params);
    const {rows:tot}=await pool.query(`SELECT COUNT(*)::int AS cantidad, COALESCE(SUM(p.total),0) AS total, COALESCE(SUM(${COBR}),0) AS cobrado, COALESCE(SUM(p.total-(${COBR})),0) AS saldo FROM pedidos p WHERE ${w}${extra}`, params);
    const t=tot[0]||{};
    res.json({ modo:'pedidos', filas: rows, resumen:{ cantidad: t.cantidad||0, total: parseFloat(t.total||0), cobrado: parseFloat(t.cobrado||0), saldo: parseFloat(t.saldo||0) } });
  }catch(e){ res.status(500).json({error:e.message}); }
});

// CUPONES, PROMOS, POPUPS, REDES, MENU, DESIGN, PAGOS, PAGINAS, BADGES, ENVIO, BUSQUEDA, SLIDER, FAVORITOS, STOCK, ANDREANI (se mantienen igual + fixes Andreani env)
app.get('/api/cupones', authPerm('config'), requiereFeature('marketing'), async (req,res)=>{ try{ const {rows}=await pool.query('SELECT c.*, array_agg(cp.producto_id) FILTER (WHERE cp.producto_id IS NOT NULL) as productos_ids FROM cupones c LEFT JOIN cupon_productos cp ON c.id=cp.cupon_id WHERE c.tenant_id=$1 GROUP BY c.id ORDER BY c.created_at DESC', [req.tenantId]); res.json(rows); }catch(e){ res.status(500).json({error:e.message}); } });
app.post('/api/cupones/validar', optionalAuth, async (req,res)=>{
  try{
    const {codigo,seccion_id,metodo_pago,items}=req.body;
    const ctx=await checkout.contexto(pool, req.tenantId, req.user?.id);
    const its=(await checkout.preciarItems(pool, ctx, items||[])).filter(i=>i.moneda==='ARS' && (!seccion_id || String(i.seccion_id)===String(seccion_id)));
    const subtotal=its.reduce((s,i)=>s+i.precio_unitario*i.cantidad,0);
    const r=await checkout.evaluarCupon(pool, ctx, codigo, { seccion_id, items:its, subtotal, metodo_pago });
    res.json(r);
  }catch(e){ if(e instanceof CheckoutError) return res.status(400).json({error:e.message}); res.status(500).json({error:'No se pudo validar el cupón'}); }
});
app.post('/api/cupones', authPerm('config'), requiereFeature('marketing'), async (req,res)=>{ try{ const c=req.body; const {rows}=await pool.query('INSERT INTO cupones (codigo,tipo,valor,secciones_ids,categoria,uso_maximo,monto_minimo,metodo_pago,activo,fecha_desde,fecha_hasta,solo_primera_compra,tenant_id) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13) RETURNING *', [c.codigo,c.tipo||'porcentaje',c.valor||0,c.secciones_ids||'',c.categoria||'',c.uso_maximo||0,c.monto_minimo||0,c.metodo_pago||'',c.activo!==false,c.fecha_desde||null,c.fecha_hasta||null,c.solo_primera_compra||false, req.tenantId]); if(c.productos_ids){ for(const pid of c.productos_ids){ await pool.query('INSERT INTO cupon_productos (cupon_id,producto_id,tenant_id) VALUES ($1,$2,$3) ON CONFLICT DO NOTHING', [rows[0].id,pid, req.tenantId]); } } res.json(rows[0]); }catch(e){ res.status(500).json({error:e.message}); } });
app.put('/api/cupones/:id', authPerm('config'), requiereFeature('marketing'), async (req,res)=>{ try{ const c=req.body; await pool.query('UPDATE cupones SET codigo=$1,tipo=$2,valor=$3,secciones_ids=$4,categoria=$5,uso_maximo=$6,monto_minimo=$7,metodo_pago=$8,activo=$9,fecha_desde=$10,fecha_hasta=$11,solo_primera_compra=$12 WHERE id=$13 AND tenant_id=$14', [c.codigo,c.tipo,c.valor,c.secciones_ids||'',c.categoria||'',c.uso_maximo||0,c.monto_minimo||0,c.metodo_pago||'',c.activo!==false,c.fecha_desde||null,c.fecha_hasta||null,c.solo_primera_compra||false,req.params.id, req.tenantId]).then(r=>{ if(!r.rowCount) throw Object.assign(new Error('Cupón no encontrado'),{status:404}); }); await pool.query('DELETE FROM cupon_productos WHERE cupon_id=$1', [req.params.id]); if(Array.isArray(c.productos_ids)){ const propios=await idsProductosDeTienda(pool, req.tenantId, c.productos_ids); for(const pid of propios){ await pool.query('INSERT INTO cupon_productos (cupon_id,producto_id,tenant_id) VALUES ($1,$2,$3)', [req.params.id,pid, req.tenantId]); } } res.json({ok:true}); }catch(e){ res.status(e.status||500).json({error:e.message}); } });
app.delete('/api/cupones/:id', authPerm('config'), requiereFeature('marketing'), async (req,res)=>{ try{ await pool.query('DELETE FROM cupones WHERE id=$1 AND tenant_id=$2', [req.params.id, req.tenantId]); res.json({ok:true}); }catch(e){ res.status(500).json({error:e.message}); } });

// PROMOCIONES
app.get('/api/promociones', authPerm('config'), requiereFeature('marketing'), async (req,res)=>{ try{ const {rows}=await pool.query('SELECT * FROM promociones WHERE tenant_id=$1 ORDER BY created_at DESC', [req.tenantId]); res.json(rows); }catch(e){ res.status(500).json({error:e.message}); } });
app.get('/api/promociones/activas', async (req,res)=>{ try{ const {rows}=await pool.query('SELECT * FROM promociones WHERE tenant_id=$1 AND activo=true AND (fecha_desde IS NULL OR fecha_desde<=CURRENT_DATE) AND (fecha_hasta IS NULL OR fecha_hasta>=CURRENT_DATE)', [req.tenantId]); res.json(rows); }catch(e){ res.status(500).json({error:e.message}); } });
app.post('/api/promociones', authPerm('config'), requiereFeature('marketing'), async (req,res)=>{ try{ const p=req.body; const {rows}=await pool.query('INSERT INTO promociones (nombre,tipo,valor,secciones_ids,categoria,productos_ids,activo,fecha_desde,fecha_hasta,tenant_id) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10) RETURNING *', [p.nombre,p.tipo,p.valor,p.secciones_ids||'',p.categoria||'',p.productos_ids||'',p.activo!==false,p.fecha_desde||null,p.fecha_hasta||null, req.tenantId]); res.json(rows[0]); }catch(e){ res.status(500).json({error:e.message}); } });
app.put('/api/promociones/:id', authPerm('config'), requiereFeature('marketing'), async (req,res)=>{ try{ const p=req.body; await pool.query('UPDATE promociones SET nombre=$1,tipo=$2,valor=$3,secciones_ids=$4,categoria=$5,productos_ids=$6,activo=$7,fecha_desde=$8,fecha_hasta=$9 WHERE id=$10 AND tenant_id=$11', [p.nombre,p.tipo,p.valor,p.secciones_ids||'',p.categoria||'',p.productos_ids||'',p.activo!==false,p.fecha_desde||null,p.fecha_hasta||null,req.params.id, req.tenantId]); res.json({ok:true}); }catch(e){ res.status(500).json({error:e.message}); } });
app.delete('/api/promociones/:id', authPerm('config'), requiereFeature('marketing'), async (req,res)=>{ try{ await pool.query('DELETE FROM promociones WHERE id=$1 AND tenant_id=$2', [req.params.id, req.tenantId]); res.json({ok:true}); }catch(e){ res.status(500).json({error:e.message}); } });

// POPUPS, REDES, MENU, DESIGN, METODOS PAGO, PAGINAS, BADGES, ENVIO CONFIG
app.get('/api/popups', async (req,res)=>{ try{ const {rows}=await pool.query('SELECT * FROM popups WHERE activo=true AND tenant_id=$1 ORDER BY created_at DESC', [req.tenantId]); res.json(rows); }catch(e){ res.status(500).json({error:e.message}); } });
app.get('/api/popups/all', authPerm('config'), async (req,res)=>{ try{ const {rows}=await pool.query('SELECT * FROM popups WHERE tenant_id=$1 ORDER BY created_at DESC', [req.tenantId]); res.json(rows); }catch(e){ res.status(500).json({error:e.message}); } });
// Pop-ups: varias imágenes (carrusel). 'imagen' queda como la primera, por compatibilidad.
const popupImagenes = (p) => {
  const arr = (Array.isArray(p.imagenes) ? p.imagenes : []).map(u => String(u || '').trim()).filter(u => /^(https?:\/\/|\/)/i.test(u)).slice(0, 10);
  if (!arr.length && p.imagen) arr.push(String(p.imagen).trim());
  return arr;
};
// Links que carga el admin (popups, banners, menú, redes): nunca "javascript:", "data:", etc.
// (el navegador ignora espacios y saltos dentro del esquema, por eso se sacan antes de revisar)
function limpiarUrl(u){ const v=String(u==null?'':u).trim(); if(!v) return ''; const compacta=v.replace(/[\u0000-\u0020\u007F]+/g,''); if(/^(javascript|data|vbscript|file|blob):/i.test(compacta)) return ''; return v.slice(0,1000); }
const sanearLinks=(campos)=>(req,res,next)=>{ const b=req.body||{}; for(const c of campos){ if(b[c]!==undefined) b[c]=limpiarUrl(b[c]); } if(Array.isArray(b.redes)) b.redes=b.redes.map(r=>({...(r||{}), url:limpiarUrl(r&&r.url)})); next(); };
app.post('/api/popups', authPerm('config'), sanearLinks(['url_destino']), async (req,res)=>{ try{ const p=req.body||{}; const imgs=popupImagenes(p); const {rows}=await pool.query('INSERT INTO popups (titulo,imagen,imagenes,url_destino,secciones_ids,activo,tenant_id) VALUES ($1,$2,$3::jsonb,$4,$5,$6,$7) RETURNING *', [p.titulo||'',imgs[0]||'',JSON.stringify(imgs),p.url_destino||'',p.secciones_ids||'',p.activo!==false, req.tenantId]); res.json(rows[0]); }catch(e){ res.status(500).json({error:e.message}); } });
app.put('/api/popups/:id', authPerm('config'), sanearLinks(['url_destino']), async (req,res)=>{ try{ const p=req.body||{}; const imgs=popupImagenes(p); await pool.query('UPDATE popups SET titulo=$1,imagen=$2,imagenes=$3::jsonb,url_destino=$4,secciones_ids=$5,activo=$6 WHERE id=$7 AND tenant_id=$8', [p.titulo||'',imgs[0]||'',JSON.stringify(imgs),p.url_destino||'',p.secciones_ids||'',p.activo!==false,req.params.id, req.tenantId]); res.json({ok:true}); }catch(e){ res.status(500).json({error:e.message}); } });
app.delete('/api/popups/:id', authPerm('config'), async (req,res)=>{ try{ await pool.query('DELETE FROM popups WHERE id=$1 AND tenant_id=$2', [req.params.id, req.tenantId]); res.json({ok:true}); }catch(e){ res.status(500).json({error:e.message}); } });

app.get('/api/redes-sociales', async (req,res)=>{ try{ const {rows}=await pool.query('SELECT * FROM redes_sociales WHERE tenant_id=$1 ORDER BY orden', [req.tenantId]); res.json(rows); }catch(e){ res.status(500).json({error:e.message}); } });
app.put('/api/redes-sociales', authPerm('config'), sanearLinks([]), async (req,res)=>{ const client=await pool.connect(); try{ const {redes}=req.body; await client.query('BEGIN'); await client.query('DELETE FROM redes_sociales WHERE tenant_id=$1', [req.tenantId]); let orden=0; for(const r of (redes||[])){ if(!r.url || !r.url.trim()) continue; await client.query('INSERT INTO redes_sociales (tipo,url,activo,orden,tenant_id) VALUES ($1,$2,$3,$4,$5)', [r.tipo, r.url.trim(), r.activo!==false, orden++, req.tenantId]); } await client.query('COMMIT'); res.json({ok:true}); }catch(e){ await client.query('ROLLBACK').catch(()=>{}); res.status(500).json({error:e.message}); } finally{ client.release(); } });

app.get('/api/menu', async (req,res)=>{ try{ const {rows}=await pool.query('SELECT * FROM menu_items WHERE visible=true AND tenant_id=$1 ORDER BY orden', [req.tenantId]); res.json(rows); }catch(e){ res.status(500).json({error:e.message}); } });
app.get('/api/menu/all', authPerm('config'), async (req,res)=>{ try{ const {rows}=await pool.query('SELECT * FROM menu_items WHERE tenant_id=$1 ORDER BY orden', [req.tenantId]); res.json(rows); }catch(e){ res.status(500).json({error:e.message}); } });
app.post('/api/menu', authPerm('config'), sanearLinks(['url']), async (req,res)=>{ try{ const m=req.body; const {rows}=await pool.query('INSERT INTO menu_items (titulo,url,tipo,visible,orden,seccion_id,tenant_id) VALUES ($1,$2,$3,$4,$5,$6,$7) RETURNING *', [m.titulo,m.url||'',m.tipo||'link',m.visible!==false,m.orden||0,m.seccion_id||null, req.tenantId]); res.json(rows[0]); }catch(e){ res.status(500).json({error:e.message}); } });
app.put('/api/menu/:id', authPerm('config'), sanearLinks(['url']), async (req,res)=>{ try{ const m=req.body; await pool.query('UPDATE menu_items SET titulo=$1,url=$2,tipo=$3,visible=$4,orden=$5,seccion_id=$6 WHERE id=$7 AND tenant_id=$8', [m.titulo,m.url,m.tipo,m.visible!==false,m.orden||0,m.seccion_id||null,req.params.id, req.tenantId]); res.json({ok:true}); }catch(e){ res.status(500).json({error:e.message}); } });
app.delete('/api/menu/:id', authPerm('config'), async (req,res)=>{ try{ await pool.query('DELETE FROM menu_items WHERE id=$1 AND tenant_id=$2', [req.params.id, req.tenantId]); res.json({ok:true}); }catch(e){ res.status(500).json({error:e.message}); } });

app.get('/api/design', async (req,res)=>{ try{ const {rows}=await pool.query('SELECT * FROM design_config WHERE tenant_id=$1', [req.tenantId]); const cfg={}; rows.forEach(r=>cfg[r.clave]=r.valor); res.json(cfg); }catch(e){ res.status(500).json({error:e.message}); } });
app.put('/api/design', authPerm('config'), async (req,res)=>{ try{ for(const [k,v] of Object.entries(req.body)){ await pool.query("INSERT INTO design_config (tenant_id,clave,valor) VALUES ($1,$2,$3) ON CONFLICT (tenant_id,clave) DO UPDATE SET valor=$3", [req.tenantId,k,v]); } res.json({ok:true}); }catch(e){ res.status(500).json({error:e.message}); } });

app.get('/api/metodos-pago', async (req,res)=>{ try{ const {seccion_id}=req.query; let q='SELECT * FROM metodos_pago WHERE activo=true AND tenant_id=$1'; const params=[req.tenantId]; if(seccion_id){ q+=' AND (seccion_id=$2 OR seccion_id IS NULL)'; params.push(seccion_id); } q+=' ORDER BY orden'; const {rows}=await pool.query(q, params); res.json(rows); }catch(e){ res.status(500).json({error:e.message}); } });
app.get('/api/metodos-pago/all', authPerm('config'), async (req,res)=>{ try{ const {rows}=await pool.query('SELECT * FROM metodos_pago WHERE tenant_id=$1 ORDER BY orden', [req.tenantId]); res.json(rows); }catch(e){ res.status(500).json({error:e.message}); } });
app.post('/api/metodos-pago', authPerm('config'), async (req,res)=>{ try{ const m=req.body; const {rows}=await pool.query('INSERT INTO metodos_pago (nombre,descripcion,instrucciones,icono,seccion_id,activo,orden,tenant_id) VALUES ($1,$2,$3,$4,$5,$6,$7,$8) RETURNING *', [m.nombre,m.descripcion||'',m.instrucciones||'',m.icono||'',m.seccion_id||null,m.activo!==false,m.orden||0, req.tenantId]); res.json(rows[0]); }catch(e){ res.status(500).json({error:e.message}); } });
app.put('/api/metodos-pago/:id', authPerm('config'), async (req,res)=>{ try{ const m=req.body; await pool.query('UPDATE metodos_pago SET nombre=$1,descripcion=$2,instrucciones=$3,icono=$4,seccion_id=$5,activo=$6,orden=$7 WHERE id=$8 AND tenant_id=$9', [m.nombre,m.descripcion,m.instrucciones,m.icono,m.seccion_id,m.activo!==false,m.orden||0,req.params.id, req.tenantId]); res.json({ok:true}); }catch(e){ res.status(500).json({error:e.message}); } });
app.delete('/api/metodos-pago/:id', authPerm('config'), async (req,res)=>{ try{ await pool.query('DELETE FROM metodos_pago WHERE id=$1 AND tenant_id=$2', [req.params.id, req.tenantId]); res.json({ok:true}); }catch(e){ res.status(500).json({error:e.message}); } });

app.get('/api/paginas', async (req,res)=>{ try{ const {seccion_id}=req.query; let q='SELECT * FROM paginas_info WHERE visible=true AND tenant_id=$1'; const params=[req.tenantId]; if(seccion_id){ q+=' AND (seccion_id=$2 OR seccion_id IS NULL)'; params.push(seccion_id); } q+=' ORDER BY orden'; const {rows}=await pool.query(q, params); res.json(rows); }catch(e){ res.status(500).json({error:e.message}); } });
app.get('/api/paginas/:id', async (req,res)=>{ try{ const {rows}=await pool.query('SELECT * FROM paginas_info WHERE id=$1 AND tenant_id=$2', [req.params.id, req.tenantId]); if(!rows[0]) return res.status(404).json({error:'No encontrada'}); res.json(rows[0]); }catch(e){ res.status(500).json({error:e.message}); } });
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
app.put('/api/envio/config/:seccion_id', authPerm('config'), async (req,res)=>{ try{ const c=req.body; const {rows:sp}=await pool.query('SELECT 1 FROM secciones WHERE id=$1 AND tenant_id=$2', [req.params.seccion_id, req.tenantId]); if(!sp[0]) return res.status(404).json({error:'Sección no encontrada'}); await pool.query('INSERT INTO config_envio (seccion_id,metodo,costo_fijo,gratis_desde,zonas,cp_origen,tenant_id) VALUES ($1,$2,$3,$4,$5,$6,$7) ON CONFLICT (seccion_id) DO UPDATE SET metodo=$2,costo_fijo=$3,gratis_desde=$4,zonas=$5,cp_origen=$6 WHERE config_envio.tenant_id=EXCLUDED.tenant_id', [req.params.seccion_id,c.metodo||'manual',c.costo_fijo||0,c.gratis_desde||0,JSON.stringify(c.zonas||[]),c.cp_origen||'1888', req.tenantId]); res.json({ok:true}); }catch(e){ res.status(500).json({error:e.message}); } });
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
    // El buscador general no incluye las tiendas con aprobación (mayorista): es un catálogo aparte
    const {rows:secciones}=await pool.query('SELECT * FROM secciones WHERE visible=true AND COALESCE(requiere_aprobacion,false)=false AND tenant_id=$1 ORDER BY orden, id', [req.tenantId]);
    const resultados=[];
    const toks = String(q).trim().split(/\s+/).filter(Boolean).slice(0,8);
    const campos = `(coalesce(nombre,'')||' '||coalesce(modelo,'')||' '||coalesce(categoria,'')||' '||coalesce(marca,'')||' '||coalesce(sku,'')||' '||coalesce(compatibilidad,'')||' '||coalesce(descripcion,''))`;
    for(const sec of secciones){
      const params=[sec.id, req.tenantId]; let pi=3; const cond=[];
      for(const tk of toks){ cond.push(`${SQL_SIN_ACENTOS(campos)} LIKE $${pi}`); params.push(tokenBusqueda(tk)); pi++; }
      const {rows}=await pool.query(`SELECT id,tenant_id,seccion_id,nombre,modelo,marca,categoria,precio_base,precio_oferta,moneda,imagen,stock,envio_gratis,permitir_sin_stock,es_digital,usa_variantes,es_preventa,preventa_precio,preventa_descuento_pct,preventa_fecha,preventa_mostrar_fecha,preventa_cupo,preventa_reservado,created_at,${IMG2('productos')},(SELECT MIN(CASE WHEN v.precio_oferta>0 AND v.precio_oferta<v.precio THEN v.precio_oferta ELSE v.precio END) FROM variantes v WHERE v.producto_id=productos.id AND v.tenant_id=productos.tenant_id AND v.precio>0) AS precio_desde,(SELECT v.moneda FROM variantes v WHERE v.producto_id=productos.id AND v.tenant_id=productos.tenant_id AND v.precio>0 ORDER BY (CASE WHEN v.precio_oferta>0 AND v.precio_oferta<v.precio THEN v.precio_oferta ELSE v.precio END) ASC LIMIT 1) AS moneda_desde FROM productos WHERE seccion_id=$1 AND tenant_id=$2 AND visible=true${cond.length?' AND '+cond.join(' AND '):''} ORDER BY stock DESC LIMIT 50`, params);
      if(rows.length){ const hidePrice=sec.slug==='mayorista' && !req.user; resultados.push({seccion:sec, productos: hidePrice? rows.map(r=>({...r, precio_base:0, precio_oferta:0})) : rows}); }
    }
    res.json({resultados, total: resultados.reduce((s,r)=>s+r.productos.length,0)});
  }catch(e){ res.status(500).json({error:e.message}); }
});

// SLIDER, FAVORITOS, NOTIF STOCK
app.get('/api/slider', async (req,res)=>{ try{ const {rows}=await pool.query('SELECT * FROM slider_banners WHERE activo=true AND tenant_id=$1 ORDER BY orden', [req.tenantId]); res.json(rows); }catch(e){ res.status(500).json({error:e.message}); } });
app.get('/api/slider/all', authPerm('config'), async (req,res)=>{ try{ const {rows}=await pool.query('SELECT * FROM slider_banners WHERE tenant_id=$1 ORDER BY orden', [req.tenantId]); res.json(rows); }catch(e){ res.status(500).json({error:e.message}); } });
app.post('/api/slider', authPerm('config'), sanearLinks(['url_destino']), async (req,res)=>{ try{ const {titulo,subtitulo,etiqueta,imagen,imagen_mobile,url_destino,orden,activo}=req.body; const {rows}=await pool.query('INSERT INTO slider_banners (titulo,subtitulo,etiqueta,imagen,url_destino,orden,activo,tenant_id,imagen_mobile) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9) RETURNING *', [titulo||'',subtitulo||'',etiqueta||'',imagen||'',url_destino||'',orden||0,activo!==false, req.tenantId, imagen_mobile||'']); res.json(rows[0]); }catch(e){ res.status(500).json({error:e.message}); } });
app.put('/api/slider/:id', authPerm('config'), sanearLinks(['url_destino']), async (req,res)=>{ try{ const {titulo,subtitulo,etiqueta,imagen,imagen_mobile,url_destino,orden,activo}=req.body; await pool.query('UPDATE slider_banners SET titulo=$1,subtitulo=$2,etiqueta=$3,imagen=$4,url_destino=$5,orden=$6,activo=$7,imagen_mobile=$10 WHERE id=$8 AND tenant_id=$9', [titulo,subtitulo||'',etiqueta||'',imagen,url_destino,orden,activo,req.params.id, req.tenantId, imagen_mobile||'']); res.json({ok:true}); }catch(e){ res.status(500).json({error:e.message}); } });
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
app.get('/api/leads', authPerm('stats'), requiereFeature('marketing'), async (req,res)=>{ try{ const {rows}=await pool.query('SELECT * FROM leads WHERE tenant_id=$1 ORDER BY created_at DESC LIMIT 500', [req.tenantId]); res.json(rows); }catch(e){ res.status(500).json({error:e.message}); } });
app.put('/api/leads/:id', authPerm('stats'), requiereFeature('marketing'), async (req,res)=>{ try{ await pool.query('UPDATE leads SET contactado=$1 WHERE id=$2 AND tenant_id=$3', [req.body.contactado!==false, req.params.id, req.tenantId]); res.json({ok:true}); }catch(e){ res.status(500).json({error:e.message}); } });
app.delete('/api/leads/:id', authPerm('stats'), requiereFeature('marketing'), async (req,res)=>{ try{ await pool.query('DELETE FROM leads WHERE id=$1 AND tenant_id=$2', [req.params.id, req.tenantId]); res.json({ok:true}); }catch(e){ res.status(500).json({error:e.message}); } });

app.get('/api/favoritos', auth(), async (req,res)=>{ try{ const {rows}=await pool.query(`SELECT f.*, p.nombre, p.modelo, p.marca, p.imagen, p.precio_base, p.precio_oferta, p.moneda, p.stock, p.categoria, p.seccion_id, p.usa_variantes, p.envio_gratis, p.permitir_sin_stock, p.es_digital, p.es_preventa, p.preventa_descuento_pct, p.preventa_fecha, p.preventa_mostrar_fecha, p.preventa_cupo, p.preventa_reservado, p.visible, p.created_at AS creado, ${IMG2('p')} FROM favoritos f JOIN productos p ON f.producto_id=p.id AND p.tenant_id=f.tenant_id WHERE f.usuario_id=$1 AND f.tenant_id=$2 ORDER BY f.created_at DESC`, [req.user.id, req.tenantId]); res.json(rows); }catch(e){ res.status(500).json({error:e.message}); } });
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
// GET /api/sitemap → sitemap.xml dinámico (home + todos los productos visibles). El rewrite de Vercel /sitemap.xml apunta acá.
app.get('/api/sitemap', async (req,res)=>{
  try{
    const t = req.tenantId || 1;
    const { rows:tr } = await pool.query('SELECT dominio_propio FROM tenants WHERE id=$1',[t]).catch(()=>({rows:[]}));
    let dom = ((tr[0] && tr[0].dominio_propio) || '').trim().replace(/^https?:\/\//,'').replace(/\/+$/,'');
    const base = 'https://' + (dom || 'lean-droidgremio.com');
    const slugify = (x)=> String(x||'').toLowerCase().normalize('NFD').replace(/[\u0300-\u036f]/g,'').replace(/[^a-z0-9]+/g,'-').replace(/(^-|-$)/g,'') || 'producto';
    const esc = (u)=> String(u).replace(/&/g,'&amp;').replace(/</g,'&lt;');
    const { rows } = await pool.query("SELECT id, nombre, modelo, created_at FROM productos WHERE tenant_id=$1 AND visible=true ORDER BY id DESC LIMIT 5000",[t]);
    let xml='<?xml version="1.0" encoding="UTF-8"?>\n<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n';
    xml+=`<url><loc>${base}/</loc><changefreq>daily</changefreq><priority>1.0</priority></url>\n`;
    for(const p of rows){
      const loc = `${base}/producto/${slugify(p.nombre||p.modelo)}-${p.id}`;
      let lm=''; try{ if(p.created_at) lm=new Date(p.created_at).toISOString().slice(0,10); }catch(_){}
      xml+=`<url><loc>${esc(loc)}</loc>${lm?`<lastmod>${lm}</lastmod>`:''}<changefreq>weekly</changefreq><priority>0.8</priority></url>\n`;
    }
    xml+='</urlset>';
    res.set('Content-Type','application/xml; charset=utf-8');
    res.set('Cache-Control','public, max-age=3600');
    res.send(xml);
  }catch(e){ res.status(500).set('Content-Type','application/xml').send('<?xml version="1.0"?><error>'+String(e.message)+'</error>'); }
});

app.post('/api/carritos-abandonados', optionalAuth, rateLimit({ windowMs: 60*1000, max: 20, standardHeaders: true, legacyHeaders: false }), async (req,res)=>{
  try{
    const {email,telefono,total,seccion_id}=req.body;
    // El usuario sale del token (antes se podía mandar el id de otro cliente y pisarle el carrito)
    const usuario_id = req.user ? req.user.id : null;
    const items = Array.isArray(req.body.items) ? req.body.items.slice(0,100) : [];
    const its=JSON.stringify(items);
    if(its.length > 50000) return res.status(413).json({error:'Carrito demasiado grande'});
    // Upsert: si el mismo cliente ya tiene un carrito activo, ACTUALIZARLO (no crear otro) → evita el spam.
    let existing=null;
    if(usuario_id){
      const r=await pool.query('SELECT id FROM carritos_abandonados WHERE tenant_id=$1 AND recuperado=false AND usuario_id=$2 ORDER BY created_at DESC LIMIT 1',[req.tenantId,usuario_id]);
      existing=r.rows[0];
    } else if((telefono&&String(telefono).trim())||(email&&String(email).trim())){
      const r=await pool.query("SELECT id FROM carritos_abandonados WHERE tenant_id=$1 AND recuperado=false AND usuario_id IS NULL AND ((NULLIF($2,'') IS NOT NULL AND telefono=$2) OR (NULLIF($3,'') IS NOT NULL AND email=$3)) ORDER BY created_at DESC LIMIT 1",[req.tenantId,telefono||'',email||'']);
      existing=r.rows[0];
    }
    if(existing){
      const {rows}=await pool.query('UPDATE carritos_abandonados SET items=$1,total=$2,seccion_id=$3,email=$4,telefono=$5,created_at=NOW() WHERE id=$6 AND tenant_id=$7 RETURNING *',[its,total||0,seccion_id||null,email||'',telefono||'',existing.id,req.tenantId]);
      return res.json(rows[0]);
    }
    const {rows}=await pool.query('INSERT INTO carritos_abandonados (usuario_id,email,telefono,items,total,seccion_id,tenant_id) VALUES ($1,$2,$3,$4,$5,$6,$7) RETURNING *', [usuario_id||null,email||'',telefono||'',its,total||0,seccion_id||null, req.tenantId]);
    res.json(rows[0]);
  }catch(e){ res.status(500).json({error:e.message}); }
});
app.get('/api/carritos-abandonados', authPerm('stats'), requiereFeature('marketing'), async (req,res)=>{ try{ const {rows}=await pool.query("SELECT c.*, u.nombre as usuario_nombre, COALESCE(NULLIF(c.telefono,''), u.telefono) as telefono, COALESCE(NULLIF(c.email,''), u.email) as email, s.nombre as seccion_nombre FROM carritos_abandonados c LEFT JOIN usuarios u ON c.usuario_id=u.id LEFT JOIN secciones s ON c.seccion_id=s.id WHERE c.recuperado=false AND c.tenant_id=$1 ORDER BY c.created_at DESC LIMIT 100", [req.tenantId]); res.json(rows); }catch(e){ res.status(500).json({error:e.message}); } });
app.post('/api/carritos-abandonados/:id/recuperar', authPerm('stats'), requiereFeature('marketing'), async (req,res)=>{ try{ await pool.query('UPDATE carritos_abandonados SET recuperado=true WHERE id=$1 AND tenant_id=$2', [req.params.id, req.tenantId]); res.json({ok:true}); }catch(e){ res.status(500).json({error:e.message}); } });
app.delete('/api/carritos-abandonados/:id', authPerm('stats'), requiereFeature('marketing'), async (req,res)=>{ try{ await pool.query('DELETE FROM carritos_abandonados WHERE id=$1 AND tenant_id=$2', [req.params.id, req.tenantId]); res.json({ok:true}); }catch(e){ res.status(500).json({error:e.message}); } });

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
      const {rows}=await pool.query('SELECT cp_origen FROM secciones WHERE id=$1 AND tenant_id=$2', [seccion_id, req.tenantId]).catch(()=>({rows:[]}));
      if(rows[0]?.cp_origen) origen=rows[0].cp_origen;
      const {rows:cfg}=await pool.query('SELECT cp_origen FROM config_envio WHERE seccion_id=$1 AND tenant_id=$2', [seccion_id, req.tenantId]).catch(()=>({rows:[]}));
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
app.get('/api/andreani/sucursales', async (req,res)=>{ try{ const {cp}=req.query; const token=await andreaniLogin(); if(!token) return res.status(503).json({error:'Andreani no configurado'}); const r=await fetch(`${ANDREANI_API}/v1/sucursales?codigoPostal=${encodeURIComponent(String(cp||'').replace(/\D/g,'').slice(0,8))}`, {headers:{'x-authorization-token':token}}); res.json(await r.json()); }catch(e){ res.status(500).json({error:e.message}); } });
app.post('/api/andreani/orden', authPerm('pedidos'), async (req,res)=>{ try{ if(Number(req.tenantId)!==1) return res.status(403).json({error:'Andreani todavía no está disponible para esta tienda'}); const token=await andreaniLogin(); if(!token) return res.status(503).json({error:'Andreani no configurado'}); const r=await fetch(`${ANDREANI_API}/v1/ordenes-de-envio`, {method:'POST', headers:{'x-authorization-token':token, 'Content-Type':'application/json'}, body:JSON.stringify(req.body)}); res.json(await r.json()); }catch(e){ res.status(500).json({error:e.message}); } });
app.get('/api/andreani/tracking/:envio', auth(), async (req,res)=>{ try{ if(Number(req.tenantId)!==1) return res.status(403).json({error:'Andreani todavía no está disponible para esta tienda'}); const token=await andreaniLogin(); if(!token) return res.status(503).json({error:'Andreani no configurado'}); const r=await fetch(`${ANDREANI_API}/v1/envios/${encodeURIComponent(req.params.envio)}/trazas`, {headers:{'x-authorization-token':token}}); res.json(await r.json()); }catch(e){ res.status(500).json({error:e.message}); } });
app.get('/api/andreani/etiqueta/:envio', authPerm('pedidos'), async (req,res)=>{ try{ if(Number(req.tenantId)!==1) return res.status(403).json({error:'Andreani todavía no está disponible para esta tienda'}); const token=await andreaniLogin(); if(!token) return res.status(503).json({error:'Andreani no configurado'}); const r=await fetch(`${ANDREANI_API}/v1/ordenes-de-envio/${encodeURIComponent(req.params.envio)}/etiquetas`, {headers:{'x-authorization-token':token, Accept:'application/pdf'}}); res.set('Content-Type','application/pdf'); const buffer=await r.arrayBuffer(); res.send(Buffer.from(buffer)); }catch(e){ res.status(500).json({error:e.message}); } });

// START
const PORT=process.env.PORT||3000;
migrate().then(()=>{ app.listen(PORT, ()=>console.log(`🚀 V4 running on ${PORT}`)); tareasSeo().catch(e=>console.log('tareas SEO warn', e.message)); }).catch(e=>{ console.error('Migration failed', e); process.exit(1); });
