
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

// CORS - V4 FIX: soporta * y *.vercel.app y no bloquea preflight
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
    console.log('CORS blocked:', origin, 'allowed:', ALLOWED_ORIGINS);
    // no bloqueamos con error, devolvemos false para que no tire 500
    return cb(null, false);
  },
  credentials: true,
  methods: ['GET','POST','PUT','DELETE','PATCH','OPTIONS'],
  allowedHeaders: ['Content-Type','Authorization']
}));

app.use(express.json({ limit: '10mb' }));

const rateLimit = require('express-rate-limit');
app.use('/api/auth', rateLimit({ windowMs: 15 * 60 * 1000, max: 30 }));
app.use('/api/', rateLimit({ windowMs: 1 * 60 * 1000, max: 300 }));
app.set('trust proxy', 1);

const pool = new Pool({ connectionString: process.env.DATABASE_URL, ssl: { rejectUnauthorized: false } });
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
      const {rows} = await pool.query('SELECT rol, activo FROM usuarios WHERE id=$1', [d.id]).catch(()=>({rows:[]}));
      if(!rows[0] || !rows[0].activo) return res.status(401).json({error:'Cuenta desactivada'});
      if(role==='admin' && rows[0].rol!=='admin') return res.status(403).json({error:'Sin permiso'});
    }
    req.user=d; req._token=t; next();
  }catch{ res.status(401).json({error:'Token inválido'}); }
};
const optionalAuth = (req,res,next)=>{ try{ const t=req.headers.authorization?.split(' ')[1]; if(t) req.user=jwt.verify(t,JWT_SECRET);}catch{} next(); };

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
    `CREATE TABLE IF NOT EXISTS favoritos (id SERIAL PRIMARY KEY, usuario_id INT REFERENCES usuarios(id) ON DELETE CASCADE, producto_id INT REFERENCES productos(id) ON DELETE CASCADE, created_at TIMESTAMP DEFAULT NOW(), UNIQUE(usuario_id, producto_id))`,
    `CREATE TABLE IF NOT EXISTS notificaciones_stock (id SERIAL PRIMARY KEY, producto_id INT REFERENCES productos(id) ON DELETE CASCADE, email VARCHAR(200), notificado BOOLEAN DEFAULT false, created_at TIMESTAMP DEFAULT NOW())`,
    `CREATE TABLE IF NOT EXISTS tokens_revocados (token_hash VARCHAR(100) PRIMARY KEY, expira TIMESTAMP DEFAULT NOW())`,
    `CREATE TABLE IF NOT EXISTS otp_codes (id SERIAL PRIMARY KEY, usuario_id INT REFERENCES usuarios(id), codigo VARCHAR(10), expira TIMESTAMP, usado BOOLEAN DEFAULT false)`,
    `CREATE TABLE IF NOT EXISTS metodos_envio_custom (id SERIAL PRIMARY KEY, seccion_id INT, nombre VARCHAR(200), descripcion TEXT DEFAULT '', precio NUMERIC(12,2) DEFAULT 0, tipo VARCHAR(30) DEFAULT 'fijo', activo BOOLEAN DEFAULT true, gratis_desde NUMERIC(12,2) DEFAULT 0, tiempo_estimado VARCHAR(100) DEFAULT '', icono VARCHAR(50) DEFAULT '🚚', orden INT DEFAULT 0, created_at TIMESTAMP DEFAULT NOW())`,
    `CREATE TABLE IF NOT EXISTS carritos_abandonados (id SERIAL PRIMARY KEY, usuario_id INT, email VARCHAR(200) DEFAULT '', telefono VARCHAR(50) DEFAULT '', items JSONB DEFAULT '[]', total NUMERIC(12,2) DEFAULT 0, seccion_id INT, created_at TIMESTAMP DEFAULT NOW(), recuperado BOOLEAN DEFAULT false)`,
  ];
  for(const q of queries) await pool.query(q).catch(e=>console.log('migrate warn', e.message.slice(0,100)));
  // Alter columns if not exists
  const alters = [
    `ALTER TABLE secciones ADD COLUMN IF NOT EXISTS ignorar_stock BOOLEAN DEFAULT false`,
    `ALTER TABLE secciones ADD COLUMN IF NOT EXISTS cp_origen VARCHAR(20) DEFAULT '1888'`,
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
  // Design defaults
  const defs = {nombre_tienda:'Mi Tienda',logo_url:'',favicon_url:'',color_primario:'#4A69E2',color_secundario:'#232321',color_acento:'#FFA52F',fuente:'Archivo',footer_texto:'',css_custom:'',hero_titulo:'',hero_subtitulo:'',promo_banner:'',whatsapp_numero:'',whatsapp_mensaje:'Hola, quiero consultar sobre un producto',confianza_1_icono:'truck',confianza_1_titulo:'Envío a todo el país',confianza_1_sub:'Andreani y más',confianza_2_icono:'shield',confianza_2_titulo:'Compra segura',confianza_2_sub:'Garantía incluida',confianza_3_icono:'message-circle',confianza_3_titulo:'Atención directa',confianza_3_sub:'WhatsApp'};
  for(const [k,v] of Object.entries(defs)){ await pool.query("INSERT INTO design_config (clave,valor) VALUES ($1,$2) ON CONFLICT (clave) DO NOTHING", [k,v]).catch(()=>{}); }
  // FIX #5: seed admin si no existe ninguno
  try{
    const {rows:admins}=await pool.query("SELECT id FROM usuarios WHERE rol='admin' LIMIT 1");
    if(!admins.length){
      const adminPass=process.env.ADMIN_PASSWORD||'Admin1234';
      const hash=await bcrypt.hash(adminPass,12);
      await pool.query("INSERT INTO usuarios (nombre,usuario,password,rol,aprobado,activo) VALUES ('Administrador','admin',$1,'admin',true,true) ON CONFLICT (usuario) DO NOTHING", [hash]);
      console.log('✅ Admin creado -> usuario: admin  password: '+adminPass+'  (cambialo en Mi Cuenta)');
    }
  }catch(e){ console.log('seed admin warn', e.message); }
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
  try{ const {rows}=await pool.query("SELECT clave,valor FROM configuracion WHERE clave IN ('mantenimiento_activo','mantenimiento_mensaje','mantenimiento_countdown')"); const cfg={}; rows.forEach(r=>cfg[r.clave]=r.valor); res.json({activo:cfg.mantenimiento_activo==='true', mensaje:cfg.mantenimiento_mensaje||'', countdown:cfg.mantenimiento_countdown||''}); }catch{ res.json({activo:false}); }
});
app.post('/api/maintenance-mode', auth('admin'), async (req,res)=>{
  try{ const {activo,mensaje,countdown}=req.body; await pool.query("INSERT INTO configuracion (clave,valor) VALUES ('mantenimiento_activo',$1) ON CONFLICT (clave) DO UPDATE SET valor=$1", [activo?'true':'false']); await pool.query("INSERT INTO configuracion (clave,valor) VALUES ('mantenimiento_mensaje',$1) ON CONFLICT (clave) DO UPDATE SET valor=$1", [mensaje||'']); await pool.query("INSERT INTO configuracion (clave,valor) VALUES ('mantenimiento_countdown',$1) ON CONFLICT (clave) DO UPDATE SET valor=$1", [countdown||'']); res.json({ok:true}); }catch(e){ res.status(500).json({error:e.message}); }
});

// === AUTH ===
let resend=null;
if(process.env.RESEND_API_KEY){ const {Resend}=require('resend'); resend=new Resend(process.env.RESEND_API_KEY); console.log('📧 Resend OK'); }
const loginAttempts={};
app.post('/api/login', async (req,res)=>{
  try{
    const {usuario,password,otp_code}=req.body;
    if(!usuario||!password) return res.status(400).json({error:'Usuario y contraseña requeridos'});
    const ip=req.ip; const key=`${ip}_${usuario.toLowerCase()}`;
    if(loginAttempts[key] && loginAttempts[key].count>=5 && Date.now()-loginAttempts[key].last<15*60*1000) return res.status(429).json({error:'Bloqueado 15min'});
    const {rows}=await pool.query('SELECT * FROM usuarios WHERE LOWER(usuario)=LOWER($1) AND activo=true', [usuario]);
    if(!rows[0]){ const {rows:pend}=await pool.query('SELECT * FROM usuarios WHERE LOWER(usuario)=LOWER($1) AND aprobado=false', [usuario]); if(pend[0]) return res.status(403).json({error:'Pendiente aprobación'}); loginAttempts[key]={count:(loginAttempts[key]?.count||0)+1, last:Date.now()}; return res.status(401).json({error:'Usuario o contraseña incorrectos'}); }
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
    const token=jwt.sign({id:rows[0].id, rol:rows[0].rol, usuario:rows[0].usuario}, JWT_SECRET, {expiresIn:'7d'});
    res.json({token, user:{...rows[0], password:undefined}});
  }catch(e){ res.status(500).json({error:e.message}); }
});
app.post('/api/logout', auth(), async (req,res)=>{
  try{ const decoded=jwt.decode(req._token); const expira=new Date(decoded.exp*1000); await pool.query('INSERT INTO tokens_revocados (token_hash,expira) VALUES ($1,$2) ON CONFLICT DO NOTHING', [hashToken(req._token), expira]); await pool.query('DELETE FROM tokens_revocados WHERE expira<NOW()').catch(()=>{}); res.json({ok:true}); }catch(e){ res.status(500).json({error:e.message}); }
});
app.post('/api/refresh-token', auth(), async (req,res)=>{
  try{ const {rows}=await pool.query('SELECT id,rol,usuario,activo FROM usuarios WHERE id=$1', [req.user.id]); if(!rows[0]||!rows[0].activo) return res.status(401).json({error:'Cuenta desactivada'}); const decoded=jwt.decode(req._token); await pool.query('INSERT INTO tokens_revocados (token_hash,expira) VALUES ($1,$2) ON CONFLICT DO NOTHING', [hashToken(req._token), new Date(decoded.exp*1000)]); const newToken=jwt.sign({id:rows[0].id, rol:rows[0].rol, usuario:rows[0].usuario}, JWT_SECRET, {expiresIn:'7d'}); res.json({token:newToken}); }catch(e){ res.status(500).json({error:e.message}); }
});
app.put('/api/me/otp', auth(), async (req,res)=>{ try{ const {activo}=req.body; await pool.query('UPDATE usuarios SET otp_activo=$1 WHERE id=$2', [activo, req.user.id]); res.json({ok:true}); }catch(e){ res.status(500).json({error:e.message}); } });

// Password reset mejorado
app.post('/api/forgot-password', async (req,res)=>{
  try{
    const {usuario, email} = req.body;
    if(!usuario && !email) return res.status(400).json({error:'Usuario o email requerido'});
    const {rows} = await pool.query('SELECT * FROM usuarios WHERE LOWER(usuario)=LOWER($1) OR LOWER(email)=LOWER($1) LIMIT 1', [usuario||email]);
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
    const {rows}=await pool.query('SELECT * FROM usuarios WHERE reset_codigo=$1 AND reset_expira>NOW()', [codigo]);
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
    const {rows}=await pool.query('INSERT INTO usuarios (nombre,usuario,password,telefono,email,direccion,nombre_fantasia,aprobado,activo) VALUES ($1,$2,$3,$4,$5,$6,$7,false,false) RETURNING *', [nombre,usuario,hash,telefono||'',email||'',direccion||'',nombre_fantasia||'']);
    res.json(rows[0]);
  }catch(e){ res.status(400).json({error:e.message.includes('duplicate')?'Usuario ya existe':e.message}); }
});
app.get('/api/me', auth(), async (req,res)=>{ try{ const {rows}=await pool.query('SELECT * FROM usuarios WHERE id=$1', [req.user.id]); res.json({...rows[0], password:undefined}); }catch(e){ res.status(500).json({error:e.message}); } });
app.put('/api/me', auth(), async (req,res)=>{
  try{
    const {nombre,telefono,email,direccion,nombre_fantasia,password}=req.body;
    if(password){ const hash=await bcrypt.hash(password,10); await pool.query('UPDATE usuarios SET nombre=$1,telefono=$2,email=$3,direccion=$4,nombre_fantasia=$5,password=$6 WHERE id=$7', [nombre,telefono,email,direccion,nombre_fantasia||'',hash,req.user.id]); }
    else{ await pool.query('UPDATE usuarios SET nombre=$1,telefono=$2,email=$3,direccion=$4,nombre_fantasia=$5 WHERE id=$6', [nombre,telefono,email,direccion,nombre_fantasia||'',req.user.id]); }
    const {rows}=await pool.query('SELECT * FROM usuarios WHERE id=$1', [req.user.id]);
    res.json({...rows[0], password:undefined});
  }catch(e){ res.status(500).json({error:e.message}); }
});

// CONFIG
app.get('/api/config', async (req,res)=>{ try{ const {rows}=await pool.query('SELECT * FROM configuracion'); const cfg={}; rows.forEach(r=>cfg[r.clave]=r.valor); res.json(cfg); }catch(e){ res.status(500).json({error:e.message}); } });
app.put('/api/config', auth('admin'), async (req,res)=>{ try{ for(const [k,v] of Object.entries(req.body)){ await pool.query("INSERT INTO configuracion (clave,valor) VALUES ($1,$2) ON CONFLICT (clave) DO UPDATE SET valor=$2", [k,v]); } res.json({ok:true}); }catch(e){ res.status(500).json({error:e.message}); } });

// LISTAS
app.get('/api/listas', async (req,res)=>{ try{ const {rows}=await pool.query('SELECT * FROM listas_precio ORDER BY multiplicador'); res.json(rows); }catch(e){ res.status(500).json({error:e.message}); } });
app.put('/api/listas', auth('admin'), async (req,res)=>{ try{ const {listas}=req.body; for(const l of listas){ await pool.query('INSERT INTO listas_precio (id,nombre,multiplicador,modo,color,compra_minima,promo_msg) VALUES ($1,$2,$3,$4,$5,$6,$7) ON CONFLICT (id) DO UPDATE SET nombre=$2,multiplicador=$3,modo=$4,color=$5,compra_minima=$6,promo_msg=$7', [l.id,l.nombre,l.multiplicador,l.modo||'porcentaje',l.color||'#2563eb',l.compra_minima||0,l.promo_msg||'']); } res.json({ok:true}); }catch(e){ res.status(500).json({error:e.message}); } });
app.post('/api/listas', auth('admin'), async (req,res)=>{ try{ const l=req.body; const {rows}=await pool.query('INSERT INTO listas_precio (id,nombre,multiplicador,modo,color,compra_minima,promo_msg) VALUES ($1,$2,$3,$4,$5,$6,$7) RETURNING *', [l.id,l.nombre,l.multiplicador||1,l.modo||'porcentaje',l.color||'#2563eb',l.compra_minima||0,l.promo_msg||'']); res.json(rows[0]); }catch(e){ res.status(400).json({error:e.message}); } });
app.put('/api/listas/:id', auth('admin'), async (req,res)=>{ try{ const l=req.body; await pool.query('UPDATE listas_precio SET nombre=$1,multiplicador=$2,modo=$3,color=$4,compra_minima=$5,promo_msg=$6 WHERE id=$7', [l.nombre,l.multiplicador,l.modo,l.color,l.compra_minima||0,l.promo_msg||'',req.params.id]); res.json({ok:true}); }catch(e){ res.status(500).json({error:e.message}); } });
app.delete('/api/listas/:id', auth('admin'), async (req,res)=>{ try{ await pool.query('DELETE FROM listas_precio WHERE id=$1', [req.params.id]); res.json({ok:true}); }catch(e){ res.status(500).json({error:e.message}); } });

// SECCIONES V4 con ignorar_stock
app.get('/api/secciones', async (req,res)=>{ try{ const {rows}=await pool.query('SELECT * FROM secciones ORDER BY orden, id'); res.json(rows); }catch(e){ res.status(500).json({error:e.message}); } });
app.get('/api/secciones/:id', async (req,res)=>{ try{ const {rows}=await pool.query('SELECT * FROM secciones WHERE id=$1', [req.params.id]); if(!rows[0]) return res.status(404).json({error:'No encontrada'}); res.json(rows[0]); }catch(e){ res.status(500).json({error:e.message}); } });
app.put('/api/secciones/:id', auth('admin'), async (req,res)=>{
  try{
    const {nombre,slug,descripcion,imagen,requiere_aprobacion,visible,orden,ignorar_stock,cp_origen,permitir_sin_stock}=req.body;
    await pool.query('UPDATE secciones SET nombre=$1,slug=$2,descripcion=$3,imagen=$4,requiere_aprobacion=$5,visible=$6,orden=$7,ignorar_stock=$8,cp_origen=$9,permitir_sin_stock=$10 WHERE id=$11', [nombre,slug,descripcion,imagen,requiere_aprobacion,visible,orden||0,ignorar_stock||false,cp_origen||'1888',permitir_sin_stock||false,req.params.id]);
    res.json({ok:true});
  }catch(e){ res.status(500).json({error:e.message}); }
});
app.post('/api/secciones', auth('admin'), async (req,res)=>{
  try{
    const {nombre,slug,descripcion,imagen,requiere_aprobacion,ignorar_stock,cp_origen}=req.body;
    const {rows}=await pool.query('INSERT INTO secciones (nombre,slug,descripcion,imagen,requiere_aprobacion,ignorar_stock,cp_origen) VALUES ($1,$2,$3,$4,$5,$6,$7) RETURNING *', [nombre,slug,descripcion||'',imagen||'',requiere_aprobacion||false,ignorar_stock||false,cp_origen||'1888']);
    res.json(rows[0]);
  }catch(e){ res.status(400).json({error:e.message}); }
});
app.delete('/api/secciones/:id', auth('admin'), async (req,res)=>{ try{ await pool.query('DELETE FROM secciones WHERE id=$1', [req.params.id]); res.json({ok:true}); }catch(e){ res.status(500).json({error:e.message}); } });

// UPLOAD
const uploadToCloudinary = (buffer, folder='productos')=> new Promise((resolve,reject)=>{
  const stream=cloudinary.uploader.upload_stream({folder, resource_type:'image', quality:'auto', fetch_format:'auto'}, (err,result)=>{ if(err) reject(err); else resolve(result); });
  stream.end(buffer);
});
app.post('/api/upload', auth('admin'), upload.single('imagen'), async (req,res)=>{
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
app.post('/api/upload-base64', auth('admin'), async (req,res)=>{
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
app.get('/api/productos', optionalAuth, async (req,res)=>{
  try{
    const {q,categoria,page=1,limit=50,seccion_id,marca}=req.query;
    let where=['visible=true']; const params=[]; let pi=1;
    if(q){ where.push(`(nombre ILIKE $${pi} OR modelo ILIKE $${pi} OR categoria ILIKE $${pi} OR sku ILIKE $${pi} OR descripcion ILIKE $${pi})`); params.push(`%${q}%`); pi++; }
    if(categoria){ where.push(`categoria=$${pi}`); params.push(categoria); pi++; }
    if(seccion_id){ where.push(`seccion_id=$${pi}`); params.push(seccion_id); pi++; }
    if(marca){ where.push(`modelo ILIKE $${pi}`); params.push(`%${marca}%`); pi++; }
    const offset=(parseInt(page)-1)*parseInt(limit);
    const countQ=`SELECT COUNT(*) FROM productos WHERE ${where.join(' AND ')}`;
    const {rows:cRows}=await pool.query(countQ, params);
    const total=parseInt(cRows[0].count);
    const query=`SELECT * FROM productos WHERE ${where.join(' AND ')} ORDER BY created_at DESC LIMIT $${pi} OFFSET $${pi+1}`;
    const {rows}=await pool.query(query, [...params, parseInt(limit), offset]);
    // hide price mayorista sin login
    let result=rows;
    if(!req.user){
      const {rows:secs}=await pool.query('SELECT id FROM secciones WHERE slug=$1', ['mayorista']).catch(()=>({rows:[]}));
      const mayId=secs[0]?.id;
      if(mayId) result=rows.map(r=> r.seccion_id==mayId ? {...r, precio_base:0, precio_oferta:0} : r);
    }
    res.json({productos:result, total, page:parseInt(page), totalPages:Math.ceil(total/parseInt(limit))});
  }catch(e){ res.status(500).json({error:e.message}); }
});
app.get('/api/categorias', async (req,res)=>{ try{ const {seccion_id}=req.query; let q='SELECT DISTINCT categoria FROM productos WHERE visible=true'; const params=[]; if(seccion_id){ q+=' AND seccion_id=$1'; params.push(seccion_id); } q+=' ORDER BY categoria'; const {rows}=await pool.query(q, params); res.json(rows.map(r=>r.categoria).filter(Boolean)); }catch(e){ res.status(500).json({error:e.message}); } });
app.post('/api/productos', auth('admin'), async (req,res)=>{
  try{
    const p=req.body;
    const {rows}=await pool.query(`INSERT INTO productos (seccion_id,categoria,modelo,nombre,precio_base,precio_original,stock,stock_minimo,imagen,notas,compatibilidad,descripcion,sku,tipo,moneda,precio_oferta,envio_gratis,visible,peso,alto,ancho,largo,permitir_sin_stock,es_digital) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,$23,$24) RETURNING *`,
      [p.seccion_id, p.categoria||'', p.modelo||'', p.nombre||'', p.precio_base||0, p.precio_original||0, p.stock||0, p.stock_minimo||0, p.imagen||'', p.notas||'', p.compatibilidad||'', p.descripcion||'', p.sku||'', p.tipo||'fisico', p.moneda||'ARS', p.precio_oferta||0, p.envio_gratis||false, p.visible!==false, p.peso||0, p.alto||0, p.ancho||0, p.largo||0, p.permitir_sin_stock||false, p.es_digital||false]);
    res.json(rows[0]);
  }catch(e){ res.status(500).json({error:e.message}); }
});
app.put('/api/productos/:id', auth('admin'), async (req,res)=>{
  try{
    const p=req.body;
    const fields=['seccion_id','categoria','modelo','nombre','precio_base','precio_original','stock','stock_minimo','imagen','notas','compatibilidad','descripcion','sku','tipo','moneda','precio_oferta','envio_gratis','visible','peso','alto','ancho','largo','permitir_sin_stock','es_digital'];
    const sets=[]; const params=[]; let pi=1;
    for(const f of fields){ if(p[f]!==undefined){ sets.push(`${f}=$${pi++}`); params.push(p[f]); } }
    if(!sets.length) return res.json({ok:true});
    // historial precios si cambia precio_base
    if(p.precio_base!==undefined){
      const {rows:old}=await pool.query('SELECT precio_base FROM productos WHERE id=$1', [req.params.id]);
      if(old[0] && old[0].precio_base!=p.precio_base){
        await pool.query('INSERT INTO historial_precios (producto_id,precio_anterior,precio_nuevo,usuario) VALUES ($1,$2,$3,$4)', [req.params.id, old[0].precio_base, p.precio_base, req.user.usuario]);
      }
    }
    params.push(req.params.id);
    await pool.query(`UPDATE productos SET ${sets.join(',')} WHERE id=$${pi}`, params);
    res.json({ok:true});
  }catch(e){ res.status(500).json({error:e.message}); }
});
app.delete('/api/productos/:id', auth('admin'), async (req,res)=>{ try{ await pool.query('DELETE FROM productos WHERE id=$1', [req.params.id]); res.json({ok:true}); }catch(e){ res.status(500).json({error:e.message}); } });
app.post('/api/productos/bulk', auth('admin'), async (req,res)=>{
  try{
    const {productos, reemplazar} = req.body;
    if(reemplazar){ await pool.query('DELETE FROM producto_imagenes'); await pool.query('DELETE FROM pedido_items'); await pool.query('DELETE FROM productos'); }
    for(const p of (productos||[])){
      await pool.query(`INSERT INTO productos (seccion_id,categoria,modelo,nombre,precio_base,stock,imagen,sku,descripcion,compatibilidad,peso,alto,ancho,largo,visible,permitir_sin_stock,es_digital) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17) ON CONFLICT DO NOTHING`, [p.seccion_id||1, p.categoria||'', p.modelo||'', p.nombre||p.modelo||'', p.precio_base||0, p.stock||0, p.imagen||'', p.sku||'', p.descripcion||'', p.compatibilidad||'', p.peso||0, p.alto||0, p.ancho||0, p.largo||0, true, p.permitir_sin_stock||false, p.es_digital||false]);
    }
    res.json({ok:true, count: productos.length, insertados: productos.length});
  }catch(e){ res.status(500).json({error:e.message}); }
});
app.delete('/api/categorias/:categoria', auth('admin'), async (req,res)=>{ try{ await pool.query('DELETE FROM productos WHERE categoria=$1', [req.params.categoria]); res.json({ok:true}); }catch(e){ res.status(500).json({error:e.message}); } });
app.delete('/api/productos/all', auth('admin'), async (req,res)=>{ try{ await pool.query('DELETE FROM productos'); res.json({ok:true}); }catch(e){ res.status(500).json({error:e.message}); } });
app.get('/api/productos/buscar', async (req,res)=>{ try{ const {q}=req.query; if(!q) return res.json([]); const {rows}=await pool.query("SELECT id,nombre,modelo,categoria,precio_base,stock,imagen FROM productos WHERE nombre ILIKE $1 OR modelo ILIKE $1 OR categoria ILIKE $1 OR sku ILIKE $1 ORDER BY nombre LIMIT 20", [`%${q}%`]); res.json(rows); }catch(e){ res.status(500).json({error:e.message}); } });

// IMAGENES y VARIANTES (igual que antes)
app.get('/api/producto-imagenes/:producto_id', async (req,res)=>{ try{ const {rows}=await pool.query('SELECT * FROM producto_imagenes WHERE producto_id=$1 ORDER BY orden', [req.params.producto_id]); res.json(rows); }catch(e){ res.status(500).json({error:e.message}); } });
app.post('/api/producto-imagenes', auth('admin'), async (req,res)=>{ try{ const {producto_id,url,orden}=req.body; const {rows}=await pool.query('INSERT INTO producto_imagenes (producto_id,url,orden) VALUES ($1,$2,$3) RETURNING *', [producto_id,url,orden||0]); res.json(rows[0]); }catch(e){ res.status(500).json({error:e.message}); } });
app.delete('/api/producto-imagenes/:id', auth('admin'), async (req,res)=>{ try{ await pool.query('DELETE FROM producto_imagenes WHERE id=$1', [req.params.id]); res.json({ok:true}); }catch(e){ res.status(500).json({error:e.message}); } });
app.put('/api/producto-imagenes/reorder', auth('admin'), async (req,res)=>{ try{ const {items}=req.body; for(const it of items){ await pool.query('UPDATE producto_imagenes SET orden=$1 WHERE id=$2', [it.orden,it.id]); } res.json({ok:true}); }catch(e){ res.status(500).json({error:e.message}); } });
app.get('/api/variantes/:producto_id', async (req,res)=>{ try{ const {rows}=await pool.query('SELECT * FROM variantes WHERE producto_id=$1 ORDER BY id', [req.params.producto_id]); res.json(rows); }catch(e){ res.status(500).json({error:e.message}); } });
app.post('/api/variantes', auth('admin'), async (req,res)=>{ try{ const {producto_id,nombre,valor,stock,precio_extra}=req.body; const {rows}=await pool.query('INSERT INTO variantes (producto_id,nombre,valor,stock,precio_extra) VALUES ($1,$2,$3,$4,$5) RETURNING *', [producto_id,nombre,valor||'',stock||0,precio_extra||0]); res.json(rows[0]); }catch(e){ res.status(500).json({error:e.message}); } });
app.put('/api/variantes/:id', auth('admin'), async (req,res)=>{ try{ const v=req.body; await pool.query('UPDATE variantes SET nombre=$1,valor=$2,stock=$3,precio_extra=$4 WHERE id=$5', [v.nombre,v.valor,v.stock||0,v.precio_extra||0,req.params.id]); res.json({ok:true}); }catch(e){ res.status(500).json({error:e.message}); } });
app.delete('/api/variantes/:id', auth('admin'), async (req,res)=>{ try{ await pool.query('DELETE FROM variantes WHERE id=$1', [req.params.id]); res.json({ok:true}); }catch(e){ res.status(500).json({error:e.message}); } });

// PRECIOS
app.post('/api/precios/ajustar', auth('admin'), async (req,res)=>{
  try{
    const {porcentaje,categoria}=req.body;
    if(categoria) await pool.query('UPDATE productos SET precio_base = precio_base * (1+$1/100)', [porcentaje]).catch(async()=>{ await pool.query('UPDATE productos SET precio_base = precio_base * $1 WHERE categoria=$2', [1+porcentaje/100, categoria]); });
    else await pool.query('UPDATE productos SET precio_base = precio_base * (1+$1/100)', [porcentaje]);
    res.json({ok:true});
  }catch(e){ res.status(500).json({error:e.message}); }
});
app.post('/api/precios/reset', auth('admin'), async (req,res)=>{ try{ const {rows}=await pool.query('SELECT * FROM historial_precios ORDER BY created_at DESC'); res.json({ok:true}); }catch(e){ res.status(500).json({error:e.message}); } });
app.get('/api/historial-precios', auth('admin'), async (req,res)=>{ try{ const {rows}=await pool.query('SELECT * FROM historial_precios ORDER BY created_at DESC LIMIT 200'); res.json(rows); }catch(e){ res.status(500).json({error:e.message}); } });
app.get('/api/precios-fijos', auth('admin'), async (req,res)=>{ try{ const {rows}=await pool.query('SELECT * FROM precios_fijos'); res.json(rows); }catch(e){ res.status(500).json({error:e.message}); } });
app.post('/api/precios-fijos', auth('admin'), async (req,res)=>{ try{ const {producto_id,lista_precio_id,precio_fijo}=req.body; await pool.query('INSERT INTO precios_fijos (producto_id,lista_precio_id,precio_fijo) VALUES ($1,$2,$3) ON CONFLICT (producto_id,lista_precio_id) DO UPDATE SET precio_fijo=$3', [producto_id,lista_precio_id,precio_fijo]); res.json({ok:true}); }catch(e){ res.status(500).json({error:e.message}); } });

// USUARIOS
app.get('/api/usuarios', auth('admin'), async (req,res)=>{
  try{ const {q}=req.query; let query='SELECT * FROM usuarios ORDER BY created_at DESC'; const params=[]; if(q){ query="SELECT * FROM usuarios WHERE nombre ILIKE $1 OR usuario ILIKE $1 OR nombre_fantasia ILIKE $1 OR email ILIKE $1 OR telefono ILIKE $1 ORDER BY created_at DESC"; params.push(`%${q}%`); } const {rows}=await pool.query(query, params); res.json(rows.map(u=>({...u,password:undefined}))); }catch(e){ res.status(500).json({error:e.message}); }
});
app.get('/api/usuarios/pendientes/count', auth('admin'), async (req,res)=>{ try{ const {rows}=await pool.query("SELECT COUNT(*) FROM usuarios WHERE aprobado=false AND activo=false"); res.json({count:parseInt(rows[0].count)}); }catch{ res.json({count:0}); } });
app.put('/api/usuarios/:id', auth('admin'), async (req,res)=>{
  try{
    const u=req.body; const sets=[]; const params=[]; let pi=1;
    const fields=['nombre','usuario','telefono','email','direccion','nombre_fantasia','rol','lista_precio_id','activo','aprobado','permisos','notas_admin','es_revendedor','descuento_revendedor'];
    for(const f of fields){ if(u[f]!==undefined){ sets.push(`${f}=$${pi++}`); params.push(u[f]); } }
    if(u.password){ const hash=await bcrypt.hash(u.password,10); sets.push(`password=$${pi++}`); params.push(hash); }
    if(!sets.length) return res.json({ok:true});
    params.push(req.params.id);
    await pool.query(`UPDATE usuarios SET ${sets.join(',')} WHERE id=$${pi}`, params);
    res.json({ok:true});
  }catch(e){ res.status(500).json({error:e.message}); }
});
app.post('/api/usuarios/:id/aprobar', auth('admin'), async (req,res)=>{ try{ const {lista_precio_id}=req.body; await pool.query('UPDATE usuarios SET aprobado=true, activo=true, lista_precio_id=$1 WHERE id=$2', [lista_precio_id||'', req.params.id]); const {rows}=await pool.query('SELECT * FROM usuarios WHERE id=$1', [req.params.id]); res.json({ok:true, user:{...rows[0], password:undefined}}); }catch(e){ res.status(500).json({error:e.message}); } });
app.post('/api/usuarios/:id/rechazar', auth('admin'), async (req,res)=>{ try{ await pool.query('UPDATE usuarios SET activo=false WHERE id=$1', [req.params.id]); res.json({ok:true}); }catch(e){ res.status(500).json({error:e.message}); } });
app.post('/api/usuarios/:id/suspender', auth('admin'), async (req,res)=>{ try{ const {activo}=req.body; await pool.query('UPDATE usuarios SET activo=$1 WHERE id=$2', [activo, req.params.id]); res.json({ok:true}); }catch(e){ res.status(500).json({error:e.message}); } });
// RESET MEJORADO - codigo largo
app.post('/api/usuarios/:id/reset-password', auth('admin'), async (req,res)=>{
  try{
    const codigo='KICKS-'+crypto.randomBytes(4).toString('hex').toUpperCase();
    const hash=await bcrypt.hash(codigo,10);
    await pool.query('UPDATE usuarios SET password=$1, reset_codigo=$2, reset_expira=NOW()+INTERVAL \'24 hours\' WHERE id=$3', [hash, codigo, req.params.id]);
    const {rows}=await pool.query('SELECT nombre,telefono,email FROM usuarios WHERE id=$1', [req.params.id]);
    res.json({ok:true, codigo, nombre:rows[0]?.nombre, telefono:rows[0]?.telefono, email:rows[0]?.email});
  }catch(e){ res.status(500).json({error:e.message}); }
});
app.delete('/api/usuarios/:id', auth('admin'), async (req,res)=>{ try{ await pool.query('DELETE FROM pedido_items WHERE pedido_id IN (SELECT id FROM pedidos WHERE usuario_id=$1)', [req.params.id]); await pool.query('DELETE FROM pedidos WHERE usuario_id=$1', [req.params.id]); await pool.query('DELETE FROM usuarios WHERE id=$1', [req.params.id]); res.json({ok:true}); }catch(e){ res.status(500).json({error:e.message}); } });

// PEDIDOS V4 - transaccion + is_test + costo_envio
app.get('/api/pedidos', auth(), async (req,res)=>{
  try{
    const {all,archivado,seccion_id,tipo,is_test}=req.query;
    let where=[]; const params=[];
    if(req.user.rol==='admin'){ if(archivado==='true') where.push('p.archivado=true'); else where.push('p.archivado=false'); if(is_test==='false') where.push('p.is_test=false'); }
    else{ where.push('p.usuario_id=$1'); params.push(req.user.id); }
    if(seccion_id){ where.push(`p.seccion_id=$${params.length+1}`); params.push(seccion_id); }
    if(tipo){ where.push(`p.tipo=$${params.length+1}`); params.push(tipo); }
    const {rows}=await pool.query(`SELECT p.*, u.nombre as usuario_nombre, u.telefono as usuario_telefono, u.email as usuario_email, u.nombre_fantasia, s.nombre as seccion_nombre, s.color as seccion_color FROM pedidos p LEFT JOIN usuarios u ON p.usuario_id=u.id LEFT JOIN secciones s ON p.seccion_id=s.id WHERE ${where.join(' AND ')} ORDER BY p.created_at DESC LIMIT 500`, params);
    res.json(rows);
  }catch(e){ res.status(500).json({error:e.message}); }
});
app.get('/api/pedidos/:id', auth(), async (req,res)=>{ try{ const {rows}=await pool.query('SELECT p.*, u.nombre as usuario_nombre, u.telefono as usuario_telefono, u.email as usuario_email, u.nombre_fantasia, u.direccion as usuario_direccion, s.nombre as seccion_nombre, s.color as seccion_color FROM pedidos p LEFT JOIN usuarios u ON p.usuario_id=u.id LEFT JOIN secciones s ON p.seccion_id=s.id WHERE p.id=$1', [req.params.id]); if(!rows[0]) return res.status(404).json({error:'No encontrado'}); const {rows:items}=await pool.query('SELECT * FROM pedido_items WHERE pedido_id=$1', [req.params.id]); res.json({...rows[0], items}); }catch(e){ res.status(500).json({error:e.message}); } });

// Pedido simple + pedido multi-tienda con transaccion
app.post('/api/pedidos', auth(), async (req,res)=>{
  const client=await pool.connect();
  try{
    const {seccion_id,items,tipo,metodo_pago,notas,cupon_codigo,subtotal,descuento,total,datos_envio,notificar_wa,costo_envio,metodo_envio,cp_destino,is_test}=req.body;
    await client.query('BEGIN');
    // Validar stock si corresponde
    for(const item of (items||[])){
      const {rows:prod}=await client.query('SELECT stock, permitir_sin_stock, es_digital, seccion_id FROM productos WHERE id=$1', [item.producto_id]);
      if(!prod[0]) continue;
      const sec=await client.query('SELECT ignorar_stock, permitir_sin_stock FROM secciones WHERE id=$1', [prod[0].seccion_id]).then(r=>r.rows[0]).catch(()=>null);
      const puedeSinStock = prod[0].permitir_sin_stock || prod[0].es_digital || sec?.permitir_sin_stock || sec?.ignorar_stock;
      if(!puedeSinStock && prod[0].stock < (item.cantidad||1)){
        await client.query('ROLLBACK');
        return res.status(400).json({error:`Sin stock: ${item.nombre_producto||''} stock:${prod[0].stock}`});
      }
    }
    const {rows}=await client.query('INSERT INTO pedidos (usuario_id,seccion_id,tipo,metodo_pago,notas,cupon_codigo,subtotal,descuento,total,datos_envio,notificar_wa,costo_envio,metodo_envio,cp_destino,is_test) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15) RETURNING *',
      [req.user.id, seccion_id, tipo||'pedido', metodo_pago||'', notas||'', cupon_codigo||'', subtotal||0, descuento||0, total||0, datos_envio||'', notificar_wa!==false, costo_envio||0, metodo_envio||'', cp_destino||'', is_test||false]);
    for(const item of (items||[])){
      await client.query('INSERT INTO pedido_items (pedido_id,producto_id,categoria,modelo,nombre_producto,cantidad,precio_unitario,precio_base) VALUES ($1,$2,$3,$4,$5,$6,$7,$8)',
        [rows[0].id, item.producto_id, item.categoria||'', item.modelo||'', item.nombre_producto||'', item.cantidad||1, item.precio_unitario||0, item.precio_base||0]);
      // Descontar stock si no es sin stock
      const {rows:prod}=await client.query('SELECT permitir_sin_stock, es_digital FROM productos WHERE id=$1', [item.producto_id]);
      if(prod[0] && !prod[0].permitir_sin_stock && !prod[0].es_digital){
        await client.query('UPDATE productos SET stock = GREATEST(0, stock - $1) WHERE id=$2 AND permitir_sin_stock=false AND es_digital=false', [item.cantidad||1, item.producto_id]);
      }
    }
    if(cupon_codigo) await client.query("UPDATE cupones SET usos_actuales = usos_actuales + 1 WHERE codigo=$1", [cupon_codigo]).catch(()=>{});
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
        const {rows:prod}=await client.query('SELECT stock, permitir_sin_stock, es_digital, seccion_id FROM productos WHERE id=$1', [item.producto_id]);
        if(!prod[0]) continue;
        const sec=await client.query('SELECT ignorar_stock, permitir_sin_stock FROM secciones WHERE id=$1', [prod[0].seccion_id]).then(r=>r.rows[0]).catch(()=>null);
        const puedeSinStock = prod[0].permitir_sin_stock || prod[0].es_digital || sec?.permitir_sin_stock || sec?.ignorar_stock;
        if(!puedeSinStock && prod[0].stock < (item.cantidad||1)){
          await client.query('ROLLBACK');
          return res.status(400).json({error:`Sin stock: ${item.nombre_producto||''} (disponible: ${prod[0].stock})`});
        }
      }
      const {rows}=await client.query('INSERT INTO pedidos (usuario_id,seccion_id,tipo,metodo_pago,notas,cupon_codigo,subtotal,descuento,total,datos_envio,costo_envio,metodo_envio,cp_destino,is_test) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14) RETURNING *',
        [req.user.id, seccion_id, 'pedido', metodo_pago||'', notas||'', cupon_codigo||'', subtotal||0, descuento||0, total||0, datos_envio||'', costo_envio||0, metodo_envio||'', cp_destino||'', is_test||false]);
      for(const item of (items||[])){
        await client.query('INSERT INTO pedido_items (pedido_id,producto_id,categoria,modelo,nombre_producto,cantidad,precio_unitario,precio_base) VALUES ($1,$2,$3,$4,$5,$6,$7,$8)',
          [rows[0].id, item.producto_id, item.categoria||'', item.modelo||'', item.nombre_producto||'', item.cantidad||1, item.precio_unitario||0, item.precio_base||0]);
        const {rows:pr}=await client.query('SELECT permitir_sin_stock, es_digital FROM productos WHERE id=$1', [item.producto_id]);
        if(pr[0] && !pr[0].permitir_sin_stock && !pr[0].es_digital){
          await client.query('UPDATE productos SET stock = GREATEST(0, stock - $1) WHERE id=$2 AND permitir_sin_stock=false AND es_digital=false', [item.cantidad||1, item.producto_id]);
        }
      }
      creados.push(rows[0]);
    }
    if(creados[0]?.cupon_codigo) await client.query("UPDATE cupones SET usos_actuales = usos_actuales + 1 WHERE codigo=$1", [creados[0].cupon_codigo]).catch(()=>{});
    await client.query('COMMIT');
    res.json({ok:true, pedidos: creados});
  }catch(e){ await client.query('ROLLBACK').catch(()=>{}); res.status(500).json({error:e.message}); }
  finally{ client.release(); }
});

app.put('/api/pedidos/:id', auth('admin'), async (req,res)=>{
  try{
    const p=req.body; const sets=[]; const params=[]; let pi=1;
    // Capturar estado + items ANTES de cambios (para devolver stock)
    const {rows:oldItemsRows}=await pool.query('SELECT producto_id, cantidad FROM pedido_items WHERE pedido_id=$1', [req.params.id]);
    const oldMap={}; for(const it of oldItemsRows){ if(it.producto_id) oldMap[it.producto_id]=(oldMap[it.producto_id]||0)+(it.cantidad||0); }
    const {rows:oldPedRows}=await pool.query('SELECT estado FROM pedidos WHERE id=$1', [req.params.id]);
    const oldEstado=String((oldPedRows[0]||{}).estado||'').toLowerCase();
    const fields=['estado','tipo','metodo_pago','notas','total','subtotal','descuento','datos_envio','usuario_id','notificar_wa','is_test','costo_envio','metodo_envio','cp_destino'];
    for(const f of fields){ if(p[f]!==undefined){ sets.push(`${f}=$${pi++}`); params.push(p[f]); } }
    sets.push(`updated_at=NOW()`);
    if(sets.length<=1) return res.json({ok:true});
    params.push(req.params.id);
    await pool.query(`UPDATE pedidos SET ${sets.join(',')} WHERE id=$${pi}`, params);
    if(p.items){ await pool.query('DELETE FROM pedido_items WHERE pedido_id=$1', [req.params.id]); for(const item of p.items){ await pool.query('INSERT INTO pedido_items (pedido_id,producto_id,categoria,modelo,nombre_producto,cantidad,precio_unitario,precio_base) VALUES ($1,$2,$3,$4,$5,$6,$7,$8)', [req.params.id, item.producto_id||item.id, item.categoria||'', item.modelo||'', item.nombre_producto||`${item.categoria} - ${item.modelo}`, item.cantidad||item.qty||1, item.precio_unitario||0, item.precio_base||0]); } }
    // Reconciliar stock: devolver al cancelar, ajustar delta al editar items
    const nuevoEstado=(p.estado!==undefined)?String(p.estado).toLowerCase():oldEstado;
    const cancelSt=['cancelado','anulado','rechazado'];
    const seCancela=cancelSt.includes(nuevoEstado)&&!cancelSt.includes(oldEstado);
    const seReactiva=!cancelSt.includes(nuevoEstado)&&cancelSt.includes(oldEstado);
    const stockAdd={};
    if(seCancela){ for(const pid in oldMap) stockAdd[pid]=(stockAdd[pid]||0)+oldMap[pid]; }
    else if(seReactiva){ const base=p.items||oldItemsRows.map(it=>({producto_id:it.producto_id,cantidad:it.cantidad})); for(const it of base){ const pid=it.producto_id||it.id; if(pid) stockAdd[pid]=(stockAdd[pid]||0)-(it.cantidad||it.qty||0); } }
    else if(p.items){ const newMap={}; for(const it of p.items){ const pid=it.producto_id||it.id; if(pid) newMap[pid]=(newMap[pid]||0)+(it.cantidad||it.qty||0); } const pids=new Set([...Object.keys(oldMap),...Object.keys(newMap)]); for(const pid of pids){ const d=(oldMap[pid]||0)-(newMap[pid]||0); if(d!==0) stockAdd[pid]=(stockAdd[pid]||0)+d; } }
    for(const pid in stockAdd){ const q=stockAdd[pid]; if(q) await pool.query('UPDATE productos SET stock=GREATEST(0, stock + $1) WHERE id=$2 AND permitir_sin_stock=false AND es_digital=false', [q, pid]); }
    res.json({ok:true});
  }catch(e){ res.status(500).json({error:e.message}); }
});
app.post('/api/pedidos/:id/archivar', auth('admin'), async (req,res)=>{ try{ await pool.query('UPDATE pedidos SET archivado=true WHERE id=$1', [req.params.id]); res.json({ok:true}); }catch(e){ res.status(500).json({error:e.message}); } });
app.post('/api/pedidos/:id/desarchivar', auth('admin'), async (req,res)=>{ try{ await pool.query('UPDATE pedidos SET archivado=false WHERE id=$1', [req.params.id]); res.json({ok:true}); }catch(e){ res.status(500).json({error:e.message}); } });
app.delete('/api/pedidos/:id', auth('admin'), async (req,res)=>{ try{ const {rows:oep}=await pool.query('SELECT estado FROM pedidos WHERE id=$1',[req.params.id]); const oe=String((oep[0]||{}).estado||'').toLowerCase(); if(!['cancelado','anulado','rechazado'].includes(oe)){ const {rows:its}=await pool.query('SELECT producto_id, cantidad FROM pedido_items WHERE pedido_id=$1',[req.params.id]); for(const it of its){ if(it.producto_id) await pool.query('UPDATE productos SET stock=GREATEST(0, stock + $1) WHERE id=$2 AND permitir_sin_stock=false AND es_digital=false',[it.cantidad||0, it.producto_id]); } } await pool.query('DELETE FROM pedido_items WHERE pedido_id=$1', [req.params.id]); await pool.query('DELETE FROM pedidos WHERE id=$1', [req.params.id]); res.json({ok:true}); }catch(e){ res.status(500).json({error:e.message}); } });

// STATS
app.get('/api/stats', auth('admin'), async (req,res)=>{
  try{
    const {seccion_id,desde,hasta,is_test}=req.query;
    let secWhere=''; const params=[];
    if(seccion_id && seccion_id!=='all'){ secWhere=' AND seccion_id=$1'; params.push(seccion_id); }
    let dateWhere=''; const dp=params.length;
    if(desde){ dateWhere+=` AND created_at >= $${dp+1}`; params.push(desde); }
    if(hasta){ dateWhere+=` AND created_at <= $${dp+2}`; params.push(hasta); }
    let testWhere='';
    if(is_test==='false') testWhere=' AND is_test=false';
    const totalPedidos=await pool.query(`SELECT COUNT(*) FROM pedidos WHERE archivado=false${secWhere}${dateWhere}${testWhere}`, params);
    const totalVentas=await pool.query(`SELECT COALESCE(SUM(total),0) as total FROM pedidos WHERE estado NOT IN ('cancelado') AND archivado=false${secWhere}${dateWhere}${testWhere}`, params);
    const totalProductos=await pool.query(`SELECT COUNT(*) FROM productos WHERE 1=1${secWhere.replace('seccion_id','seccion_id')}`, seccion_id && seccion_id!=='all' ? [seccion_id] : []);
    const totalUsuarios=await pool.query('SELECT COUNT(*) FROM usuarios WHERE rol != $1', ['admin']);
    const ventasPorDia=await pool.query(`SELECT DATE(created_at) as fecha, COUNT(*) as cantidad, COALESCE(SUM(total),0) as total FROM pedidos WHERE estado NOT IN ('cancelado') AND archivado=false${secWhere}${dateWhere}${testWhere} GROUP BY DATE(created_at) ORDER BY fecha DESC LIMIT 30`, params);
    const topCat=await pool.query(`SELECT pi.categoria, COUNT(*) as cantidad, SUM(pi.precio_unitario * pi.cantidad) as total FROM pedido_items pi JOIN pedidos p ON pi.pedido_id=p.id WHERE p.estado NOT IN ('cancelado')${secWhere.replace('seccion_id','p.seccion_id')}${dateWhere.replace('created_at','p.created_at')}${testWhere.replace('p.','p.')} GROUP BY pi.categoria ORDER BY total DESC LIMIT 10`, params);
    const abandonados=await pool.query('SELECT COUNT(*) FROM carritos_abandonados WHERE recuperado=false').catch(()=>({rows:[{count:0}]}));
    res.json({ total_pedidos: parseInt(totalPedidos.rows[0].count), total_ventas: parseFloat(totalVentas.rows[0].total), total_productos: parseInt(totalProductos.rows[0].count), total_usuarios: parseInt(totalUsuarios.rows[0].count), ventas_por_dia: ventasPorDia.rows, top_categorias: topCat.rows, carritos_abandonados: parseInt(abandonados.rows[0].count) });
  }catch(e){ res.status(500).json({error:e.message}); }
});

// CUPONES, PROMOS, POPUPS, REDES, MENU, DESIGN, PAGOS, PAGINAS, BADGES, ENVIO, BUSQUEDA, SLIDER, FAVORITOS, STOCK, ANDREANI (se mantienen igual + fixes Andreani env)
app.get('/api/cupones', auth('admin'), async (req,res)=>{ try{ const {rows}=await pool.query('SELECT c.*, array_agg(cp.producto_id) FILTER (WHERE cp.producto_id IS NOT NULL) as productos_ids FROM cupones c LEFT JOIN cupon_productos cp ON c.id=cp.cupon_id GROUP BY c.id ORDER BY c.created_at DESC'); res.json(rows); }catch(e){ res.status(500).json({error:e.message}); } });
app.post('/api/cupones/validar', async (req,res)=>{
  try{
    const {codigo,seccion_id,subtotal,metodo_pago,items}=req.body;
    const {rows}=await pool.query('SELECT * FROM cupones WHERE codigo=$1 AND activo=true', [codigo]);
    if(!rows[0]) return res.status(404).json({error:'Cupón no válido'});
    const c=rows[0];
    if(c.uso_maximo>0 && c.usos_actuales>=c.uso_maximo) return res.status(400).json({error:'Cupón agotado'});
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
app.post('/api/cupones', auth('admin'), async (req,res)=>{ try{ const c=req.body; const {rows}=await pool.query('INSERT INTO cupones (codigo,tipo,valor,secciones_ids,categoria,uso_maximo,monto_minimo,metodo_pago,activo,fecha_desde,fecha_hasta) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11) RETURNING *', [c.codigo,c.tipo||'porcentaje',c.valor||0,c.secciones_ids||'',c.categoria||'',c.uso_maximo||0,c.monto_minimo||0,c.metodo_pago||'',c.activo!==false,c.fecha_desde||null,c.fecha_hasta||null]); if(c.productos_ids){ for(const pid of c.productos_ids){ await pool.query('INSERT INTO cupon_productos (cupon_id,producto_id) VALUES ($1,$2) ON CONFLICT DO NOTHING', [rows[0].id,pid]); } } res.json(rows[0]); }catch(e){ res.status(500).json({error:e.message}); } });
app.put('/api/cupones/:id', auth('admin'), async (req,res)=>{ try{ const c=req.body; await pool.query('UPDATE cupones SET codigo=$1,tipo=$2,valor=$3,secciones_ids=$4,categoria=$5,uso_maximo=$6,monto_minimo=$7,metodo_pago=$8,activo=$9,fecha_desde=$10,fecha_hasta=$11 WHERE id=$12', [c.codigo,c.tipo,c.valor,c.secciones_ids||'',c.categoria||'',c.uso_maximo||0,c.monto_minimo||0,c.metodo_pago||'',c.activo!==false,c.fecha_desde||null,c.fecha_hasta||null,req.params.id]); await pool.query('DELETE FROM cupon_productos WHERE cupon_id=$1', [req.params.id]); if(c.productos_ids){ for(const pid of c.productos_ids){ await pool.query('INSERT INTO cupon_productos (cupon_id,producto_id) VALUES ($1,$2)', [req.params.id,pid]); } } res.json({ok:true}); }catch(e){ res.status(500).json({error:e.message}); } });
app.delete('/api/cupones/:id', auth('admin'), async (req,res)=>{ try{ await pool.query('DELETE FROM cupones WHERE id=$1', [req.params.id]); res.json({ok:true}); }catch(e){ res.status(500).json({error:e.message}); } });

// PROMOCIONES
app.get('/api/promociones', auth('admin'), async (req,res)=>{ try{ const {rows}=await pool.query('SELECT * FROM promociones ORDER BY created_at DESC'); res.json(rows); }catch(e){ res.status(500).json({error:e.message}); } });
app.get('/api/promociones/activas', async (req,res)=>{ try{ const {rows}=await pool.query('SELECT * FROM promociones WHERE activo=true AND (fecha_desde IS NULL OR fecha_desde<=NOW()) AND (fecha_hasta IS NULL OR fecha_hasta>=NOW())'); res.json(rows); }catch(e){ res.status(500).json({error:e.message}); } });
app.post('/api/promociones', auth('admin'), async (req,res)=>{ try{ const p=req.body; const {rows}=await pool.query('INSERT INTO promociones (nombre,tipo,valor,secciones_ids,categoria,productos_ids,activo,fecha_desde,fecha_hasta) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9) RETURNING *', [p.nombre,p.tipo,p.valor,p.secciones_ids||'',p.categoria||'',p.productos_ids||'',p.activo!==false,p.fecha_desde||null,p.fecha_hasta||null]); res.json(rows[0]); }catch(e){ res.status(500).json({error:e.message}); } });
app.put('/api/promociones/:id', auth('admin'), async (req,res)=>{ try{ const p=req.body; await pool.query('UPDATE promociones SET nombre=$1,tipo=$2,valor=$3,secciones_ids=$4,categoria=$5,productos_ids=$6,activo=$7,fecha_desde=$8,fecha_hasta=$9 WHERE id=$10', [p.nombre,p.tipo,p.valor,p.secciones_ids||'',p.categoria||'',p.productos_ids||'',p.activo!==false,p.fecha_desde||null,p.fecha_hasta||null,req.params.id]); res.json({ok:true}); }catch(e){ res.status(500).json({error:e.message}); } });
app.delete('/api/promociones/:id', auth('admin'), async (req,res)=>{ try{ await pool.query('DELETE FROM promociones WHERE id=$1', [req.params.id]); res.json({ok:true}); }catch(e){ res.status(500).json({error:e.message}); } });

// POPUPS, REDES, MENU, DESIGN, METODOS PAGO, PAGINAS, BADGES, ENVIO CONFIG
app.get('/api/popups', async (req,res)=>{ try{ const {rows}=await pool.query('SELECT * FROM popups WHERE activo=true ORDER BY created_at DESC'); res.json(rows); }catch(e){ res.status(500).json({error:e.message}); } });
app.get('/api/popups/all', auth('admin'), async (req,res)=>{ try{ const {rows}=await pool.query('SELECT * FROM popups ORDER BY created_at DESC'); res.json(rows); }catch(e){ res.status(500).json({error:e.message}); } });
app.post('/api/popups', auth('admin'), async (req,res)=>{ try{ const p=req.body; const {rows}=await pool.query('INSERT INTO popups (titulo,imagen,url_destino,secciones_ids,activo) VALUES ($1,$2,$3,$4,$5) RETURNING *', [p.titulo||'',p.imagen||'',p.url_destino||'',p.secciones_ids||'',p.activo!==false]); res.json(rows[0]); }catch(e){ res.status(500).json({error:e.message}); } });
app.put('/api/popups/:id', auth('admin'), async (req,res)=>{ try{ const p=req.body; await pool.query('UPDATE popups SET titulo=$1,imagen=$2,url_destino=$3,secciones_ids=$4,activo=$5 WHERE id=$6', [p.titulo,p.imagen,p.url_destino,p.secciones_ids||'',p.activo!==false,req.params.id]); res.json({ok:true}); }catch(e){ res.status(500).json({error:e.message}); } });
app.delete('/api/popups/:id', auth('admin'), async (req,res)=>{ try{ await pool.query('DELETE FROM popups WHERE id=$1', [req.params.id]); res.json({ok:true}); }catch(e){ res.status(500).json({error:e.message}); } });

app.get('/api/redes-sociales', async (req,res)=>{ try{ const {rows}=await pool.query('SELECT * FROM redes_sociales ORDER BY orden'); res.json(rows); }catch(e){ res.status(500).json({error:e.message}); } });
app.put('/api/redes-sociales', auth('admin'), async (req,res)=>{ try{ const {redes}=req.body; for(const r of redes){ await pool.query('INSERT INTO redes_sociales (id,tipo,url,activo,orden) VALUES ($1,$2,$3,$4,$5) ON CONFLICT (id) DO UPDATE SET url=$3,activo=$4,orden=$5', [r.id,r.tipo,r.url,r.activo,r.orden]); } res.json({ok:true}); }catch(e){ res.status(500).json({error:e.message}); } });

app.get('/api/menu', async (req,res)=>{ try{ const {rows}=await pool.query('SELECT * FROM menu_items WHERE visible=true ORDER BY orden'); res.json(rows); }catch(e){ res.status(500).json({error:e.message}); } });
app.get('/api/menu/all', auth('admin'), async (req,res)=>{ try{ const {rows}=await pool.query('SELECT * FROM menu_items ORDER BY orden'); res.json(rows); }catch(e){ res.status(500).json({error:e.message}); } });
app.post('/api/menu', auth('admin'), async (req,res)=>{ try{ const m=req.body; const {rows}=await pool.query('INSERT INTO menu_items (titulo,url,tipo,visible,orden,seccion_id) VALUES ($1,$2,$3,$4,$5,$6) RETURNING *', [m.titulo,m.url||'',m.tipo||'link',m.visible!==false,m.orden||0,m.seccion_id||null]); res.json(rows[0]); }catch(e){ res.status(500).json({error:e.message}); } });
app.put('/api/menu/:id', auth('admin'), async (req,res)=>{ try{ const m=req.body; await pool.query('UPDATE menu_items SET titulo=$1,url=$2,tipo=$3,visible=$4,orden=$5,seccion_id=$6 WHERE id=$7', [m.titulo,m.url,m.tipo,m.visible!==false,m.orden||0,m.seccion_id||null,req.params.id]); res.json({ok:true}); }catch(e){ res.status(500).json({error:e.message}); } });
app.delete('/api/menu/:id', auth('admin'), async (req,res)=>{ try{ await pool.query('DELETE FROM menu_items WHERE id=$1', [req.params.id]); res.json({ok:true}); }catch(e){ res.status(500).json({error:e.message}); } });

app.get('/api/design', async (req,res)=>{ try{ const {rows}=await pool.query('SELECT * FROM design_config'); const cfg={}; rows.forEach(r=>cfg[r.clave]=r.valor); res.json(cfg); }catch(e){ res.status(500).json({error:e.message}); } });
app.put('/api/design', auth('admin'), async (req,res)=>{ try{ for(const [k,v] of Object.entries(req.body)){ await pool.query("INSERT INTO design_config (clave,valor) VALUES ($1,$2) ON CONFLICT (clave) DO UPDATE SET valor=$2", [k,v]); } res.json({ok:true}); }catch(e){ res.status(500).json({error:e.message}); } });

app.get('/api/metodos-pago', async (req,res)=>{ try{ const {seccion_id}=req.query; let q='SELECT * FROM metodos_pago WHERE activo=true'; const params=[]; if(seccion_id){ q+=' AND (seccion_id=$1 OR seccion_id IS NULL)'; params.push(seccion_id); } q+=' ORDER BY orden'; const {rows}=await pool.query(q, params); res.json(rows); }catch(e){ res.status(500).json({error:e.message}); } });
app.get('/api/metodos-pago/all', auth('admin'), async (req,res)=>{ try{ const {rows}=await pool.query('SELECT * FROM metodos_pago ORDER BY orden'); res.json(rows); }catch(e){ res.status(500).json({error:e.message}); } });
app.post('/api/metodos-pago', auth('admin'), async (req,res)=>{ try{ const m=req.body; const {rows}=await pool.query('INSERT INTO metodos_pago (nombre,descripcion,instrucciones,icono,seccion_id,activo,orden) VALUES ($1,$2,$3,$4,$5,$6,$7) RETURNING *', [m.nombre,m.descripcion||'',m.instrucciones||'',m.icono||'💳',m.seccion_id||null,m.activo!==false,m.orden||0]); res.json(rows[0]); }catch(e){ res.status(500).json({error:e.message}); } });
app.put('/api/metodos-pago/:id', auth('admin'), async (req,res)=>{ try{ const m=req.body; await pool.query('UPDATE metodos_pago SET nombre=$1,descripcion=$2,instrucciones=$3,icono=$4,seccion_id=$5,activo=$6,orden=$7 WHERE id=$8', [m.nombre,m.descripcion,m.instrucciones,m.icono,m.seccion_id,m.activo!==false,m.orden||0,req.params.id]); res.json({ok:true}); }catch(e){ res.status(500).json({error:e.message}); } });
app.delete('/api/metodos-pago/:id', auth('admin'), async (req,res)=>{ try{ await pool.query('DELETE FROM metodos_pago WHERE id=$1', [req.params.id]); res.json({ok:true}); }catch(e){ res.status(500).json({error:e.message}); } });

app.get('/api/paginas', async (req,res)=>{ try{ const {seccion_id}=req.query; let q='SELECT * FROM paginas_info WHERE visible=true'; const params=[]; if(seccion_id){ q+=' AND (seccion_id=$1 OR seccion_id IS NULL)'; params.push(seccion_id); } q+=' ORDER BY orden'; const {rows}=await pool.query(q, params); res.json(rows); }catch(e){ res.status(500).json({error:e.message}); } });
app.get('/api/paginas/:id', async (req,res)=>{ try{ const {rows}=await pool.query('SELECT * FROM paginas_info WHERE id=$1', [req.params.id]); res.json(rows[0]); }catch(e){ res.status(500).json({error:e.message}); } });
app.post('/api/paginas', auth('admin'), async (req,res)=>{ try{ const p=req.body; const {rows}=await pool.query('INSERT INTO paginas_info (titulo,slug,contenido,seccion_id,visible,orden) VALUES ($1,$2,$3,$4,$5,$6) RETURNING *', [p.titulo,p.slug,p.contenido||'',p.seccion_id||null,p.visible!==false,p.orden||0]); res.json(rows[0]); }catch(e){ res.status(500).json({error:e.message}); } });
app.put('/api/paginas/:id', auth('admin'), async (req,res)=>{ try{ const p=req.body; await pool.query('UPDATE paginas_info SET titulo=$1,slug=$2,contenido=$3,seccion_id=$4,visible=$5,orden=$6 WHERE id=$7', [p.titulo,p.slug,p.contenido||'',p.seccion_id||null,p.visible!==false,p.orden||0,req.params.id]); res.json({ok:true}); }catch(e){ res.status(500).json({error:e.message}); } });
app.delete('/api/paginas/:id', auth('admin'), async (req,res)=>{ try{ await pool.query('DELETE FROM paginas_info WHERE id=$1', [req.params.id]); res.json({ok:true}); }catch(e){ res.status(500).json({error:e.message}); } });

app.get('/api/badges', async (req,res)=>{ try{ const {seccion_id}=req.query; let q='SELECT * FROM badges WHERE visible=true'; const params=[]; if(seccion_id){ q+=` AND (secciones_ids='' OR secciones_ids IS NULL OR ',' || secciones_ids || ',' LIKE $1)`; params.push(`%,${seccion_id},%`); } q+=' ORDER BY orden'; const {rows}=await pool.query(q, params); res.json(rows); }catch(e){ res.status(500).json({error:e.message}); } });
app.get('/api/badges/all', auth('admin'), async (req,res)=>{ try{ const {rows}=await pool.query('SELECT * FROM badges ORDER BY orden'); res.json(rows); }catch(e){ res.status(500).json({error:e.message}); } });
app.post('/api/badges', auth('admin'), async (req,res)=>{ try{ const b=req.body; const {rows}=await pool.query('INSERT INTO badges (icono,texto,color,visible,secciones_ids,orden) VALUES ($1,$2,$3,$4,$5,$6) RETURNING *', [b.icono||'⭐',b.texto||'',b.color||'#2563eb',b.visible!==false,b.secciones_ids||'',b.orden||0]); res.json(rows[0]); }catch(e){ res.status(500).json({error:e.message}); } });
app.put('/api/badges/:id', auth('admin'), async (req,res)=>{ try{ const b=req.body; await pool.query('UPDATE badges SET icono=$1,texto=$2,color=$3,visible=$4,secciones_ids=$5,orden=$6 WHERE id=$7', [b.icono,b.texto,b.color,b.visible!==false,b.secciones_ids||'',b.orden||0,req.params.id]); res.json({ok:true}); }catch(e){ res.status(500).json({error:e.message}); } });
app.delete('/api/badges/:id', auth('admin'), async (req,res)=>{ try{ await pool.query('DELETE FROM badges WHERE id=$1', [req.params.id]); res.json({ok:true}); }catch(e){ res.status(500).json({error:e.message}); } });

// ENVIO CONFIG + CUSTOM
app.get('/api/envio/config/:seccion_id', async (req,res)=>{ try{ const {rows}=await pool.query('SELECT * FROM config_envio WHERE seccion_id=$1', [req.params.seccion_id]); res.json(rows[0]||{metodo:'manual',costo_fijo:0,gratis_desde:0,cp_origen:'1888'}); }catch(e){ res.status(500).json({error:e.message}); } });
app.put('/api/envio/config/:seccion_id', auth('admin'), async (req,res)=>{ try{ const c=req.body; await pool.query('INSERT INTO config_envio (seccion_id,metodo,costo_fijo,gratis_desde,zonas,cp_origen) VALUES ($1,$2,$3,$4,$5,$6) ON CONFLICT (seccion_id) DO UPDATE SET metodo=$2,costo_fijo=$3,gratis_desde=$4,zonas=$5,cp_origen=$6', [req.params.seccion_id,c.metodo||'manual',c.costo_fijo||0,c.gratis_desde||0,JSON.stringify(c.zonas||[]),c.cp_origen||'1888']); res.json({ok:true}); }catch(e){ res.status(500).json({error:e.message}); } });
app.post('/api/envio/cotizar', async (req,res)=>{ try{ const {seccion_id,codigo_postal}=req.body; const {rows}=await pool.query('SELECT * FROM config_envio WHERE seccion_id=$1', [seccion_id]); const cfg=rows[0]||{metodo:'manual',costo_fijo:0}; res.json({costo:cfg.costo_fijo, metodo:cfg.metodo, gratis_desde:cfg.gratis_desde}); }catch(e){ res.status(500).json({error:e.message}); } });

// METODOS ENVIO CUSTOM - Uber, Didi, etc
app.get('/api/envio/custom', async (req,res)=>{ try{ const {seccion_id}=req.query; let q='SELECT * FROM metodos_envio_custom WHERE activo=true'; const params=[]; if(seccion_id){ q+=' AND (seccion_id=$1 OR seccion_id IS NULL)'; params.push(seccion_id); } q+=' ORDER BY orden'; const {rows}=await pool.query(q, params); res.json(rows); }catch(e){ res.status(500).json({error:e.message}); } });
app.get('/api/envio/custom/all', auth('admin'), async (req,res)=>{ try{ const {rows}=await pool.query('SELECT * FROM metodos_envio_custom ORDER BY seccion_id, orden'); res.json(rows); }catch(e){ res.status(500).json({error:e.message}); } });
app.post('/api/envio/custom', auth('admin'), async (req,res)=>{ try{ const m=req.body; const {rows}=await pool.query('INSERT INTO metodos_envio_custom (seccion_id,nombre,descripcion,precio,tipo,activo,gratis_desde,tiempo_estimado,icono,orden) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10) RETURNING *', [m.seccion_id||null,m.nombre,m.descripcion||'',m.precio||0,m.tipo||'fijo',m.activo!==false,m.gratis_desde||0,m.tiempo_estimado||'',m.icono||'🚚',m.orden||0]); res.json(rows[0]); }catch(e){ res.status(500).json({error:e.message}); } });
app.put('/api/envio/custom/:id', auth('admin'), async (req,res)=>{ try{ const m=req.body; await pool.query('UPDATE metodos_envio_custom SET seccion_id=$1,nombre=$2,descripcion=$3,precio=$4,tipo=$5,activo=$6,gratis_desde=$7,tiempo_estimado=$8,icono=$9,orden=$10 WHERE id=$11', [m.seccion_id||null,m.nombre,m.descripcion,m.precio,m.tipo,m.activo!==false,m.gratis_desde||0,m.tiempo_estimado||'',m.icono||'🚚',m.orden||0,req.params.id]); res.json({ok:true}); }catch(e){ res.status(500).json({error:e.message}); } });
app.delete('/api/envio/custom/:id', auth('admin'), async (req,res)=>{ try{ await pool.query('DELETE FROM metodos_envio_custom WHERE id=$1', [req.params.id]); res.json({ok:true}); }catch(e){ res.status(500).json({error:e.message}); } });

// BUSQUEDA GLOBAL con debounce ready
app.get('/api/busqueda-global', optionalAuth, async (req,res)=>{
  try{
    const {q}=req.query; if(!q||q.length<2) return res.json({resultados:[], total:0});
    const {rows:secciones}=await pool.query('SELECT * FROM secciones WHERE visible=true ORDER BY orden, id');
    const resultados=[];
    for(const sec of secciones){
      const {rows}=await pool.query("SELECT id,nombre,modelo,categoria,precio_base,precio_oferta,imagen,stock,envio_gratis,permitir_sin_stock,es_digital FROM productos WHERE seccion_id=$1 AND visible=true AND (nombre ILIKE $2 OR modelo ILIKE $2 OR categoria ILIKE $2 OR compatibilidad ILIKE $2 OR sku ILIKE $2) ORDER BY stock DESC LIMIT 10", [sec.id, `%${q}%`]);
      if(rows.length){ const hidePrice=sec.slug==='mayorista' && !req.user; resultados.push({seccion:sec, productos: hidePrice? rows.map(r=>({...r, precio_base:0, precio_oferta:0})) : rows}); }
    }
    res.json({resultados, total: resultados.reduce((s,r)=>s+r.productos.length,0)});
  }catch(e){ res.status(500).json({error:e.message}); }
});

// SLIDER, FAVORITOS, NOTIF STOCK
app.get('/api/slider', async (req,res)=>{ try{ const {rows}=await pool.query('SELECT * FROM slider_banners WHERE activo=true ORDER BY orden'); res.json(rows); }catch(e){ res.status(500).json({error:e.message}); } });
app.get('/api/slider/all', auth('admin'), async (req,res)=>{ try{ const {rows}=await pool.query('SELECT * FROM slider_banners ORDER BY orden'); res.json(rows); }catch(e){ res.status(500).json({error:e.message}); } });
app.post('/api/slider', auth('admin'), async (req,res)=>{ try{ const {titulo,subtitulo,etiqueta,imagen,url_destino,orden,activo}=req.body; const {rows}=await pool.query('INSERT INTO slider_banners (titulo,subtitulo,etiqueta,imagen,url_destino,orden,activo) VALUES ($1,$2,$3,$4,$5,$6,$7) RETURNING *', [titulo||'',subtitulo||'',etiqueta||'',imagen||'',url_destino||'',orden||0,activo!==false]); res.json(rows[0]); }catch(e){ res.status(500).json({error:e.message}); } });
app.put('/api/slider/:id', auth('admin'), async (req,res)=>{ try{ const {titulo,subtitulo,etiqueta,imagen,url_destino,orden,activo}=req.body; await pool.query('UPDATE slider_banners SET titulo=$1,subtitulo=$2,etiqueta=$3,imagen=$4,url_destino=$5,orden=$6,activo=$7 WHERE id=$8', [titulo,subtitulo||'',etiqueta||'',imagen,url_destino,orden,activo,req.params.id]); res.json({ok:true}); }catch(e){ res.status(500).json({error:e.message}); } });
app.delete('/api/slider/:id', auth('admin'), async (req,res)=>{ try{ await pool.query('DELETE FROM slider_banners WHERE id=$1', [req.params.id]); res.json({ok:true}); }catch(e){ res.status(500).json({error:e.message}); } });
// ── BARRAS DE TEXTO DESLIZANTES ──
app.get('/api/barras', async (req,res)=>{ try{ const {rows}=await pool.query('SELECT * FROM barras_texto WHERE activo=true ORDER BY id'); res.json(rows); }catch(e){ res.status(500).json({error:e.message}); } });
app.get('/api/barras/all', auth('admin'), async (req,res)=>{ try{ const {rows}=await pool.query('SELECT * FROM barras_texto ORDER BY id'); res.json(rows); }catch(e){ res.status(500).json({error:e.message}); } });
app.post('/api/barras', auth('admin'), async (req,res)=>{ try{ const b=req.body; const {rows}=await pool.query('INSERT INTO barras_texto (posicion,frases,estilo,color_fondo,color_texto,velocidad,activo) VALUES ($1,$2,$3,$4,$5,$6,$7) RETURNING *', [b.posicion||'top',b.frases||'',b.estilo||'negro',b.color_fondo||'',b.color_texto||'',b.velocidad||25,b.activo!==false]); res.json(rows[0]); }catch(e){ res.status(500).json({error:e.message}); } });
app.put('/api/barras/:id', auth('admin'), async (req,res)=>{ try{ const b=req.body; await pool.query('UPDATE barras_texto SET posicion=$1,frases=$2,estilo=$3,color_fondo=$4,color_texto=$5,velocidad=$6,activo=$7 WHERE id=$8', [b.posicion||'top',b.frases||'',b.estilo||'negro',b.color_fondo||'',b.color_texto||'',b.velocidad||25,b.activo!==false,req.params.id]); res.json({ok:true}); }catch(e){ res.status(500).json({error:e.message}); } });
app.delete('/api/barras/:id', auth('admin'), async (req,res)=>{ try{ await pool.query('DELETE FROM barras_texto WHERE id=$1', [req.params.id]); res.json({ok:true}); }catch(e){ res.status(500).json({error:e.message}); } });

app.get('/api/favoritos', auth(), async (req,res)=>{ try{ const {rows}=await pool.query('SELECT f.*, p.nombre, p.modelo, p.imagen, p.precio_base, p.precio_oferta, p.stock, p.categoria, p.seccion_id FROM favoritos f JOIN productos p ON f.producto_id=p.id WHERE f.usuario_id=$1 ORDER BY f.created_at DESC', [req.user.id]); res.json(rows); }catch(e){ res.status(500).json({error:e.message}); } });
app.post('/api/favoritos/:producto_id', auth(), async (req,res)=>{ try{ await pool.query('INSERT INTO favoritos (usuario_id,producto_id) VALUES ($1,$2) ON CONFLICT DO NOTHING', [req.user.id, req.params.producto_id]); res.json({ok:true}); }catch(e){ res.status(500).json({error:e.message}); } });
app.delete('/api/favoritos/:producto_id', auth(), async (req,res)=>{ try{ await pool.query('DELETE FROM favoritos WHERE usuario_id=$1 AND producto_id=$2', [req.user.id, req.params.producto_id]); res.json({ok:true}); }catch(e){ res.status(500).json({error:e.message}); } });

app.post('/api/notificar-stock', async (req,res)=>{ try{ const {producto_id,email}=req.body; if(!email||!producto_id) return res.status(400).json({error:'email y producto_id requeridos'}); await pool.query('INSERT INTO notificaciones_stock (producto_id,email) VALUES ($1,$2)', [producto_id,email]); res.json({ok:true}); }catch(e){ res.status(500).json({error:e.message}); } });

// CARRITOS ABANDONADOS
app.post('/api/carritos-abandonados', async (req,res)=>{ try{ const {usuario_id,email,telefono,items,total,seccion_id}=req.body; const {rows}=await pool.query('INSERT INTO carritos_abandonados (usuario_id,email,telefono,items,total,seccion_id) VALUES ($1,$2,$3,$4,$5,$6) RETURNING *', [usuario_id||null,email||'',telefono||'',JSON.stringify(items||[]),total||0,seccion_id||null]); res.json(rows[0]); }catch(e){ res.status(500).json({error:e.message}); } });
app.get('/api/carritos-abandonados', auth('admin'), async (req,res)=>{ try{ const {rows}=await pool.query('SELECT * FROM carritos_abandonados WHERE recuperado=false ORDER BY created_at DESC LIMIT 100'); res.json(rows); }catch(e){ res.status(500).json({error:e.message}); } });

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
app.post('/api/andreani/orden', auth('admin'), async (req,res)=>{ try{ const token=await andreaniLogin(); if(!token) return res.status(503).json({error:'Andreani no configurado'}); const r=await fetch(`${ANDREANI_API}/v1/ordenes-de-envio`, {method:'POST', headers:{'x-authorization-token':token, 'Content-Type':'application/json'}, body:JSON.stringify(req.body)}); res.json(await r.json()); }catch(e){ res.status(500).json({error:e.message}); } });
app.get('/api/andreani/tracking/:envio', async (req,res)=>{ try{ const token=await andreaniLogin(); if(!token) return res.status(503).json({error:'Andreani no configurado'}); const r=await fetch(`${ANDREANI_API}/v1/envios/${req.params.envio}/trazas`, {headers:{'x-authorization-token':token}}); res.json(await r.json()); }catch(e){ res.status(500).json({error:e.message}); } });
app.get('/api/andreani/etiqueta/:envio', async (req,res)=>{ try{ const token=await andreaniLogin(); if(!token) return res.status(503).json({error:'Andreani no configurado'}); const r=await fetch(`${ANDREANI_API}/v1/ordenes-de-envio/${req.params.envio}/etiquetas`, {headers:{'x-authorization-token':token, Accept:'application/pdf'}}); res.set('Content-Type','application/pdf'); const buffer=await r.arrayBuffer(); res.send(Buffer.from(buffer)); }catch(e){ res.status(500).json({error:e.message}); } });

// START
const PORT=process.env.PORT||3000;
migrate().then(()=>{ app.listen(PORT, ()=>console.log(`🚀 V4 running on ${PORT}`)); }).catch(e=>{ console.error('Migration failed', e); process.exit(1); });
