-- ═══════════════════════════════════════════════════════════
-- Migration v3 — Fases 1+2+3 completas
-- Ejecutar en Railway PostgreSQL
-- ═══════════════════════════════════════════════════════════

-- === NUEVAS COLUMNAS EN PRODUCTOS ===
ALTER TABLE productos ADD COLUMN IF NOT EXISTS nombre VARCHAR(300) NOT NULL DEFAULT '';
ALTER TABLE productos ADD COLUMN IF NOT EXISTS descripcion TEXT NOT NULL DEFAULT '';
ALTER TABLE productos ADD COLUMN IF NOT EXISTS sku VARCHAR(100) NOT NULL DEFAULT '';
ALTER TABLE productos ADD COLUMN IF NOT EXISTS tipo VARCHAR(20) NOT NULL DEFAULT 'fisico';
ALTER TABLE productos ADD COLUMN IF NOT EXISTS moneda VARCHAR(10) NOT NULL DEFAULT 'ARS';
ALTER TABLE productos ADD COLUMN IF NOT EXISTS precio_oferta NUMERIC(12,2) NOT NULL DEFAULT 0;
ALTER TABLE productos ADD COLUMN IF NOT EXISTS envio_gratis BOOLEAN NOT NULL DEFAULT false;
ALTER TABLE productos ADD COLUMN IF NOT EXISTS visible BOOLEAN NOT NULL DEFAULT true;
ALTER TABLE productos ADD COLUMN IF NOT EXISTS peso INT NOT NULL DEFAULT 0;
ALTER TABLE productos ADD COLUMN IF NOT EXISTS alto INT NOT NULL DEFAULT 0;
ALTER TABLE productos ADD COLUMN IF NOT EXISTS ancho INT NOT NULL DEFAULT 0;
ALTER TABLE productos ADD COLUMN IF NOT EXISTS largo INT NOT NULL DEFAULT 0;

-- === BADGES: secciones_ids para filtrar por sección ===
ALTER TABLE badges ADD COLUMN IF NOT EXISTS secciones_ids TEXT NOT NULL DEFAULT '';

-- === TABLA PROMOCIONES (descuentos automáticos sin código) ===
CREATE TABLE IF NOT EXISTS promociones (
  id SERIAL PRIMARY KEY,
  nombre VARCHAR(200) NOT NULL DEFAULT '',
  tipo VARCHAR(30) NOT NULL DEFAULT 'porcentaje',
  valor NUMERIC(12,2) NOT NULL DEFAULT 0,
  secciones_ids TEXT NOT NULL DEFAULT '',
  categoria VARCHAR(200) NOT NULL DEFAULT '',
  productos_ids TEXT NOT NULL DEFAULT '',
  fecha_inicio DATE,
  fecha_fin DATE,
  activa BOOLEAN NOT NULL DEFAULT true,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- === TABLA POPUPS PROMOCIONALES ===
CREATE TABLE IF NOT EXISTS popups (
  id SERIAL PRIMARY KEY,
  titulo VARCHAR(200) NOT NULL DEFAULT '',
  imagen TEXT NOT NULL DEFAULT '',
  url_destino TEXT NOT NULL DEFAULT '',
  secciones_ids TEXT NOT NULL DEFAULT '',
  activo BOOLEAN NOT NULL DEFAULT true,
  mostrar_una_vez BOOLEAN NOT NULL DEFAULT true,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- === TABLA REDES SOCIALES ===
CREATE TABLE IF NOT EXISTS redes_sociales (
  id SERIAL PRIMARY KEY,
  tipo VARCHAR(50) NOT NULL,
  url TEXT NOT NULL DEFAULT '',
  activo BOOLEAN NOT NULL DEFAULT true,
  orden INT NOT NULL DEFAULT 0
);

-- Insertar defaults
INSERT INTO redes_sociales (tipo, url, activo, orden) VALUES
  ('facebook', '', false, 1),
  ('instagram', '', false, 2),
  ('tiktok', '', false, 3),
  ('whatsapp_canal', '', false, 4),
  ('whatsapp_grupo', '', false, 5)
ON CONFLICT DO NOTHING;

-- === TABLA MENU ITEMS (menú editable) ===
CREATE TABLE IF NOT EXISTS menu_items (
  id SERIAL PRIMARY KEY,
  titulo VARCHAR(100) NOT NULL,
  url TEXT NOT NULL DEFAULT '',
  tipo VARCHAR(30) NOT NULL DEFAULT 'link',
  seccion_id INT REFERENCES secciones(id),
  orden INT NOT NULL DEFAULT 0,
  visible BOOLEAN NOT NULL DEFAULT true
);

-- Insertar defaults
INSERT INTO menu_items (titulo, url, tipo, orden, visible) VALUES
  ('Inicio', '/', 'link', 1, true),
  ('Local', '/seccion/local', 'seccion', 2, true),
  ('Dropshipping', '/seccion/dropshipping', 'seccion', 3, true),
  ('Mayorista', '/seccion/mayorista', 'seccion', 4, true),
  ('Contacto', '/contacto', 'link', 5, true)
ON CONFLICT DO NOTHING;

-- === TABLA DESIGN CONFIG (editor diseño/plantillas) ===
CREATE TABLE IF NOT EXISTS design_config (
  clave VARCHAR(100) PRIMARY KEY,
  valor TEXT NOT NULL DEFAULT ''
);

-- Defaults de diseño
INSERT INTO design_config (clave, valor) VALUES
  ('color_primario', '#2563eb'),
  ('color_secundario', '#1e40af'),
  ('color_acento', '#f59e0b'),
  ('font_familia', 'Inter, sans-serif'),
  ('logo_url', ''),
  ('favicon_url', ''),
  ('banner_url', ''),
  ('nombre_tienda', 'Mi Tienda'),
  ('plantilla', 'moderna'),
  ('footer_texto', ''),
  ('header_estilo', 'standard')
ON CONFLICT (clave) DO NOTHING;

-- === TABLA CUPÓN-PRODUCTOS (multi-producto) ===
CREATE TABLE IF NOT EXISTS cupon_productos (
  id SERIAL PRIMARY KEY,
  cupon_id INT NOT NULL REFERENCES cupones(id) ON DELETE CASCADE,
  producto_id INT NOT NULL REFERENCES productos(id) ON DELETE CASCADE,
  UNIQUE(cupon_id, producto_id)
);

-- === MÉTODOS DE PAGO con descripción ===
CREATE TABLE IF NOT EXISTS metodos_pago (
  id SERIAL PRIMARY KEY,
  nombre VARCHAR(100) NOT NULL,
  descripcion TEXT NOT NULL DEFAULT '',
  instrucciones TEXT NOT NULL DEFAULT '',
  seccion_id INT REFERENCES secciones(id),
  activo BOOLEAN NOT NULL DEFAULT true,
  orden INT NOT NULL DEFAULT 0
);

-- === NUEVAS COLUMNAS EN USUARIOS (descuento revendedor) ===
ALTER TABLE usuarios ADD COLUMN IF NOT EXISTS es_revendedor BOOLEAN NOT NULL DEFAULT false;
ALTER TABLE usuarios ADD COLUMN IF NOT EXISTS descuento_revendedor NUMERIC(5,2) NOT NULL DEFAULT 0;

-- === STATS: tabla para gráficos por día ===
-- (usamos pedidos existentes con created_at para stats por período)

-- === INDEXES NUEVOS ===
CREATE INDEX IF NOT EXISTS idx_productos_visible ON productos(visible);
CREATE INDEX IF NOT EXISTS idx_productos_envio_gratis ON productos(envio_gratis);
CREATE INDEX IF NOT EXISTS idx_promociones_activa ON promociones(activa);
CREATE INDEX IF NOT EXISTS idx_popups_activo ON popups(activo);
