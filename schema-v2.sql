-- ═══════════════════════════════════════════════════════════
-- Schema v2 — Sistema Unificado Multi-Sección
-- ═══════════════════════════════════════════════════════════

CREATE TABLE IF NOT EXISTS configuracion (
  clave VARCHAR(100) PRIMARY KEY,
  valor TEXT NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS listas_precio (
  id VARCHAR(50) PRIMARY KEY,
  nombre VARCHAR(100) NOT NULL,
  multiplicador NUMERIC(6,4) NOT NULL DEFAULT 1,
  porcentaje NUMERIC(6,2) NOT NULL DEFAULT 0,
  color VARCHAR(20) NOT NULL DEFAULT '#2563eb',
  compra_minima NUMERIC(12,2) NOT NULL DEFAULT 0,
  promo_msg TEXT NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS usuarios (
  id SERIAL PRIMARY KEY,
  nombre VARCHAR(200) NOT NULL,
  usuario VARCHAR(100) UNIQUE NOT NULL,
  password VARCHAR(200) NOT NULL,
  telefono VARCHAR(50) NOT NULL DEFAULT '',
  email VARCHAR(200) NOT NULL DEFAULT '',
  direccion TEXT NOT NULL DEFAULT '',
  nombre_fantasia TEXT NOT NULL DEFAULT '',
  rol VARCHAR(20) NOT NULL DEFAULT 'cliente',
  lista_precio_id VARCHAR(50) REFERENCES listas_precio(id),
  aprobado BOOLEAN NOT NULL DEFAULT false,
  activo BOOLEAN NOT NULL DEFAULT true,
  notas_admin TEXT NOT NULL DEFAULT '',
  permisos TEXT NOT NULL DEFAULT '',
  secciones_permitidas TEXT NOT NULL DEFAULT '',
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS secciones (
  id SERIAL PRIMARY KEY,
  nombre VARCHAR(100) NOT NULL,
  slug VARCHAR(50) UNIQUE NOT NULL,
  descripcion TEXT NOT NULL DEFAULT '',
  color VARCHAR(20) NOT NULL DEFAULT '#2563eb',
  whatsapp VARCHAR(30) NOT NULL DEFAULT '',
  cbu TEXT NOT NULL DEFAULT '',
  direccion_despacho TEXT NOT NULL DEFAULT '',
  metodos_pago TEXT NOT NULL DEFAULT '',
  activa BOOLEAN NOT NULL DEFAULT true,
  requiere_aprobacion BOOLEAN NOT NULL DEFAULT false,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS productos (
  id SERIAL PRIMARY KEY,
  nombre VARCHAR(300) NOT NULL DEFAULT '',
  categoria VARCHAR(200) NOT NULL,
  modelo VARCHAR(300) NOT NULL,
  precio_base NUMERIC(12,2) NOT NULL DEFAULT 0,
  precio_original NUMERIC(12,2) NOT NULL DEFAULT 0,
  stock INT NOT NULL DEFAULT 0,
  stock_minimo INT NOT NULL DEFAULT 0,
  imagen TEXT NOT NULL DEFAULT '',
  notas TEXT NOT NULL DEFAULT '',
  compatibilidad TEXT NOT NULL DEFAULT '',
  seccion_id INT REFERENCES secciones(id) DEFAULT 1,
  marca VARCHAR(100) NOT NULL DEFAULT '',
  compra_minima_unidades INT NOT NULL DEFAULT 1,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS precios_fijos (
  id SERIAL PRIMARY KEY,
  producto_id INT NOT NULL REFERENCES productos(id) ON DELETE CASCADE,
  lista_precio_id VARCHAR(50) NOT NULL REFERENCES listas_precio(id),
  precio_fijo NUMERIC(12,2) NOT NULL DEFAULT 0,
  UNIQUE(producto_id, lista_precio_id)
);

CREATE TABLE IF NOT EXISTS pedidos (
  id SERIAL PRIMARY KEY,
  usuario_id INT REFERENCES usuarios(id),
  cliente_nombre VARCHAR(200) NOT NULL DEFAULT '',
  cliente_telefono VARCHAR(50) NOT NULL DEFAULT '',
  tipo_entrega VARCHAR(20) NOT NULL DEFAULT 'retiro',
  direccion_envio TEXT NOT NULL DEFAULT '',
  estado VARCHAR(30) NOT NULL DEFAULT 'pendiente',
  estado_pago VARCHAR(30) NOT NULL DEFAULT 'pendiente',
  notas TEXT NOT NULL DEFAULT '',
  total NUMERIC(12,2) NOT NULL DEFAULT 0,
  lista_precio_nombre VARCHAR(50) NOT NULL DEFAULT '',
  metodo_pago VARCHAR(50) NOT NULL DEFAULT '',
  tipo VARCHAR(20) NOT NULL DEFAULT 'pedido',
  archivado BOOLEAN NOT NULL DEFAULT false,
  asignado_usuario_id INT REFERENCES usuarios(id),
  seccion_id INT REFERENCES secciones(id),
  costo_envio NUMERIC(12,2) NOT NULL DEFAULT 0,
  cupon_codigo VARCHAR(50) NOT NULL DEFAULT '',
  cupon_descuento NUMERIC(12,2) NOT NULL DEFAULT 0,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS pedido_items (
  id SERIAL PRIMARY KEY,
  pedido_id INT NOT NULL REFERENCES pedidos(id) ON DELETE CASCADE,
  producto_id INT REFERENCES productos(id),
  nombre_producto VARCHAR(300) NOT NULL,
  cantidad INT NOT NULL DEFAULT 1,
  precio_unitario NUMERIC(12,2) NOT NULL DEFAULT 0,
  subtotal NUMERIC(12,2) NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS historial_precios (
  id SERIAL PRIMARY KEY,
  producto_id INT REFERENCES productos(id) ON DELETE CASCADE,
  precio_anterior NUMERIC(12,2),
  precio_nuevo NUMERIC(12,2),
  usuario_id INT REFERENCES usuarios(id),
  usuario_nombre VARCHAR(200) NOT NULL DEFAULT '',
  tipo VARCHAR(30) NOT NULL DEFAULT 'manual',
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS cupones (
  id SERIAL PRIMARY KEY,
  codigo VARCHAR(50) UNIQUE NOT NULL,
  tipo VARCHAR(30) NOT NULL DEFAULT 'porcentaje',
  valor NUMERIC(12,2) NOT NULL DEFAULT 0,
  compra_minima NUMERIC(12,2) NOT NULL DEFAULT 0,
  uso_maximo INT NOT NULL DEFAULT 0,
  usos_actuales INT NOT NULL DEFAULT 0,
  fecha_inicio DATE,
  fecha_fin DATE,
  secciones_ids TEXT NOT NULL DEFAULT '',
  categoria VARCHAR(200) NOT NULL DEFAULT '',
  producto_id INT REFERENCES productos(id) ON DELETE SET NULL,
  medio_pago VARCHAR(100) NOT NULL DEFAULT '',
  activo BOOLEAN NOT NULL DEFAULT true,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS paginas_info (
  id SERIAL PRIMARY KEY,
  titulo VARCHAR(200) NOT NULL,
  slug VARCHAR(100) NOT NULL,
  contenido TEXT NOT NULL DEFAULT '',
  seccion_id INT REFERENCES secciones(id),
  orden INT NOT NULL DEFAULT 0,
  visible BOOLEAN NOT NULL DEFAULT true,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS badges (
  id SERIAL PRIMARY KEY,
  icono VARCHAR(10) NOT NULL DEFAULT '⭐',
  texto VARCHAR(200) NOT NULL DEFAULT '',
  orden INT NOT NULL DEFAULT 0,
  visible BOOLEAN NOT NULL DEFAULT true
);

CREATE TABLE IF NOT EXISTS config_envio (
  id SERIAL PRIMARY KEY,
  seccion_id INT REFERENCES secciones(id) UNIQUE,
  metodo VARCHAR(30) NOT NULL DEFAULT 'manual',
  costo_fijo NUMERIC(12,2) NOT NULL DEFAULT 0,
  gratis_desde NUMERIC(12,2) NOT NULL DEFAULT 0,
  zonas JSONB NOT NULL DEFAULT '[]'
);

-- Indexes
CREATE INDEX IF NOT EXISTS idx_productos_categoria ON productos(categoria);
CREATE INDEX IF NOT EXISTS idx_productos_seccion ON productos(seccion_id);
CREATE INDEX IF NOT EXISTS idx_productos_marca ON productos(marca);
CREATE INDEX IF NOT EXISTS idx_pedidos_usuario ON pedidos(usuario_id);
CREATE INDEX IF NOT EXISTS idx_pedidos_estado ON pedidos(estado);
CREATE INDEX IF NOT EXISTS idx_pedidos_seccion ON pedidos(seccion_id);
CREATE INDEX IF NOT EXISTS idx_cupones_codigo ON cupones(codigo);
CREATE INDEX IF NOT EXISTS idx_cupones_producto ON cupones(producto_id);

-- Default sections
INSERT INTO secciones (nombre, slug, descripcion, color) VALUES
  ('Local','local','Venta presencial','#2563eb'),
  ('Dropshipping','dropshipping','Envío directo','#7c3aed'),
  ('Mayorista','mayorista','Venta por mayor','#059669')
ON CONFLICT (slug) DO NOTHING;
