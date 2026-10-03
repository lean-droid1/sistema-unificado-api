// ═══════════════════════════════════════════════════════════════
// checkout.js — Precios, envíos, cupones y totales calculados en el SERVIDOR.
//
// La web muestra estos mismos números, pero el pedido se guarda SIEMPRE con lo
// que calcula este archivo (nunca con lo que manda el navegador). Así nadie
// puede cambiar un precio, un descuento o un envío desde el navegador.
//
// Reglas de precio (iguales a las de la web, ver precioCliente en App.jsx):
//   1. Variante: su precio (u oferta si es menor). Promos solo si es en pesos.
//   2. Preventa: precio base con el % de descuento de reserva.
//   3. Lista de precios del cliente: precio fijo de la lista, o base × multiplicador.
//   4. Oferta del producto si es menor.
//   5. Revendedor (solo sección dropshipping): su % de descuento, sin promos.
//   6. Si no, la mejor promoción activa.
//
// Envíos: cada tienda (sección) cotiza su propio envío. Hoy usa los métodos
// cargados en el panel; los correos (Andreani, Envia, etc.) se enchufan en
// PROVEEDORES_ENVIO y cotizan solos con el código postal.
// ═══════════════════════════════════════════════════════════════

const round2 = (n) => Math.round((Number(n) || 0) * 100) / 100;
const num = (n) => Number(n) || 0;

class CheckoutError extends Error {
  constructor(msg, status = 400) { super(msg); this.status = status; }
}

// Misma lógica que aplicarPromo() de la web: entre todas las promos que aplican, la que más baja el precio.
function aplicarPromo(base, product, promos, seccionId, moneda) {
  if ((moneda && moneda !== 'ARS') || !(base > 0) || !product || !promos || !promos.length) return null;
  const secId = seccionId != null ? String(seccionId) : (product.seccion_id != null ? String(product.seccion_id) : '');
  let mejor = null;
  for (const pr of promos) {
    if (pr.tipo !== 'porcentaje' && pr.tipo !== 'monto_fijo') continue;
    const secs = String(pr.secciones_ids || '').split(',').map(s => s.trim()).filter(Boolean);
    if (secs.length && !(secId && secs.includes(secId))) continue;
    const prods = String(pr.productos_ids || '').split(',').map(s => s.trim()).filter(Boolean);
    if (prods.length && !prods.includes(String(product.id))) continue;
    if (pr.categoria && pr.categoria !== product.categoria) continue;
    let final = base;
    if (pr.tipo === 'porcentaje') final = Math.round(base * (1 - num(pr.valor) / 100));
    else final = Math.max(0, base - num(pr.valor));
    if (final < base && (!mejor || final < mejor.final)) mejor = { final, original: base, nombre: pr.nombre };
  }
  return mejor;
}

// Precio de una variante (usa la oferta si es válida). Compatibilidad con variantes viejas sin precio absoluto.
function precioVariante(v, base) {
  const pr = num(v.precio), of = num(v.precio_oferta);
  if (pr > 0) return (of > 0 && of < pr) ? of : pr;
  return num(base) + num(v.precio_extra);
}

// Precio que le corresponde a ESTE cliente por ESTE producto. Devuelve { precio, moneda }.
function precioCliente(p, { lista, precioFijo, promos, user, seccionSlug, variante }) {
  const base = num(p.precio_base);
  if (variante) {
    const moneda = variante.moneda || 'ARS';
    const pv = precioVariante(variante, base);
    const promo = aplicarPromo(pv, p, promos, p.seccion_id, moneda);
    return { precio: promo ? promo.final : pv, moneda };
  }
  const moneda = p.moneda && p.moneda !== 'ARS' ? p.moneda : 'ARS';
  if (p.es_preventa) {
    const pct = num(p.preventa_descuento_pct);
    return { precio: pct > 0 ? Math.round(base * (1 - pct / 100)) : base, moneda };
  }
  let precio = base;
  if (lista) {
    if (num(precioFijo) > 0) precio = num(precioFijo);
    else {
      const m = num(lista.multiplicador);
      precio = round2(base * (m > 0 && m <= 10 ? m : 1));
    }
  }
  const of = num(p.precio_oferta);
  if (of > 0 && of < precio) precio = of;
  if (seccionSlug === 'dropshipping' && user && user.es_revendedor && num(user.descuento_revendedor) > 0) {
    return { precio: Math.round(precio * (1 - num(user.descuento_revendedor) / 100)), moneda };
  }
  const promo = aplicarPromo(precio, p, promos, p.seccion_id, moneda);
  return { precio: promo ? promo.final : precio, moneda };
}

// ═══ PROVEEDORES DE ENVÍO (correos) ═══
// Para sumar uno nuevo (Envia.com, Correo Argentino, etc.) agregar un objeto con:
//   id, nombre, configurado(), cotizar({ cpOrigen, cpDestino, pesoKg, volumenCm3, valor }) → [{ id, nombre, costo, tiempo_estimado }]
const ANDREANI_API = process.env.ANDREANI_API || 'https://apis.andreani.com';
async function andreaniToken() {
  const user = process.env.ANDREANI_USER, pass = process.env.ANDREANI_PASS;
  if (!user || !pass) return null;
  const r = await fetch(`${ANDREANI_API}/login`, { headers: { authorization: 'Basic ' + Buffer.from(`${user}:${pass}`).toString('base64') } });
  return r.headers.get('x-authorization-token');
}
const PROVEEDORES_ENVIO = [
  {
    id: 'andreani',
    nombre: 'Andreani',
    configurado: () => !!(process.env.ANDREANI_USER && process.env.ANDREANI_PASS && (process.env.ANDREANI_CLIENTE || process.env.ANDREANI_NRO_CLIENTE)),
    async cotizar({ cpOrigen, cpDestino, pesoKg, volumenCm3, valor }) {
      const token = await andreaniToken();
      if (!token) return [];
      const body = {
        cpDestino, contrato: process.env.ANDREANI_CONTRATO || 'AND00EST',
        cliente: process.env.ANDREANI_CLIENTE || process.env.ANDREANI_NRO_CLIENTE,
        sucursalOrigen: '', cpOrigen,
        bultos: [{ valorDeclarado: Math.max(1, Math.round(valor)), volumen: Math.max(1, Math.round(volumenCm3)), kilos: Math.max(0.1, pesoKg) }],
      };
      const r = await fetch(`${ANDREANI_API}/v1/tarifas`, { method: 'POST', headers: { 'x-authorization-token': token, 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
      if (!r.ok) return [];
      const d = await r.json();
      const total = num(d?.tarifaConIva?.total ?? d?.tarifaConIva ?? d?.total);
      if (!(total > 0)) return [];
      return [{ id: 'andreani:domicilio', nombre: 'Andreani — envío a domicilio', costo: Math.round(total), tiempo_estimado: '2 a 5 días hábiles' }];
    },
  },
];

// Cotización del dólar para mínimos en USD y precios en dólares.
// Fuente configurable (configuracion.usd_fuente): blue (por defecto) | oficial | manual (usd_manual).
const _cotCache = {};
async function cotizacionDolar(db, tenantId) {
  const { rows } = await db.query("SELECT clave, valor FROM configuracion WHERE tenant_id=$1 AND clave IN ('usd_fuente','usd_manual','dolar_blue')", [tenantId]).catch(() => ({ rows: [] }));
  const cfg = {}; rows.forEach(r => { cfg[r.clave] = r.valor; });
  const fuente = ['oficial', 'manual'].includes(cfg.usd_fuente) ? cfg.usd_fuente : 'blue';
  if (fuente === 'manual' && num(cfg.usd_manual) > 0) return { valor: num(cfg.usd_manual), fuente: 'manual' };
  const tipo = fuente === 'oficial' ? 'oficial' : 'blue';
  const hit = _cotCache[tipo];
  if (hit && Date.now() - hit.ts < 15 * 60 * 1000) return { valor: hit.valor, fuente: tipo, actualizado: hit.fecha };
  try {
    const r = await fetch(`https://dolarapi.com/v1/dolares/${tipo}`, { signal: AbortSignal.timeout(6000) });
    if (r.ok) {
      const d = await r.json(); const v = num(d.venta);
      if (v > 0) { _cotCache[tipo] = { valor: v, ts: Date.now(), fecha: d.fechaActualizacion || null }; return { valor: v, fuente: tipo, actualizado: d.fechaActualizacion || null }; }
    }
  } catch (e) { /* sin conexión: usa lo último que se obtuvo o el valor manual */ }
  if (hit) return { valor: hit.valor, fuente: tipo, actualizado: hit.fecha, viejo: true };
  const resp = num(cfg.usd_manual) || num(cfg.dolar_blue);
  return resp > 0 ? { valor: resp, fuente: 'respaldo' } : { valor: 0, fuente: 'sin_datos' };
}

function createCheckout(pool) {
  // Todo lo que depende del cliente y de la tienda (una sola vez por cotización)
  async function contexto(db, tenantId, userId) {
    const [u, promos, secs, cfg] = await Promise.all([
      userId ? db.query('SELECT id, rol, permisos, lista_precio_id, es_revendedor, descuento_revendedor, mayorista, activo FROM usuarios WHERE id=$1 AND tenant_id=$2', [userId, tenantId]) : { rows: [] },
      db.query('SELECT * FROM promociones WHERE tenant_id=$1 AND activo=true AND (fecha_desde IS NULL OR fecha_desde<=CURRENT_DATE) AND (fecha_hasta IS NULL OR fecha_hasta>=CURRENT_DATE)', [tenantId]),
      db.query('SELECT id, nombre, slug, cp_origen, ignorar_stock, permitir_sin_stock, requiere_aprobacion FROM secciones WHERE tenant_id=$1', [tenantId]),
      db.query("SELECT clave, valor FROM configuracion WHERE tenant_id=$1 AND (clave LIKE 'envio_gratis_desde_%' OR clave LIKE 'compra_minima_%' OR clave LIKE 'min_aplica_retiro_%')", [tenantId]),
    ]);
    const user = u.rows[0] || null;
    let lista = null; const pf = {};
    if (user && user.lista_precio_id) {
      const l = await db.query('SELECT id, multiplicador FROM listas_precio WHERE id=$1 AND tenant_id=$2', [user.lista_precio_id, tenantId]);
      lista = l.rows[0] || null;
      if (lista) {
        const f = await db.query('SELECT producto_id, precio_fijo FROM precios_fijos WHERE lista_precio_id=$1 AND tenant_id=$2', [lista.id, tenantId]);
        f.rows.forEach(r => { pf[r.producto_id] = r.precio_fijo; });
      }
    }
    const config = {}; cfg.rows.forEach(r => { config[r.clave] = r.valor; });
    const secciones = {}; secs.rows.forEach(s => { secciones[s.id] = s; });
    const esStaff = !!user && (user.rol === 'admin' || (user.rol === 'subadmin' && String(user.permisos || '').split(',').includes('pedidos')));
    // Tiendas con aprobación (mayorista): solo clientes autorizados o el equipo
    const accesoMayorista = !!user && user.activo !== false && (user.rol === 'admin' || user.rol === 'subadmin' || !!user.mayorista);
    return { tenantId, user, lista, pf, promos: promos.rows, secciones, config, esStaff, accesoMayorista };
  }

  // Normaliza los ítems que manda la web y les pone el precio del servidor
  // Con { avisos: [] } (solo al cotizar) no corta: anota lo que falta y lo deja afuera, así el carrito se corrige solo.
  async function preciarItems(db, ctx, itemsIn, { permitirOcultos = false, avisos = null } = {}) {
    const items = (Array.isArray(itemsIn) ? itemsIn : []).slice(0, 500).map(i => ({
      producto_id: parseInt(i.producto_id ?? i.id, 10),
      variante_id: i.variante_id ? parseInt(i.variante_id, 10) : null,
      cantidad: Math.min(10000, Math.max(1, parseInt(i.cantidad ?? i.qty, 10) || 1)),
    })).filter(i => i.producto_id > 0);
    if (!items.length) return [];
    const ids = [...new Set(items.map(i => i.producto_id))];
    const varIds = [...new Set(items.map(i => i.variante_id).filter(Boolean))];
    const { rows: prods } = await db.query(
      `SELECT id, seccion_id, nombre, modelo, categoria, imagen, precio_base, precio_oferta, moneda, stock, permitir_sin_stock, es_digital,
              es_preventa, preventa_cupo, preventa_reservado, preventa_descuento_pct, envio_gratis, visible, usa_variantes, peso, alto, ancho, largo
       FROM productos WHERE id = ANY($1::int[]) AND tenant_id=$2`, [ids, ctx.tenantId]);
    const prodMap = {}; prods.forEach(p => { prodMap[p.id] = p; });
    const varMap = {};
    if (varIds.length) {
      const { rows: vs } = await db.query('SELECT id, producto_id, nombre, valor, precio, precio_oferta, precio_extra, moneda, stock, combinacion FROM variantes WHERE id = ANY($1::int[]) AND tenant_id=$2', [varIds, ctx.tenantId]);
      vs.forEach(v => { varMap[v.id] = v; });
    }
    const falla = (i, tipo, msg) => { if (avisos) { avisos.push({ producto_id: i.producto_id, variante_id: i.variante_id, tipo, mensaje: msg }); return true; } throw new CheckoutError(msg); };
    const out = [];
    for (const i of items) {
      const p = prodMap[i.producto_id];
      if (!p || (!p.visible && !permitirOcultos)) { falla(i, 'no_disponible', p ? `"${p.nombre || p.modelo}" ya no está disponible.` : 'Un producto del carrito ya no está disponible.'); continue; }
      if (ctx.secciones[p.seccion_id] && ctx.secciones[p.seccion_id].requiere_aprobacion && !ctx.accesoMayorista) {
        falla(i, 'no_disponible', `"${p.nombre || p.modelo}" es de la lista mayorista: solo pueden comprarlo clientes autorizados.`); continue;
      }
      let v = null;
      if (i.variante_id) {
        v = varMap[i.variante_id];
        if (!v || v.producto_id !== p.id) { falla(i, 'no_disponible', `La opción elegida de "${p.nombre || p.modelo}" ya no existe. Volvé a elegirla.`); continue; }
      } else if (p.usa_variantes) {
        falla(i, 'elegir_opcion', `Elegí las opciones de "${p.nombre || p.modelo}" antes de comprar.`); continue;
      }
      // Stock (mismo criterio que al crear el pedido): al cotizar se avisa y se ajusta la cantidad
      const secS = ctx.secciones[p.seccion_id] || {};
      const sinLimite = v || p.es_preventa || p.permitir_sin_stock || p.es_digital || secS.permitir_sin_stock || secS.ignorar_stock;
      if (avisos && !sinLimite && num(p.stock) < i.cantidad) {
        if (num(p.stock) <= 0) { avisos.push({ producto_id: p.id, variante_id: null, tipo: 'sin_stock', disponible: 0, mensaje: `"${p.nombre || p.modelo}" se quedó sin stock.` }); continue; }
        avisos.push({ producto_id: p.id, variante_id: null, tipo: 'stock', disponible: num(p.stock), mensaje: `"${p.nombre || p.modelo}": solo quedan ${num(p.stock)}, ajustamos la cantidad.` });
        i.cantidad = num(p.stock);
      }
      const sec = ctx.secciones[p.seccion_id];
      const { precio, moneda } = precioCliente(p, {
        lista: ctx.lista, precioFijo: ctx.pf[p.id], promos: ctx.promos, user: ctx.user, seccionSlug: sec && sec.slug, variante: v,
      });
      const label = v ? ((v.combinacion && Object.keys(v.combinacion).length) ? Object.values(v.combinacion).join(' / ') : `${v.nombre ? v.nombre + ': ' : ''}${v.valor || ''}`.trim()) : '';
      out.push({
        producto_id: p.id, variante_id: v ? v.id : null, variante_label: label, cantidad: i.cantidad,
        precio_unitario: round2(precio), precio_base: num(p.precio_base), moneda,
        nombre_producto: p.nombre || p.modelo || '', categoria: p.categoria || '', modelo: p.modelo || '', imagen: p.imagen || '',
        seccion_id: p.seccion_id, envio_gratis: !!p.envio_gratis, es_digital: !!p.es_digital, _preventa: !!p.es_preventa,
        peso: num(p.peso), alto: num(p.alto), ancho: num(p.ancho), largo: num(p.largo),
        _prod: p, _var: v,
      });
    }
    return out;
  }

  async function opcionesEnvio(db, ctx, sec, itemsArs, subtotal, cp) {
    const umbral = num(ctx.config[`envio_gratis_desde_${sec.id}`]);
    const fisicos = itemsArs.filter(i => !i.es_digital);
    const todosGratis = fisicos.length > 0 && fisicos.every(i => i.envio_gratis);
    const gratisSeccion = (umbral > 0 && subtotal >= umbral) || todosGratis;
    const { rows } = await db.query('SELECT * FROM metodos_envio_custom WHERE activo=true AND tenant_id=$1 AND (seccion_id=$2 OR seccion_id IS NULL) ORDER BY orden, id', [ctx.tenantId, sec.id]);
    // tipo: 'fijo' (cobra su precio), 'gratis' (siempre sin cargo) o 'a_cotizar' (el costo se pasa después).
    // Un método 'fijo' sin precio cargado también es "a cotizar": nunca se muestra como gratis por error.
    const opciones = rows.map(m => {
      const esGratis = m.tipo === 'gratis';
      const sinPrecio = !esGratis && (m.tipo === 'a_cotizar' || num(m.precio) <= 0);
      const original = esGratis || sinPrecio ? 0 : num(m.precio);
      const gd = num(m.gratis_desde);
      const bonificado = !esGratis && (gratisSeccion || (gd > 0 && subtotal >= gd));
      const aCotizar = sinPrecio && !bonificado;
      return { id: `custom:${m.id}`, nombre: m.nombre, descripcion: m.descripcion || '', tiempo_estimado: m.tiempo_estimado || '', icono: m.icono || 'truck', costo: bonificado || aCotizar ? 0 : original, costo_original: original, gratis: esGratis || bonificado, a_cotizar: aCotizar, proveedor: 'propio' };
    });
    const cpLimpio = String(cp || '').replace(/\D/g, '').slice(0, 8);
    if (cpLimpio.length >= 4) {
      const pesoKg = fisicos.reduce((s, i) => s + (i.peso > 0 ? i.peso : 0.5) * i.cantidad, 0) || 0.5;
      const volumenCm3 = fisicos.reduce((s, i) => s + ((i.alto * i.ancho * i.largo) > 0 ? i.alto * i.ancho * i.largo : 1000) * i.cantidad, 0) || 1000;
      for (const prov of PROVEEDORES_ENVIO) {
        if (!prov.configurado()) continue;
        try {
          const cot = await prov.cotizar({ cpOrigen: sec.cp_origen || '1888', cpDestino: cpLimpio, pesoKg, volumenCm3, valor: subtotal });
          for (const c of cot) opciones.push({ id: c.id, nombre: c.nombre, descripcion: '', tiempo_estimado: c.tiempo_estimado || '', icono: 'truck', costo: gratisSeccion ? 0 : num(c.costo), costo_original: num(c.costo), gratis: gratisSeccion, proveedor: prov.id });
        } catch (e) { console.log(`[envio] ${prov.id} no cotizó:`, e.message); }
      }
    }
    return { opciones, gratis_seccion: gratisSeccion, umbral, falta_para_gratis: umbral > 0 && !gratisSeccion ? round2(umbral - subtotal) : 0 };
  }

  // Valida un cupón contra los ítems de UNA sección. Devuelve { descuento, envio_gratis } o tira CheckoutError.
  async function evaluarCupon(db, ctx, codigo, { seccion_id, items, subtotal, metodo_pago, final = false }) {
    const { rows } = await db.query('SELECT * FROM cupones WHERE UPPER(codigo)=UPPER($1) AND activo=true AND tenant_id=$2', [String(codigo || '').trim(), ctx.tenantId]);
    const c = rows[0];
    if (!c) throw new CheckoutError('Cupón no válido');
    if (c.uso_maximo > 0 && c.usos_actuales >= c.uso_maximo) throw new CheckoutError('Cupón agotado');
    if (c.fecha_desde && new Date() < new Date(c.fecha_desde)) throw new CheckoutError('El cupón todavía no está vigente');
    if (c.fecha_hasta && new Date(new Date(c.fecha_hasta).getTime() + 86400000) < new Date()) throw new CheckoutError('El cupón está vencido');
    if (c.solo_primera_compra) {
      if (!ctx.user) throw new CheckoutError('Iniciá sesión para usar este cupón');
      const { rows: prev } = await db.query("SELECT COUNT(*)::int AS n FROM pedidos WHERE usuario_id=$1 AND tipo='pedido' AND tenant_id=$2 AND LOWER(COALESCE(estado,'')) NOT IN ('cancelado','anulado')", [ctx.user.id, ctx.tenantId]);
      if (prev[0].n > 0) throw new CheckoutError('Este cupón es solo para la primera compra');
    }
    const sids = String(c.secciones_ids || '').split(',').map(Number).filter(Boolean);
    if (sids.length && !sids.includes(Number(seccion_id))) throw new CheckoutError('El cupón no aplica a esta tienda');
    // Al cotizar todavía puede no haber medio de pago elegido; al crear el pedido tiene que coincidir sí o sí
    if (c.metodo_pago && (metodo_pago || final) && c.metodo_pago !== metodo_pago) throw new CheckoutError(`El cupón solo vale pagando con ${c.metodo_pago}`);
    const { rows: cp } = await db.query('SELECT producto_id FROM cupon_productos WHERE cupon_id=$1', [c.id]);
    const pids = cp.map(r => r.producto_id);
    const elegibles = items.filter(i => (!pids.length || pids.includes(i.producto_id)) && (!c.categoria || i.categoria === c.categoria));
    if (!elegibles.length) throw new CheckoutError('El cupón no aplica a estos productos');
    if (num(c.monto_minimo) > 0 && subtotal < num(c.monto_minimo)) throw new CheckoutError(`El cupón pide una compra mínima de $${num(c.monto_minimo).toLocaleString('es-AR')}`);
    const baseDesc = (pids.length || c.categoria) ? elegibles.reduce((s, i) => s + i.precio_unitario * i.cantidad, 0) : subtotal;
    let descuento = 0, envioGratis = false;
    if (c.tipo === 'porcentaje') descuento = Math.round(baseDesc * num(c.valor) / 100);
    else if (c.tipo === 'monto_fijo') descuento = num(c.valor);
    else if (c.tipo === 'envio_gratis') envioGratis = true;
    return { codigo: c.codigo, cupon_id: c.id, tipo: c.tipo, valor: num(c.valor), descuento: Math.min(round2(descuento), subtotal), envio_gratis: envioGratis };
  }

  // Cotiza el carrito completo. body = { secciones:[{seccion_id, items, envio_id}], entrega:{tipo, cp}, cupon, metodo_pago }
  async function cotizarCarrito(db, tenantId, userId, body, opts = {}) {
    const ctx = opts.ctx || await contexto(db, tenantId, userId);
    // Cotización del dólar: solo si alguna tienda tiene el mínimo en USD o muestra precios en dólares
    const usaUsd = Object.keys(ctx.config).some(k => (k.startsWith('compra_minima_moneda_') && ctx.config[k] === 'USD'));
    const usd = usaUsd ? await cotizacionDolar(db, tenantId) : null;
    const entregaTipo = body?.entrega?.tipo === 'retiro' ? 'retiro' : 'envio';
    const cp = body?.entrega?.cp || '';
    const cuponCodigo = String(body?.cupon || '').trim();
    // Agrupar por la sección REAL de cada producto (la web puede mandar todo junto o separado)
    const todos = [];
    const envioElegido = {};
    for (const s of (Array.isArray(body?.secciones) ? body.secciones : [])) {
      for (const it of (s.items || [])) todos.push(it);
      if (s.envio_id && s.seccion_id != null) envioElegido[String(s.seccion_id)] = String(s.envio_id);
      if (s.metodo_envio && s.seccion_id != null && !s.envio_id) envioElegido[`nombre:${s.seccion_id}`] = String(s.metodo_envio);
    }
    const avisos = opts.cotizacion ? [] : null;
    const preciados = await preciarItems(db, ctx, todos, { ...opts, avisos });
    const porSec = new Map();
    for (const it of preciados) {
      const k = it.seccion_id;
      if (!porSec.has(k)) porSec.set(k, []);
      porSec.get(k).push(it);
    }
    const resultado = []; const errores = [];
    let cuponInfo = cuponCodigo ? { codigo: cuponCodigo, ok: false, error: null, seccion_id: null } : null;
    for (const [secId, items] of porSec) {
      const sec = ctx.secciones[secId] || { id: secId, nombre: 'Tienda', slug: '', cp_origen: '1888' };
      const ars = items.filter(i => i.moneda === 'ARS');
      const subtotal = round2(ars.reduce((s, i) => s + i.precio_unitario * i.cantidad, 0));
      const subtotalUsdt = round2(items.filter(i => i.moneda !== 'ARS').reduce((s, i) => s + i.precio_unitario * i.cantidad, 0));
      const requiereEnvio = items.some(i => !i.es_digital);
      // Cupón: se aplica a la primera tienda donde sea válido
      let descuento = 0, cuponAplicado = null, envioGratisCupon = false;
      if (cuponInfo && !cuponInfo.ok && subtotal > 0) {
        try {
          const r = await evaluarCupon(db, ctx, cuponCodigo, { seccion_id: secId, items: ars, subtotal, metodo_pago: body?.metodo_pago, final: !opts.cotizacion });
          descuento = r.descuento; envioGratisCupon = r.envio_gratis; cuponAplicado = r.codigo;
          cuponInfo = { ...cuponInfo, ok: true, error: null, seccion_id: secId, codigo: r.codigo, descuento: r.descuento, tipo: r.tipo };
        } catch (e) { if (!cuponInfo.error) cuponInfo.error = e.message; }
      }
      // Envío
      let envio = { opciones: [], gratis_seccion: false, umbral: 0, falta_para_gratis: 0 };
      let elegido = null, costoEnvio = 0;
      if (requiereEnvio) {
        envio = await opcionesEnvio(db, ctx, sec, ars, subtotal, cp);
        if (envioGratisCupon) envio.opciones = envio.opciones.map(o => ({ ...o, costo: 0, gratis: true, a_cotizar: false }));
        if (entregaTipo === 'envio') {
          const pedido = envioElegido[String(secId)];
          const porNombre = envioElegido[`nombre:${secId}`];
          elegido = envio.opciones.find(o => o.id === pedido) || (porNombre ? envio.opciones.find(o => o.nombre === porNombre) : null) || null;
          costoEnvio = elegido ? elegido.costo : 0;
        }
      }
      const total = round2(Math.max(0, subtotal - descuento) + costoEnvio);
      // Compra mínima en pesos o en dólares (en USD se cotiza al momento de cerrar el carrito)
      const minUsd = ctx.config[`compra_minima_moneda_${secId}`] === 'USD';
      const minBase = num(ctx.config[`compra_minima_${secId}`]);
      const min = minUsd ? (usd && usd.valor > 0 ? Math.round(minBase * usd.valor) : 0) : minBase;
      const minAplica = min > 0 && (entregaTipo === 'envio' || ctx.config[`min_aplica_retiro_${secId}`] === 'true');
      const faltaMinimo = minAplica && subtotal < min ? round2(min - subtotal) : 0;
      if (faltaMinimo > 0) errores.push({ seccion_id: secId, tipo: 'minimo', mensaje: minUsd
        ? `${sec.nombre}: la compra mínima${entregaTipo === 'envio' ? ' para envío' : ''} es de USD ${minBase.toLocaleString('es-AR')} (hoy $${min.toLocaleString('es-AR')} al dólar de $${num(usd && usd.valor).toLocaleString('es-AR')}).`
        : `${sec.nombre}: la compra mínima${entregaTipo === 'envio' ? ' para envío' : ''} es de $${min.toLocaleString('es-AR')}.` });
      if (entregaTipo === 'envio' && requiereEnvio && envio.opciones.length && !elegido) errores.push({ seccion_id: secId, tipo: 'envio', mensaje: `Elegí cómo querés recibir lo de ${sec.nombre}.` });
      resultado.push({
        seccion_id: secId, nombre: sec.nombre, slug: sec.slug,
        items: items.map(({ _prod, _var, peso, alto, ancho, largo, ...rest }) => rest),
        subtotal, subtotal_usdt: subtotalUsdt, descuento, cupon: cuponAplicado,
        requiere_envio: requiereEnvio, envio: { ...envio, elegido, costo: costoEnvio, a_cotizar: !!(elegido && elegido.a_cotizar), a_coordinar: entregaTipo === 'envio' && requiereEnvio && !envio.opciones.length },
        total, compra_minima: min, compra_minima_usd: minUsd ? minBase : null, falta_minimo: faltaMinimo,
        _items: items,
      });
    }
    if (cuponInfo && !cuponInfo.ok && !cuponInfo.error) cuponInfo.error = 'El cupón no aplica a estos productos';
    const totales = {
      subtotal: round2(resultado.reduce((s, r) => s + r.subtotal, 0)),
      descuento: round2(resultado.reduce((s, r) => s + r.descuento, 0)),
      envio: round2(resultado.reduce((s, r) => s + r.envio.costo, 0)),
      envio_a_cotizar: resultado.some(r => r.envio.a_cotizar),
      total: round2(resultado.reduce((s, r) => s + r.total, 0)),
      total_usdt: round2(resultado.reduce((s, r) => s + r.subtotal_usdt, 0)),
    };
    return { ctx, entrega: { tipo: entregaTipo, cp }, secciones: resultado, totales, cupon: cuponInfo, errores, avisos: avisos || [], usd };
  }

  // Versión para mandar a la web (sin datos internos)
  function publico(cot) {
    return {
      entrega: cot.entrega, totales: cot.totales, cupon: cot.cupon, errores: cot.errores, avisos: cot.avisos, usd: cot.usd || null,
      secciones: cot.secciones.map(({ _items, ...s }) => s),
    };
  }

  return { contexto, preciarItems, cotizarCarrito, evaluarCupon, publico, CheckoutError };
}

module.exports = { createCheckout, precioCliente, aplicarPromo, CheckoutError, PROVEEDORES_ENVIO, cotizacionDolar };
