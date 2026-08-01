const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const fs = require('fs');
const path = require('path');

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false,
});

async function init() {
  try {
    // 1. Aplicar schema
    const schema = fs.readFileSync(path.join(__dirname, 'schema-v2.sql'), 'utf8');
    await pool.query(schema);
    console.log('[DB] Schema applied');

    // 2. Crear listas de precio PRIMERO
    const { rows } = await pool.query('SELECT COUNT(*) FROM listas_precio');
    if (parseInt(rows[0].count) === 0) {
      const listas = [
        ['may_aaa', 'Mayorista AAA', 1.00, 0, '#2563eb'],
        ['may_aa', 'Mayorista AA', 1.15, 15, '#7c3aed'],
        ['may_a', 'Mayorista A', 1.35, 35, '#059669'],
        ['minorista', 'Minorista', 1.70, 70, '#d97706'],
        ['dropshipping', 'Dropshipping', 2.20, 120, '#dc2626'],
      ];
      for (const [id, nombre, mult, pct, color] of listas) {
        await pool.query('INSERT INTO listas_precio (id,nombre,multiplicador,porcentaje,color) VALUES ($1,$2,$3,$4,$5) ON CONFLICT DO NOTHING',
          [id, nombre, mult, pct, color]);
      }
      console.log('[DB] Default listas created');
    }

    // 3. Crear admin DESPUÉS de las listas
    const hash = await bcrypt.hash('admin', 10);
    await pool.query(`INSERT INTO usuarios (nombre,usuario,password,rol,aprobado,activo,lista_precio_id)
      VALUES ('Administrador','admin',$1,'admin',true,true,'may_aaa') ON CONFLICT DO NOTHING`, [hash]);
    console.log('[DB] Admin user ready');

    await pool.end();
    console.log('[DB] Init complete');
  } catch (e) { console.error('[DB] Init error:', e.message); process.exit(1); }
}

init();
