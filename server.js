require('dotenv').config();
const express = require('express');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');
const cookieParser = require('cookie-parser');
const { createClient } = require('@supabase/supabase-js');

const app = express();
const PORT = process.env.PORT || 10000;

app.use(express.json());
app.use(cookieParser());
app.use(express.static('public'));

// -----------------------------------------------------------
// Supabase #1: ECIDs (la que me diste primero)
// Supabase #2: Usuarios + Créditos (la nueva)
// -----------------------------------------------------------
const sb1 = createClient(process.env.SUPABASE_URL_1, process.env.SUPABASE_ANON_KEY_1);
const sb2 = process.env.SUPABASE_URL_2 && process.env.SUPABASE_ANON_KEY_2
  ? createClient(process.env.SUPABASE_URL_2, process.env.SUPABASE_ANON_KEY_2)
  : null;

// -----------------------------------------------------------
// Helpers
// -----------------------------------------------------------
const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const ADMIN_EMAIL = 'admin@michi.local'; // cambia al email que quieras como admin

function setCookieHeader(res, token) {
  res.setHeader('Set-Cookie',
    `sesion=${token}; HttpOnly; Path=/; Max-Age=2592000; SameSite=Lax; Secure`);
}

// ---------- Usuario por cookie (solo en Supabase #2) ----------
async function usuarioPorCookie(req) {
  const token = req.cookies?.sesion;
  if (!token || !sb2) return null;
  const { data: ses } = await sb2
    .from('sesiones')
    .select('usuario_id')
    .eq('token', token)
    .gt('expira', new Date().toISOString())
    .single();
  if (!ses) return null;
  const { data: usr } = await sb2
    .from('usuarios')
    .select('id, email, creditos')
    .eq('id', ses.usuario_id)
    .single();
  return usr ? { id: usr.id, email: usr.email, creditos: usr.creditos } : null;
}

function setCookieHeader(res, token) {
  res.setHeader('Set-Cookie',
    `sesion=${token}; HttpOnly; Path=/; Max-Age=2592000; SameSite=Lax; Secure`);
}

async function nuevaSesion(sb, usuario_id) {
  const token = crypto.randomBytes(32).toString('hex');
  await sb.from('sesiones').insert({
    token,
    usuario_id,
    expira: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000).toISOString()
  });
  return token;
}

// ---------- Middleware admin ----------
async function requireAdmin(req, res, next) {
  const u = await usuarioPorCookie(req);
  if (!u) return res.status(401).json({ ok: false, error: 'No hay sesion' });
  if (u.email !== ADMIN_EMAIL) return res.status(403).json({ ok: false, error: 'Solo admin' });
  req.admin = u;
  next();
}

// -----------------------------------------------------------
// Auth (todo en Supabase #2)
// -----------------------------------------------------------
app.get('/api/sesion', async (req, res) => {
  const u = await usuarioPorCookie(req);
  res.json(u ? { ok: true, email: u.email, creditos: u.creditos } : { ok: false });
});

app.post('/api/registro', async (req, res) => {
  try {
    if (!sb2) return res.status(500).json({ ok: false, error: 'Supabase #2 no configurado' });
    const email = String((req.body && req.body.email) || '').trim().toLowerCase();
    const pass = String((req.body && req.body.pass) || '');
    if (!EMAIL_RE.test(email)) return res.status(400).json({ ok: false, error: 'Email invalido' });
    if (pass.length < 8) return res.status(400).json({ ok: false, error: 'Minimo 8 caracteres' });

    const hash = await bcrypt.hash(pass, 10);
    const { data: usr, error } = await sb2
      .from('usuarios')
      .insert({ email, pass_hash: hash })
      .select('id, email, creditos')
      .single();
    if (error) {
      if (error.code === '23505') return res.status(409).json({ ok: false, error: 'Ese email ya existe' });
      throw error;
    }
    const token = crypto.randomBytes(32).toString('hex');
    await sb2.from('sesiones').insert({
      token,
      usuario_id: usr.id,
      expira: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000).toISOString()
    });
    setCookieHeader(res, token);
    res.json({ ok: true, email: usr.email, creditos: usr.creditos });
  } catch (e) {
    console.error('Error registro:', e.message);
    res.status(500).json({ ok: false, error: 'Error del servidor' });
  }
});

app.post('/api/login', async (req, res) => {
  try {
    if (!sb2) return res.status(500).json({ ok: false, error: 'Supabase #2 no configurado' });
    const email = String((req.body && req.body.email) || '').trim().toLowerCase();
    const pass = String((req.body && req.body.pass) || '');
    const { data: usr } = await sb2
      .from('usuarios')
      .select('id, email, pass_hash, creditos')
      .eq('email', email)
      .single();
    if (!usr || !(await bcrypt.compare(pass, usr.pass_hash))) {
      return res.status(401).json({ ok: false, error: 'Email o contrasena incorrectos' });
    }
    const token = crypto.randomBytes(32).toString('hex');
    await sb2.from('sesiones').insert({
      token,
      usuario_id: usr.id,
      expira: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000).toISOString()
    });
    setCookieHeader(res, token);
    res.json({ ok: true, email: usr.email, creditos: usr.creditos });
  } catch (e) {
    console.error('Error login:', e.message);
    res.status(500).json({ ok: false, error: 'Error del servidor' });
  }
});

app.post('/api/logout', (_req, res) => {
  res.setHeader('Set-Cookie', 'sesion=; HttpOnly; Path=/; Max-Age=0; SameSite=Lax');
  res.json({ ok: true });
});

// -----------------------------------------------------------
// ECIDs -> se guardan en Supabase #1 (con usuario_id de la #2)
// Cada registro cuesta 3 créditos
// -----------------------------------------------------------
app.post('/api/ecid', async (req, res) => {
  try {
    const u = await usuarioPorCookie(req);
    if (!u) return res.status(401).json({ ok: false, error: 'No hay sesion' });
    const ecid = String((req.body && req.body.ecid) || '').trim();
    if (!/^0x[0-9a-fA-F]{1,40}$/.test(ecid)) {
      return res.status(400).json({ ok: false, error: 'ECID invalido' });
    }
    if ((u.creditos || 0) < 3) {
      return res.status(402).json({ ok: false, error: 'Créditos insuficientes (mín 3)' });
    }

    const { error: errUp } = await sb1.from('ecids').upsert(
      { usuario_id: u.id, ecid, ultima_vez: new Date().toISOString() },
      { onConflict: 'usuario_id,ecid', ignoreDuplicates: false }
    );
    if (errUp) throw errUp;

    const { data: upd } = await sb2
      .from('usuarios')
      .update({ creditos: u.creditos - 3 })
      .eq('id', u.id)
      .select('creditos')
      .single();
    res.json({ ok: true, ecid, creditos: upd.creditos });
  } catch (e) {
    console.error('Error guardando ECID:', e.message);
    res.status(500).json({ ok: false, error: 'Error de base de datos' });
  }
});

app.get('/api/ecids', async (req, res) => {
  try {
    const u = await usuarioPorCookie(req);
    if (!u) return res.status(401).json({ ok: false, error: 'No hay sesion' });
    const { data: rows } = await sb1
      .from('ecids')
      .select('ecid, creado, ultima_vez, veces')
      .eq('usuario_id', u.id)
      .order('ultima_vez', { ascending: false });
    const veces = rows.reduce((a, e) => a + (e.veces || 1), 0);
    res.json({ ok: true, email: u.email, creditos: u.creditos, total: rows.length, veces, ecids: rows });
  } catch (e) {
    console.error('Error leyendo ECIDs:', e.message);
    res.status(500).json({ ok: false, error: 'Error de base de datos' });
  }
});

// -----------------------------------------------------------
// ADMIN ROUTES (protegidos)
// -----------------------------------------------------------
app.get('/api/admin/stats', requireAdmin, async (req, res) => {
  try {
    const [{ count: totalUsuarios }, { data: creditosData }, { count: totalEcids }] = await Promise.all([
      sb2.from('usuarios').select('*', { count: 'exact', head: true }),
      sb2.from('usuarios').select('creditos'),
      sb1.from('ecids').select('*', { count: 'exact', head: true })
    ]);
    const totalCreditos = creditosData?.data?.reduce((a, u) => a + (u.creditos || 0), 0) || 0;
    res.json({ ok: true, totalUsuarios: totalUsuarios || 0, totalCreditos: totalCreditos || 0, totalEcids: totalEcids || 0 });
  } catch (e) {
    console.error('Error stats:', e.message);
    res.status(500).json({ ok: false, error: 'Error de base de datos' });
  }
});

app.get('/api/admin/usuarios', requireAdmin, async (req, res) => {
  try {
    const { data } = await sb2.from('usuarios').select('id, email, creditos, creado').order('creado', { ascending: false });
    res.json({ ok: true, usuarios: data || [] });
  } catch (e) {
    console.error('Error listando usuarios:', e.message);
    res.status(500).json({ ok: false, error: 'Error de base de datos' });
  }
});

app.get('/api/admin/ecids', requireAdmin, async (req, res) => {
  try {
    const { data } = await sb1
      .from('ecids')
      .select('id, ecid, usuario_id, creado, ultima_vez, veces')
      .order('ultima_vez', { ascending: false })
      .limit(500);
    // Enriquecer con email de usuario
    const userIds = [...new Set(data.map(e => e.usuario_id))];
    const { data: users } = await sb2.from('usuarios').select('id, email').in('id', userIds);
    const emailMap = Object.fromEntries((users || []).map(u => [u.id, u.email]));
    const ecids = data.map(e => ({ ...e, usuario_email: emailMap[e.usuario_id] || '—' }));
    res.json({ ok: true, ecids });
  } catch (e) {
    console.error('Error listando ECIDs:', e.message);
    res.status(500).json({ ok: false, error: 'Error de base de datos' });
  }
});

app.post('/api/admin/usuario', requireAdmin, async (req, res) => {
  try {
    const email = String((req.body && req.body.email) || '').trim().toLowerCase();
    const pass = String((req.body && req.body.pass) || '');
    const creditos = parseInt(req.body.creditos) || 0;
    if (!EMAIL_RE.test(email)) return res.status(400).json({ ok: false, error: 'Email invalido' });
    if (pass.length < 8) return res.status(400).json({ ok: false, error: 'Minimo 8 caracteres' });
    const hash = await bcrypt.hash(pass, 10);
    const { data: usr, error } = await sb2
      .from('usuarios')
      .insert({ email, pass_hash: hash, creditos })
      .select('id, email, creditos')
      .single();
    if (error) {
      if (error.code === '23505') return res.status(409).json({ ok: false, error: 'Ese email ya existe' });
      throw error;
    }
    res.json({ ok: true, usuario: usr });
  } catch (e) {
    console.error('Error creando usuario:', e.message);
    res.status(500).json({ ok: false, error: 'Error del servidor' });
  }
});

app.put('/api/admin/usuario/:id', requireAdmin, async (req, res) => {
  try {
    const id = req.params.id;
    const email = String((req.body && req.body.email) || '').trim().toLowerCase();
    const pass = String((req.body && req.body.pass) || '');
    const creditos = parseInt(req.body.creditos) || 0;
    const updates = { creditos };
    if (email) updates.email = email;
    if (pass) updates.pass_hash = await bcrypt.hash(pass, 10);
    const { data, error } = await sb2
      .from('usuarios')
      .update(updates)
      .eq('id', id)
      .select('id, email, creditos')
      .single();
    if (error) throw error;
    res.json({ ok: true, usuario: data });
  } catch (e) {
    console.error('Error editando usuario:', e.message);
    res.status(500).json({ ok: false, error: 'Error del servidor' });
  }
});

app.post('/api/admin/creditos/:id', requireAdmin, async (req, res) => {
  try {
    const id = req.params.id;
    const cantidad = parseInt(req.body.cantidad) || 0;
    if (cantidad < 1) return res.status(400).json({ ok: false, error: 'Cantidad invalida' });
    const { data, error } = await sb2
      .from('usuarios')
      .update({ creditos: sb2.rpc('increment', { row_id: id, amount: cantidad }) }) // fallback manual
      .eq('id', id)
      .select('creditos')
      .single();
    // Fallback manual si RPC no existe
    if (error || !data) {
      const { data: usr } = await sb2.from('usuarios').select('creditos').eq('id', id).single();
      const nuevo = (usr?.creditos || 0) + cantidad;
      const { data: upd, error: e2 } = await sb2.from('usuarios').update({ creditos: nuevo }).eq('id', id).select('creditos').single();
      if (e2) throw e2;
      return res.json({ ok: true, creditos: nuevo });
    }
    res.json({ ok: true, creditos: data.creditos });
  } catch (e) {
    console.error('Error sumando creditos:', e.message);
    res.status(500).json({ ok: false, error: 'Error del servidor' });
  }
});

// Sumar créditos por email (admin)
app.post('/api/admin/creditos/email', requireAdmin, async (req, res) => {
  try {
    const email = String((req.body && req.body.email) || '').trim().toLowerCase();
    const cantidad = parseInt(req.body.cantidad) || 0;
    if (!email || cantidad < 1) return res.status(400).json({ ok: false, error: 'Email y cantidad requeridos' });
    const { data: usr } = await sb2
      .from('usuarios')
      .select('id, creditos')
      .eq('email', email)
      .single();
    if (!usr) return res.status(404).json({ ok: false, error: 'Usuario no encontrado' });
    const nuevo = (usr.creditos || 0) + cantidad;
    const { error } = await sb2
      .from('usuarios')
      .update({ creditos: nuevo })
      .eq('id', usr.id);
    if (error) throw error;
    res.json({ ok: true, creditos: nuevo, email });
  } catch (e) {
    console.error('Error sumando creditos por email:', e.message);
    res.status(500).json({ ok: false, error: e.message });
  }
});

// -----------------------------------------------------------
function setCookieHeader(res, token) {
  res.setHeader('Set-Cookie',
    `sesion=${token}; HttpOnly; Path=/; Max-Age=2592000; SameSite=Lax; Secure`);
}

async function usuarioPorCookie(req) {
  const token = req.cookies?.sesion;
  if (!token || !sb2) return null;
  const { data: ses } = await sb2
    .from('sesiones')
    .select('usuario_id')
    .eq('token', token)
    .gt('expira', new Date().toISOString())
    .single();
  if (!ses) return null;
  const { data: usr } = await sb2
    .from('usuarios')
    .select('id, email, creditos')
    .eq('id', ses.usuario_id)
    .single();
  return usr ? { id: usr.id, email: usr.email, creditos: usr.creditos } : null;
}

function setCookieHeader(res, token) {
  res.setHeader('Set-Cookie',
    `sesion=${token}; HttpOnly; Path=/; Max-Age=2592000; SameSite=Lax; Secure`);
}

async function nuevaSesion(sb, usuario_id) {
  const token = crypto.randomBytes(32).toString('hex');
  await sb.from('sesiones').insert({
    token,
    usuario_id,
    expira: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000).toISOString()
  });
  return token;
}

// Admin ECID registration (no credit cost)
app.post('/api/admin/ecid', requireAdmin, async (req, res) => {
  try {
    const ecid = String((req.body && req.body.ecid) || '').trim();
    if (!/^0x[0-9a-fA-F]{1,40}$/.test(ecid)) {
      return res.status(400).json({ ok: false, error: 'ECID invalido' });
    }

    const { error: errUp } = await sb1.from('ecids').upsert(
      { usuario_id: req.admin.id, ecid, ultima_vez: new Date().toISOString() },
      { onConflict: 'usuario_id,ecid', ignoreDuplicates: false }
    );
    if (errUp) throw errUp;

    res.json({ ok: true, ecid });
  } catch (e) {
    console.error('Error guardando ECID admin:', e.message);
    res.status(500).json({ ok: false, error: 'Error de base de datos' });
  }
});

app.get('/', (_req, res) => res.redirect('/index.html'));

app.listen(PORT, () => console.log('Michi ECID Registro (2 Supabase) en puerto ' + PORT));