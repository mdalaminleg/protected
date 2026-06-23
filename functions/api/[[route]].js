// ============================================================
// MINIMAL FIXED BACKEND - functions/api/[[route]].js
// ============================================================

const CORS_HEADERS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type, Authorization',
  'Access-Control-Max-Age': '86400'
};

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      ...CORS_HEADERS,
      'Content-Type': 'application/json'
    }
  });
}

function err(msg, status = 400) {
  return json({ error: msg }, status);
}

async function sha256(text) {
  const encoder = new TextEncoder();
  const data = encoder.encode(text);
  const hashBuffer = await crypto.subtle.digest('SHA-256', data);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
}

const JWT_SECRET = 'sciverse-academy-jwt-secret-key-2026';

async function signToken(payload) {
  const header = { alg: 'HS256', typ: 'JWT' };
  const headerB64 = btoa(JSON.stringify(header)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  const payloadB64 = btoa(JSON.stringify(payload)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  const signature = await hmacSha256(JWT_SECRET, `${headerB64}.${payloadB64}`);
  return `${headerB64}.${payloadB64}.${signature}`;
}

async function hmacSha256(key, data) {
  const encoder = new TextEncoder();
  const keyData = encoder.encode(key);
  const cryptoKey = await crypto.subtle.importKey(
    'raw', keyData, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign', 'verify']
  );
  const signature = await crypto.subtle.sign('HMAC', cryptoKey, encoder.encode(data));
  const bytes = Array.from(new Uint8Array(signature));
  return btoa(String.fromCharCode(...bytes)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

async function verifyToken(token) {
  try {
    const parts = token.split('.');
    if (parts.length !== 3) return null;
    const [headerB64, payloadB64, signature] = parts;
    const expectedSig = await hmacSha256(JWT_SECRET, `${headerB64}.${payloadB64}`);
    if (signature !== expectedSig) return null;
    const payload = JSON.parse(atob(payloadB64.replace(/-/g, '+').replace(/_/g, '/')));
    if (payload.exp && payload.exp < Date.now()) return null;
    return payload;
  } catch (e) {
    return null;
  }
}

async function getUser(request) {
  const auth = request.headers.get('Authorization') || '';
  const token = auth.replace('Bearer ', '');
  if (!token) return null;
  return await verifyToken(token);
}

async function ensureTables(db) {
  await db.prepare(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT NOT NULL,
      email TEXT NOT NULL UNIQUE,
      password TEXT NOT NULL,
      role TEXT NOT NULL DEFAULT 'student',
      is_approved INTEGER NOT NULL DEFAULT 0,
      is_blocked INTEGER NOT NULL DEFAULT 0,
      device_fingerprint TEXT,
      device_ip TEXT,
      created_at TEXT NOT NULL DEFAULT (datetime('now'))
    )
  `).run();

  const adminPass = await sha256('Sc1Verse@Admin#2026');
  await db.prepare(`
    INSERT OR IGNORE INTO users (name, email, password, role, is_approved)
    VALUES ('Admin', 'admin@sciverse.com', ?, 'admin', 1)
  `).bind(adminPass).run();
}

// ─── MAIN ROUTER ────────────────────────────────────────────

export async function onRequest(context) {
  const { request, env } = context;
  const db = env.PROTECTED_DB;
  const url = new URL(request.url);
  const method = request.method;
  const path = url.pathname.replace('/api', '');

  // ═══════════════════════════════════════════════════════════
  // CORS - MUST BE FIRST
  // ═══════════════════════════════════════════════════════════
  if (method === 'OPTIONS') {
    return new Response(null, {
      status: 204,
      headers: CORS_HEADERS
    });
  }

  // Ensure tables
  if (!globalThis.__tablesReady) {
    await ensureTables(db);
    globalThis.__tablesReady = true;
  }

  let body = null;
  if (method === 'POST' || method === 'PUT') {
    try { body = await request.json(); } catch (e) { body = {}; }
  }

  // ═══════════════════════════════════════════════════════════
  // AUTH ROUTES - NO AUTH REQUIRED
  // ═══════════════════════════════════════════════════════════

  // REGISTER
  if (method === 'POST' && path === '/auth/register') {
    const { name, email, password } = body || {};
    if (!name || !email || !password) {
      return err('Name, email, and password are required.', 400);
    }
    if (password.length < 6) {
      return err('Password must be at least 6 characters.', 400);
    }
    
    const existing = await db.prepare('SELECT id FROM users WHERE email = ?').bind(email.toLowerCase().trim()).first();
    if (existing) {
      return err('An account with this email already exists.', 409);
    }
    
    const hashedPw = await sha256(password);
    const result = await db.prepare(
      'INSERT INTO users (name, email, password, role, is_approved, is_blocked) VALUES (?, ?, ?, ?, ?, ?)'
    ).bind(name.trim(), email.toLowerCase().trim(), hashedPw, 'student', 0, 0).run();
    
    return json({ message: 'Account created successfully. Awaiting admin approval.' }, 201);
  }

  // LOGIN
  if (method === 'POST' && path === '/auth/login') {
    const { email, password } = body || {};
    if (!email || !password) {
      return err('Email and password are required.', 400);
    }

    const user = await db.prepare('SELECT * FROM users WHERE email = ?').bind(email.toLowerCase().trim()).first();
    if (!user) {
      return err('Invalid email or password.', 401);
    }

    const hashedPw = await sha256(password);
    if (user.password !== hashedPw) {
      return err('Invalid email or password.', 401);
    }

    if (user.is_blocked) {
      return err('Your account has been blocked. Contact admin.', 403);
    }
    if (!user.is_approved) {
      return err('Your account is pending approval. Contact admin.', 403);
    }

    const token = await signToken({
      id: user.id,
      email: user.email,
      role: user.role,
      exp: Date.now() + 30 * 24 * 60 * 60 * 1000
    });

    return json({
      token,
      user: { id: user.id, name: user.name, email: user.email, role: user.role }
    });
  }

  // ═══════════════════════════════════════════════════════════
  // PROTECTED ROUTES - AUTH REQUIRED
  // ═══════════════════════════════════════════════════════════
  const authUser = await getUser(request);
  if (!authUser) {
    return err('Authentication required.', 401);
  }

  // USER ROUTES
  if (method === 'GET' && path === '/user/me') {
    const u = await db.prepare('SELECT id, name, email, role, is_approved, is_blocked, created_at FROM users WHERE id = ?').bind(authUser.id).first();
    return json({ user: u });
  }

  // ADMIN ROUTES
  if (path.startsWith('/admin/')) {
    if (authUser.role !== 'admin') {
      return err('Forbidden. Admin access required.', 403);
    }
    if (method === 'GET' && path === '/admin/users') {
      const users = await db.prepare('SELECT id, name, email, role, is_approved, is_blocked, created_at FROM users ORDER BY created_at DESC').all();
      return json({ users: users.results });
    }
    if (method === 'PUT' && path.match(/^\/admin\/users\/\d+\/approve$/)) {
      const userId = parseInt(path.split('/')[3]);
      await db.prepare('UPDATE users SET is_approved = 1 WHERE id = ?').bind(userId).run();
      return json({ message: 'User approved.' });
    }
    if (method === 'PUT' && path.match(/^\/admin\/users\/\d+\/block$/)) {
      const userId = parseInt(path.split('/')[3]);
      await db.prepare('UPDATE users SET is_blocked = 1 WHERE id = ?').bind(userId).run();
      return json({ message: 'User blocked.' });
    }
    if (method === 'PUT' && path.match(/^\/admin\/users\/\d+\/unblock$/)) {
      const userId = parseInt(path.split('/')[3]);
      await db.prepare('UPDATE users SET is_blocked = 0 WHERE id = ?').bind(userId).run();
      return json({ message: 'User unblocked.' });
    }
    if (method === 'DELETE' && path.match(/^\/admin\/users\/\d+$/)) {
      const userId = parseInt(path.split('/')[3]);
      await db.prepare('DELETE FROM users WHERE id = ?').bind(userId).run();
      return json({ message: 'User deleted.' });
    }
  }

  return err('API endpoint not found', 404);
}
