// ============================================================
// SciVerse Academy — Complete Protected Backend
// ============================================================

const JWT_SECRET = 'sciverse-academy-jwt-secret-key-2026';
const ENCRYPTION_SECRET = 'sciverse-encrypt-2026-secure-key';

const CORS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type, Authorization, X-Encrypted',
  'Access-Control-Allow-Credentials': 'true',
  'Access-Control-Max-Age': '86400'
};

// ============================================================
// BLOCKED USER AGENTS (Proxy Tools)
// ============================================================

const BLOCKED_USER_AGENTS = [
  'HTTPS Canary', 'Requestly', 'Charles', 'Fiddler', 'Burp',
  'Postman', 'Insomnia', 'Wireshark', 'Mitmproxy', 'ZAP',
  'OWASP', 'Nessus', 'Nmap', 'Sqlmap', 'Hydra', 'John',
  'Aircrack', 'Metasploit', 'Nikto', 'WPScan', 'Dirbuster',
  'Gobuster', 'FFUF', 'WFuzz', 'OpenVAS', 'Nexpose'
];

function isBlockedUserAgent(userAgent) {
  if (!userAgent) return false;
  const ua = userAgent.toLowerCase();
  return BLOCKED_USER_AGENTS.some(agent => ua.includes(agent.toLowerCase()));
}

// ============================================================
// ENCRYPTION HELPERS
// ============================================================

async function encryptResponse(data) {
  const encoder = new TextEncoder();
  const keyData = encoder.encode(ENCRYPTION_SECRET);

  const cryptoKey = await crypto.subtle.importKey(
    'raw',
    keyData,
    { name: 'AES-GCM' },
    false,
    ['encrypt']
  );

  const iv = crypto.getRandomValues(new Uint8Array(12));
  const encodedData = encoder.encode(JSON.stringify(data));

  const encrypted = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv: iv },
    cryptoKey,
    encodedData
  );

  const combined = new Uint8Array(iv.length + encrypted.byteLength);
  combined.set(iv);
  combined.set(new Uint8Array(encrypted), iv.length);

  return btoa(String.fromCharCode(...combined));
}

async function decryptResponse(encryptedBase64) {
  try {
    const combined = Uint8Array.from(atob(encryptedBase64), c => c.charCodeAt(0));
    const iv = combined.slice(0, 12);
    const encrypted = combined.slice(12);

    const encoder = new TextEncoder();
    const keyData = encoder.encode(ENCRYPTION_SECRET);

    const cryptoKey = await crypto.subtle.importKey(
      'raw',
      keyData,
      { name: 'AES-GCM' },
      false,
      ['decrypt']
    );

    const decrypted = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: iv },
      cryptoKey,
      encrypted
    );

    const decoder = new TextDecoder();
    return JSON.parse(decoder.decode(decrypted));
  } catch (e) {
    return null;
  }
}

// ============================================================
// YOUTUBE ID OBFUSCATION
// ============================================================

function obfuscateYoutubeId(id) {
  if (!id) return '';
  const reversed = id.split('').reverse().join('');
  return btoa(reversed);
}

function deobfuscateYoutubeId(obfuscated) {
  try {
    const decoded = atob(obfuscated);
    return decoded.split('').reverse().join('');
  } catch (e) {
    return null;
  }
}

// ============================================================
// RATE LIMITING
// ============================================================

async function checkRateLimit(db, userId, action = 'default') {
  try {
    const minute = Math.floor(Date.now() / 60000);
    const key = `rate_${userId || 'anonymous'}_${action}_${minute}`;

    const existing = await db.prepare('SELECT count FROM rate_limits WHERE id = ?').bind(key).first();

    const limit = userId ? 100 : 20;

    if (existing && existing.count >= limit) {
      return false;
    }

    await db.prepare(
      'INSERT INTO rate_limits (id, count, created_at) VALUES (?, 1, datetime("now")) ON CONFLICT(id) DO UPDATE SET count = count + 1'
    ).bind(key).run();

    return true;
  } catch (e) {
    return true;
  }
}

// ============================================================
// ORIGIN VALIDATION
// ============================================================

function isValidOrigin(request) {
  const origin = request.headers.get('Origin') || '';
  const referer = request.headers.get('Referer') || '';

  const allowedDomains = [
    'sciverseacademy.pages.dev',
    'sciverse-api.workers.dev',
    'localhost',
    '127.0.0.1'
  ];

  const check = (url) => {
    try {
      const parsed = new URL(url);
      return allowedDomains.some(domain => parsed.hostname.includes(domain));
    } catch {
      return false;
    }
  };

  return check(origin) || check(referer);
}

// ============================================================
// RESPONSE HELPERS
// ============================================================

async function jsonEncrypted(data, status = 200) {
  const encrypted = await encryptResponse(data);
  return new Response(JSON.stringify({
    encrypted: true,
    data: encrypted,
    timestamp: Date.now()
  }), {
    status,
    headers: { ...CORS, 'Content-Type': 'application/json' }
  });
}

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { ...CORS, 'Content-Type': 'application/json' }
  });
}

function err(msg, status = 400) {
  return json({ error: msg }, status);
}

// ============================================================
// JWT HELPERS
// ============================================================

async function sha256(text) {
  const encoder = new TextEncoder();
  const data = encoder.encode(text);
  const hashBuffer = await crypto.subtle.digest('SHA-256', data);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
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

function base64UrlDecode(str) {
  str = str.replace(/-/g, '+').replace(/_/g, '/');
  while (str.length % 4) str += '=';
  return atob(str);
}

async function signToken(payload) {
  const header = { alg: 'HS256', typ: 'JWT' };
  const headerB64 = btoa(JSON.stringify(header)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  const payloadB64 = btoa(JSON.stringify(payload)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  const signature = await hmacSha256(JWT_SECRET, `${headerB64}.${payloadB64}`);
  return `${headerB64}.${payloadB64}.${signature}`;
}

async function verifyToken(token) {
  try {
    const parts = token.split('.');
    if (parts.length !== 3) return null;
    const [headerB64, payloadB64, signature] = parts;
    const expectedSig = await hmacSha256(JWT_SECRET, `${headerB64}.${payloadB64}`);
    if (signature !== expectedSig) return null;
    const payload = JSON.parse(base64UrlDecode(payloadB64));
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
  const payload = await verifyToken(token);
  if (!payload) return null;
  return payload;
}

function getFingerprint(request) {
  const ua = request.headers.get('User-Agent') || '';
  const ip = request.headers.get('CF-Connecting-IP') || request.headers.get('X-Forwarded-For') || 'unknown';
  return `${ua}|${ip}`;
}

async function hashFingerprint(fp) {
  return await sha256(fp);
}

// ============================================================
// DATABASE SETUP
// ============================================================

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
      created_at TEXT NOT NULL DEFAULT (datetime('now')),
      updated_at TEXT NOT NULL DEFAULT (datetime('now'))
    )
  `).run();

  await db.prepare(`
    CREATE TABLE IF NOT EXISTS courses (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      title TEXT NOT NULL,
      description TEXT DEFAULT '',
      created_at TEXT NOT NULL DEFAULT (datetime('now')),
      updated_at TEXT NOT NULL DEFAULT (datetime('now'))
    )
  `).run();

  await db.prepare(`
    CREATE TABLE IF NOT EXISTS subjects (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      course_id INTEGER NOT NULL,
      title TEXT NOT NULL,
      description TEXT DEFAULT '',
      sort_order INTEGER NOT NULL DEFAULT 0,
      created_at TEXT NOT NULL DEFAULT (datetime('now')),
      updated_at TEXT NOT NULL DEFAULT (datetime('now')),
      FOREIGN KEY (course_id) REFERENCES courses(id)
    )
  `).run();

  await db.prepare(`
    CREATE TABLE IF NOT EXISTS lectures (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      subject_id INTEGER NOT NULL,
      title TEXT NOT NULL,
      youtube_id TEXT DEFAULT '',
      pdf_url TEXT DEFAULT '',
      sort_order INTEGER NOT NULL DEFAULT 0,
      created_at TEXT NOT NULL DEFAULT (datetime('now')),
      updated_at TEXT NOT NULL DEFAULT (datetime('now')),
      FOREIGN KEY (subject_id) REFERENCES subjects(id)
    )
  `).run();

  await db.prepare(`
    CREATE TABLE IF NOT EXISTS resources (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      course_id INTEGER NOT NULL,
      title TEXT NOT NULL,
      description TEXT DEFAULT '',
      link_url TEXT DEFAULT '',
      sort_order INTEGER NOT NULL DEFAULT 0,
      created_at TEXT NOT NULL DEFAULT (datetime('now')),
      updated_at TEXT NOT NULL DEFAULT (datetime('now')),
      FOREIGN KEY (course_id) REFERENCES courses(id)
    )
  `).run();

  await db.prepare(`
    CREATE TABLE IF NOT EXISTS enrollments (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL,
      course_id INTEGER NOT NULL,
      enrolled_at TEXT NOT NULL DEFAULT (datetime('now')),
      FOREIGN KEY (user_id) REFERENCES users(id),
      FOREIGN KEY (course_id) REFERENCES courses(id),
      UNIQUE(user_id, course_id)
    )
  `).run();

  await db.prepare(`
    CREATE TABLE IF NOT EXISTS audit_logs (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER,
      action TEXT NOT NULL,
      ip_address TEXT DEFAULT '',
      user_agent TEXT DEFAULT '',
      created_at TEXT NOT NULL DEFAULT (datetime('now'))
    )
  `).run();

  await db.prepare(`
    CREATE TABLE IF NOT EXISTS rate_limits (
      id TEXT PRIMARY KEY,
      count INTEGER DEFAULT 0,
      created_at TEXT
    )
  `).run();

  await db.prepare(`CREATE INDEX IF NOT EXISTS idx_users_email ON users(email)`).run();
  await db.prepare(`CREATE INDEX IF NOT EXISTS idx_subjects_course ON subjects(course_id)`).run();
  await db.prepare(`CREATE INDEX IF NOT EXISTS idx_lectures_subject ON lectures(subject_id)`).run();
  await db.prepare(`CREATE INDEX IF NOT EXISTS idx_resources_course ON resources(course_id)`).run();
  await db.prepare(`CREATE INDEX IF NOT EXISTS idx_enrollments_user ON enrollments(user_id)`).run();
  await db.prepare(`CREATE INDEX IF NOT EXISTS idx_enrollments_course ON enrollments(course_id)`).run();
  await db.prepare(`CREATE INDEX IF NOT EXISTS idx_audit_user ON audit_logs(user_id)`).run();

  // Seed admin
  const adminPass = await sha256('Sc1Verse@Admin#2026');
  await db.prepare(`
    INSERT OR IGNORE INTO users (name, email, password, role, is_approved)
    VALUES ('Admin', 'text.me.md.alamin@gmail.com', ?, 'admin', 1)
  `).bind(adminPass).run();

  // Migrations
  const migrations = [
    "ALTER TABLE users ADD COLUMN device_ip TEXT",
    "ALTER TABLE users ADD COLUMN device_fingerprint TEXT",
  ];
  for (const sql of migrations) {
    try { await db.prepare(sql).run(); } catch (e) { /* column likely exists */ }
  }
}

// ============================================================
// AUTH HANDLERS
// ============================================================

async function handleAuth(method, path, body, db, request) {
  // POST /api/auth/register
  if (method === 'POST' && path === '/auth/register') {
    const { name, email, password } = body || {};
    if (!name || !email || !password) return err('Name, email, and password are required.', 400);
    if (password.length < 6) return err('Password must be at least 6 characters.', 400);
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return err('Invalid email format.', 400);

    const existing = await db.prepare('SELECT id FROM users WHERE email = ?').bind(email.toLowerCase().trim()).first();
    if (existing) return err('An account with this email already exists.', 409);

    const fp = getFingerprint(request);
    const fpHash = await hashFingerprint(fp);

    const hashedPw = await sha256(password);
    const result = await db.prepare(
      'INSERT INTO users (name, email, password, role, is_approved, is_blocked, device_fingerprint, device_ip) VALUES (?, ?, ?, ?, ?, ?, ?, ?)'
    ).bind(name.trim(), email.toLowerCase().trim(), hashedPw, 'student', 0, 0, fpHash, request.headers.get('CF-Connecting-IP') || '').run();

    await db.prepare(
      'INSERT INTO audit_logs (user_id, action, ip_address, user_agent) VALUES (?, ?, ?, ?)'
    ).bind(result.meta.last_row_id, 'account_created', request.headers.get('CF-Connecting-IP') || '', request.headers.get('User-Agent') || '').run();

    return json({ message: 'Account created successfully. Awaiting admin approval.' }, 201);
  }

  // POST /api/auth/login
  if (method === 'POST' && path === '/auth/login') {
    const { email, password } = body || {};
    if (!email || !password) return err('Email and password are required.', 400);

    const user = await db.prepare('SELECT * FROM users WHERE email = ?').bind(email.toLowerCase().trim()).first();
    if (!user) return err('Invalid email or password.', 401);

    const hashedPw = await sha256(password);
    if (user.password !== hashedPw) {
      await db.prepare(
        'INSERT INTO audit_logs (user_id, action, ip_address, user_agent) VALUES (?, ?, ?, ?)'
      ).bind(user.id, 'login_failed', request.headers.get('CF-Connecting-IP') || '', request.headers.get('User-Agent') || '').run();
      return err('Invalid email or password.', 401);
    }

    if (user.is_blocked) return err('Your account has been blocked. Contact admin.', 403);
    if (!user.is_approved) return err('Your account is pending approval. Contact admin.', 403);

    // Device fingerprint check — skip for admin
    if (user.role !== 'admin') {
      const fp = getFingerprint(request);
      const fpHash = await hashFingerprint(fp);
      if (user.device_fingerprint && user.device_fingerprint !== fpHash) {
        await db.prepare('UPDATE users SET is_blocked = 1 WHERE id = ?').bind(user.id).run();
        await db.prepare(
          'INSERT INTO audit_logs (user_id, action, ip_address, user_agent) VALUES (?, ?, ?, ?)'
        ).bind(user.id, 'device_mismatch_blocked', request.headers.get('CF-Connecting-IP') || '', request.headers.get('User-Agent') || '').run();
        return err('Device mismatch detected. Your account has been locked for security. Contact admin.', 403);
      }
    }

    const token = await signToken({
      id: user.id,
      email: user.email,
      role: user.role,
      exp: Date.now() + 30 * 24 * 60 * 60 * 1000
    });

    await db.prepare(
      'INSERT INTO audit_logs (user_id, action, ip_address, user_agent) VALUES (?, ?, ?, ?)'
    ).bind(user.id, 'login_success', request.headers.get('CF-Connecting-IP') || '', request.headers.get('User-Agent') || '').run();

    return json({
      token,
      user: { id: user.id, name: user.name, email: user.email, role: user.role }
    });
  }

  return err('Not found', 404);
}

// ============================================================
// USER HANDLERS
// ============================================================

async function handleUser(method, path, body, db, user, request) {
  // GET /api/user/me
  if (method === 'GET' && path === '/user/me') {
    const u = await db.prepare('SELECT id, name, email, role, is_approved, is_blocked, created_at FROM users WHERE id = ?').bind(user.id).first();
    if (!u) return err('User not found', 404);
    return json({ user: u });
  }

  // GET /api/user/courses
  if (method === 'GET' && path === '/user/courses') {
    const courses = await db.prepare(`
      SELECT c.* FROM courses c
      JOIN enrollments e ON c.id = e.course_id
      WHERE e.user_id = ?
      ORDER BY c.created_at DESC
    `).bind(user.id).all();
    return json({ courses: courses.results });
  }

  // GET /api/user/course?id=X
  if (method === 'GET' && path === '/user/course') {
    const url = new URL(request.url);
    const courseId = url.searchParams.get('id');
    if (!courseId) return err('Course ID required', 400);

    // Admin bypass — admins can view any course without enrollment
    if (user.role !== 'admin') {
      const enrollment = await db.prepare('SELECT * FROM enrollments WHERE user_id = ? AND course_id = ?').bind(user.id, courseId).first();
      if (!enrollment) return err('Not enrolled in this course', 403);
    }

    const course = await db.prepare('SELECT * FROM courses WHERE id = ?').bind(courseId).first();
    if (!course) return err('Course not found', 404);

    const subjects = await db.prepare('SELECT * FROM subjects WHERE course_id = ? ORDER BY sort_order ASC, id ASC').bind(courseId).all();
    const resources = await db.prepare('SELECT * FROM resources WHERE course_id = ? ORDER BY sort_order ASC, id ASC').bind(courseId).all();

    // Get lectures for each subject with obfuscated YouTube IDs
    const subjectsWithLectures = [];
    for (const sub of subjects.results) {
      const lectures = await db.prepare('SELECT * FROM lectures WHERE subject_id = ? ORDER BY sort_order ASC, id ASC').bind(sub.id).all();
      const obfuscatedLectures = lectures.results.map(lec => ({
        ...lec,
        youtube_id: obfuscateYoutubeId(lec.youtube_id)
      }));
      subjectsWithLectures.push({ ...sub, lectures: obfuscatedLectures });
    }

    const responseData = { course, subjects: subjectsWithLectures, resources: resources.results };
    return await jsonEncrypted(responseData);
  }

  return err('Not found', 404);
}

// ============================================================
// ADMIN HANDLERS
// ============================================================

async function handleAdmin(method, path, body, db, user, request) {
  // ── USERS ──
  if (method === 'GET' && path === '/admin/users') {
    const users = await db.prepare('SELECT id, name, email, role, is_approved, is_blocked, device_fingerprint, device_ip, created_at FROM users ORDER BY created_at DESC').all();
    return json({ users: users.results });
  }

  if (method === 'PUT' && path.match(/^\/admin\/users\/\d+\/approve$/)) {
    const userId = parseInt(path.split('/')[3]);
    await db.prepare('UPDATE users SET is_approved = 1, updated_at = datetime(\'now\') WHERE id = ?').bind(userId).run();
    await db.prepare('INSERT INTO audit_logs (user_id, action, ip_address, user_agent) VALUES (?, ?, ?, ?)').bind(user.id, `approved_user_${userId}`, request.headers.get('CF-Connecting-IP') || '', request.headers.get('User-Agent') || '').run();
    return json({ message: 'User approved.' });
  }

  if (method === 'PUT' && path.match(/^\/admin\/users\/\d+\/block$/)) {
    const userId = parseInt(path.split('/')[3]);
    await db.prepare('UPDATE users SET is_blocked = 1, updated_at = datetime(\'now\') WHERE id = ?').bind(userId).run();
    await db.prepare('INSERT INTO audit_logs (user_id, action, ip_address, user_agent) VALUES (?, ?, ?, ?)').bind(user.id, `blocked_user_${userId}`, request.headers.get('CF-Connecting-IP') || '', request.headers.get('User-Agent') || '').run();
    return json({ message: 'User blocked.' });
  }

  if (method === 'PUT' && path.match(/^\/admin\/users\/\d+\/unblock$/)) {
    const userId = parseInt(path.split('/')[3]);
    await db.prepare('UPDATE users SET is_blocked = 0, updated_at = datetime(\'now\') WHERE id = ?').bind(userId).run();
    await db.prepare('INSERT INTO audit_logs (user_id, action, ip_address, user_agent) VALUES (?, ?, ?, ?)').bind(user.id, `unblocked_user_${userId}`, request.headers.get('CF-Connecting-IP') || '', request.headers.get('User-Agent') || '').run();
    return json({ message: 'User unblocked.' });
  }

  if (method === 'DELETE' && path.match(/^\/admin\/users\/\d+$/)) {
    const userId = parseInt(path.split('/')[3]);
    await db.prepare('DELETE FROM enrollments WHERE user_id = ?').bind(userId).run();
    await db.prepare('DELETE FROM audit_logs WHERE user_id = ?').bind(userId).run();
    await db.prepare('DELETE FROM users WHERE id = ?').bind(userId).run();
    await db.prepare('INSERT INTO audit_logs (user_id, action, ip_address, user_agent) VALUES (?, ?, ?, ?)').bind(user.id, `deleted_user_${userId}`, request.headers.get('CF-Connecting-IP') || '', request.headers.get('User-Agent') || '').run();
    return json({ message: 'User deleted.' });
  }

  if (method === 'PUT' && path.match(/^\/admin\/users\/\d+\/reset-device$/)) {
    const userId = parseInt(path.split('/')[3]);
    await db.prepare('UPDATE users SET device_fingerprint = NULL, updated_at = datetime(\'now\') WHERE id = ?').bind(userId).run();
    await db.prepare('INSERT INTO audit_logs (user_id, action, ip_address, user_agent) VALUES (?, ?, ?, ?)').bind(user.id, `reset_device_${userId}`, request.headers.get('CF-Connecting-IP') || '', request.headers.get('User-Agent') || '').run();
    return json({ message: 'Device fingerprint reset. User can log in from a new device.' });
  }

  // ── ENROLLMENTS ──
  if (method === 'POST' && path === '/admin/enrollments') {
    const { user_id, course_id } = body || {};
    if (!user_id || !course_id) return err('user_id and course_id required', 400);
    await db.prepare('INSERT OR IGNORE INTO enrollments (user_id, course_id) VALUES (?, ?)').bind(user_id, course_id).run();
    await db.prepare('INSERT INTO audit_logs (user_id, action, ip_address, user_agent) VALUES (?, ?, ?, ?)').bind(user.id, `enrolled_user_${user_id}_course_${course_id}`, request.headers.get('CF-Connecting-IP') || '', request.headers.get('User-Agent') || '').run();
    return json({ message: 'User enrolled in course.' });
  }

  if (method === 'DELETE' && path.match(/^\/admin\/enrollments\/\d+\/\d+$/)) {
    const parts = path.split('/');
    const userId = parseInt(parts[3]);
    const courseId = parseInt(parts[4]);
    await db.prepare('DELETE FROM enrollments WHERE user_id = ? AND course_id = ?').bind(userId, courseId).run();
    await db.prepare('INSERT INTO audit_logs (user_id, action, ip_address, user_agent) VALUES (?, ?, ?, ?)').bind(user.id, `unenrolled_user_${userId}_course_${courseId}`, request.headers.get('CF-Connecting-IP') || '', request.headers.get('User-Agent') || '').run();
    return json({ message: 'User unenrolled from course.' });
  }

  if (method === 'GET' && path === '/admin/enrollments') {
    const enrollments = await db.prepare(`
      SELECT e.*, u.name as user_name, u.email as user_email, c.title as course_title
      FROM enrollments e
      JOIN users u ON e.user_id = u.id
      JOIN courses c ON e.course_id = c.id
      ORDER BY e.enrolled_at DESC
    `).all();
    return json({ enrollments: enrollments.results });
  }

  // ── COURSES ──
  if (method === 'GET' && path === '/admin/courses') {
    const courses = await db.prepare('SELECT * FROM courses ORDER BY created_at DESC').all();
    return json({ courses: courses.results });
  }

  if (method === 'POST' && path === '/admin/courses') {
    const { title, description } = body || {};
    if (!title) return err('Title required', 400);
    const result = await db.prepare('INSERT INTO courses (title, description) VALUES (?, ?)').bind(title.trim(), description || '').run();
    await db.prepare('INSERT INTO audit_logs (user_id, action, ip_address, user_agent) VALUES (?, ?, ?, ?)').bind(user.id, `created_course_${result.meta.last_row_id}`, request.headers.get('CF-Connecting-IP') || '', request.headers.get('User-Agent') || '').run();
    return json({ id: result.meta.last_row_id, message: 'Course created.' }, 201);
  }

  if (method === 'PUT' && path.match(/^\/admin\/courses\/\d+$/)) {
    const courseId = parseInt(path.split('/')[3]);
    const { title, description } = body || {};
    if (!title) return err('Title required', 400);
    await db.prepare('UPDATE courses SET title = ?, description = ?, updated_at = datetime(\'now\') WHERE id = ?').bind(title.trim(), description || '', courseId).run();
    return json({ message: 'Course updated.' });
  }

  if (method === 'DELETE' && path.match(/^\/admin\/courses\/\d+$/)) {
    const courseId = parseInt(path.split('/')[3]);
    const subjects = await db.prepare('SELECT id FROM subjects WHERE course_id = ?').bind(courseId).all();
    for (const sub of subjects.results) {
      await db.prepare('DELETE FROM lectures WHERE subject_id = ?').bind(sub.id).run();
    }
    await db.prepare('DELETE FROM subjects WHERE course_id = ?').bind(courseId).run();
    await db.prepare('DELETE FROM resources WHERE course_id = ?').bind(courseId).run();
    await db.prepare('DELETE FROM enrollments WHERE course_id = ?').bind(courseId).run();
    await db.prepare('DELETE FROM courses WHERE id = ?').bind(courseId).run();
    await db.prepare('INSERT INTO audit_logs (user_id, action, ip_address, user_agent) VALUES (?, ?, ?, ?)').bind(user.id, `deleted_course_${courseId}`, request.headers.get('CF-Connecting-IP') || '', request.headers.get('User-Agent') || '').run();
    return json({ message: 'Course and all related data deleted.' });
  }

  // ── SUBJECTS ──
  if (method === 'POST' && path === '/admin/subjects') {
    const { course_id, title, description, sort_order } = body || {};
    if (!course_id || !title) return err('course_id and title required', 400);
    const result = await db.prepare('INSERT INTO subjects (course_id, title, description, sort_order) VALUES (?, ?, ?, ?)').bind(course_id, title.trim(), description || '', sort_order || 0).run();
    return json({ id: result.meta.last_row_id, message: 'Subject created.' }, 201);
  }

  if (method === 'PUT' && path.match(/^\/admin\/subjects\/\d+$/)) {
    const subjectId = parseInt(path.split('/')[3]);
    const { title, description, sort_order } = body || {};
    if (!title) return err('Title required', 400);
    await db.prepare('UPDATE subjects SET title = ?, description = ?, sort_order = ?, updated_at = datetime(\'now\') WHERE id = ?').bind(title.trim(), description || '', sort_order || 0, subjectId).run();
    return json({ message: 'Subject updated.' });
  }

  if (method === 'DELETE' && path.match(/^\/admin\/subjects\/\d+$/)) {
    const subjectId = parseInt(path.split('/')[3]);
    await db.prepare('DELETE FROM lectures WHERE subject_id = ?').bind(subjectId).run();
    await db.prepare('DELETE FROM subjects WHERE id = ?').bind(subjectId).run();
    return json({ message: 'Subject deleted.' });
  }

  // ── LECTURES ──
  if (method === 'POST' && path === '/admin/lectures') {
    const { subject_id, title, youtube_id, pdf_url, sort_order } = body || {};
    if (!subject_id || !title) return err('subject_id and title required', 400);
    const result = await db.prepare('INSERT INTO lectures (subject_id, title, youtube_id, pdf_url, sort_order) VALUES (?, ?, ?, ?, ?)').bind(subject_id, title.trim(), youtube_id || '', pdf_url || '', sort_order || 0).run();
    return json({ id: result.meta.last_row_id, message: 'Lecture created.' }, 201);
  }

  if (method === 'PUT' && path.match(/^\/admin\/lectures\/\d+$/)) {
    const lectureId = parseInt(path.split('/')[3]);
    const { title, youtube_id, pdf_url, sort_order } = body || {};
    if (!title) return err('Title required', 400);
    await db.prepare('UPDATE lectures SET title = ?, youtube_id = ?, pdf_url = ?, sort_order = ?, updated_at = datetime(\'now\') WHERE id = ?').bind(title.trim(), youtube_id || '', pdf_url || '', sort_order || 0, lectureId).run();
    return json({ message: 'Lecture updated.' });
  }

  if (method === 'DELETE' && path.match(/^\/admin\/lectures\/\d+$/)) {
    const lectureId = parseInt(path.split('/')[3]);
    await db.prepare('DELETE FROM lectures WHERE id = ?').bind(lectureId).run();
    return json({ message: 'Lecture deleted.' });
  }

  // ── RESOURCES ──
  if (method === 'POST' && path === '/admin/resources') {
    const { course_id, title, description, link_url, sort_order } = body || {};
    if (!course_id || !title) return err('course_id and title required', 400);
    const result = await db.prepare('INSERT INTO resources (course_id, title, description, link_url, sort_order) VALUES (?, ?, ?, ?, ?)').bind(course_id, title.trim(), description || '', link_url || '', sort_order || 0).run();
    return json({ id: result.meta.last_row_id, message: 'Resource created.' }, 201);
  }

  if (method === 'PUT' && path.match(/^\/admin\/resources\/\d+$/)) {
    const resourceId = parseInt(path.split('/')[3]);
    const { title, description, link_url, sort_order } = body || {};
    if (!title) return err('Title required', 400);
    await db.prepare('UPDATE resources SET title = ?, description = ?, link_url = ?, sort_order = ?, updated_at = datetime(\'now\') WHERE id = ?').bind(title.trim(), description || '', link_url || '', sort_order || 0, resourceId).run();
    return json({ message: 'Resource updated.' });
  }

  if (method === 'DELETE' && path.match(/^\/admin\/resources\/\d+$/)) {
    const resourceId = parseInt(path.split('/')[3]);
    await db.prepare('DELETE FROM resources WHERE id = ?').bind(resourceId).run();
    return json({ message: 'Resource deleted.' });
  }

  // ── AUDIT LOGS ──
  if (method === 'GET' && path === '/admin/audit-logs') {
    const logs = await db.prepare(`
      SELECT a.*, u.name as user_name, u.email as user_email
      FROM audit_logs a
      LEFT JOIN users u ON a.user_id = u.id
      ORDER BY a.created_at DESC
      LIMIT 500
    `).all();
    return json({ logs: logs.results });
  }

  if (method === 'DELETE' && path.match(/^\/admin\/audit-logs\/\d+$/)) {
    const logId = parseInt(path.split('/')[3]);
    await db.prepare('DELETE FROM audit_logs WHERE id = ?').bind(logId).run();
    return json({ message: 'Log deleted.' });
  }

  if (method === 'DELETE' && path === '/admin/audit-logs/all') {
    await db.prepare('DELETE FROM audit_logs').run();
    await db.prepare('INSERT INTO audit_logs (user_id, action, ip_address, user_agent) VALUES (?, ?, ?, ?)').bind(user.id, 'deleted_all_audit_logs', request.headers.get('CF-Connecting-IP') || '', request.headers.get('User-Agent') || '').run();
    return json({ message: 'All audit logs deleted.' });
  }

  // ── DASHBOARD STATS ──
  if (method === 'GET' && path === '/admin/stats') {
    const totalUsers = await db.prepare('SELECT COUNT(*) as count FROM users').first();
    const totalCourses = await db.prepare('SELECT COUNT(*) as count FROM courses').first();
    const totalEnrollments = await db.prepare('SELECT COUNT(*) as count FROM enrollments').first();
    const pendingUsers = await db.prepare('SELECT COUNT(*) as count FROM users WHERE is_approved = 0 AND is_blocked = 0').first();
    const blockedUsers = await db.prepare('SELECT COUNT(*) as count FROM users WHERE is_blocked = 1').first();
    return json({
      stats: {
        total_users: totalUsers.count,
        total_courses: totalCourses.count,
        total_enrollments: totalEnrollments.count,
        pending_users: pendingUsers.count,
        blocked_users: blockedUsers.count
      }
    });
  }

  return err('Not found', 404);
}

// ============================================================
// MAIN ROUTER
// ============================================================

export async function onRequest(context) {
  const { request, env } = context;
  const db = env.PROTECTED_DB;
  const url = new URL(request.url);
  const method = request.method;
  const path = url.pathname.replace('/api', '');

  // CORS preflight
  if (method === 'OPTIONS') {
    return new Response(null, { status: 204, headers: CORS });
  }

  // Block proxy tools
  const userAgent = request.headers.get('User-Agent') || '';
  if (isBlockedUserAgent(userAgent)) {
    return new Response(JSON.stringify({
      error: 'Access Denied',
      message: 'Proxy tools are not allowed'
    }), {
      status: 403,
      headers: { ...CORS, 'Content-Type': 'application/json' }
    });
  }

  // Validate origin
  if (!isValidOrigin(request)) {
    return new Response(JSON.stringify({
      error: 'Invalid Request',
      message: 'Origin not allowed'
    }), {
      status: 403,
      headers: { ...CORS, 'Content-Type': 'application/json' }
    });
  }

  // Ensure tables once per worker
  if (!globalThis.__tablesReady) {
    await ensureTables(db);
    globalThis.__tablesReady = true;
  }

  let body = null;
  if (method === 'POST' || method === 'PUT') {
    try { body = await request.json(); } catch (e) { body = {}; }
  }

  // Auth routes (no login required)
  if (path.startsWith('/auth/')) {
    return handleAuth(method, path, body, db, request);
  }

  // Protected routes
  const authUser = await getUser(request);
  if (!authUser) return err('Authentication required.', 401);

  // Check rate limit
  const rateLimitOk = await checkRateLimit(db, authUser.id, path);
  if (!rateLimitOk) {
    return err('Too many requests. Please try again later.', 429);
  }

  // Admin routes
  if (path.startsWith('/admin/')) {
    if (authUser.role !== 'admin') return err('Forbidden. Admin access required.', 403);
    return handleAdmin(method, path, body, db, authUser, request);
  }

  // User routes
  if (path.startsWith('/user/')) {
    return handleUser(method, path, body, db, authUser, request);
  }

  // GET /api/courses/:id — for lecture page
  if (method === 'GET' && path.match(/^\/courses\/\d+$/)) {
    const courseId = parseInt(path.split('/')[2]);

    // Skip enrollment check for admin users
    if (authUser.role !== 'admin') {
      const enrollment = await db.prepare('SELECT * FROM enrollments WHERE user_id = ? AND course_id = ?').bind(authUser.id, courseId).first();
      if (!enrollment) return err('Not enrolled in this course', 403);
    }

    const course = await db.prepare('SELECT * FROM courses WHERE id = ?').bind(courseId).first();
    if (!course) return err('Course not found', 404);

    const subjects = await db.prepare('SELECT * FROM subjects WHERE course_id = ? ORDER BY sort_order ASC, id ASC').bind(courseId).all();
    const resources = await db.prepare('SELECT * FROM resources WHERE course_id = ? ORDER BY sort_order ASC, id ASC').bind(courseId).all();

    const subjectsWithLectures = [];
    for (const sub of subjects.results) {
      const lectures = await db.prepare('SELECT * FROM lectures WHERE subject_id = ? ORDER BY sort_order ASC, id ASC').bind(sub.id).all();
      const obfuscatedLectures = lectures.results.map(lec => ({
        ...lec,
        youtube_id: obfuscateYoutubeId(lec.youtube_id)
      }));
      subjectsWithLectures.push({ ...sub, lectures: obfuscatedLectures });
    }

    const responseData = { course, subjects: subjectsWithLectures, resources: resources.results };
    return await jsonEncrypted(responseData);
  }

  // GET /api/user/lecture/:id - Get single lecture with obfuscated YouTube ID
  if (method === 'GET' && path.match(/^\/user\/lecture\/\d+$/)) {
    const lectureId = parseInt(path.split('/')[3]);

    const lecture = await db.prepare('SELECT * FROM lectures WHERE id = ?').bind(lectureId).first();
    if (!lecture) return err('Lecture not found', 404);

    // Check enrollment
    if (authUser.role !== 'admin') {
      const enrollment = await db.prepare(`
        SELECT e.* FROM enrollments e
        JOIN subjects s ON s.course_id = e.course_id
        WHERE e.user_id = ? AND s.id = ?
      `).bind(authUser.id, lecture.subject_id).first();
      if (!enrollment) return err('Not enrolled in this course', 403);
    }

    const responseData = {
      ...lecture,
      youtube_id: obfuscateYoutubeId(lecture.youtube_id)
    };

    return await jsonEncrypted(responseData);
  }

  return err('API endpoint not found', 404);
}
