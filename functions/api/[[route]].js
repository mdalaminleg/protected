// ============================================================
// SciVerse Academy — Complete Backend
// functions/api/[[route]].js
// ============================================================

const JWT_SECRET = 'sciverse-academy-jwt-secret-key-2026';
const CORS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type, Authorization, X-Master-Key'
};

// ─── HELPERS ────────────────────────────────────────────────

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

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { ...CORS, 'Content-Type': 'application/json' }
  });
}

function err(msg, status = 400) {
  return json({ error: msg }, status);
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

// ─── DATABASE SETUP ─────────────────────────────────────────

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
      master_key_hash TEXT,
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

  // Indexes
  await db.prepare(`CREATE INDEX IF NOT EXISTS idx_users_email ON users(email)`).run();
  await db.prepare(`CREATE INDEX IF NOT EXISTS idx_users_fingerprint ON users(device_fingerprint)`).run();
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
    "ALTER TABLE users ADD COLUMN master_key_hash TEXT",
  ];
  for (const sql of migrations) {
    try { await db.prepare(sql).run(); } catch (e) { /* column likely exists */ }
  }
}

// ─── MASTER KEY VERIFICATION ────────────────────────────────

async function verifyMasterKey(db, userId, masterKey) {
  if (!masterKey) return false;
  const user = await db.prepare('SELECT master_key_hash FROM users WHERE id = ?').bind(userId).first();
  if (!user || !user.master_key_hash) return false;
  const hashed = await sha256(masterKey);
  return hashed === user.master_key_hash;
}

async function requireMasterKey(db, user, request) {
  // Only check for admin users
  if (user.role !== 'admin') return true;

  // Check if master key is even set up
  const adminUser = await db.prepare('SELECT master_key_hash FROM users WHERE id = ?').bind(user.id).first();
  if (!adminUser || !adminUser.master_key_hash) {
    // Master key not set yet — only allow the set-master-key endpoint
    const url = new URL(request.url);
    const path = url.pathname.replace('/api', '');
    if (path === '/admin/set-master-key') return true;
    return false; // Block all other admin routes until master key is set
  }

  // Master key is set — verify it
  const masterKey = request.headers.get('X-Master-Key') || '';
  const isValid = await verifyMasterKey(db, user.id, masterKey);
  return isValid;
}

// ─── AUTH HANDLERS ──────────────────────────────────────────

async function handleAuth(method, path, body, db, request) {
  // POST /api/auth/register
  if (method === 'POST' && path === '/auth/register') {
    const { name, email, password } = body || {};
    if (!name || !email || !password) return err('Name, email, and password are required.', 400);
    if (password.length < 6) return err('Password must be at least 6 characters.', 400);
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return err('Invalid email format.', 400);

    // Check if email already exists
    const existing = await db.prepare('SELECT id FROM users WHERE email = ?').bind(email.toLowerCase().trim()).first();
    if (existing) return err('An account with this email already exists.', 409);

    // One account per device — check fingerprint
    const fp = getFingerprint(request);
    const fpHash = await hashFingerprint(fp);
    const existingDevice = await db.prepare('SELECT id FROM users WHERE device_fingerprint = ?').bind(fpHash).first();
    if (existingDevice) return err('An account already exists on this device.', 409);

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

      // If fingerprint is NULL (just reset by admin), save the new one
      if (!user.device_fingerprint) {
        await db.prepare('UPDATE users SET device_fingerprint = ?, device_ip = ?, updated_at = datetime(\'now\') WHERE id = ?')
          .bind(fpHash, request.headers.get('CF-Connecting-IP') || '', user.id).run();
      } else if (user.device_fingerprint !== fpHash) {
        // Fingerprint exists and doesn't match — block the account
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

    // Check if master key is set (for admin)
    const needsMasterKey = user.role === 'admin' && !user.master_key_hash;

    return json({
      token,
      user: { id: user.id, name: user.name, email: user.email, role: user.role },
      needsMasterKey: needsMasterKey || false
    });
  }

  return err('Not found', 404);
}

// ─── USER HANDLERS ──────────────────────────────────────────

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

    if (user.role !== 'admin') {
      const enrollment = await db.prepare('SELECT * FROM enrollments WHERE user_id = ? AND course_id = ?').bind(user.id, courseId).first();
      if (!enrollment) return err('Not enrolled in this course', 403);
    }

    const course = await db.prepare('SELECT * FROM courses WHERE id = ?').bind(courseId).first();
    if (!course) return err('Course not found', 404);

    const subjects = await db.prepare('SELECT * FROM subjects WHERE course_id = ? ORDER BY sort_order ASC, id ASC').bind(courseId).all();
    const resources = await db.prepare('SELECT * FROM resources WHERE course_id = ? ORDER BY sort_order ASC, id ASC').bind(courseId).all();

    const subjectsWithLectures = [];
    for (const sub of subjects.results) {
      const lectures = await db.prepare('SELECT * FROM lectures WHERE subject_id = ? ORDER BY sort_order ASC, id ASC').bind(sub.id).all();
      subjectsWithLectures.push({ ...sub, lectures: lectures.results });
    }

    return json({ course, subjects: subjectsWithLectures, resources: resources.results });
  }

  return err('Not found', 404);
}

// ─── ADMIN HANDLERS ─────────────────────────────────────────

async function handleAdmin(method, path, body, db, user, request) {
  // ── MASTER KEY SETUP ──
  if (method === 'POST' && path === '/admin/set-master-key') {
    const { masterKey } = body || {};
    if (!masterKey || masterKey.length < 6) return err('Master key must be at least 6 characters.', 400);

    const existing = await db.prepare('SELECT master_key_hash FROM users WHERE id = ?').bind(user.id).first();
    if (existing && existing.master_key_hash) return err('Master key is already set.', 400);

    const hashed = await sha256(masterKey);
    await db.prepare('UPDATE users SET master_key_hash = ?, updated_at = datetime(\'now\') WHERE id = ?').bind(hashed, user.id).run();

    await db.prepare('INSERT INTO audit_logs (user_id, action, ip_address, user_agent) VALUES (?, ?, ?, ?)')
      .bind(user.id, 'master_key_set', request.headers.get('CF-Connecting-IP') || '', request.headers.get('User-Agent') || '').run();

    return json({ message: 'Master key set successfully.' });
  }

  // ── MASTER KEY VERIFY ──
  if (method === 'POST' && path === '/admin/verify-master-key') {
    const { masterKey } = body || {};
    if (!masterKey) return err('Master key is required.', 400);

    const isValid = await verifyMasterKey(db, user.id, masterKey);
    if (!isValid) {
      await db.prepare('INSERT INTO audit_logs (user_id, action, ip_address, user_agent) VALUES (?, ?, ?, ?)')
        .bind(user.id, 'master_key_failed', request.headers.get('CF-Connecting-IP') || '', request.headers.get('User-Agent') || '').run();
      return err('Invalid master key.', 403);
    }

    await db.prepare('INSERT INTO audit_logs (user_id, action, ip_address, user_agent) VALUES (?, ?, ?, ?)')
      .bind(user.id, 'master_key_verified', request.headers.get('CF-Connecting-IP') || '', request.headers.get('User-Agent') || '').run();

    return json({ message: 'Master key verified.' });
  }

  // ── CHECK MASTER KEY STATUS ──
  if (method === 'GET' && path === '/admin/master-key-status') {
    const adminUser = await db.prepare('SELECT master_key_hash FROM users WHERE id = ?').bind(user.id).first();
    return json({ isSet: !!(adminUser && adminUser.master_key_hash) });
  }

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
    await db.prepare('UPDATE users SET device_fingerprint = NULL, device_ip = NULL, updated_at = datetime(\'now\') WHERE id = ?').bind(userId).run();
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

// ─── MAIN ROUTER ────────────────────────────────────────────

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

  // Admin routes
  if (path.startsWith('/admin/')) {
    if (authUser.role !== 'admin') return err('Forbidden. Admin access required.', 403);

    // Skip master key check for these endpoints
    if (path === '/admin/set-master-key' || path === '/admin/verify-master-key' || path === '/admin/master-key-status') {
      return handleAdmin(method, path, body, db, authUser, request);
    }

    // Require master key for all other admin routes
    const masterOk = await requireMasterKey(db, authUser, request);
    if (!masterOk) return err('Master key required. Please verify your master key first.', 403);

    return handleAdmin(method, path, body, db, authUser, request);
  }

  // User routes
  if (path.startsWith('/user/')) {
    return handleUser(method, path, body, db, authUser, request);
  }

  // GET /api/courses/:id
  if (method === 'GET' && path.match(/^\/courses\/\d+$/)) {
    const courseId = parseInt(path.split('/')[2]);

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
      subjectsWithLectures.push({ ...sub, lectures: lectures.results });
    }

    return json({ course, subjects: subjectsWithLectures, resources: resources.results });
  }

  return err('API endpoint not found', 404);
}
