// ============================================================
// SciVerse Academy — Complete Backend (FULLY FIXED)
// functions/api/[[route]].js
// ============================================================

const JWT_SECRET = 'sciverse-academy-jwt-secret-key-2026';
const IMGBB_API_KEY = '32006c4775fab8a5ff2fae9d23b9f863';

const CORS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type, Authorization'
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
  // Users table
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

  // Courses table
  await db.prepare(`
    CREATE TABLE IF NOT EXISTS courses (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      title TEXT NOT NULL,
      description TEXT DEFAULT '',
      thumbnail_url TEXT DEFAULT '',
      icon TEXT DEFAULT '📚',
      is_public INTEGER DEFAULT 0,
      is_featured INTEGER DEFAULT 0,
      created_at TEXT NOT NULL DEFAULT (datetime('now')),
      updated_at TEXT NOT NULL DEFAULT (datetime('now'))
    )
  `).run();

  // Subjects table
  await db.prepare(`
    CREATE TABLE IF NOT EXISTS subjects (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      course_id INTEGER NOT NULL,
      title TEXT NOT NULL,
      description TEXT DEFAULT '',
      sort_order INTEGER NOT NULL DEFAULT 0,
      created_at TEXT NOT NULL DEFAULT (datetime('now')),
      updated_at TEXT NOT NULL DEFAULT (datetime('now')),
      FOREIGN KEY (course_id) REFERENCES courses(id) ON DELETE CASCADE
    )
  `).run();

  // Lectures table
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
      FOREIGN KEY (subject_id) REFERENCES subjects(id) ON DELETE CASCADE
    )
  `).run();

  // Resources table
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
      FOREIGN KEY (course_id) REFERENCES courses(id) ON DELETE CASCADE
    )
  `).run();

  // Enrollments table
  await db.prepare(`
    CREATE TABLE IF NOT EXISTS enrollments (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL,
      course_id INTEGER NOT NULL,
      enrolled_at TEXT NOT NULL DEFAULT (datetime('now')),
      FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
      FOREIGN KEY (course_id) REFERENCES courses(id) ON DELETE CASCADE,
      UNIQUE(user_id, course_id)
    )
  `).run();

  // Audit logs table
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

  // Payments table
  await db.prepare(`
    CREATE TABLE IF NOT EXISTS payments (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL,
      course_id INTEGER NOT NULL,
      amount INTEGER NOT NULL DEFAULT 0,
      method TEXT NOT NULL,
      phone TEXT NOT NULL,
      transaction_id TEXT,
      status TEXT DEFAULT 'pending',
      created_at TEXT NOT NULL DEFAULT (datetime('now')),
      verified_at TEXT,
      FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
      FOREIGN KEY (course_id) REFERENCES courses(id) ON DELETE CASCADE
    )
  `).run();

  // Indexes
  await db.prepare(`CREATE INDEX IF NOT EXISTS idx_users_email ON users(email)`).run();
  await db.prepare(`CREATE INDEX IF NOT EXISTS idx_subjects_course ON subjects(course_id)`).run();
  await db.prepare(`CREATE INDEX IF NOT EXISTS idx_lectures_subject ON lectures(subject_id)`).run();
  await db.prepare(`CREATE INDEX IF NOT EXISTS idx_resources_course ON resources(course_id)`).run();
  await db.prepare(`CREATE INDEX IF NOT EXISTS idx_enrollments_user ON enrollments(user_id)`).run();
  await db.prepare(`CREATE INDEX IF NOT EXISTS idx_enrollments_course ON enrollments(course_id)`).run();
  await db.prepare(`CREATE INDEX IF NOT EXISTS idx_audit_user ON audit_logs(user_id)`).run();
  await db.prepare(`CREATE INDEX IF NOT EXISTS idx_payments_user ON payments(user_id)`).run();
  await db.prepare(`CREATE INDEX IF NOT EXISTS idx_payments_course ON payments(course_id)`).run();
  await db.prepare(`CREATE INDEX IF NOT EXISTS idx_payments_status ON payments(status)`).run();

  // Seed admin
  const adminPass = await sha256('Sc1Verse@Admin#2026');
  await db.prepare(`
    INSERT OR IGNORE INTO users (name, email, password, role, is_approved)
    VALUES ('Admin', 'admin@sciverse.com', ?, 'admin', 1)
  `).bind(adminPass).run();

  // Seed sample course
  await db.prepare(`
    INSERT OR IGNORE INTO courses (title, description, icon, is_public, is_featured)
    VALUES ('Introduction to Science', 'Learn the fundamentals of science.', '🔬', 1, 1)
  `).run();

  // Seed sample subject
  await db.prepare(`
    INSERT OR IGNORE INTO subjects (course_id, title, description, sort_order)
    VALUES (1, 'Chapter 1: Basics', 'Introduction to basic concepts', 0)
  `).run();

  // Seed sample lecture
  await db.prepare(`
    INSERT OR IGNORE INTO lectures (subject_id, title, youtube_id, sort_order)
    VALUES (1, 'Lesson 1: Getting Started', 'dQw4w9WgXcQ', 0)
  `).run();

  // Migrations
  const migrations = [
    "ALTER TABLE users ADD COLUMN device_ip TEXT",
    "ALTER TABLE users ADD COLUMN device_fingerprint TEXT",
    "ALTER TABLE courses ADD COLUMN is_public INTEGER DEFAULT 0",
    "ALTER TABLE courses ADD COLUMN is_featured INTEGER DEFAULT 0",
    "ALTER TABLE courses ADD COLUMN thumbnail_url TEXT DEFAULT ''",
    "ALTER TABLE courses ADD COLUMN icon TEXT DEFAULT '📚'",
  ];
  for (const sql of migrations) {
    try { await db.prepare(sql).run(); } catch (e) { /* column likely exists */ }
  }
}

// ─── AUTH HANDLERS ──────────────────────────────────────────

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

// ─── PUBLIC COURSE HANDLERS ──────────────────────────────────

async function handlePublicCourses(method, path, db, request) {
  // GET /api/courses/public - Featured courses for index
  if (method === 'GET' && path === '/courses/public') {
    const url = new URL(request.url);
    const limit = parseInt(url.searchParams.get('limit')) || 3;
    
    const courses = await db.prepare(`
      SELECT 
        c.*,
        COUNT(DISTINCT s.id) as subject_count,
        COUNT(DISTINCT l.id) as lecture_count,
        COUNT(DISTINCT e.id) as enrollment_count
      FROM courses c
      LEFT JOIN subjects s ON c.id = s.course_id
      LEFT JOIN lectures l ON s.id = l.subject_id
      LEFT JOIN enrollments e ON c.id = e.course_id
      WHERE c.is_public = 1 AND c.is_featured = 1
      GROUP BY c.id
      ORDER BY c.created_at DESC
      LIMIT ?
    `).bind(limit).all();
    
    return json({ courses: courses.results });
  }

  // GET /api/courses/explore - All public courses
  if (method === 'GET' && path === '/courses/explore') {
    const courses = await db.prepare(`
      SELECT 
        c.*,
        COUNT(DISTINCT s.id) as subject_count,
        COUNT(DISTINCT l.id) as lecture_count,
        COUNT(DISTINCT e.id) as enrollment_count
      FROM courses c
      LEFT JOIN subjects s ON c.id = s.course_id
      LEFT JOIN lectures l ON s.id = l.subject_id
      LEFT JOIN enrollments e ON c.id = e.course_id
      WHERE c.is_public = 1
      GROUP BY c.id
      ORDER BY c.is_featured DESC, c.created_at DESC
    `).all();
    
    return json({ courses: courses.results });
  }

  // GET /api/courses/:id - Single course detail
  if (method === 'GET' && path.match(/^\/courses\/\d+$/)) {
    const courseId = parseInt(path.split('/')[2]);
    
    const course = await db.prepare('SELECT * FROM courses WHERE id = ?').bind(courseId).first();
    if (!course) return err('Course not found', 404);
    
    // If course is not public, check auth
    if (!course.is_public) {
      const authUser = await getUser(request);
      if (!authUser) return err('Authentication required', 401);
      if (authUser.role !== 'admin') {
        const enrollment = await db.prepare('SELECT * FROM enrollments WHERE user_id = ? AND course_id = ?').bind(authUser.id, courseId).first();
        if (!enrollment) return err('Access denied. Course is not public.', 403);
      }
    }
    
    const subjects = await db.prepare('SELECT * FROM subjects WHERE course_id = ? ORDER BY sort_order ASC, id ASC').bind(courseId).all();
    const resources = await db.prepare('SELECT * FROM resources WHERE course_id = ? ORDER BY sort_order ASC, id ASC').bind(courseId).all();
    const enrollmentCount = await db.prepare('SELECT COUNT(*) as count FROM enrollments WHERE course_id = ?').bind(courseId).first();
    
    const subjectsWithLectures = [];
    for (const sub of subjects.results) {
      const lectures = await db.prepare('SELECT * FROM lectures WHERE subject_id = ? ORDER BY sort_order ASC, id ASC').bind(sub.id).all();
      subjectsWithLectures.push({ ...sub, lectures: lectures.results });
    }
    
    return json({ 
      course: { 
        ...course, 
        enrollment_count: enrollmentCount ? enrollmentCount.count : 0 
      }, 
      subjects: subjectsWithLectures, 
      resources: resources.results 
    });
  }

  // GET /api/courses/stats - Course statistics
  if (method === 'GET' && path === '/courses/stats') {
    const totalCourses = await db.prepare('SELECT COUNT(*) as count FROM courses WHERE is_public = 1').first();
    const totalSubjects = await db.prepare('SELECT COUNT(*) as count FROM subjects').first();
    const totalLectures = await db.prepare('SELECT COUNT(*) as count FROM lectures').first();
    
    return json({
      stats: {
        total_courses: totalCourses ? totalCourses.count : 0,
        total_subjects: totalSubjects ? totalSubjects.count : 0,
        total_lectures: totalLectures ? totalLectures.count : 0
      }
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

    // Admin bypass — admins can view any course without enrollment
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
  // ── USERS ──
  if (method === 'GET' && path === '/admin/users') {
    const users = await db.prepare('SELECT id, name, email, role, is_approved, is_blocked, device_fingerprint, device_ip, created_at FROM users ORDER BY created_at DESC').all();
    return json({ users: users.results });
  }

  if (method === 'PUT' && path.match(/^\/admin\/users\/\d+\/approve$/)) {
    const userId = parseInt(path.split('/')[3]);
    await db.prepare('UPDATE users SET is_approved = 1, updated_at = datetime("now") WHERE id = ?').bind(userId).run();
    await db.prepare('INSERT INTO audit_logs (user_id, action, ip_address, user_agent) VALUES (?, ?, ?, ?)').bind(user.id, `approved_user_${userId}`, request.headers.get('CF-Connecting-IP') || '', request.headers.get('User-Agent') || '').run();
    return json({ message: 'User approved.' });
  }

  if (method === 'PUT' && path.match(/^\/admin\/users\/\d+\/block$/)) {
    const userId = parseInt(path.split('/')[3]);
    await db.prepare('UPDATE users SET is_blocked = 1, updated_at = datetime("now") WHERE id = ?').bind(userId).run();
    await db.prepare('INSERT INTO audit_logs (user_id, action, ip_address, user_agent) VALUES (?, ?, ?, ?)').bind(user.id, `blocked_user_${userId}`, request.headers.get('CF-Connecting-IP') || '', request.headers.get('User-Agent') || '').run();
    return json({ message: 'User blocked.' });
  }

  if (method === 'PUT' && path.match(/^\/admin\/users\/\d+\/unblock$/)) {
    const userId = parseInt(path.split('/')[3]);
    await db.prepare('UPDATE users SET is_blocked = 0, updated_at = datetime("now") WHERE id = ?').bind(userId).run();
    await db.prepare('INSERT INTO audit_logs (user_id, action, ip_address, user_agent) VALUES (?, ?, ?, ?)').bind(user.id, `unblocked_user_${userId}`, request.headers.get('CF-Connecting-IP') || '', request.headers.get('User-Agent') || '').run();
    return json({ message: 'User unblocked.' });
  }

  if (method === 'DELETE' && path.match(/^\/admin\/users\/\d+$/)) {
    const userId = parseInt(path.split('/')[3]);
    await db.prepare('DELETE FROM enrollments WHERE user_id = ?').bind(userId).run();
    await db.prepare('DELETE FROM audit_logs WHERE user_id = ?').bind(userId).run();
    await db.prepare('DELETE FROM payments WHERE user_id = ?').bind(userId).run();
    await db.prepare('DELETE FROM users WHERE id = ?').bind(userId).run();
    await db.prepare('INSERT INTO audit_logs (user_id, action, ip_address, user_agent) VALUES (?, ?, ?, ?)').bind(user.id, `deleted_user_${userId}`, request.headers.get('CF-Connecting-IP') || '', request.headers.get('User-Agent') || '').run();
    return json({ message: 'User deleted.' });
  }

  if (method === 'PUT' && path.match(/^\/admin\/users\/\d+\/reset-device$/)) {
    const userId = parseInt(path.split('/')[3]);
    await db.prepare('UPDATE users SET device_fingerprint = NULL, updated_at = datetime("now") WHERE id = ?').bind(userId).run();
    await db.prepare('INSERT INTO audit_logs (user_id, action, ip_address, user_agent) VALUES (?, ?, ?, ?)').bind(user.id, `reset_device_${userId}`, request.headers.get('CF-Connecting-IP') || '', request.headers.get('User-Agent') || '').run();
    return json({ message: 'Device fingerprint reset. User can log in from a new device.' });
  }

  // ── COURSES ──
  if (method === 'GET' && path === '/admin/courses') {
    const courses = await db.prepare('SELECT * FROM courses ORDER BY created_at DESC').all();
    return json({ courses: courses.results });
  }

  if (method === 'POST' && path === '/admin/courses') {
    const { title, description, thumbnail_url, icon, is_public, is_featured } = body || {};
    if (!title) return err('Title required', 400);
    const result = await db.prepare(
      'INSERT INTO courses (title, description, thumbnail_url, icon, is_public, is_featured) VALUES (?, ?, ?, ?, ?, ?)'
    ).bind(title.trim(), description || '', thumbnail_url || '', icon || '📚', is_public || 0, is_featured || 0).run();
    await db.prepare('INSERT INTO audit_logs (user_id, action, ip_address, user_agent) VALUES (?, ?, ?, ?)').bind(user.id, `created_course_${result.meta.last_row_id}`, request.headers.get('CF-Connecting-IP') || '', request.headers.get('User-Agent') || '').run();
    return json({ id: result.meta.last_row_id, message: 'Course created.' }, 201);
  }

  if (method === 'PUT' && path.match(/^\/admin\/courses\/\d+$/)) {
    const courseId = parseInt(path.split('/')[3]);
    const { title, description, thumbnail_url, icon, is_public, is_featured } = body || {};
    if (!title) return err('Title required', 400);
    await db.prepare(
      'UPDATE courses SET title = ?, description = ?, thumbnail_url = ?, icon = ?, is_public = ?, is_featured = ?, updated_at = datetime("now") WHERE id = ?'
    ).bind(title.trim(), description || '', thumbnail_url || '', icon || '📚', is_public || 0, is_featured || 0, courseId).run();
    return json({ message: 'Course updated.' });
  }

  if (method === 'DELETE' && path.match(/^\/admin\/courses\/\d+$/)) {
    const courseId = parseInt(path.split('/')[3]);
    await db.prepare('DELETE FROM courses WHERE id = ?').bind(courseId).run();
    await db.prepare('INSERT INTO audit_logs (user_id, action, ip_address, user_agent) VALUES (?, ?, ?, ?)').bind(user.id, `deleted_course_${courseId}`, request.headers.get('CF-Connecting-IP') || '', request.headers.get('User-Agent') || '').run();
    return json({ message: 'Course deleted.' });
  }

  // Toggle public
  if (method === 'PUT' && path.match(/^\/admin\/courses\/\d+\/toggle-public$/)) {
    const courseId = parseInt(path.split('/')[3]);
    const course = await db.prepare('SELECT is_public FROM courses WHERE id = ?').bind(courseId).first();
    if (!course) return err('Course not found', 404);
    const newVal = course.is_public ? 0 : 1;
    await db.prepare('UPDATE courses SET is_public = ?, updated_at = datetime("now") WHERE id = ?').bind(newVal, courseId).run();
    return json({ is_public: newVal, message: 'Course visibility toggled.' });
  }

  // Toggle featured
  if (method === 'PUT' && path.match(/^\/admin\/courses\/\d+\/toggle-featured$/)) {
    const courseId = parseInt(path.split('/')[3]);
    const course = await db.prepare('SELECT is_featured FROM courses WHERE id = ?').bind(courseId).first();
    if (!course) return err('Course not found', 404);
    const newVal = course.is_featured ? 0 : 1;
    await db.prepare('UPDATE courses SET is_featured = ?, updated_at = datetime("now") WHERE id = ?').bind(newVal, courseId).run();
    return json({ is_featured: newVal, message: 'Course featured toggled.' });
  }

  // Upload thumbnail via ImgBB
  if (method === 'POST' && path.match(/^\/admin\/courses\/\d+\/thumbnail$/)) {
    const courseId = parseInt(path.split('/')[3]);
    const formData = await request.formData();
    const image = formData.get('image');
    if (!image) return err('Image required', 400);

    try {
      const imgFormData = new FormData();
      imgFormData.append('image', image);
      const response = await fetch(`https://api.imgbb.com/1/upload?key=${IMGBB_API_KEY}`, {
        method: 'POST',
        body: imgFormData
      });
      const data = await response.json();
      if (!data.success) return err('Failed to upload to ImgBB', 400);
      
      const thumbnail_url = data.data.url;
      await db.prepare('UPDATE courses SET thumbnail_url = ?, updated_at = datetime("now") WHERE id = ?').bind(thumbnail_url, courseId).run();
      return json({ thumbnail_url, message: 'Thumbnail uploaded successfully.' });
    } catch (e) {
      return err('Failed to upload image.', 500);
    }
  }

  // ── SUBJECTS ──
  if (method === 'GET' && path === '/admin/subjects') {
    const subjects = await db.prepare('SELECT * FROM subjects ORDER BY course_id, sort_order ASC').all();
    return json({ subjects: subjects.results });
  }

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
    await db.prepare('UPDATE subjects SET title = ?, description = ?, sort_order = ?, updated_at = datetime("now") WHERE id = ?').bind(title.trim(), description || '', sort_order || 0, subjectId).run();
    return json({ message: 'Subject updated.' });
  }

  if (method === 'DELETE' && path.match(/^\/admin\/subjects\/\d+$/)) {
    const subjectId = parseInt(path.split('/')[3]);
    await db.prepare('DELETE FROM subjects WHERE id = ?').bind(subjectId).run();
    return json({ message: 'Subject deleted.' });
  }

  // ── LECTURES ──
  if (method === 'GET' && path === '/admin/lectures') {
    const lectures = await db.prepare('SELECT * FROM lectures ORDER BY subject_id, sort_order ASC').all();
    return json({ lectures: lectures.results });
  }

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
    await db.prepare('UPDATE lectures SET title = ?, youtube_id = ?, pdf_url = ?, sort_order = ?, updated_at = datetime("now") WHERE id = ?').bind(title.trim(), youtube_id || '', pdf_url || '', sort_order || 0, lectureId).run();
    return json({ message: 'Lecture updated.' });
  }

  if (method === 'DELETE' && path.match(/^\/admin\/lectures\/\d+$/)) {
    const lectureId = parseInt(path.split('/')[3]);
    await db.prepare('DELETE FROM lectures WHERE id = ?').bind(lectureId).run();
    return json({ message: 'Lecture deleted.' });
  }

  // ── RESOURCES ──
  if (method === 'GET' && path === '/admin/resources') {
    const resources = await db.prepare('SELECT * FROM resources ORDER BY course_id, sort_order ASC').all();
    return json({ resources: resources.results });
  }

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
    await db.prepare('UPDATE resources SET title = ?, description = ?, link_url = ?, sort_order = ?, updated_at = datetime("now") WHERE id = ?').bind(title.trim(), description || '', link_url || '', sort_order || 0, resourceId).run();
    return json({ message: 'Resource updated.' });
  }

  if (method === 'DELETE' && path.match(/^\/admin\/resources\/\d+$/)) {
    const resourceId = parseInt(path.split('/')[3]);
    await db.prepare('DELETE FROM resources WHERE id = ?').bind(resourceId).run();
    return json({ message: 'Resource deleted.' });
  }

  // ── ENROLLMENTS ──
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

  // ── PAYMENTS ──
  if (method === 'GET' && path === '/admin/payments') {
    const payments = await db.prepare(`
      SELECT p.*, u.name as user_name, u.email as user_email, c.title as course_title
      FROM payments p
      JOIN users u ON p.user_id = u.id
      JOIN courses c ON p.course_id = c.id
      ORDER BY p.created_at DESC
    `).all();
    return json({ payments: payments.results });
  }

  if (method === 'GET' && path === '/admin/payments/pending') {
    const payments = await db.prepare(`
      SELECT p.*, u.name as user_name, u.email as user_email, c.title as course_title
      FROM payments p
      JOIN users u ON p.user_id = u.id
      JOIN courses c ON p.course_id = c.id
      WHERE p.status = 'pending'
      ORDER BY p.created_at ASC
    `).all();
    return json({ payments: payments.results });
  }

  if (method === 'PUT' && path.match(/^\/admin\/payments\/\d+\/verify$/)) {
    const paymentId = parseInt(path.split('/')[3]);
    const payment = await db.prepare('SELECT * FROM payments WHERE id = ?').bind(paymentId).first();
    if (!payment) return err('Payment not found', 404);
    if (payment.status !== 'pending') return err('Payment already verified or rejected', 400);
    
    await db.prepare('UPDATE payments SET status = "verified", verified_at = datetime("now") WHERE id = ?').bind(paymentId).run();
    await db.prepare('INSERT OR IGNORE INTO enrollments (user_id, course_id) VALUES (?, ?)').bind(payment.user_id, payment.course_id).run();
    await db.prepare('INSERT INTO audit_logs (user_id, action, ip_address, user_agent) VALUES (?, ?, ?, ?)').bind(user.id, `verified_payment_${paymentId}`, request.headers.get('CF-Connecting-IP') || '', request.headers.get('User-Agent') || '').run();
    return json({ message: 'Payment verified and user enrolled.' });
  }

  if (method === 'DELETE' && path.match(/^\/admin\/payments\/\d+$/)) {
    const paymentId = parseInt(path.split('/')[3]);
    const payment = await db.prepare('SELECT * FROM payments WHERE id = ?').bind(paymentId).first();
    if (!payment) return err('Payment not found', 404);
    
    await db.prepare('DELETE FROM payments WHERE id = ?').bind(paymentId).run();
    await db.prepare('INSERT INTO audit_logs (user_id, action, ip_address, user_agent) VALUES (?, ?, ?, ?)').bind(user.id, `deleted_payment_${paymentId}`, request.headers.get('CF-Connecting-IP') || '', request.headers.get('User-Agent') || '').run();
    return json({ message: 'Payment deleted.' });
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
    const totalPayments = await db.prepare('SELECT COUNT(*) as count FROM payments WHERE status = "verified"').first();
    const totalRevenue = await db.prepare('SELECT SUM(amount) as total FROM payments WHERE status = "verified"').first();
    return json({
      stats: {
        total_users: totalUsers ? totalUsers.count : 0,
        total_courses: totalCourses ? totalCourses.count : 0,
        total_enrollments: totalEnrollments ? totalEnrollments.count : 0,
        pending_users: pendingUsers ? pendingUsers.count : 0,
        blocked_users: blockedUsers ? blockedUsers.count : 0,
        total_payments: totalPayments ? totalPayments.count : 0,
        total_revenue: totalRevenue ? totalRevenue.total : 0
      }
    });
  }

  return err('Not found', 404);
}

// ─── PAYMENT HANDLERS ──────────────────────────────────────

async function handlePayments(method, path, body, db, user, request) {
  // POST /api/payments - Submit payment
  if (method === 'POST' && path === '/payments') {
    const { course_id, method, phone, transaction_id, amount } = body || {};
    if (!course_id || !method || !phone) return err('course_id, method, and phone are required', 400);
    if (!['bkash', 'nagad'].includes(method)) return err('Invalid payment method', 400);
    
    const course = await db.prepare('SELECT * FROM courses WHERE id = ?').bind(course_id).first();
    if (!course) return err('Course not found', 404);
    
    // Check if already enrolled
    const enrolled = await db.prepare('SELECT * FROM enrollments WHERE user_id = ? AND course_id = ?').bind(user.id, course_id).first();
    if (enrolled) return err('Already enrolled in this course', 400);
    
    // Check if payment already exists
    const existing = await db.prepare('SELECT * FROM payments WHERE user_id = ? AND course_id = ? AND status = "pending"').bind(user.id, course_id).first();
    if (existing) return err('You already have a pending payment for this course', 400);
    
    const result = await db.prepare(
      'INSERT INTO payments (user_id, course_id, amount, method, phone, transaction_id, status) VALUES (?, ?, ?, ?, ?, ?, ?)'
    ).bind(user.id, course_id, amount || 0, method, phone, transaction_id || '', 'pending').run();
    
    await db.prepare('INSERT INTO audit_logs (user_id, action, ip_address, user_agent) VALUES (?, ?, ?, ?)').bind(user.id, `submitted_payment_${result.meta.last_row_id}`, request.headers.get('CF-Connecting-IP') || '', request.headers.get('User-Agent') || '').run();
    
    return json({ 
      id: result.meta.last_row_id, 
      message: 'Payment submitted successfully. Awaiting admin verification.' 
    }, 201);
  }

  // GET /api/payments/status/:id - Check payment status
  if (method === 'GET' && path.match(/^\/payments\/status\/\d+$/)) {
    const paymentId = parseInt(path.split('/')[3]);
    const payment = await db.prepare('SELECT status, created_at, verified_at FROM payments WHERE id = ? AND user_id = ?').bind(paymentId, user.id).first();
    if (!payment) return err('Payment not found', 404);
    return json({ payment });
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

  console.log('📡 Request:', method, path);

  // CORS preflight
  if (method === 'OPTIONS') {
    return new Response(null, { status: 204, headers: CORS });
  }

  // Ensure tables once per worker
  if (!globalThis.__tablesReady) {
    console.log('📦 Creating tables...');
    await ensureTables(db);
    globalThis.__tablesReady = true;
    console.log('✅ Tables ready');
  }

  let body = null;
  if (method === 'POST' || method === 'PUT') {
    try { 
      body = await request.json(); 
      console.log('📦 Body:', JSON.stringify(body));
    } catch (e) { 
      body = {}; 
    }
  }

  // ═══════════════════════════════════════════════════════════
  // ROUTE: AUTH - NO AUTH REQUIRED (MUST BE FIRST)
  // ═══════════════════════════════════════════════════════════
  if (path === '/auth/login' || path === '/auth/register') {
    console.log('🔐 Auth route:', path);
    return handleAuth(method, path, body, db, request);
  }

  // ═══════════════════════════════════════════════════════════
  // ROUTE: PUBLIC COURSES - NO AUTH REQUIRED
  // ═══════════════════════════════════════════════════════════
  if (path === '/courses/public' || path === '/courses/explore' || path === '/courses/stats') {
    console.log('📚 Public courses route:', path);
    return handlePublicCourses(method, path, db, request);
  }

  // Single course - check if public
  if (path.match(/^\/courses\/\d+$/)) {
    console.log('📖 Single course route:', path);
    const courseId = parseInt(path.split('/')[2]);
    const course = await db.prepare('SELECT is_public FROM courses WHERE id = ?').bind(courseId).first();
    
    // If course is public, allow access without auth
    if (course && course.is_public === 1) {
      return handlePublicCourses(method, path, db, request);
    }
  }

  // ═══════════════════════════════════════════════════════════
  // PROTECTED ROUTES - AUTH REQUIRED
  // ═══════════════════════════════════════════════════════════
  const authUser = await getUser(request);
  if (!authUser) {
    console.log('❌ No auth token');
    return err('Authentication required.', 401);
  }
  console.log('✅ Auth user:', authUser.email);

  // Admin routes
  if (path.startsWith('/admin/')) {
    if (authUser.role !== 'admin') {
      console.log('❌ Not admin:', authUser.role);
      return err('Forbidden. Admin access required.', 403);
    }
    console.log('👑 Admin route:', path);
    return handleAdmin(method, path, body, db, authUser, request);
  }

  // User routes
  if (path.startsWith('/user/')) {
    console.log('👤 User route:', path);
    return handleUser(method, path, body, db, authUser, request);
  }

  // Payment routes
  if (path === '/payments' || path.startsWith('/payments/')) {
    console.log('💳 Payment route:', path);
    return handlePayments(method, path, body, db, authUser, request);
  }

  console.log('❌ Route not found:', path);
  return err('API endpoint not found', 404);
}
