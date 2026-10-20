const express = require('express');
const session = require('express-session');
const Database = require('better-sqlite3');
const crypto = require('crypto');

const app = express();
const db = new Database('db/campus.db');

const MODE = process.env.MODE || 'vulnerable';

app.set('view engine', 'ejs');
app.use(express.urlencoded({ extended: true }));
app.use(session({ secret: 'campusconnect-secret', resave: false, saveUninitialized: false }));

// ---- Helpers ----
function requireLogin(req, res, next) {
  if (!req.session.userId) return res.redirect('/login');
  next();
}

function getCsrfToken(req) {
  if (!req.session.csrfToken) {
    req.session.csrfToken = crypto.randomBytes(16).toString('hex');
  }
  return req.session.csrfToken;
}

function escapeHtml(str) {
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

// ---- Routes ----
app.get('/', (req, res) => res.redirect('/login'));

app.get('/login', (req, res) => {
  res.render('login', { error: null });
});

app.post('/login', (req, res) => {
  const { username, password } = req.body;
  let user;

  if (MODE === 'vulnerable') {
    // VULNERABLE: raw string concatenation — classic SQL Injection
    const query = `SELECT * FROM users WHERE username = '${username}' AND password = '${password}'`;
    console.log('Executing SQL:', query);
    try {
      user = db.prepare(query).get();
    } catch (e) {
      return res.render('login', { error: 'SQL Error: ' + e.message });
    }
  } else {
    // SAFE: parameterized query
    user = db.prepare('SELECT * FROM users WHERE username = ? AND password = ?')
             .get(username, password);
  }

  if (!user) {
    return res.render('login', { error: 'Invalid username or password.' });
  }
  req.session.userId = user.id;
  res.redirect('/dashboard');
});

app.get('/logout', (req, res) => {
  req.session.destroy(() => res.redirect('/login'));
});

app.get('/dashboard', requireLogin, (req, res) => {
  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(req.session.userId);
  res.render('dashboard', {
    user, mode: MODE,
    bioHtml: user.bio,
    searchResultsHtml: '',
    lookupResult: '',
    csrfToken: getCsrfToken(req)
  });
});

app.post('/bio', requireLogin, (req, res) => {
  const { bio, _csrf } = req.body;

  if (MODE === 'safe') {
    // SAFE: verify CSRF token before performing the state-changing action
    if (!_csrf || _csrf !== req.session.csrfToken) {
      return res.status(403).send('<h3>403 Forbidden: Invalid or missing CSRF token.</h3><a href="/dashboard">Back</a>');
    }
  }
  // VULNERABLE (default): no token check performed at all — request accepted from anywhere

  db.prepare('UPDATE users SET bio = ? WHERE id = ?').run(bio, req.session.userId);
  res.redirect('/dashboard');
});

// VULNERABLE DEMO ROUTE: state-changing action via GET, no CSRF token check
// (kept only to demonstrate the Vulnerable Version's attack; disabled in Safe mode)
app.get('/bio-update-csrf', requireLogin, (req, res) => {
  if (MODE === 'safe') {
    return res.status(403).send('<h3>403 Forbidden: This endpoint is disabled in Safe mode.</h3><a href="/dashboard">Back</a>');
  }
  const bio = req.query.bio || '';
  db.prepare('UPDATE users SET bio = ? WHERE id = ?').run(bio, req.session.userId);
  res.send('<h3>Bio updated via CSRF demo route.</h3><a href="/dashboard">Back to dashboard</a>');
});

app.get('/search', requireLogin, (req, res) => {
  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(req.session.userId);
  const q = req.query.q || '';
  let html = '';

  if (MODE === 'vulnerable') {
    // VULNERABLE: raw concatenation inside LIKE — allows UNION-based injection + Reflected XSS
    const query = `SELECT full_name, bio FROM users WHERE full_name LIKE '%${q}%'`;
    console.log('Executing SQL:', query);
    try {
      const results = db.prepare(query).all();
      html = `<p>Results for: ${q}</p><ul>`;
      results.forEach(r => { html += `<li>${r.full_name} — ${r.bio}</li>`; });
      html += '</ul>';
    } catch (e) {
      html = `<p style="color:red;">SQL Error: ${e.message}</p>`;
    }
  } else {
    // SAFE: parameterized query + output encoding of user-controlled values
    const results = db.prepare('SELECT full_name, bio FROM users WHERE full_name LIKE ?').all(`%${q}%`);
    html = `<p>Results for: ${escapeHtml(q)}</p><ul>`;
    results.forEach(r => { html += `<li>${escapeHtml(r.full_name)}</li>`; });
    html += '</ul>';
  }

  res.render('dashboard', {
    user, mode: MODE, bioHtml: user.bio, searchResultsHtml: html, lookupResult: '',
    csrfToken: getCsrfToken(req)
  });
});

app.get('/student-lookup', requireLogin, (req, res) => {
  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(req.session.userId);
  const username = req.query.username || '';
  let found;

  if (MODE === 'vulnerable') {
    const query = `SELECT * FROM users WHERE username = '${username}'`;
    console.log('Executing SQL:', query);
    try {
      found = db.prepare(query).get();
    } catch (e) {
      return res.render('dashboard', {
        user, mode: MODE, bioHtml: user.bio, searchResultsHtml: '',
        lookupResult: `<p style="color:red;">Query error (payload broke syntax).</p>`,
        csrfToken: getCsrfToken(req)
      });
    }
  } else {
    found = db.prepare('SELECT * FROM users WHERE username = ?').get(username);
  }

  const lookupResult = found
    ? '<p><b>Student exists.</b></p>'
    : '<p><b>Student not found.</b></p>';

  res.render('dashboard', {
    user, mode: MODE, bioHtml: user.bio, searchResultsHtml: '', lookupResult,
    csrfToken: getCsrfToken(req)
  });
});

app.listen(3000, () => {
  console.log(`CampusConnect running at http://localhost:3000  [MODE=${MODE}]`);
});