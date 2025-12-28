// server.js
require('dotenv').config();

const express = require('express');
const path = require('path');
const fs = require('fs');
const session = require('express-session');
const multer = require('multer');
const bcrypt = require('bcrypt');
const rateLimit = require('express-rate-limit');

const app = express();

/**
 * 🔴 REQUIRED FOR RENDER (HTTPS behind proxy)
 * This prevents login -> instant logout
 */
app.set('trust proxy', 1);

const PORT = process.env.PORT || 3000;

// ---------- IP WHITELIST (optional) ----------
const allowedIPs = process.env.ALLOWED_IPS
  ? process.env.ALLOWED_IPS.split(',').map((ip) => ip.trim())
  : [];

app.use((req, res, next) => {
  if (allowedIPs.length === 0) return next();
  const ip = req.ip.replace('::ffff:', '');
  if (!allowedIPs.includes(ip)) {
    return res.status(403).send('Access denied');
  }
  next();
});

// ---------- Ensure uploads folder ----------
const uploadDir = path.join(__dirname, 'uploads');
if (!fs.existsSync(uploadDir)) {
  fs.mkdirSync(uploadDir, { recursive: true });
}

// ---------- Middleware ----------
app.use(express.urlencoded({ extended: true }));
app.use(express.static('public'));

// ---------- SESSION (FINAL FIX) ----------
app.use(
  session({
    name: 'yvideo.sid',
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    proxy: true, // 🔴 REQUIRED on Render
    cookie: {
      httpOnly: true,
      secure: true, // 🔴 REQUIRED for HTTPS (Render)
      sameSite: 'lax',
      maxAge: Number(process.env.SESSION_TIMEOUT) || 30 * 60 * 1000,
    },
  })
);

// ---------- Rate limit login ----------
app.use(
  '/login',
  rateLimit({
    windowMs: 5 * 60 * 1000,
    max: 10,
  })
);

// ---------- Multer (video only) ----------
const storage = multer.diskStorage({
  destination: uploadDir,
  filename(req, file, cb) {
    const name =
      Date.now() +
      '-' +
      Math.round(Math.random() * 1e9) +
      path.extname(file.originalname);
    cb(null, name);
  },
});

const upload = multer({
  storage,
  fileFilter(req, file, cb) {
    if (!file.mimetype.startsWith('video/')) {
      return cb(new Error('Video files only'));
    }
    cb(null, true);
  },
  limits: { fileSize: 500 * 1024 * 1024 },
});

// ---------- Password Hash ----------
if (!process.env.SITE_PASSWORD || !process.env.ADMIN_PASSWORD) {
  console.error('❌ Missing SITE_PASSWORD or ADMIN_PASSWORD');
  process.exit(1);
}

const siteHash = bcrypt.hashSync(process.env.SITE_PASSWORD, 10);
const adminHash = bcrypt.hashSync(process.env.ADMIN_PASSWORD, 10);

// ---------- Auth helpers ----------
function requireLogin(req, res, next) {
  if (!req.session.user) {
    return res.redirect('/login.html');
  }
  next();
}

function requireAdmin(req, res, next) {
  if (!req.session.user || req.session.user.role !== 'admin') {
    return res.status(403).send('Admins only');
  }
  next();
}

// ---------- Routes ----------

// LOGIN (password-only)
app.post('/login', async (req, res) => {
  const { password } = req.body;

  if (!password) {
    return res.redirect('/login.html?error=1');
  }

  if (await bcrypt.compare(password, adminHash)) {
    req.session.user = { role: 'admin' };
    return res.redirect('/admin.html');
  }

  if (await bcrypt.compare(password, siteHash)) {
    req.session.user = { role: 'viewer' };
    return res.redirect('/dashboard.html');
  }

  res.redirect('/login.html?error=1');
});

// LOGOUT
app.get('/logout', (req, res) => {
  req.session.destroy(() => {
    res.redirect('/login.html');
  });
});

// UPLOAD (admin only)
app.post('/upload', requireAdmin, upload.single('video'), (req, res) => {
  if (!req.file) {
    return res.status(400).send('No file uploaded');
  }
  res.redirect('/admin.html');
});

// LIST VIDEOS
app.get('/videos', requireLogin, (req, res) => {
  let files = [];
  try {
    files = fs.readdirSync(uploadDir);
  } catch (err) {
    console.error(err);
  }
  res.json(files.map((f) => ({ name: f })));
});

// STREAM (protected)
app.get('/stream/:name', requireLogin, (req, res) => {
  const fileName = path.basename(req.params.name);
  const filePath = path.join(uploadDir, fileName);

  if (!fs.existsSync(filePath)) {
    return res.sendStatus(404);
  }

  res.setHeader('Content-Type', 'video/mp4');
  res.setHeader('Cache-Control', 'no-store');
  res.setHeader('Content-Disposition', 'inline');

  fs.createReadStream(filePath).pipe(res);
});

// DELETE (admin only)
app.delete('/delete-video/:name', requireAdmin, (req, res) => {
  const filePath = path.join(uploadDir, path.basename(req.params.name));

  if (!fs.existsSync(filePath)) {
    return res.status(404).json({ error: 'File not found' });
  }

  fs.unlink(filePath, (err) => {
    if (err) {
      return res.status(500).json({ error: 'Delete failed' });
    }
    res.json({ success: true });
  });
});

// ---------- Start server ----------
app.listen(PORT, () => {
  console.log(`🔒 Secure Private Video Server running on port ${PORT}`);
});
