require('dotenv').config();

const express = require('express');
const session = require('express-session');
const multer = require('multer');
const bcrypt = require('bcrypt');
const fs = require('fs');
const path = require('path');
const ffmpeg = require('fluent-ffmpeg');

const app = express();
const PORT = process.env.PORT || 3000;

/* =========================
   DIRECTORIES (FREE SAFE)
   ========================= */

const uploadDir = path.join(__dirname, 'uploads');
const thumbDir = path.join(uploadDir, 'thumbnails');
const logDir = path.join(__dirname, 'logs');

if (!fs.existsSync(uploadDir)) fs.mkdirSync(uploadDir);
if (!fs.existsSync(thumbDir)) fs.mkdirSync(thumbDir);
if (!fs.existsSync(logDir)) fs.mkdirSync(logDir);

const auditLog = path.join(logDir, 'audit.log');

/* =========================
   MIDDLEWARE
   ========================= */

app.use(express.urlencoded({ extended: true }));

// Protect admin page
app.get('/admin.html', (req, res, next) => {
  if (!req.session.user || req.session.user.role !== 'admin') {
    return res.redirect('/login.html');
  }
  next();
});

app.use(express.static('public'));
app.use('/thumbnails', express.static(thumbDir));

/* =========================
   SESSION
   ========================= */

app.use(
  session({
    secret: process.env.SESSION_SECRET || 'secret',
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true,
      maxAge: 15 * 60 * 1000 // 15 minutes auto logout
    }
  })
);

/* =========================
   PASSWORDS
   ========================= */

const adminHash = bcrypt.hashSync(process.env.ADMIN_PASSWORD, 10);
const siteHash = bcrypt.hashSync(process.env.SITE_PASSWORD, 10);

/* =========================
   HELPERS
   ========================= */

function requireLogin(req, res, next) {
  if (!req.session.user) return res.redirect('/login.html');
  next();
}

function requireAdmin(req, res, next) {
  if (!req.session.user || req.session.user.role !== 'admin') {
    return res.status(403).send('Admins only');
  }
  next();
}

function logView(req, video) {
  const entry = {
    role: req.session.user.role,
    video,
    ip: req.headers['x-forwarded-for'] || req.socket.remoteAddress,
    time: new Date().toISOString()
  };

  fs.appendFile(auditLog, JSON.stringify(entry) + '\n', () => {});
}

/* =========================
   AUTH ROUTES
   ========================= */

app.post('/login', async (req, res) => {
  const { password } = req.body;

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

app.get('/logout', (req, res) => {
  req.session.destroy(() => res.redirect('/login.html'));
});

/* =========================
   UPLOAD + THUMBNAIL
   ========================= */

const upload = multer({ dest: uploadDir });

app.post('/upload', requireAdmin, upload.single('video'), (req, res) => {
  const videoPath = path.join(uploadDir, req.file.filename);
  const thumbPath = path.join(thumbDir, req.file.filename + '.jpg');

  ffmpeg(videoPath)
    .screenshots({
      timestamps: ['5'],
      filename: path.basename(thumbPath),
      folder: thumbDir,
      size: '320x180'
    })
    .on('end', () => res.redirect('/admin.html'))
    .on('error', err => {
      console.error('FFmpeg error:', err.message);
      res.redirect('/admin.html');
    });
});

/* =========================
   VIDEOS API
   ========================= */

app.get('/videos', requireLogin, (req, res) => {
  const files = fs
    .readdirSync(uploadDir)
    .filter(f => f !== 'thumbnails');

  res.json(files.map(name => ({ name })));
});

/* =========================
   STREAM VIDEO
   ========================= */

app.get('/stream/:name', requireLogin, (req, res) => {
  const fileName = path.basename(req.params.name);
  const filePath = path.join(uploadDir, fileName);

  if (!fs.existsSync(filePath)) return res.sendStatus(404);

  logView(req, fileName);
  fs.createReadStream(filePath).pipe(res);
});

/* =========================
   DELETE VIDEO
   ========================= */

app.delete('/delete-video/:name', requireAdmin, (req, res) => {
  const name = path.basename(req.params.name);

  fs.unlinkSync(path.join(uploadDir, name));
  fs.unlink(path.join(thumbDir, name + '.jpg'), () => {});

  res.json({ success: true });
});

/* =========================
   ADMIN LOGS
   ========================= */

app.get('/admin/logs', requireAdmin, (req, res) => {
  if (!fs.existsSync(auditLog)) return res.json([]);

  const logs = fs
    .readFileSync(auditLog, 'utf8')
    .trim()
    .split('\n')
    .map(JSON.parse)
    .reverse();

  res.json(logs);
});

/* =========================
   START SERVER
   ========================= */

app.listen(PORT, () => {
  console.log('🎬 YVideo running (Render Free Plan)');
});
