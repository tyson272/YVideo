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

// ===== Directories =====
const uploadDir = process.env.UPLOAD_DIR || path.join(__dirname, 'uploads');
const thumbDir = path.join(uploadDir, 'thumbnails');
const baseDataDir = process.env.DATA_DIR || __dirname;
const logDir = path.join(baseDataDir, 'logs');

if (!fs.existsSync(uploadDir)) fs.mkdirSync(uploadDir, { recursive: true });
if (!fs.existsSync(thumbDir)) fs.mkdirSync(thumbDir, { recursive: true });
if (!fs.existsSync(logDir)) fs.mkdirSync(logDir, { recursive: true });

const auditLogFile = path.join(logDir, 'audit.log');

// ===== Middleware =====
app.use(express.urlencoded({ extended: true }));

// Hide admin page from public
app.get('/admin.html', (req, res, next) => {
  if (!req.session.user || req.session.user.role !== 'admin') {
    return res.redirect('/login.html');
  }
  next();
});

app.use(express.static('public'));
app.use('/thumbnails', express.static(thumbDir));

// ===== Session =====
app.use(
  session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true,
      maxAge: 15 * 60 * 1000 // auto logout 15 min
    }
  })
);

// ===== Passwords =====
const adminHash = bcrypt.hashSync(process.env.ADMIN_PASSWORD, 10);
const siteHash = bcrypt.hashSync(process.env.SITE_PASSWORD, 10);

// ===== Helpers =====
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
    role: req.session.user?.role,
    video,
    ip: req.headers['x-forwarded-for'] || req.socket.remoteAddress,
    ua: req.headers['user-agent'],
    time: new Date().toISOString()
  };
  fs.appendFile(auditLogFile, JSON.stringify(entry) + '\n', () => {});
}

// ===== Login =====
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

// ===== Logout =====
app.get('/logout', (req, res) => {
  req.session.destroy(() => res.redirect('/login.html'));
});

// ===== Multer =====
const upload = multer({ dest: uploadDir });

// ===== UPLOAD + THUMBNAIL =====
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
    .on('end', () => {
      console.log('Thumbnail created');
      res.redirect('/admin.html');
    })
    .on('error', err => {
      console.error('FFmpeg error:', err);
      res.redirect('/admin.html');
    });
});

// ===== VIDEOS LIST =====
app.get('/videos', requireLogin, (req, res) => {
  const files = fs.readdirSync(uploadDir)
    .filter(f => f !== 'thumbnails');

  res.json(files.map(name => ({ name })));
});

// ===== STREAM =====
app.get('/stream/:name', requireLogin, (req, res) => {
  const fileName = path.basename(req.params.name);
  const filePath = path.join(uploadDir, fileName);
  if (!fs.existsSync(filePath)) return res.sendStatus(404);

  logView(req, fileName);
  fs.createReadStream(filePath).pipe(res);
});

// ===== DELETE =====
app.delete('/delete-video/:name', requireAdmin, (req, res) => {
  const fileName = path.basename(req.params.name);
  fs.unlinkSync(path.join(uploadDir, fileName));
  fs.unlink(path.join(thumbDir, fileName + '.jpg'), () => {});
  res.json({ success: true });
});

// ===== ADMIN LOGS =====
app.get('/admin/logs', requireAdmin, (req, res) => {
  if (!fs.existsSync(auditLogFile)) return res.json([]);
  const logs = fs.readFileSync(auditLogFile, 'utf8')
    .trim()
    .split('\n')
    .filter(Boolean)
    .map(l => JSON.parse(l))
    .reverse();
  res.json(logs);
});

// ===== START =====
app.listen(PORT, () => {
  console.log('🎬 YVideo with thumbnails running');
});
