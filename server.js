require('dotenv').config();



const express = require('express');
const path = require('path');
const fs = require('fs');
const session = require('express-session');
const multer = require('multer');
const bcrypt = require('bcrypt');
const rateLimit = require('express-rate-limit');

const app = express();
const PORT = process.env.PORT || 3000;

// ---------- IP WHITELIST ----------
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
if (!fs.existsSync(uploadDir)) fs.mkdirSync(uploadDir);

// ---------- Middleware ----------
app.use(express.urlencoded({ extended: true }));
app.use(express.static('public'));

app.use(
  session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true,
      sameSite: 'strict',
      maxAge: Number(process.env.SESSION_TIMEOUT),
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
      Date.now() + '-' + Math.round(Math.random() * 1e9) + path.extname(file.originalname);
    cb(null, name);
  },
});

const upload = multer({
  storage,
  fileFilter(req, file, cb) {
    if (!file.mimetype.startsWith('video/')) {
      return cb(new Error('Video only'));
    }
    cb(null, true);
  },
  limits: { fileSize: 500 * 1024 * 1024 },
});

// ---------- Password Hash ----------
const siteHash = bcrypt.hashSync(process.env.SITE_PASSWORD, 10);
const adminHash = bcrypt.hashSync(process.env.ADMIN_PASSWORD, 10);

// ---------- Auth helpers ----------
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

// ---------- Routes ----------

// LOGIN
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

// LOGOUT
app.get('/logout', (req, res) => {
  req.session.destroy(() => res.redirect('/login.html'));
});

// UPLOAD
app.post('/upload', requireAdmin, upload.single('video'), (req, res) => {
  res.redirect('/admin.html');
});

// LIST VIDEOS
app.get('/videos', requireLogin, (req, res) => {
  const files = fs.readdirSync(uploadDir);
  res.json(files.map((f) => ({ name: f })));
});

// STREAM (ANTI-DOWNLOAD BEST EFFORT)
app.get('/stream/:name', requireLogin, (req, res) => {
  const fileName = path.basename(req.params.name);
  const filePath = path.join(uploadDir, fileName);

  if (!fs.existsSync(filePath)) return res.sendStatus(404);

  res.setHeader('Content-Type', 'video/mp4');
  res.setHeader('Accept-Ranges', 'bytes');
  res.setHeader('Cache-Control', 'no-store');
  res.setHeader('Content-Disposition', 'inline');

  fs.createReadStream(filePath).pipe(res);
});

// DELETE
app.delete('/delete-video/:name', requireAdmin, (req, res) => {
  const filePath = path.join(uploadDir, path.basename(req.params.name));
  fs.unlinkSync(filePath);
  res.json({ success: true });
});

// ---------- Start ----------
app.listen(PORT, () => {
  console.log(`🔒 Secure Private Video Server running on ${PORT}`);
});
