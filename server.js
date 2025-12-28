// server.js
require('dotenv').config();

const express = require('express');
const path = require('path');
const fs = require('fs');
const multer = require('multer');
const bcrypt = require('bcrypt');
const rateLimit = require('express-rate-limit');
const cookieSession = require('cookie-session');

const app = express();
const PORT = process.env.PORT || 3000;

// ---------- Middleware ----------
app.use(express.urlencoded({ extended: true }));
app.use(express.static('public'));

// ---------- COOKIE SESSION (RENDER SAFE) ----------
app.use(
  cookieSession({
    name: 'yvideo-session',
    keys: [process.env.SESSION_SECRET],
    maxAge: Number(process.env.SESSION_TIMEOUT) || 30 * 60 * 1000,
    sameSite: 'lax',
    secure: true, // Render is HTTPS
    httpOnly: true,
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

// ---------- Upload folder ----------
const uploadDir = path.join(__dirname, 'uploads');
if (!fs.existsSync(uploadDir)) {
  fs.mkdirSync(uploadDir, { recursive: true });
}

// ---------- Multer ----------
const storage = multer.diskStorage({
  destination: uploadDir,
  filename(req, file, cb) {
    cb(
      null,
      Date.now() + '-' + Math.round(Math.random() * 1e9) + path.extname(file.originalname)
    );
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
});

// ---------- Password Hash ----------
const siteHash = bcrypt.hashSync(process.env.SITE_PASSWORD, 10);
const adminHash = bcrypt.hashSync(process.env.ADMIN_PASSWORD, 10);

// ---------- Auth helpers ----------
function requireLogin(req, res, next) {
  if (!req.session || !req.session.role) {
    return res.redirect('/login.html');
  }
  next();
}

function requireAdmin(req, res, next) {
  if (!req.session || req.session.role !== 'admin') {
    return res.status(403).send('Admins only');
  }
  next();
}

// ---------- Routes ----------

// LOGIN
app.post('/login', async (req, res) => {
  const { password } = req.body;

  if (await bcrypt.compare(password, adminHash)) {
    req.session.role = 'admin';
    return res.redirect('/admin.html');
  }

  if (await bcrypt.compare(password, siteHash)) {
    req.session.role = 'viewer';
    return res.redirect('/dashboard.html');
  }

  res.redirect('/login.html?error=1');
});

// LOGOUT
app.get('/logout', (req, res) => {
  req.session = null;
  res.redirect('/login.html');
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

// STREAM
app.get('/stream/:name', requireLogin, (req, res) => {
  const filePath = path.join(uploadDir, path.basename(req.params.name));
  if (!fs.existsSync(filePath)) return res.sendStatus(404);

  res.setHeader('Content-Type', 'video/mp4');
  res.setHeader('Cache-Control', 'no-store');
  res.setHeader('Content-Disposition', 'inline');

  fs.createReadStream(filePath).pipe(res);
});

// DELETE
app.delete('/delete-video/:name', requireAdmin, (req, res) => {
  fs.unlinkSync(path.join(uploadDir, path.basename(req.params.name)));
  res.json({ success: true });
});

// ---------- Start ----------
app.listen(PORT, () => {
  console.log(`✅ YVideo running securely on port ${PORT}`);
});
