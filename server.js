require('dotenv').config();

const express = require('express');
const path = require('path');
const fs = require('fs');
const multer = require('multer');
const bcrypt = require('bcrypt');
const rateLimit = require('express-rate-limit');
const crypto = require('crypto');

const app = express();
const PORT = process.env.PORT || 3000;

// ---------- Simple token ----------
const TOKEN_NAME = 'yvideo_token';
const VIEWER_TOKEN = crypto
  .createHash('sha256')
  .update(process.env.SITE_PASSWORD)
  .digest('hex');

const ADMIN_TOKEN = crypto
  .createHash('sha256')
  .update(process.env.ADMIN_PASSWORD)
  .digest('hex');

// ---------- Middleware ----------
app.use(express.urlencoded({ extended: true }));
app.use(express.static('public'));

// ---------- Cookie parser (manual) ----------
function getCookie(req, name) {
  const cookies = req.headers.cookie || '';
  const match = cookies.match(new RegExp('(^| )' + name + '=([^;]+)'));
  return match ? match[2] : null;
}

// ---------- Rate limit ----------
app.use(
  '/login',
  rateLimit({
    windowMs: 5 * 60 * 1000,
    max: 10,
  })
);

// ---------- Upload folder ----------
const uploadDir = path.join(__dirname, 'uploads');
if (!fs.existsSync(uploadDir)) fs.mkdirSync(uploadDir, { recursive: true });

// ---------- Multer ----------
const upload = multer({
  storage: multer.diskStorage({
    destination: uploadDir,
    filename(req, file, cb) {
      cb(null, Date.now() + '-' + file.originalname);
    },
  }),
  fileFilter(req, file, cb) {
    if (!file.mimetype.startsWith('video/')) return cb(new Error('Video only'));
    cb(null, true);
  },
});

// ---------- Auth helpers ----------
function requireLogin(req, res, next) {
  const token = getCookie(req, TOKEN_NAME);
  if (token !== VIEWER_TOKEN && token !== ADMIN_TOKEN) {
    return res.redirect('/login.html');
  }
  next();
}

function requireAdmin(req, res, next) {
  const token = getCookie(req, TOKEN_NAME);
  if (token !== ADMIN_TOKEN) {
    return res.status(403).send('Admins only');
  }
  next();
}

// ---------- Routes ----------

// LOGIN
app.post('/login', (req, res) => {
  const { password } = req.body;

  if (!password) return res.redirect('/login.html?error=1');

  if (bcrypt.compareSync(password, process.env.ADMIN_PASSWORD)) {
    res.setHeader(
      'Set-Cookie',
      `${TOKEN_NAME}=${ADMIN_TOKEN}; Path=/; HttpOnly; SameSite=Lax`
    );
    return res.redirect('/admin.html');
  }

  if (bcrypt.compareSync(password, process.env.SITE_PASSWORD)) {
    res.setHeader(
      'Set-Cookie',
      `${TOKEN_NAME}=${VIEWER_TOKEN}; Path=/; HttpOnly; SameSite=Lax`
    );
    return res.redirect('/dashboard.html');
  }

  res.redirect('/login.html?error=1');
});

// LOGOUT
app.get('/logout', (req, res) => {
  res.setHeader(
    'Set-Cookie',
    `${TOKEN_NAME}=; Path=/; Max-Age=0`
  );
  res.redirect('/login.html');
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
  fs.createReadStream(filePath).pipe(res);
});

// UPLOAD
app.post('/upload', requireAdmin, upload.single('video'), (req, res) => {
  res.redirect('/admin.html');
});

// DELETE
app.delete('/delete-video/:name', requireAdmin, (req, res) => {
  fs.unlinkSync(path.join(uploadDir, path.basename(req.params.name)));
  res.json({ success: true });
});

// ---------- Start ----------
app.listen(PORT, () => {
  console.log(`✅ YVideo running on port ${PORT}`);
});
