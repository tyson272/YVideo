require('dotenv').config();

const express = require('express');
const session = require('express-session');
const multer = require('multer');
const bcrypt = require('bcrypt');
const fs = require('fs');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;

// ---------- Ensure uploads folder ----------
const uploadDir = path.join(__dirname, 'uploads');
if (!fs.existsSync(uploadDir)) fs.mkdirSync(uploadDir, { recursive: true });

// ---------- Middleware ----------
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(express.static('public'));
app.use('/uploads', express.static(uploadDir));

app.set('trust proxy', 1); // REQUIRED for Render sessions

app.use(
  session({
    name: 'yvideo.sid',
    secret: process.env.SESSION_SECRET || 'yvideo-secret',
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true,
      sameSite: 'lax',
      secure: false, // Render handles HTTPS
      maxAge: 1000 * 60 * 60, // 1 hour
    },
  })
);

// ---------- Password hashes (from ENV) ----------
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD;
const SITE_PASSWORD = process.env.SITE_PASSWORD;

if (!ADMIN_PASSWORD || !SITE_PASSWORD) {
  console.error('❌ Missing environment passwords');
  process.exit(1);
}

const adminHash = bcrypt.hashSync(ADMIN_PASSWORD, 10);
const siteHash = bcrypt.hashSync(SITE_PASSWORD, 10);

// ---------- Auth helpers ----------
function requireLogin(req, res, next) {
  if (!req.session.user) return res.redirect('/login.html');
  next();
}

function requireAdmin(req, res, next) {
  if (!req.session.user || req.session.user.role !== 'admin') {
    return res.redirect('/login.html');
  }
  next();
}

// ---------- Multer (photos + videos) ----------
const storage = multer.diskStorage({
  destination(req, file, cb) {
    const album = req.body.album || 'general';
    const dir = path.join(uploadDir, album);
    fs.mkdirSync(dir, { recursive: true });
    cb(null, dir);
  },
  filename(req, file, cb) {
    cb(null, Date.now() + '-' + file.originalname);
  },
});

const upload = multer({
  storage,
  fileFilter(req, file, cb) {
    if (
      file.mimetype.startsWith('image/') ||
      file.mimetype.startsWith('video/')
    ) {
      cb(null, true);
    } else {
      cb(new Error('Only images & videos allowed'));
    }
  },
});

// ---------- ROUTES ----------

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
  req.session.destroy(() => {
    res.redirect('/login.html');
  });
});

// UPLOAD (ADMIN)
app.post('/upload', requireAdmin, upload.single('media'), (req, res) => {
  res.redirect('/admin.html');
});

// LIST MEDIA
app.get('/media', requireLogin, (req, res) => {
  const albums = fs.readdirSync(uploadDir);

  const data = albums.map((album) => ({
    album,
    files: fs.readdirSync(path.join(uploadDir, album)),
  }));

  res.json(data);
});

// STREAM MEDIA
app.get('/media/:album/:file', requireLogin, (req, res) => {
  const filePath = path.join(
    uploadDir,
    req.params.album,
    req.params.file
  );

  if (!fs.existsSync(filePath)) return res.sendStatus(404);
  fs.createReadStream(filePath).pipe(res);
});

// DELETE MEDIA (ADMIN)
app.delete('/delete/:album/:file', requireAdmin, (req, res) => {
  const filePath = path.join(
    uploadDir,
    req.params.album,
    req.params.file
  );
  fs.unlinkSync(filePath);
  res.json({ success: true });
});

// ---------- START ----------
app.listen(PORT, () => {
  console.log(`🔒 YVideo running on port ${PORT}`);
});
