require('dotenv').config();

const express = require('express');
const session = require('express-session');
const multer = require('multer');
const bcrypt = require('bcrypt');
const path = require('path');
const cloudinary = require('cloudinary').v2;
const { CloudinaryStorage } = require('multer-storage-cloudinary');

const app = express();
const PORT = process.env.PORT || 3000;

/* =========================
   CLOUDINARY CONFIG
   ========================= */

cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key: process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET
});

/* =========================
   MIDDLEWARE
   ========================= */

app.use(express.urlencoded({ extended: true }));
app.use(express.static('public'));

/* =========================
   SESSION (STABLE CONFIG)
   ========================= */

app.use(
  session({
    name: 'yvideo.sid',
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true,
      sameSite: 'lax',
      secure: false,
      maxAge: 60 * 60 * 1000 // 1 hour
    }
  })
);

/* =========================
   ENV CHECK
   ========================= */

if (
  !process.env.ADMIN_PASSWORD ||
  !process.env.SITE_PASSWORD ||
  !process.env.SESSION_SECRET ||
  !process.env.CLOUDINARY_CLOUD_NAME ||
  !process.env.CLOUDINARY_API_KEY ||
  !process.env.CLOUDINARY_API_SECRET
) {
  console.error('❌ Missing environment variables');
  process.exit(1);
}

/* =========================
   PASSWORDS
   ========================= */

const adminHash = bcrypt.hashSync(process.env.ADMIN_PASSWORD, 10);
const siteHash = bcrypt.hashSync(process.env.SITE_PASSWORD, 10);

/* =========================
   AUTH HELPERS
   ========================= */

function requireLogin(req, res, next) {
  if (!req.session.user) return res.redirect('/login.html');
  next();
}

function requireAdmin(req, res, next) {
  if (!req.session.user || req.session.user.role !== 'admin') {
    return res.status(401).json({ error: 'Unauthorized' });
  }
  next();
}

/* =========================
   LOGIN / LOGOUT
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
   CLOUDINARY STORAGE
   ========================= */

const storage = new CloudinaryStorage({
  cloudinary,
  params: async (req, file) => {
    const rawTitle = req.body.title || path.parse(file.originalname).name;
    const safeTitle = rawTitle
      .trim()
      .replace(/[^a-zA-Z0-9-_ ]/g, '')
      .replace(/\s+/g, '-')
      .toLowerCase();

    return {
      folder: 'yvideo',
      resource_type: 'video',
      public_id: safeTitle,
      overwrite: false
    };
  }
});

const upload = multer({ storage });

/* =========================
   UPLOAD (ADMIN ONLY)
   ========================= */

app.post('/upload', requireAdmin, upload.single('video'), (req, res) => {
  res.redirect('/admin.html');
});

/* =========================
   LIST VIDEOS
   ========================= */

app.get('/videos', requireLogin, async (req, res) => {
  const result = await cloudinary.search
    .expression('folder:yvideo')
    .sort_by('created_at', 'desc')
    .max_results(100)
    .execute();

  res.json(
    result.resources.map(v => ({
      id: v.public_id,
      title: v.public_id
        .split('/')
        .pop()
        .replace(/-/g, ' ')
        .replace(/\b\w/g, c => c.toUpperCase()),
      thumbnail: cloudinary.url(v.public_id, {
        resource_type: 'video',
        format: 'jpg',
        transformation: [{ width: 320, height: 180, crop: 'fill' }]
      }),
      stream: cloudinary.url(v.public_id, {
        resource_type: 'video',
        secure: true,
        transformation: []
      })
    }))
  );
});

/* =========================
   DELETE (ADMIN ONLY)
   ========================= */

app.delete('/delete-video/:id', requireAdmin, async (req, res) => {
  await cloudinary.uploader.destroy(req.params.id, {
    resource_type: 'video'
  });
  res.json({ success: true });
});

/* =========================
   START SERVER
   ========================= */

app.listen(PORT, () => {
  console.log('🎬 YVideo running — upload loop FIXED');
});
