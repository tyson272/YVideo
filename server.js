require('dotenv').config();

const express = require('express');
const session = require('express-session');
const multer = require('multer');
const bcrypt = require('bcrypt');
const fs = require('fs');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;

// ===== Upload folder =====
const uploadDir = path.join(__dirname, 'uploads');
if (!fs.existsSync(uploadDir)) fs.mkdirSync(uploadDir);

// ===== Middleware =====
app.use(express.urlencoded({ extended: true }));
app.use(express.static('public'));

app.use(
  session({
    secret: process.env.SESSION_SECRET || 'private-secret',
    resave: false,
    saveUninitialized: false,
    cookie: { httpOnly: true }
  })
);

// ===== Password hashes =====
const adminHash = bcrypt.hashSync(process.env.ADMIN_PASSWORD, 10);
const siteHash = bcrypt.hashSync(process.env.SITE_PASSWORD, 10);

// ===== Auth helpers =====
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

// ===== Upload (admin only) =====
const upload = multer({ dest: uploadDir });

app.post('/upload', requireAdmin, upload.single('video'), (req, res) => {
  res.redirect('/admin.html');
});

// ===== List videos =====
app.get('/videos', requireLogin, (req, res) => {
  const files = fs.readdirSync(uploadDir);
  res.json(files.map(name => ({ name })));
});

// ===== Stream =====
app.get('/stream/:name', requireLogin, (req, res) => {
  const filePath = path.join(uploadDir, path.basename(req.params.name));
  if (!fs.existsSync(filePath)) return res.sendStatus(404);
  fs.createReadStream(filePath).pipe(res);
});

// ===== Delete =====
app.delete('/delete-video/:name', requireAdmin, (req, res) => {
  const filePath = path.join(uploadDir, path.basename(req.params.name));
  if (fs.existsSync(filePath)) fs.unlinkSync(filePath);
  res.json({ success: true });
});

// ===== Start =====
app.listen(PORT, () => {
  console.log('🔒 Private YVideo running');
});
