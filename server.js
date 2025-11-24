const express = require('express');
const multer = require('multer');
const path = require('path');
const session = require('express-session');
const fs = require('fs');

const app = express();
const PORT = 3000;

// Serve static files and parse forms
app.use(express.static('public'));
app.use('/uploads', express.static('uploads'));
app.use(express.urlencoded({ extended: true }));

// Sessions for login
app.use(session({
  secret: 'yvideo-secret',
  resave: false,
  saveUninitialized: true
}));

// Demo users
const users = {
  admin: { password: 'admin123', role: 'admin' },
  user: { password: 'user123', role: 'member' }
};

// Where uploaded files are saved
const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, 'uploads/'),
  filename: (req, file, cb) =>
    cb(null, Date.now() + path.extname(file.originalname))
});

const upload = multer({ storage });

// LOGIN
app.post('/login', (req, res) => {
  const { username, password } = req.body;
  const user = users[username];

  if (!user || user.password !== password) {
    return res.redirect('/login.html');
  }

  req.session.user = { username, role: user.role };
  res.redirect('/dashboard.html');
});

// LOGOUT
app.get('/logout', (req, res) => {
  req.session.destroy(() => {
    res.redirect('/');
  });
});

// UPLOAD (admin only)
app.post('/upload', upload.single('video'), (req, res) => {
  if (!req.session.user || req.session.user.role !== 'admin') {
    return res.status(403).send('Forbidden – admin only');
  }
  if (!req.file) {
    return res.status(400).send('No file uploaded');
  }
  res.redirect('/admin.html');
});

// LIST VIDEOS (members only)
app.get('/videos', (req, res) => {
  if (!req.session.user) {
    return res.status(401).json({ error: 'Not logged in' });
  }

  const files = fs.readdirSync('./uploads');
  const videos = files.map(f => ({ url: `/uploads/${f}` }));
  res.json(videos);
});

// CHECK AUTH (for dashboard)
app.get('/check-auth', (req, res) => {
  if (!req.session.user) {
    return res.status(401).json({ error: 'Not authorized' });
  }
  res.json({ user: req.session.user });
});

app.listen(PORT, () => {
  console.log(`YVideo running at http://localhost:${PORT}`);
});
