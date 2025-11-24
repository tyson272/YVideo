// server.js

const express = require('express');
const path = require('path');
const fs = require('fs');
const session = require('express-session');
const multer = require('multer');

const app = express();
const PORT = process.env.PORT || 3000;

// ---------- Ensure uploads folder exists ----------
const uploadDir = path.join(__dirname, 'uploads');

if (!fs.existsSync(uploadDir)) {
  fs.mkdirSync(uploadDir, { recursive: true });
}

// ---------- Middleware ----------
app.use(express.static('public'));            // serve /public files
app.use('/uploads', express.static(uploadDir)); // serve uploaded videos
app.use(express.urlencoded({ extended: true })); // parse form data

app.use(
  session({
    secret: 'yvideo-secret',
    resave: false,
    saveUninitialized: true,
  })
);

// ---------- Demo users ----------
const users = {
  pavankumar: { password: 'Admin@', role: 'admin' },
  User: { password: 'user watch', role: 'member' },
};


// ---------- Multer (file upload) ----------
const storage = multer.diskStorage({
  destination(req, file, cb) {
    cb(null, uploadDir); // use the folder we created
  },
  filename(req, file, cb) {
    const uniqueName =
      Date.now() + '-' + Math.round(Math.random() * 1e9) + path.extname(file.originalname);
    cb(null, uniqueName);
  },
});

const upload = multer({ storage });

// ---------- Auth helpers ----------
function requireLogin(req, res, next) {
  if (!req.session.user) {
    return res.status(401).redirect('/login.html');
  }
  next();
}
function requireAdmin(req, res, next) {
  console.log('requireAdmin session user:', req.session.user);

  // Not logged in at all → go to login
  if (!req.session.user) {
    return res.redirect('/login.html');
  }

  // Logged in but not admin → show clear error instead of login
  if (req.session.user.role !== 'admin') {
    return res
      .status(403)
      .send(`Forbidden: you are logged in as "${req.session.user.username}", not an admin.`);
  }

  next();
}


// ---------- Routes ----------

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
app.post('/upload', requireAdmin, upload.single('video'), (req, res) => {
  if (!req.file) {
    return res.status(400).send('No file uploaded');
  }
  // Go back to admin page after successful upload
  res.redirect('/admin.html');
});

// LIST VIDEOS (members only)
app.get('/videos', requireLogin, (req, res) => {
  let files = [];
  try {
    files = fs.readdirSync(uploadDir);
  } catch (err) {
    console.error('Error reading uploads folder', err);
    files = [];
  }

  const videos = files.map((f) => ({ url: `/uploads/${f}` }));
  res.json(videos);
});
// DELETE video (admin only)
app.delete('/delete-video/:name', requireAdmin, (req, res) => {
  const fileName = req.params.name;
  const filePath = path.join(uploadDir, fileName);

  if (!fs.existsSync(filePath)) {
    return res.status(404).json({ error: 'File not found' });
  }

  fs.unlink(filePath, (err) => {
    if (err) {
      console.error('Delete error:', err);
      return res.status(500).json({ error: 'Failed to delete video' });
    }
    res.json({ success: true });
  });
});


// CHECK AUTH (for dashboard)
app.get('/check-auth', (req, res) => {
  if (!req.session.user) {
    return res.status(401).json({ error: 'Not authorized' });
  }
  res.json({ user: req.session.user });
});

// ---------- Start server ----------
app.listen(PORT, () => {
  console.log(`YVideo running at http://localhost:${PORT}`);
});
