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
app.use(express.static('public'));               // serve /public
app.use('/uploads', express.static(uploadDir));  // serve uploaded videos
app.use(express.urlencoded({ extended: true })); // parse form posts

app.use(
  session({
    secret: 'yvideo-secret',
    resave: false,
    saveUninitialized: true,
  })
);

// ---------- Users in memory ----------
// NOTE: this is only in memory – if server restarts, users reset.
const users = {
  // admin account – change these to your own
  myAdmin01: { password: 'Admin@2025', role: 'admin' },
  // you can add more fixed users if you want, but signup will create members
};

// ---------- Multer upload config ----------
const storage = multer.diskStorage({
  destination(req, file, cb) {
    cb(null, uploadDir);
  },
  filename(req, file, cb) {
    const uniqueName =
      Date.now() +
      '-' +
      Math.round(Math.random() * 1e9) +
      path.extname(file.originalname);
    cb(null, uniqueName);
  },
});
const upload = multer({ storage });

// ---------- Auth helpers ----------
function requireLogin(req, res, next) {
  if (!req.session.user) {
    return res.redirect('/login.html');
  }
  next();
}

function requireAdmin(req, res, next) {
  console.log('requireAdmin session user:', req.session.user);
  if (!req.session.user) {
    return res.redirect('/login.html');
  }
  if (req.session.user.role !== 'admin') {
    return res
      .status(403)
      .send(`Forbidden: you are logged in as "${req.session.user.username}", not an admin.`);
  }
  next();
}

// ---------- Routes ----------

// LOGIN (with error message support)
app.post('/login', (req, res) => {
  const { username, password } = req.body;
  const user = users[username];

  if (!user || user.password !== password) {
    return res.redirect('/login.html?error=1');
  }

  req.session.user = { username, role: user.role };
  res.redirect('/dashboard.html');
});

// SIGNUP (create new member with validation)
app.post('/signup', (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.redirect('/signup.html?error=required');
  }

  if (username.length < 3) {
    return res.redirect('/signup.html?error=user_short');
  }

  if (password.length < 6) {
    return res.redirect('/signup.html?error=pwd_short');
  }

  if (users[username]) {
    return res.redirect('/signup.html?error=user_exists');
  }

  // create member user
  users[username] = { password, role: 'member' };
  console.log('New user created:', username, users[username]);

  // auto-login as member
  req.session.user = { username, role: 'member' };
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
  res.redirect('/admin.html');
});

// LIST VIDEOS (logged-in users)
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

// DELETE VIDEO (admin only)
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

// CHECK AUTH (for frontend JS)
app.get('/check-auth', (req, res) => {
  if (!req.session.user) {
    return res.status(401).json({ error: 'Not authorized' });
  }
  res.json({ user: req.session.user });
});

// CHANGE PASSWORD (profile page)
app.post('/change-password', requireLogin, (req, res) => {
  const { currentPassword, newPassword, confirmPassword } = req.body;
  const username = req.session.user.username;
  const user = users[username];

  if (!user) {
    return res.redirect('/profile.html?error=not_found');
  }

  if (!currentPassword || !newPassword || !confirmPassword) {
    return res.redirect('/profile.html?error=required');
  }

  if (user.password !== currentPassword) {
    return res.redirect('/profile.html?error=wrong_current');
  }

  if (newPassword.length < 6) {
    return res.redirect('/profile.html?error=pwd_short');
  }

  if (newPassword !== confirmPassword) {
    return res.redirect('/profile.html?error=mismatch');
  }

  users[username].password = newPassword;
  console.log('Password changed for', username);
  res.redirect('/profile.html?status=success');
});

// ---------- Start server ----------
app.listen(PORT, () => {
  console.log(`YVideo running at http://localhost:${PORT}`);
});
