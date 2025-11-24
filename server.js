const express = require('express');
const multer = require('multer');
const path = require('path');
const session = require('express-session');
const fs = require('fs');

const app = express();
const PORT = process.env.PORT || 3000;

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

const multer = require("multer");

const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    cb(null, "uploads/");
  },
  filename: function (req, file, cb) {
    cb(null, Date.now() + "-" + file.originalname);
  }
});

const upload = multer({ storage: storage });


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

app.post("/upload", upload.single("video"), (req, res) => {
  if (!req.file) {
    return res.status(400).send("No file uploaded");
  }
  res.send("Video uploaded successfully!");
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
const fs = require("fs");
const path = require("path");

const uploadDir = path.join(__dirname, "uploads");

// Create uploads folder if it doesn't exist
if (!fs.existsSync(uploadDir)) {
  fs.mkdirSync(uploadDir);
}
