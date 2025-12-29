// ===== Upload (admin only, photos + videos) =====
const storage = multer.diskStorage({
  destination(req, file, cb) {
    const album = req.body.album || 'general';
    const dir = path.join(uploadDir, album);
    fs.mkdirSync(dir, { recursive: true });
    cb(null, dir);
  },
  filename(req, file, cb) {
    cb(null, Date.now() + '-' + file.originalname);
  }
});

const upload = multer({
  storage,
  fileFilter(req, file, cb) {
    if (
      file.mimetype.startsWith('video/') ||
      file.mimetype.startsWith('image/')
    ) {
      cb(null, true);
    } else {
      cb(new Error('Only images & videos allowed'));
    }
  }
});

// Upload route
app.post('/upload', requireAdmin, upload.single('media'), (req, res) => {
  res.redirect('/admin.html');
});

// ===== List albums & media =====
app.get('/media', requireLogin, (req, res) => {
  const albums = fs.readdirSync(uploadDir);

  const data = albums.map(album => {
    const files = fs.readdirSync(path.join(uploadDir, album));
    return {
      album,
      files
    };
  });

  res.json(data);
});

// ===== Stream media =====
app.get('/media/:album/:file', requireLogin, (req, res) => {
  const filePath = path.join(
    uploadDir,
    req.params.album,
    req.params.file
  );
  if (!fs.existsSync(filePath)) return res.sendStatus(404);
  fs.createReadStream(filePath).pipe(res);
});

// ===== Delete =====
app.delete('/delete/:album/:file', requireAdmin, (req, res) => {
  fs.unlinkSync(
    path.join(uploadDir, req.params.album, req.params.file)
  );
  res.json({ success: true });
});
