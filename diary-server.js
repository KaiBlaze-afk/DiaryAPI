require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const cors = require('cors');

app.use(cors({
  origin: '*', // allow requests from any origin
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization'],
}));

const {
  MONGO_URI,
  JWT_SECRET,
  MASTER_KEY,
  PORT = 4000,
} = process.env;

if (!MONGO_URI || !JWT_SECRET || !MASTER_KEY) {
  console.error('Missing required env vars. See .env.example');
  process.exit(1);
}

let MASTER_KEY_BUF;
try {
  MASTER_KEY_BUF = Buffer.from(MASTER_KEY, 'base64');
  if (MASTER_KEY_BUF.length !== 32) throw new Error('MASTER_KEY must be 32 bytes after base64 decoding');
} catch (e) {
  console.error('Invalid MASTER_KEY:', e.message);
  process.exit(1);
}

mongoose.connect(MONGO_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
}).then(() => console.log('Connected to MongoDB'))
  .catch(err => { console.error('MongoDB connection error', err); process.exit(1); });

const { Schema } = mongoose;

const UserSchema = new Schema({
  email: { type: String, required: true, unique: true, lowercase: true, trim: true },
  passwordHash: { type: String, required: true },
  name: { type: String },
  createdAt: { type: Date, default: Date.now },
});

const EntrySchema = new Schema({
  user: { type: Schema.Types.ObjectId, ref: 'User', required: true, index: true },
  title: { type: String },
  ciphertext: { type: String, required: true },
  iv: { type: String, required: true },
  tag: { type: String, required: true },
  entryDate: { type: Date, default: Date.now }, // custom diary date
  tags: { type: [String], default: [] }, // free-form tags
  location: { type: String },
  weather: { type: String },
  mood: { type: Number, min: 1, max: 5 },
  createdAt: { type: Date, default: Date.now },
  updatedAt: { type: Date, default: Date.now },
});

EntrySchema.pre('save', function(next) {
  this.updatedAt = Date.now();
  next();
});

const User = mongoose.model('User', UserSchema);
const Entry = mongoose.model('Entry', EntrySchema);

function deriveKey(userId) {
  return crypto.createHmac('sha256', MASTER_KEY_BUF).update(String(userId)).digest();
}

function encryptForUser(userId, plaintext) {
  const key = deriveKey(userId);
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv, { authTagLength: 16 });
  const ciphertext = Buffer.concat([cipher.update(Buffer.from(String(plaintext), 'utf8')), cipher.final()]);
  const tag = cipher.getAuthTag();
  return {
    ciphertext: ciphertext.toString('base64'),
    iv: iv.toString('base64'),
    tag: tag.toString('base64'),
  };
}

function decryptForUser(userId, ciphertext_b64, iv_b64, tag_b64) {
  const key = deriveKey(userId);
  const iv = Buffer.from(iv_b64, 'base64');
  const tag = Buffer.from(tag_b64, 'base64');
  const ciphertext = Buffer.from(ciphertext_b64, 'base64');
  const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv, { authTagLength: 16 });
  decipher.setAuthTag(tag);
  const decrypted = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
  return decrypted.toString('utf8');
}

const app = express();

app.use(helmet());
app.use(express.json({ limit: '100kb' }));
app.use(cors({ origin: true }));

const limiter = rateLimit({
  windowMs: 1 * 60 * 1000,
  max: 60,
});
app.use(limiter);

function authMiddleware(req, res, next) {
  const auth = req.headers.authorization;
  if (!auth || !auth.startsWith('Bearer ')) return res.status(401).json({ error: 'Unauthorized' });
  const token = auth.slice(7);
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    req.user = payload;
    next();
  } catch (e) {
    return res.status(401).json({ error: 'Invalid token' });
  }
}

app.get('/', (req, res) => res.json({ ok: true, msg: 'Diary API running' }));

app.post('/auth/register', async (req, res) => {
  try {
    const { email, password, name } = req.body;
    if (!email || !password) return res.status(400).json({ error: 'email and password required' });
    const existing = await User.findOne({ email });
    if (existing) return res.status(409).json({ error: 'User already exists' });
    const passwordHash = await bcrypt.hash(password, 12);
    const user = await User.create({ email, passwordHash, name });
    const token = jwt.sign({ userId: user._id.toString() }, JWT_SECRET, { expiresIn: '7d' });
    return res.json({ token, user: { id: user._id, email: user.email, name: user.name } });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ error: 'email and password required' });
    const user = await User.findOne({ email });
    if (!user) return res.status(401).json({ error: 'Invalid credentials' });
    const ok = await bcrypt.compare(password, user.passwordHash);
    if (!ok) return res.status(401).json({ error: 'Invalid credentials' });
    const token = jwt.sign({ userId: user._id.toString() }, JWT_SECRET, { expiresIn: '7d' });
    return res.json({ token, user: { id: user._id, email: user.email, name: user.name } });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Server error' });
  }
});

// Create entry
app.post('/entries', authMiddleware, async (req, res) => {
  try {
    const { title = '', content = '', entryDate, tags = [], location = '', weather = '', mood } = req.body;
    if (typeof content !== 'string') return res.status(400).json({ error: 'content must be string' });
    if (mood && (mood < 1 || mood > 5)) return res.status(400).json({ error: 'mood must be between 1 and 5' });
    const enc = encryptForUser(req.user.userId, content);
    const entry = await Entry.create({
      user: req.user.userId,
      title,
      ciphertext: enc.ciphertext,
      iv: enc.iv,
      tag: enc.tag,
      entryDate: entryDate ? new Date(entryDate) : new Date(),
      tags,
      location,
      weather,
      mood,
    });
    res.json({ id: entry._id, createdAt: entry.createdAt });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Server error' });
  }
});

// List entries
app.get('/entries', authMiddleware, async (req, res) => {
  try {
    const docs = await Entry.find({ user: req.user.userId }).sort({ entryDate: -1 }).limit(200).lean();
    const items = docs.map(d => {
      let plain = '';
      try { plain = decryptForUser(req.user.userId, d.ciphertext, d.iv, d.tag); } catch (e) { plain = '[decryption_failed]'; }
      return {
        id: d._id,
        title: d.title,
        content: plain,
        entryDate: d.entryDate,
        tags: d.tags,
        location: d.location,
        weather: d.weather,
        mood: d.mood,
        createdAt: d.createdAt,
        updatedAt: d.updatedAt
      };
    });
    res.json({ items });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Server error' });
  }
});

// Get single entry
app.get('/entries/:id', authMiddleware, async (req, res) => {
  try {
    const doc = await Entry.findOne({ _id: req.params.id, user: req.user.userId }).lean();
    if (!doc) return res.status(404).json({ error: 'Not found' });
    let plain = '';
    try { plain = decryptForUser(req.user.userId, doc.ciphertext, doc.iv, doc.tag); } catch (e) { return res.status(500).json({ error: 'Decryption failed' }); }
    res.json({
      id: doc._id,
      title: doc.title,
      content: plain,
      entryDate: doc.entryDate,
      tags: doc.tags,
      location: doc.location,
      weather: doc.weather,
      mood: doc.mood,
      createdAt: doc.createdAt,
      updatedAt: doc.updatedAt
    });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Server error' });
  }
});

// Update entry
app.put('/entries/:id', authMiddleware, async (req, res) => {
  try {
    const { title, content, entryDate, tags, location, weather, mood } = req.body;
    const doc = await Entry.findOne({ _id: req.params.id, user: req.user.userId });
    if (!doc) return res.status(404).json({ error: 'Not found' });
    if (typeof content === 'string') {
      const enc = encryptForUser(req.user.userId, content);
      doc.ciphertext = enc.ciphertext;
      doc.iv = enc.iv;
      doc.tag = enc.tag;
    }
    if (typeof title === 'string') doc.title = title;
    if (entryDate) doc.entryDate = new Date(entryDate);
    if (Array.isArray(tags)) doc.tags = tags;
    if (typeof location === 'string') doc.location = location;
    if (typeof weather === 'string') doc.weather = weather;
    if (mood && (mood >= 1 && mood <= 5)) doc.mood = mood;
    await doc.save();
    res.json({ ok: true });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Server error' });
  }
});

app.delete('/entries/:id', authMiddleware, async (req, res) => {
  try {
    const r = await Entry.deleteOne({ _id: req.params.id, user: req.user.userId });
    if (r.deletedCount === 0) return res.status(404).json({ error: 'Not found' });
    res.json({ ok: true });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Server error' });
  }
});

app.listen(PORT, () => console.log(`Diary API listening on port ${PORT}`));
