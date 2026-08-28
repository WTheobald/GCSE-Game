const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');

const app = express();
app.use(express.json());
app.use(cors());

const JWT_SECRET = 'your_jwt_secret_key_here';
const MONGO_URI = process.env.MONGO_URI || 'mongodb://localhost:27017/aqa_chemistry_quest';

mongoose.connect(MONGO_URI)
  .then(() => console.log('Connected to MongoDB'))
  .catch(err => console.error('MongoDB connection error:', err));

const UserSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  gameState: {
    xp: { type: Number, default: 0 },
    streak: { type: Number, default: 3 },
    completedTopics: { type: [Number], default: [] },
    activeTopicId: { type: mongoose.Schema.Types.Mixed, default: null },
    activeQuestionIdx: { type: Number, default: 0 },
    topicScores: { type: Object, default: {} },
    bestScores: { type: Object, default: {} },
    randomChallengeSource: { type: String, default: "all" },
    username: { type: String, default: "" }
  }
});

const User = mongoose.model('User', UserSchema);

// Middleware to authenticate JWT token
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) return res.status(401).json({ success: false, error: 'Unauthorized token' });

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ success: false, error: 'Invalid token' });
    req.user = user;
    next();
  });
};

// Authentication & Progress Endpoints
app.post('/api/register', async (req, res) => {
  try {
    const { username, password } = req.body;
    const existingUser = await User.findOne({ username });
    if (existingUser) return res.json({ success: false, error: 'Username already taken.' });

    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser = new User({
      username,
      password: hashedPassword,
      gameState: { xp: 0, streak: 3, completedTopics: [], bestScores: {}, username }
    });
    await newUser.save();
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

app.post('/api/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    const user = await User.findOne({ username });
    if (!user) return res.json({ success: false, error: 'User not found.' });

    const match = await bcrypt.compare(password, user.password);
    if (!match) return res.json({ success: false, error: 'Incorrect password.' });

    const token = jwt.sign({ id: user._id, username: user.username }, JWT_SECRET, { expiresIn: '7d' });
    res.json({ success: true, token });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

app.get('/api/get-progress', authenticateToken, async (req, res) => {
  try {
    const user = await User.findById(req.user.id);
    if (!user) return res.json({ success: false, error: 'User not found' });
    res.json({ success: true, gameState: user.gameState });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

app.post('/api/update-progress', authenticateToken, async (req, res) => {
  try {
    const { gameState } = req.body;
    await User.findByIdAndUpdate(req.user.id, { gameState });
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

app.post('/api/reset-password', authenticateToken, async (req, res) => {
  try {
    const { newPassword } = req.body;
    const hashedPassword = await bcrypt.hash(newPassword, 10);
    await User.findByIdAndUpdate(req.user.id, { password: hashedPassword });
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

app.listen(3000, () => console.log('Server running on port 3000'));