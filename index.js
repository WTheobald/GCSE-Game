const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const path = require('path');

const app = express();
app.use(express.json());
app.use(cors());

// Serve static frontend files
app.use(express.static(__dirname));

// MongoDB Connection Debug Check
console.log("DEBUG - MONGO_URI is:", process.env.MONGO_URI ? "Present and loaded" : "MISSING/UNDEFINED");

// MongoDB Connection
const MONGO_URI = process.env.MONGO_URI || 'mongodb://localhost:27017/gcse-chemistry';
const JWT_SECRET = process.env.JWT_SECRET || 'your_super_secret_key_change_me';

mongoose.connect(MONGO_URI)
    .then(() => console.log('Connected to MongoDB successfully'))
    .catch(err => console.error('MongoDB connection error:', err));

// User Schema Model
const userSchema = new mongoose.Schema({
    username: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    xp: { type: Number, default: 0 },
    streak: { type: Number, default: 3 },
    completedTopics: { type: Array, default: [] },
    bestScores: { type: Object, default: {} }
});

const User = mongoose.model('User', userSchema);

// API Routes
app.post('/api/register', async (req, res) => {
    try {
        const { username, password } = req.body;
        const hashedPassword = await bcrypt.hash(password, 10);
        const newUser = new User({ username, password: hashedPassword });
        await newUser.save();
        res.json({ success: true, message: 'User registered successfully' });
    } catch (err) {
        res.status(400).json({ success: false, error: 'Username already exists or invalid data.' });
    }
});

app.post('/api/login', async (req, res) => {
    try {
        const { username, password } = req.body;
        const user = await User.findOne({ username });
        if (!user || !(await bcrypt.compare(password, user.password))) {
            return res.status(401).json({ success: false, error: 'Invalid username or password.' });
        }
        const token = jwt.sign({ userId: user._id, username: user.username }, JWT_SECRET, { expiresIn: '7d' });
        res.json({ success: true, token, user: { xp: user.xp, streak: user.streak, completedTopics: user.completedTopics, bestScores: user.bestScores } });
    } catch (err) {
        res.status(500).json({ success: false, error: 'Server error during login.' });
    }
});

app.post('/api/reset-password', async (req, res) => {
    try {
        const authHeader = req.headers.authorization;
        if (!authHeader) return res.status(401).json({ success: false, error: 'No token provided.' });
        const token = authHeader.split(' ')[1];
        const decoded = jwt.verify(token, JWT_SECRET);
        
        const { newPassword } = req.body;
        const hashedPassword = await bcrypt.hash(newPassword, 10);
        await User.findByIdAndUpdate(decoded.userId, { password: hashedPassword });
        
        res.json({ success: true, message: 'Password updated successfully.' });
    } catch (err) {
        res.status(401).json({ success: false, error: 'Unauthorized or invalid token.' });
    }
});

// Get User Game Progress from MongoDB
app.get('/api/get-progress', async (req, res) => {
    try {
        const authHeader = req.headers.authorization;
        if (!authHeader) return res.status(401).json({ success: false, error: 'No token provided.' });
        
        const token = authHeader.split(' ')[1];
        const decoded = jwt.verify(token, JWT_SECRET);
        
        const user = await User.findById(decoded.userId);
        if (!user) return res.status(404).json({ success: false, error: 'User not found.' });
        
        res.json({ 
            success: true, 
            gameState: {
                xp: user.xp,
                streak: user.streak,
                completedTopics: user.completedTopics,
                bestScores: user.bestScores
            } 
        });
    } catch (err) {
        res.status(401).json({ success: false, error: 'Unauthorized or invalid token.' });
    }
});

// Save / Update User Game Progress in MongoDB
const handleProgressUpdate = async (req, res) => {
    try {
        const authHeader = req.headers.authorization;
        if (!authHeader) return res.status(401).json({ success: false, error: 'No token provided.' });
        
        const token = authHeader.split(' ')[1];
        const decoded = jwt.verify(token, JWT_SECRET);
        
        const { xp, streak, completedTopics, bestScores } = req.body;
        
        await User.findByIdAndUpdate(decoded.userId, {
            xp,
            streak,
            completedTopics,
            bestScores
        });
        
        res.json({ success: true, message: 'Progress synchronized with MongoDB successfully.' });
    } catch (err) {
        res.status(401).json({ success: false, error: 'Unauthorized or invalid token.' });
    }
};

app.post('/api/update-progress', handleProgressUpdate);
app.post('/api/save-progress', handleProgressUpdate);

// Fallback to index.html for SPA routing
app.get('*', (req, res) => {
    res.sendFile(path.join(__dirname, 'index.html'));
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));