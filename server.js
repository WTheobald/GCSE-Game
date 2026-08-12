const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const app = express();
app.use(express.json());
app.use(cors());

// Serve static frontend files from the current folder[cite: 12]
app.use(express.static('.'));

// MongoDB Connection String[cite: 10, 12]
const MONGO_URI = 'mongodb+srv://will7996_db_user:lqrZ7nUiUBra9YF0@cluster0.rfqx8e3.mongodb.net/?appName=Cluster0';

mongoose.connect(MONGO_URI)
    .then(() => console.log('Connected to MongoDB database successfully!'))
    .catch(err => console.error('Database connection error:', err));

const JWT_SECRET = 'your_super_secret_key_here';

// User Database Schema[cite: 12]
const UserSchema = new mongoose.Schema({
    username: { type: String, unique: true, required: true },
    password: { type: String, required: true },
    xp: { type: Number, default: 0 },
    streak: { type: Number, default: 3 },
    completedTopics: { type: Array, default: [] },
    bestScores: { type: Object, default: {} }
});
const User = mongoose.model('User', UserSchema);

// Authentication Middleware[cite: 10, 12]
const verifyToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    if (!authHeader) {
        return res.status(401).json({ success: false, error: 'Access denied. No token provided.' });
    }

    const token = authHeader.split(' ')[1];
    if (!token) {
        return res.status(401).json({ success: false, error: 'Access denied. Malformed token.' });
    }

    try {
        const verified = jwt.verify(token, JWT_SECRET);
        req.user = verified;
        next();
    } catch (err) {
        res.status(403).json({ success: false, error: 'Invalid or expired token.' });
    }
};

// Test API endpoint[cite: 12]
app.get('/api/health', (req, res) => {
    res.json({ status: 'Server is running!' });
});

// Register Route[cite: 12]
app.post('/api/register', async (req, res) => {
    try {
        const { username, password } = req.body;
        if (!username || !password) return res.status(400).json({ error: 'Username and password required.' });
        
        const hashedPassword = await bcrypt.hash(password, 10);
        await User.create({ username, password: hashedPassword });
        res.json({ success: true, message: 'Account created successfully!' });
    } catch (err) {
        res.status(400).json({ success: false, error: 'Username already taken or invalid.' });
    }
});

// Login Route[cite: 10, 12]
app.post('/api/login', async (req, res) => {
    try {
        const { username, password } = req.body;
        const user = await User.findOne({ username });
        if (!user || !(await bcrypt.compare(password, user.password))) {
            return res.status(400).json({ success: false, error: 'Invalid username or password.' });
        }
        
        const token = jwt.sign({ id: user._id, username: user.username }, JWT_SECRET);
        res.json({ 
            success: true, 
            token, 
            user: { 
                xp: user.xp, 
                streak: user.streak, 
                completedTopics: user.completedTopics, 
                bestScores: user.bestScores 
            } 
        });
    } catch (err) {
        res.status(500).json({ success: false, error: 'Server error during login.' });
    }
});

// Logout Route[cite: 12]
app.post('/api/logout', verifyToken, (req, res) => {
    res.json({ success: true, message: 'Logged out successfully on server.' });
});

// Get User Profile Route[cite: 10, 12]
app.get('/api/user', verifyToken, async (req, res) => {
    try {
        const user = await User.findById(req.user.id).select('-password');
        if (!user) {
            return res.status(404).json({ success: false, error: 'User not found.' });
        }
        res.json({
            success: true,
            user: {
                xp: user.xp,
                streak: user.streak,
                completedTopics: user.completedTopics,
                bestScores: user.bestScores
            }
        });
    } catch (err) {
        res.status(500).json({ success: false, error: 'Server error fetching user profile.' });
    }
});

// Protected Progress Tracking Route[cite: 10, 12]
app.post('/api/update-progress', verifyToken, async (req, res) => {
    try {
        const { xp, streak, completedTopics, bestScores } = req.body;
        
        const updatedUser = await User.findByIdAndUpdate(
            req.user.id,
            { 
                ...(xp !== undefined && { xp }),
                ...(streak !== undefined && { streak }),
                ...(completedTopics !== undefined && { completedTopics }),
                ...(bestScores !== undefined && { bestScores })
            },
            { new: true }
        );

        if (!updatedUser) {
            return res.status(404).json({ success: false, error: 'User profile not found.' });
        }

        res.json({ success: true, user: { xp: updatedUser.xp, streak: updatedUser.streak, completedTopics: updatedUser.completedTopics, bestScores: updatedUser.bestScores } });
    } catch (err) {
        res.status(500).json({ success: false, error: 'Failed to update user progress.' });
    }
});

// Password Reset Route
app.post('/api/reset-password', verifyToken, async (req, res) => {
    try {
        const { newPassword } = req.body;
        if (!newPassword) return res.status(400).json({ success: false, error: 'New password required.' });
        
        const hashedPassword = await bcrypt.hash(newPassword, 10);
        await User.findByIdAndUpdate(req.user.id, { password: hashedPassword });
        res.json({ success: true, message: 'Password updated successfully.' });
    } catch (err) {
        res.status(500).json({ success: false, error: 'Server error updating password.' });
    }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, 'localhost', () => {
    console.log(`Server running at http://localhost:${PORT}`);
});