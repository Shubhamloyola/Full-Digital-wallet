# Full-Digital-wallet



const express = require('express');
const mongoose = require('mongoose');
const dotenv = require('dotenv');
const bodyParser = require('body-parser');
const cors = require('cors');

dotenv.config();
const app = express();
app.use(cors());
app.use(bodyParser.json());

// Connect to MongoDB
mongoose.connect(process.env.MONGO_URI, { useNewUrlParser: true, useUnifiedTopology: true })
    .then(() => console.log('MongoDB connected'))
    .catch(err => console.log(err));
    
// Import Routes
const userRoutes = require('./routes/user');
app.use('/api/user', userRoutes);

// Server Start
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(Server running on port ${PORT}));

models/User.js (User Model)

const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');

const userSchema = new mongoose.Schema({
    name: { type: String, required: true },
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    walletBalance: { type: Number, default: 0 },
});

// Password Hashing Middleware
userSchema.pre('save', async function(next) {
    if (!this.isModified('password')) return next();
    this.password = await bcrypt.hash(this.password, 10);
    next();
});

module.exports = mongoose.model('User', userSchema);

routes/user.js (User Routes)

const express = require('express');
const User = require('../models/User');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const router = express.Router();
const auth = require('../middleware/auth');

// Register Route
router.post('/register', async (req, res) => {
    const { name, email, password } = req.body;
    try {
        const user = new User({ name, email, password });
        await user.save();
        res.status(201).json({ message: 'User registered successfully!' });
    } catch (error) {
        res.status(400).json({ error: error.message });
    }
});

// Login Route
router.post('/login', async (req, res) => {
    const { email, password } = req.body;
    try {
        const user = await User.findOne({ email });
        if (!user || !(await bcrypt.compare(password, user.password))) {
            return res.status(400).json({ error: 'Invalid credentials' });
        }
        const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, { expiresIn: '1h' });
        res.json({ token, user: { id: user._id, name: user.name, walletBalance: user.walletBalance } });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Get Wallet Balance (Protected)
router.get('/wallet', auth, async (req, res) => {
    const user = await User.findById(req.user.id);
    res.json({ walletBalance: user.walletBalance });
});

// Add Money
router.post('/add-money', auth, async (req, res) => {
    const { amount } = req.body;
    const user = await User.findById(req.user.id);
    user.walletBalance += amount;
    await user.save();
    res.json({ message: 'Money added successfully!', walletBalance: user.walletBalance });
});

// Transfer Money
router.post('/transfer', auth, async (req, res) => {
    const { recipientEmail, amount } = req.body;
    const sender = await User.findById(req.user.id);
    const recipient = await User.findOne({ email: recipientEmail });

    if (!recipient || sender.walletBalance < amount) {
        return res.status(400).json({ error: 'Invalid transfer' });
    }

    sender.walletBalance -= amount;
    recipient.walletBalance += amount;

    await sender.save();
    await recipient.save();

    res.json({ message: 'Transfer successful!' });
});

module.exports = router;
const jwt = require('jsonwebtoken');

module.exports = (req, res, next) => {
    const token = req.header('Authorization');
    if (!token) return res.status(401).json({ error: 'Unauthorized' });

    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        req.user = decoded;
        next();
    } catch {
        res.status(401).json({ error: 'Invalid token' });
    }
};
import React from 'react';
import { BrowserRouter as Router, Routes, Route } from 'react-router-dom';
import Login from './components/Login';
import Dashboard from './components/Dashboard';

function App() {
    return (
        <Router>
            <Routes>
                <Route path="/" element={<Login />} />
                <Route path="/dashboard" element={<Dashboard />} />
            </Routes>
        </Router>
    );
}

export default App;
