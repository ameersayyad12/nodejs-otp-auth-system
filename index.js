const express = require('express');
const cookieParser = require('cookie-parser');
const jwt = require('jsonwebtoken');
const { v4: uuidv4 } = require('uuid');
const app = express();
const bcrypt = require('bcrypt'); // For password hashing

require('dotenv').config();



app.use(express.json());
app.use(cookieParser());

// In-memory storage
const users = {};
const otpStore = {};
const refreshTokens = {};

const JWT_SECRET = process.env.JWT_SECRET;
const REFRESH_SECRET = process.env.REFRESH_SECRET;


// Middleware
const authMiddleware = require('./authMiddleware');

// Utils
const { generateOtp, sendOtp } = require('./utils');

// --- Signup ---
app.post('/signup', async (req, res) => {
    const { name, email, mobile, password } = req.body;
    if (!name || !email || !mobile || !password) {
        return res.status(400).json({ message: 'All fields are required' });
    }
    if (users[email]) {
        return res.status(409).json({ message: 'User already exists' });
    }
    if (Object.values(users).find(u => u.mobile === mobile)) {
        return res.status(409).json({ message: 'Mobile number already registered' });
    }
    const hashedPassword = await bcrypt.hash(password, 10); // Hash password
    users[email] = { name, email, mobile, password: hashedPassword };
    res.status(201).json({ message: 'User created successfully' });
});

// --- Login ---
app.post('/login', async (req, res) => {
    const { email, mobile, password } = req.body;
    let user;

    if (email) {
        user = users[email];
    } else if (mobile) {
        user = Object.values(users).find(u => u.mobile === mobile);
    }

    if (!user || !(await bcrypt.compare(password, user.password))) {
        return res.status(401).json({ message: 'Invalid credentials' });
    }

    // Generate OTP
    const otp = generateOtp();
    const otpId = uuidv4();
    otpStore[otpId] = {
        email: user.email,
        mobile: user.mobile,
        otp,
        expiresAt: Date.now() + 5 * 60 * 1000 // 5 minutes
    };

    // Simulate sending OTP
    sendOtp(user.email || user.mobile, otp);

    res.json({
        message: 'OTP sent',
        otpId
    });
});


// --- Verify OTP ---
app.post('/verify-otp', (req, res) => {
    const { otpId, otp } = req.body;
    const storedOtp = otpStore[otpId];

    if (!storedOtp || storedOtp.expiresAt < Date.now() || storedOtp.otp !== otp) {
        return res.status(400).json({ message: 'Invalid or expired OTP' });
    }

    const accessToken = jwt.sign({ email: storedOtp.email }, JWT_SECRET, { expiresIn: '10m' });
    const refreshToken = jwt.sign({ email: storedOtp.email }, REFRESH_SECRET, { expiresIn: '7d' });

    refreshTokens[refreshToken] = storedOtp.email;

    // Set HTTP-only cookie
    res.cookie('refreshToken', refreshToken, {
        httpOnly: true,
        secure: false,
        maxAge: 7 * 24 * 60 * 60 * 1000
    });

    delete otpStore[otpId];

    res.json({ accessToken });
});

// --- Refresh Token ---
app.post('/refresh-token', (req, res) => {
    const refreshToken = req.cookies.refreshToken;

    if (!refreshToken || !refreshTokens[refreshToken]) {
        return res.status(401).json({ message: 'Unauthorized' });
    }

    try {
        const payload = jwt.verify(refreshToken, REFRESH_SECRET);
        const accessToken = jwt.sign({ email: payload.email }, JWT_SECRET, { expiresIn: '10m' });

        res.json({ accessToken });
    } catch (err) {
        return res.status(401).json({ message: 'Invalid refresh token' });
    }
});

// --- Protected Route Example ---
app.get('/protected', authMiddleware, (req, res) => {
    res.json({ message: 'You are authorized!', user: req.user });
});

const PORT = 3000;
if (require.main === module) {
  app.listen(PORT, () => console.log(`Server running on http://localhost:${PORT}`));
}
module.exports = { app, otpStore };