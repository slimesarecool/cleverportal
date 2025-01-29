const express = require('express');
const cors = require('cors');
const crypto = require('crypto');
const fs = require('fs').promises;
const path = require('path');

const app = express();
const port = 8000;

// Middleware
app.use(express.json());
app.use(cors({
    origin: '*',
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Authorization', 'Content-Type']
}));

// Constants
const DATA_FILE = 'data.json';

// Global state (will be loaded from file)
let USER_CREDENTIALS = {
    "admin": { "pin": "7197", "created": 420, "urls": {}, "is_admin": true }
};
let ACTIVE_TOKENS = {};

// Helper functions
async function loadData() {
    try {
        const data = await fs.readFile(DATA_FILE, 'utf8');
        const parsed = JSON.parse(data);
        USER_CREDENTIALS = parsed.users || USER_CREDENTIALS;
        ACTIVE_TOKENS = parsed.tokens || {};
    } catch (error) {
        if (error.code !== 'ENOENT') {
            console.error('Error loading data:', error);
        }
        // If file doesn't exist, we'll use the defaults
    }
}

async function saveData() {
    try {
        await fs.writeFile(DATA_FILE, JSON.stringify({
            users: USER_CREDENTIALS,
            tokens: ACTIVE_TOKENS
        }, null, 4));
    } catch (error) {
        console.error('Error saving data:', error);
    }
}

// Load data on startup
loadData();

// Serve static files
app.use(express.static('.'));

// Routes
app.get('/status', (req, res) => {
    res.json({ status: 'online' });
});

app.post('/check-username', (req, res) => {
    const { username } = req.body;
    
    if (!username) {
        return res.status(400).json({ success: false, message: 'Username is required' });
    }
    
    if (!(username in USER_CREDENTIALS)) {
        return res.json({ exists: false, message: 'Invalid username' });
    }
    
    const needsPin = USER_CREDENTIALS[username].pin === null;
    res.json({ exists: true, needs_pin: needsPin });
});

app.post('/auth', (req, res) => {
    const { username, pin, is_setting_pin } = req.body;
    
    if (!username) {
        return res.status(400).json({ success: false, message: 'Username is required' });
    }
    
    if (!(username in USER_CREDENTIALS)) {
        return res.status(401).json({ success: false, message: 'Invalid username' });
    }

    if (USER_CREDENTIALS[username].pin === null) {
        if (!is_setting_pin) {
            return res.status(401).json({ success: false, message: 'PIN needs to be set', needs_pin: true });
        }
        if (!pin || pin.length !== 4 || !/^\d{4}$/.test(pin)) {
            return res.status(400).json({ success: false, message: 'PIN must be 4 digits' });
        }
        
        USER_CREDENTIALS[username].pin = pin;
        USER_CREDENTIALS[username].created = Date.now() / 1000;
        const token = crypto.randomBytes(32).toString('base64url');
        ACTIVE_TOKENS[token] = { expires: (Date.now() / 1000) + (24 * 3600), username };
        saveData();
        
        return res.json({
            success: true,
            token,
            message: 'PIN set successfully',
            is_admin: USER_CREDENTIALS[username].is_admin
        });
    } else {
        if (pin !== USER_CREDENTIALS[username].pin) {
            return res.status(401).json({ success: false, message: 'Incorrect PIN' });
        }
        
        const token = crypto.randomBytes(32).toString('base64url');
        ACTIVE_TOKENS[token] = { expires: (Date.now() / 1000) + (24 * 3600), username };
        saveData();
        
        return res.json({
            success: true,
            token,
            is_admin: USER_CREDENTIALS[username].is_admin
        });
    }
});

app.post('/verify', (req, res) => {
    const { token } = req.body;
    
    if (!token) {
        return res.status(401).json({ valid: false, message: 'No token provided' });
    }
    
    if (token in ACTIVE_TOKENS) {
        if (Date.now() / 1000 < ACTIVE_TOKENS[token].expires) {
            return res.json({ valid: true });
        } else {
            delete ACTIVE_TOKENS[token];
            saveData();
        }
    }
    
    return res.status(401).json({ valid: false });
});

// Middleware to check authentication
function checkAuth(req, res, next) {
    const token = req.headers.authorization;
    
    if (!token || !(token in ACTIVE_TOKENS) || (Date.now() / 1000) >= ACTIVE_TOKENS[token].expires) {
        return res.status(401).json({ success: false, message: 'Invalid or expired token' });
    }
    
    req.username = ACTIVE_TOKENS[token].username;
    next();
}

// URL Management Routes
app.get('/urls', checkAuth, (req, res) => {
    res.json({ urls: USER_CREDENTIALS[req.username].urls });
});

app.post('/urls', checkAuth, (req, res) => {
    const { url, nickname } = req.body;
    
    if (!url || !nickname) {
        return res.status(400).json({ success: false, message: 'URL and nickname are required' });
    }
    
    const urlId = crypto.randomBytes(6).toString('base64url');
    USER_CREDENTIALS[req.username].urls[urlId] = { url, nickname };
    saveData();
    
    res.json({ success: true, url_id: urlId });
});

app.put('/urls', checkAuth, (req, res) => {
    const { url_id, nickname } = req.body;
    
    if (!url_id || !nickname || !(url_id in USER_CREDENTIALS[req.username].urls)) {
        return res.status(400).json({ success: false, message: 'Invalid URL ID or nickname' });
    }
    
    USER_CREDENTIALS[req.username].urls[url_id].nickname = nickname;
    saveData();
    
    res.json({ success: true });
});

app.delete('/urls/:url_id', checkAuth, (req, res) => {
    const { url_id } = req.params;
    
    if (!url_id || !(url_id in USER_CREDENTIALS[req.username].urls)) {
        return res.status(400).json({ success: false, message: 'Invalid URL ID' });
    }
    
    delete USER_CREDENTIALS[req.username].urls[url_id];
    saveData();
    
    res.json({ success: true });
});

// Admin Routes
function checkAdmin(req, res, next) {
    if (!USER_CREDENTIALS[req.username].is_admin) {
        return res.status(403).json({ success: false, message: 'Unauthorized' });
    }
    next();
}

app.get('/admin/users', checkAuth, checkAdmin, (req, res) => {
    const users = {};
    for (const [name, data] of Object.entries(USER_CREDENTIALS)) {
        users[name] = {
            created: data.created,
            is_admin: data.is_admin,
            has_pin: data.pin !== null,
            pin: data.pin || 'Not Set'
        };
    }
    res.json({ users });
});

app.post('/admin/users', checkAuth, checkAdmin, (req, res) => {
    const { username, is_admin = false } = req.body;
    
    if (!username || username in USER_CREDENTIALS) {
        return res.status(400).json({ success: false, message: 'Invalid or existing username' });
    }
    
    USER_CREDENTIALS[username] = {
        pin: null,
        created: null,
        urls: {},
        is_admin
    };
    saveData();
    
    res.json({ success: true });
});

app.put('/admin/users', checkAuth, checkAdmin, (req, res) => {
    const { username, pin, is_admin } = req.body;
    
    if (!(username in USER_CREDENTIALS)) {
        return res.status(404).json({ success: false, message: 'User not found' });
    }
    
    if (pin !== undefined) {
        if (!pin || pin.length !== 4 || !/^\d{4}$/.test(pin)) {
            return res.status(400).json({ success: false, message: 'PIN must be 4 digits' });
        }
        USER_CREDENTIALS[username].pin = pin;
    }
    
    if (is_admin !== undefined) {
        USER_CREDENTIALS[username].is_admin = is_admin;
    }
    
    saveData();
    res.json({ success: true });
});

app.delete('/admin/users', checkAuth, checkAdmin, (req, res) => {
    const { username } = req.body;
    
    if (!username || !(username in USER_CREDENTIALS)) {
        return res.status(400).json({ success: false, message: 'Invalid username' });
    }
    
    if (username === req.username) {
        return res.status(400).json({ success: false, message: 'Cannot delete yourself' });
    }
    
    delete USER_CREDENTIALS[username];
    
    // Remove any active tokens for this user
    for (const [token, data] of Object.entries(ACTIVE_TOKENS)) {
        if (data.username === username) {
            delete ACTIVE_TOKENS[token];
        }
    }
    
    saveData();
    res.json({ success: true });
});

// Start server
app.listen(port, () => {
    console.log(`Server running at http://localhost:${port}`);
}); 