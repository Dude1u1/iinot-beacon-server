const express = require('express');
const cors = require('cors');
const { Pool } = require('pg');
const dotenv = require('dotenv');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

dotenv.config();

const app = express();
const PORT = process.env.PORT || 3000;

// Database connection
const pool = new Pool({
    host: process.env.DB_HOST,
    port: process.env.DB_PORT,
    database: process.env.DB_NAME,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
});

// Test database connection
pool.connect((err) => {
    if (err) {
        console.error('❌ Database connection error:', err.message);
    } else {
        console.log('✅ Connected to PostgreSQL database');
    }
});

// Middleware
app.use(cors());
app.use(express.json());

// ==================== API ROUTES ====================

// Health check
app.get('/api/health', (req, res) => {
    res.json({ 
        status: 'ok', 
        timestamp: new Date(),
        database: pool ? 'connected' : 'disconnected'
    });
});

// ==================== SIGNUP ENDPOINT ====================
app.post('/api/auth/signup', async (req, res) => {
    try {
        const { username, password } = req.body;
        
        // Validate input
        if (!username || !password) {
            return res.status(400).json({ error: 'Username and password required' });
        }
        
        if (username.length < 3) {
            return res.status(400).json({ error: 'Username must be at least 3 characters' });
        }
        
        if (password.length < 3) {
            return res.status(400).json({ error: 'Password must be at least 3 characters' });
        }
        
        // Check if user already exists
        const existingUser = await pool.query(
            'SELECT id FROM users WHERE username = $1',
            [username]
        );
        
        if (existingUser.rows.length > 0) {
            return res.status(400).json({ error: 'Username already exists' });
        }
        
        // Hash the password
        const saltRounds = 10;
        const hashedPassword = await bcrypt.hash(password, saltRounds);
        
        // Insert new user
        const result = await pool.query(
            `INSERT INTO users (username, password_hash, created_at) 
             VALUES ($1, $2, CURRENT_TIMESTAMP) 
             RETURNING id, username, created_at`,
            [username, hashedPassword]
        );
        
        console.log(`✅ New user created: ${username}`);
        
        res.status(201).json({ 
            message: 'User created successfully',
            user: result.rows[0]
        });
        
    } catch (error) {
        console.error('❌ Signup error:', error);
        res.status(500).json({ error: 'Signup failed' });
    }
});

// ==================== LOGIN ENDPOINT ====================
app.post('/api/auth/login', async (req, res) => {
    try {
        const { username, password } = req.body;
        
        // Find user
        const result = await pool.query(
            'SELECT * FROM users WHERE username = $1',
            [username]
        );
        
        if (result.rows.length === 0) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }
        
        const user = result.rows[0];
        
        // Check password
        let isValidPassword = false;
        
        if (user.password_hash && user.password_hash.startsWith('$2b$')) {
            isValidPassword = await bcrypt.compare(password, user.password_hash);
        } else {
            // For demo user with plain text '1234'
            isValidPassword = (password === '1234');
        }
        
        if (!isValidPassword) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }
        
        // Update last login
        await pool.query(
            'UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = $1',
            [user.id]
        );
        
        // Generate token
        const token = jwt.sign(
            { id: user.id, username: user.username },
            process.env.JWT_SECRET,
            { expiresIn: '7d' }
        );
        
        res.json({
            message: 'Login successful',
            user: {
                id: user.id,
                username: user.username,
                email: user.email,
                full_name: user.full_name
            },
            token
        });
        
    } catch (error) {
        console.error('❌ Login error:', error);
        res.status(500).json({ error: 'Login failed' });
    }
});

// ==================== BEACON ENDPOINTS ====================

// Get all beacons for a user
app.get('/api/beacons/:username', async (req, res) => {
    try {
        const { username } = req.params;
        
        const userResult = await pool.query(
            'SELECT id FROM users WHERE username = $1',
            [username]
        );
        
        if (userResult.rows.length === 0) {
            return res.json([]);
        }
        
        const userId = userResult.rows[0].id;
        
        const result = await pool.query(
            'SELECT * FROM beacons WHERE user_id = $1 ORDER BY last_seen DESC',
            [userId]
        );
        
        res.json(result.rows);
    } catch (error) {
        console.error('❌ Error fetching beacons:', error);
        res.status(500).json({ error: 'Server error' });
    }
});

// Save a beacon
app.post('/api/beacons', async (req, res) => {
    try {
        const { username, beacon_id, beacon_name } = req.body;
        
        const userResult = await pool.query(
            'SELECT id FROM users WHERE username = $1',
            [username]
        );
        
        if (userResult.rows.length === 0) {
            return res.status(404).json({ error: 'User not found' });
        }
        
        const userId = userResult.rows[0].id;
        
        // Check if beacon exists
        const existing = await pool.query(
            'SELECT id FROM beacons WHERE user_id = $1 AND beacon_id = $2',
            [userId, beacon_id]
        );
        
        if (existing.rows.length > 0) {
            // Update last seen
            await pool.query(
                'UPDATE beacons SET last_seen = CURRENT_TIMESTAMP WHERE user_id = $1 AND beacon_id = $2',
                [userId, beacon_id]
            );
            return res.json({ message: 'Beacon updated' });
        }
        
        // Insert new beacon
        await pool.query(
            `INSERT INTO beacons (user_id, beacon_id, beacon_name, first_seen, last_seen)
             VALUES ($1, $2, $3, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)`,
            [userId, beacon_id, beacon_name]
        );
        
        res.status(201).json({ message: 'Beacon saved' });
    } catch (error) {
        console.error('❌ Error saving beacon:', error);
        res.status(500).json({ error: 'Server error' });
    }
});

// ==================== ALERT ENDPOINTS ====================

// Save an alert
app.post('/api/alerts', async (req, res) => {
    try {
        const { username, beacon_id, alert_type, alert_description, rssi } = req.body;
        
        const userResult = await pool.query(
            'SELECT id FROM users WHERE username = $1',
            [username]
        );
        
        if (userResult.rows.length === 0) {
            return res.status(404).json({ error: 'User not found' });
        }
        
        const userId = userResult.rows[0].id;
        
        await pool.query(
            `INSERT INTO beacon_alerts 
             (user_id, beacon_id, alert_type, alert_description, rssi, timestamp)
             VALUES ($1, $2, $3, $4, $5, CURRENT_TIMESTAMP)`,
            [userId, beacon_id, alert_type, alert_description, rssi]
        );
        
        res.status(201).json({ message: 'Alert saved' });
    } catch (error) {
        console.error('❌ Error saving alert:', error);
        res.status(500).json({ error: 'Server error' });
    }
});

// Get alert history for a user
app.get('/api/alerts/:username', async (req, res) => {
    try {
        const { username } = req.params;
        const { limit = 50 } = req.query;
        
        const userResult = await pool.query(
            'SELECT id FROM users WHERE username = $1',
            [username]
        );
        
        if (userResult.rows.length === 0) {
            return res.json([]);
        }
        
        const userId = userResult.rows[0].id;
        
        const result = await pool.query(
            `SELECT ba.*, b.beacon_name 
             FROM beacon_alerts ba
             LEFT JOIN beacons b ON ba.user_id = b.user_id AND ba.beacon_id = b.beacon_id
             WHERE ba.user_id = $1
             ORDER BY ba.timestamp DESC
             LIMIT $2`,
            [userId, limit]
        );
        
        res.json(result.rows);
    } catch (error) {
        console.error('❌ Error fetching alerts:', error);
        res.status(500).json({ error: 'Server error' });
    }
});

// ==================== DELETE ENDPOINT ====================

// Delete a beacon
app.delete('/api/beacons/:username/:beacon_id', async (req, res) => {
    try {
        const { username, beacon_id } = req.params;
        
        const userResult = await pool.query(
            'SELECT id FROM users WHERE username = $1',
            [username]
        );
        
        if (userResult.rows.length === 0) {
            return res.status(404).json({ error: 'User not found' });
        }
        
        const userId = userResult.rows[0].id;
        
        await pool.query(
            'DELETE FROM beacons WHERE user_id = $1 AND beacon_id = $2',
            [userId, beacon_id]
        );
        
        res.json({ message: 'Beacon deleted' });
    } catch (error) {
        console.error('❌ Error deleting beacon:', error);
        res.status(500).json({ error: 'Server error' });
    }
});

// Start server
app.listen(PORT, '0.0.0.0', () => {
    console.log(`🚀 Server running on port ${PORT}`);
    console.log(`📱 Server is ready for connections`);
    console.log(`✅ Signup endpoint available at: /api/auth/signup`);
});