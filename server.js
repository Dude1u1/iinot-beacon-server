// Load environment variables from .env file (MUST BE FIRST)
require('dotenv').config();

const express = require('express');
const cors = require('cors');
const { Pool } = require('pg');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

const app = express();
const PORT = process.env.PORT || 8080;

// Debug: Check if env vars are loaded (remove in production)
console.log('📋 Environment Variables Check:');
console.log('================================');
console.log('DB_HOST:', process.env.DB_HOST ? '✅ ' + process.env.DB_HOST : '❌ Missing');
console.log('DB_PORT:', process.env.DB_PORT ? '✅ ' + process.env.DB_PORT : '❌ Missing');
console.log('DB_NAME:', process.env.DB_NAME ? '✅ ' + process.env.DB_NAME : '❌ Missing');
console.log('DB_USER:', process.env.DB_USER ? '✅ ' + process.env.DB_USER : '❌ Missing');
console.log('DB_PASSWORD:', process.env.DB_PASSWORD ? '✅ [HIDDEN]' : '❌ Missing');
console.log('JWT_SECRET:', process.env.JWT_SECRET ? '✅ [HIDDEN]' : '❌ Missing');
console.log('NODE_ENV:', process.env.NODE_ENV ? '✅ ' + process.env.NODE_ENV : '⚠️ Not set (defaults to development)');
console.log('================================');

// Database connection with environment awareness
let poolConfig;

if (process.env.NODE_ENV === 'production') {
    // Production: Use Cloud SQL socket - CORRECT FORMAT
    poolConfig = {
        host: process.env.DB_HOST,  // Should be /cloudsql/project:region:instance
        database: process.env.DB_NAME,
        user: process.env.DB_USER,
        password: process.env.DB_PASSWORD,
        connectionTimeoutMillis: 5000,
        idleTimeoutMillis: 30000,
        max: 20,
        // Important: Don't specify port for Unix socket
    };
    console.log('📡 Production mode: Using Cloud SQL socket at:', process.env.DB_HOST);
} else {
    // Development: Use localhost with port
    poolConfig = {
        host: process.env.DB_HOST || 'localhost',
        port: parseInt(process.env.DB_PORT) || 5432,
        database: process.env.DB_NAME,
        user: process.env.DB_USER,
        password: process.env.DB_PASSWORD,
        connectionTimeoutMillis: 5000,
        idleTimeoutMillis: 30000,
        max: 20,
    };
    console.log('💻 Development mode: Connecting to', process.env.DB_HOST + ':' + (process.env.DB_PORT || '5432'));
}

const pool = new Pool(poolConfig);

// Test database connection on startup
const testConnection = async () => {
    try {
        const client = await pool.connect();
        console.log('✅ Database connected successfully');
        
        // Test query to verify everything works
        const result = await client.query('SELECT NOW() as time');
        console.log('📅 Database time:', result.rows[0].time);
        
        client.release();
        return true;
    } catch (err) {
        console.error('❌ Database connection error:', err.message);
        console.error('🔧 Please check:');
        console.error('   1. Your .env file has correct values');
        console.error('   2. Database server is running');
        console.error('   3. IP address is correct');
        console.error('   4. Firewall allows connection');
        return false;
    }
};

// Test connection immediately
testConnection();

// Middleware
app.use(cors());
app.use(express.json());

// Health check endpoint
app.get('/api/health', async (req, res) => {
    try {
        const client = await pool.connect();
        const result = await client.query('SELECT NOW() as time');
        client.release();
        res.json({ 
            status: 'ok', 
            time: result.rows[0].time,
            database: 'connected',
            env: process.env.NODE_ENV || 'development'
        });
    } catch (err) {
        res.json({ 
            status: 'ok', 
            database: 'disconnected',
            error: err.message,
            env: process.env.NODE_ENV || 'development'
        });
    }
});

// Debug endpoint to check database connection (REMOVE IN PRODUCTION)
app.get('/api/debug/db', async (req, res) => {
    // Only allow in development
    if (process.env.NODE_ENV === 'production') {
        return res.status(403).json({ error: 'Not available in production' });
    }
    
    try {
        const result = await pool.query('SELECT NOW() as time, current_database() as db, current_user as user');
        res.json({
            connected: true,
            database: result.rows[0].db,
            user: result.rows[0].user,
            time: result.rows[0].time,
            config: {
                host: process.env.DB_HOST,
                port: process.env.DB_PORT,
                database: process.env.DB_NAME,
                user: process.env.DB_USER,
            }
        });
    } catch (error) {
        res.status(500).json({
            connected: false,
            error: error.message,
            config: {
                host: process.env.DB_HOST,
                port: process.env.DB_PORT,
                database: process.env.DB_NAME,
                user: process.env.DB_USER,
            }
        });
    }
});

// Signup endpoint
app.post('/api/auth/signup', async (req, res) => {
    try {
        const { username, password } = req.body;
        
        console.log('📝 Signup attempt for username:', username);
        
        if (!username || !password) {
            return res.status(400).json({ error: 'Username and password required' });
        }
        
        // Check database connection first
        try {
            await pool.query('SELECT 1');
        } catch (dbError) {
            console.error('❌ Database not available during signup:', dbError.message);
            return res.status(503).json({ 
                error: 'Database service unavailable',
                details: 'Please try again later'
            });
        }
        
        // Check if user exists
        const existingUser = await pool.query(
            'SELECT id FROM users WHERE username = $1',
            [username]
        );
        
        if (existingUser.rows.length > 0) {
            return res.status(409).json({ error: 'Username already exists' });
        }
        
        // Hash password
        const saltRounds = 10;
        const hashedPassword = await bcrypt.hash(password, saltRounds);
        
        // Create user
        const result = await pool.query(
            `INSERT INTO users (username, password_hash, created_at) 
             VALUES ($1, $2, CURRENT_TIMESTAMP) 
             RETURNING id, username, created_at`,
            [username, hashedPassword]
        );
        
        console.log('✅ User created successfully:', username);
        res.status(201).json({ 
            message: 'User created successfully',
            user: result.rows[0]
        });
        
    } catch (error) {
        console.error('❌ Signup error:', error);
        res.status(500).json({ 
            error: 'Signup failed', 
            details: error.message 
        });
    }
});

// Login endpoint
app.post('/api/auth/login', async (req, res) => {
    try {
        const { username, password } = req.body;
        
        console.log('🔐 Login attempt for username:', username);
        
        if (!username || !password) {
            return res.status(400).json({ error: 'Username and password required' });
        }
        
        // Check database connection
        try {
            await pool.query('SELECT 1');
        } catch (dbError) {
            return res.status(503).json({ error: 'Database unavailable' });
        }
        
        const result = await pool.query(
            'SELECT * FROM users WHERE username = $1',
            [username]
        );
        
        if (result.rows.length === 0) {
            console.log('❌ Login failed: User not found:', username);
            return res.status(401).json({ error: 'Invalid credentials' });
        }
        
        const user = result.rows[0];
        
        // Check password
        const isValidPassword = await bcrypt.compare(password, user.password_hash);
        
        if (!isValidPassword) {
            console.log('❌ Login failed: Invalid password for:', username);
            return res.status(401).json({ error: 'Invalid credentials' });
        }
        
        // Update last login
        await pool.query(
            'UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = $1',
            [user.id]
        );
        
        // Create JWT token
        const token = jwt.sign(
            { id: user.id, username: user.username },
            process.env.JWT_SECRET || 'your-secret-key-change-this',
            { expiresIn: '7d' }
        );
        
        console.log('✅ Login successful:', username);
        res.json({
            message: 'Login successful',
            user: {
                id: user.id,
                username: user.username
            },
            token
        });
        
    } catch (error) {
        console.error('❌ Login error:', error);
        res.status(500).json({ error: 'Login failed' });
    }
});

// Save beacon
app.post('/api/beacons', async (req, res) => {
    try {
        const { username, beacon_id, beacon_name } = req.body;
        
        // Get user id
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
            // Update existing
            await pool.query(
                'UPDATE beacons SET last_seen = CURRENT_TIMESTAMP WHERE user_id = $1 AND beacon_id = $2',
                [userId, beacon_id]
            );
            return res.json({ message: 'Beacon updated' });
        }
        
        // Insert new
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

// Get user's beacons
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

// Save alert
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

// Get alert history
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

// Start server
app.listen(PORT, '0.0.0.0', () => {
    console.log('================================');
    console.log(`🚀 Server running on port ${PORT}`);
    console.log(`✅ Health endpoint: http://localhost:${PORT}/api/health`);
    console.log(`🔍 Debug endpoint: http://localhost:${PORT}/api/debug/db`);
    console.log(`📝 Environment: ${process.env.NODE_ENV || 'development'}`);
    console.log('================================');
});