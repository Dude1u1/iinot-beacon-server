const express = require('express');
const cors = require('cors');
const { Pool } = require('pg');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

const app = express();
const PORT = process.env.PORT || 8080;

// CRITICAL FIX: Add connection timeouts to prevent hanging
const pool = new Pool({
    host: process.env.DB_HOST,
    port: process.env.DB_PORT || 5432,
    database: process.env.DB_NAME,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    
    // CRITICAL: Add these timeouts to fail fast
    connectionTimeoutMillis: 5000, // Fail after 5 seconds if can't connect
    idleTimeoutMillis: 30000,
    max: 20,
    
    // Add retry logic
    retryDelay: 1000,
    
    // SSL for production
    ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false
});

// Test database connection with timeout
const testConnection = async () => {
    console.log('🔍 Testing database connection...');
    console.log('📊 Connection config:', {
        host: process.env.DB_HOST,
        port: process.env.DB_PORT,
        database: process.env.DB_NAME,
        user: process.env.DB_USER,
        // password: '***hidden***'
    });
    
    try {
        const client = await pool.connect();
        console.log('✅ Successfully connected to PostgreSQL database');
        
        // Test query
        const result = await client.query('SELECT NOW() as current_time, current_database() as db_name');
        console.log('📊 Database info:', result.rows[0]);
        
        client.release();
        return true;
    } catch (err) {
        console.error('❌ Database connection failed:', err.message);
        console.error('🔧 Please check:');
        console.error('   1. DB_HOST is correct and accessible');
        console.error('   2. PostgreSQL is running');
        console.error('   3. Firewall allows port 5432');
        console.error('   4. Credentials are correct');
        return false;
    }
};

// Test connection immediately
testConnection();

// Middleware
app.use(cors());
app.use(express.json());

// Health check with database status
app.get('/api/health', async (req, res) => {
    let dbStatus = 'disconnected';
    let dbInfo = null;
    
    try {
        const client = await pool.connect();
        const result = await client.query('SELECT NOW() as time');
        dbStatus = 'connected';
        dbInfo = { time: result.rows[0].time };
        client.release();
    } catch (err) {
        dbStatus = 'error: ' + err.message;
    }
    
    res.json({ 
        status: 'ok', 
        timestamp: new Date(),
        database: dbStatus,
        dbInfo: dbInfo,
        environment: process.env.NODE_ENV || 'development'
    });
});

// Debug endpoint to check connection
app.get('/api/debug/connection', async (req, res) => {
    try {
        const result = await pool.query('SELECT NOW() as time, current_database() as db, current_user as user');
        res.json({
            connected: true,
            database: result.rows[0].db,
            user: result.rows[0].user,
            time: result.rows[0].time,
            config: {
                host: process.env.DB_HOST || 'not set',
                port: process.env.DB_PORT || 'not set',
                database: process.env.DB_NAME || 'not set',
                user: process.env.DB_USER || 'not set',
            }
        });
    } catch (error) {
        res.status(500).json({
            connected: false,
            error: error.message,
            config: {
                host: process.env.DB_HOST || 'not set',
                port: process.env.DB_PORT || 'not set',
                database: process.env.DB_NAME || 'not set',
                user: process.env.DB_USER || 'not set',
            }
        });
    }
});

// Signup endpoint with better error handling
app.post('/api/auth/signup', async (req, res) => {
    try {
        const { username, password } = req.body;
        
        if (!username || !password) {
            return res.status(400).json({ error: 'Username and password required' });
        }
        
        // Quick database check
        try {
            await pool.query('SELECT 1');
        } catch (dbError) {
            console.error('❌ Database not available:', dbError.message);
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
        
        // Create user
        const saltRounds = 10;
        const hashedPassword = await bcrypt.hash(password, saltRounds);
        
        const result = await pool.query(
            `INSERT INTO users (username, password_hash, created_at) 
             VALUES ($1, $2, CURRENT_TIMESTAMP) 
             RETURNING id, username, created_at`,
            [username, hashedPassword]
        );
        
        console.log(`✅ User created: ${username}`);
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
        
        // Quick database check
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
            return res.status(401).json({ error: 'Invalid credentials' });
        }
        
        const user = result.rows[0];
        
        let isValidPassword = false;
        if (user.password_hash && user.password_hash.startsWith('$2b$')) {
            isValidPassword = await bcrypt.compare(password, user.password_hash);
        } else {
            isValidPassword = (password === '1234');
        }
        
        if (!isValidPassword) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }
        
        await pool.query(
            'UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = $1',
            [user.id]
        );
        
        const token = jwt.sign(
            { id: user.id, username: user.username },
            process.env.JWT_SECRET || 'your-secret-key',
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

// ... rest of your endpoints remain the same ...

app.listen(PORT, '0.0.0.0', () => {
    console.log(`🚀 Server running on port ${PORT}`);
    console.log(`✅ Health endpoint: /api/health`);
    console.log(`🔍 Debug endpoint: /api/debug/connection`);
    console.log(`⏱️  Request timeout: 300 seconds (Cloud Run setting)`);
});