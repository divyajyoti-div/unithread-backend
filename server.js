const express = require('express');
const cors = require('cors');
const bodyParser = require('body-parser');
const { Pool } = require('pg'); 
require('dotenv').config();
const { createClient } = require('@supabase/supabase-js');

// --- 1. IMPORT JWT & SET SECRET KEY ---
const jwt = require('jsonwebtoken');
const JWT_SECRET = process.env.JWT_SECRET || 'my-super-secret-campus-key-2026';

const supabase = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_SERVICE_KEY);

const app = express();
app.use(cors());
app.use(bodyParser.json({ limit: '10mb' })); 

const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: { rejectUnauthorized: false },
    connectionTimeoutMillis: 10000, 
    idleTimeoutMillis: 30000,
    max: 10
});

pool.connect()
    .then(client => {
        console.log("✅ PostgreSQL Connected Successfully!");
        client.release();
    })
    .catch((err) => console.error("❌ Postgres Connection Error:", err.message));

const initDb = async () => {
    // 🚨 NEW: Create the Guest List (Users Table)
    const createUsersQuery = `
        CREATE TABLE IF NOT EXISTS users (
            email TEXT PRIMARY KEY,
            username TEXT UNIQUE NOT NULL,
            course TEXT,
            year TEXT,
            status TEXT DEFAULT 'pending',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
    `;

    const createPostsQuery = `
        CREATE TABLE IF NOT EXISTS posts (
            id SERIAL PRIMARY KEY,
            title TEXT NOT NULL,
            content TEXT,
            image_data TEXT, 
            author TEXT DEFAULT 'u/Anonymous',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
    `;
    
    const createCommentsQuery = `
        CREATE TABLE IF NOT EXISTS comments (
            id SERIAL PRIMARY KEY,
            post_id INTEGER REFERENCES posts(id) ON DELETE CASCADE,
            content TEXT NOT NULL,
            author TEXT DEFAULT 'u/Anonymous',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
    `;

    try {
        await pool.query(createUsersQuery); // Initialize users table
        await pool.query(createPostsQuery);
        await pool.query(`ALTER TABLE posts ADD COLUMN IF NOT EXISTS image_data TEXT;`).catch(()=>console.log("Image column exists"));
        await pool.query(`ALTER TABLE posts ADD COLUMN IF NOT EXISTS score INTEGER DEFAULT 1;`).catch(()=>console.log("Score column exists"));
        await pool.query(`ALTER TABLE posts ADD COLUMN IF NOT EXISTS author TEXT DEFAULT 'u/Anonymous';`).catch(()=>console.log("Author column exists"));
        await pool.query(createCommentsQuery);
        console.log("✅ Database tables verified.");
    } catch (err) {
        console.error("❌ Table creation error:", err.message);
    }
};
initDb();

let otpStore = {}; 

// --- BREVO API EMAIL ROUTE ---
app.post('/send-otp', async (req, res) => {
    const { email } = req.body;
    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    otpStore[email] = otp;

    try {
        const response = await fetch('https://api.brevo.com/v3/smtp/email', {
            method: 'POST',
            headers: {
                'accept': 'application/json',
                'api-key': process.env.BREVO_API_KEY,
                'content-type': 'application/json'
            },
            body: JSON.stringify({
                sender: { 
                    name: "UniThread Admin", 
                    email: "mishradivyajyoti178@gmail.com" 
                }, 
                to: [{ email: email }], 
                subject: "Your UniThread Verification Code",
                htmlContent: `<h1>Your OTP is: ${otp}</h1>`
            })
        });

        if (!response.ok) {
            const errorData = await response.json();
            console.error("❌ BREVO ERROR:", errorData);
            return res.status(500).send({ message: "Failed to send", success: false });
        }

        res.status(200).send({ message: "OTP Sent!", success: true });
    } catch (error) {
        console.error("❌ SERVER ERROR:", error); 
        res.status(500).send({ message: "Failed to send", success: false });
    }
});

// --- 2. UPGRADED: VERIFY OTP & CHECK GUEST LIST ---
app.post('/verify-otp', async (req, res) => {
    const { email, otp } = req.body;
    
    if (otpStore[email] && otpStore[email] === otp) {
        delete otpStore[email]; 
        
        try {
            // Check if they are on the Guest List
            const userResult = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
            const user = userResult.rows[0];

            if (!user) {
                // Not on the list! Tell the frontend to show the "Setup Profile" form
                return res.status(200).send({ success: true, isNewUser: true, email: email, message: "Please complete your profile setup." });
            } else if (user.status === 'pending') {
                // On the list, but not approved yet
                return res.status(403).send({ success: false, message: "Application submitted! Waiting for Admin approval." });
            } else if (user.status === 'approved') {
                // Fully approved! Give them the JWT Badge (now containing their official username)
                const token = jwt.sign({ email: email, username: user.username }, JWT_SECRET, { expiresIn: '24h' });
                return res.status(200).send({ success: true, isNewUser: false, token: token, message: "Verified!" });
            }
        } catch (dbError) {
            console.error("Database error during login:", dbError);
            return res.status(500).send({ success: false, message: "Server error checking user status." });
        }
    } else {
        res.status(400).send({ success: false, message: "Invalid OTP" });
    }
});

// --- 3. NEW: SAVE PROFILE & SET TO PENDING ---
app.post('/api/setup-profile', async (req, res) => {
    const { email, username, course, year } = req.body;
    try {
        // Automatically add u/ to the start if they forgot
        const formattedUsername = username.startsWith('u/') ? username : 'u/' + username;

        const query = 'INSERT INTO users (email, username, course, year, status) VALUES ($1, $2, $3, $4, $5) RETURNING *';
        await pool.query(query, [email, formattedUsername, course, year, 'pending']);

        res.status(200).send({ success: true, message: "Profile submitted! Waiting for admin approval." });
    } catch (error) {
        console.error("Error setting up profile:", error);
        // Postgres error code 23505 means "Unique Violation" (Username already taken)
        if (error.code === '23505') {
            return res.status(400).send({ success: false, message: "Username is already taken! Please choose another." });
        }
        res.status(500).send({ success: false, message: "Server Error" });
    }
});

// --- 4. THE SECURITY GUARD MIDDLEWARE ---
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1]; 
    
    if (!token) return res.status(401).json({ success: false, message: "Access Denied: No Token Provided!" });

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) return res.status(403).json({ success: false, message: "Access Denied: Invalid or Expired Token!" });
        req.user = user; 
        next();
    });
};

// ==========================================
// --- SECURE ROUTES (Requires Token) ---
// ==========================================

// SECURE: Create Post
app.post('/api/posts', authenticateToken, async (req, res) => {
    try {
        const { title, content, image_data } = req.body;
        let finalImageUrl = null;
        
        // 🚨 NEW: Pull their official username securely from the JWT badge!
        const finalAuthor = req.user.username;

        if (image_data) {
            try {
                const matches = image_data.match(/^data:([A-Za-z-+\/]+);base64,(.+)$/);
                if (matches && matches.length === 3) {
                    const mimeType = matches[1]; 
                    const imageBuffer = Buffer.from(matches[2], 'base64');
                    const fileExt = mimeType.split('/')[1];
                    const fileName = `${Date.now()}-${Math.random().toString(36).substring(7)}.${fileExt}`;

                    const { data: uploadData, error: uploadError } = await supabase.storage
                        .from('post-images')
                        .upload(fileName, imageBuffer, { contentType: mimeType, upsert: false });

                    if (uploadError) throw uploadError;

                    const { data: publicUrlData } = supabase.storage.from('post-images').getPublicUrl(fileName);
                    finalImageUrl = publicUrlData.publicUrl;
                }
            } catch (supaError) {
                console.log("⚠️ Supabase skipped: Image upload failed, but saving text post anyway!");
            }
        }

        const query = 'INSERT INTO posts (title, content, image_data, author) VALUES ($1, $2, $3, $4) RETURNING *';
        const result = await pool.query(query, [title, content, finalImageUrl, finalAuthor]);
        res.status(201).json({ success: true, post: result.rows[0] });
    } catch (error) {
        console.error("Error saving post:", error);
        res.status(500).json({ success: false, message: "Server Error" });
    }
});

// SECURE: Delete Post
app.delete('/api/posts/:id', authenticateToken, async (req, res) => {
    try {
        const { id } = req.params;
        await pool.query('DELETE FROM posts WHERE id = $1', [id]);
        res.status(200).json({ success: true, message: "Post deleted!" });
    } catch (error) {
        res.status(500).json({ success: false, message: "Server Error" });
    }
});

// SECURE: Add Comment
app.post('/api/posts/:id/comments', authenticateToken, async (req, res) => {
    try {
        const postId = req.params.id;
        const { content } = req.body; 
        
        // 🚨 NEW: Pull their official username securely from the JWT badge!
        const finalAuthor = req.user.username; 

        const query = 'INSERT INTO comments (post_id, content, author) VALUES ($1, $2, $3) RETURNING *';
        const result = await pool.query(query, [postId, content, finalAuthor]);
        res.status(201).json({ success: true, comment: result.rows[0] });
    } catch (error) {
        console.error("Error saving comment:", error);
        res.status(500).json({ success: false, message: "Server Error" });
    }
});

// SECURE: Vote
app.post('/api/posts/:id/vote', authenticateToken, async (req, res) => {
    try {
        const { id } = req.params;
        const { action } = req.body; 
        const change = action === 'up' ? 1 : -1;
        const query = 'UPDATE posts SET score = score + $1 WHERE id = $2 RETURNING score';
        const result = await pool.query(query, [change, id]);
        res.status(200).json({ success: true, newScore: result.rows[0].score });
    } catch (error) {
        console.error("Error updating vote:", error);
        res.status(500).json({ success: false, message: "Server Error" });
    }
});

// ==========================================
// --- PUBLIC ROUTES (No Token Needed) ---
// ==========================================

// Anyone can view the feed
app.get('/api/posts', async (req, res) => {
    try {
        const result = await pool.query('SELECT * FROM posts ORDER BY created_at DESC');
        res.status(200).json({ success: true, posts: result.rows });
    } catch (error) {
        res.status(500).json({ success: false, message: "Server Error" });
    }
});

// Anyone can view comments
app.get('/api/posts/:id/comments', async (req, res) => {
    try {
        const postId = req.params.id;
        const query = 'SELECT * FROM comments WHERE post_id = $1 ORDER BY created_at ASC';
        const result = await pool.query(query, [postId]);
        res.status(200).json({ success: true, comments: result.rows });
    } catch (error) {
        console.error("Error fetching comments:", error);
        res.status(500).json({ success: false, message: "Server Error" });
    }
});

app.listen(5000, () => console.log("🚀 Server running on port 5000"));