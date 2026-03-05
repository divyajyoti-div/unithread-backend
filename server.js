const express = require('express');
const nodemailer = require('nodemailer');
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
    const createPostsQuery = `
        CREATE TABLE IF NOT EXISTS posts (
            id SERIAL PRIMARY KEY,
            title TEXT NOT NULL,
            content TEXT,
            image_data TEXT, 
            author TEXT DEFAULT 'u/Divyajyoti_mishra',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
    `;
    
    const createCommentsQuery = `
        CREATE TABLE IF NOT EXISTS comments (
            id SERIAL PRIMARY KEY,
            post_id INTEGER REFERENCES posts(id) ON DELETE CASCADE,
            content TEXT NOT NULL,
            author TEXT DEFAULT 'u/Student',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
    `;

    try {
        await pool.query(createPostsQuery);
        await pool.query(`ALTER TABLE posts ADD COLUMN IF NOT EXISTS image_data TEXT;`).catch(()=>console.log("Image column exists"));
        await pool.query(`ALTER TABLE posts ADD COLUMN IF NOT EXISTS score INTEGER DEFAULT 1;`).catch(()=>console.log("Score column exists"));
        await pool.query(`ALTER TABLE posts ADD COLUMN IF NOT EXISTS author TEXT DEFAULT 'u/Divyajyoti_mishra';`).catch(()=>console.log("Author column exists"));
        await pool.query(createCommentsQuery);
        console.log("✅ Database tables verified.");
    } catch (err) {
        console.error("❌ Table creation error:", err.message);
    }
};
initDb();

let otpStore = {}; 

app.post('/send-otp', async (req, res) => {
    const { email } = req.body;
    const otp = Math.floor(100000 + Math.random() * 900000);
    otpStore[email] = otp.toString();

    let transporter = nodemailer.createTransport({
        service: 'gmail',
        auth: { user: process.env.EMAIL_USER, pass: process.env.EMAIL_PASS }
    });

    try {
        await transporter.sendMail({
            from: `"UniThread Admin" <${process.env.EMAIL_USER}>`,
            to: email,
            subject: "Verification Code",
            html: `<h1>Your OTP is: ${otp}</h1>`
        });
        res.status(200).send({ message: "OTP Sent!", success: true });
    } catch (error) {
        res.status(500).send({ message: "Failed to send", success: false });
    }
});

// --- 2. GENERATE THE JWT BADGE ON LOGIN ---
app.post('/verify-otp', (req, res) => {
    const { email, otp } = req.body;
    if (otpStore[email] && otpStore[email] === otp) {
        delete otpStore[email]; 
        
        // Create the JWT Badge valid for 24 hours
        const token = jwt.sign({ email: email }, JWT_SECRET, { expiresIn: '24h' });
        
        // Send the token back to the frontend
        res.status(200).send({ success: true, message: "Verified!", token: token });
    } else {
        res.status(400).send({ success: false, message: "Invalid OTP" });
    }
});

// --- 3. THE SECURITY GUARD MIDDLEWARE ---
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1]; // Extract token from "Bearer <token>"
    
    if (!token) return res.status(401).json({ success: false, message: "Access Denied: No Token Provided!" });

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) return res.status(403).json({ success: false, message: "Access Denied: Invalid or Expired Token!" });
        req.user = user; // Badge is valid! Let them through.
        next();
    });
};

// ==========================================
// --- SECURE ROUTES (Requires Token) ---
// ==========================================

// SECURE: Create Post
app.post('/api/posts', authenticateToken, async (req, res) => {
    try {
        const { title, content, image_data, author } = req.body;
        let finalImageUrl = null;
        const finalAuthor = author || 'u/Divyajyoti_mishra';

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
        const { content, author } = req.body; 
        const finalAuthor = author || 'u/Divyajyoti_mishra'; 
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