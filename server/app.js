require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const multer = require('multer');
const fs = require('fs');
const path = require('path');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const crypto = require('crypto'); // Required for decryption constants
const { generateKeyPairSync } = require('crypto');
const axios = require('axios');

const app = express();
const PORT = 5000;

// --- CONFIGURATION ---
const JWT_SECRET = process.env.JWT_SECRET || "super_secret_key_123";
const VT_API_KEY = process.env.VT_API_KEY; // Must be in .env file

// --- MIDDLEWARE ---
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// --- FOLDER SETUP ---
const uploadDir = path.join(__dirname, 'uploads');
const tempDir = path.join(__dirname, 'uploads/temp');
if (!fs.existsSync(uploadDir)) fs.mkdirSync(uploadDir);
if (!fs.existsSync(tempDir)) fs.mkdirSync(tempDir);

// --- MONGODB CONNECTION ---
mongoose.connect(process.env.MONGO_URI )
    .then(() => console.log('✅ MongoDB Connected'))
    .catch(err => console.log('❌ DB Error:', err));



// --- SCHEMAS ---
const UserSchema = new mongoose.Schema({
    username: { type: String, required: true, unique: true },
    password: { type: String, required: true }
});
const UserModel = mongoose.model('User', UserSchema);

const FileSchema = new mongoose.Schema({
    originalName: String,
    storedFilename: String,
    filePath: String,
    totalChunks: Number,
    size: Number,
    owner: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    encryptedKey: String, // The AES Key (Encrypted with RSA)
    iv: String,           // The Initialization Vector
    uploadDate: { type: Date, default: Date.now }
});
const FileModel = mongoose.model('File', FileSchema);

// --- AUTH MIDDLEWARE ---
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    if (!authHeader) return res.status(401).json({ message: "Access Denied" });

    const token = authHeader.startsWith('Bearer ') ? authHeader.slice(7) : authHeader;

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) return res.status(403).json({ message: "Invalid Token" });
        req.user = user;
        next();
    });
};

const upload = multer({ dest: 'uploads/temp/' });

// ==========================================
// ROUTES
// ==========================================

// 1. VIRUS SCAN PROXY (Fixes CORS)
app.post('/scan-file', authenticateToken, async (req, res) => {
    const { fileHash } = req.body;

    try {
        // 1. Check if we already scanned this in our own MongoDB
        const existingScan = await FileModel.findOne({ fileHash: fileHash }); 
        // (Note: You may want a dedicated 'ScanResult' model for better organization)
        
        if (existingScan) {
            console.log("🎯 Backend Cache Hit: File is already known to be safe.");
            return res.json({ data: { attributes: { last_analysis_stats: { malicious: 0 } } } });
        }

        // 2. If unknown, call VirusTotal
        const response = await axios.get(`https://www.virustotal.com/api/v3/files/${fileHash}`, {
            headers: { 'x-apikey': process.env.VT_API_KEY }
        });

        res.json(response.data);
    } catch (error) {
        // If 404, the file is unknown to VT (usually safe)
        if (error.response && error.response.status === 404) {
            return res.json({ message: "File unknown to VirusTotal" });
        }
        res.status(500).json({ error: "Scan failed" });
    }
});

// 2. AUTHENTICATION
app.post('/register', async (req, res) => {
    try {
        const { username, password } = req.body;
        const hashedPassword = await bcrypt.hash(password, 10);
        const newUser = new UserModel({ username, password: hashedPassword });
        await newUser.save();
        res.json({ message: "User registered!" });
    } catch (err) {
        res.status(500).json({ error: "User already exists" });
    }
});

app.post('/login', async (req, res) => {
    const { username, password } = req.body;
    const user = await UserModel.findOne({ username });
    if (!user) return res.status(400).json({ error: "User not found" });

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) return res.status(400).json({ error: "Invalid credentials" });

    const token = jwt.sign({ id: user._id, username: user.username }, JWT_SECRET, { expiresIn: '2h' });
    res.json({ token, username });
});

// 3. UPLOAD (Chunked + Encrypted)
app.post('/upload', authenticateToken, upload.single('file'), async (req, res) => {
    try {
        if (!req.file) throw new Error("No file received");

        const { chunkIndex, totalChunks, originalName, passwordHash, salt } = req.body;
        
        const chunkPath = req.file.path;
        // Use UserID in filename to prevent collisions between users
        const targetPath = path.join(tempDir, `${originalName}-${chunkIndex}-${req.user.id}`);

        fs.renameSync(chunkPath, targetPath);

        if (Number(chunkIndex) === Number(totalChunks) - 1) {
            console.log(`✅ Last chunk for ${originalName}. Merging...`);
            
            await mergeChunks(
                originalName, 
                Number(totalChunks), 
                req.user.id, 
                passwordHash, // Encrypted AES Key
                salt          // IV
            );
            
            res.json({ message: "Upload complete!" });
        } else {
            res.json({ message: `Chunk ${chunkIndex} stored` });
        }
    } catch (error) {
        console.error("Upload Error:", error);
        res.status(500).send(error.message);
    }
});

// 4. MY FILES
app.get('/myfiles', authenticateToken, async (req, res) => {
    try {
        const files = await FileModel.find({ owner: req.user.id });
        res.json(files);
    } catch (err) {
        res.status(500).json({ error: "Error fetching files" });
    }
});

// 5. DOWNLOAD (Sends Encrypted File)
app.get('/download/:id', authenticateToken, async (req, res) => {
    try {
        const fileMeta = await FileModel.findById(req.params.id);
        if (!fileMeta) return res.status(404).send("File not found");

        if (fileMeta.owner.toString() !== req.user.id) {
            return res.status(403).send("Access Denied");
        }

        const absolutePath = path.resolve(__dirname, fileMeta.filePath);
        res.download(absolutePath, fileMeta.originalName);
    } catch (error) {
        res.status(500).send("Error downloading");
    }
});


// 6. GET FILE METADATA (Zero-Knowledge Version)
app.get('/request-file-metadata/:id', authenticateToken, async (req, res) => {
    try {
        const fileMeta = await FileModel.findById(req.params.id);
        if (!fileMeta) return res.status(404).json({ error: "File not found" });

        if (fileMeta.owner.toString() !== req.user.id) {
            return res.status(403).json({ error: "Access Denied" });
        }

        // Send the raw encrypted AES key back. The server cannot read it.
        res.json({
            encryptedKey: fileMeta.encryptedKey, 
            iv: fileMeta.iv,
            totalChunks: fileMeta.totalChunks
        });

    } catch (err) {
        console.error("Metadata Error:", err);
        res.status(500).json({ error: "Failed to retrieve file metadata" });
    }
});

// 6. DELETE FILE (Robust Version)
// --- ENSURE THIS IS IN app.js ---
app.delete('/delete/:id', authenticateToken, async (req, res) => {
    try {
        console.log(`🗑️ Delete request for file ID: ${req.params.id}`);
        
        const fileMeta = await FileModel.findById(req.params.id);
        
        // 1. Check if file exists in DB
        if (!fileMeta) {
            console.log("❌ File not found in DB");
            return res.status(404).json({ message: "File not found" });
        }

        // 2. Check Ownership
        if (fileMeta.owner.toString() !== req.user.id) {
            console.log("⛔ Access Denied: Not the owner");
            return res.status(403).json({ message: "Access Denied" });
        }

        // 3. Delete from Disk
        const absolutePath = path.resolve(__dirname, fileMeta.filePath);
        if (fs.existsSync(absolutePath)) {
            fs.unlinkSync(absolutePath);
            console.log("✅ File deleted from disk");
        } else {
            console.log("⚠️ File already missing from disk");
        }

        // 4. Delete from DB
        await FileModel.findByIdAndDelete(req.params.id);
        
        console.log("✅ Database record deleted");
        res.json({ message: "File deleted successfully" });

    } catch (err) {
        console.error("❌ Delete Error:", err);
        res.status(500).json({ message: "Server error during delete" });
    }
});

// --- HELPER: MERGE CHUNKS (FIXED: appendFileSync) ---
const mergeChunks = async (fileName, totalChunks, userId, encryptedKey, iv) => {
    const finalFilename = `${Date.now()}-${fileName}`;
    const finalFilePath = path.join(uploadDir, finalFilename);

    try {
        // Create empty file
        fs.writeFileSync(finalFilePath, ''); 

        for (let i = 0; i < totalChunks; i++) {
            const chunkPath = path.join(tempDir, `${fileName}-${i}-${userId}`);
            
            if (fs.existsSync(chunkPath)) {
                const data = fs.readFileSync(chunkPath);
                // Append synchronously to avoid "writev" race conditions
                fs.appendFileSync(finalFilePath, data);
                fs.unlinkSync(chunkPath);
            } else {
                throw new Error(`Chunk ${i} missing`);
            }
        }

        console.log(`🎉 File merged: ${finalFilePath}`);

        const newFile = new FileModel({
            originalName: fileName,
            storedFilename: finalFilename,
            filePath: `uploads/${finalFilename}`,
            totalChunks: totalChunks,
            size: fs.statSync(finalFilePath).size,
            owner: userId,
            encryptedKey: encryptedKey,
            iv: iv
        });

        await newFile.save();
        console.log(`📄 Metadata saved for User ${userId}`);

    } catch (err) {
        console.error("Merge failed:", err);
        if (fs.existsSync(finalFilePath)) fs.unlinkSync(finalFilePath);
        throw err;
    }
};

app.listen(PORT, () => console.log(`🚀 Server running on http://localhost:${PORT}`));