require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const multer = require('multer');
const fs = require('fs');
const path = require('path');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { generateKeyPairSync } = require('crypto');
const axios = require('axios'); // Required for VirusTotal Proxy

const app = express();
const PORT = 5000;
const JWT_SECRET = process.env.JWT_SECRET || "super_secret_key_123";
const VT_API_KEY = process.env.VT_API_KEY; // Loaded from .env

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
mongoose.connect(process.env.MONGO_URI || 'mongodb://localhost:27017/secure_cloud_db')
    .then(() => console.log('✅ MongoDB Connected'))
    .catch(err => console.log('❌ DB Error:', err));

// --- RSA KEY GENERATION (ON STARTUP) ---
// Generates a fresh Key Pair every time the server starts.
let privateKey, publicKey;
try {
    const keys = generateKeyPairSync('rsa', {
        modulusLength: 2048,
        publicKeyEncoding: { type: 'spki', format: 'pem' },
        privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
    });
    privateKey = keys.privateKey;
    publicKey = keys.publicKey;
    console.log("🔐 RSA Keys Generated Successfully");
} catch (error) {
    console.error("Key Gen Error:", error);
}

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

// 1. PUBLIC KEY (For Frontend Encryption)
app.get('/public-key', (req, res) => {
    res.json({ publicKey });
});

// 2. VIRUS SCAN PROXY (Fixes CORS Error)
app.post('/scan-file', async (req, res) => {
    try {
        const { fileHash } = req.body;
        if (!VT_API_KEY) {
            return res.status(500).json({ error: "Server missing VirusTotal API Key" });
        }
        
        // Call VirusTotal from the Server
        const response = await axios.get(
            `https://www.virustotal.com/api/v3/files/${fileHash}`,
            { headers: { 'x-apikey': VT_API_KEY } }
        );

        res.json(response.data);

    } catch (error) {
        // 404 means the file is new/unknown (safe)
        if (error.response && error.response.status === 404) {
            return res.json({ data: { attributes: { last_analysis_stats: { malicious: 0 } } } });
        }
        console.error("VirusTotal Error:", error.message);
        res.status(500).json({ error: "Scan failed" });
    }
});

// 3. AUTHENTICATION
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

// 4. UPLOAD (Chunked + Encrypted)
app.post('/upload', authenticateToken, upload.single('file'), async (req, res) => {
    try {
        if (!req.file) throw new Error("No file received");

        const { chunkIndex, totalChunks, originalName, passwordHash, salt } = req.body;
        
        const chunkPath = req.file.path;
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

// 5. MY FILES
app.get('/myfiles', authenticateToken, async (req, res) => {
    try {
        const files = await FileModel.find({ owner: req.user.id });
        res.json(files);
    } catch (err) {
        res.status(500).json({ error: "Error fetching files" });
    }
});

// 6. DOWNLOAD (Sends Encrypted File)
app.get('/download/:id', authenticateToken, async (req, res) => {
    try {
        const fileMeta = await FileModel.findById(req.params.id);
        if (!fileMeta) return res.status(404).send("File not found");

        if (fileMeta.owner.toString() !== req.user.id) {
            return res.status(403).send("Access Denied");
        }

        const absolutePath = path.resolve(fileMeta.filePath);
        res.download(absolutePath, fileMeta.originalName);
    } catch (error) {
        res.status(500).send("Error downloading");
    }
});

// 7. DELETE FILE
app.delete('/delete/:id', authenticateToken, async (req, res) => {
    try {
        const fileMeta = await FileModel.findById(req.params.id);
        if (!fileMeta) return res.status(404).json({ message: "File not found" });

        if (fileMeta.owner.toString() !== req.user.id) {
            return res.status(403).json({ message: "Access Denied" });
        }

        const absolutePath = path.resolve(fileMeta.filePath);
        if (fs.existsSync(absolutePath)) {
            fs.unlinkSync(absolutePath);
        }

        await FileModel.findByIdAndDelete(req.params.id);
        res.json({ message: "File deleted successfully" });
    } catch (err) {
        res.status(500).json({ message: "Error deleting file" });
    }
});

// --- HELPER: MERGE CHUNKS ---
// --- HELPER: MERGE CHUNKS (ROBUST VERSION) ---
const mergeChunks = async (fileName, totalChunks, userId, encryptedKey, iv) => {
    const finalFilename = `${Date.now()}-${fileName}`;
    const finalFilePath = path.join(uploadDir, finalFilename);

    try {
        // Ensure the final file exists (create empty file)
        fs.writeFileSync(finalFilePath, ''); 

        for (let i = 0; i < totalChunks; i++) {
            const chunkPath = path.join(tempDir, `${fileName}-${i}-${userId}`);
            
            if (fs.existsSync(chunkPath)) {
                // Read the chunk
                const data = fs.readFileSync(chunkPath);
                
                // Append strictly synchronously to avoid stream errors
                fs.appendFileSync(finalFilePath, data);
                
                // Delete the chunk immediately
                fs.unlinkSync(chunkPath);
            } else {
                console.error(`Missing chunk: ${chunkPath}`);
                throw new Error(`Chunk ${i} is missing! Upload failed.`);
            }
        }

        console.log(`🎉 File merged successfully: ${finalFilePath}`);

        // SAVE METADATA TO DB
        const newFile = new FileModel({
            originalName: fileName,
            storedFilename: finalFilename,
            filePath: `uploads/${finalFilename}`,
            totalChunks: totalChunks,
            size: fs.statSync(finalFilePath).size,
            owner: userId,
            encryptedKey: encryptedKey, // Save the keys needed for decryption
            iv: iv
        });

        await newFile.save();
        console.log("📄 Metadata saved to MongoDB");

    } catch (err) {
        console.error("Merge Error:", err);
        // Cleanup: If merge fails, try to delete the partial file
        if (fs.existsSync(finalFilePath)) fs.unlinkSync(finalFilePath);
        throw err; // Propagate error so the route knows it failed
    }
};
// --- NEW ROUTE: REQUEST DECRYPTION KEY ---
// The user needs the raw AES key to decrypt the file in their browser.
// Only the Server (holding the RSA Private Key) can unlock it.
app.get('/request-decryption-key/:id', authenticateToken, async (req, res) => {
    try {
        const fileMeta = await FileModel.findById(req.params.id);
        if (!fileMeta) return res.status(404).json({ error: "File not found" });

        if (fileMeta.owner.toString() !== req.user.id) {
            return res.status(403).json({ error: "Access Denied" });
        }

        // 1. Get the Encrypted AES Key from DB
        const encryptedKeyBuffer = Buffer.from(fileMeta.encryptedKey, 'base64');

        // 2. Decrypt it using the Server's Private RSA Key
        const decryptedAesKey = crypto.privateDecrypt(
            {
                key: privateKey,
                padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
                oaepHash: "sha256",
            },
            encryptedKeyBuffer
        );

        // 3. Send the Raw AES Key (Base64) + IV back to the client
        res.json({
            aesKey: decryptedAesKey.toString('base64'),
            iv: fileMeta.iv // This was stored as a JSON string or Base64
        });

    } catch (err) {
        console.error("Decryption Key Error:", err);
        res.status(500).json({ error: "Failed to retrieve decryption key" });
    }
});

app.listen(PORT, () => console.log(`🚀 Server running on http://localhost:${PORT}`));