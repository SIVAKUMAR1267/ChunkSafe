import CryptoJS from 'crypto-js';

// Helper: Convert string to ArrayBuffer
function str2ab(str) {
  const buf = new ArrayBuffer(str.length);
  const bufView = new Uint8Array(buf);
  for (let i = 0, strLen = str.length; i < strLen; i++) {
    bufView[i] = str.charCodeAt(i);
  }
  return buf;
}

// Helper: Convert ArrayBuffer to Base64
function arrayBufferToBase64(buffer) {
  let binary = '';
  const bytes = new Uint8Array(buffer);
  const len = bytes.byteLength;
  for (let i = 0; i < len; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return window.btoa(binary);
}

// Import RSA Public Key
async function importPublicKey(pem) {
  const binaryDerString = window.atob(
    pem.replace(/-----BEGIN PUBLIC KEY-----/, '')
       .replace(/-----END PUBLIC KEY-----/, '')
       .replace(/\n/g, '')
  );
  const binaryDer = str2ab(binaryDerString);

  return window.crypto.subtle.importKey(
    "spki",
    binaryDer,
    { name: "RSA-OAEP", hash: "SHA-256" },
    true,
    ["encrypt"]
  );
}

// Generate AES Key
async function generateAESKey() {
  return window.crypto.subtle.generateKey(
    { name: "AES-GCM", length: 256 },
    true,
    ["encrypt", "decrypt"]
  );
}

// --- NEW: SESSION BASED ENCRYPTION ---

// 1. Start the Session (Generate Keys ONCE)
export async function startEncryptionSession(pemPublicKey) {
  try {
    const aesKey = await generateAESKey();
    const rsaKey = await importPublicKey(pemPublicKey);
    
    // Generate a Base IV (12 bytes)
    const iv = window.crypto.getRandomValues(new Uint8Array(12));

    // Encrypt the AES Key with RSA (so the server can store it securely)
    const rawAesKey = await window.crypto.subtle.exportKey("raw", aesKey);
    const encryptedAesKey = await window.crypto.subtle.encrypt(
      { name: "RSA-OAEP" },
      rsaKey,
      rawAesKey
    );

    return {
      aesKey, // Keep raw key for client-side usage (encrypting chunks)
      encryptedKey: arrayBufferToBase64(encryptedAesKey), // Send to server
      iv: iv // Keep raw IV for manipulation
    };
  } catch (err) {
    console.error("Key Generation Failed:", err);
    throw err;
  }
}

// 2. Encrypt a Single Chunk
export async function encryptChunk(chunk, aesKey, baseIv, chunkIndex) {
  try {
    // Clone the IV so we don't modify the original
    const ivCopy = new Uint8Array(baseIv);
    
    // Modify the last 4 bytes of the IV based on the chunk index
    // This ensures every chunk has a UNIQUE IV (Security Requirement)
    const view = new DataView(ivCopy.buffer);
    // We treat the last 4 bytes as a counter. 
    // chunkIndex 0 -> IV ends in ...0000
    // chunkIndex 1 -> IV ends in ...0001
    // This allows up to 4 billion chunks.
    const last4Bytes = view.getUint32(8, false) + chunkIndex; 
    view.setUint32(8, last4Bytes, false); 

    const chunkBuffer = await chunk.arrayBuffer();

    const encryptedContent = await window.crypto.subtle.encrypt(
      { name: "AES-GCM", iv: ivCopy },
      aesKey,
      chunkBuffer
    );

    return new Blob([encryptedContent]);
  } catch (err) {
    console.error(`Chunk ${chunkIndex} Encryption Failed:`, err);
    throw err;
  }
}

// --- HASHING FUNCTION ---
export function calculateFileHash(file) {
  return new Promise((resolve, reject) => {
    const chunkSize = 20 * 1024 * 1024; // 20MB
    const totalChunks = Math.ceil(file.size / chunkSize);
    const sha256 = CryptoJS.algo.SHA256.create();
    let currentChunk = 0;

    const reader = new FileReader();

    reader.onload = function(e) {
      const wordArray = CryptoJS.lib.WordArray.create(e.target.result);
      sha256.update(wordArray);
      currentChunk++;
      if (currentChunk < totalChunks) loadNext();
      else resolve(sha256.finalize().toString(CryptoJS.enc.Hex));
    };

    reader.onerror = (err) => reject(err);

    function loadNext() {
      const start = currentChunk * chunkSize;
      const end = Math.min(start + chunkSize, file.size);
      reader.readAsArrayBuffer(file.slice(start, end));
    }
    loadNext();
  });
}