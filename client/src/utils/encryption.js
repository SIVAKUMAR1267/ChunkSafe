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
// ... (keep existing imports and functions) ...

// --- NEW: DECRYPT FILE FUNCTION ---
// ... (Keep existing imports and functions) ...

// --- NEW: CHUNKED DECRYPTION FUNCTION ---
export async function decryptFile(encryptedBlob, base64AesKey, base64Iv, totalChunks) {
  try {
    console.log(`🔓 Decrypting ${totalChunks} chunks...`);

    // 1. Import Key
    const rawKey = Uint8Array.from(atob(base64AesKey), c => c.charCodeAt(0));
    const aesKey = await window.crypto.subtle.importKey(
      "raw",
      rawKey,
      { name: "AES-GCM" },
      true,
      ["decrypt"]
    );

    // 2. Prepare Base IV
    let ivString = base64Iv;
    if (ivString.startsWith('"') && ivString.endsWith('"')) ivString = JSON.parse(ivString);
    const baseIv = Uint8Array.from(atob(ivString), c => c.charCodeAt(0));

    // 3. Constants (MUST MATCH UPLOAD SETTINGS)
    const CHUNK_SIZE = 5 * 1024 * 1024; // 5MB
    const TAG_LENGTH = 16; // AES-GCM adds 16 bytes tag overhead
    const ENCRYPTED_CHUNK_SIZE = CHUNK_SIZE + TAG_LENGTH; 

    const decryptedParts = [];
    let currentOffset = 0;

    // 4. Decrypt Loop
    for (let i = 0; i < totalChunks; i++) {
      // Calculate start/end of this encrypted chunk
      // If it's the last chunk, it takes whatever is left
      const isLastChunk = i === totalChunks - 1;
      const sliceLength = isLastChunk ? (encryptedBlob.size - currentOffset) : ENCRYPTED_CHUNK_SIZE;
      
      const chunkBlob = encryptedBlob.slice(currentOffset, currentOffset + sliceLength);
      const chunkBuffer = await chunkBlob.arrayBuffer();

      // Calculate the Unique IV for this chunk (Base IV + Index)
      const ivCopy = new Uint8Array(baseIv);
      const view = new DataView(ivCopy.buffer);
      const last4Bytes = view.getUint32(8, false) + i; 
      view.setUint32(8, last4Bytes, false);

      // Decrypt
      try {
        const decryptedChunk = await window.crypto.subtle.decrypt(
          { name: "AES-GCM", iv: ivCopy },
          aesKey,
          chunkBuffer
        );
        decryptedParts.push(decryptedChunk);
      } catch (chunkErr) {
        console.error(`Failed to decrypt chunk ${i}. Offset: ${currentOffset}, Size: ${sliceLength}`);
        throw chunkErr;
      }

      currentOffset += sliceLength;
    }

    // 5. Merge all decrypted parts into one Blob
    return new Blob(decryptedParts);

  } catch (err) {
    console.error("Decryption Failed:", err);
    alert("Decryption failed! File might be corrupted.");
    throw err;
  }
}