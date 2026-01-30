// cryptoUtils.js

// 1. Generate a random AES-256 Key (Session Key)
export const generateAESKey = async () => {
  return await window.crypto.subtle.generateKey(
    {
      name: "AES-GCM",
      length: 256,
    },
    true, // Extractable (so we can encrypt it with RSA)
    ["encrypt", "decrypt"]
  );
};

// 2. Import Receiver's RSA Public Key (PEM String -> CryptoKey)
export const importRSAPublicKey = async (pem) => {
  // Fetch the part of the PEM string between header and footer
  const pemHeader = "-----BEGIN PUBLIC KEY-----";
  const pemFooter = "-----END PUBLIC KEY-----";
  const pemContents = pem.substring(
    pem.indexOf(pemHeader) + pemHeader.length,
    pem.indexOf(pemFooter)
  );
  
  // Decode Base64 to binary
  const binaryDerString = window.atob(pemContents.replace(/\s/g, ''));
  const binaryDer = new Uint8Array(binaryDerString.length);
  for (let i = 0; i < binaryDerString.length; i++) {
    binaryDer[i] = binaryDerString.charCodeAt(i);
  }

  return await window.crypto.subtle.importKey(
    "spki",
    binaryDer.buffer,
    {
      name: "RSA-OAEP",
      hash: "SHA-256",
    },
    true,
    ["encrypt"]
  );
};

// 3. Encrypt the AES Key using RSA (Hybrid Step)
export const encryptSessionKey = async (aesKey, rsaPublicKey) => {
  // Export AES key to raw bytes
  const rawKeyData = await window.crypto.subtle.exportKey("raw", aesKey);
  
  // Encrypt those bytes with RSA
  const encryptedKeyBuffer = await window.crypto.subtle.encrypt(
    {
      name: "RSA-OAEP",
    },
    rsaPublicKey,
    rawKeyData
  );
  
  // Return as Base64 string for easy storage in MongoDB
  return arrayBufferToBase64(encryptedKeyBuffer);
};

// 4. Encrypt a File Chunk using AES-GCM
export const encryptChunk = async (chunkArrayBuffer, aesKey) => {
  // Generate a unique IV (Initialization Vector) for this chunk
  const iv = window.crypto.getRandomValues(new Uint8Array(12));
  
  const encryptedContent = await window.crypto.subtle.encrypt(
    {
      name: "AES-GCM",
      iv: iv,
    },
    aesKey,
    chunkArrayBuffer
  );

  // Combine IV + Ciphertext (We need the IV to decrypt later!)
  // Blob format: [ 12 bytes IV | ... Encrypted Data ... ]
  return new Blob([iv, new Uint8Array(encryptedContent)]);
};

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