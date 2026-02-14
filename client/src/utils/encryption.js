import CryptoJS from 'crypto-js';

// --- HELPER FUNCTIONS ---
function arrayBufferToBase64(buffer) {
  let binary = '';
  const bytes = new Uint8Array(buffer);
  for (let i = 0; i < bytes.byteLength; i++) binary += String.fromCharCode(bytes[i]);
  return window.btoa(binary);
}

function base64ToArrayBuffer(base64) {
  const binary_string = window.atob(base64);
  const len = binary_string.length;
  const bytes = new Uint8Array(len);
  for (let i = 0; i < len; i++) bytes[i] = binary_string.charCodeAt(i);
  return bytes.buffer;
}

// --- ZERO-KNOWLEDGE: LOCAL RSA KEY MANAGEMENT ---
// Generates keys in the browser and saves them to LocalStorage
export async function setupLocalRSAKeys() {
  if (localStorage.getItem("zk_public_key") && localStorage.getItem("zk_private_key")) {
    return; // Keys already exist
  }

  console.log("🔐 Generating Zero-Knowledge RSA Keys in Browser...");
  const keyPair = await window.crypto.subtle.generateKey(
    { name: "RSA-OAEP", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" },
    true,
    ["encrypt", "decrypt"]
  );

  const exportedPublicKey = await window.crypto.subtle.exportKey("jwk", keyPair.publicKey);
  const exportedPrivateKey = await window.crypto.subtle.exportKey("jwk", keyPair.privateKey);

  localStorage.setItem("zk_public_key", JSON.stringify(exportedPublicKey));
  localStorage.setItem("zk_private_key", JSON.stringify(exportedPrivateKey));
  console.log("✅ Local Keys Saved securely.");
}

async function getLocalPublicKey() {
  const jwk = JSON.parse(localStorage.getItem("zk_public_key"));
  return window.crypto.subtle.importKey("jwk", jwk, { name: "RSA-OAEP", hash: "SHA-256" }, true, ["encrypt"]);
}

async function getLocalPrivateKey() {
  const jwk = JSON.parse(localStorage.getItem("zk_private_key"));
  return window.crypto.subtle.importKey("jwk", jwk, { name: "RSA-OAEP", hash: "SHA-256" }, true, ["decrypt"]);
}

// --- ENCRYPTION (UPLOAD) ---
export async function startEncryptionSession() {
  const aesKey = await window.crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, true, ["encrypt", "decrypt"]);
  const iv = window.crypto.getRandomValues(new Uint8Array(12));

  const rawAesKey = await window.crypto.subtle.exportKey("raw", aesKey);
  const publicKey = await getLocalPublicKey(); // Get user's own public key
  
  // Encrypt AES key with User's Public Key (Server can't read this)
  const encryptedAesKey = await window.crypto.subtle.encrypt({ name: "RSA-OAEP" }, publicKey, rawAesKey);

  return { aesKey, encryptedKey: arrayBufferToBase64(encryptedAesKey), iv };
}

export async function encryptChunk(chunk, aesKey, baseIv, chunkIndex) {
  const ivCopy = new Uint8Array(baseIv);
  const view = new DataView(ivCopy.buffer);
  view.setUint32(8, view.getUint32(8, false) + chunkIndex, false);

  const encryptedContent = await window.crypto.subtle.encrypt({ name: "AES-GCM", iv: ivCopy }, aesKey, await chunk.arrayBuffer());
  return new Blob([encryptedContent]);
}

// DECRYPTION (DOWNLOAD) 
// NEW: The client now unwraps its own AES key using its local Private Key
export async function decryptFile(encryptedBlob, base64EncryptedAesKey, base64Iv, totalChunks) {
  console.log(`🔓 Unlocking AES Key with Local Private Key...`);
  
  const privateKey = await getLocalPrivateKey();
  const encryptedAesKeyBuffer = base64ToArrayBuffer(base64EncryptedAesKey);

  // Client-side RSA Decryption!
  const rawAesKeyBuffer = await window.crypto.subtle.decrypt({ name: "RSA-OAEP" }, privateKey, encryptedAesKeyBuffer);
  
  const aesKey = await window.crypto.subtle.importKey("raw", rawAesKeyBuffer, { name: "AES-GCM" }, true, ["decrypt"]);

  let ivString = base64Iv;
  if (ivString.startsWith('"')) ivString = JSON.parse(ivString);
  const baseIv = new Uint8Array(base64ToArrayBuffer(ivString));

  const CHUNK_SIZE = 5 * 1024 * 1024;
  const ENCRYPTED_CHUNK_SIZE = CHUNK_SIZE + 16; 
  const decryptedParts = [];
  let currentOffset = 0;

  for (let i = 0; i < totalChunks; i++) {
    const isLastChunk = i === totalChunks - 1;
    const sliceLength = isLastChunk ? (encryptedBlob.size - currentOffset) : ENCRYPTED_CHUNK_SIZE;
    const chunkBuffer = await encryptedBlob.slice(currentOffset, currentOffset + sliceLength).arrayBuffer();

    const ivCopy = new Uint8Array(baseIv);
    const view = new DataView(ivCopy.buffer);
    view.setUint32(8, view.getUint32(8, false) + i, false);

    const decryptedChunk = await window.crypto.subtle.decrypt({ name: "AES-GCM", iv: ivCopy }, aesKey, chunkBuffer);
    decryptedParts.push(decryptedChunk);
    currentOffset += sliceLength;
  }
  return new Blob(decryptedParts);
}

// --- HASHING ---
export function calculateFileHash(file) {
  return new Promise((resolve, reject) => {
    const chunkSize = 20 * 1024 * 1024;
    const totalChunks = Math.ceil(file.size / chunkSize);
    const sha256 = CryptoJS.algo.SHA256.create();
    let currentChunk = 0;
    const reader = new FileReader();

    reader.onload = function(e) {
      sha256.update(CryptoJS.lib.WordArray.create(e.target.result));
      currentChunk++;
      currentChunk < totalChunks ? loadNext() : resolve(sha256.finalize().toString(CryptoJS.enc.Hex));
    };
    reader.onerror = reject;
    function loadNext() { reader.readAsArrayBuffer(file.slice(currentChunk * chunkSize, Math.min((currentChunk + 1) * chunkSize, file.size))); }
    loadNext();
  });
}