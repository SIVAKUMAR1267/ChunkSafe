import React, { useState, useEffect } from 'react';
import axios from 'axios';
import { startEncryptionSession, encryptChunk, calculateFileHash } from '../utils/encryption';

// Helper to convert Uint8Array IV to Base64 string for upload
function arrayBufferToBase64(buffer) {
    let binary = '';
    const bytes = new Uint8Array(buffer);
    const len = bytes.byteLength;
    for (let i = 0; i < len; i++) {
        binary += String.fromCharCode(bytes[i]);
    }
    return window.btoa(binary);
}

const FileUpload = ({ token, refreshFiles }) => {
  const [selectedFile, setSelectedFile] = useState(null);
  const [uploadProgress, setUploadProgress] = useState(0);
  const [status, setStatus] = useState(""); 
  const [serverPublicKey, setServerPublicKey] = useState(null);

  useEffect(() => {
    axios.get('http://localhost:5000/public-key')
      .then(res => setServerPublicKey(res.data.publicKey))
      .catch(err => console.error("Key Error", err));
  }, []);

  const handleFileSelect = (e) => {
    if (e.target.files && e.target.files[0]) {
      setSelectedFile(e.target.files[0]);
      setStatus("");
      setUploadProgress(0);
    }
  };

  const handleUploadClick = async () => {
    if (!selectedFile) return alert("Please select a file.");
    if (!serverPublicKey) return alert("Server Public Key missing.");

    try {
      // 1. VIRUS SCAN
      setStatus("🔍 Scanning for viruses...");
      const fileHash = await calculateFileHash(selectedFile);
      
      try {
        const scanResponse = await axios.post('http://localhost:5000/scan-file', { fileHash });
        const stats = scanResponse.data.data?.attributes?.last_analysis_stats;
        if (stats && stats.malicious > 0) {
           setStatus("❌ Upload Blocked: Virus Detected");
           return alert(`❌ DANGER: File flagged as malicious!`);
        }
      } catch (err) {
        console.warn("Virus scan skipped (likely network/API issue).");
      }

      // 2. PREPARE ENCRYPTION SESSION (Generate Keys)
      setStatus("🔐 Preparing Encryption...");
      const { aesKey, encryptedKey, iv } = await startEncryptionSession(serverPublicKey);
      
      // 3. CHUNK + ENCRYPT + UPLOAD LOOP
      setStatus("🚀 Encrypting & Uploading...");
      
      const CHUNK_SIZE = 5 * 1024 * 1024; // 5MB Chunks
      const totalChunks = Math.ceil(selectedFile.size / CHUNK_SIZE);

      for (let chunkIndex = 0; chunkIndex < totalChunks; chunkIndex++) {
        const start = chunkIndex * CHUNK_SIZE;
        const end = Math.min(start + CHUNK_SIZE, selectedFile.size);
        
        // A. Slice the ORIGINAL file (Not encrypted yet)
        const fileSlice = selectedFile.slice(start, end);

        // B. Encrypt ONLY this slice
        // We pass the chunkIndex to ensure unique IV for each chunk
        const encryptedChunkBlob = await encryptChunk(fileSlice, aesKey, iv, chunkIndex);

        // C. Upload the Encrypted Chunk
        const formData = new FormData();
        formData.append('chunkIndex', chunkIndex);
        formData.append('totalChunks', totalChunks);
        formData.append('originalName', selectedFile.name);
        formData.append('file', encryptedChunkBlob);
        
        // Metadata (Sent with every chunk for simplicity, or just the last one)
        formData.append('passwordHash', encryptedKey); 
        formData.append('salt', JSON.stringify(arrayBufferToBase64(iv))); 

        await axios.post('http://localhost:5000/upload', formData, {
          headers: { 
            Authorization: `Bearer ${token}`,
            'Content-Type': 'multipart/form-data'
          }
        });

        setUploadProgress(Math.round(((chunkIndex + 1) / totalChunks) * 100));
      }

      setStatus("✅ Complete!");
      alert("Secure Upload Successful!");
      setSelectedFile(null);
      setUploadProgress(0);
      refreshFiles();

    } catch (err) {
      console.error(err);
      setStatus("❌ Error occurred");
      alert("Upload failed. See console.");
    }
  };

  return (
    <div className="upload-section">
      <h3>Secure Upload</h3>
      <div style={{ display: 'flex', gap: '10px', alignItems: 'center' }}>
        <input type="file" onChange={handleFileSelect} disabled={status.includes("Uploading")} />
        <button 
          onClick={handleUploadClick}
          disabled={!selectedFile || status.includes("Uploading")}
          style={{ 
            backgroundColor: !selectedFile ? '#ccc' : '#28a745', 
            cursor: !selectedFile ? 'not-allowed' : 'pointer'
          }}
        >
          {status.includes("Uploading") ? "Processing..." : "Upload Now"}
        </button>
      </div>
      {status && <p style={{ fontWeight: 'bold', color: '#007bff', marginTop: '10px' }}>{status}</p>}
      {uploadProgress > 0 && <progress value={uploadProgress} max="100" style={{ width: '100%' }}></progress>}
    </div>
  );
};

export default FileUpload;