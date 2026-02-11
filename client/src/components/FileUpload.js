import React, { useState } from 'react';
import axios from 'axios';
import { startEncryptionSession, encryptChunk, calculateFileHash } from '../utils/encryption';

const FileUpload = ({ token, refreshFiles }) => {
  const [selectedFile, setSelectedFile] = useState(null);
  const [status, setStatus] = useState(""); 
  const [uploadProgress, setUploadProgress] = useState(0);

  // --- Handle File Selection ---
  const handleFileSelect = (e) => {
    if (e.target.files && e.target.files[0]) {
      setSelectedFile(e.target.files[0]);
      setStatus("");
      setUploadProgress(0);
    }
  };

  // --- Handle The Upload Process ---
  const handleUploadClick = async () => {
    if (!selectedFile) return;

    try {
      // 1. VIRUS SCAN
      setStatus("🔍 Scanning...");
      const fileHash = await calculateFileHash(selectedFile);
      try {
        const scanRes = await axios.post('http://localhost:5000/scan-file', { fileHash });
        if (scanRes.data.data?.attributes?.last_analysis_stats?.malicious > 0) {
            setStatus("❌ Upload Blocked: Virus Detected");
            return alert("❌ DANGER: Virus Detected!");
        }
      } catch (e) {
        console.warn("Virus scan skipped (likely network/API issue).");
      }

      // 2. ZERO-KNOWLEDGE ENCRYPTION
      setStatus("🔐 Encrypting Locally...");
      const { aesKey, encryptedKey, iv } = await startEncryptionSession();
      
      // 3. CHUNK AND UPLOAD
      setStatus("🚀 Uploading...");
      const CHUNK_SIZE = 5 * 1024 * 1024; // 5MB chunks
      const totalChunks = Math.ceil(selectedFile.size / CHUNK_SIZE);

      for (let i = 0; i < totalChunks; i++) {
        // Slice the file
        const fileSlice = selectedFile.slice(i * CHUNK_SIZE, Math.min((i + 1) * CHUNK_SIZE, selectedFile.size));
        
        // Encrypt the slice
        const encryptedChunk = await encryptChunk(fileSlice, aesKey, iv, i);

        // Prepare form data
        const formData = new FormData();
        formData.append('chunkIndex', i);
        formData.append('totalChunks', totalChunks);
        formData.append('originalName', selectedFile.name);
        formData.append('file', encryptedChunk);
        formData.append('passwordHash', encryptedKey); 
        formData.append('salt', window.btoa(String.fromCharCode(...iv))); 

        // Upload to server
        await axios.post('http://localhost:5000/upload', formData, {
          headers: { Authorization: `Bearer ${token}` }
        });
        
        setUploadProgress(Math.round(((i + 1) / totalChunks) * 100));
      }

      // 4. CLEANUP
      setStatus("✅ Complete!");
      alert("Secure Upload Successful!");
      setSelectedFile(null);
      setUploadProgress(0);
      refreshFiles();

    } catch (err) { 
      console.error("Upload Error:", err);
      setStatus("❌ Error occurred");
      alert("Upload Failed. Check console for details."); 
    }
  };

  // --- UI RENDER ---
  return (
    <div className="upload-section">
      <h3>Secure Upload</h3>
      <div style={{ display: 'flex', gap: '10px', alignItems: 'center' }}>
        <input 
          type="file" 
          onChange={handleFileSelect} 
          disabled={status.includes("Uploading")} 
        />
        <button 
          onClick={handleUploadClick}
          disabled={!selectedFile || status.includes("Uploading")}
          style={{ 
            backgroundColor: !selectedFile ? '#ccc' : '#28a745', 
            cursor: !selectedFile ? 'not-allowed' : 'pointer',
            color: 'white',
            border: 'none',
            padding: '8px 16px',
            borderRadius: '4px'
          }}
        >
          {status.includes("Uploading") ? "Processing..." : "Upload Now"}
        </button>
      </div>
      {status && <p style={{ fontWeight: 'bold', color: '#007bff', marginTop: '10px' }}>{status}</p>}
      {uploadProgress > 0 && (
        <div style={{ marginTop: '10px' }}>
            <progress value={uploadProgress} max="100" style={{ width: '100%' }}></progress>
            <div style={{ textAlign: 'center', fontSize: '12px' }}>{uploadProgress}%</div>
        </div>
      )}
    </div>
  );
};

export default FileUpload;