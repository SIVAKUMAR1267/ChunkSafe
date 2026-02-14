import React, { useState, useRef } from 'react';
import axios from 'axios';
import { startEncryptionSession, encryptChunk, calculateFileHash } from '../utils/encryption';

const FileUpload = ({ token, refreshFiles }) => {
  const [selectedFile, setSelectedFile] = useState(null);
  const [status, setStatus] = useState(""); 
  const [uploadProgress, setUploadProgress] = useState(0);
  
  // UI State: IDLE, SCANNING, UPLOADING, PAUSED, ERROR
  const [uploadState, setUploadState] = useState("IDLE"); 

  // Refs for real-time loop control (bypasses React's async state updates)
  const isPaused = useRef(false);
  const isCancelled = useRef(false);
  
  // Refs to store progress and crypto keys across pause/resume cycles
  const currentChunkRef = useRef(0);
  const cryptoData = useRef(null);

  // --- 1. FILE SELECTION ---
  const handleFileSelect = (e) => {
    if (e.target.files && e.target.files[0]) {
      setSelectedFile(e.target.files[0]);
      setStatus("");
      setUploadProgress(0);
      setUploadState("IDLE");
      
      // Reset all trackers for a fresh file
      currentChunkRef.current = 0;
      cryptoData.current = null;
      isPaused.current = false;
      isCancelled.current = false;
    }
  };

  // --- 2. INITIALIZE UPLOAD (Runs once per file) ---
  const initUpload = async () => {
    isPaused.current = false;
    isCancelled.current = false;
    
    try {
      // Only scan and generate keys if starting from chunk 0
      if (currentChunkRef.current === 0) {
        setStatus("🔍 Scanning...");
        setUploadState("SCANNING");
        
        // Virus Scan
        const fileHash = await calculateFileHash(selectedFile);
        try {
          const scanRes = await axios.post('http://localhost:5000/scan-file', { fileHash });
          if (scanRes.data.data?.attributes?.last_analysis_stats?.malicious > 0) {
              setStatus("❌ Upload Blocked: Virus Detected");
              setUploadState("IDLE");
              return alert("❌ DANGER: Virus Detected!");
          }
        } catch (e) {
          console.warn("Virus scan skipped (Network/API issue).");
        }

        // Generate Session Keys
        setStatus("🔐 Encrypting Locally...");
        cryptoData.current = await startEncryptionSession();
      }

      // Enter the upload loop
      processUploadLoop();

    } catch (err) {
      console.error("Setup Error:", err);
      setStatus("❌ Setup Failed. Try again.");
      setUploadState("ERROR");
    }
  };

  // --- 3. THE UPLOAD LOOP (Can be paused, resumed, or cancelled) ---
  const processUploadLoop = async () => {
    setUploadState("UPLOADING");
    setStatus(currentChunkRef.current > 0 ? "🚀 Resuming Upload..." : "🚀 Uploading...");
    
    const CHUNK_SIZE = 5 * 1024 * 1024; // 5MB
    const totalChunks = Math.ceil(selectedFile.size / CHUNK_SIZE);
    const { aesKey, encryptedKey, iv } = cryptoData.current;

    try {
      while (currentChunkRef.current < totalChunks) {
        
        // Check control flags BEFORE processing the next chunk
        if (isCancelled.current) {
          setStatus("🚫 Upload Cancelled");
          setUploadState("IDLE");
          setSelectedFile(null);
          setUploadProgress(0);
          return;
        }
        
        if (isPaused.current) {
          setStatus("⏸️ Paused");
          setUploadState("PAUSED");
          return; // Exit loop, but keep all progress in memory
        }

        const i = currentChunkRef.current;
        const fileSlice = selectedFile.slice(i * CHUNK_SIZE, Math.min((i + 1) * CHUNK_SIZE, selectedFile.size));
        const encryptedChunk = await encryptChunk(fileSlice, aesKey, iv, i);

        const formData = new FormData();
        formData.append('chunkIndex', i);
        formData.append('totalChunks', totalChunks);
        formData.append('originalName', selectedFile.name);
        formData.append('file', encryptedChunk);
        formData.append('passwordHash', encryptedKey); 
        formData.append('salt', window.btoa(String.fromCharCode(...iv))); 

        // Network Request
        await axios.post('http://localhost:5000/upload', formData, {
          headers: { Authorization: `Bearer ${token}` }
        });
        
        // Increment progress successfully
        currentChunkRef.current = i + 1; 
        setUploadProgress(Math.round((currentChunkRef.current / totalChunks) * 100));
      }

      // Loop finished naturally
      setStatus("✅ Complete!");
      setUploadState("IDLE");
      alert("Secure Upload Successful!");
      setSelectedFile(null);
      setUploadProgress(0);
      currentChunkRef.current = 0;
      refreshFiles();

    } catch (err) {
      console.error("Network Error During Upload:", err);
      setStatus("❌ Upload Interrupted (Network Error)");
      setUploadState("ERROR"); 
      // currentChunkRef is left exactly where it failed. 
      // Clicking "Resume" will re-attempt this exact chunk.
    }
  };

  // --- 4. CONTROL HANDLERS ---
  const handlePause = () => { isPaused.current = true; };
  const handleResume = () => { isPaused.current = false; processUploadLoop(); };
  const handleCancel = () => { isCancelled.current = true; };

  // --- UI RENDER ---
  return (
    <div className="upload-section">
      <h3>Secure Upload</h3>
      <div style={{ display: 'flex', gap: '10px', alignItems: 'center', flexWrap: 'wrap' }}>
        
        <input 
          type="file" 
          onChange={handleFileSelect} 
          disabled={uploadState === "UPLOADING" || uploadState === "SCANNING"} 
        />

        {/* Dynamic Buttons Based on State */}
        {uploadState === "IDLE" && (
          <button 
            onClick={initUpload}
            disabled={!selectedFile}
            style={btnStyle(selectedFile ? '#28a745' : '#ccc')}
          >
            Upload Now
          </button>
        )}

        {uploadState === "SCANNING" && (
          <button disabled style={btnStyle('#ccc')}>Scanning...</button>
        )}

        {uploadState === "UPLOADING" && (
          <>
            <button onClick={handlePause} style={btnStyle('#ffc107', 'black')}>Pause</button>
            <button onClick={handleCancel} style={btnStyle('#dc3545')}>Cancel</button>
          </>
        )}

        {(uploadState === "PAUSED" || uploadState === "ERROR") && (
          <>
            <button onClick={handleResume} style={btnStyle('#17a2b8')}>
              {uploadState === "ERROR" ? "Retry Chunk" : "Resume"}
            </button>
            <button onClick={handleCancel} style={btnStyle('#dc3545')}>Cancel</button>
          </>
        )}

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

// Quick helper for button styling to keep JSX clean
const btnStyle = (bg, color = 'white') => ({
  backgroundColor: bg,
  color: color,
  border: 'none',
  padding: '8px 16px',
  borderRadius: '4px',
  cursor: bg === '#ccc' ? 'not-allowed' : 'pointer'
});

export default FileUpload;