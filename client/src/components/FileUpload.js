import React, { useState, useRef, useEffect } from 'react';
import axios from 'axios';
import { startEncryptionSession, encryptChunk, calculateFileHash } from '../utils/encryption';

const FileUpload = ({ token, refreshFiles }) => {
  // Queue Management
  const [uploadQueue, setUploadQueue] = useState([]);
  const [currentFileIndex, setCurrentFileIndex] = useState(0);
  
  // Status State
  const [status, setStatus] = useState(""); 
  const [uploadProgress, setUploadProgress] = useState(0);
  const [uploadState, setUploadState] = useState("IDLE"); // IDLE, SCANNING, UPLOADING, PAUSED, ERROR, QUEUE_DONE

  // Refs for loop control
  const isPaused = useRef(false);
  const isCancelled = useRef(false);
  const currentChunkRef = useRef(0);
  const cryptoData = useRef(null);

  // --- 1. HANDLE FOLDER / FILE SELECTION ---
  const handleSelection = (e) => {
    if (e.target.files && e.target.files.length > 0) {
      // Convert FileList to Array
      const files = Array.from(e.target.files);
      setUploadQueue(files);
      setCurrentFileIndex(0);
      resetTrackers();
      
      setStatus(`Ready to upload ${files.length} files.`);
      setUploadState("IDLE");
    }
  };

  const resetTrackers = () => {
    currentChunkRef.current = 0;
    cryptoData.current = null;
    isPaused.current = false;
    isCancelled.current = false;
    setUploadProgress(0);
  };

  // --- 2. START QUEUE PROCESSING ---
  const startQueue = () => {
    if (uploadQueue.length > 0) {
      processCurrentFile();
    }
  };

  // --- 3. PROCESS SINGLE FILE (The Brain) ---
  const processCurrentFile = async () => {
    const currentFile = uploadQueue[currentFileIndex];
    if (!currentFile) return;

    // Use webkitRelativePath for folders, else name
    const filePathName = currentFile.webkitRelativePath || currentFile.name;

    setStatus(`Processing ${currentFileIndex + 1}/${uploadQueue.length}: ${filePathName}`);
    isPaused.current = false;
    isCancelled.current = false;

    try {
      // A. INITIALIZE (Scan & Encrypt) only if starting fresh
      if (currentChunkRef.current === 0) {
        setUploadState("SCANNING");
        
        // 1. Virus Scan
        const fileHash = await calculateFileHash(currentFile);
        try {
          const scanRes = await axios.post('http://localhost:5000/scan-file', { fileHash });
          if (scanRes.data.data?.attributes?.last_analysis_stats?.malicious > 0) {
             alert(`❌ Virus Detected in ${filePathName}! Skipping file.`);
             moveToNextFile();
             return;
          }
        } catch (e) { console.warn("Virus scan skipped."); }

        // 2. Encrypt Keys
        setStatus("🔐 Encrypting...");
        cryptoData.current = await startEncryptionSession();
      }

      // B. START UPLOAD LOOP
      processUploadLoop(currentFile, filePathName);

    } catch (err) {
      console.error("Setup Error:", err);
      setUploadState("ERROR");
    }
  };

  // --- 4. UPLOAD LOOP ---
  const processUploadLoop = async (file, fileName) => {
    setUploadState("UPLOADING");
    
    const CHUNK_SIZE = 5 * 1024 * 1024;
    const totalChunks = Math.ceil(file.size / CHUNK_SIZE);
    const { aesKey, encryptedKey, iv } = cryptoData.current;

    try {
      while (currentChunkRef.current < totalChunks) {
        if (isCancelled.current) {
          setUploadState("IDLE");
          setUploadQueue([]);
          return;
        }
        if (isPaused.current) {
          setUploadState("PAUSED");
          setStatus("⏸️ Paused");
          return;
        }

        const i = currentChunkRef.current;
        const fileSlice = file.slice(i * CHUNK_SIZE, Math.min((i + 1) * CHUNK_SIZE, file.size));
        const encryptedChunk = await encryptChunk(fileSlice, aesKey, iv, i);

        const formData = new FormData();
        formData.append('chunkIndex', i);
        formData.append('totalChunks', totalChunks);
        formData.append('originalName', fileName); // Send path: "Folder/File.txt"
        formData.append('file', encryptedChunk);
        formData.append('passwordHash', encryptedKey); 
        formData.append('salt', window.btoa(String.fromCharCode(...iv))); 

        await axios.post('http://localhost:5000/upload', formData, {
          headers: { Authorization: `Bearer ${token}` }
        });
        
        currentChunkRef.current = i + 1; 
        setUploadProgress(Math.round((currentChunkRef.current / totalChunks) * 100));
      }

      // File Complete!
      moveToNextFile();

    } catch (err) {
      console.error("Upload Loop Error:", err);
      setUploadState("ERROR");
      setStatus("❌ Network Error. Click Resume.");
    }
  };

  // --- 5. MOVE TO NEXT FILE ---
  const moveToNextFile = () => {
    resetTrackers();
    if (currentFileIndex + 1 < uploadQueue.length) {
      setCurrentFileIndex(prev => prev + 1);
      // Small timeout to let state update before starting next
      setTimeout(() => document.getElementById('btn-auto-next').click(), 100);
    } else {
      setUploadState("QUEUE_DONE");
      setStatus("✅ All Files Uploaded Successfully!");
      setUploadQueue([]);
      refreshFiles();
      alert("Folder Upload Complete!");
    }
  };

  // --- RENDER HELPERS ---
  const handlePause = () => { isPaused.current = true; };
  const handleResume = () => { isPaused.current = false; processCurrentFile(); };
  const handleCancel = () => { isCancelled.current = true; };

  return (
    <div className="upload-section" style={{ padding: '20px', border: '1px solid #ddd', borderRadius: '8px', marginBottom: '20px' }}>
      <h3>Secure Upload</h3>
      
      {/* HIDDEN BUTTON FOR AUTO-ADVANCE */}
      <button id="btn-auto-next" style={{display:'none'}} onClick={processCurrentFile}></button>

      <div style={{ display: 'flex', gap: '10px', alignItems: 'center', flexWrap: 'wrap' }}>
        
        {/* INPUTS */}
        {uploadState === "IDLE" || uploadState === "QUEUE_DONE" ? (
          <>
            <label className="custom-file-upload" style={btnStyle('#007bff')}>
              📂 Select Folder
              <input 
                type="file" 
                webkitdirectory="" 
                directory="" 
                multiple 
                onChange={handleSelection} 
                style={{ display: 'none' }}
              />
            </label>

            <label className="custom-file-upload" style={btnStyle('#6c757d')}>
              📄 Select Files
              <input 
                type="file" 
                multiple 
                onChange={handleSelection} 
                style={{ display: 'none' }}
              />
            </label>
          </>
        ) : null}

        {/* ACTION BUTTONS */}
        {uploadState === "IDLE" && uploadQueue.length > 0 && (
          <button onClick={startQueue} style={btnStyle('#28a745')}>
            Start Upload ({uploadQueue.length} files)
          </button>
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
      
      {uploadProgress > 0 && uploadState !== "QUEUE_DONE" && (
        <div style={{ marginTop: '10px' }}>
            <progress value={uploadProgress} max="100" style={{ width: '100%', height: '20px' }}></progress>
            <div style={{ textAlign: 'center', fontSize: '12px' }}>
              File {currentFileIndex + 1} of {uploadQueue.length} — {uploadProgress}%
            </div>
        </div>
      )}
    </div>
  );
};

const btnStyle = (bg, color = 'white') => ({
  backgroundColor: bg,
  color: color,
  border: 'none',
  padding: '10px 20px',
  borderRadius: '5px',
  cursor: 'pointer',
  fontWeight: 'bold',
  display: 'inline-block'
});

export default FileUpload;