import React, { useEffect, useState, useCallback } from 'react';
import axios from 'axios';
import FileUpload from './FileUpload';
import { decryptFile } from '../utils/encryption';

const Dashboard = ({ token, user, logout }) => {
  const [files, setFiles] = useState([]);

  // --- FETCH FILES ---
  const fetchFiles = useCallback(async () => {
    try {
      const res = await axios.get('http://localhost:5000/myfiles', {
        headers: { Authorization: `Bearer ${token}` }
      });
      setFiles(res.data);
    } catch (err) {
      console.error("Fetch error:", err);
    }
  }, [token]);

  useEffect(() => {
    fetchFiles();
  }, [fetchFiles]);

  // --- DELETE FUNCTION (Debug Version) ---
  const handleDelete = async (fileId) => {
    console.log("1. handleDelete function STARTED for ID:", fileId);
    
    // Check if token exists
    if (!token) {
        console.error("❌ NO TOKEN FOUND. Log in again.");
        return;
    }

    try {
      console.log("2. Sending DELETE request to server...");
      
      const res = await axios.delete(`http://localhost:5000/delete/${fileId}`, {
        headers: { Authorization: `Bearer ${token}` }
      });

      console.log("3. Server responded:", res.status, res.data);

      if (res.status === 200) {
        console.log("4. Updating UI...");
        setFiles(currentFiles => currentFiles.filter(f => f._id !== fileId));
        alert("✅ File Deleted!");
      }

    } catch (err) {
      console.error("❌ DELETE FAILED:", err);
      if (err.response) {
        console.error("Server Error Data:", err.response.data);
        alert(`Failed: ${err.response.data.message || err.response.statusText}`);
      } else {
        alert("Network Error or Server Down");
      }
    }
  };

  // --- DOWNLOAD FUNCTION ---
  const handleDownload = async (fileId, fileName) => {
    try {
      console.log("⬇️ Fetching encrypted file...");
      const fileRes = await axios.get(`http://localhost:5000/download/${fileId}`, {
        headers: { Authorization: `Bearer ${token}` },
        responseType: 'blob'
      });

      console.log("🔑 Fetching key...");
      const keyRes = await axios.get(`http://localhost:5000/request-decryption-key/${fileId}`, {
         headers: { Authorization: `Bearer ${token}` }
      });
      
      const { aesKey, iv, totalChunks } = keyRes.data;

      console.log("🔓 Decrypting...");
      const decryptedBlob = await decryptFile(fileRes.data, aesKey, iv, totalChunks);

      const url = window.URL.createObjectURL(decryptedBlob);
      const link = document.createElement('a');
      link.href = url;
      link.setAttribute('download', fileName);
      document.body.appendChild(link);
      link.click();
      link.remove();
    } catch (err) {
      console.error("Download Error:", err);
      alert("Download Failed: " + err.message);
    }
  };

  // --- UI RENDER ---
  return (
    <div className="dashboard">
      <header>
        <h2>Welcome, {user}</h2>
        <button onClick={logout} className="logout-btn">Logout</button>
      </header>

      <FileUpload token={token} refreshFiles={fetchFiles} />

      <div className="files-section">
        <h3>My Files</h3>
        {files.length === 0 ? <p>No files found.</p> : (
          <ul>
            {files.map(file => (
              <li key={file._id} style={{ padding: '10px', borderBottom: '1px solid #ccc' }}>
                
                <span>{file.originalName} ({(file.size / 1024).toFixed(1)} KB)</span>
                
                <div className="actions">
                  <button onClick={() => handleDownload(file._id, file.originalName)}>
                    Download
                  </button>
                  
                  {/* DIRECT DELETE BUTTON */}
                  <button 
                    onClick={() => handleDelete(file._id)} 
                    style={{ marginLeft: '10px', backgroundColor: '#dc3545', color: 'white' }}
                  >
                    Delete Now
                  </button>
                </div>

              </li>
            ))}
          </ul>
        )}
      </div>
    </div>
  );
};

export default Dashboard;