import React, { useEffect, useState, useCallback } from 'react';
import axios from 'axios';
import FileUpload from './FileUpload';
import { decryptFile, setupLocalRSAKeys } from '../utils/encryption';

const Dashboard = ({ token, user, logout }) => {
  const [files, setFiles] = useState([]);

  // Generate Zero-Knowledge Keys on load
  useEffect(() => {
    setupLocalRSAKeys().catch(err => console.error("Key Setup Failed:", err));
  }, []);

  const fetchFiles = useCallback(async () => {
    try {
      const res = await axios.get('http://localhost:5000/myfiles', { headers: { Authorization: `Bearer ${token}` } });
      setFiles(res.data);
    } catch (err) {
      console.error("Fetch error:", err);
    }
  }, [token]);

  useEffect(() => { fetchFiles(); }, [fetchFiles]);

  const handleDelete = async (fileId) => {
    if (!window.confirm("Permanently delete this file?")) return;
    try {
      await axios.delete(`http://localhost:5000/delete/${fileId}`, { headers: { Authorization: `Bearer ${token}` } });
      setFiles(current => current.filter(f => f._id !== fileId));
    } catch (err) { alert("Delete failed"); }
  };

  const handleDownload = async (fileId, fileName) => {
    try {
      console.log("⬇️ Fetching encrypted file...");
      const fileRes = await axios.get(`http://localhost:5000/download/${fileId}`, {
        headers: { Authorization: `Bearer ${token}` }, responseType: 'blob'
      });

      console.log("🔑 Fetching metadata (encrypted key)...");
      // UPDATED ROUTE:
      const metaRes = await axios.get(`http://localhost:5000/request-file-metadata/${fileId}`, {
         headers: { Authorization: `Bearer ${token}` }
      });
      
      // We receive the ENCRYPTED AES key here
      const { encryptedKey, iv, totalChunks } = metaRes.data;

      console.log("🔓 Client-Side Decryption Initiated...");
      const decryptedBlob = await decryptFile(fileRes.data, encryptedKey, iv, totalChunks);

      const url = window.URL.createObjectURL(decryptedBlob);
      const link = document.createElement('a');
      link.href = url;
      link.setAttribute('download', fileName);
      document.body.appendChild(link);
      link.click();
      link.remove();
    } catch (err) {
      console.error("Download Error:", err);
      alert("Decryption Failed! Are you missing your local Private Key?");
    }
  };

  return (
    <div className="dashboard">
      <header>
        <h2>Welcome, {user} (Zero-Knowledge Mode)</h2>
        <button onClick={logout} className="logout-btn">Logout</button>
      </header>
      <FileUpload token={token} refreshFiles={fetchFiles} />
      <div className="files-section">
        <h3>My Secure Files</h3>
        <ul>
          {files.map(file => (
            <li key={file._id} style={{ padding: '10px', borderBottom: '1px solid #ccc' }}>
              <span>{file.originalName}</span>
              <div className="actions">
                <button onClick={() => handleDownload(file._id, file.originalName)}>Download</button>
                <button onClick={() => handleDelete(file._id)} style={{ marginLeft: '10px', backgroundColor: '#dc3545' }}>Delete</button>
              </div>
            </li>
          ))}
        </ul>
      </div>
    </div>
  );
};

export default Dashboard;