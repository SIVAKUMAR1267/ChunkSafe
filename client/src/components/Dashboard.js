import React, { useEffect, useState, useCallback } from 'react'; // Import useCallback
import axios from 'axios';
import FileUpload from './FileUpload';

const Dashboard = ({ token, user, logout }) => {
  const [files, setFiles] = useState([]);

  // WRAP IN USECALLBACK
  const fetchFiles = useCallback(async () => {
    try {
      const res = await axios.get('http://localhost:5000/myfiles', {
        headers: { Authorization: `Bearer ${token}` }
      });
      setFiles(res.data);
    } catch (err) {
      console.error("Fetch error:", err);
    }
  }, [token]); // dependency is 'token'

  // NOW USEEFFECT IS HAPPY
  useEffect(() => {
    fetchFiles();
  }, [fetchFiles]); 

  const handleDownload = async (fileId, fileName) => {
    try {
      const res = await axios.get(`http://localhost:5000/download/${fileId}`, {
        headers: { Authorization: `Bearer ${token}` },
        responseType: 'blob'
      });
      const url = window.URL.createObjectURL(new Blob([res.data]));
      const link = document.createElement('a');
      link.href = url;
      link.setAttribute('download', fileName);
      document.body.appendChild(link);
      link.click();
      link.remove();
    } catch (err) {
      alert("Download failed");
    }
  };

  const handleDelete = async (fileId) => {
    if (!window.confirm("Delete this file?")) return;
    try {
      await axios.delete(`http://localhost:5000/delete/${fileId}`, {
        headers: { Authorization: `Bearer ${token}` }
      });
      setFiles(files.filter(f => f._id !== fileId));
    } catch (err) {
      alert("Delete failed");
    }
  };

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
              <li key={file._id}>
                <span>{file.originalName} ({(file.size / 1024).toFixed(1)} KB)</span>
                <div className="actions">
                  <button onClick={() => handleDownload(file._id, file.originalName)}>Download</button>
                  <button 
                    onClick={() => handleDelete(file._id)} 
                    style={{ marginLeft: '10px', backgroundColor: '#dc3545' }}
                  >
                    Delete
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