import React, { useEffect, useState } from "react";
import axios from "axios";
import { toast } from "react-toastify";

const FileList = ({ user }) => {
  const [files, setFiles] = useState([]);

  // Fetch files when the component loads
  const fetchFiles = async () => {
    try {
      const res = await axios.get(`http://localhost:5000/my-files?user=${user}`);
      setFiles(res.data);
    } catch (err) {
      console.error(err);
    }
  };

  useEffect(() => {
    fetchFiles();
  }, [user]);

  // Handle Download
  const handleDownload = (id, fileName) => {
    // In a real app, we would decrypt here. For now, we download the encrypted blob.
    window.open(`http://localhost:5000/download/${id}`, "_blank");
  };

  // Handle Delete
  const handleDelete = async (id) => {
    if(!window.confirm("Are you sure you want to delete this file?")) return;
    
    try {
      await axios.delete(`http://localhost:5000/files/${id}`);
      toast.success("File deleted");
      fetchFiles(); // Refresh list
    } catch (err) {
      toast.error("Delete failed");
    }
  };

  return (
    <div className="w-full max-w-2xl mt-8">
      <h3 className="text-xl font-bold mb-4 text-gray-700">My Uploaded Files</h3>
      
      {files.length === 0 ? (
        <p className="text-gray-500 italic">No files found for {user}. Upload one!</p>
      ) : (
        <div className="bg-white rounded-lg shadow overflow-hidden">
          {files.map((file) => (
            <div key={file._id} className="flex items-center justify-between p-4 border-b last:border-b-0 hover:bg-gray-50">
              <div className="flex flex-col">
                <span className="font-semibold text-gray-800">{file.originalName}</span>
                <span className="text-xs text-gray-500">
                  {(file.size / 1024 / 1024).toFixed(2)} MB • {new Date(file.uploadDate).toLocaleDateString()}
                </span>
              </div>
              <div className="flex gap-2">
                <button 
                  onClick={() => handleDownload(file._id, file.originalName)}
                  className="px-3 py-1 text-sm text-blue-600 border border-blue-600 rounded hover:bg-blue-50"
                >
                  Download
                </button>
                <button 
                  onClick={() => handleDelete(file._id)}
                  className="px-3 py-1 text-sm text-red-600 border border-red-600 rounded hover:bg-red-50"
                >
                  Delete
                </button>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
};

export default FileList;