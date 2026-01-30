import React, { useState } from "react";
import axios from "axios";
import { toast } from "react-toastify";
import ProgressBar from "./ProgressBar"; // Import local component
import FilePreview from "./FilePreview"; // Import local component
import { generateAESKey, encryptChunk, encryptSessionKeyWithRSA } from "../utils/encryption"; // ✅ Correct Path

const CHUNK_SIZE = 1024 * 1024; // 1MB
const CONCURRENCY = 3;

const UploadForm = () => {
  const [file, setFile] = useState(null);
  const [progress, setProgress] = useState(0);
  const [status, setStatus] = useState("Idle");

  const onFileSelect = (selectedFile) => {
    setFile(selectedFile);
    setProgress(0);
    setStatus("Ready to Encrypt & Upload");
  };

  const handleSecureUpload = async () => {
    if (!file) return;

    try {
      setStatus("🔐 1/3 Generating Keys...");
      const aesKey = await generateAESKey();
      const encryptedSessionKey = await encryptSessionKeyWithRSA(aesKey);

      setStatus("🚀 2/3 Encrypting & Uploading...");
      
      const totalChunks = Math.ceil(file.size / CHUNK_SIZE);
      let chunksUploaded = 0;
      const queue = Array.from({ length: totalChunks }, (_, i) => i);

      const uploadWorker = async () => {
        while (queue.length > 0) {
          const index = queue.shift();
          const start = index * CHUNK_SIZE;
          const end = Math.min(file.size, start + CHUNK_SIZE);

          // 1. Slice
          const fileSlice = file.slice(start, end);
          const arrayBuffer = await fileSlice.arrayBuffer();

          // 2. Encrypt (Client Side)
          const encryptedBlob = await encryptChunk(arrayBuffer, aesKey);

          // 3. Upload
          const formData = new FormData();
          formData.append("file", encryptedBlob);
          formData.append("chunkIndex", index);
          formData.append("totalChunks", totalChunks);
          formData.append("originalName", file.name);
          
          if (index === 0) formData.append("passwordHash", encryptedSessionKey);

          // Send to Server
          await axios.post("http://localhost:5000/upload", formData);
          
          chunksUploaded++;
          setProgress(Math.round((chunksUploaded / totalChunks) * 100));
        }
      };

      await Promise.all(Array(CONCURRENCY).fill(null).map(uploadWorker));

      setStatus("🎉 Upload Complete!");
      toast.success("File encrypted and stored successfully.");
      setFile(null); // Reset

    } catch (error) {
      console.error(error);
      setStatus("❌ Error occurred");
      toast.error("Upload failed. Check server console.");
    }
  };

  return (
    <div className="p-6">
      <div className="w-full h-32 border-2 border-dashed border-blue-400 flex items-center justify-center bg-blue-50 rounded-lg cursor-pointer relative hover:bg-blue-100 transition">
        <input 
          type="file" 
          onChange={(e) => onFileSelect(e.target.files[0])} 
          className="absolute inset-0 w-full h-full opacity-0 cursor-pointer"
        />
        <p className="text-gray-500 font-medium">Click to select a file</p>
      </div>

      {file && <FilePreview file={file} />}

      {progress > 0 && (
        <div className="mt-4">
          <ProgressBar progress={progress} />
          <p className="text-center text-sm text-blue-600 mt-2 font-mono">{status}</p>
        </div>
      )}

      <button
        disabled={!file || (progress > 0 && progress < 100)}
        onClick={handleSecureUpload}
        className="w-full mt-6 bg-blue-600 hover:bg-blue-700 text-white font-bold py-3 px-4 rounded-lg disabled:bg-gray-400 disabled:cursor-not-allowed transition-all"
      >
        {progress === 100 ? "Upload Another" : "Start Secure Upload"}
      </button>
    </div>
  );
};

export default UploadForm;