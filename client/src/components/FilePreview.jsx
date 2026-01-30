import React from 'react';
const FilePreview = ({ file }) => {
  return (
    <div className="mt-4 p-3 bg-gray-50 border rounded flex items-center justify-between">
      <div>
        <p className="text-sm font-semibold text-gray-700">{file.name}</p>
        <p className="text-xs text-gray-500">{(file.size / 1024 / 1024).toFixed(2)} MB</p>
      </div>
    </div>
  );
};
export default FilePreview;