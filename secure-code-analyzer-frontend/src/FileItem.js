// FileItem.js
import React, { useState, useEffect } from 'react';

const FileItem = ({ file, index, removeFile, formatFileSize, getZipFileInfo }) => {
  const [zipContents, setZipContents] = useState(null);
  const [showZipContents, setShowZipContents] = useState(false);
  
  useEffect(() => {
    if (file.name.endsWith('.zip')) {
      getZipFileInfo(file).then(contents => setZipContents(contents));
    }
  }, [file, getZipFileInfo]);

  return (
    <div className="file-item">
      <span className="file-icon">
        {file.name.endsWith('.zip') ? '📦' : '📄'}
      </span>
      <span className="file-name">{file.name}</span>
      <span className="file-size">({formatFileSize(file.size)})</span>
      
      {file.name.endsWith('.zip') && zipContents && (
        <button 
          type="button"
          className="toggle-zip-btn"
          onClick={() => setShowZipContents(!showZipContents)}
          title={showZipContents ? "Hide contents" : "Show contents"}
        >
          {showZipContents ? "▲" : "▼"}
        </button>
      )}
      
      <button 
        type="button"
        className="remove-file-btn"
        onClick={() => removeFile(index)}
        title="Remove file"
      >
        ×
      </button>
      
      {showZipContents && zipContents && (
        <div className="zip-contents">
          <div className="zip-contents-header">
            <span>Contains {zipContents.length} files:</span>
          </div>
          <div className="zip-files-list">
            {zipContents.slice(0, 5).map((fileName, i) => (
              <div key={i} className="zip-file-item">
                <span className="zip-file-icon">📄</span>
                <span className="zip-file-name">{fileName}</span>
              </div>
            ))}
            {zipContents.length > 5 && (
              <div className="zip-more-files">
                + {zipContents.length - 5} more files
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
};

export default FileItem;