import React, { useState, useEffect, useMemo, useCallback } from "react";
import { PieChart, Pie, Cell, Tooltip, ResponsiveContainer } from "recharts";
import API_BASE_URL from "./config";

// ... (all your React component code remains here)
// BUT remove the Python/Flask code at the bottom
const SEVERITY_COLORS = {
  CRITICAL: { chip: "critical", row: "severity-critical", chart: "#ef4444" },
  HIGH: { chip: "high", row: "severity-high", chart: "#f59e0b" },
  MEDIUM: { chip: "medium", row: "severity-medium", chart: "#06b6d4" },
  LOW: { chip: "low", row: "severity-low", chart: "#10b981" },
  INFO: { chip: "info", row: "severity-info", chart: "#94a3b8" },
};

const FILE_EXTENSIONS = {
  PYTHON: [".py"],
  JAVASCRIPT: [".js", ".jsx"],
  PHP: [".php"],
  JAVA: [".java"],
};

const OWASP_VULNERABILITIES = [
  {
    name: "A01: Broken Access Control",
    id: "A01",
    color: "#ef4444",
    description: "Restrictions on authenticated users not properly enforced"
  },
  {
    name: "A02: Cryptographic Failures",
    id: "A02",
    color: "#f59e0b",
    description: "Sensitive data exposure due to cryptographic failures"
  },
  {
    name: "A03: Injection",
    id: "A03",
    color: "#dc2626",
    description: "SQL, NoSQL, OS command injection vulnerabilities"
  },
  {
    name: "A04: Insecure Design",
    id: "A04",
    color: "#9333ea",
    description: "Security risks from insecure design patterns"
  },
  {
    name: "A05: Security Misconfiguration",
    id: "A05",
    color: "#0891b2",
    description: "Improperly configured security settings"
  },
  {
    name: "A06: Vulnerable Components",
    id: "A06",
    color: "#059669",
    description: "Using components with known vulnerabilities"
  },
  {
    name: "A07: Authentication Failures",
    id: "A07",
    color: "#7c3aed",
    description: "Broken authentication and session management"
  },
  {
    name: "A08: Software Integrity Failures",
    id: "A08",
    color: "#be185d",
    description: "Code and infrastructure integrity violations"
  },
  {
    name: "A09: Logging & Monitoring Failures",
    id: "A09",
    color: "#b91c1c",
    description: "Insufficient logging and monitoring"
  },
  {
    name: "A10: Server-Side Request Forgery",
    id: "A10",
    color: "#374151",
    description: "SSRF flaws allowing server-side requests"
  }
];


function App() {
  const [issues, setIssues] = useState([]);
  const [selectedFiles, setSelectedFiles] = useState([]);
  const [scanTime, setScanTime] = useState("0s");
  const [filters, setFilters] = useState({
    severity: "ALL",
    owasp: "ALL",
    cwe: "ALL",
    fileType: "ALL",
    search: "",
  });
  
  const [showCli, setShowCli] = useState(false);
  const [sidebarOpen, setSidebarOpen] = useState(false);
  const [filtersVisible, setFiltersVisible] = useState(true);
  const [theme, setTheme] = useState("dark");
  const [activeBar, setActiveBar] = useState(null);
  const [isScanning, setIsScanning] = useState(false);
  const [scanProgress, setScanProgress] = useState(0);
  const [expandedRows, setExpandedRows] = useState({});
  const [showDownloadOptions, setShowDownloadOptions] = useState(false);
  const [chartAnimated, setChartAnimated] = useState(false);
  const [uploadError, setUploadError] = useState(null);
  const [isRefreshing, setIsRefreshing] = useState(false);
  const [notification, setNotification] = useState({ message: '', type: '' });
  const [isDragging, setIsDragging] = useState(false);
  // ... your state declarations ...
 const filterOptions = useMemo(() => {
    const options = {
      severities: new Set(["ALL"]),
      owaspCategories: new Set(["ALL"]),
      cweCategories: new Set(["ALL"]),
      fileTypes: new Set(["ALL"]),
    };

    issues.forEach(issue => {
      // Add severity
      options.severities.add(issue.severity.toUpperCase());
      
      // Add OWASP categories
      if (issue.owasp) {
        const owaspMatch = issue.owasp.match(/A\d+/);
        if (owaspMatch && owaspMatch[0]) {
          options.owaspCategories.add(owaspMatch[0]);
        }
      }
      
      // Add CWE categories
      if (issue.cwe) {
        const cweMatch = issue.cwe.match(/CWE-\d+/);
        if (cweMatch && cweMatch[0]) {
          options.cweCategories.add(cweMatch[0]);
        }
      }
      
      // Add file types
      if (issue.file) {
        const fileExt = issue.file.substring(issue.file.lastIndexOf('.'));
        const fileType = Object.entries(FILE_EXTENSIONS).find(([_, exts]) => 
          exts.includes(fileExt)
        );
        if (fileType) {
          options.fileTypes.add(fileType[0]);
        }
      }
    });

    // Convert Sets to Arrays for easier mapping
    return {
      severities: Array.from(options.severities),
      owaspCategories: Array.from(options.owaspCategories),
      cweCategories: Array.from(options.cweCategories),
      fileTypes: Array.from(options.fileTypes),
    };
  }, [issues]);

  // Function to get OWASP category name from ID
  const getOwaspName = (id) => {
    const vuln = OWASP_VULNERABILITIES.find(v => v.id === id);
    return vuln ? vuln.name : id;
  };

  // NUCLEAR OPTION: Prevent ALL page refreshes
  useEffect(() => {
    console.log('🚀 Installing nuclear page refresh prevention');
    
    const preventEverything = (e) => {
      // Prevent ALL form submissions
      if (e.type === 'submit' || e.target.tagName === 'FORM' || e.target.closest('form')) {
        console.log('🚫 BLOCKED FORM SUBMISSION', e.target);
        e.preventDefault();
        e.stopPropagation();
        e.stopImmediatePropagation();
        return false;
      }
      
      // Prevent button clicks from submitting forms
      if (e.target.tagName === 'BUTTON' && e.target.type !== 'button') {
        console.log('🚫 BLOCKED BUTTON CLICK', e.target);
        e.preventDefault();
        e.stopPropagation();
        e.stopImmediatePropagation();
        return false;
      }
    };

    // Nuclear event listeners - capture EVERYTHING
    window.addEventListener('beforeunload', (e) => {
      e.preventDefault();
      e.returnValue = '';
      console.log('🚫 BLOCKED PAGE UNLOAD');
    });
    
    document.addEventListener('submit', preventEverything, true);
    document.addEventListener('click', preventEverything, true);
    document.addEventListener('mousedown', preventEverything, true);

    return () => {
      window.removeEventListener('beforeunload', preventEverything);
      document.removeEventListener('submit', preventEverything, true);
      document.removeEventListener('click', preventEverything, true);
      document.removeEventListener('mousedown', preventEverything, true);
    };
  }, []);
  useEffect(() => {
  // Find all buttons missing type="button"
  const buttons = document.querySelectorAll('button:not([type="button"])');
  console.log('Buttons missing type="button":', buttons.length);
  
  buttons.forEach(button => {
    console.log('Missing type:', button.textContent.trim());
    button.style.border = '3px solid red'; // Highlight in red
  });
}, []);
useEffect(() => {
  // Automatically add type="button" to all buttons missing it
  const buttons = document.querySelectorAll('button:not([type])');
  buttons.forEach(button => {
    button.setAttribute('type', 'button');
    console.log('✅ Fixed button:', button.textContent.trim());
  });
  
  // Also fix buttons with type="submit"
  const submitButtons = document.querySelectorAll('button[type="submit"]');
  submitButtons.forEach(button => {
    button.setAttribute('type', 'button');
    console.log('✅ Fixed submit button:', button.textContent.trim());
  });
}, []);

  useEffect(() => {
  // Automatically add type="button" to all buttons missing it
  const allButtons = document.querySelectorAll('button');
  allButtons.forEach(button => {
    if (!button.hasAttribute('type')) {
      button.setAttribute('type', 'button');
      console.log('Fixed button:', button.textContent);
    }
  });
}, []);
  // Fixed useEffect to prevent infinite refresh
  useEffect(() => {
  let isMounted = true;

  const loadInitialData = async () => {
    try {
      // Try to load the report automatically on app start
      const response = await fetch('/reports/report.json');
      
      if (response.ok) {
        const reportData = await response.json();
        if (isMounted && reportData.issues) {
          setIssues(reportData.issues);
          console.log('Loaded', reportData.issues.length, 'issues from saved report');
        }
      }
    } catch (err) {
      console.log('No saved report found or error loading:', err.message);
    } finally {
      setTimeout(() => setChartAnimated(true), 1000);
    }
  };

  loadInitialData();

  return () => {
    isMounted = false;
  };
}, []);


    // Load initial data with a small delay
  //   const timer = setTimeout(() => {
  //     loadInitialIssues();
  //   }, 500);

  //   return () => {
  //     isMounted = false;
  //     clearTimeout(timer);
  //   };
  // }, []); // Empty dependency array ensures this runs only once
    const loadReportFromFile = async () => {
    try {
      setIsScanning(true);
      setUploadError(null);
      
      const response = await fetch(`${API_BASE_URL}/reports/report.json`);
      
      if (!response.ok) {
        throw new Error(`Failed to load report: ${response.status}`);
      }
      
      const reportData = await response.json();
      const deduplicatedIssues = deduplicateIssues(reportData.issues || []);
      
      setIssues(deduplicatedIssues);
      setScanTime("From saved report");
      
      setNotification({ 
  message: `Scan completed! Found ${deduplicatedIssues.length} unique issues in ${selectedFiles.length} file${selectedFiles.length !== 1 ? 's' : ''} ${selectedFiles.some(f => f.name.endsWith('.zip')) ? '(including ZIP contents)' : ''}`, 
  type: 'success' 
});
    } catch (err) {
      console.error('Error loading report:', err);
      setUploadError('No report found. Please scan files first.');
    } finally {
      setIsScanning(false);
    }
  };
//   const handleRefresh = useCallback(async () => {
//   if (isRefreshing) return;
//   setIsRefreshing(true);

//   try {
//     const response = await fetch(`${API_BASE_URL}/refresh`, {
//       method: 'POST',
//     });

//     if (!response.ok) {
//       throw new Error(`HTTP error! status: ${response.status}`);
//     }

//     // After backend refresh, load the updated report
//     await loadReportFromFile();
    
//   } catch (err) {
//     console.error('Refresh error:', err);
//     setNotification({ message: 'Refresh failed: ' + err.message, type: 'error' });
//   } finally {
//     setIsRefreshing(false);
//   }
// }, [isRefreshing]);
 const generateVulnerabilityId = (issue) => {
    return `${issue.file}-${issue.line}-${issue.id}-${issue.message}`.replace(/\s+/g, '-');
  };

   const deduplicateIssues = (issuesArray) => {
    const uniqueIssues = {};
    const result = [];
    
    issuesArray.forEach(issue => {
      const id = generateVulnerabilityId(issue);
      if (!uniqueIssues[id]) {
        uniqueIssues[id] = true;
        result.push({...issue, uniqueId: id});
      }
    });
    
    return result;
  };

  const clearFilters = () => {
    setFilters({
      severity: "ALL",
      owasp: "ALL",
      cwe: "ALL",
      fileType: "ALL",
      search: "",
    });
  };

  const clearAllIssues = () => {
    setIssues([]);
    setScanTime("0s");
    setSelectedFiles([]);
    setNotification({ message: 'All issues cleared successfully', type: 'success' });
  };

  const filteredIssues = useMemo(() => {
    return issues.filter(issue => {
      if (filters.severity !== "ALL" && issue.severity !== filters.severity) {
        return false;
      }

      if (filters.owasp !== "ALL" && !issue.owasp.includes(filters.owasp)) {
        return false;
      }

      if (filters.cwe !== "ALL" && !issue.cwe.includes(filters.cwe)) {
        return false;
      }

      if (filters.fileType !== "ALL") {
        const fileExt = issue.file.substring(issue.file.lastIndexOf('.'));
        if (!FILE_EXTENSIONS[filters.fileType]?.includes(fileExt)) {
          return false;
        }
      }

      if (filters.search) {
        const searchTerm = filters.search.toLowerCase();
        const searchableFields = [
          issue.file,
          issue.message,
          issue.category,
          issue.id,
          issue.detected_by,
          issue.owasp,
          issue.cwe,
          issue.suggestion
        ].join(" ").toLowerCase();

        if (!searchableFields.includes(searchTerm)) {
          return false;
        }
      }

      return true;
    });
  }, [issues, filters]);

  const owaspCounts = useMemo(() => {
    const counts = {};

    OWASP_VULNERABILITIES.forEach(vuln => {
      counts[vuln.id] = 0;
    });

    filteredIssues.forEach(issue => {
      const owaspMatch = issue.owasp.match(/A\d+/);
      if (owaspMatch && owaspMatch[0]) {
        const owaspId = owaspMatch[0];
        if (counts.hasOwnProperty(owaspId)) {
          counts[owaspId]++;
        }
      }
    });

    return counts;
  }, [filteredIssues]);

  const owaspChartData = useMemo(() => {
    return OWASP_VULNERABILITIES.map(vuln => {
      const count = owaspCounts[vuln.id] || 0;
      const percentage = filteredIssues.length > 0
        ? Math.round((count / filteredIssues.length) * 100)
        : 0;

      return {
        ...vuln,
        count,
        value: percentage,
      };
    }).filter(item => item.count > 0)
      .sort((a, b) => b.count - a.count);
  }, [owaspCounts, filteredIssues.length]);

  const severityCounts = useMemo(() => {
    const counts = {
      CRITICAL: 0,
      HIGH: 0,
      MEDIUM: 0,
      LOW: 0,
      INFO: 0,
    };

    filteredIssues.forEach(issue => {
      const severity = issue.severity.toUpperCase();
      if (counts.hasOwnProperty(severity)) {
        counts[severity]++;
      }
    });

    return counts;
  }, [filteredIssues]);

  const totalIssues = Object.values(severityCounts).reduce((a, b) => a + b, 0);
  const securityScore = Math.max(0, 100 -
    (severityCounts.CRITICAL * 10 +
     severityCounts.HIGH * 5 +
     severityCounts.MEDIUM * 2 +
     severityCounts.LOW * 1));

  const getScoreRange = (score) => {
    if (score >= 90) return "excellent";
    if (score >= 70) return "good";
    if (score >= 50) return "average";
    return "poor";
  };

  const SeverityChip = ({ severity }) => {
    const sev = severity.toUpperCase();
    const colorClass = SEVERITY_COLORS[sev]?.chip || "";
    return <span className={`chip ${colorClass}`}>{sev}</span>;
  };
  const handleRefresh = useCallback(async (event) => {
  if (isRefreshing) return;
  
  // Prevent default if event exists
  if (event) {
    event.preventDefault();
    event.stopPropagation();
  }
  
  setIsRefreshing(true);

  try {
    const response = await fetch(`${API_BASE_URL}/refresh`, {
      method: 'POST',
    });

    if (!response.ok) {
      throw new Error(`HTTP error! status: ${response.status}`);
    }

    const data = await response.json();
    setIssues(data.issues || []);
    setScanTime(`${Date.now() % 1000}ms`);
    setNotification({ message: 'Data refreshed successfully', type: 'success' });
  } catch (err) {
    console.error('Refresh error:', err);
    setNotification({ message: 'Refresh failed: ' + err.message, type: 'error' });
  } finally {
    setIsRefreshing(false);
  }
}, [isRefreshing]);
const FileItem = ({ file, index, removeFile, formatFileSize }) => {
    const [zipContents, setZipContents] = useState(null);
    const [showZipContents, setShowZipContents] = useState(false);
    
    useEffect(() => {
      if (file.name.endsWith('.zip')) {
        getZipFileInfo(file).then(contents => setZipContents(contents));
      }
    }, [file]);

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

const handleFileSelect = (event) => {
  if (event && event.preventDefault) {
    event.preventDefault();
  }
  
  const files = Array.from(event.target.files || []);
  
  if (files.length === 0) {
    return;
  }

  // Validate file types - ADDED JAVA AND PYTHON
  const validFiles = files.filter(file => {
    const fileName = file.name.toLowerCase();
    return fileName.endsWith('.js') || 
           fileName.endsWith('.php') || 
           fileName.endsWith('.java') ||  // ADDED
           fileName.endsWith('.py') ||    // ADDED
           fileName.endsWith('.zip');
  });

  if (validFiles.length === 0) {
    setUploadError('Please select .js, .php, .java, .py, or .zip files only.');
    return;
  }

  setSelectedFiles(prevFiles => [...prevFiles, ...validFiles]);
  
  // Reset the input
  event.target.value = '';
};
const handleDragEnter = (e) => {
  e.preventDefault();
  e.stopPropagation();
  setIsDragging(true);
  // Add dragging class to the drop zone
  const dropZone = e.currentTarget.closest('.drag-drop-zone');
  if (dropZone) {
    dropZone.classList.add('dragging');
  }
};

const handleDragLeave = (e) => {
  e.preventDefault();
  e.stopPropagation();
  setIsDragging(false);
  // Remove dragging class from the drop zone
  const dropZone = e.currentTarget.closest('.drag-drop-zone');
  if (dropZone) {
    dropZone.classList.remove('dragging');
  }
};

const handleDragOver = (e) => {
  e.preventDefault();
  e.stopPropagation();
  setIsDragging(true);
};

const handleDrop = (e) => {
  e.preventDefault();
  e.stopPropagation();
  setIsDragging(false);
  
  // Remove dragging class from the drop zone
  const dropZone = e.currentTarget.closest('.drag-drop-zone');
  if (dropZone) {
    dropZone.classList.remove('dragging');
  }
  
  const files = Array.from(e.dataTransfer.files);
  
  if (files.length === 0) {
    return;
  }

  // Validate file types - ADDED JAVA AND PYTHON
  const validFiles = files.filter(file => {
    const fileName = file.name.toLowerCase();
    return fileName.endsWith('.js') || 
           fileName.endsWith('.php') || 
           fileName.endsWith('.java') ||  // ADDED
           fileName.endsWith('.py') ||    // ADDED
           fileName.endsWith('.zip');
  });

  if (validFiles.length === 0) {
    setUploadError('Please select .js, .php, .java, .py, or .zip files only.');
    return;
  }

  setSelectedFiles(prevFiles => [...prevFiles, ...validFiles]);
};
const handleDropZoneClick = () => {
  document.getElementById('file-upload-input').click();
};
   const handleFileUpload = async () => {
  if (selectedFiles.length === 0) {
    setUploadError('Please select at least one file to scan');
    return;
  }

  setIsScanning(true);
  setScanProgress(0);
  setUploadError(null);

  try {
    const formData = new FormData();
    
    // Add each file individually with the correct field name
    selectedFiles.forEach(file => {
      formData.append('files', file); // Make sure it's 'files' (plural)
    });

    // Log what we're sending for debugging
    console.log('FormData entries:');
    for (let [key, value] of formData.entries()) {
      console.log(key, value.name, value.size);
    }

    const progressInterval = setInterval(() => {
      setScanProgress(prev => Math.min(prev + 10, 90));
    }, 200);

    const response = await fetch(`${API_BASE_URL}/scan`, {
      method: 'POST',
      body: formData,
      // DO NOT set Content-Type header - let browser set it with boundary
    });

    clearInterval(progressInterval);
    setScanProgress(100);

    if (!response.ok) {
      let errorMessage = `Server returned ${response.status}`;
      try {
        const errorData = await response.json();
        errorMessage = errorData.error || errorMessage;
        if (errorData.details) {
          errorMessage += `: ${errorData.details}`;
        }
      } catch (e) {
        errorMessage += ` - ${response.statusText}`;
      }
      throw new Error(errorMessage);
    }

    const data = await response.json();
    const deduplicatedIssues = deduplicateIssues(data.issues || []);
    
    setIssues(deduplicatedIssues);
    setScanTime(`${Date.now() % 1000}ms`);
    
    setNotification({ 
      message: `Scan completed! Found ${deduplicatedIssues.length} unique issues`, 
      type: 'success' 
    });

  } catch (err) {
    console.error('Upload error:', err);
    setUploadError('Scan failed: ' + err.message);
  } finally {
    setIsScanning(false);
  }
};


  const handleDownload = async (format) => {
    try {
      const response = await fetch(`${API_BASE_URL}/reports/report.${format}`);

      if (!response.ok) {
        throw new Error(`HTTP error! status: ${response.status}`);
      }

      const blob = await response.blob();
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `report.${format}`;
      document.body.appendChild(a);
      a.click();
      window.URL.revokeObjectURL(url);
      document.body.removeChild(a);

      setNotification({ message: `Downloaded report as ${format.toUpperCase()}`, type: 'success' });
    } catch (err) {
      console.error('Download error:', err);
      setNotification({ message: 'Download failed: ' + err.message, type: 'error' });
    } finally {
      setShowDownloadOptions(false);
    }
  };

  const toggleTheme = () => {
    setTheme(theme === "dark" ? "light" : "dark");
  };
  const getZipFileInfo = async (file) => {
  if (file.name.endsWith('.zip')) {
    try {
      // Dynamically import JSZip only when needed
      const JSZip = await import('jszip');
      const zip = new JSZip.default();
      const arrayBuffer = await file.arrayBuffer();
      const contents = await zip.loadAsync(arrayBuffer);
      
      const fileList = [];
      contents.forEach((relativePath, zipEntry) => {
        if (!zipEntry.dir && 
            (relativePath.endsWith('.js') || 
             relativePath.endsWith('.php') || 
             relativePath.endsWith('.java') || 
             relativePath.endsWith('.py'))) {
          fileList.push(zipEntry.name);
        }
      });
      
      return fileList;
    } catch (error) {
      console.error('Error reading ZIP file:', error);
      return ['ZIP file contents could not be read'];
    }
  }
  return null;
};

  const handleBarClick = (index) => {
    setActiveBar(index === activeBar ? null : index);
  };
const formatFileSize = (bytes) => {
  if (bytes === 0) return '0 Bytes';
  const k = 1024;
  const sizes = ['Bytes', 'KB', 'MB', 'GB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
};
const removeFile = (index) => {
  setSelectedFiles(prevFiles => prevFiles.filter((_, i) => i !== index));
};

const clearAllFiles = () => {
  setSelectedFiles([]);
  setUploadError(null);
};

  const toggleRowExpansion = (index) => {
    setExpandedRows(prev => ({
      ...prev,
      [index]: !prev[index]
    }));
  };

  useEffect(() => {
    document.body.className = theme;
  }, [theme]);
  useEffect(() => {
  const preventFormSubmit = (e) => {
    // Prevent all form submissions in the app
    if (e.target.closest('form') || e.target.tagName === 'FORM') {
      console.log('Form submission prevented');
      e.preventDefault();
      e.stopPropagation();
      e.stopImmediatePropagation();
      return false;
    }
  };

  // Listen at the capture phase to catch all submissions
  document.addEventListener('submit', preventFormSubmit, true);
  document.addEventListener('click', preventFormSubmit, true);

  return () => {
    document.removeEventListener('submit', preventFormSubmit, true);
    document.removeEventListener('click', preventFormSubmit, true);
  };
}, []);

  // Auto-hide notification after 3 seconds
  useEffect(() => {
    if (notification.message) {
      const timer = setTimeout(() => {
        setNotification({ message: '', type: '' });
      }, 3000);
      return () => clearTimeout(timer);
    }
  }, [notification]);

  return (
    <div className="container">
      {/* Notification */}
      {notification.message && (
        <div className={`notification ${notification.type}`}>
          {notification.message}
        </div>
      )}

      {/* Sidebar */}
      <div className={`sidebar ${sidebarOpen ? 'open' : ''}`}>
        <div className="sidebar-header">
          <h2>Security Analyzer</h2>
          <button type="button" className="close-sidebar" onClick={() => setSidebarOpen(false)}>×</button>
        </div>
        <div className="sidebar-content">
  {/* Upload */}
  <button 
    type="button"
    className="sidebar-item"
    onClick={() => document.getElementById('file-upload-input').click()}
    style={{background: 'none', border: 'none', width: '100%', textAlign: 'left', cursor: 'pointer'}}
  >
    <span className="sidebar-icon">📁</span>
    <span>Upload</span>
  </button>

  {/* CLI Commands */}
  <button 
    type="button"
    className="sidebar-item"
    onClick={() => setShowCli(true)}
    style={{background: 'none', border: 'none', width: '100%', textAlign: 'left', cursor: 'pointer'}}
  >
    <span className="sidebar-icon">💻</span>
    <span>CLI Commands</span>
  </button>

  {/* Download Reports */}
  <button 
    type="button"
    className="sidebar-item"
    onClick={() => setShowDownloadOptions(true)}
    style={{background: 'none', border: 'none', width: '100%', textAlign: 'left', cursor: 'pointer'}}
  >
    <span className="sidebar-icon">📥</span>
    <span>Download Reports</span>
  </button>
</div>
      </div>

      {/* Download Options Modal */}
      {showDownloadOptions && (
        <div className="modal-overlay" onClick={() => setShowDownloadOptions(false)}>
          <div className="modal-content" onClick={(e) => e.stopPropagation()}>
            <h3>Download Report</h3>
            <p>Select format to download:</p>
            <div className="download-options">
              <button type="button" className="download-option-btn" onClick={() => handleDownload("html")}>
                <span>📄</span> HTML
              </button>
              <button type="button" className="download-option-btn" onClick={() => handleDownload("json")}>
                <span>📝</span> JSON
              </button>
            </div>
            <button type="button" className="close-modal-btn" onClick={() => setShowDownloadOptions(false)}>
              Cancel
            </button>
          </div>
        </div>
      )}
      {/* Add this somewhere in your JSX */}

      {/* Add this somewhere in your JSX for debugging */}


      {/* Main Content */}
      <div className="main-content">
        {/* Header */}
        <div className="header">
          

          <div className="header-title">
            <h1>Security Analyzer</h1>
            <span className="file-info">
              {selectedFiles.length > 0
                ? `${selectedFiles.length} file${selectedFiles.length > 1 ? 's' : ''} selected`
                : 'No files selected'
              } <span className="scanned-badge">✓ Scanned</span>
            </span>
          </div>

          <div className="header-actions">
             <button 
      type="button" 
      className={`icon-btn ${isRefreshing ? 'refreshing' : ''}`} 
      title="Refresh" 
      onClick={(e) => {
        e.preventDefault();
        e.stopPropagation();
        handleRefresh();
      }}
    >
      <span>🔄</span>
      <span className="tooltip">Refresh</span>
    </button>
            <button type="button" className="icon-btn" title="CLI Commands" onClick={() => setShowCli(true)}>
              <span>💻</span>
              <span className="tooltip">CLI</span>
            </button>
            <button type="button" className="icon-btn" title={theme === "dark" ? "Switch to Light Mode" : "Switch to Dark Mode"} onClick={toggleTheme}>
              <span>{theme === "dark" ? "☀️" : "🌙"}</span>
              <span className="tooltip">{theme === "dark" ? "Light Mode" : "Dark Mode"}</span>
            </button>
            <input 
  type="file" 
  id="file-upload"
  onChange={handleFileSelect} 
  className="file-input" 
  multiple 
  onClick={(e) => {
    e.stopPropagation();
  }}
/>
          </div>
        </div>

        {/* CLI Modal */}
        {showCli && (
          <div className="modal-overlay" onClick={() => setShowCli(false)}>
            <div className="modal-content cli-modal" onClick={(e) => e.stopPropagation()}>
              <h3>CLI Commands</h3>
              <pre>
{`security-scanner scan --files ${selectedFiles.length > 0 ? selectedFiles.map(f => f.name).join(' ') : 'file1.js file2.py'}
security-scanner scan --dir ./src --format json
security-scanner scan --all --output report.html`}
              </pre>
              <button type="button" className="close-modal-btn" onClick={() => setShowCli(false)}>Close</button>
            </div>
          </div>
        )}

        {/* Dashboard Cards */}
        <div className="dashboard-cards">
          {/* Upload Card */}
          {/* Upload Card */}
{/* Upload Card */}
{/* Upload Card */}
{/* Upload Card */}
{/* Upload Card */}
{/* Upload Card */}
<div className="dashboard-card upload-card">
  <div className="card-header">
    <h2>Upload Files</h2>
    {selectedFiles.length > 0 && (
      <span className="file-count">{selectedFiles.length} files selected</span>
    )}
  </div>

  <div className="upload-section">
    <div className="upload-area">
      <div 
        className="drag-drop-zone"
        onClick={handleDropZoneClick}
        onDragEnter={handleDragEnter}
        onDragOver={handleDragOver}
        onDragLeave={handleDragLeave}
        onDrop={handleDrop}
      >
        <div className="drop-content">
          <span className="drop-icon">📁</span>
          <p>Drag and drop files/folders here or click to select</p>
          <p className="drop-zone-subtext">Supports .js, .php, .java, .py, and .zip files</p>
        </div>
        <input 
          type="file" 
          id="file-upload-input"
          onChange={handleFileSelect} 
          className="file-input" 
          multiple 
        />
      </div>
    </div>

    {selectedFiles.length > 0 && (
      <div className="selected-files-section">
        <div className="files-header">
          <h4>Selected Files</h4>
          <button 
            type="button"
            className="clear-all-btn"
            onClick={clearAllFiles}
          >
            Clear All
          </button>
        </div>
        
        <div className="files-list">
        
{selectedFiles.map((file, index) => (
  <FileItem 
    key={index}
    file={file}
    index={index}
    removeFile={removeFile}
    formatFileSize={formatFileSize}
  />
))}
        </div>
        
        {/* SINGLE SCAN BUTTON */}
        <div className="scan-actions">
          <button 
            type="button"
            className="scan-all-btn"
            onClick={handleFileUpload}
            disabled={isScanning || selectedFiles.length === 0}
          >
            {isScanning ? (
              <>
                <span className="scanning-spinner"></span>
                Scanning {scanProgress}%...
              </>
            ) : (
              <>
                <span className="scan-icon">🔍</span>
                Scan All Files
              </>
            )}
          </button>
          
          {isScanning && (
            <div className="progress-container">
              <div className="progress-bar">
                <div 
                  className="progress-fill" 
                  style={{width: `${scanProgress}%`}}
                ></div>
              </div>
              <span className="progress-text">{scanProgress}% complete</span>
            </div>
          )}
        </div>
      </div>
    )}

    {selectedFiles.length === 0 && (
      <div className="upload-status">
        <span className="status-text">Ready to scan</span>
        <button 
          type="button"
          className="choose-file-btn"
          onClick={() => document.getElementById('file-upload-input').click()}
        >
          Choose Files
        </button>
      </div>
    )}

    {uploadError && (
      <div className="error-message">
        <span>⚠️</span> {uploadError}
      </div>
    )}
  </div>
</div>
          {/* Results Card */}
          <div className="dashboard-card results-card">
            <div className="card-icon">📊</div>
            <h3>Results</h3>
            <div className="security-score">
              <div className="score-value" data-score-range={getScoreRange(securityScore)}>
                {securityScore}%
              </div>
              <div className="score-label">Security Score</div>
            </div>
            <div className="results-details">
              <div className="result-item">
                <span className="result-icon">🚨</span>
                <span className="result-value">{totalIssues}</span>
                <span className="result-label">Total Issues</span>
              </div>
              <div className="result-item">
                <span className="result-icon">📄</span>
                <span className="result-value">{selectedFiles.length}</span>
                <span className="result-label">Files Scanned</span>
              </div>
            </div>
          </div>

          {/* Download Card */}
          {/* Download Card */}
<div className="dashboard-card download-card">
  <div className="card-icon">📥</div>
  <h3>Download</h3>
  <p>Export comprehensive security reports in multiple formats</p>
  <div className="format-tags">
    <span className="format-tag">HTML</span>
    <span className="format-tag">JSON</span>
  </div>
  <div className="download-actions">
    <button 
      type="button"  // ← ADD THIS
      className="download-btn" 
      onClick={() => setShowDownloadOptions(true)}
    >
      Download Report
    </button>
  </div>
</div>
        </div>

        {/* Filters Section */}
         <div className="filters-section">
        <div className="filters-header">
          <h3>Filters</h3>
          <div>
            <button 
              type="button"
              className="filters-clear-btn" 
              onClick={clearFilters}
            >
              Clear Filters
            </button>
            
            <button 
              type="button"
              className="filters-clear-btn" 
              onClick={clearAllIssues}
            >
              Clear All Issues
            </button>
            
            <button 
              type="button"
              className="filters-toggle-btn" 
              onClick={() => setFiltersVisible(!filtersVisible)}
            >
              {filtersVisible ? "▲" : "▼"}
            </button>
          </div>
        </div>

        {filtersVisible && (
          <div className="filters-row">
            {/* Severity Filter */}
            <div className="filter-item">
              <label>Severity</label>
              <select 
                value={filters.severity} 
                onChange={(e) => setFilters({...filters, severity: e.target.value})}
              >
                {filterOptions.severities.map(severity => (
                  <option key={severity} value={severity}>
                    {severity === "ALL" ? "All Severity" : severity}
                  </option>
                ))}
              </select>
            </div>

            {/* OWASP Filter */}
            <div className="filter-item">
              <label>OWASP</label>
              <select 
                value={filters.owasp} 
                onChange={(e) => setFilters({...filters, owasp: e.target.value})}
              >
                {filterOptions.owaspCategories.map(owasp => (
                  <option key={owasp} value={owasp}>
                    {owasp === "ALL" ? "All OWASP" : getOwaspName(owasp)}
                  </option>
                ))}
              </select>
            </div>

            {/* CWE Filter */}
            <div className="filter-item">
              <label>CWE</label>
              <select 
                value={filters.cwe} 
                onChange={(e) => setFilters({...filters, cwe: e.target.value})}
              >
                {filterOptions.cweCategories.map(cwe => (
                  <option key={cwe} value={cwe}>
                    {cwe === "ALL" ? "All CWE" : cwe}
                  </option>
                ))}
              </select>
            </div>

            {/* File Type Filter */}
            <div className="filter-item">
              <label>File Type</label>
              <select 
                value={filters.fileType} 
                onChange={(e) => setFilters({...filters, fileType: e.target.value})}
              >
                {filterOptions.fileTypes.map(fileType => (
                  <option key={fileType} value={fileType}>
                    {fileType === "ALL" ? "All Files" : fileType}
                  </option>
                ))}
              </select>
            </div>

            {/* Search Filter (unchanged) */}
            <div className="filter-item search-item">
              <label>Search</label>
              <div className="search-input">
                <input
                  type="text"
                  placeholder="Search vulnerabilities..."
                  value={filters.search}
                  onChange={(e) => setFilters({...filters, search: e.target.value})}
                />
                <span>🔍</span>
              </div>
            </div>
          </div>
        )}
      </div>

        {/* Charts Section */}
        <div className="charts-section">
          {/* Severity Distribution */}
          <div className="chart-card">
            <h3>Severity Distribution</h3>
            <div className="chart-content enhanced-severity">
              <div className="donut-container">
                <ResponsiveContainer width="100%" height="100%">
  <PieChart>
    <Pie
      data={Object.entries(severityCounts)
        .filter(([_, value]) => value > 0)
        .map(([name, value]) => ({ name, value }))}
      dataKey="value"
      cx="50%"
      cy="50%"
      innerRadius={60}
      outerRadius={80}
      paddingAngle={2}
      startAngle={90}
      endAngle={-270}
      animationBegin={0}
      animationDuration={1000}
    >
      {Object.entries(severityCounts)
        .filter(([_, value]) => value > 0)
        .map(([name], index) => (
          <Cell
            key={`cell-${index}`}
            fill={SEVERITY_COLORS[name]?.chart || "#94a3b8"}
            stroke="#1e293b"
            strokeWidth={2}
          />
        ))}
    </Pie>
    <Tooltip
      formatter={(value, name) => [`${value} issues`, name]}
      contentStyle={{
        backgroundColor: '#1e293b',
        border: '1px solid #334155',
        borderRadius: '8px',
        color: '#ffffff', // Changed to white for better contrast
        fontSize: '14px',
        fontWeight: '500'
      }}
      itemStyle={{
        color: '#ffffff' // White text for individual items
      }}
      labelStyle={{
        color: '#f8fafc', // Light color for labels
        fontWeight: '600'
      }}
    />
  </PieChart>
</ResponsiveContainer>

                <div className="donut-center-text">
                  <div className="donut-total">{totalIssues}</div>
                  <div className="donut-label">Total Issues</div>
                </div>
              </div>

              <div className="severity-values-column">
                {Object.entries(severityCounts).map(([name, value]) => (
                  <div key={name} className="severity-value-item">
                    <div className="severity-indicator" style={{backgroundColor: SEVERITY_COLORS[name]?.chart || "#94a3b8"}}></div>
                    <div className="severity-info">
                      <div className="severity-name">{name}</div>
                      <div className="severity-count">{value} issue{value !== 1 ? 's' : ''}</div>
                    </div>
                    <div className="severity-percentage">
                      {totalIssues > 0 ? Math.round((value / totalIssues) * 100) : 0}%
                    </div>
                  </div>
                ))}
              </div>
            </div>
          </div>

          {/* OWASP Top 10 Vulnerabilities */}
          <div className="chart-card">
            <h3>OWASP Top 10 Vulnerabilities</h3>
            <div className="chart-content">
              {owaspChartData.length > 0 ? (
                <div className="owasp-chart">
                  {owaspChartData.map((item, index) => {
                    const maxValue = Math.max(...owaspChartData.map(i => i.count), 1);
                    const widthPercentage = chartAnimated ? (item.count / maxValue) * 100 : 0;

                    return (
                      <div
                        key={item.id}
                        className="owasp-bar-container"
                        onClick={() => handleBarClick(index)}
                      >
                        <div className="owasp-bar-info">
                          <div className="owasp-label">{item.name}</div>
                          <div className="owasp-value">{item.count} issues ({item.value}%)</div>
                        </div>
                        <div className="owasp-bar-track">
                          <div
                            className={`owasp-bar ${activeBar === index ? 'active' : ''}`}
                            style={{
                              width: `${widthPercentage}%`,
                              backgroundColor: item.color,
                              animationDelay: `${index * 0.15}s`
                            }}
                          >
                            <div className="owasp-bar-glow"></div>
                          </div>
                        </div>
                        {activeBar === index && (
                          <div className="owasp-description">
                            {item.description}
                          </div>
                        )}
                      </div>
                    );
                  })}
                </div>
              ) : (
                <div className="no-data-message">
                  No OWASP vulnerabilities found with current filters
                </div>
              )}
            </div>
          </div>
        </div>

        {/* Issues Table */}
        <div className="table-container">
          <h3>Security Vulnerabilities ({filteredIssues.length} issues)</h3>
          <table className="issues-table">
            <thead>
              <tr>
                <th width="40px"></th>
                <th>SEVERITY</th>
                <th>FILE</th>
                <th>LINE</th>
                <th>CATEGORY</th>
                <th>RULE</th>
                <th>MESSAGE</th>
                <th>DETECTED BY</th>
              </tr>
            </thead>
            <tbody>
               {filteredIssues.map((issue, index) => (
    <React.Fragment key={issue.uniqueId || index}>
                  <tr className={SEVERITY_COLORS[issue.severity]?.row || ""}>
                    <td>
                      <button
                      type="button"
                        className="expand-btn"
                        onClick={() => toggleRowExpansion(index)}
                      >
                        {expandedRows[index] ? "▼" : "►"}
                      </button>
                    </td>
                    <td><SeverityChip severity={issue.severity} /></td>
                    <td>{issue.file}</td>
                    <td>{issue.line}</td>
                    <td>{issue.category}</td>
                    <td>{issue.id}</td>
                    <td>{issue.message}</td>
                    <td>{issue.detected_by}</td>
                  </tr>
                  {expandedRows[index] && (
                    <tr className={`detail-row ${SEVERITY_COLORS[issue.severity]?.row || ""}`}>
                      <td colSpan="8">
                        <div className="issue-details">
                          <div className="detail-section">
                            <h4>Code Snippet:</h4>
                            <code>{issue.snippet}</code>
                          </div>
                          <div className="detail-section">
                            <h4>Suggestion:</h4>
                            <p>{issue.suggestion}</p>
                          </div>
                          <div className="detail-section">
                            <h4>OWASP:</h4>
                            <span className="security-tag">{issue.owasp}</span>
                          </div>
                          <div className="detail-section">
                            <h4>CWE:</h4>
                            <span className="security-tag">{issue.cwe}</span>
                          </div>
                        </div>
                      </td>
                    </tr>
                  )}
                </React.Fragment>
              ))}
            </tbody>
          </table>
        </div>

        {/* Enhanced Footer */}
        <footer className="app-footer">
            
          <div className="footer-bottom">
            <p>&copy; {new Date().getFullYear()} Security Analyzer. All rights reserved.</p>
          </div>
        </footer>
      </div>

      <style>{`
        * {
          margin: 0;
          padding: 0;
          box-sizing: border-box;
          font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', 'Roboto', sans-serif;
        }
           /* Additional styling for disabled filter options */
        .filter-item select option:disabled {
          color: #64748b;
          font-style: italic;
        }

        .filter-item select:empty::before {
          content: "No options available";
          color: #64748b;
        }

        /* Responsive adjustments for filters */
        @media (max-width: 1024px) {
          .filters-row {
            grid-template-columns: repeat(2, 1fr);
          }
          
          .search-item {
            grid-column: 1 / -1;
          }
        }

        @media (max-width: 640px) {
          .filters-row {
            grid-template-columns: 1fr;
          }
        }
        body {
          background-color: #0f172a;
          color: #e2e8f0;
          transition: background-color 0.3s ease;
        }
          .drop-zone-subtext {
  font-size: 0.75rem;
  color: #94a3b8;
  margin-top: 4px;
}

        body.light {
          background-color: #f8fafc;
          color: #1e293b;
        }

        .container {
          display: flex;
          min-height: 100vh;
        }

        /* Notification */
        .notification {
          position: fixed;
          top: 20px;
          right: 20px;
          padding: 12px 20px;
          border-radius: 8px;
          z-index: 1000;
          box-shadow: 0 4px 12px rgba(0, 0, 0, 0.15);
          animation: slideIn 0.3s ease;
        }

        .notification.success {
          background-color: #10b981;
          color: white;
        }

        .notification.error {
          background-color: #ef4444;
          color: white;
        }

        @keyframes slideIn {
          from { transform: translateX(100%); opacity: 0; }
          to { transform: translateX(0); opacity: 1; }
        }

        /* Sidebar */
        .sidebar {
          width: 280px;
          background-color: #1e293b;
          position: fixed;
          height: 100vh;
          left: -280px;
          transition: left 0.3s ease;
          z-index: 100;
          padding: 20px 0;
          box-shadow: 2px 0 10px rgba(0, 0, 0, 0.1);
        }

        .sidebar.open {
          left: 0;
        }

        .sidebar-header {
          display: flex;
          justify-content: space-between;
          align-items: center;
          padding: 0 20px 20px;
          border-bottom: 1px solid #334155;
        }

        .sidebar-header h2 {
          font-size: 1.5rem;
          font-weight: 600;
        }

        .close-sidebar {
          background: none;
          border: none;
          color: #94a3b8;
          font-size: 1.5rem;
          cursor: pointer;
        }

        .sidebar-content {
          padding: 20px 0;
        }

        .sidebar-item {
          display: flex;
          align-items: center;
          padding: 12px 20px;
          cursor: pointer;
          transition: background-color 0.2s;
        }

        .sidebar-item:hover {
          background-color: #334155;
        }

        .sidebar-icon {
          margin-right: 12px;
          font-size: 1.2rem;
        }

        /* Main Content */
        .main-content {
          flex: 1;
          padding: 0;
          transition: margin-left 0.3s ease;
        }

        /* Header */
        .header {
          display: flex;
          align-items: center;
          padding: 16px 24px;
          background-color: #1e293b;
          border-bottom: 1px solid #334155;
        }

        .menu-btn {
          background: none;
          border: none;
          color: #e2e8f0;
          font-size: 1.2rem;
          cursor: pointer;
          margin-right: 16px;
          padding: 8px;
          border-radius: 4px;
          transition: background-color 0.2s;
        }

        .menu-btn:hover {
          background-color: #334155;
        }

        .header-title {
          flex: 1;
        }

        .header-title h1 {
          font-size: 1.5rem;
          font-weight: 600;
          margin-bottom: 4px;
        }

        .file-info {
          font-size: 0.875rem;
          color: #94a3b8;
        }

        .scanned-badge {
          background-color: #10b981;
          color: white;
          padding: 2px 6px;
          border-radius: 4px;
          font-size: 0.75rem;
          margin-left: 8px;
        }

        .header-actions {
          display: flex;
          gap: 8px;
        }

        .icon-btn {
          background: none;
          border: none;
          color: #e2e8f0;
          font-size: 1.2rem;
          cursor: pointer;
          padding: 8px;
          border-radius: 4px;
          position: relative;
          transition: background-color 0.2s;
        }

        .icon-btn:hover {
          background-color: #334155;
        }

        .icon-btn.refreshing {
          animation: spin 1s linear infinite;
        }

        @keyframes spin {
          from { transform: rotate(0deg); }
          to { transform: rotate(360deg); }
        }

        .tooltip {
          position: absolute;
          bottom: -30px;
          left: 50%;
          transform: translateX(-50%);
          background-color: #1e293b;
          color: #e2e8f0;
          padding: 4px 8px;
          border-radius: 4px;
          font-size: 0.75rem;
          white-space: nowrap;
          opacity: 0;
          visibility: hidden;
          transition: opacity 0.2s, visibility 0.2s;
        }

        .icon-btn:hover .tooltip {
          opacity: 1;
          visibility: visible;
        }

        .file-input {
          display: none;
        }

        /* Dashboard Cards */
        .dashboard-cards {
          display: grid;
          grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
          gap: 24px;
          padding: 24px;
        }

        .dashboard-card {
          background-color: #1e293b;
          border-radius: 12px;
          padding: 24px;
          box-shadow: 0 4px 12px rgba(0, 0, 0, 0.1);
          transition: transform 0.2s, box-shadow 0.2s;
        }

        .dashboard-card:hover {
          transform: translateY(-4px);
          box-shadow: 0 8px 24px rgba(0, 0, 0, 0.15);
        }

        .card-icon {
          font-size: 2.5rem;
          margin-bottom: 16px;
        }

        .dashboard-card h3 {
          font-size: 1.25rem;
          font-weight: 600;
          margin-bottom: 12px;
        }

        .dashboard-card p {
          color: #94a3b8;
          margin-bottom: 20px;
          line-height: 1.5;
        }

        /* Upload Card */
        .upload-status {
          margin-bottom: 20px;
        }

        .scan-progress {
          display: flex;
          flex-direction: column;
          gap: 8px;
        }

        .progress-bar {
          height: 8px;
          background-color: #334155;
          border-radius: 4px;
          overflow: hidden;
        }

        .progress-fill {
          height: 100%;
          background-color: #06b6d4;
          border-radius: 4px;
          transition: width 0.3s ease;
        }

        .ready-text {
          color: #10b981;
          font-weight: 500;
        }

        .upload-btn {
          display: inline-block;
          background-color: #3b82f6;
          color: white;
          padding: 10px 16px;
          border-radius: 6px;
          cursor: pointer;
          transition: background-color 0.2s;
          margin-bottom: 12px;
          text-align: center;
        }

        .upload-btn:hover {
          background-color: #2563eb;
        }

        .scan-btn {
          display: block;
          width: 100%;
          background-color: #10b981;
          color: white;
          border: none;
          padding: 10px 16px;
          border-radius: 6px;
          cursor: pointer;
          transition: background-color 0.2s;
          margin-bottom: 8px;
          font-weight: 500;
        }

        .scan-btn:hover:not(:disabled) {
          background-color: #059669;
        }

        .scan-btn:disabled {
          background-color: #64748b;
          cursor: not-allowed;
        }

        .remove-all-btn {
          display: block;
          width: 100%;
          background: none;
          border: 1px solid #64748b;
          color: #94a3b8;
          padding: 10px 16px;
          border-radius: 6px;
          cursor: pointer;
          transition: background-color 0.2s;
        }

        .remove-all-btn:hover:not(:disabled) {
          background-color: #334155;
        }

        .remove-all-btn:disabled {
          opacity: 0.5;
          cursor: not-allowed;
        }

        .error-message {
          display: flex;
          align-items: center;
          gap: 8px;
          color: #ef4444;
          margin-top: 12px;
          font-size: 0.875rem;
        }

        /* Results Card */
        .results-card {
          display: flex;
          flex-direction: column;
        }

        .security-score {
          text-align: center;
          margin: 20px 0;
        }

        .score-value {
          font-size: 2.5rem;
          font-weight: 700;
          margin-bottom: 4px;
        }

        .score-value[data-score-range="excellent"] {
          color: #10b981;
        }

        .score-value[data-score-range="good"] {
          color: #84cc16;
        }

        .score-value[data-score-range="average"] {
          color: #f59e0b;
        }

        .score-value[data-score-range="poor"] {
          color: #ef4444;
        }

        .score-label {
          color: #94a3b8;
          font-size: 0.875rem;
        }

        .results-details {
          display: grid;
          grid-template-columns: 1fr 1fr;
          gap: 16px;
          margin-top: auto;
        }

        .result-item {
          text-align: center;
        }

        .result-icon {
          font-size: 1.5rem;
          display: block;
          margin-bottom: 4px;
        }

        .result-value {
          display: block;
          font-size: 1.5rem;
          font-weight: 600;
        }

        .result-label {
          display: block;
          color: #94a3b8;
          font-size: 0.875rem;
        }

        /* Download Card */
        .download-card {
          display: flex;
          flex-direction: column;
        }

        .format-tags {
          display: flex;
          gap: 8px;
          margin-bottom: 20px;
        }

        .format-tag {
          background-color: #334155;
          color: #e2e8f0;
          padding: 4px 8px;
          border-radius: 4px;
          font-size: 0.75rem;
        }

        .download-actions {
          margin-top: auto;
        }

        .download-btn {
          display: block;
          width: 100%;
          background-color: #8b5cf6;
          color: white;
          border: none;
          padding: 10px 16px;
          border-radius: 6px;
          cursor: pointer;
          transition: background-color 0.2s;
          font-weight: 500;
        }

        .download-btn:hover {
          background-color: #7c3aed;
        }

        /* Filters Section */
        .filters-section {
          padding: 0 24px;
          margin-bottom: 24px;
        }

        .filters-header {
          display: flex;
          justify-content: space-between;
          align-items: center;
          margin-bottom: 16px;
        }

        .filters-header h3 {
          font-size: 1.25rem;
          font-weight: 600;
        }

        .filters-clear-btn {
          background: none;
          border: none;
          color: #94a3b8;
          cursor: pointer;
          margin-right: 10px;
          font-size: 0.9rem;
          transition: color 0.2s;
        }

        .filters-clear-btn:hover {
          color: #e2e8f0;
        }

        .filters-toggle-btn {
          background: none;
          border: none;
          color: #94a3b8;
          cursor: pointer;
          font-size: 0.9rem;
          padding: 4px 8px;
          border-radius: 4px;
          transition: background-color 0.2s;
        }

        .filters-toggle-btn:hover {
          background-color: #334155;
        }

        .filters-row {
          display: grid;
          grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
          gap: 16px;
          background-color: #1e293b;
          padding: 20px;
          border-radius: 8px;
          box-shadow: 0 4px 12px rgba(0, 0, 0, 0.1);
        }

        .filter-item {
          display: flex;
          flex-direction: column;
          gap: 8px;
        }

        .filter-item label {
          font-size: 0.875rem;
          font-weight: 500;
          color: #94a3b8;
        }

        .filter-item select, .filter-item input {
          background-color: #334155;
          border: 1px solid #475569;
          border-radius: 6px;
          padding: 8px 12px;
          color: #e2e8f0;
          font-size: 0.875rem;
        }

        .filter-item select:focus, .filter-item input:focus {
          outline: none;
          border-color: #3b82f6;
        }

        .search-item {
          grid-column: 1 / -1;
        }

        .search-input {
          position: relative;
        }

        .search-input input {
          width: 100%;
          padding-left: 36px;
        }

        .search-input span {
          position: absolute;
          left: 12px;
          top: 50%;
          transform: translateY(-50%);
          color: #94a3b8;
        }

        /* Charts Section */
        .charts-section {
          display: grid;
          grid-template-columns: repeat(auto-fit, minmax(500px, 1fr));
          gap: 24px;
          padding: 0 24px;
          margin-bottom: 24px;
        }

        .chart-card {
          background-color: #1e293b;
          border-radius: 12px;
          padding: 24px;
          box-shadow: 0 4px 12px rgba(0, 0, 0, 0.1);
        }

        .chart-card h3 {
          font-size: 1.25rem;
          font-weight: 600;
          margin-bottom: 20px;
        }

        .chart-content {
          height: 300px;
        }

        .enhanced-severity {
          display: flex;
          gap: 24px;
        }

        .donut-container {
          position: relative;
          width: 200px;
          height: 200px;
          flex-shrink: 0;
        }

        .donut-center-text {
          position: absolute;
          top: 50%;
          left: 50%;
          transform: translate(-50%, -50%);
          text-align: center;
        }

        .donut-total {
          font-size: 2rem;
          font-weight: 700;
        }

        .donut-label {
          font-size: 0.875rem;
          color: #94a3b8;
        }

        .severity-values-column {
          flex: 1;
          display: flex;
          flex-direction: column;
          justify-content: center;
          gap: 12px;
        }

        .severity-value-item {
          display: flex;
          align-items: center;
          gap: 12px;
        }

        .severity-indicator {
          width: 12px;
          height: 12px;
          border-radius: 50%;
          flex-shrink: 0;
        }

        .severity-info {
          flex: 1;
        }

        .severity-name {
          font-size: 0.875rem;
          font-weight: 500;
        }

        .severity-count {
          font-size: 0.75rem;
          color: #94a3b8;
        }

        .severity-percentage {
          font-size: 0.875rem;
          font-weight: 600;
          color: #94a3b8;
        }

        /* OWASP Chart */
        .owasp-chart {
          display: flex;
          flex-direction: column;
          gap: 12px;
          height: 100%;
          overflow-y: auto;
        }

        .owasp-bar-container {
          cursor: pointer;
        }

        .owasp-bar-info {
          display: flex;
          justify-content: space-between;
          margin-bottom: 4px;
        }

        .owasp-label {
          font-size: 0.875rem;
          font-weight: 500;
        }

        .owasp-value {
          font-size: 0.75rem;
          color: #94a3b8;
        }

        .owasp-bar-track {
          height: 8px;
          background-color: #334155;
          border-radius: 4px;
          overflow: hidden;
          position: relative;
        }

        .owasp-bar {
          height: 100%;
          border-radius: 4px;
          position: relative;
          transition: width 0.5s ease;
        }

        .owasp-bar-glow {
          position: absolute;
          top: 0;
          left: 0;
          right: 0;
          bottom: 0;
          background: linear-gradient(90deg, transparent 0%, rgba(255,255,255,0.2) 50%, transparent 100%);
          animation: glow 2s infinite;
        }

        @keyframes glow {
          0% { transform: translateX(-100%); }
          100% { transform: translateX(100%); }
        }

        .owasp-description {
          font-size: 0.75rem;
          color: #94a3b8;
          margin-top: 4px;
          padding: 8px;
          background-color: #334155;
          border-radius: 4px;
        }

        .no-data-message {
          display: flex;
          align-items: center;
          justify-content: center;
          height: 100%;
          color: #94a3b8;
          font-style: italic;
        }

        /* Table */
        .table-container {
          padding: 0 24px;
          margin-bottom: 40px;
        }

        .table-container h3 {
          font-size: 1.25rem;
          font-weight: 600;
          margin-bottom: 16px;
        }

        .issues-table {
          width: 100%;
          border-collapse: collapse;
          background-color: #1e293b;
          border-radius: 8px;
          overflow: hidden;
          box-shadow: 0 4px 12px rgba(0, 0, 0, 0.1);
        }

        .issues-table th {
          background-color: #334155;
          padding: 12px 16px;
          text-align: left;
          font-size: 0.875rem;
          font-weight: 500;
          color: #94a3b8;
        }

        .issues-table td {
          padding: 12px 16px;
          border-bottom: 1px solid #334155;
          font-size: 0.875rem;
        }

        .issues-table tr:last-child td {
          border-bottom: none;
        }

        .expand-btn {
          background: none;
          border: none;
          color: #94a3b8;
          cursor: pointer;
          font-size: 0.75rem;
          padding: 4px;
        }

        .chip {
          display: inline-block;
          padding: 4px 8px;
          border-radius: 4px;
          font-size: 0.75rem;
          font-weight: 600;
          text-transform: uppercase;
        }

        .chip.critical {
          background-color: rgba(239, 68, 68, 0.2);
          color: #ef4444;
        }

        .chip.high {
          background-color: rgba(245, 158, 11, 0.2);
          color: #f59e0b;
        }

        .chip.medium {
          background-color: rgba(6, 182, 212, 0.2);
          color: #06b6d4;
        }

        .chip.low {
          background-color: rgba(16, 185, 129, 0.2);
          color: #10b981;
        }

        .chip.info {
          background-color: rgba(148, 163, 184, 0.2);
          color: #94a3b8;
        }

        .severity-critical {
          background-color: rgba(239, 68, 68, 0.05);
        }

        .severity-high {
          background-color: rgba(245, 158, 11, 0.05);
        }

        .severity-medium {
          background-color: rgba(6, 182, 212, 0.05);
        }

        .severity-low {
          background-color: rgba(16, 185, 129, 0.05);
        }

        .severity-info {
          background-color: rgba(148, 163, 184, 0.05);
        }

        .detail-row td {
          padding: 0;
        }

        .issue-details {
          padding: 16px;
          background-color: #1e293b;
        }

        .detail-section {
          margin-bottom: 16px;
        }

        .detail-section:last-child {
          margin-bottom: 0;
        }

        .detail-section h4 {
          font-size: 0.875rem;
          font-weight: 600;
          margin-bottom: 8px;
          color: #94a3b8;
        }

        .detail-section code {
          display: block;
          background-color: #334155;
          padding: 12px;
          border-radius: 4px;
          font-family: 'Fira Code', monospace;
          font-size: 0.75rem;
          overflow-x: auto;
        }

        .detail-section p {
          line-height: 1.5;
        }

        .security-tag {
          display: inline-block;
          background-color: #334155;
          color: #e2e8f0;
          padding: 4px 8px;
          border-radius: 4px;
          font-size: 0.75rem;
        }

        /* Footer */
        .app-footer {
          background-color: #1e293b;
          border-top: 1px solid #334155;
          padding: 24px;
        }

        .footer-content {
          display: flex;
          justify-content: space-between;
          align-items: center;
          margin-bottom: 16px;
        }

        .scan-info {
          display: flex;
          gap: 24px;
        }

        .info-item {
          display: flex;
          flex-direction: column;
          gap: 4px;
        }

        .info-label {
          font-size: 0.75rem;
          color: #94a3b8;
        }

        .info-value {
          font-size: 0.875rem;
          font-weight: 500;
        }

        .footer-meta {
          display: flex;
          gap: 8px;
          font-size: 0.75rem;
          color: #94a3b8;
        }

        .footer-bottom {
          text-align: center;
          padding-top: 16px;
          border-top: 1px solid #334155;
        }

        .footer-bottom p {
          font-size: 0.75rem;
          color: #94a3b8;
        }

        /* Modal */
        .modal-overlay {
          position: fixed;
          top: 0;
          left: 0;
          right: 0;
          bottom: 0;
          background-color: rgba(0, 0, 0, 0.5);
          display: flex;
          align-items: center;
          justify-content: center;
          z-index: 1000;
          padding: 20px;
        }

        .modal-content {
          background-color: #1e293b;
          border-radius: 12px;
          padding: 24px;
          max-width: 500px;
          width: 100%;
          box-shadow: 0 10px 25px rgba(0, 0, 0, 0.2);
        }

        .modal-content h3 {
          font-size: 1.5rem;
          font-weight: 600;
          margin-bottom: 16px;
        }

        .modal-content p {
          color: #94a3b8;
          margin-bottom: 20px;
        }

        .download-options {
          display: grid;
          grid-template-columns: 1fr 1fr;
          gap: 12px;
          margin-bottom: 20px;
        }

        .download-option-btn {
          display: flex;
          flex-direction: column;
          align-items: center;
          gap: 8px;
          background-color: #334155;
          border: none;
          border-radius: 8px;
          padding: 16px;
          color: #e2e8f0;
          cursor: pointer;
          transition: background-color 0.2s;
        }

        .download-option-btn:hover {
          background-color: #475569;
        }

        .download-option-btn span:first-child {
          font-size: 1.5rem;
        }

        .close-modal-btn {
          display: block;
          width: 100%;
          background: none;
          border: 1px solid #64748b;
          color: #94a3b8;
          padding: 10px 16px;
          border-radius: 6px;
          cursor: pointer;
          transition: background-color 0.2s;
        }

        .close-modal-btn:hover {
          background-color: #334155;
        }

        .cli-modal {
          max-width: 600px;
        }

        .cli-modal pre {
          background-color: #334155;
          padding: 16px;
          border-radius: 6px;
          overflow-x: auto;
          margin-bottom: 20px;
          font-size: 0.875rem;
          line-height: 1.5;
        }

        /* Light theme adjustments */
        body.light .sidebar,
        body.light .header,
        body.light .dashboard-card,
        body.light .chart-card,
        body.light .issues-table,
        body.light .app-footer,
        body.light .modal-content,
        body.light .filters-row,
        body.light .issue-details {
          background-color: #ffffff;
          color: #1e293b;
          border-color: #e2e8f0;
        }

        body.light .sidebar-header,
        body.light .issues-table th {
          background-color: #f1f5f9;
          border-color: #e2e8f0;
        }

        body.light .file-info,
        body.light .dashboard-card p,
        body.light .score-label,
        body.light .result-label,
        body.light .filters-header label,
        body.light .filter-item label,
        body.light .donut-label,
        body.light .severity-count,
        body.light .owasp-value,
        body.light .no-data-message,
        body.light .detail-section h4,
        body.light .info-label,
        body.light .footer-meta,
        body.light .footer-bottom p,
        body.light .modal-content p {
          color: #64748b;
        }

        body.light .filter-item select,
        body.light .filter-item input,
        body.light .detail-section code,
        body.light .security-tag,
        body.light .download-option-btn,
        body.light .cli-modal pre {
          background-color: #f1f5f9;
          color: #1e293b;
          border-color: #e2e8f0;
        }

        body.light .progress-bar,
        body.light .owasp-bar-track {
          background-color: #e2e8f0;
        }

        body.light .severity-critical { background-color: rgba(239, 68, 68, 0.05); }
        body.light .severity-high { background-color: rgba(245, 158, 11, 0.05); }
        body.light .severity-medium { background-color: rgba(6, 182, 212, 0.05); }
        body.light .severity-low { background-color: rgba(16, 185, 129, 0.05); }
        body.light .severity-info { background-color: rgba(148, 163, 184, 0.05); }

        /* Responsive Design */
        @media (max-width: 1024px) {
          .charts-section {
            grid-template-columns: 1fr;
          }

          .enhanced-severity {
            flex-direction: column;
            align-items: center;
          }

          .severity-values-column {
            width: 100%;
          }
        }

        @media (max-width: 768px) {
          .dashboard-cards {
            grid-template-columns: 1fr;
          }

          .filters-row {
            grid-template-columns: 1fr;
          }

          .scan-info {
            flex-direction: column;
            gap: 12px;
          }

          .footer-content {
            flex-direction: column;
            gap: 16px;
            align-items: flex-start;
          }

          .header {
            flex-wrap: wrap;
          }

          .header-title {
            order: 3;
            width: 100%;
            margin-top: 16px;
          }
        }

        @media (max-width: 640px) {
          .dashboard-cards,
          .charts-section,
          .filters-section,
          .table-container {
            padding: 0 16px;
          }

          .header {
            padding: 16px;
          }

          .modal-content {
            padding: 16px;
          }
        }
                  /* Drop Zone Styles */
        .drop-zone {
          border: 2px dashed #475569;
          border-radius: 8px;
          padding: 30px 20px;
          text-align: center;
          cursor: pointer;
          transition: all 0.3s ease;
          margin-bottom: 20px;
          background-color: rgba(51, 65, 85, 0.1);
        }

        .drop-zone.dragging {
          border-color: #3b82f6;
          background-color: rgba(59, 130, 246, 0.1);
          transform: scale(1.02);
        }

        .drop-zone-content {
          display: flex;
          flex-direction: column;
          align-items: center;
          gap: 12px;
        }

        .drop-zone-icon {
          font-size: 2.5rem;
          opacity: 0.7;
        }

        .drop-zone-text {
          font-weight: 500;
          color: #e2e8f0;
          margin: 0;
        }

        .drop-zone-subtext {
          font-size: 0.875rem;
          color: #94a3b8;
          margin: 0;
        }

        /* Selected files list */
        .selected-files-list ul {
          list-style: none;
          margin: 12px 0;
          max-height: 150px;
          overflow-y: auto;
        }

        .selected-files-list li {
          display: flex;
          justify-content: space-between;
          align-items: center;
          padding: 8px 12px;
          background-color: #334155;
          border-radius: 4px;
          margin-bottom: 8px;
          font-size: 0.875rem;
        }

        .remove-file-btn {
          background: none;
          border: none;
          color: #94a3b8;
          cursor: pointer;
          font-size: 1.2rem;
          padding: 0;
          width: 20px;
          height: 20px;
          display: flex;
          align-items: center;
          justify-content: center;
          border-radius: 50%;
        }

        .remove-file-btn:hover {
          background-color: #475569;
          color: #e2e8f0;
        }

        /* Light theme adjustments */
        body.light .drop-zone {
          border-color: #cbd5e1;
          background-color: rgba(241, 245, 249, 0.5);
        }

        body.light .drop-zone.dragging {
          border-color: #3b82f6;
          background-color: rgba(59, 130, 246, 0.1);
        }

        body.light .drop-zone-text {
          color: #1e293b;
        }

        body.light .selected-files-list li {
          background-color: #f1f5f9;
        }
          /* Upload Card Header */
.card-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 20px;
  padding-bottom: 15px;
  border-bottom: 1px solid #334155;
}

.card-header h2 {
  font-size: 1.5rem;
  font-weight: 600;
  margin: 0;
}

.file-name {
  color: #3b82f6;
  font-weight: 500;
  background: rgba(59, 130, 246, 0.1);
  padding: 4px 8px;
  border-radius: 4px;
  font-size: 0.875rem;
}

/* Upload Section */
.upload-section h3 {
  font-size: 1.1rem;
  font-weight: 600;
  margin-bottom: 15px;
  color: #e2e8f0;
}

.drag-drop-zone {
  border: 2px dashed #475569;
  border-radius: 8px;
  padding: 30px 20px;
  text-align: center;
  transition: all 0.3s ease;
  cursor: pointer;
  margin-bottom: 20px;
  background: rgba(71, 85, 105, 0.1);
}

.drag-drop-zone:hover {
  border-color: #3b82f6;
  background: rgba(59, 130, 246, 0.05);
}

.drag-drop-zone.dragging {
  border-color: #3b82f6;
  background: rgba(59, 130, 246, 0.1);
}

.drop-content {
  display: flex;
  flex-direction: column;
  align-items: center;
  gap: 12px;
}

.drop-icon {
  font-size: 2rem;
  opacity: 0.7;
}

/* Selected Files Section */
.selected-files-section {
  margin-bottom: 20px;
}

.file-item {
  display: flex;
  align-items: center;
  gap: 12px;
  padding: 12px;
  background: #334155;
  border-radius: 6px;
  margin-bottom: 8px;
}

.file-icon {
  font-size: 1.2rem;
}

.file-name {
  flex: 1;
  font-weight: 500;
}

.file-actions {
  display: flex;
  gap: 8px;
}

.action-btn {
  padding: 6px 12px;
  border: 1px solid #475569;
  background: #1e293b;
  color: #e2e8f0;
  border-radius: 4px;
  cursor: pointer;
  font-size: 0.75rem;
  transition: all 0.2s;
}

.action-btn:hover {
  background: #374151;
}

.action-btn.scan-btn {
  background: #10b981;
  border-color: #10b981;
  color: white;
}

.action-btn.scan-btn:hover:not(:disabled) {
  background: #059669;
}

.action-btn.scan-btn:disabled {
  background: #64748b;
  cursor: not-allowed;
}

/* Upload Status Section */
.upload-status-section {
  margin-top: 20px;
}

.status-divider {
  height: 1px;
  background: #334155;
  margin: 20px 0;
}

.upload-status {
  display: flex;
  justify-content: space-between;
  align-items: center;
}

.status-text {
  color: #94a3b8;
  font-weight: 500;
}

.choose-file-btn {
  padding: 8px 16px;
  background: #3b82f6;
  color: white;
  border: none;
  border-radius: 6px;
  cursor: pointer;
  font-weight: 500;
  transition: background-color 0.2s;
}

.choose-file-btn:hover {
  background: #2563eb;
}

/* Compact Filters */
.filters-section.compact {
  margin-top: 20px;
  padding-top: 20px;
  border-top: 1px solid #334155;
}

.filters-section.compact h3 {
  font-size: 1.1rem;
  font-weight: 600;
  margin-bottom: 15px;
  color: #e2e8f0;
}

.compact-filters {
  display: grid;
  grid-template-columns: 1fr 2fr;
  gap: 16px;
}

/* Light theme adjustments */
body.light .card-header {
  border-bottom-color: #e2e8f0;
}

body.light .file-name {
  background: rgba(59, 130, 246, 0.1);
  color: #2563eb;
}

body.light .drag-drop-zone {
  border-color: #e2e8f0;
  background: rgba(241, 245, 249, 0.5);
}

body.light .drag-drop-zone:hover {
  border-color: #3b82f6;
  background: rgba(59, 130, 246, 0.05);
}

body.light .file-item {
  background: #f1f5f9;
}

body.light .action-btn {
  background: white;
  border-color: #e2e8f0;
  color: #1e293b;
}

body.light .action-btn:hover {
  background: #f8fafc;
}

body.light .status-divider {
  background: #e2e8f0;
}

body.light .filters-section.compact {
  border-top-color: #e2e8f0;
}

/* Responsive adjustments */
@media (max-width: 768px) {
  .card-header {
    flex-direction: column;
    align-items: flex-start;
    gap: 10px;
  }
  
  .compact-filters {
    grid-template-columns: 1fr;
  }
  
  .file-item {
    flex-direction: column;
    align-items: flex-start;
    gap: 8px;
  }
  
  .file-actions {
    width: 100%;
    justify-content: space-between;
  }
  
  .upload-status {
    flex-direction: column;
    gap: 12px;
    align-items: flex-start;
  }
  
  .choose-file-btn {
    width: 100%;
    text-align: center;
  }
}

@media (max-width: 480px) {
  .file-actions {
    flex-direction: column;
  }
  
  .action-btn {
    width: 100%;
  }
}
  /* File items and list */
.files-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 12px;
  padding-bottom: 8px;
  border-bottom: 1px solid #334155;
}

.files-header h4 {
  margin: 0;
  font-size: 1rem;
  font-weight: 600;
}

.clear-all-btn {
  background: none;
  border: none;
  color: #ef4444;
  cursor: pointer;
  font-size: 0.875rem;
  padding: 4px 8px;
  border-radius: 4px;
  transition: background-color 0.2s;
}

.clear-all-btn:hover {
  background-color: rgba(239, 68, 68, 0.1);
}

.files-list {
  max-height: 200px;
  overflow-y: auto;
  margin-bottom: 20px;
  border: 1px solid #334155;
  border-radius: 8px;
  padding: 8px;
}

.file-item {
  display: flex;
  align-items: center;
  gap: 8px;
  padding: 8px;
  background: #334155;
  border-radius: 4px;
  margin-bottom: 6px;
  font-size: 0.875rem;
}

.file-item:last-child {
  margin-bottom: 0;
}

.file-icon {
  font-size: 1rem;
}

.file-name {
  flex: 1;
  font-weight: 500;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.file-size {
  color: #94a3b8;
  font-size: 0.75rem;
}

.remove-file-btn {
  background: none;
  border: none;
  color: #94a3b8;
  cursor: pointer;
  font-size: 1.2rem;
  padding: 0;
  width: 20px;
  height: 20px;
  display: flex;
  align-items: center;
  justify-content: center;
  border-radius: 50%;
  transition: all 0.2s;
}

.remove-file-btn:hover {
  background-color: #475569;
  color: #e2e8f0;
}

/* Scan button */
.scan-actions {
  margin-top: 20px;
  padding-top: 20px;
  border-top: 1px solid #334155;
}

.scan-all-btn {
  display: flex;
  align-items: center;
  justify-content: center;
  gap: 8px;
  width: 100%;
  background: linear-gradient(135deg, #10b981, #059669);
  color: white;
  border: none;
  padding: 12px 20px;
  border-radius: 8px;
  cursor: pointer;
  font-weight: 600;
  font-size: 1rem;
  transition: all 0.3s ease;
  box-shadow: 0 4px 6px rgba(16, 185, 129, 0.2);
}

.scan-all-btn:hover:not(:disabled) {
  background: linear-gradient(135deg, #059669, #047857);
  transform: translateY(-2px);
  box-shadow: 0 6px 12px rgba(16, 185, 129, 0.3);
}

.scan-all-btn:disabled {
  background: #64748b;
  cursor: not-allowed;
  transform: none;
  box-shadow: none;
}

.scan-icon {
  font-size: 1.2rem;
}

/* Progress bar */
.progress-container {
  margin-top: 12px;
}

.progress-bar {
  height: 8px;
  background-color: #334155;
  border-radius: 4px;
  overflow: hidden;
  margin-bottom: 8px;
}

.progress-fill {
  height: 100%;
  background: linear-gradient(90deg, #06b6d4, #3b82f6);
  border-radius: 4px;
  transition: width 0.3s ease;
  box-shadow: 0 0 8px rgba(59, 130, 246, 0.4);
}

.progress-text {
  font-size: 0.75rem;
  color: #94a3b8;
  text-align: center;
  display: block;
}

/* Scanning spinner */
.scanning-spinner {
  width: 16px;
  height: 16px;
  border: 2px solid rgba(255, 255, 255, 0.3);
  border-radius: 50%;
  border-top-color: white;
  animation: spin 1s linear infinite;
}

@keyframes spin {
  to {
    transform: rotate(360deg);
  }
}

/* Light theme adjustments */
body.light .files-header {
  border-bottom-color: #e2e8f0;
}

body.light .files-list {
  border-color: #e2e8f0;
}

body.light .file-item {
  background: #f1f5f9;
}

body.light .remove-file-btn:hover {
  background-color: #e2e8f0;
}

body.light .scan-actions {
  border-top-color: #e2e8f0;
}

body.light .progress-bar {
  background-color: #e2e8f0;
}
  /* ZIP file specific styles */
.toggle-zip-btn {
  background: none;
  border: none;
  color: #3b82f6;
  cursor: pointer;
  font-size: 0.75rem;
  padding: 2px 6px;
  border-radius: 3px;
  margin-left: 8px;
}

.toggle-zip-btn:hover {
  background-color: rgba(59, 130, 246, 0.1);
}

.zip-contents {
  margin-top: 8px;
  padding: 8px;
  background-color: #334155;
  border-radius: 4px;
  border-left: 3px solid #3b82f6;
}

.zip-contents-header {
  font-size: 0.75rem;
  color: #94a3b8;
  margin-bottom: 6px;
  font-weight: 500;
}

.zip-files-list {
  max-height: 120px;
  overflow-y: auto;
}

.zip-file-item {
  display: flex;
  align-items: center;
  gap: 6px;
  padding: 4px;
  font-size: 0.75rem;
}

.zip-file-icon {
  font-size: 0.875rem;
}

.zip-file-name {
  color: #e2e8f0;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.zip-more-files {
  font-size: 0.7rem;
  color: #94a3b8;
  font-style: italic;
  padding: 4px;
}

/* Light theme adjustments */
body.light .zip-contents {
  background-color: #f1f5f9;
  border-left-color: #3b82f6;
}

body.light .zip-file-name {
  color: #1e293b;
}
      `}</style>
    </div>
  );
}


export default App;
