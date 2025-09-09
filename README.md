# Secure Code Analyzer

A comprehensive security vulnerability scanner for web applications that analyzes JavaScript, PHP, Python, and Java code for common security issues.

## 🚀 Features

- **Multi-Language Support**: Scan JavaScript, PHP, Python, and Java files
- **ZIP Archive Support**: Upload and scan entire ZIP archives containing multiple files
- **Real-time Scanning**: Fast AST-based vulnerability detection
- **Interactive Dashboard**: Modern React frontend with filtering and visualization
- **Comprehensive Reports**: Generate detailed JSON and HTML security reports
- **OWASP Top 10 Coverage**: Detect vulnerabilities aligned with OWASP standards
- **Severity Classification**: Issues categorized as Critical, High, Medium, and Low
- **File Type Detection**: Automatic language detection and appropriate scanning
- **Dark/Light Theme**: User-friendly interface with theme switching

## 🛠️ Technology Stack

### Backend

- **Python 3.8+**
- **Flask** - Web framework
- **Flask-CORS** - Cross-origin resource sharing
- **AST Parsing** - Abstract syntax tree analysis for multiple languages
- **Jinja2** - Template engine for HTML reports

### Frontend

- **React 18** - User interface framework
- **Recharts** - Data visualization library
- **Material-UI** - Component library
- **Axios** - HTTP client for API communication
- **JSZip** - ZIP file handling

## 📋 Prerequisites

- Python 3.8 or higher
- Node.js 16 or higher
- npm or yarn package manager
- Git

## 🚀 Quick Start

### Local Development Setup

1. **Clone the repository**

   ```bash
   git clone https://github.com/Pravinkumarg18/My-secure-code-analyzer.git
   cd My-secure-code-analyzer
   ```

2. **Backend Setup**

   ```bash
   # Install Python dependencies
   pip install -r requirements.txt

   # Run the Flask server
   python src/secure_code_analyzer/cli.py --serve
   ```

3. **Frontend Setup**

   ```bash
   cd secure-code-analyzer-frontend

   # Install Node.js dependencies
   npm install

   # Start the development server
   npm start
   ```

4. **Access the Application**
   - Frontend: http://localhost:3000
   - Backend API: http://localhost:5000

## 📖 Usage

### CLI Mode

```bash
# Scan individual files
python src/secure_code_analyzer/cli.py file1.js file2.php

# Scan directories
python src/secure_code_analyzer/cli.py --dir ./src

# Scan with custom output format
python src/secure_code_analyzer/cli.py --files *.js --format json
```

### Web Interface

1. Open http://localhost:3000 in your browser
2. Upload files or ZIP archives containing source code
3. Click "Scan All Files" to start analysis
4. View results in the interactive dashboard
5. Filter by severity, OWASP category, or file type
6. Download detailed reports in HTML or JSON format

## 🔍 Supported File Types

- **JavaScript**: `.js`, `.jsx`
- **PHP**: `.php`
- **Python**: `.py`
- **Java**: `.java`
- **Archives**: `.zip` (containing any of the above)

## 🛡️ Security Checks

The analyzer detects various security vulnerabilities including:

### OWASP Top 10 Coverage

- **A01: Broken Access Control**
- **A02: Cryptographic Failures**
- **A03: Injection** (SQL, NoSQL, OS command injection)
- **A04: Insecure Design**
- **A05: Security Misconfiguration**
- **A06: Vulnerable Components**
- **A07: Authentication Failures**
- **A08: Software Integrity Failures**
- **A09: Logging & Monitoring Failures**
- **A10: Server-Side Request Forgery**

### Language-Specific Checks

- **JavaScript**: XSS vulnerabilities, insecure eval usage, prototype pollution
- **PHP**: SQL injection, file inclusion vulnerabilities, insecure functions
- **Python**: Command injection, pickle deserialization, insecure imports
- **Java**: SQL injection, XSS, insecure deserialization

## 📊 Report Formats

### JSON Report

```json
{
  "issues": [
    {
      "file": "example.js",
      "line": 15,
      "severity": "HIGH",
      "message": "Potential XSS vulnerability",
      "category": "Cross-Site Scripting",
      "owasp": "A03",
      "cwe": "CWE-79",
      "suggestion": "Use proper output encoding"
    }
  ],
  "count": 1,
  "files_processed": 1
}
```

### HTML Report

- Interactive web-based report
- Severity distribution charts
- OWASP category breakdown
- Detailed vulnerability descriptions
- Code snippets with highlighted issues

## 🔧 Configuration

### Backend Configuration

- **Port**: Configurable via `PORT` environment variable (default: 5000)
- **Reports Directory**: `./reports/` (auto-created)
- **Uploads Directory**: `./uploads/` (auto-created)

### Frontend Configuration

- **API Base URL**: Configurable via `REACT_APP_API_URL` environment variable
- **Default**: `http://localhost:5000`

## 🚀 Deployment

### Backend Deployment (Render.com)

1. Push code to GitHub
2. Connect repository to Render.com
3. Render automatically detects `render.yaml`
4. Deploy with one click

### Frontend Deployment (Vercel)

1. Build the React app: `npm run build`
2. Set `REACT_APP_API_URL` environment variable
3. Deploy to Vercel with Git integration

## 🧪 Testing

### Backend Testing

```bash
# Run with test files
python src/secure_code_analyzer/cli.py test_vulnerable.js

# API endpoint testing
curl -X POST http://localhost:5000/scan \
  -F "files=@test_file.js"
```

### Frontend Testing

```bash
cd secure-code-analyzer-frontend
npm test
```

## 📁 Project Structure

```
My-secure-code-analyzer/
├── src/
│   └── secure_code_analyzer/
│       ├── cli.py                 # Main CLI and server entry point
│       ├── core/
│       │   ├── scanner.py         # Core scanning logic
│       │   ├── detectors.py       # Vulnerability detection rules
│       │   ├── reporters.py       # Report generation
│       │   ├── severity.py        # Severity classification
│       │   └── utils.py           # Utility functions
│       └── rules/                 # Language-specific rules
├── secure-code-analyzer-frontend/
│   ├── src/
│   │   ├── App.js                # Main React component
│   │   ├── config.js             # API configuration
│   │   └── components/           # React components
│   ├── package.json
│   └── public/
├── requirements.txt               # Python dependencies
├── render.yaml                   # Render deployment config
├── package.json                  # Root package config
└── README.md
```

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/new-feature`
3. Commit changes: `git commit -am 'Add new feature'`
4. Push to branch: `git push origin feature/new-feature`
5. Submit a pull request

## 📝 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 🙏 Acknowledgments

- OWASP for security standards and guidelines
- Open source AST parsing libraries
- React and Flask communities

## 📞 Support

For questions or issues:

- Create an issue on GitHub
- Check the documentation
- Review existing issues for similar problems

---

**Happy Secure Coding! 🔒**
