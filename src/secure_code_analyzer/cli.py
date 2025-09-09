import argparse
import os
import sys
import zipfile
import shutil
import tempfile
import uuid
import re
import time

from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
from secure_code_analyzer.core.scanner import scan_file
from secure_code_analyzer.core.reporters import (
    generate_json_report,
    generate_html_report,
)

# Default reports directory
REPORTS_DIR = os.path.abspath("reports")
UPLOADS_DIR = os.path.abspath("uploads")

# Supported file extensions
SUPPORTED_EXTENSIONS = (".js", ".php", ".py", ".java")

# File size limits (for Render free tier)
MAX_FILE_SIZE = 15 * 1024 * 1024  # 15MB per file
MAX_CONTENT_LENGTH = 30 * 1024 * 1024  # 30MB total request size
MAX_ZIP_EXTRACTION_SIZE = 50 * 1024 * 1024  # 50MB max extraction size


def collect_files(paths):
    """
    Collect all supported files (.js, .php, .py, .java) from given paths.
    Supports both individual files and directories.
    """
    files = []
    for path in paths:
        if os.path.isfile(path):
            if path.endswith(SUPPORTED_EXTENSIONS):
                files.append(path)
        elif os.path.isdir(path):
            for root, _, filenames in os.walk(path):
                for fname in filenames:
                    if fname.endswith(SUPPORTED_EXTENSIONS):
                        files.append(os.path.join(root, fname))
        else:
            print(f"[WARNING] {path} does not exist, skipping.")
    return files


def run_scan(files_to_scan, detailed_output=False):
    """Run scan on given files and return list of issues."""
    all_issues = []
    for file in files_to_scan:
        try:
            issues = scan_file(file)
            if issues:
                # Deduplicate per file - keep first occurrence for CLI, all for reports
                seen = {}
                deduped_issues = []
                
                for issue in issues:
                    key = (issue["message"], issue["file"])
                    if key not in seen:
                        # For CLI, we'll just show the first occurrence
                        simplified_issue = issue.copy()
                        if not detailed_output:
                            simplified_issue["lines"] = [issue.get("line", 0)]
                        else:
                            # For reports, track all lines
                            simplified_issue["lines"] = [issue.get("line", 0)]
                        seen[key] = simplified_issue
                        deduped_issues.append(simplified_issue)
                    elif detailed_output:
                        # For reports, add line numbers to existing issue
                        seen[key]["lines"].append(issue.get("line", 0))

                if detailed_output:
                    print(f"\nFound {len(deduped_issues)} unique issues in {file}:")
                    for issue in deduped_issues:
                        line_info = ", ".join(map(str, sorted(issue["lines"])))
                        print(
                            f"  [{issue['severity']}] {issue['file']}:{line_info} - {issue['message']}"
                        )
                else:
                    print(f"\nFound {len(deduped_issues)} issues in {file}:")
                    for issue in deduped_issues:
                        print(
                            f"  [{issue['severity']}] {issue['file']}:{issue['lines'][0]} - {issue['message']}"
                        )

                all_issues.extend(deduped_issues)
            else:
                print(f"\nNo issues found in {file}")
        except Exception as e:
            print(f"\n[ERROR] Could not scan {file}: {e}")
            error_issue = {
                "severity": "LOW",
                "file": file,
                "line": 0,
                "message": f"Error reading file: {e}",
                "lines": [0]
            }
            all_issues.append(error_issue)
            print(f"  [LOW] {file}:0 - Error reading file: {e}")
    return all_issues


def cli_mode(args):
    """Run in classic CLI mode."""
    files_to_scan = collect_files(args.targets)
    if not files_to_scan:
        print(f"❌ No {', '.join(SUPPORTED_EXTENSIONS)} files found to scan.")
        sys.exit(1)

    print(f"\n🔍 Scanning {len(files_to_scan)} files...")
    all_issues = run_scan(files_to_scan, detailed_output=False)

    print("\n" + "="*50)
    print("📊 SCAN COMPLETE")
    print("="*50)
    
    # Count issues by severity
    severity_count = {"HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for issue in all_issues:
        severity_count[issue["severity"]] += 1
    
    print(f"📁 Files Scanned: {len(files_to_scan)}")
    print(f"🚨 Total Issues: {len(all_issues)}")
    print(f"   🔴 HIGH: {severity_count['HIGH']}")
    print(f"   🟡 MEDIUM: {severity_count['MEDIUM']}")  
    print(f"   🔵 LOW: {severity_count['LOW']}")
    print("="*50)

    if all_issues:
        # For reports, we want detailed information with all line numbers
        detailed_issues = []
        seen = {}
        for issue in all_issues:
            key = (issue["message"], issue["file"])
            if key not in seen:
                detailed_issue = issue.copy()
                detailed_issue["lines"] = issue.get("lines", [issue.get("line", 0)])
                seen[key] = detailed_issue
                detailed_issues.append(detailed_issue)
            else:
                # Add line numbers to existing issue
                seen[key]["lines"].extend(issue.get("lines", [issue.get("line", 0)]))
                seen[key]["lines"] = sorted(set(seen[key]["lines"]))  # Remove duplicates
        
        # Save reports with detailed information
        os.makedirs(REPORTS_DIR, exist_ok=True)
        json_path = os.path.join(REPORTS_DIR, "report.json")
        html_path = os.path.join(REPORTS_DIR, "report.html")
        generate_json_report(detailed_issues, json_path)
        generate_html_report(detailed_issues, html_path)
        print(f"📄 JSON report saved to {json_path}")
        print(f"📄 HTML report saved to {html_path}")
        
        if severity_count['HIGH'] > 0:
            print("\n❌ Scan completed with critical issues!")
            sys.exit(1)
        else:
            print("\n✅ Scan completed successfully!")
    else:
        print("\n✅ No security issues found!")


def serve_mode():
    """Run Flask server for frontend integration."""
    app = Flask(__name__)

    # Configure file size limits
    app.config['MAX_CONTENT_LENGTH'] = MAX_CONTENT_LENGTH

    # CORS configuration
    CORS(app, origins=[
        "https://final-commit-1.vercel.app",
        "http://localhost:3000",
        "http://localhost:3001"
    ], supports_credentials=True)

    # Error handlers for file size limits
    @app.errorhandler(413)
    def too_large(e):
        return jsonify({"error": f"File too large. Maximum upload size is {MAX_FILE_SIZE//1024//1024}MB per file"}), 413

    @app.errorhandler(500)
    def internal_error(e):
        return jsonify({"error": "Internal server error. Please try again with smaller files."}), 500

    @app.before_request
    def check_file_size():
        """Check file size before processing the request."""
        if request.method == 'POST' and request.content_length:
            if request.content_length > MAX_CONTENT_LENGTH:
                return jsonify({
                    "error": f"Request too large. Maximum total upload size is {MAX_CONTENT_LENGTH//1024//1024}MB"
                }), 413
    
    @app.route("/scan", methods=["POST", "OPTIONS"])
    def scan_endpoint():
        """
        Upload and scan files via API.
        Expects files in multipart form-data.
        """
        try:
            # Handle preflight OPTIONS request
            if request.method == "OPTIONS":
                return jsonify({"status": "preflight"}), 200
                
            print("=== SCAN REQUEST RECEIVED ===")
            start_time = time.time()
            
            if "files" not in request.files:
                return jsonify({"error": "No files uploaded"}), 400

            uploaded_files = request.files.getlist("files")
            if not uploaded_files or all(f.filename == '' for f in uploaded_files):
                return jsonify({"error": "No valid files uploaded"}), 400

            # Check individual file sizes
            for f in uploaded_files:
                if f.filename and f.filename != '':  # Only check files with names
                    # Save to temp file to check size
                    temp_dir = tempfile.mkdtemp()
                    temp_path = os.path.join(temp_dir, f.filename)
                    try:
                        f.save(temp_path)
                        file_size = os.path.getsize(temp_path)
                        
                        if file_size > MAX_FILE_SIZE:
                            return jsonify({
                                "error": f"File '{f.filename}' is too large ({file_size//1024//1024}MB). Maximum size is {MAX_FILE_SIZE//1024//1024}MB per file."
                            }), 413
                    finally:
                        # Clean up temp file
                        try:
                            os.remove(temp_path)
                            os.rmdir(temp_dir)
                        except:
                            pass
            
            filepaths = []
            file_mapping = {}  # Map temporary names to original names
            total_extracted_size = 0
            
            # Create uploads directory if it doesn't exist
            os.makedirs(UPLOADS_DIR, exist_ok=True)
                
            for f in uploaded_files:
                if f.filename == '':
                    continue
                    
                original_filename = f.filename
                print(f"Processing file: {original_filename}")
                
                # Normalize path to prevent directory traversal attacks
                safe_path = os.path.normpath(original_filename)
                if safe_path.startswith("..") or os.path.isabs(safe_path):
                    print(f"Rejected unsafe filename: {original_filename}")
                    continue

                if safe_path.lower().endswith(".zip"):
                    # Extract ZIP safely while preserving original structure
                    try:
                        print(f"Extracting ZIP: {original_filename}")
                        
                        # Check ZIP file size first
                        temp_zip = tempfile.NamedTemporaryFile(delete=False)
                        f.save(temp_zip.name)
                        zip_size = os.path.getsize(temp_zip.name)
                        
                        if zip_size > MAX_FILE_SIZE:
                            os.unlink(temp_zip.name)
                            return jsonify({
                                "error": f"ZIP file '{original_filename}' is too large ({zip_size//1024//1024}MB). Maximum size is {MAX_FILE_SIZE//1024//1024}MB."
                            }), 413
                        
                        with zipfile.ZipFile(temp_zip.name) as zip_ref:
                            zip_files = zip_ref.namelist()
                            print(f"ZIP contains {len(zip_files)} files")
                            
                            for member in zip_files:
                                if total_extracted_size > MAX_ZIP_EXTRACTION_SIZE:
                                    raise ValueError(f"ZIP extraction exceeded maximum size limit of {MAX_ZIP_EXTRACTION_SIZE//1024//1024}MB")
                                    
                                member_path = os.path.normpath(member)
                                if member_path.startswith("..") or os.path.isabs(member_path):
                                    print(f"Skipping unsafe path in ZIP: {member}")
                                    continue
                                    
                                # Skip directories
                                if member.endswith('/'):
                                    continue
                                    
                                # Only process supported file types
                                if any(member_path.endswith(ext) for ext in SUPPORTED_EXTENSIONS):
                                    # Create a unique directory for this ZIP's contents
                                    zip_base_name = os.path.splitext(original_filename)[0]
                                    safe_zip_dir = re.sub(r'[^a-zA-Z0-9_]', '_', zip_base_name)
                                    target_dir = os.path.join(UPLOADS_DIR, f"zip_{safe_zip_dir}_{uuid.uuid4().hex[:8]}")
                                    os.makedirs(target_dir, exist_ok=True)
                                    
                                    # Preserve original path structure within the ZIP
                                    target_path = os.path.join(target_dir, member_path)
                                    os.makedirs(os.path.dirname(target_path), exist_ok=True)
                                    
                                    # Extract file and track size
                                    with zip_ref.open(member) as source, open(target_path, "wb") as target:
                                        content = source.read()
                                        total_extracted_size += len(content)
                                        if total_extracted_size > MAX_ZIP_EXTRACTION_SIZE:
                                            raise ValueError(f"ZIP extraction exceeded maximum size limit of {MAX_ZIP_EXTRACTION_SIZE//1024//1024}MB")
                                        target.write(content)
                                    
                                    # Store mapping with original ZIP name + internal path
                                    original_name_in_zip = f"{original_filename}/{member_path}"
                                    file_mapping[target_path] = original_name_in_zip
                                    filepaths.append(target_path)
                                    print(f"Extracted: {member_path} ({len(content)//1024}KB)")
                        
                        os.unlink(temp_zip.name)
                                
                    except Exception as e:
                        print(f"ZIP extraction failed: {e}")
                        # Clean up any extracted files
                        for filepath in filepaths:
                            try:
                                os.remove(filepath)
                                dir_path = os.path.dirname(filepath)
                                if os.path.exists(dir_path) and dir_path != UPLOADS_DIR:
                                    shutil.rmtree(dir_path, ignore_errors=True)
                            except:
                                pass
                        return jsonify({"error": f"Failed to process ZIP: {e}"}), 400
                else:
                    # Check if it's a supported file type
                    if not any(safe_path.lower().endswith(ext) for ext in SUPPORTED_EXTENSIONS):
                        print(f"Skipping unsupported file type: {original_filename}")
                        continue
                    
                    # Create a safe filename that preserves the original name
                    base_name = os.path.splitext(original_filename)[0]
                    file_ext = os.path.splitext(original_filename)[1]
                    
                    # Make filename safe
                    safe_base_name = re.sub(r'[^a-zA-Z0-9_]', '_', base_name)
                    unique_filename = f"{safe_base_name}_{uuid.uuid4().hex[:8]}{file_ext}"
                    path = os.path.join(UPLOADS_DIR, unique_filename)
                    
                    f.save(path)
                    file_mapping[path] = original_filename  # Store original name mapping
                    filepaths.append(path)
                    print(f"Saved: {original_filename} -> {unique_filename}")

            print(f"Total files to scan: {len(filepaths)}")
            if not filepaths:
                return jsonify({"error": "No supported files found in upload"}), 400

            # Scan files but preserve original names in results
            issues = []
            scanned_files = 0
            for filepath in filepaths:
                try:
                    file_issues = scan_file(filepath)
                    scanned_files += 1
                    
                    # Deduplicate issues per file
                    seen = {}
                    for issue in file_issues:
                        key = (issue["message"], issue["file"])
                        if key not in seen:
                            seen[key] = issue
                            seen[key]["lines"] = [issue.get("line", 0)]
                        else:
                            seen[key]["lines"].append(issue.get("line", 0))
                    
                    deduped_issues = list(seen.values())
                    
                    # Replace temporary filenames with original names in the results
                    for issue in deduped_issues:
                        original_name = file_mapping.get(filepath, os.path.basename(filepath))
                        issue['file'] = original_name
                    
                    issues.extend(deduped_issues)
                    
                    # Send progress update for large scans
                    if len(filepaths) > 5 and scanned_files % 5 == 0:
                        print(f"Scanned {scanned_files}/{len(filepaths)} files...")
                        
                except Exception as e:
                    print(f"Error scanning {filepath}: {e}")
                    original_name = file_mapping.get(filepath, os.path.basename(filepath))
                    issues.append({
                        "severity": "LOW",
                        "file": original_name,
                        "line": 0,
                        "message": f"Error scanning file: {e}",
                        "category": "SCAN_ERROR"
                    })

            print(f"Found {len(issues)} issues in {scanned_files} files")

            # Save reports
            os.makedirs(REPORTS_DIR, exist_ok=True)
            json_path = os.path.join(REPORTS_DIR, "report.json")
            html_path = os.path.join(REPORTS_DIR, "report.html")
            generate_json_report(issues, json_path)
            generate_html_report(issues, html_path)

            # Clean up uploaded files after processing
            for filepath in filepaths:
                try:
                    # Remove the file
                    os.remove(filepath)
                    # Try to remove empty directories
                    directory = os.path.dirname(filepath)
                    if directory and directory != UPLOADS_DIR and os.path.exists(directory):
                        try:
                            os.rmdir(directory)
                        except OSError:
                            # Directory not empty, remove recursively
                            shutil.rmtree(directory, ignore_errors=True)
                    print(f"Cleaned up: {filepath}")
                except Exception as e:
                    print(f"Warning: Could not clean up file {filepath}: {e}")

            processing_time = time.time() - start_time
            print(f"Scan completed in {processing_time:.2f} seconds")
            
            return jsonify({
                "issues": issues, 
                "count": len(issues),
                "files_processed": len(filepaths),
                "processing_time": round(processing_time, 2)
            })

        except Exception as e:
            print(f"Unexpected error in scan endpoint: {e}")
            return jsonify({"error": "Internal server error", "details": str(e)}), 500

    @app.route("/reports/<path:filename>", methods=["GET"])
    def serve_reports(filename):
        """Serve saved reports to frontend."""
        return send_from_directory(REPORTS_DIR, filename)

    @app.route("/health", methods=["GET"])
    def health_check():
        """Health check endpoint for monitoring."""
        return jsonify({"status": "healthy", "timestamp": time.time()})

    @app.route("/limits", methods=["GET"])
    def get_limits():
        """Get current file size limits."""
        return jsonify({
            "max_file_size_mb": MAX_FILE_SIZE // 1024 // 1024,
            "max_total_size_mb": MAX_CONTENT_LENGTH // 1024 // 1024,
            "max_zip_extraction_mb": MAX_ZIP_EXTRACTION_SIZE // 1024 // 1024,
            "supported_extensions": SUPPORTED_EXTENSIONS
        })

    @app.route("/refresh", methods=["POST", "OPTIONS"])
    def refresh_scan():
        """Re-run scan on last uploaded files."""
        # Handle preflight OPTIONS request
        if request.method == "OPTIONS":
            return jsonify({"status": "preflight"}), 200
            
        if not os.path.exists(UPLOADS_DIR):
            return jsonify({"error": "No uploaded files to rescan"}), 400

        filepaths = collect_files([UPLOADS_DIR])
        issues = run_scan(filepaths, detailed_output=True)  # Use detailed output for API

        # Save updated reports
        json_path = os.path.join(REPORTS_DIR, "report.json")
        html_path = os.path.join(REPORTS_DIR, "report.html")
        generate_json_report(issues, json_path)
        generate_html_report(issues, html_path)

        return jsonify({"issues": issues, "count": len(issues)})

    port = int(os.environ.get("PORT", 5000))
    print(f"🚀 Secure Code Analyzer server running at http://0.0.0.0:{port}")
    print(f"📁 File size limits: {MAX_FILE_SIZE//1024//1024}MB per file, {MAX_CONTENT_LENGTH//1024//1024}MB total")
    app.run(host="0.0.0.0", port=port, debug=False)


def main():
    parser = argparse.ArgumentParser(description="Secure Code Analyzer CLI + Server")
    parser.add_argument(
        "targets",
        nargs="*",
        help="Files or directories to scan (for CLI mode)",
    )
    parser.add_argument(
        "--serve",
        action="store_true",
        help="Run as server instead of CLI mode",
    )

    args = parser.parse_args()

    if args.serve:
        serve_mode()
    else:
        cli_mode(args)
        

if __name__ == "__main__":
    main()