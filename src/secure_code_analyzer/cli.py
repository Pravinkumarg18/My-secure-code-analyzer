import argparse
import os
import sys
import zipfile
import shutil
import tempfile
import uuid
import re

from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
from secure_code_analyzer.core.scanner import scan_file
from secure_code_analyzer.core.reporters import (
    generate_json_report,
    generate_html_report,
)

# Default reports directory
REPORTS_DIR = os.path.abspath("reports")

# Supported file extensions (combined from both versions)
SUPPORTED_EXTENSIONS = (".js", ".php", ".py", ".java")


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


def run_scan(files_to_scan):
    """Run scan on given files and return list of issues."""
    all_issues = []
    for file in files_to_scan:
        try:
            issues = scan_file(file)
            if issues:
                print(f"\nFound {len(issues)} issues in {file}:")
                for issue in issues:
                    print(
                        f"  [{issue['severity']}] {issue['file']}:{issue['line']} - {issue['message']}"
                    )
                all_issues.extend(issues)
            else:
                print(f"\nNo issues found in {file}")
        except Exception as e:
            print(f"\n[ERROR] Could not scan {file}: {e}")
            all_issues.append(
                {
                    "severity": "LOW",
                    "file": file,
                    "line": 0,
                    "message": f"Error reading file: {e}",
                }
            )
    return all_issues


def cli_mode(args):
    """Run in classic CLI mode."""
    files_to_scan = collect_files(args.targets)
    if not files_to_scan:
        print(f"❌ No {', '.join(SUPPORTED_EXTENSIONS)} files found to scan.")
        sys.exit(1)

    all_issues = run_scan(files_to_scan)

    print("\n=== SCAN COMPLETE ===")
    print(f"Total Issues Found: {len(all_issues)} across {len(files_to_scan)} files")

    if all_issues:
        # Save reports
        os.makedirs(REPORTS_DIR, exist_ok=True)
        json_path = os.path.join(REPORTS_DIR, "report.json")
        html_path = os.path.join(REPORTS_DIR, "report.html")
        generate_json_report(all_issues, json_path)
        generate_html_report(all_issues, html_path)
        print(f"[+] JSON report saved to {json_path}")
        print(f"[+] HTML report saved to {html_path}")


def serve_mode():
    """Run Flask server for frontend integration."""
    app = Flask(__name__)

    # --- SIMPLE CORS CONFIGURATION ---
    CORS(app, origins=[
        "https://final-commit-1.vercel.app",
        "http://localhost:3000"
    ], supports_credentials=True)
    # --- END OF CORS CONFIGURATION ---

    if request.method == "OPTIONS":
            # Handle preflight request
            return jsonify({"status": "preflight"}), 200
    @app.route("/scan", methods=["POST", "OPTIONS"])  # Add OPTIONS to methods
    def scan_endpoint():
        if request.method == "OPTIONS":
            # Handle preflight request
            return jsonify({"status": "preflight"}), 200
        try:
            print("=== SCAN REQUEST RECEIVED ===")
            
            if "files" not in request.files:
                return jsonify({"error": "No files uploaded"}), 400

            uploaded_files = request.files.getlist("files")
            if not uploaded_files or all(f.filename == '' for f in uploaded_files):
                return jsonify({"error": "No valid files uploaded"}), 400

            filepaths = []
            file_mapping = {}  # Map temporary names to original names
            
            # Create uploads directory if it doesn't exist
            os.makedirs("uploads", exist_ok=True)
                
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
                        with zipfile.ZipFile(f) as zip_ref:
                            zip_files = zip_ref.namelist()
                            print(f"ZIP contains {len(zip_files)} files")
                            
                            for member in zip_files:
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
                                    target_dir = os.path.join("uploads", f"zip_{safe_zip_dir}_{uuid.uuid4().hex[:8]}")
                                    os.makedirs(target_dir, exist_ok=True)
                                    
                                    # Preserve original path structure within the ZIP
                                    target_path = os.path.join(target_dir, member_path)
                                    os.makedirs(os.path.dirname(target_path), exist_ok=True)
                                    
                                    # Extract file
                                    with zip_ref.open(member) as source, open(target_path, "wb") as target:
                                        target.write(source.read())
                                    
                                    # Store mapping with original ZIP name + internal path
                                    original_name_in_zip = f"{original_filename}/{member_path}"
                                    file_mapping[target_path] = original_name_in_zip
                                    filepaths.append(target_path)
                                    print(f"Extracted: {member_path}")
                    except Exception as e:
                        print(f"ZIP extraction failed: {e}")
                        return jsonify({"error": f"Failed to extract ZIP: {e}"}), 400
                else:
                    # Check if it's a supported file type
                    if not any(safe_path.lower().endswith(ext) for ext in SUPPORTED_EXTENSIONS):
                        print(f"Skipping unsupported file type: {original_filename}")
                        continue
                    
                    # Create a safe filename that preserves the original name
                    base_name = os.path.splitext(original_filename)[0]
                    file_ext = os.path.splitext(original_filename)[1]
                    
                    # Make filename safe for Windows
                    safe_base_name = re.sub(r'[^a-zA-Z0-9_]', '_', base_name)
                    unique_filename = f"{safe_base_name}_{uuid.uuid4().hex[:8]}{file_ext}"
                    path = os.path.join("uploads", unique_filename)
                    
                    f.save(path)
                    file_mapping[path] = original_filename  # Store original name mapping
                    filepaths.append(path)
                    print(f"Saved: {original_filename} -> {unique_filename}")

            print(f"Total files to scan: {len(filepaths)}")
            if not filepaths:
                return jsonify({"error": "No supported files found in upload"}), 400

            # Scan files but preserve original names in results
            issues = []
            for filepath in filepaths:
                try:
                    file_issues = scan_file(filepath)
                    # Replace temporary filenames with original names in the results
                    for issue in file_issues:
                        original_name = file_mapping.get(filepath, os.path.basename(filepath))
                        issue['file'] = original_name
                    issues.extend(file_issues)
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

            print(f"Found {len(issues)} issues")

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
                    if directory and directory != "uploads" and os.path.exists(directory):
                        try:
                            os.rmdir(directory)
                        except OSError:
                            pass  # Directory not empty, that's fine
                    print(f"Cleaned up: {filepath}")
                except Exception as e:
                    print(f"Warning: Could not clean up file {filepath}: {e}")

            return jsonify({
                "issues": issues, 
                "count": len(issues),
                "files_processed": len(filepaths)
            })

        except Exception as e:
            print(f"Unexpected error in scan endpoint: {e}")
            return jsonify({"error": "Internal server error", "details": str(e)}), 500


    

    @app.route("/reports/<path:filename>", methods=["GET"])
    def serve_reports(filename):
        """Serve saved reports to frontend."""
        return send_from_directory(REPORTS_DIR, filename)

    @app.route("/refresh", methods=["POST"])
    def refresh_scan():
        """Re-run scan on last uploaded files."""
        upload_dir = "uploads"
        if not os.path.exists(upload_dir):
            return jsonify({"error": "No uploaded files to rescan"}), 400

        filepaths = collect_files([upload_dir])
        issues = run_scan(filepaths)

        # Save updated reports
        json_path = os.path.join(REPORTS_DIR, "report.json")
        html_path = os.path.join(REPORTS_DIR, "report.html")
        generate_json_report(issues, json_path)
        generate_html_report(issues, html_path)

        return jsonify({"issues": issues, "count": len(issues)})

    port = int(os.environ.get("PORT", 5000))
    print(f"🚀 Secure Code Analyzer server running at http://0.0.0.0:{port}")
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
