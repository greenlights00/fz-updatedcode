from flask import Flask, request, jsonify, redirect, make_response
import random
import re

app = Flask(__name__)

# --- Directory/File Discovery Vulnerabilities ---
@app.route("/admin")
def admin():
    return "<h1>Admin Panel</h1>Access granted!", 200

@app.route("/backup.zip")
def backup():
    return "This is a backup file. [Sensitive Data]", 200

@app.route("/config.php")
def config():
    return "<?php // config file with secrets ?>", 200

@app.route("/hidden")
def hidden():
    return "You found a hidden endpoint!", 200

# --- Directory Listing and Sensitive Files ---
@app.route("/files/")
def files_listing():
    # Simulate directory listing
    return "<pre>secret.txt\nnotes.md\nbackup/.git\n</pre>", 200

@app.route("/admin/secret.txt")
def admin_secret():
    return "SuperSecretPassword=admin123", 200

@app.route("/backup/.git")
def backup_git():
    return "Git repo leak! HEAD: ref: refs/heads/main", 200

# --- Parameter Fuzzing Vulnerabilities ---
@app.route("/search")
def search():
    q = request.args.get("q", "")
    # Reflected XSS
    if "<script>" in q:
        return f"<h1>Search Results</h1>Query: {q}", 200
    # SQLi simulation
    if "' OR '1'='1" in q:
        return "All users: admin, guest, test", 200
    return f"Results for: {q}", 200

@app.route("/redirect")
def open_redirect():
    url = request.args.get("url", "")
    # Open redirect vulnerability
    if url.startswith("http"):
        return redirect(url)
    return "No redirect.", 200

@app.route("/error")
def error():
    param = request.args.get("param", "")
    if param == "crash":
        # Simulate verbose error
        return "Exception: Stack trace... at line 42", 500
    return "No error.", 200

# --- Vhost-Only Access ---
@app.route("/vhost-admin")
def vhost_admin():
    host = request.headers.get("Host", "")
    if host == "admin.localhost":
        return "Admin vhost access granted!", 200
    return "Forbidden: vhost required", 403

# --- Parameter-Based Vulnerabilities ---
@app.route("/profile")
def profile():
    user_id = request.args.get("id", "")
    # SQLi simulation
    if "' OR '1'='1" in user_id:
        return "All user profiles: admin, guest, test", 200
    if user_id == "1":
        return "Profile: admin", 200
    return "Profile not found", 404

@app.route("/comment")
def comment():
    text = request.args.get("text", "")
    # Reflected XSS
    if "<script>" in text:
        return f"<div>Comment: {text}</div>", 200
    return f"<div>Comment: {text}</div>", 200

@app.route("/logic")
def logic():
    flag = request.args.get("flag", "")
    # Logic flaw: flag=admin bypasses auth
    if flag == "admin":
        return "Logic flaw: admin access granted!", 200
    return "Normal user access", 200

# --- API Endpoints (Unprotected, Verbose Errors) ---
@app.route("/api/data", methods=["GET", "POST"])
def api_data():
    if request.method == "POST":
        data = request.json or {}
        if data.get("auth") == "letmein":
            return jsonify({"data": "Sensitive API data!"})
        else:
            return make_response(jsonify({"error": "Unauthorized", "debug": "Missing or wrong auth"}), 401)
    return jsonify({"info": "Send POST with auth param"})

@app.route("/api/verbose")
def api_verbose():
    # Simulate verbose error
    return make_response(jsonify({"error": "NullReferenceException at api_verbose()"}), 500)

# --- Vhost Simulation ---
@app.route("/vhost")
def vhost():
    host = request.headers.get("Host", "")
    if host.startswith("admin."):
        return "Welcome, admin vhost!", 200
    elif host.startswith("test."):
        return "Test vhost detected.", 200
    return "Default vhost.", 200

# --- Wayback/Hidden/Legacy Endpoints ---
@app.route("/old-api")
def old_api():
    return "Deprecated API endpoint. Still works!", 200

@app.route("/js-endpoint")
def js_endpoint():
    # Simulate endpoint only referenced in JS
    return "Found via JS analysis!", 200

# --- Logging for all requests ---
@app.before_request
def log_request():
    print(f"[MOCK SERVER] {request.method} {request.path} Host: {request.headers.get('Host')} Args: {dict(request.args)} Data: {request.get_data(as_text=True)}")

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True) 