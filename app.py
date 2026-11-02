"""
app.py - Flask website for the phishing URL checker.

Run locally:
    pip install -r requirements.txt
    python app.py                 # then open http://127.0.0.1:5000

Run in production (example):
    gunicorn -w 2 -b 0.0.0.0:8000 app:app

Endpoints:
    GET  /            the web page
    POST /api/check   JSON {"url": "..."} -> JSON verdict
    GET  /health      simple health check
"""

from flask import Flask, jsonify, render_template, request

from url_analyzer import PhishingChecker

app = Flask(__name__, template_folder=".")
app.config["MAX_CONTENT_LENGTH"] = 16 * 1024      # reject request bodies larger than 16 KB

checker = PhishingChecker()                        # load the trained model once at start-up


@app.get("/")
def index():
    return render_template("index.html")


@app.post("/api/check")
def api_check():
    data = request.get_json(silent=True) or {}
    url = data.get("url", "")
    if not isinstance(url, str):
        return jsonify(error="'url' must be a string."), 400
    try:
        return jsonify(checker.check(url))
    except ValueError as e:                        # bad user input -> 400, not a server error
        return jsonify(error=str(e)), 400


@app.get("/health")
def health():
    return jsonify(status="ok")


@app.after_request
def security_headers(resp):
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["Referrer-Policy"] = "no-referrer"
    resp.headers["Content-Security-Policy"] = (
        "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'"
    )
    return resp

app.run(host="127.0.0.1", port=5000, debug=False)
