"""
app.py - the Flask web app for Clickwise.

Flask's job here is small: receive the URL from the form, hand it to
detector.py, and show the result with an HTML template.
Nothing is saved anywhere. Submitted URLs are never visited.
"""

import re
from flask import Flask, Response, redirect, render_template, request, url_for

from detector import MAX_INPUT_LENGTH, RULE_DOCS, analyze_url
from report import build_csv

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 16 * 1024   # reject huge form posts

TIMESTAMP_PATTERN = re.compile(r"\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2} UTC")


@app.after_request
def add_security_headers(response):
    """Basic browser protections. Our pages load nothing from other sites."""
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Content-Security-Policy"] = "default-src 'self'; base-uri 'none'; form-action 'self'"
    return response


@app.route("/")
def index():
    return render_template("index.html", error=None, url_value="", rules=RULE_DOCS, max_len=MAX_INPUT_LENGTH)


@app.route("/scan", methods=["POST"])
def scan():
    raw = request.form.get("url", "")
    result = analyze_url(raw)
    if not result["valid"]:
        # Show the form again with the error. Jinja escapes everything it prints.
        return render_template("index.html", error=result["error"], url_value=result["input"][:MAX_INPUT_LENGTH],
                               rules=RULE_DOCS, max_len=MAX_INPUT_LENGTH)
    return render_template("result.html", result=result)


@app.route("/download", methods=["POST"])
def download():
    """
    Build the CSV by scanning again instead of trusting numbers sent by the browser.
    This also means we never need to store anything on the server.
    """
    result = analyze_url(request.form.get("url", ""))
    if not result["valid"]:
        return redirect(url_for("index"))
    sent_time = request.form.get("scanned_at", "")
    if TIMESTAMP_PATTERN.fullmatch(sent_time):
        result["scanned_at"] = sent_time        # keep the time of the original scan
    csv_text = build_csv(result)
    return Response(
        csv_text.encode("utf-8-sig"),           # utf-8-sig so Excel reads special characters correctly
        mimetype="text/csv",
        headers={"Content-Disposition": "attachment; filename=clickwise_report.csv"},
    )


if __name__ == "__main__":
    # debug=False on purpose: debug mode must never be exposed on a public server.
    app.run(host="127.0.0.1", port=5000, debug=False)
