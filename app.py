from flask import Flask, render_template, request, jsonify
from scanner import run_scan

app = Flask(__name__)


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/scan", methods=["POST"])
def api_scan():
    data = request.get_json(silent=True) or {}
    target = (data.get("target") or "").strip()
    if not target:
        return jsonify({"ok": False, "error": "Please provide a target URL or domain."}), 400
    if len(target) > 300:
        return jsonify({"ok": False, "error": "Target value is too long."}), 400

    result = run_scan(target)
    status = 200 if result.get("ok") else 422
    return jsonify(result), status


if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000)
