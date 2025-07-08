# server.py
from flask import Flask, request, jsonify, render_template
from flask_cors import CORS
import subprocess

app = Flask(__name__)
CORS(app)

@app.route('/')
def index():
    return render_template("index.html")

@app.route('/scan', methods=['POST'])
def scan_url():
    data = request.get_json()
    url = data.get("url")
    if not url:
        return jsonify({"error": "URL missing"}), 400
    try:
        result = subprocess.check_output(
            ['python3', 'scanner.py', url],
            stderr=subprocess.STDOUT,
            text=True
        )
        return jsonify({"output": result})
    except subprocess.CalledProcessError as e:
        return jsonify({"error": e.output}), 500
    except Exception as e:
        return jsonify({"error": str(e)}), 500
