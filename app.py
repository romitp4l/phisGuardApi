from flask import Flask, request, jsonify
import requests
import json
import warnings
warnings.filterwarnings("ignore", category=requests.packages.urllib3.exceptions.InsecureRequestWarning)

# Import the analyze_url function from model.py
from model import analyze_url  # This is the crucial line!

app = Flask(__name__)

@app.route('/analyze', methods=['POST'])
def analyze():
    try:
        data = request.get_json()
        if not data or 'url' not in data:
            return jsonify({'error': 'Missing "url" parameter'}), 400

        url = data['url']
        analysis_result = analyze_url(url)  # Use the imported function
        return jsonify(analysis_result), 200

    except Exception as e:
        return jsonify({'error': str(e)}), 500

# if __name__ == "__main__":
#     app.run(debug=True)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)  # Ensure the app binds to all IPs

