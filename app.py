from flask import Flask, jsonify, redirect
from flask import request
import requests

app = Flask(__name__)

@app.route('/', methods=['GET'])
def hello():
    return redirect("https://youtu.be/3BFTio5296w", code=302)

@app.route('/', methods=['POST'])
def proxy():
    data = request.get_json()

    if not data:
        return jsonify({"error": "Invalid JSON data"}), 400

    url = data.get('uri')
    if not url:
        return jsonify({"error": "Missing 'uri' in request data"}), 400

    request_options = {
        'headers': data.get('headers', {}),
        'allow_redirects': True
    }

    # Add query parameters to the URL
    if 'query' in data:
        url = requests.Request('GET', url, params=data['query']).prepare().url

    # Add cookies to the request headers
    if 'cookies' in data:
        cookies = '; '.join([f"{key}={value}" for key, value in data['cookies'].items()])
        request_options['headers']['Cookie'] = cookies

    # Add data to the request body
    if 'data' in data:
        request_options['data'] = data['data']

    # Make the web request
    session = requests.Session() 
    response = session.request(method=data['method'], url=url, **request_options)

    # Process the response
    response_data = {
        "status": response.status_code,
        "headers": dict(response.headers),
        "cookies": session.cookies.get_dict(),
        "data": response.json() if 'application/json' in response.headers.get('Content-Type', '') else { "text": response.text }
    }

    return jsonify(response_data), response.status_code
