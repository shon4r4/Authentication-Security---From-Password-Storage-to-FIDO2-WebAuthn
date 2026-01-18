import requests
from flask import Flask, request, Response
from urllib.parse import urljoin

app = Flask(__name__)

TARGET = "http://127.0.0.1:5000"

@app.route("/<path:path>", methods=["POST"])
def relay(path):
    data = request.get_json() or {}
    print("Captured:", data)

    # forward to target
    resp = requests.post(urljoin(TARGET, path), json=data)
    
    # immediately replay
    replay_resp = requests.post(urljoin(TARGET, path), json=data)
    print(f"Replayed to target: status={replay_resp.status_code}")

    return Response(resp.content, status=resp.status_code)

if __name__ == "__main__":
    app.run(port=8000)
