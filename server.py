from flask import Flask, jsonify, request, make_response
from flask_cors import CORS
import secrets
import time
import json
import os

app = Flask(__name__)
# Update CORS configuration to handle all routes and methods properly
CORS(app, resources={r"/*": {
    "origins": "*",
    "allow_headers": ["Authorization", "Content-Type"],
    "methods": ["GET", "POST", "PUT", "DELETE", "OPTIONS"]
}}, supports_credentials=True)

DATA_FILE = 'data.json'

# Load data from file if it exists, otherwise use defaults
def load_data():
    if os.path.exists(DATA_FILE):
        with open(DATA_FILE, 'r') as f:
            data = json.load(f)
            return data.get('users', {}), data.get('tokens', {})
    return {
        "admin": {"pin": "7197", "created": 420, "urls": {}, "is_admin": True},
    }, {}

def save_data():
    with open(DATA_FILE, 'w') as f:
        json.dump({
            'users': USER_CREDENTIALS,
            'tokens': ACTIVE_TOKENS
        }, f, indent=4)

# Initialize data
USER_CREDENTIALS, ACTIVE_TOKENS = load_data()

@app.route('/')
def serve_client():
    with open('client.html', 'r') as f:
        return f.read()

@app.route('/status', methods=['GET'])
def check_status():
    return jsonify({"status": "online"})

@app.route('/auth', methods=['POST'])
def authenticate():
    username = request.json.get('username')
    pin = request.json.get('pin')
    is_setting_pin = request.json.get('is_setting_pin', False)
    
    if not username:
        return jsonify({"success": False, "message": "Username is required"}), 400
        
    if username not in USER_CREDENTIALS:
        return jsonify({"success": False, "message": "Invalid username"}), 401

    if USER_CREDENTIALS[username]["pin"] is None:
        if not is_setting_pin:
            return jsonify({"success": False, "message": "PIN needs to be set", "needs_pin": True}), 401
        if not pin or len(pin) != 4 or not pin.isdigit():
            return jsonify({"success": False, "message": "PIN must be 4 digits"}), 400
            
        USER_CREDENTIALS[username]["pin"] = pin
        USER_CREDENTIALS[username]["created"] = time.time()
        token = secrets.token_urlsafe(32)
        ACTIVE_TOKENS[token] = {"expires": time.time() + (24 * 3600), "username": username}
        save_data()  # Save after setting PIN
        return jsonify({
            "success": True, 
            "token": token, 
            "message": "PIN set successfully",
            "is_admin": USER_CREDENTIALS[username]["is_admin"]
        })
    
    else:
        if pin != USER_CREDENTIALS[username]["pin"]:
            return jsonify({"success": False, "message": "Incorrect PIN"}), 401
            
        token = secrets.token_urlsafe(32)
        ACTIVE_TOKENS[token] = {"expires": time.time() + (24 * 3600), "username": username}
        save_data()  # Save after creating new token
        return jsonify({
            "success": True, 
            "token": token,
            "is_admin": USER_CREDENTIALS[username]["is_admin"]
        })

@app.route('/check-username', methods=['POST'])
def check_username():
    username = request.json.get('username')
    if not username:
        return jsonify({"success": False, "message": "Username is required"}), 400
        
    if username not in USER_CREDENTIALS:
        return jsonify({"exists": False, "message": "Invalid username"})
        
    needs_pin = USER_CREDENTIALS[username]["pin"] is None
    return jsonify({"exists": True, "needs_pin": needs_pin})

@app.route('/verify', methods=['POST'])
def verify_token():
    token = request.json.get('token')
    
    if not token:
        return jsonify({"valid": False, "message": "No token provided"}), 401
        
    if token in ACTIVE_TOKENS:
        if time.time() < ACTIVE_TOKENS[token]["expires"]:
            return jsonify({"valid": True})
        else:
            del ACTIVE_TOKENS[token]
            save_data()  # Save after removing expired token
    
    return jsonify({"valid": False}), 401

@app.route('/urls/<url_id>', methods=['DELETE'])
def delete_url(url_id):
    token = request.headers.get('Authorization')
    if not token or token not in ACTIVE_TOKENS or time.time() >= ACTIVE_TOKENS[token]["expires"]:
        return jsonify({"success": False, "message": "Invalid or expired token"}), 401
        
    username = ACTIVE_TOKENS[token]["username"]
    
    if not url_id or url_id not in USER_CREDENTIALS[username]["urls"]:
        return jsonify({"success": False, "message": "Invalid URL ID"}), 400
        
    del USER_CREDENTIALS[username]["urls"][url_id]
    save_data()  # Save after deleting URL
    return jsonify({"success": True})

@app.route('/urls', methods=['GET', 'POST', 'PUT'])
def manage_urls():
    token = request.headers.get('Authorization')
    if not token or token not in ACTIVE_TOKENS or time.time() >= ACTIVE_TOKENS[token]["expires"]:
        return jsonify({"success": False, "message": "Invalid or expired token"}), 401
        
    username = ACTIVE_TOKENS[token]["username"]
    
    if request.method == 'GET':
        return jsonify({"urls": USER_CREDENTIALS[username]["urls"]})
        
    elif request.method == 'POST':
        url = request.json.get('url')
        nickname = request.json.get('nickname')
        if not url or not nickname:
            return jsonify({"success": False, "message": "URL and nickname are required"}), 400
            
        url_id = secrets.token_urlsafe(8)
        USER_CREDENTIALS[username]["urls"][url_id] = {"url": url, "nickname": nickname}
        save_data()  # Save after adding URL
        return jsonify({"success": True, "url_id": url_id})
        
    elif request.method == 'PUT':
        url_id = request.json.get('url_id')
        nickname = request.json.get('nickname')
        if not url_id or not nickname or url_id not in USER_CREDENTIALS[username]["urls"]:
            return jsonify({"success": False, "message": "Invalid URL ID or nickname"}), 400
            
        USER_CREDENTIALS[username]["urls"][url_id]["nickname"] = nickname
        save_data()  # Save after updating URL nickname
        return jsonify({"success": True})

# Admin endpoints
@app.route('/admin/users', methods=['GET', 'POST', 'PUT', 'DELETE'])
def manage_users():
    token = request.headers.get('Authorization')
    if not token or token not in ACTIVE_TOKENS or time.time() >= ACTIVE_TOKENS[token]["expires"]:
        return jsonify({"success": False, "message": "Invalid or expired token"}), 401
        
    username = ACTIVE_TOKENS[token]["username"]
    if not USER_CREDENTIALS[username]["is_admin"]:
        return jsonify({"success": False, "message": "Unauthorized"}), 403

    if request.method == 'GET':
        users = {name: {
            "created": data["created"],
            "is_admin": data["is_admin"],
            "has_pin": data["pin"] is not None,
            "pin": data["pin"] or "Not Set"
        } for name, data in USER_CREDENTIALS.items()}
        return jsonify({"users": users})

    elif request.method == 'POST':
        new_username = request.json.get('username')
        is_admin = request.json.get('is_admin', False)
        
        if not new_username or new_username in USER_CREDENTIALS:
            return jsonify({"success": False, "message": "Invalid or existing username"}), 400
            
        USER_CREDENTIALS[new_username] = {
            "pin": None,
            "created": None,
            "urls": {},
            "is_admin": is_admin
        }
        save_data()  # Save after creating new user
        return jsonify({"success": True})

    elif request.method == 'PUT':
        target_username = request.json.get('username')
        new_pin = request.json.get('pin')
        is_admin = request.json.get('is_admin')
        
        if target_username not in USER_CREDENTIALS:
            return jsonify({"success": False, "message": "User not found"}), 404
            
        if new_pin is not None:
            if not new_pin or len(new_pin) != 4 or not new_pin.isdigit():
                return jsonify({"success": False, "message": "PIN must be 4 digits"}), 400
            USER_CREDENTIALS[target_username]["pin"] = new_pin
            
        if is_admin is not None:
            USER_CREDENTIALS[target_username]["is_admin"] = is_admin
            
        save_data()  # Save after updating user
        return jsonify({"success": True})

    elif request.method == 'DELETE':
        target_username = request.json.get('username')
        if not target_username or target_username not in USER_CREDENTIALS:
            return jsonify({"success": False, "message": "Invalid username"}), 400
            
        if target_username == username:
            return jsonify({"success": False, "message": "Cannot delete yourself"}), 400
            
        del USER_CREDENTIALS[target_username]
        # Remove any active tokens for this user
        for token_key in list(ACTIVE_TOKENS.keys()):
            if ACTIVE_TOKENS[token_key]["username"] == target_username:
                del ACTIVE_TOKENS[token_key]
        save_data()  # Save after deleting user
        return jsonify({"success": True})

if __name__ == '__main__':
    app.run(debug=False, port=8000)
