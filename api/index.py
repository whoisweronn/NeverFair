from flask import Flask, request, jsonify
import hashlib
import os
import requests
from datetime import datetime

app = Flask(__name__)

SUPABASE_URL = os.environ.get("SUPABASE_URL")
SUPABASE_KEY = os.environ.get("SUPABASE_SERVICE_KEY")
# Секретный пароль для доступа к панели (можно изменить на любой другой)
PANEL_PASSWORD = "NeverFairAdminPassword2026"

def get_headers():
    return {
        "apikey": SUPABASE_KEY,
        "Authorization": f"Bearer {SUPABASE_KEY}",
        "Content-Type": "application/json",
        "Prefer": "return=representation"
    }

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def verify_password(data):
    return data and data.get('admin_pass') == PANEL_PASSWORD

def log_action(admin_name, action_desc):
    try:
        url = f"{SUPABASE_URL}/rest/v1/audit_logs"
        payload = {
            "admin": admin_name,
            "action": action_desc,
            "timestamp": datetime.utcnow().isoformat()
        }
        requests.post(url, headers=get_headers(), json=payload)
    except Exception:
        pass

@app.route('/api/v1/auth/register', methods=['POST'])
def register():
    data = request.json
    if not data or 'username' not in data or 'password' not in data:
        return jsonify({"error": "Пустые данные"}), 400
        
    username = data['username']
    password = hash_password(data['password'])
    
    headers = get_headers()
    url = f"{SUPABASE_URL}/rest/v1/users"
    
    check_res = requests.get(f"{url}?username=eq.{username}", headers=headers)
    if check_res.status_code == 200 and len(check_res.json()) > 0:
        return jsonify({"error": "Никнейм уже занят"}), 400

    payload = {"username": username, "password": password, "role": "Игрок"}
    res = requests.post(url, headers=headers, json=payload)
    
    if res.status_code in [200, 201]:
        return jsonify({"status": "ok"}), 200
    else:
        return jsonify({"error": f"Ошибка Supabase: {res.text}"}), 500

@app.route('/api/v1/auth/login', methods=['POST'])
def login():
    data = request.json
    if not data or 'username' not in data or 'password' not in data:
        return jsonify({"error": "Пустые данные"}), 400

    username = data['username']
    password = hash_password(data['password'])
    
    headers = get_headers()
    url = f"{SUPABASE_URL}/rest/v1/users?username=eq.{username}&password=eq.{password}&select=role,user_id"
    
    res = requests.get(url, headers=headers)
    if res.status_code == 200:
        users = res.json()
        if len(users) > 0:
            return jsonify({
                "id": users[0].get("user_id") or f"ID-{len(username)*42}",
                "token": "secure_token_placeholder",
                "username": username,
                "role": users[0]["role"]
            }), 200
            
    return jsonify({"error": "Неверный логин или пароль"}), 401

# --- ЗАЩИЩЕННЫЕ ЭНДПОИНТЫ ПАНЕЛИ УПРАВЛЕНИЯ ---

@app.route('/api/v1/admin/data', methods=['POST'])
def get_admin_data():
    data = request.json
    if not verify_password(data):
        return jsonify({"error": "Неверный пароль панели"}), 403

    headers = get_headers()
    users_res = requests.get(f"{SUPABASE_URL}/rest/v1/users?select=username,role,user_id", headers=headers)
    bans_res = requests.get(f"{SUPABASE_URL}/rest/v1/banned_ips", headers=headers)
    logs_res = requests.get(f"{SUPABASE_URL}/rest/v1/audit_logs?select=*&order=timestamp.desc&limit=50", headers=headers)
    
    if users_res.status_code == 200:
        return jsonify({
            "users": users_res.json(),
            "bans": bans_res.json() if bans_res.status_code == 200 else [],
            "logs": logs_res.json() if logs_res.status_code == 200 else []
        }), 200
    return jsonify({"error": "Ошибка загрузки данных"}), 500

@app.route('/api/v1/admin/set_role', methods=['POST'])
def set_role():
    data = request.json
    if not verify_password(data):
        return jsonify({"error": "Неверный пароль панели"}), 403

    admin, username, role = data.get('admin', 'System'), data.get('username'), data.get('role')
    
    url = f"{SUPABASE_URL}/rest/v1/users?username=eq.{username}"
    res = requests.patch(url, headers=get_headers(), json={"role": role})
    
    if res.status_code in [200, 204]:
        log_action(admin, f"Изменил роль игроку {username} на {role}")
        return jsonify({"status": "ok"}), 200
    return jsonify({"error": res.text}), 500

@app.route('/api/v1/admin/set_id', methods=['POST'])
def set_id():
    data = request.json
    if not verify_password(data):
        return jsonify({"error": "Неверный пароль панели"}), 403

    admin, username, new_id = data.get('admin', 'System'), data.get('username'), data.get('new_id')
    
    url = f"{SUPABASE_URL}/rest/v1/users?username=eq.{username}"
    res = requests.patch(url, headers=get_headers(), json={"user_id": new_id})
    
    if res.status_code in [200, 204]:
        log_action(admin, f"Изменил ID игроку {username} на {new_id}")
        return jsonify({"status": "ok"}), 200
    return jsonify({"error": res.text}), 500

@app.route('/api/v1/admin/ban', methods=['POST'])
def ban_player():
    data = request.json
    if not verify_password(data):
        return jsonify({"error": "Неверный пароль панели"}), 403

    admin, username = data.get('admin', 'System'), data.get('username')
    ip = data.get('ip', '192.168.1.1')
    
    url = f"{SUPABASE_URL}/rest/v1/banned_ips"
    res = requests.post(url, headers=get_headers(), json={"ip": ip, "username": username})
    
    if res.status_code in [200, 201]:
        log_action(admin, f"Забанил игрока {username} (IP: {ip})")
        return jsonify({"status": "ok"}), 200
    return jsonify({"error": res.text}), 500

@app.route('/api/v1/admin/unban', methods=['POST'])
def unban_player():
    data = request.json
    if not verify_password(data):
        return jsonify({"error": "Неверный пароль панели"}), 403

    admin, ip = data.get('admin', 'System'), data.get('ip')
    
    url = f"{SUPABASE_URL}/rest/v1/banned_ips?ip=eq.{ip}"
    res = requests.delete(url, headers=get_headers())
    
    if res.status_code in [200, 204]:
        log_action(admin, f"Разбанил IP: {ip}")
        return jsonify({"status": "ok"}), 200
    return jsonify({"error": res.text}), 500
