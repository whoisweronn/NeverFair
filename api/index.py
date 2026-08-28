from flask import Flask, request, jsonify
import hashlib
import os
import requests

app = Flask(__name__)

# Данные для подключения к Supabase через HTTP API (вместопрямого подключения)
SUPABASE_URL = os.environ.get("SUPABASE_URL")       # Например: https://hdbdktukmawqdrkceate.supabase.co
SUPABASE_KEY = os.environ.get("SUPABASE_SERVICE_KEY") # Секретный ключ service_role из настроек Supabase

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

@app.route('/api/v1/auth/register', methods=['POST'])
def register():
    data = request.json
    if not data or 'username' not in data or 'password' not in data:
        return jsonify({"error": "Пустые данные"}), 400
        
    username = data['username']
    password = hash_password(data['password'])
    
    headers = {
        "apikey": SUPABASE_KEY,
        "Authorization": f"Bearer {SUPABASE_KEY}",
        "Content-Type": "application/json",
        "Prefer": "return=representation"
    }
    
    url = f"{SUPABASE_URL}/rest/v1/users"
    
    # Проверяем, существует ли пользователь
    check_res = requests.get(f"{url}?username=eq.{username}", headers=headers)
    if check_res.status_code == 200 and len(check_res.json()) > 0:
        return jsonify({"error": "Никнейм уже занят"}), 400

    # Создаем нового пользователя
    payload = {
        "username": username,
        "password": password,
        "role": "Игрок"
    }
    
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
    
    headers = {
        "apikey": SUPABASE_KEY,
        "Authorization": f"Bearer {SUPABASE_KEY}",
        "Content-Type": "application/json"
    }
    
    url = f"{SUPABASE_URL}/rest/v1/users?username=eq.{username}&password=eq.{password}&select=role"
    
    res = requests.get(url, headers=headers)
    
    if res.status_code == 200:
        users = res.json()
        if len(users) > 0:
            role = users[0]["role"]
            return jsonify({
                "id": f"ID-{len(username)*42}",
                "token": "secure_token_placeholder",
                "username": username,
                "role": role
            }), 200
            
    return jsonify({"error": "Неверный логин или пароль"}), 401
