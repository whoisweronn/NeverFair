from flask import Flask, request, jsonify
import psycopg2
import hashlib
import os

app = Flask(__name__)

# Пароль от БД будет спрятан в настройках Vercel
DATABASE_URL = os.environ.get("DATABASE_URL")

def get_db_connection():
    return psycopg2.connect(DATABASE_URL)

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

# Создаем таблицу в Supabase при первом запуске
def init_db():
    conn = get_db_connection()
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS users 
                 (username VARCHAR(255) PRIMARY KEY, password VARCHAR(255), role VARCHAR(50))''')
    conn.commit()
    c.close()
    conn.close()

try:
    init_db()
except Exception as e:
    print("Ошибка инициализации БД:", e)

@app.route('/api/v1/auth/register', methods=['POST'])
def register():
    data = request.json
    if not data or 'username' not in data or 'password' not in data:
        return jsonify({"error": "Пустые данные"}), 400
        
    username = data['username']
    password = data['password']
    
    try:
        conn = get_db_connection()
        c = conn.cursor()
        
        c.execute("SELECT * FROM users WHERE username=%s", (username,))
        if c.fetchone():
            c.close()
            conn.close()
            return jsonify({"error": "Никнейм уже занят"}), 400
            
        c.execute("INSERT INTO users (username, password, role) VALUES (%s, %s, %s)", 
                  (username, hash_password(password), "Игрок"))
        conn.commit()
        c.close()
        conn.close()
        
        return jsonify({"status": "ok"}), 200
    except Exception as e:
        # Теперь сервер вернет точную техническую ошибку в тексте!
        return jsonify({"error": f"Ошибка БД: {str(e)}"}), 500

@app.route('/api/v1/auth/login', methods=['POST'])
def login():
    data = request.json
    if not data or 'username' not in data or 'password' not in data:
        return jsonify({"error": "Пустые данные"}), 400

    username = data['username']
    password = hash_password(data['password'])
    
    conn = get_db_connection()
    c = conn.cursor()
    c.execute("SELECT role FROM users WHERE username=%s AND password=%s", (username, password))
    user = c.fetchone()
    c.close()
    conn.close()
    
    if user:
        return jsonify({
            "id": f"ID-{len(username)*42}",
            "token": "secure_token_placeholder",
            "username": username,
            "role": user[0]
        }), 200
    else:
        return jsonify({"error": "Неверный логин или пароль"}), 401
