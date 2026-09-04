import os
import hashlib
import secrets
from datetime import datetime
from typing import Optional, List
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from supabase import create_client, Client

app = FastAPI(title="NeverFair Client Backend API", version="1.5.0")

# Разрешаем CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Переменные окружения Vercel
SUPABASE_URL = os.environ.get("SUPABASE_URL", "https://hdbdktukmawqdrkceate.supabase.co")
SUPABASE_KEY = os.environ.get("SUPABASE_KEY", "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6ImhkYmRrdHVrbWF3cWRya2NlYXRlIiwicm9sZSI6InNlcnZpY2Vfcm9sZSIsImlhdCI6MTc4Nzk0OTA5MiwiZXhwIjoyMTAzNTI1MDkyfQ.HiGG3-0FZXT3QRc_VvF0i0Msl1vlausyYZ2eJ_4Tfgo")  # Рекомендуется Service Role Key
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "JdhuywAleu827FLle")
PASSWORD_SALT = os.environ.get("PASSWORD_SALT", "JdhuywAleu827FLlekawiIuwdkAUAUoi")

supabase: Optional[Client] = (
    create_client(SUPABASE_URL, SUPABASE_KEY) if SUPABASE_URL and SUPABASE_KEY else None
)

def hash_password(password: str) -> str:
    raw = f"{password}:{PASSWORD_SALT}"
    return hashlib.sha256(raw.encode()).hexdigest()

def err(message: str, status_code: int = 400) -> JSONResponse:
    return JSONResponse(status_code=status_code, content={"error": message})

def verify_admin(pass_attempt: str) -> bool:
    return secrets.compare_digest(pass_attempt, ADMIN_PASSWORD)

def log_audit(admin: str, action: str):
    if not supabase:
        return
    now_str = datetime.now().strftime("%Y-%m-%d %H:%M")
    supabase.table("audit_logs").insert({
        "admin": admin,
        "action": action,
        "timestamp": now_str
    }).execute()

# ==================== МОДЕЛИ ЗАПРОСОВ (PYDANTIC) ====================

class AuthRequest(BaseModel):
    username: str
    password: str
    hwid: Optional[str] = None

class AdminBaseRequest(BaseModel):
    admin_pass: str

class AdminUserAction(BaseModel):
    admin_pass: str
    admin: str
    username: str

class AdminRoleRequest(AdminUserAction):
    role: str

class AdminIdRequest(AdminUserAction):
    new_id: str

class AdminToggleAccessRequest(AdminUserAction):
    branch: str
    state: bool

class AdminUnbanRequest(BaseModel):
    admin_pass: str
    admin: str
    ip: str

class CrashReportRequest(BaseModel):
    nickname: str
    role: str
    version: str
    hwid: str
    title: str
    solution: str
    log_preview: str

# ==================== АВТОРИЗАЦИЯ И РЕГИСТРАЦИЯ ====================

@app.post("/api/v1/auth/register")
async def register(req: AuthRequest):
    if not supabase:
        return err("База данных временно недоступна", status_code=500)

    clean_username = req.username.strip()
    if not clean_username or not req.password:
        return err("Логин и пароль не могут быть пустыми")

    # Проверка уникальности ника
    existing = supabase.table("users").select("id").eq("username", clean_username).execute()
    if existing.data:
        return err("Пользователь с таким логином уже зарегистрирован", status_code=409)

    hashed_pw = hash_password(req.password)
    user_id_gen = f"NF-{secrets.token_hex(3).upper()}"

    insert_payload = {
        "username": clean_username,
        "password_hash": hashed_pw,
        "hwid": req.hwid,  # Первая привязка HWID при создании
        "role": "Игрок",
        "user_id": user_id_gen,
        "has_release": True,
        "has_beta": False,
        "has_alpha": False
    }

    res = supabase.table("users").insert(insert_payload).execute()
    if not res.data:
        return err("Не удалось сохранить пользователя в базе данных", status_code=500)

    return {}

@app.post("/api/v1/auth/login")
async def login(req: AuthRequest, request: Request):
    if not supabase:
        return err("База данных временно недоступна", status_code=500)

    clean_username = req.username.strip()
    client_ip = request.headers.get("x-forwarded-for", request.client.host if request.client else "0.0.0.0").split(",")[0].strip()

    # 1. Проверка блокировок по нику или IP
    ban_check = supabase.table("bans").select("*").or_(f"username.eq.{clean_username},ip.eq.{client_ip}").execute()
    if ban_check.data:
        return err("Доступ заблокирован: ваш аккаунт или IP-адрес находится в черном списке", status_code=403)

    # 2. Поиск пользователя
    user_res = supabase.table("users").select("*").eq("username", clean_username).execute()
    if not user_res.data:
        return err("Неверный логин или пароль", status_code=401)

    user = user_res.data[0]

    # 3. Сверка хэша пароля
    if user["password_hash"] != hash_password(req.password):
        return err("Неверный логин или пароль", status_code=401)

    # 4. Проверка и привязка HWID
    stored_hwid = user.get("hwid")
    incoming_hwid = req.hwid

    if not stored_hwid:
        # Если HWID еще не привязан (или сброшен админом) — привязываем текущее устройство
        if incoming_hwid:
            supabase.table("users").update({"hwid": incoming_hwid}).eq("id", user["id"]).execute()
            stored_hwid = incoming_hwid
    else:
        # Проверка на соответствие привязанному железу
        if incoming_hwid and stored_hwid != incoming_hwid:
            return err("Ошибка HWID: несовпадение оборудования с привязанным ПК!", status_code=403)

    # 5. Генерация активного токена сессии
    session_token = secrets.token_hex(32)
    supabase.table("users").update({"token": session_token}).eq("id", user["id"]).execute()

    return {
        "id": user.get("user_id") or str(user["id"]),
        "token": session_token,
        "username": user["username"],
        "role": user.get("role", "Игрок"),
        "has_release": user.get("has_release", True),
        "has_beta": user.get("has_beta", False),
        "has_alpha": user.get("has_alpha", False)
    }

# ==================== ПАНЕЛЬ АДМИНИСТРАТОРА ====================

@app.post("/api/v1/admin/data")
async def get_admin_data(req: AdminBaseRequest):
    if not verify_admin(req.admin_pass):
        return err("Доступ запрещен: неверный пароль панели", status_code=403)

    users_res = supabase.table("users").select(
        "username, role, user_id, hwid, has_release, has_beta, has_alpha"
    ).order("username").execute()

    bans_res = supabase.table("bans").select("ip, username").execute()

    logs_res = supabase.table("audit_logs").select(
        "id, admin, action, timestamp"
    ).order("id", desc=True).limit(50).execute()

    return {
        "users": users_res.data or [],
        "bans": bans_res.data or [],
        "logs": logs_res.data or []
    }

@app.post("/api/v1/admin/toggle_access")
async def toggle_access(req: AdminToggleAccessRequest):
    if not verify_admin(req.admin_pass):
        return err("Доступ запрещен", status_code=403)

    branch_col = f"has_{req.branch.lower().strip()}"
    if branch_col not in ["has_release", "has_beta", "has_alpha"]:
        return err("Некорректное имя ветки (доступны: release, beta, alpha)")

    supabase.table("users").update({branch_col: req.state}).eq("username", req.username).execute()
    log_audit(req.admin, f"{'Выдал доступ к' if req.state else 'Отозвал доступ от'} {req.branch.upper()} у игрока {req.username}")
    return {}

@app.post("/api/v1/admin/reset_hwid")
async def reset_hwid(req: AdminUserAction):
    if not verify_admin(req.admin_pass):
        return err("Доступ запрещен", status_code=403)

    supabase.table("users").update({"hwid": None}).eq("username", req.username).execute()
    log_audit(req.admin, f"Сбросил привязку HWID для игрока {req.username}")
    return {}

@app.post("/api/v1/admin/kill_session")
async def kill_session(req: AdminUserAction):
    if not verify_admin(req.admin_pass):
        return err("Доступ запрещен", status_code=403)

    supabase.table("users").update({"token": None}).eq("username", req.username).execute()
    log_audit(req.admin, f"Экстренно сбросил сессию игрока {req.username}")
    return {}

@app.post("/api/v1/admin/set_role")
async def set_role(req: AdminRoleRequest):
    if not verify_admin(req.admin_pass):
        return err("Доступ запрещен", status_code=403)

    supabase.table("users").update({"role": req.role.strip()}).eq("username", req.username).execute()
    log_audit(req.admin, f"Установил роль '{req.role}' для игрока {req.username}")
    return {}

@app.post("/api/v1/admin/set_id")
async def set_id(req: AdminIdRequest):
    if not verify_admin(req.admin_pass):
        return err("Доступ запрещен", status_code=403)

    supabase.table("users").update({"user_id": req.new_id.strip()}).eq("username", req.username).execute()
    log_audit(req.admin, f"Изменил ID игрока {req.username} на '{req.new_id}'")
    return {}

@app.post("/api/v1/admin/ban")
async def ban_user(req: AdminUserAction):
    if not verify_admin(req.admin_pass):
        return err("Доступ запрещен", status_code=403)

    # Инвалидируем сессию забаненного
    supabase.table("users").update({"token": None}).eq("username", req.username).execute()
    supabase.table("bans").insert({"username": req.username, "ip": "0.0.0.0"}).execute()
    log_audit(req.admin, f"Заблокировал аккаунт {req.username}")
    return {}

@app.post("/api/v1/admin/unban")
async def unban_user(req: AdminUnbanRequest):
    if not verify_admin(req.admin_pass):
        return err("Доступ запрещен", status_code=403)

    supabase.table("bans").delete().eq("ip", req.ip).execute()
    log_audit(req.admin, f"Разблокировал IP: {req.ip}")
    return {}

@app.post("/api/v1/admin/crash_report")
async def save_crash_report(req: CrashReportRequest):
    if not supabase:
        return {}

    supabase.table("crash_reports").insert({
        "nickname": req.nickname,
        "role": req.role,
        "version": req.version,
        "hwid": req.hwid,
        "title": req.title,
        "solution": req.solution,
        "log_preview": req.log_preview[:3000]
    }).execute()
    return {}
