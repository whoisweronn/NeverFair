"""NeverFair Vercel API. Python standard library only; secrets stay on the server."""

from __future__ import annotations

import base64
import hashlib
import hmac
import io
import json
import logging
import math
import os
import re
import time
from concurrent.futures import ThreadPoolExecutor
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.error import HTTPError
from urllib.parse import quote, urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener

MAX_BODY_BYTES = 16_384
MAX_JAR_BYTES = 268_435_456
MAX_JSON_BYTES = 2_097_152
CHANNELS = ("release", "beta", "alpha", "26.2")
UUID_PATTERN = r"[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{12}"
VERSION_PATTERN = r"[0-9]{1,6}(?:\.[0-9]{1,6}){0,2}"


class ApiError(Exception):
    def __init__(self, status: int, code: str):
        self.status = status
        self.code = code
        super().__init__(code)


def fail(status, code):
    raise ApiError(status, code)


def env(name):
    value = os.environ.get(name)
    if not value:
        fail(500, "SERVER_CONFIG_ERROR")
    return value


def supabase_url():
    return env("SUPABASE_URL").rstrip("/")


def keyed_hash(value):
    return hmac.new(env("HWID_PEPPER").encode("utf-8"), value.encode("utf-8"), hashlib.sha256).hexdigest()


def profile_view(profile):
    return {"id": profile["id"], "login": profile["login"], "role": profile["role"],
            "lastLogin": profile.get("last_login"), "createdAt": profile.get("created_at")}


def json_bytes(value):
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), allow_nan=False).encode("utf-8")


def parse_json(data):
    def invalid_constant(_):
        raise ValueError("Invalid JSON constant")
    return json.loads(data.decode("utf-8"), parse_constant=invalid_constant)


class NoRedirect(HTTPRedirectHandler):
    # Never forward an Authorization header to a download host on redirect.
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class Response:
    def __init__(self, stream):
        self.stream = stream
        self.status = stream.code
        self.headers = stream.headers

    @property
    def ok(self):
        return 200 <= self.status < 300

    def read(self, maximum):
        with io.BytesIO() as output:
            while True:
                chunk = self.stream.read(min(81_920, maximum + 1 - output.tell()))
                if not chunk:
                    return output.getvalue()
                output.write(chunk)
                if output.tell() > maximum:
                    fail(502, "ASSET_TOO_LARGE")

    def json(self):
        return parse_json(self.read(MAX_JSON_BYTES))

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.stream.close()


def http_request(url, *, method="GET", headers=None, data=None, timeout=30):
    request = Request(url, data=data, headers=headers or {}, method=method)
    try:
        stream = build_opener(NoRedirect()).open(request, timeout=timeout)
    except HTTPError as error:
        stream = error  # Status codes are translated by the API, never returned verbatim.
    return Response(stream)


def supa(path, *, method="GET", payload=None, data=None, bearer=None, public_key=False, headers=None):
    key = env("SUPABASE_ANON_KEY" if public_key else "SUPABASE_SERVICE_ROLE_KEY")
    request_headers = {"apikey": key, "Authorization": "Bearer " + (key if bearer is None else bearer),
                       "Content-Type": "application/json"}
    request_headers.update(headers or {})
    return http_request(supabase_url() + "/" + path, method=method, headers=request_headers,
                        data=json_bytes(payload) if payload is not None else data)


def db(path, *, method="GET", payload=None):
    with supa("rest/v1/" + path, method=method, payload=payload) as response:
        if not response.ok:
            try:
                message = response.json().get("message", "")
            except Exception:
                message = ""
            for code in ("HWID_MISMATCH", "SESSION_REVOKED", "ADMIN_REQUIRED", "USER_NOT_FOUND"):
                if isinstance(message, str) and code in message:
                    fail(404 if code == "USER_NOT_FOUND" else 403, code)
            fail(500, "DATABASE_ERROR")
        raw = response.read(MAX_JSON_BYTES)
        return parse_json(raw) if raw else None


def rpc(name, payload):
    return db("rpc/" + name, method="POST", payload=payload)


def rate(key, limit, seconds):
    if rpc("nf_rate", {"p_key": keyed_hash("rate:" + key), "p_limit": limit, "p_seconds": seconds}) is not True:
        fail(429, "RATE_LIMITED")


def device(value):
    if not isinstance(value, str) or not re.fullmatch(r"[a-f0-9]{64}", value):
        fail(400, "HWID_MISMATCH")
    return keyed_hash("device:" + value)


def login_name(value):
    login = value.strip().lower() if isinstance(value, str) else ""
    if not re.fullmatch(r"[a-z0-9_]{3,24}", login):
        fail(400, "LOGIN_INVALID")
    return login


def password(value):
    try:
        # .NET and the previous JS API count UTF-16 units, including for emoji.
        length = len(value.encode("utf-16-le")) // 2 if isinstance(value, str) else 0
    except UnicodeEncodeError:
        fail(400, "PASSWORD_INVALID")
    if not 12 <= length <= 128:
        fail(400, "PASSWORD_INVALID")
    return value


def uuid(value):
    if not isinstance(value, str) or not re.fullmatch(UUID_PATTERN, value):
        fail(400, "INVALID_ID")
    return value.lower()


def channel(value):
    if value not in CHANNELS:
        fail(400, "INVALID_CHANNEL")
    return value


def session_id(token):
    try:
        encoded = token.split(".")[1]
        payload = parse_json(base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4)))
        return uuid(payload.get("session_id"))
    except Exception:
        fail(401, "LOGIN_REQUIRED")


def verify_token(token):
    # Supabase validates the token before any claim is decoded locally.
    with supa("auth/v1/user", bearer=token, public_key=True) as response:
        if not response.ok:
            fail(401, "LOGIN_REQUIRED")
        user = response.json()
    return {"uid": uuid(user.get("id")), "sid": session_id(token)}


def context(headers, hwid):
    authorization = headers.get("authorization")
    if not isinstance(authorization, str) or not authorization.startswith("Bearer "):
        fail(401, "LOGIN_REQUIRED")
    token = authorization[7:]
    identity = verify_token(token)
    profile = rpc("nf_check", {"p_uid": identity["uid"], "p_sid": identity["sid"], "p_hwid": hwid})
    return {**identity, "token": token, "hwid": hwid, "profile": profile}


def require_admin(ctx):
    if ctx["profile"]["role"] != "admin":
        fail(403, "ADMIN_REQUIRED")


def session_view(tokens, profile):
    expires = tokens.get("expires_at")
    if expires is None:
        expires = int(time.time()) + tokens["expires_in"]
    return {"accessToken": tokens["access_token"], "refreshToken": tokens["refresh_token"],
            "expiresAt": expires, "user": profile_view(profile)}


def revoke_auth(token):
    try:
        with supa("auth/v1/logout?scope=local", method="POST", bearer=token, public_key=True):
            pass
    except Exception:
        pass  # Database session grants are independently revoked.


def log_event(actor_id, action, details=None):
    db("nf_logs", method="POST", payload={"actor_id": actor_id, "action": action, "details": details or {}})


def repository():
    repo = env("GITHUB_REPO")
    if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repo):
        fail(500, "SERVER_CONFIG_ERROR")
    return repo


def github(path, binary=False):
    response = http_request("https://api.github.com/repos/" + repository() + "/" + path,
                            headers={"Authorization": "Bearer " + env("GITHUB_TOKEN"),
                                     "Accept": "application/octet-stream" if binary else "application/vnd.github+json",
                                     "X-GitHub-Api-Version": "2022-11-28", "User-Agent": "NeverFairLauncher"}, timeout=25)
    if response.status == 404:
        response.__exit__()
        fail(404, "GITHUB_NOT_FOUND")
    if not response.ok and response.status not in (302, 307):
        response.__exit__()
        fail(502, "GITHUB_ERROR")
    return response


def safe_download_url(value):
    try:
        url = urlsplit(value)
        allowed = url.hostname == "github.com" or (url.hostname or "").endswith(".githubusercontent.com")
        if url.scheme != "https" or url.username is not None or url.password is not None or not allowed:
            fail(502, "GITHUB_ERROR")
        if any(ord(character) < 32 for character in value) or "\\" in value:
            fail(502, "GITHUB_ERROR")
        return value
    except (TypeError, ValueError):
        fail(502, "GITHUB_ERROR")


def asset_hash(asset):
    digest = asset.get("digest")
    match = re.fullmatch(r"sha256:([a-fA-F0-9]{64})", digest) if isinstance(digest, str) else None
    if not match:
        fail(502, "MANIFEST_INVALID")
    return match[1].lower()


def safe_jar(name):
    return isinstance(name, str) and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]*\.jar", name) is not None and ".." not in name


def integer(value):
    return type(value) is int or (isinstance(value, float) and math.isfinite(value) and int(value) == value)


def valid_asset(asset, maximum):
    return (isinstance(asset, dict) and integer(asset.get("id")) and 0 < asset["id"] <= 9_007_199_254_740_991
            and integer(asset.get("size")) and 0 < asset["size"] <= maximum)


def verify_bytes(asset, data):
    expected = bytes.fromhex(asset_hash(asset))
    if len(data) != asset["size"] or not hmac.compare_digest(expected, hashlib.sha256(data).digest()):
        fail(502, "HASH_MISMATCH")


def read_download(url, maximum):
    # A fresh request with no GitHub credentials; validate every redirect hop.
    for _ in range(6):
        with http_request(safe_download_url(url), timeout=25) as response:
            if response.status in (301, 302, 303, 307, 308):
                url = response.headers.get("Location")
                continue
            if not response.ok:
                fail(502, "GITHUB_ERROR")
            return response.read(maximum)
    fail(502, "GITHUB_ERROR")


def read_asset(asset, maximum):
    if not valid_asset(asset, maximum):
        fail(502, "MANIFEST_INVALID")
    with github("releases/assets/" + str(asset["id"]), True) as response:
        if response.status in (302, 307):
            data = read_download(response.headers.get("Location"), maximum)
        else:
            data = response.read(maximum)
    verify_bytes(asset, data)
    return data


def asset_url(asset):
    with github("releases/assets/" + str(asset["id"]), True) as response:
        if response.status in (302, 307):
            return safe_download_url(response.headers.get("Location"))
        data = response.read(MAX_JAR_BYTES)
    verify_bytes(asset, data)
    object_path = str(asset["id"]) + "/" + asset_hash(asset) + "/" + asset["name"]
    with supa("storage/v1/object/nf-builds/" + object_path, method="POST", data=data,
              headers={"Content-Type": "application/octet-stream", "x-upsert": "true"}) as upload:
        if not upload.ok:
            fail(502, "STORAGE_ERROR")
    with supa("storage/v1/object/sign/nf-builds/" + object_path, method="POST", payload={"expiresIn": 60}) as signed:
        if not signed.ok:
            fail(502, "STORAGE_ERROR")
        location = signed.json().get("signedURL")
    if not isinstance(location, str) or not location.startswith("/object/sign/"):
        fail(502, "STORAGE_ERROR")
    return supabase_url() + "/storage/v1" + location


def version_key(version):
    parts = [int(part) for part in version.split(".")]
    return (*parts, *([0] * (3 - len(parts))), version)


def release_assets(release_id):
    assets = []
    for page in range(1, 21):
        with github(f"releases/{release_id}/assets?per_page=100&page={page}") as response:
            batch = response.json()
        if not isinstance(batch, list):
            fail(502, "GITHUB_ERROR")
        assets.extend(batch)
        if len(batch) < 100:
            return assets
    fail(502, "TOO_MANY_ASSETS")


def find_build(selected):
    tag = os.environ.get("GITHUB_TAG_" + selected.upper().replace(".", "_"), selected)
    try:
        with github("releases/tags/" + quote(tag, safe="")) as response:
            release = response.json()
    except ApiError as error:
        if error.code == "GITHUB_NOT_FOUND":
            return None
        raise
    if release.get("draft"):
        return None
    assets = release_assets(release["id"])
    candidates = []
    for asset in assets:
        match = re.fullmatch("neverfair-" + re.escape(selected) + "-v(" + VERSION_PATTERN + r")\.jar", asset.get("name", ""))
        if match:
            candidates.append((match[1], asset))
    if not candidates:
        return None
    version, asset = max(candidates, key=lambda item: version_key(item[0]))
    asset_hash(asset)
    return {"channel": selected, "version": version, "name": asset["name"], "assetId": asset["id"],
            "updatedAt": asset["updated_at"], "asset": asset, "assets": assets}


def prepare_build(selected):
    build = find_build(selected)
    if build is None:
        fail(404, "NO_BUILD")
    manifest_name = build["name"][:-4] + ".json"
    manifest_asset = next((asset for asset in build["assets"] if asset["name"] == manifest_name), None)
    if manifest_asset is None:
        fail(502, "MANIFEST_INVALID")
    try:
        manifest = parse_json(read_asset(manifest_asset, 65_536))
    except ApiError:
        raise
    except Exception:
        fail(502, "MANIFEST_INVALID")
    if (not isinstance(manifest, dict) or not isinstance(manifest.get("minecraftVersion"), str)
            or not re.fullmatch(r"[A-Za-z0-9._-]{1,60}", manifest["minecraftVersion"])
            or not isinstance(manifest.get("fabricLoader"), str)
            or not re.fullmatch(r"[A-Za-z0-9._+-]{1,60}", manifest["fabricLoader"])
            or not isinstance(manifest.get("dependencies"), list) or len(manifest["dependencies"]) > 31):
        fail(502, "MANIFEST_INVALID")
    names = [build["name"], *manifest["dependencies"]]
    if selected == "26.2" and manifest["minecraftVersion"] != "26.2":
        fail(502, "MANIFEST_INVALID")
    if not all(safe_jar(name) for name in names) or len(set(names)) != len(names):
        fail(502, "MANIFEST_INVALID")
    files = []
    for name in names:
        asset = next((asset for asset in build["assets"] if asset["name"] == name), None)
        if not valid_asset(asset, MAX_JAR_BYTES):
            fail(502, "MANIFEST_INVALID")
        files.append({"name": name, "sha256": asset_hash(asset), "size": asset["size"], "url": asset_url(asset)})
    return {"channel": selected, "version": build["version"], "assetId": build["assetId"],
            "minecraftVersion": manifest["minecraftVersion"], "fabricLoader": manifest["fabricLoader"], "files": files}


def offset(value):
    try:
        number = float(value) if value not in (None, "") else 0
    except (ValueError, TypeError, OverflowError):
        fail(400, "INVALID_OFFSET")
    if not integer(number) or not 0 <= number <= 10_000_000:
        fail(400, "INVALID_OFFSET")
    return int(number)


def dispatch(body, headers):
    action = body.get("action")
    if not isinstance(action, str):
        fail(400, "INVALID_ACTION")
    payload = body.get("payload", {})
    if not isinstance(payload, dict):
        fail(400, "INVALID_BODY")
    ip_header = headers.get("x-vercel-forwarded-for", headers.get("x-forwarded-for", "unknown"))
    if isinstance(ip_header, list):
        ip_header = ip_header[0]
    ip = ip_header.split(",")[0].strip()
    rate("ip:" + ip, 180, 60)

    if action == "register":
        rate("register:" + ip, 5, 3600)
        login = login_name(payload.get("login"))
        secret = password(payload.get("password"))
        if secret != payload.get("passwordRepeat"):
            fail(400, "PASSWORD_INVALID")
        with supa("auth/v1/admin/users", method="POST", payload={"email": login + "@users.neverfair.invalid",
                  "password": secret, "email_confirm": True, "user_metadata": {"login": login}}) as response:
            if not response.ok:
                fail(400, "REGISTRATION_FAILED")
        return {"ok": True}

    hwid = device(body.get("hwid"))
    if action == "modVerify":
        rate("mod:" + hwid, 30, 60)
        uid = uuid(payload["userId"]) if "userId" in payload else None
        profiles = db("nf_profiles?select=id,login,role,hwid_hash,last_login,created_at&hwid_hash=eq."
                      + hwid + ("&id=eq." + uid if uid else "") + "&limit=2")
        if not isinstance(profiles, list) or not profiles:
            fail(403, "HWID_MISMATCH")
        if len(profiles) != 1:
            fail(403, "LAUNCHER_REQUIRED")
        profile = profiles[0]
        if profile.get("hwid_hash") != hwid or (uid and profile["id"] != uid):
            fail(403, "HWID_MISMATCH")
        log_event(profile["id"], "mod_hwid_verified")
        return {"ok": True, "user": profile_view(profile)}

    if action in ("login", "refresh"):
        rate(("login:" if action == "login" else "refresh:") + ip, 20 if action == "login" else 40, 300)
        if action == "login":
            login = login_name(payload.get("login"))
            auth_payload = {"email": login + "@users.neverfair.invalid", "password": password(payload.get("password"))}
        else:
            token = payload.get("refreshToken")
            if not isinstance(token, str) or not 10 <= len(token) <= 4096:
                fail(401, "LOGIN_REQUIRED")
            auth_payload = {"refresh_token": token}
        grant = "password" if action == "login" else "refresh_token"
        with supa("auth/v1/token?grant_type=" + grant, method="POST", payload=auth_payload, public_key=True) as response:
            if not response.ok:
                fail(401, "INVALID_CREDENTIALS" if action == "login" else "LOGIN_REQUIRED")
            tokens = response.json()
        identity = verify_token(tokens["access_token"])
        try:
            # Refresh cannot bind an empty HWID or resurrect a reset session.
            profile = rpc("nf_bind" if action == "login" else "nf_check",
                          {"p_uid": identity["uid"], "p_sid": identity["sid"], "p_hwid": hwid})
            return session_view(tokens, profile)
        except Exception:
            revoke_auth(tokens["access_token"])
            raise

    ctx = context(headers, hwid)
    rate("user:" + ctx["uid"], 120, 60)
    if action == "logout":
        db("nf_sessions?session_id=eq." + ctx["sid"] + "&user_id=eq." + ctx["uid"], method="DELETE")
        revoke_auth(ctx["token"])
        log_event(ctx["uid"], "logout")
        return {"ok": True}
    if action == "catalog":
        with ThreadPoolExecutor(max_workers=4) as pool:
            builds = list(pool.map(find_build, CHANNELS))
        keys = ("channel", "version", "name", "assetId", "updatedAt")
        return {"user": profile_view(ctx["profile"]),
                "builds": [{key: build[key] for key in keys} for build in builds if build is not None]}
    if action == "prepare":
        selected = channel(payload.get("channel"))
        rate("prepare:" + ctx["uid"], 10, 60)
        plan = prepare_build(selected)
        # Recheck after potentially slow GitHub downloads in case an admin reset access.
        rpc("nf_check", {"p_uid": ctx["uid"], "p_sid": ctx["sid"], "p_hwid": ctx["hwid"]})
        log_event(ctx["uid"], "build_prepared", {"channel": selected, "version": plan["version"]})
        return plan
    if action == "event":
        selected = channel(payload.get("channel"))
        event = payload.get("eventName")
        if event not in ("launch_requested", "launch_exit"):
            fail(400, "INVALID_EVENT")
        version = payload.get("version")
        if not isinstance(version, str) or not re.fullmatch(VERSION_PATTERN, version):
            fail(400, "INVALID_VERSION")
        code = payload.get("exitCode")
        if code is not None and (not integer(code) or not -2_147_483_648 <= code <= 2_147_483_647):
            fail(400, "INVALID_EVENT")
        log_event(ctx["uid"], "client_" + event, {"channel": selected, "version": version, "exitCode": code})
        return {"ok": True}
    if action in ("adminUsers", "adminReset", "adminLogs"):
        require_admin(ctx)
        if action == "adminReset":
            rpc("nf_reset", {"p_uid": ctx["uid"], "p_sid": ctx["sid"], "p_hwid": ctx["hwid"],
                             "p_target": uuid(payload.get("userId"))})
            return {"ok": True}
        page = offset(payload.get("offset"))
        if action == "adminUsers":
            users = db("nf_profiles?select=id,login,role,hwid_hash,last_login&order=login.asc&offset=" + str(page) + "&limit=100")
            return {"users": [{**profile_view(user), "hwidSet": user.get("hwid_hash") is not None} for user in users]}
        logs = db("nf_logs?select=id,created_at,actor_id,target_id,action,details&order=id.desc&offset=" + str(page) + "&limit=100")
        return {"logs": logs}
    fail(400, "INVALID_ACTION")


def handle_api(body, headers=None, method="POST"):
    if method != "POST":
        return 405, {"error": "METHOD_NOT_ALLOWED"}
    try:
        if not isinstance(body, dict) or not body or len(json_bytes(body)) > MAX_BODY_BYTES:
            fail(400, "INVALID_BODY")
        return 200, dispatch(body, {key.lower(): value for key, value in (headers or {}).items()})
    except ApiError as error:
        return error.status, {"error": error.code}
    except Exception as error:
        # Never include exception text, URLs, credentials, request bodies or HWIDs.
        logging.error("NeverFair request failed: %s", type(error).__name__)
        return 500, {"error": "SERVER_ERROR"}


class handler(BaseHTTPRequestHandler):
    """File-based Vercel function: api/launcher.py -> /api/launcher."""

    def log_message(self, *_):
        pass  # Access URLs and query strings do not belong in application logs.

    def respond(self, status, body):
        data = json_bytes(body)
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        if status == 405:
            self.send_header("Allow", "POST")
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(data)

    def do_POST(self):
        try:
            lengths = self.headers.get_all("Content-Length", [])
            if len(lengths) != 1 or self.headers.get("Transfer-Encoding"):
                fail(400, "INVALID_BODY")
            length = int(lengths[0])
            if not 0 < length <= MAX_BODY_BYTES:
                fail(400, "INVALID_BODY")
            if self.headers.get("Content-Type", "").split(";")[0].strip().lower() != "application/json":
                fail(400, "INVALID_BODY")
            connection = getattr(self, "connection", None)
            if callable(getattr(connection, "settimeout", None)):
                connection.settimeout(15)
            raw = self.rfile.read(length)
            if len(raw) != length:
                fail(400, "INVALID_BODY")
            body = parse_json(raw)
        except ApiError as error:
            self.respond(error.status, {"error": error.code})
            return
        except (ValueError, UnicodeError, RecursionError, OSError):
            self.respond(400, {"error": "INVALID_BODY"})
            return
        status, result = handle_api(body, dict(self.headers))
        self.respond(status, result)

    def do_GET(self):
        self.respond(405, {"error": "METHOD_NOT_ALLOWED"})

    do_HEAD = do_GET
    do_PUT = do_GET
    do_DELETE = do_GET
    do_PATCH = do_GET
    do_OPTIONS = do_GET


if __name__ == "__main__":
    ThreadingHTTPServer(("127.0.0.1", 8000), handler).serve_forever()
