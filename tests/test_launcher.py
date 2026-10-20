"""Offline regression suite: real HTTP adapter, fake upstream services, no accounts."""

import base64
import hashlib
import hmac
import http.client
import importlib.util
import io
import json
import os
from email.message import Message
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import threading
import unittest
from unittest.mock import patch
from urllib.parse import parse_qs, urlsplit

SPEC = importlib.util.spec_from_file_location("neverfair_launcher", Path(__file__).parents[1] / "api" / "launcher.py")
api = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(api)

UID = "aaaaaaaa-1111-4111-8111-111111111111"
SID = "bbbbbbbb-2222-4222-8222-222222222222"
HARDWARE = "a" * 64
PEPPER = "test-only-device-pepper"
DEVICE = hmac.new(PEPPER.encode(), ("device:" + HARDWARE).encode(), hashlib.sha256).hexdigest()
ENV = {"SUPABASE_URL": "https://supabase.test", "SUPABASE_ANON_KEY": "test-anon",
       "SUPABASE_SERVICE_ROLE_KEY": "test-server", "HWID_PEPPER": PEPPER,
       "GITHUB_REPO": "example/neverfair", "GITHUB_TOKEN": "test-github"}


def jwt(payload):
    def encode(value):
        return base64.urlsafe_b64encode(api.json_bytes(value)).decode().rstrip("=")
    return encode({"alg": "test-only"}) + "." + encode(payload) + ".test-signature"


TOKEN = jwt({"session_id": SID, "sub": UID})


def response(body=None, status=200, headers=None, raw=None):
    stream = io.BytesIO(api.json_bytes(body) if raw is None else raw)
    stream.code = status
    stream.headers = Message()
    for key, value in (headers or {}).items():
        stream.headers[key] = value
    return api.Response(stream)


class Upstream:
    def __init__(self):
        self.profile = {"id": UID, "login": "test_user", "role": "user", "hwid_hash": DEVICE,
                        "last_login": None, "created_at": "2026-01-01T00:00:00Z"}
        self.tokens = {"access_token": TOKEN, "refresh_token": "test-refresh-token-long", "expires_at": 2_000_000_000,
                       "expires_in": 3600, "user": {"id": UID}}
        self.calls = []
        self.logs = []
        self.active = True
        self.allowed = True
        self.auth_ok = True
        self.database_error = None
        self.mod_profiles = None
        self.direct = set()
        self.bad_download = None
        self.storage_failure = None
        self.checks = 0
        self.reset_during_prepare = False
        self.blobs = {}
        self.releases = {}
        self.assets = {}
        for index, channel in enumerate(api.CHANNELS, 1):
            release = {"id": index, "draft": False}
            self.releases[channel] = release
            items = []
            for asset_id, name, data in [
                (index * 100 + 1, f"neverfair-{channel}-v1.jar", b"old-mod-jar"),
                (index * 100 + 2, f"neverfair-{channel}-v2.jar", b"new-mod-jar"),
                (index * 100 + 3, f"neverfair-{channel}-v2.json", api.json_bytes(
                    {"minecraftVersion": "26.2" if channel == "26.2" else "1.21.11", "fabricLoader": "0.19.4", "dependencies": ["extra-lib.jar"]})),
                (index * 100 + 4, "extra-lib.jar", b"dependency-jar")
            ]:
                self.blobs[asset_id] = data
                items.append({"id": asset_id, "name": name, "size": len(data),
                              "digest": "sha256:" + hashlib.sha256(data).hexdigest(), "updated_at": "2026-01-01T00:00:00Z"})
            self.assets[index] = items

    def fetch(self, url, *, method="GET", headers=None, data=None, timeout=30):
        self.calls.append({"url": url, "method": method, "headers": headers or {}, "data": data})
        parsed = urlsplit(url)
        path = parsed.path
        payload = api.parse_json(data) if data is not None and (headers or {}).get("Content-Type") != "application/octet-stream" else None
        if parsed.hostname == "supabase.test":
            expected = "test-anon" if path in ("/auth/v1/user", "/auth/v1/token", "/auth/v1/logout") else "test-server"
            if headers.get("apikey") != expected:
                raise AssertionError("Wrong server credential scope")
            if path == "/rest/v1/rpc/nf_rate":
                return response(self.allowed)
            if path == "/auth/v1/admin/users":
                return response({"id": UID})
            if path == "/auth/v1/token":
                return response(self.tokens if self.auth_ok else {}, status=200 if self.auth_ok else 401)
            if path == "/auth/v1/user":
                return response({"id": UID}, status=200 if self.auth_ok else 401)
            if path == "/auth/v1/logout":
                return response(raw=b"", status=204)
            if self.database_error:
                return response({"message": self.database_error}, status=400)
            if path == "/rest/v1/rpc/nf_bind":
                if self.profile["hwid_hash"] not in (None, payload["p_hwid"]):
                    return response({"message": "HWID_MISMATCH"}, status=403)
                self.profile["hwid_hash"] = payload["p_hwid"]
                self.active = True
                return response(self.profile)
            if path == "/rest/v1/rpc/nf_check":
                self.checks += 1
                if not self.active or (self.reset_during_prepare and self.checks > 1) or self.profile["hwid_hash"] != payload["p_hwid"]:
                    return response({"message": "SESSION_REVOKED"}, status=403)
                return response(self.profile)
            if path == "/rest/v1/rpc/nf_reset":
                self.active = False
                self.profile["hwid_hash"] = None
                return response(raw=b"", status=204)
            if path == "/rest/v1/nf_sessions" and method == "DELETE":
                self.active = False
                return response(raw=b"", status=204)
            if path == "/rest/v1/nf_profiles":
                query = parse_qs(parsed.query)
                if "hwid_hash" in query:
                    if self.mod_profiles is not None:
                        return response(self.mod_profiles)
                    profiles = [self.profile] if self.profile["hwid_hash"] == query["hwid_hash"][0][3:] else []
                    if query.get("id", ["eq." + UID])[0] != "eq." + UID:
                        profiles = []
                    return response(profiles)
                return response([self.profile])
            if path == "/rest/v1/nf_logs":
                if method == "POST":
                    self.logs.append(payload)
                    return response(raw=b"", status=201)
                return response(self.logs)
            if path.startswith("/storage/v1/object/sign/"):
                return response({"signedURL": "https://wrong.test" if self.storage_failure == "url" else "/object/sign/nf-builds/test?token=mock"},
                                status=500 if self.storage_failure == "sign" else 200)
            if path.startswith("/storage/v1/object/nf-builds/"):
                return response({}, status=500 if self.storage_failure == "upload" else 201)
        if parsed.hostname == "api.github.com":
            if headers.get("Authorization") != "Bearer test-github":
                raise AssertionError("Missing GitHub credential")
            suffix = path.removeprefix("/repos/example/neverfair/")
            if suffix.startswith("releases/tags/"):
                release = self.releases.get(suffix.split("/")[-1])
                return response(release or {}, status=200 if release else 404)
            if suffix.startswith("releases/assets/"):
                asset_id = int(suffix.split("/")[-1])
                if asset_id in self.direct:
                    return response(raw=self.blobs[asset_id])
                location = self.bad_download or f"https://release-assets.githubusercontent.com/{asset_id}"
                return response(status=302, headers={"Location": location}, raw=b"")
            if suffix.endswith("/assets"):
                return response(self.assets[int(suffix.split("/")[1])])
        if parsed.hostname == "release-assets.githubusercontent.com":
            if headers:
                raise AssertionError("Credentials forwarded to download host")
            return response(raw=self.blobs[int(path[1:])])
        raise AssertionError("Unexpected upstream operation")


class BackendFixture(unittest.TestCase):
    def setUp(self):
        self.upstream = Upstream()
        self.environment = patch.dict(os.environ, ENV, clear=True)
        self.environment.start()
        self.transport = patch.object(api, "http_request", side_effect=self.upstream.fetch)
        self.transport.start()
        self.addCleanup(self.transport.stop)
        self.addCleanup(self.environment.stop)

    def call(self, action, payload=None, *, authenticated=True, hwid=HARDWARE):
        headers = {"Authorization": "Bearer " + TOKEN} if authenticated else {}
        return api.handle_api({"action": action, "hwid": hwid, "payload": payload or {}}, headers)

    def error(self, status, code, action, payload=None, **kwargs):
        self.assertEqual(self.call(action, payload, **kwargs), (status, {"error": code}))


class BackendTests(BackendFixture):
    def test_registration_normalizes_login_and_uses_server_only_key(self):
        self.assertEqual(self.call("register", {"login": " TEST_User ", "password": "test-password-123", "passwordRepeat": "test-password-123"}), (200, {"ok": True}))
        posted = self.upstream.calls[-1]
        self.assertEqual(api.parse_json(posted["data"])["email"], "test_user@users.neverfair.invalid")
        self.assertEqual(posted["headers"]["apikey"], "test-server")

    def test_registration_validation(self):
        for payload, code in [({"login": "x", "password": "test-password-123"}, "LOGIN_INVALID"),
                              ({"login": "valid", "password": "short"}, "PASSWORD_INVALID"),
                              ({"login": "valid", "password": "test-password-123", "passwordRepeat": "different"}, "PASSWORD_INVALID")]:
            with self.subTest(code=code):
                self.error(400, code, "register", payload)

    def test_password_uses_existing_dotnet_utf16_length(self):
        self.assertEqual(api.password("😀" * 6), "😀" * 6)
        with self.assertRaises(api.ApiError):
            api.password("😀" * 65)

    def test_login_binds_same_device_hmac_and_returns_unchanged_dto(self):
        self.upstream.profile["hwid_hash"] = None
        status, body = self.call("login", {"login": "test_user", "password": "test-password-123"})
        self.assertEqual(status, 200)
        self.assertEqual(body["accessToken"], TOKEN)
        self.assertEqual(body["refreshToken"], self.upstream.tokens["refresh_token"])
        self.assertEqual(body["expiresAt"], 2_000_000_000)
        self.assertEqual(self.upstream.profile["hwid_hash"], DEVICE)
        self.assertNotIn("hwid_hash", body["user"])

    def test_wrong_device_login_revokes_auth_session(self):
        self.upstream.profile["hwid_hash"] = "0" * 64
        self.error(403, "HWID_MISMATCH", "login", {"login": "test_user", "password": "test-password-123"})
        self.assertTrue(any("/auth/v1/logout" in call["url"] for call in self.upstream.calls))

    def test_bad_credentials(self):
        self.upstream.auth_ok = False
        self.error(401, "INVALID_CREDENTIALS", "login", {"login": "test_user", "password": "test-password-123"})

    def test_refresh_checks_session_without_binding(self):
        self.assertEqual(self.call("refresh", {"refreshToken": "test-refresh-token-long"})[0], 200)
        self.assertFalse(any("nf_bind" in call["url"] for call in self.upstream.calls))
        self.upstream.active = False
        self.error(403, "SESSION_REVOKED", "refresh", {"refreshToken": "test-refresh-token-long"})

    def test_refresh_after_hardware_reset_never_rebinds(self):
        self.upstream.profile["hwid_hash"] = None
        self.error(403, "SESSION_REVOKED", "refresh", {"refreshToken": "test-refresh-token-long"})
        self.assertIsNone(self.upstream.profile["hwid_hash"])

    def test_refresh_validation(self):
        for token in (None, "short", 123, "x" * 4097):
            self.error(401, "LOGIN_REQUIRED", "refresh", {"refreshToken": token})

    def test_remote_auth_validation_precedes_claims_and_db_access(self):
        self.upstream.auth_ok = False
        self.error(401, "LOGIN_REQUIRED", "catalog")
        self.assertFalse(any("nf_check" in call["url"] for call in self.upstream.calls))

    def test_catalog_requires_bearer(self):
        self.error(401, "LOGIN_REQUIRED", "catalog", authenticated=False)

    def test_catalog_all_channels_newest_version(self):
        status, body = self.call("catalog")
        self.assertEqual(status, 200)
        self.assertEqual([item["channel"] for item in body["builds"]], list(api.CHANNELS))
        self.assertEqual([item["version"] for item in body["builds"]], ["2"] * len(api.CHANNELS))
        self.assertNotIn("asset", body["builds"][0])

    def test_catalog_skips_missing_and_draft_releases(self):
        del self.upstream.releases["beta"]
        self.upstream.releases["alpha"]["draft"] = True
        self.assertEqual(len(self.call("catalog")[1]["builds"]), len(api.CHANNELS) - 2)

    def test_26_2_channel_uses_separate_manifest_and_tag_variable(self):
        os.environ["GITHUB_TAG_26_2"] = "26.2-v2"
        self.upstream.releases["26.2-v2"] = self.upstream.releases.pop("26.2")
        status, plan = self.call("prepare", {"channel": "26.2"})
        self.assertEqual(status, 200)
        self.assertEqual(plan["minecraftVersion"], "26.2")
        self.assertEqual(plan["files"][0]["name"], "neverfair-26.2-v2.jar")

    def test_26_2_rejects_old_minecraft_manifest(self):
        manifest = api.json_bytes({"minecraftVersion": "1.21.11", "fabricLoader": "0.19.4", "dependencies": []})
        self.upstream.blobs[403] = manifest
        self.upstream.assets[4][2]["size"] = len(manifest)
        self.upstream.assets[4][2]["digest"] = "sha256:" + hashlib.sha256(manifest).hexdigest()
        self.error(502, "MANIFEST_INVALID", "prepare", {"channel": "26.2"})

    def test_26_2_asset_pattern_treats_dot_literally(self):
        for asset in self.upstream.assets[4]:
            asset["name"] = asset["name"].replace("26.2", "26x2")
        self.error(404, "NO_BUILD", "prepare", {"channel": "26.2"})

    def test_prepare_manifest_dependencies_and_no_credentials_in_download_request(self):
        status, plan = self.call("prepare", {"channel": "alpha"})
        self.assertEqual(status, 200)
        self.assertEqual(plan["minecraftVersion"], "1.21.11")
        self.assertEqual(plan["fabricLoader"], "0.19.4")
        self.assertEqual([item["name"] for item in plan["files"]], ["neverfair-alpha-v2.jar", "extra-lib.jar"])
        self.assertEqual(self.upstream.checks, 2)
        self.assertEqual(self.upstream.logs[-1]["action"], "build_prepared")

    def test_prepare_rechecks_reset_before_returning_urls(self):
        self.upstream.reset_during_prepare = True
        self.error(403, "SESSION_REVOKED", "prepare", {"channel": "alpha"})
        self.assertFalse(self.upstream.logs)

    def test_prepare_rejects_missing_and_tampered_manifest(self):
        self.upstream.blobs[303] = b"tampered"
        self.error(502, "HASH_MISMATCH", "prepare", {"channel": "alpha"})

    def test_prepare_rejects_traversal_duplicate_and_non_jar_dependencies(self):
        for dependencies in (["../evil.jar"], ["extra-lib.jar", "extra-lib.jar"], ["no.exe"], [None]):
            with self.subTest(dependencies=dependencies):
                manifest = api.json_bytes({"minecraftVersion": "1.21.11", "fabricLoader": "0.19.4", "dependencies": dependencies})
                self.upstream.blobs[303] = manifest
                asset = self.upstream.assets[3][2]
                asset["size"] = len(manifest)
                asset["digest"] = "sha256:" + hashlib.sha256(manifest).hexdigest()
                self.error(502, "MANIFEST_INVALID", "prepare", {"channel": "alpha"})

    def test_untrusted_redirect_is_rejected(self):
        self.upstream.bad_download = "https://evil.test/steal"
        self.error(502, "GITHUB_ERROR", "prepare", {"channel": "alpha"})
        self.assertFalse(any("evil.test" in call["url"] for call in self.upstream.calls))

    def test_storage_fallback_uploads_verified_bytes_and_returns_private_url(self):
        self.upstream.direct.add(302)
        status, plan = self.call("prepare", {"channel": "alpha"})
        self.assertEqual(status, 200)
        self.assertTrue(plan["files"][0]["url"].startswith("https://supabase.test/storage/v1/object/sign/"))
        uploads = [call for call in self.upstream.calls if "/storage/v1/object/nf-builds/" in call["url"]]
        self.assertEqual(uploads[0]["data"], self.upstream.blobs[302])

    def test_storage_fallback_errors_are_closed(self):
        self.upstream.direct.add(302)
        for failure in ("upload", "sign", "url"):
            self.upstream.storage_failure = failure
            self.error(502, "STORAGE_ERROR", "prepare", {"channel": "alpha"})

    def test_mod_verify_without_launcher_token_and_without_rebinding(self):
        status, body = self.call("modVerify", {"userId": UID}, authenticated=False)
        self.assertEqual(status, 200)
        self.assertEqual(body["user"]["id"], UID)
        self.assertNotIn(DEVICE, json.dumps(body))
        self.assertTrue(all("nf_bind" not in call["url"] and "/auth/" not in call["url"] for call in self.upstream.calls))

    def test_mod_verify_rejects_reset_missing_other_user_and_wrong_hardware(self):
        self.upstream.profile["hwid_hash"] = None
        self.error(403, "HWID_MISMATCH", "modVerify", authenticated=False)
        self.upstream.profile["hwid_hash"] = DEVICE
        self.error(403, "HWID_MISMATCH", "modVerify", {"userId": SID}, authenticated=False)
        self.error(403, "HWID_MISMATCH", "modVerify", hwid="b" * 64, authenticated=False)

    def test_mod_verify_ambiguous_or_invalid_profile_is_denied(self):
        self.upstream.mod_profiles = [self.upstream.profile, self.upstream.profile]
        self.error(403, "LAUNCHER_REQUIRED", "modVerify", authenticated=False)
        self.upstream.mod_profiles = [{**self.upstream.profile, "hwid_hash": None}]
        self.error(403, "HWID_MISMATCH", "modVerify", authenticated=False)

    def test_mod_verify_uses_same_pinned_hmac_as_node_backend(self):
        self.assertEqual(api.device(HARDWARE), DEVICE)
        self.call("modVerify", {"userId": UID})
        lookup = next(call for call in self.upstream.calls if "/nf_profiles?" in call["url"])
        self.assertIn("hwid_hash=eq." + DEVICE, lookup["url"])

    def test_regular_user_cannot_use_admin_routes(self):
        for action in ("adminUsers", "adminReset", "adminLogs"):
            self.error(403, "ADMIN_REQUIRED", action)

    def test_admin_users_omit_hash_and_report_binding(self):
        self.upstream.profile["role"] = "admin"
        status, body = self.call("adminUsers", {"offset": 100})
        self.assertEqual(status, 200)
        self.assertTrue(body["users"][0]["hwidSet"])
        self.assertNotIn("hwid_hash", body["users"][0])

    def test_admin_reset_calls_atomic_rpc_and_revokes_existing_access(self):
        self.upstream.profile["role"] = "admin"
        self.assertEqual(self.call("adminReset", {"userId": UID}), (200, {"ok": True}))
        reset = next(call for call in self.upstream.calls if "rpc/nf_reset" in call["url"])
        self.assertEqual(api.parse_json(reset["data"]), {"p_uid": UID, "p_sid": SID, "p_hwid": DEVICE, "p_target": UID})
        self.error(403, "SESSION_REVOKED", "adminLogs")

    def test_admin_logs_and_offset_validation(self):
        self.upstream.profile["role"] = "admin"
        self.assertEqual(self.call("adminLogs")[0], 200)
        for offset in (-1, 1.5, 10_000_001, "bad", []):
            self.error(400, "INVALID_OFFSET", "adminLogs", {"offset": offset})

    def test_telemetry_and_exit_code_contract(self):
        self.assertEqual(self.call("event", {"channel": "alpha", "version": "0.2.7", "eventName": "launch_exit", "exitCode": -1}), (200, {"ok": True}))
        self.assertEqual(self.upstream.logs[-1]["action"], "client_launch_exit")
        for value in (True, "0", 1.5, 2**50, 10**400):
            self.error(400, "INVALID_EVENT", "event", {"channel": "alpha", "version": "1", "eventName": "launch_exit", "exitCode": value})

    def test_logout_removes_grant(self):
        self.assertEqual(self.call("logout"), (200, {"ok": True}))
        self.error(403, "SESSION_REVOKED", "catalog")

    def test_rate_limit_does_not_continue_to_auth_or_github(self):
        self.upstream.allowed = False
        self.error(429, "RATE_LIMITED", "catalog")
        self.assertEqual(len(self.upstream.calls), 1)

    def test_invalid_hwid_id_and_action(self):
        self.error(400, "HWID_MISMATCH", "modVerify", hwid="A" * 64)
        self.error(400, "INVALID_ID", "modVerify", {"userId": "bad"})
        self.error(400, "INVALID_ACTION", "unknown")

    def test_database_errors_do_not_expose_upstream_details(self):
        self.upstream.database_error = "private table name"
        self.error(500, "DATABASE_ERROR", "modVerify")

    def test_network_exception_does_not_log_tokens_or_request_body(self):
        with patch.object(api, "http_request", side_effect=OSError("private-password-and-token")):
            with self.assertLogs(level="ERROR") as captured:
                self.error(500, "SERVER_ERROR", "catalog")
            self.assertNotIn("private-password-and-token", " ".join(captured.output))

    def test_missing_server_configuration(self):
        del os.environ["HWID_PEPPER"]
        self.error(500, "SERVER_CONFIG_ERROR", "modVerify")

    def test_asset_size_cap_matches_large_mod(self):
        self.assertTrue(api.valid_asset({"id": 1, "size": 98_787_366}, api.MAX_JAR_BYTES))
        self.assertFalse(api.valid_asset({"id": 1, "size": api.MAX_JAR_BYTES + 1}, api.MAX_JAR_BYTES))

    def test_bounded_download_rejects_oversized_response(self):
        with response(raw=b"123456") as reply:
            with self.assertRaises(api.ApiError) as caught:
                reply.read(5)
            self.assertEqual(caught.exception.code, "ASSET_TOO_LARGE")

    def test_download_hosts_and_embedded_credentials(self):
        for url in ("http://github.com/file", "https://github.com.evil.test/file", "https://u:p@github.com/file",
                    "https://github.com/\nfile", "https://github.com\\evil.test/file", None):
            with self.subTest(url=url), self.assertRaises(api.ApiError):
                api.safe_download_url(url)


class HttpAdapterTests(BackendFixture):
    # Run HTTP-specific tests against the same Vercel handler, listening only on loopback.
    def setUp(self):
        super().setUp()
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), api.handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.addCleanup(self.server.server_close)
        self.addCleanup(self.server.shutdown)

    def send(self, method="POST", data=None, headers=None):
        connection = http.client.HTTPConnection("127.0.0.1", self.server.server_port, timeout=5)
        try:
            connection.request(method, "/api/launcher", data, headers or {})
            reply = connection.getresponse()
            return reply.status, dict(reply.headers), reply.read()
        finally:
            connection.close()

    def test_http_json_request_and_response(self):
        status, headers, data = self.send(data=api.json_bytes({"action": "modVerify", "hwid": HARDWARE, "payload": {}}),
                                          headers={"Content-Type": "application/json; charset=utf-8"})
        self.assertEqual(status, 200)
        self.assertEqual(headers["Cache-Control"], "no-store")
        self.assertEqual(headers["X-Content-Type-Options"], "nosniff")
        self.assertEqual(api.parse_json(data)["user"]["id"], UID)

    def test_http_wrong_methods_return_json(self):
        for method in ("GET", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"):
            status, headers, data = self.send(method)
            self.assertEqual(status, 405)
            self.assertEqual(headers["Allow"], "POST")
            if method != "HEAD":
                self.assertEqual(api.parse_json(data), {"error": "METHOD_NOT_ALLOWED"})

    def test_http_invalid_utf8_json_types_and_nan(self):
        for data in (b"{", b"\xff", b"null", b"[]", b'{}', b'{"action":"modVerify","payload":null}', b'{"x":NaN}'):
            self.assertEqual(self.send(data=data, headers={"Content-Type": "application/json"})[0], 400)

    def test_http_body_limit_and_content_type(self):
        self.assertEqual(self.send(data=b"x" * (api.MAX_BODY_BYTES + 1), headers={"Content-Type": "application/json"})[0], 400)
        self.assertEqual(self.send(data=b"{}", headers={"Content-Type": "text/plain"})[0], 400)


class TransportTests(unittest.TestCase):
    def setUp(self):
        self.requests = []
        requests = self.requests
        class LocalUpstream(BaseHTTPRequestHandler):
            def log_message(self, *_): pass
            def do_GET(self):
                requests.append(self.path)
                if self.path == "/redirect":
                    self.send_response(302)
                    self.send_header("Location", "/private-target")
                    self.send_header("Content-Length", "0")
                    self.end_headers()
                else:
                    data = b'{"ok":true}'
                    self.send_response(200 if self.path == "/ok" else 403)
                    self.send_header("Content-Length", str(len(data)))
                    self.end_headers()
                    self.wfile.write(data)
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), LocalUpstream)
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        self.addCleanup(self.server.server_close)
        self.addCleanup(self.server.shutdown)
        self.url = "http://127.0.0.1:" + str(self.server.server_port)

    def test_real_transport_never_follows_authenticated_redirect(self):
        with api.http_request(self.url + "/redirect", headers={"Authorization": "Bearer test-only"}) as reply:
            self.assertEqual(reply.status, 302)
            self.assertEqual(reply.headers.get("Location"), "/private-target")
        self.assertEqual(self.requests, ["/redirect"])

    def test_real_transport_handles_success_and_http_error_streams(self):
        for path, status in (("/ok", 200), ("/forbidden", 403)):
            with api.http_request(self.url + path) as reply:
                self.assertEqual(reply.status, status)
                self.assertEqual(reply.json(), {"ok": True})


if __name__ == "__main__":
    unittest.main()
