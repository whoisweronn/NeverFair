import type {
    VercelRequest,
    VercelResponse
} from "@vercel/node";

import {
    createHash,
    createHmac,
    timingSafeEqual
} from "node:crypto";

type Channel = "release" | "beta" | "alpha";

type Profile = {
    id: string;
    login: string;
    role: "user" | "admin";
    hwid_hash: string | null;
    last_login: string | null;
};

type AuthTokens = {
    access_token: string;
    refresh_token: string;
    expires_in: number;
    expires_at?: number;
    user: {
        id: string;
    };
};

type Asset = {
    id: number;
    name: string;
    size: number;
    digest: string | null;
    updated_at: string;
};

type Release = {
    id: number;
    draft: boolean;
    assets?: Asset[];
};

type Build = {
    channel: Channel;
    version: string;
    name: string;
    assetId: number;
    updatedAt: string;
    asset: Asset;
    assets: Asset[];
};

type Context = {
    uid: string;
    sid: string;
    token: string;
    hwid: string;
    profile: Profile;
};

class ApiError extends Error {
    constructor(
        public status: number,
        public code: string
    ) {
        super(code);
    }
}

function fail(status: number, code: string): never {
    throw new ApiError(status, code);
}

function env(name: string): string {
    const value = process.env[name];

    if (!value) {
        fail(500, "SERVER_CONFIG_ERROR");
    }

    return value!;
}

function supabaseUrl(): string {
    return env("SUPABASE_URL").replace(/\/$/, "");
}

function hash(value: string): string {
    return createHmac("sha256", env("HWID_PEPPER"))
        .update(value)
        .digest("hex");
}

function profileView(profile: Profile) {
    return {
        id: profile.id,
        login: profile.login,
        role: profile.role,
        lastLogin: profile.last_login
    };
}

function headers(
    key: string,
    bearer: string = key
): Record<string, string> {
    return {
        apikey: key,
        Authorization: `Bearer ${bearer}`,
        "Content-Type": "application/json"
    };
}

async function supa(
    path: string,
    init: RequestInit = {},
    bearer?: string,
    publicKey = false
): Promise<Response> {
    const key = env(
        publicKey
            ? "SUPABASE_ANON_KEY"
            : "SUPABASE_SERVICE_ROLE_KEY"
    );

    return fetch(`${supabaseUrl()}/${path}`, {
        ...init,
        headers: {
            ...headers(key, bearer ?? key),
            ...init.headers
        },
        signal: AbortSignal.timeout(30_000)
    });
}

async function db(
    path: string,
    init: RequestInit = {}
): Promise<any> {
    const response = await supa(`rest/v1/${path}`, init);

    if (!response.ok) {
        let message = "";

        try {
            const body = await response.json() as {
                message?: string;
            };

            message = body.message ?? "";
        } catch {
            // Upstream bodies are never returned to the client.
        }

        for (const code of [
            "HWID_MISMATCH",
            "SESSION_REVOKED",
            "ADMIN_REQUIRED",
            "USER_NOT_FOUND"
        ]) {
            if (message.includes(code)) {
                fail(
                    code === "USER_NOT_FOUND" ? 404 : 403,
                    code
                );
            }
        }

        fail(500, "DATABASE_ERROR");
    }

    const text = await response.text();
    return text ? JSON.parse(text) : null;
}

async function rpc(
    name: string,
    payload: Record<string, unknown>
): Promise<any> {
    return db(`rpc/${name}`, {
        method: "POST",
        body: JSON.stringify(payload)
    });
}

async function rate(
    key: string,
    limit: number,
    seconds: number
): Promise<void> {
    const allowed = await rpc("nf_rate", {
        p_key: hash(`rate:${key}`),
        p_limit: limit,
        p_seconds: seconds
    });

    if (allowed !== true) {
        fail(429, "RATE_LIMITED");
    }
}

function device(value: unknown): string {
    if (
        typeof value !== "string" ||
        !/^[a-f0-9]{64}$/.test(value)
    ) {
        fail(400, "HWID_MISMATCH");
    }

    return hash(`device:${value}`);
}

function loginName(value: unknown): string {
    const login =
        typeof value === "string"
            ? value.trim().toLowerCase()
            : "";

    if (!/^[a-z0-9_]{3,24}$/.test(login)) {
        fail(400, "LOGIN_INVALID");
    }

    return login;
}

function password(value: unknown): string {
    if (
        typeof value !== "string" ||
        value.length < 12 ||
        value.length > 128
    ) {
        fail(400, "PASSWORD_INVALID");
    }

    return value;
}

function uuid(value: unknown): string {
    if (
        typeof value !== "string" ||
        !/^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/i
            .test(value)
    ) {
        fail(400, "INVALID_ID");
    }

    return value;
}

function channel(value: unknown): Channel {
    if (
        value !== "release" &&
        value !== "beta" &&
        value !== "alpha"
    ) {
        fail(400, "INVALID_CHANNEL");
    }

    return value;
}

function sessionId(token: string): string {
    try {
        const payload = JSON.parse(
            Buffer.from(
                token.split(".")[1],
                "base64url"
            ).toString("utf8")
        ) as {
            session_id?: string;
        };

        return uuid(payload.session_id);
    } catch {
        fail(401, "LOGIN_REQUIRED");
    }
}

async function verifyToken(
    token: string
): Promise<{ uid: string; sid: string }> {
    // Decoding below is used only after server-side Auth validation.
    const response = await supa(
        "auth/v1/user",
        {},
        token,
        true
    );

    if (!response.ok) {
        fail(401, "LOGIN_REQUIRED");
    }

    const user = await response.json() as {
        id: string;
    };

    return {
        uid: uuid(user.id),
        sid: sessionId(token)
    };
}

async function context(
    req: VercelRequest,
    hwid: string
): Promise<Context> {
    const authorization = req.headers.authorization;

    if (
        typeof authorization !== "string" ||
        !authorization.startsWith("Bearer ")
    ) {
        fail(401, "LOGIN_REQUIRED");
    }

    const token = authorization.slice(7);
    const identity = await verifyToken(token);

    const profile = await rpc("nf_check", {
        p_uid: identity.uid,
        p_sid: identity.sid,
        p_hwid: hwid
    }) as Profile;

    return {
        ...identity,
        token,
        hwid,
        profile
    };
}

function requireAdmin(ctx: Context): void {
    if (ctx.profile.role !== "admin") {
        fail(403, "ADMIN_REQUIRED");
    }
}

function sessionView(
    tokens: AuthTokens,
    profile: Profile
) {
    return {
        accessToken: tokens.access_token,
        refreshToken: tokens.refresh_token,
        expiresAt:
            tokens.expires_at ??
            Math.floor(Date.now() / 1000) + tokens.expires_in,
        user: profileView(profile)
    };
}

async function revokeAuth(token: string): Promise<void> {
    try {
        await supa(
            "auth/v1/logout?scope=local",
            { method: "POST" },
            token,
            true
        );
    } catch {
        // Launcher grants are independently revoked in the database.
    }
}

async function logEvent(
    actorId: string,
    action: string,
    details: Record<string, unknown> = {}
): Promise<void> {
    await db("nf_logs", {
        method: "POST",
        body: JSON.stringify({
            actor_id: actorId,
            action,
            details
        })
    });
}

function repository(): string {
    const repo = env("GITHUB_REPO");

    if (!/^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/.test(repo)) {
        fail(500, "SERVER_CONFIG_ERROR");
    }

    return repo;
}

async function github(
    path: string,
    binary = false
): Promise<Response> {
    const response = await fetch(
        `https://api.github.com/repos/${repository()}/${path}`,
        {
            headers: {
                Authorization: `Bearer ${env("GITHUB_TOKEN")}`,
                Accept: binary
                    ? "application/octet-stream"
                    : "application/vnd.github+json",
                "X-GitHub-Api-Version": "2022-11-28",
                "User-Agent": "NeverFairLauncher"
            },
            redirect: "manual",
            cache: "no-store",
            signal: AbortSignal.timeout(25_000)
        }
    );

    if (response.status === 404) {
        fail(404, "GITHUB_NOT_FOUND");
    }

    if (
        !response.ok &&
        response.status !== 302 &&
        response.status !== 307
    ) {
        fail(502, "GITHUB_ERROR");
    }

    return response;
}

function safeDownloadUrl(value: string): string {
    const url = new URL(value);

    const allowed =
        url.hostname === "github.com" ||
        url.hostname.endsWith(".githubusercontent.com");

    if (
        url.protocol !== "https:" ||
        url.username ||
        url.password ||
        !allowed
    ) {
        fail(502, "GITHUB_ERROR");
    }

    return url.toString();
}

function assetHash(asset: Asset): string {
    const match =
        /^sha256:([a-f0-9]{64})$/i.exec(
            asset.digest ?? ""
        );

    if (!match) {
        fail(502, "MANIFEST_INVALID");
    }

    return match![1].toLowerCase();
}

function safeJar(name: string): boolean {
    return (
        /^[A-Za-z0-9][A-Za-z0-9._-]*\.jar$/.test(name) &&
        !name.includes("..")
    );
}

async function boundedBytes(
    response: Response,
    maximum: number
): Promise<Buffer> {
    if (!response.body) {
        fail(502, "GITHUB_ERROR");
    }

    const reader = response.body!.getReader();
    const parts: Buffer[] = [];

    let size = 0;

    try {
        for (; ;) {
            const result = await reader.read();

            if (result.done) {
                break;
            }

            size += result.value.length;

            if (size > maximum) {
                await reader.cancel();
                fail(502, "ASSET_TOO_LARGE");
            }

            parts.push(Buffer.from(result.value));
        }
    } finally {
        reader.releaseLock();
    }

    return Buffer.concat(parts);
}

function verifyBytes(
    asset: Asset,
    bytes: Buffer
): void {
    const expected = Buffer.from(assetHash(asset), "hex");

    const actual = createHash("sha256")
        .update(bytes)
        .digest();

    if (
        bytes.length !== asset.size ||
        !timingSafeEqual(expected, actual)
    ) {
        fail(502, "HASH_MISMATCH");
    }
}

async function readAsset(
    asset: Asset,
    maximum: number
): Promise<Buffer> {
    if (
        !Number.isSafeInteger(asset.id) ||
        asset.size <= 0 ||
        asset.size > maximum
    ) {
        fail(502, "MANIFEST_INVALID");
    }

    let response = await github(
        `releases/assets/${asset.id}`,
        true
    );

    if (
        response.status === 302 ||
        response.status === 307
    ) {
        const location = response.headers.get("location");

        if (!location) {
            fail(502, "GITHUB_ERROR");
        }

        response = await fetch(
            safeDownloadUrl(location!),
            {
                // GitHub credentials are not forwarded.
                signal: AbortSignal.timeout(25_000)
            }
        );
    }

    if (!response.ok) {
        fail(502, "GITHUB_ERROR");
    }

    const bytes = await boundedBytes(response, maximum);
    verifyBytes(asset, bytes);

    return bytes;
}

async function assetUrl(asset: Asset): Promise<string> {
    const response = await github(
        `releases/assets/${asset.id}`,
        true
    );

    if (
        response.status === 302 ||
        response.status === 307
    ) {
        const location = response.headers.get("location");

        if (!location) {
            fail(502, "GITHUB_ERROR");
        }

        return safeDownloadUrl(location!);
    }

    // GitHub may return HTTP 200 with the binary body.
    // Mirror that response into a private Storage bucket.
    // The binary is never returned through the Vercel API body.
    const bytes = await boundedBytes(
        response,
        67_108_864
    );

    verifyBytes(asset, bytes);

    const objectPath =
        `${asset.id}/${assetHash(asset)}/${asset.name}`;

    const upload = await supa(
        `storage/v1/object/nf-builds/${objectPath}`,
        {
            method: "POST",
            headers: {
                "Content-Type": "application/octet-stream",
                "x-upsert": "true"
            },
            body: new Uint8Array(bytes)
        }
    );

    if (!upload.ok) {
        fail(502, "STORAGE_ERROR");
    }

    const signed = await supa(
        `storage/v1/object/sign/nf-builds/${objectPath}`,
        {
            method: "POST",
            body: JSON.stringify({
                expiresIn: 60
            })
        }
    );

    if (!signed.ok) {
        fail(502, "STORAGE_ERROR");
    }

    const result = await signed.json() as {
        signedURL?: string;
    };

    if (
        !result.signedURL?.startsWith("/object/sign/")
    ) {
        fail(502, "STORAGE_ERROR");
    }

    return `${supabaseUrl()}/storage/v1${result.signedURL}`;
}

function compareVersions(
    first: string,
    second: string
): number {
    const a = first.split(".").map(Number);
    const b = second.split(".").map(Number);

    for (let i = 0; i < 3; i++) {
        const difference =
            (a[i] ?? 0) - (b[i] ?? 0);

        if (difference !== 0) {
            return difference;
        }
    }

    return first.localeCompare(second);
}

async function releaseAssets(
    releaseId: number
): Promise<Asset[]> {
    const assets: Asset[] = [];

    for (let page = 1; page <= 20; page++) {
        const response = await github(
            `releases/${releaseId}/assets?per_page=100&page=${page}`
        );

        const batch = await response.json() as Asset[];
        assets.push(...batch);

        if (batch.length < 100) {
            return assets;
        }
    }

    fail(502, "TOO_MANY_ASSETS");
}

async function findBuild(
    selectedChannel: Channel
): Promise<Build | null> {
    const tag =
        process.env[
        `GITHUB_TAG_${selectedChannel.toUpperCase()}`
        ] ?? selectedChannel;

    let release: Release;

    try {
        const response = await github(
            `releases/tags/${encodeURIComponent(tag)}`
        );

        release = await response.json() as Release;
    } catch (error) {
        if (
            error instanceof ApiError &&
            error.code === "GITHUB_NOT_FOUND"
        ) {
            return null;
        }

        throw error;
    }

    if (release.draft) {
        return null;
    }

    const assets = await releaseAssets(release.id);

    const expression = new RegExp(
        `^neverfair-${selectedChannel}-v` +
        `(\\d{1,6}(?:\\.\\d{1,6}){0,2})\\.jar$`
    );

    const candidates = assets.flatMap(asset => {
        const match = expression.exec(asset.name);

        return match
            ? [{ asset, version: match[1] }]
            : [];
    });

    candidates.sort(
        (a, b) =>
            compareVersions(b.version, a.version)
    );

    const latest = candidates[0];

    if (!latest) {
        return null;
    }

    assetHash(latest.asset);

    return {
        channel: selectedChannel,
        version: latest.version,
        name: latest.asset.name,
        assetId: latest.asset.id,
        updatedAt: latest.asset.updated_at,
        asset: latest.asset,
        assets
    };
}

async function prepareBuild(
    selectedChannel: Channel
) {
    const build = await findBuild(selectedChannel);

    if (!build) {
        fail(404, "NO_BUILD");
    }

    const manifestName =
        build!.name.replace(/\.jar$/, ".json");

    const manifestAsset = build!.assets.find(
        asset => asset.name === manifestName
    );

    if (!manifestAsset) {
        fail(502, "MANIFEST_INVALID");
    }

    let manifest: {
        minecraftVersion?: unknown;
        fabricLoader?: unknown;
        dependencies?: unknown;
    };

    try {
        const bytes = await readAsset(
            manifestAsset!,
            65_536
        );

        manifest = JSON.parse(bytes.toString("utf8"));
    } catch (error) {
        if (error instanceof ApiError) {
            throw error;
        }

        fail(502, "MANIFEST_INVALID");
    }

    if (
        typeof manifest!.minecraftVersion !== "string" ||
        !/^[A-Za-z0-9._-]{1,60}$/.test(
            manifest!.minecraftVersion
        ) ||
        typeof manifest!.fabricLoader !== "string" ||
        !/^[A-Za-z0-9._+-]{1,60}$/.test(
            manifest!.fabricLoader
        ) ||
        !Array.isArray(manifest!.dependencies) ||
        manifest!.dependencies.length > 31
    ) {
        fail(502, "MANIFEST_INVALID");
    }

    const names: string[] = [
        build!.name,
        ...manifest!.dependencies as unknown[]
    ].map(value => {
        if (
            typeof value !== "string" ||
            !safeJar(value)
        ) {
            fail(502, "MANIFEST_INVALID");
        }

        return value as string;
    });

    if (new Set(names).size !== names.length) {
        fail(502, "MANIFEST_INVALID");
    }

    const files = [];

    // Sequential resolution avoids multiplying large binary
    // fallback buffers within one Vercel invocation.
    for (const name of names) {
        const asset = build!.assets.find(
            item => item.name === name
        );

        if (
            !asset ||
            asset.size <= 0 ||
            asset.size > 67_108_864
        ) {
            fail(502, "MANIFEST_INVALID");
        }

        files.push({
            name,
            sha256: assetHash(asset!),
            size: asset!.size,
            url: await assetUrl(asset!)
        });
    }

    return {
        channel: selectedChannel,
        version: build!.version,
        assetId: build!.assetId,
        minecraftVersion: manifest!.minecraftVersion,
        fabricLoader: manifest!.fabricLoader,
        files
    };
}

function offset(value: unknown): number {
    const number = Number(value ?? 0);

    if (
        !Number.isSafeInteger(number) ||
        number < 0 ||
        number > 10_000_000
    ) {
        fail(400, "INVALID_OFFSET");
    }

    return number;
}

export default async function handler(
    req: VercelRequest,
    res: VercelResponse
): Promise<void> {
    res.setHeader("Cache-Control", "no-store");
    res.setHeader("X-Content-Type-Options", "nosniff");

    if (req.method !== "POST") {
        res.setHeader("Allow", "POST");
        res.status(405).json({
            error: "METHOD_NOT_ALLOWED"
        });

        return;
    }

    try {
        if (
            !req.body ||
            typeof req.body !== "object" ||
            Buffer.byteLength(JSON.stringify(req.body)) > 16_384
        ) {
            fail(400, "INVALID_BODY");
        }

        const body = req.body as {
            action?: unknown;
            hwid?: unknown;
            payload?: Record<string, unknown>;
        };

        const action = body.action;

        if (typeof action !== "string") {
            fail(400, "INVALID_ACTION");
        }

        const payload = body.payload ?? {};

        if (
            typeof payload !== "object" ||
            Array.isArray(payload)
        ) {
            fail(400, "INVALID_BODY");
        }

        const ipHeader =
            req.headers["x-vercel-forwarded-for"] ??
            req.headers["x-forwarded-for"];

        const ip = (
            Array.isArray(ipHeader)
                ? ipHeader[0]
                : ipHeader ?? "unknown"
        ).split(",")[0].trim();

        await rate(`ip:${ip}`, 180, 60);

        if (action === "register") {
            await rate(`register:${ip}`, 5, 3600);

            const login = loginName(payload.login);
            const pass = password(payload.password);

            if (pass !== payload.passwordRepeat) {
                fail(400, "PASSWORD_INVALID");
            }

            // Supabase Auth uses an internal synthetic email because
            // the launcher UI intentionally accepts a username only.
            const response = await supa(
                "auth/v1/admin/users",
                {
                    method: "POST",
                    body: JSON.stringify({
                        email: `${login}@users.neverfair.invalid`,
                        password: pass,
                        email_confirm: true,
                        user_metadata: {
                            login
                        }
                    })
                }
            );

            if (!response.ok) {
                fail(400, "REGISTRATION_FAILED");
            }

            res.status(200).json({ ok: true });
            return;
        }

        const hwid = device(body.hwid);

        if (action === "login") {
            await rate(`login:${ip}`, 20, 300);

            const login = loginName(payload.login);
            const pass = password(payload.password);

            const response = await supa(
                "auth/v1/token?grant_type=password",
                {
                    method: "POST",
                    body: JSON.stringify({
                        email: `${login}@users.neverfair.invalid`,
                        password: pass
                    })
                },
                undefined,
                true
            );

            if (!response.ok) {
                fail(401, "INVALID_CREDENTIALS");
            }

            const tokens =
                await response.json() as AuthTokens;

            const identity =
                await verifyToken(tokens.access_token);

            try {
                const profile = await rpc("nf_bind", {
                    p_uid: identity.uid,
                    p_sid: identity.sid,
                    p_hwid: hwid
                }) as Profile;

                res.status(200).json(
                    sessionView(tokens, profile)
                );
            } catch (error) {
                await revokeAuth(tokens.access_token);
                throw error;
            }

            return;
        }

        if (action === "refresh") {
            await rate(`refresh:${ip}`, 40, 300);

            const refreshToken = payload.refreshToken;

            if (
                typeof refreshToken !== "string" ||
                refreshToken.length < 10 ||
                refreshToken.length > 4096
            ) {
                fail(401, "LOGIN_REQUIRED");
            }

            const response = await supa(
                "auth/v1/token?grant_type=refresh_token",
                {
                    method: "POST",
                    body: JSON.stringify({
                        refresh_token: refreshToken
                    })
                },
                undefined,
                true
            );

            if (!response.ok) {
                fail(401, "LOGIN_REQUIRED");
            }

            const tokens =
                await response.json() as AuthTokens;

            const identity =
                await verifyToken(tokens.access_token);

            try {
                // Refresh never rebinds an empty HWID.
                const profile = await rpc("nf_check", {
                    p_uid: identity.uid,
                    p_sid: identity.sid,
                    p_hwid: hwid
                }) as Profile;

                res.status(200).json(
                    sessionView(tokens, profile)
                );
            } catch (error) {
                await revokeAuth(tokens.access_token);
                throw error;
            }

            return;
        }

        const ctx = await context(req, hwid);

        await rate(`user:${ctx.uid}`, 120, 60);

        if (action === "logout") {
            await db(
                `nf_sessions?session_id=eq.${ctx.sid}` +
                `&user_id=eq.${ctx.uid}`,
                { method: "DELETE" }
            );

            await revokeAuth(ctx.token);
            await logEvent(ctx.uid, "logout");

            res.status(200).json({ ok: true });
            return;
        }

        if (action === "catalog") {
            const builds = await Promise.all(
                (["release", "beta", "alpha"] as Channel[])
                    .map(findBuild)
            );

            res.status(200).json({
                user: profileView(ctx.profile),
                builds: builds
                    .filter((build): build is Build => build !== null)
                    .map(build => ({
                        channel: build.channel,
                        version: build.version,
                        name: build.name,
                        assetId: build.assetId,
                        updatedAt: build.updatedAt
                    }))
            });

            return;
        }

        if (action === "prepare") {
            const selected = channel(payload.channel);

            await rate(`prepare:${ctx.uid}`, 10, 60);

            const plan = await prepareBuild(selected);

            // A reset that happened during GitHub access invalidates
            // this request before URLs are returned.
            await rpc("nf_check", {
                p_uid: ctx.uid,
                p_sid: ctx.sid,
                p_hwid: ctx.hwid
            });

            await logEvent(ctx.uid, "build_prepared", {
                channel: selected,
                version: plan.version
            });

            res.status(200).json(plan);
            return;
        }

        if (action === "event") {
            const selected = channel(payload.channel);

            const eventName = payload.eventName;

            if (
                eventName !== "launch_requested" &&
                eventName !== "launch_exit"
            ) {
                fail(400, "INVALID_EVENT");
            }

            const version = payload.version;

            if (
                typeof version !== "string" ||
                !/^\d{1,6}(?:\.\d{1,6}){0,2}$/.test(version)
            ) {
                fail(400, "INVALID_VERSION");
            }

            const exitCode = payload.exitCode;

            if (
                exitCode !== undefined &&
                exitCode !== null &&
                (
                    typeof exitCode !== "number" ||
                    !Number.isInteger(exitCode) ||
                    exitCode < -2147483648 ||
                    exitCode > 2147483647
                )
            ) {
                fail(400, "INVALID_EVENT");
            }

            // Explicitly marked as client-reported telemetry.
            await logEvent(
                ctx.uid,
                `client_${eventName}`,
                {
                    channel: selected,
                    version,
                    exitCode: exitCode ?? null
                }
            );

            res.status(200).json({ ok: true });
            return;
        }

        if (action === "adminUsers") {
            requireAdmin(ctx);

            const pageOffset = offset(payload.offset);

            const users = await db(
                "nf_profiles" +
                "?select=id,login,role,hwid_hash,last_login" +
                "&order=login.asc" +
                `&offset=${pageOffset}&limit=100`
            ) as Profile[];

            res.status(200).json({
                users: users.map(user => ({
                    ...profileView(user),
                    hwidSet: user.hwid_hash !== null
                }))
            });

            return;
        }

        if (action === "adminReset") {
            requireAdmin(ctx);

            const target = uuid(payload.userId);

            await rpc("nf_reset", {
                p_uid: ctx.uid,
                p_sid: ctx.sid,
                p_hwid: ctx.hwid,
                p_target: target
            });

            res.status(200).json({ ok: true });
            return;
        }

        if (action === "adminLogs") {
            requireAdmin(ctx);

            const pageOffset = offset(payload.offset);

            const logs = await db(
                "nf_logs" +
                "?select=id,created_at,actor_id,target_id,action,details" +
                "&order=id.desc" +
                `&offset=${pageOffset}&limit=100`
            );

            res.status(200).json({ logs });
            return;
        }

        fail(400, "INVALID_ACTION");
    } catch (error) {
        if (error instanceof ApiError) {
            res.status(error.status).json({
                error: error.code
            });

            return;
        }

        // Do not log request bodies, passwords, tokens or HWIDs.
        console.error(
            "NeverFair request failed:",
            error instanceof Error ? error.name : "UnknownError"
        );

        res.status(500).json({
            error: "SERVER_ERROR"
        });
    }
}