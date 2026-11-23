import json;
import os;
import base64;
import hashlib;
import hmac;
import time;

glob device_names: list[str] = [
    "Android", "iOS", "Chrome Extension", "Firefox Extension", "Opera Extension", "Edge Extension",
    "Windows", "macOS", "Linux", "Chrome", "Firefox", "Opera", "Edge", "Internet Explorer",
    "Unknown Browser", "Android", "UWP", "Safari", "Vivaldi", "Vivaldi Extension", "Safari Extension",
    "SDK", "Server", "Windows CLI", "macOS CLI", "Linux CLI", "DuckDuckGo"
];

glob prelogin_spec: dict[str, any] = {"email": "str"};

glob verification_spec: dict[str, any] = {"email": "str", "name": "str?"};

glob register_spec: dict[str, any] = {
    "email": "str",
    "kdf|kdfType": "int",
    "kdfIterations|iterations": "int",
    "kdfMemory|memory": "int?",
    "kdfParallelism|parallelism": "int?",
    "key|userSymmetricKey": "str",
    "masterPasswordHash": "str",
    "keys|userAsymmetricKeys": {"?": True, "encryptedPrivateKey": "str", "publicKey": "str"},
    "accountKeys": "dict?",
    "masterPasswordHint": "str?",
    "organizationUserId": "str?",
    "emailVerificationToken": "str?",
    "acceptEmergencyAccessId": "str?",
    "acceptEmergencyAccessInviteToken": "str?",
    "orgInviteToken|token": "str?"
};

glob version_missing: str = "No client version header found, required to prevent encryption errors. Please confirm your client is supplying the header: \"Bitwarden-Client-Version\"";

def hash_password(given: str, salt: bytes, iterations: int) -> str {
    return base64.b64encode(hashlib.pbkdf2_hmac("sha256", given.encode(), salt, iterations, 32)).decode();
}

def kdf_of(u: User) -> dict[str, any] {
    return {"kdf": u.kdf_type, "kdfIterations": u.kdf_iter, "kdfMemory": u.kdf_memory, "kdfParallelism": u.kdf_parallelism};
}

impl prelogin(body: str) -> Reply {
    data = json.loads(body);
    if not fits(data, prelogin_spec) {
        return unprocessable();
    }
    u = user_by_email(str(data.get("email", "")));
    k = kdf_of(u) if u is not None else {"kdf": 1, "kdfIterations": 3, "kdfMemory": 64, "kdfParallelism": 4};
    return ok({
        "kdf": k["kdf"],
        "kdfIterations": k["kdfIterations"],
        "kdfMemory": k["kdfMemory"],
        "kdfParallelism": k["kdfParallelism"],
        "kdfSettings": {"iterations": k["kdfIterations"], "kdfType": k["kdf"], "memory": k["kdfMemory"], "parallelism": k["kdfParallelism"]},
        "salt": None
    });
}

impl send_verification(body: str, accept: str) -> Reply {
    data = json.loads(body);
    if not fits(data, verification_spec) {
        return unprocessable();
    }
    now = int(time.time());
    tok = sign({
        "nbf": now,
        "exp": now + 1800,
        "iss": "http://localhost|register_verify",
        "sub": data.get("email"),
        "name": data.get("name"),
        "verified": False
    });
    if accept.split(",")[0].split(";")[0].strip() == "application/json" {
        return ok(tok);
    }
    return Reply(body=tok, ctype="text/plain; charset=utf-8");
}

impl register_finish(body: str) -> Reply {
    data = json.loads(body);
    if not fits(data, register_spec) {
        return unprocessable();
    }
    email = str(data.get("email", "")).lower();
    vtoken = data.get("emailVerificationToken");
    if not vtoken {
        return err("Registration is missing required parameters");
    }
    claims = verify(str(vtoken), "http://localhost|register_verify");
    if claims is None {
        return err("Token is invalid");
    }
    if claims.get("sub") != data.get("email") {
        return err("Email verification token does not match email");
    }
    name = claims.get("name");
    if name is not None and len(str(name)) > 50 {
        return err("The field Name must be a string with a maximum length of 50.");
    }
    kdf = int(data.get("kdf", 0) or 0);
    iters = int(data.get("kdfIterations", 600000) or 0);
    if kdf == 0 and iters < 600000 {
        return err("PBKDF2 KDF iterations must be at least 600000.");
    }
    u = user_by_email(email);
    if u is not None and u.password_hash {
        return err("Registration not allowed or user already exists");
    }
    now = now_us();
    if u is None {
        u = User(uuid=new_uuid(), email=email, name=email, security_stamp=new_uuid(), created_us=now, updated_us=now);
        u.salt = base64.b64encode(os.urandom(64)).decode();
        root.shared ++> u;
    }
    u.kdf_type = kdf;
    u.kdf_iter = iters;
    u.kdf_memory = data.get("kdfMemory") if kdf == 1 else None;
    u.kdf_parallelism = data.get("kdfParallelism") if kdf == 1 else None;
    u.password_hash = hash_password(str(data.get("masterPasswordHash", "")), base64.b64decode(u.salt), u.password_iterations);
    u.akey = str(data.get("userSymmetricKey", ""));
    hint = data.get("masterPasswordHint");
    u.password_hint = hint or None;
    u.security_stamp = new_uuid();
    if name is not None {
        u.name = str(name);
    }
    keys = data.get("userAsymmetricKeys");
    if isinstance(keys, dict) {
        u.public_key = keys.get("publicKey");
        u.private_key = keys.get("encryptedPrivateKey");
    }
    u.updated_us = now;
    return ok({"object": "registerFinish"});
}

def form(body: str) -> dict[str, str] {
    raw = json.loads(body);
    out: dict[str, str] = {};
    alias = {"granttype": "grant_type", "refreshtoken": "refresh_token", "clientid": "client_id", "clientsecret": "client_secret",
             "deviceidentifier": "device_identifier", "devicename": "device_name", "devicetype": "device_type",
             "twofactorprovider": "two_factor_provider", "twofactortoken": "two_factor_token", "twofactorremember": "two_factor_remember"};
    for (k, v) in raw.items() {
        key = str(k).lower();
        out[alias.get(key, key)] = str(v);
    }
    return out;
}

def access_claims(u: User, d: Device, client_id: str | None) -> dict[str, any] {
    now = int(time.time());
    name = device_names[d.atype] if 0 <= d.atype < len(device_names) else "Unknown Browser";
    return {
        "nbf": now,
        "exp": now + 7200,
        "iss": "http://localhost|login",
        "sub": u.uuid,
        "premium": True,
        "name": u.name,
        "email": u.email,
        "email_verified": True,
        "sstamp": u.security_stamp,
        "device": d.uuid,
        "devicetype": name,
        "client_id": client_id,
        "scope": ["api", "offline_access"],
        "amr": ["Application"]
    };
}

def refresh_for(d: Device) -> str {
    now = int(time.time());
    days = 90 if d.atype in (0, 1) else 30;
    return sign({"nbf": now, "exp": now + days * 86400, "iss": "http://localhost|login", "sub": "password", "device_token": d.refresh_token, "token": None});
}

def device_of(u: User, f: dict[str, str]) -> Device {
    did = f["device_identifier"];
    for d in [u ->:Uses:->] {
        if isinstance(d, Device) and d.uuid == did {
            return d;
        }
    }
    try {
        atype = int(f["device_type"]);
    } except ValueError {
        atype = 14;
    }
    now = now_us();
    d = Device(uuid=did, name=f["device_name"], atype=atype, refresh_token=base64.urlsafe_b64encode(os.urandom(64)).decode(), created_us=now, updated_us=now);
    u +>:Uses:+> d;
    return d;
}

def password_login(f: dict[str, str], version: str) -> Reply {
    for want in ["client_id", "password", "scope", "username", "device_identifier", "device_name", "device_type"] {
        if want not in f {
            return err(want + " cannot be blank");
        }
    }
    if f["scope"] != "api offline_access" {
        return err("Scope (" + f["scope"] + ") not supported");
    }
    u = user_by_email(f["username"].strip());
    if u is None or not u.password_hash {
        return err("Username or password is incorrect. Try again");
    }
    if not hmac.compare_digest(hash_password(f["password"], base64.b64decode(u.salt), u.password_iterations), u.password_hash) {
        return err("Username or password is incorrect. Try again");
    }
    if not version {
        return Reply(status=400, body=dumps({"ErrorModel": {"Message": version_missing, "Object": "error"}, "error": "version_header_missing", "error_description": version_missing}));
    }
    d = device_of(u, f);
    d.updated_us = now_us();
    unlock = {
        "Kdf": {"Iterations": u.kdf_iter, "KdfType": u.kdf_type, "Memory": u.kdf_memory, "Parallelism": u.kdf_parallelism},
        "MasterKeyEncryptedUserKey": u.akey,
        "MasterKeyWrappedUserKey": u.akey,
        "Salt": u.email.strip().lower()
    };
    out = {
        "access_token": sign(access_claims(u, d, f.get("client_id"))),
        "expires_in": 7200,
        "token_type": "Bearer",
        "refresh_token": refresh_for(d),
        "PrivateKey": u.private_key,
        "Kdf": u.kdf_type,
        "KdfIterations": u.kdf_iter,
        "KdfMemory": u.kdf_memory,
        "KdfParallelism": u.kdf_parallelism,
        "ForcePasswordReset": False,
        "MasterPasswordPolicy": {"Object": "masterPasswordPolicy"},
        "scope": "api offline_access",
        "AccountKeys": account_keys(u),
        "UserDecryptionOptions": {"HasMasterPassword": True, "MasterPasswordUnlock": unlock, "Object": "userDecryptionOptions"}
    };
    if u.akey {
        out["Key"] = u.akey;
    }
    return ok(out);
}

def refresh_login(f: dict[str, str]) -> Reply {
    bad = Reply(status=400, body=dumps({"error": "invalid_grant"}));
    claims = verify(f["refresh_token"], "http://localhost|login");
    if claims is None or claims.get("sub") != "password" {
        return bad;
    }
    want = claims.get("device_token");
    for u in [root.shared --> [?:User]] {
        for d in [u ->:Uses:->] {
            if isinstance(d, Device) and d.refresh_token == want {
                d.updated_us = now_us();
                return ok({
                    "refresh_token": refresh_for(d),
                    "access_token": sign(access_claims(u, d, f.get("client_id"))),
                    "expires_in": 7200,
                    "token_type": "Bearer",
                    "scope": "api offline_access"
                });
            }
        }
    }
    return bad;
}

impl token(body: str, version: str) -> Reply {
    f = form(body);
    grant = f.get("grant_type", "");
    if grant == "refresh_token" {
        if "refresh_token" not in f {
            return err("refresh_token cannot be blank");
        }
        return refresh_login(f);
    }
    if grant == "password" {
        return password_login(f, version);
    }
    if grant == "authorization_code" {
        return err("SSO sign-in is not available");
    }
    return err("Invalid type");
}
