import json;
import os;
import hmac;
import hashlib;
import base64;
import uuid;
import time;
import from datetime { datetime, timezone }
import from stdjac { data_dir }

impl dumps(v: any) -> str {
    return json.dumps(v, sort_keys=True, separators=(",", ":"));
}

impl ok(v: any) -> Reply {
    return Reply(body=dumps(v));
}

impl empty -> Reply {
    return Reply(body="");
}

impl err(msg: str) -> Reply {
    return Reply(
        status=400,
        body=json.dumps(
            {
                "message": msg,
                "validationErrors": {"": [msg]},
                "errorModel": {"message": msg, "object": "error"},
                "error": "",
                "error_description": "",
                "exceptionMessage": None,
                "exceptionStackTrace": None,
                "innerExceptionMessage": None,
                "object": "error",
            },
            separators=(",", ":"),
        ),
    );
}

impl unprocessable -> Reply {
    return Reply(status=422, body=rocket_422, ctype="text/html; charset=utf-8");
}

def kind_fits(v: any, kind: any) -> bool {
    if isinstance(kind, dict) {
        return (v is None and kind.get("?", False)) or fits(v, kind);
    }
    if kind.endswith("?") {
        return v is None or kind_fits(v, kind[:-1]);
    }
    if kind == "str" {
        return isinstance(v, str);
    }
    if kind == "bool" {
        return isinstance(v, bool);
    }
    if kind == "int" {
        return isinstance(v, int) and not isinstance(v, bool) and -2147483648 <= v <= 2147483647;
    }
    if kind == "hex32" {
        return isinstance(v, str) and len(v) == 32 and all(ch in "0123456789abcdef" for ch in v);
    }
    if kind == "list" {
        return isinstance(v, list);
    }
    if kind == "dict" {
        return isinstance(v, dict);
    }
    return True;
}

impl fits(v: any, spec: dict[str, any]) -> bool {
    if not isinstance(v, dict) {
        return False;
    }
    for (names, kind) in spec.items() {
        if names == "?" {
            continue;
        }
        given = [n for n in names.split("|") if n in v];
        if len(given) > 1 {
            return False;
        }
        if not given {
            if not (isinstance(kind, str) and kind.endswith("?"))
                and not (isinstance(kind, dict) and kind.get("?", False))
                and kind != "any"
            {
                return False;
            }
            continue;
        }
        if not kind_fits(v[given[0]], kind) {
            return False;
        }
    }
    return True;
}

impl now_us -> int {
    return time.time_ns() // 1000;
}

impl fmt_date(us: int | None) -> str | None {
    if us is None {
        return None;
    }
    d = datetime.fromtimestamp(us / 1000000, tz=timezone.utc);
    return d.strftime("%Y-%m-%dT%H:%M:%S.%fZ");
}

impl parse_date(s: str) -> int | None {
    try {
        d = datetime.fromisoformat(s.replace("Z", "+00:00"));
    } except ValueError {
        return None;
    }
    if d.tzinfo is None {
        d = d.replace(tzinfo=timezone.utc);
    }
    return int(d.timestamp() * 1000000);
}

impl b64url(b: bytes) -> str {
    return base64.urlsafe_b64encode(b).decode().rstrip("=");
}

impl unb64url(s: str) -> bytes {
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4));
}

def key -> bytes {
    path = os.path.join(data_dir(), "jwt.key");
    if not os.path.exists(path) {
        try {
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600);
            os.write(fd, os.urandom(32));
            os.close(fd);
        } except FileExistsError {}
    }
    with open(path, "rb") as f {
        return f.read();
    }
}

impl sign(claims: dict[str, any]) -> str {
    head = b64url(dumps({"alg": "HS256", "typ": "JWT"}).encode());
    body = b64url(dumps(claims).encode());
    mac = hmac.new(key(), (head + "." + body).encode(), hashlib.sha256).digest();
    return head + "." + body + "." + b64url(mac);
}

impl verify(token: str, iss: str) -> dict[str, any] | None {
    parts = token.split(".");
    if len(parts) != 3 {
        return None;
    }
    mac = hmac.new(key(), (parts[0] + "." + parts[1]).encode(), hashlib.sha256).digest();
    try {
        if not hmac.compare_digest(b64url(mac), parts[2]) {
            return None;
        }
        claims = json.loads(unb64url(parts[1]));
    } except Exception {
        return None;
    }
    if not isinstance(claims, dict) or claims.get("iss") != iss {
        return None;
    }
    if int(claims.get("exp", 0)) < int(time.time()) {
        return None;
    }
    return claims;
}

impl new_uuid -> str {
    return str(uuid.uuid4());
}

impl prelogin_index(email: str, n: int) -> int {
    k = hmac.new(key(), b"prelogin-kdf", hashlib.sha256).digest();
    tag = hmac.new(k, email.encode(), hashlib.sha256).digest();
    return ((tag[0] << 8) | tag[1]) % n;
}

impl opt(s: str) -> str | None {
    return s or None;
}
