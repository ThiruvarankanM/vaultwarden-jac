impl BwAuth.open {
    return;
}

impl BwAuth.caller(headers: dict[str, str]) -> str | None {
    got = headers.get("authorization", "");
    if not got.lower().startswith("bearer ") {
        return None;
    }
    return subject(got[7:].strip(), self.issuer);
}

impl BwAuth.asks(headers: dict[str, str]) -> SignIn {
    return SignIn(fields=[], actions=[], redirect="", session=None);
}

impl BwAuth.answer(action: str, given: dict[str, str], client: str) -> Session {
    raise Rejected(detail="sign in at /identity/connect/token", retry_after=0);
}

impl BwAuth.leave(headers: dict[str, str]) {
    return;
}

impl unb64(s: str) -> bytes {
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4));
}

impl subject(token: str, iss: str) -> str | None {
    path = os.path.join(data_dir(), "jwt.key");
    parts = token.split(".");
    if len(parts) != 3 or not os.path.exists(path) {
        return None;
    }
    with open(path, "rb") as f {
        key = f.read();
    }
    mac = hmac.new(key, (parts[0] + "." + parts[1]).encode(), hashlib.sha256).digest();
    try {
        if not hmac.compare_digest(unb64(parts[2]), mac) {
            return None;
        }
        claims = json.loads(unb64(parts[1]));
    } except Exception {
        return None;
    }
    if not isinstance(claims, dict)
        or claims.get("iss") != iss
        or int(claims.get("exp", 0)) < int(time.time())
    {
        return None;
    }
    sub = claims.get("sub");
    return sub if isinstance(sub, str) else None;
}
