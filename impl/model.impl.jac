import from stdjac { allroots }

impl user_by_email(email: str) -> User | None {
    want = email.lower();
    for u in [root.shared --> [?:User]] {
        if u.email == want {
            return u;
        }
    }
    return None;
}

impl user_by_id(uuid: str) -> User | None {
    for u in [root.shared --> [?:User]] {
        if u.uuid == uuid {
            return u;
        }
    }
    return None;
}

impl account(bearer: str) -> User | None {
    claims = verify(bearer, "http://localhost|login");
    if claims is None {
        return None;
    }
    return user_by_id(str(claims.get("sub", "")));
}

impl touch(u: User) {
    u.updated_us = now_us();
}

impl folder_of(c: Cipher) -> Folder | None {
    for f in [c <-:Holds:<-] {
        if isinstance(f, Folder) {
            return f;
        }
    }
    return None;
}

impl find_folder(uuid: str) -> Folder | None {
    for f in [root --> [?:Folder]] {
        if f.uuid == uuid {
            return f;
        }
    }
    return None;
}

impl find_cipher(uuid: str) -> Cipher | None {
    for r in allroots() {
        for c in [r --> [?:Cipher]] {
            if c.uuid == uuid {
                return c;
            }
        }
    }
    return None;
}

impl owned(c: Cipher) -> bool {
    return any(x.uuid == c.uuid for x in [root --> [?:Cipher]]);
}

impl account_keys(u: User) -> dict[str, any] | None {
    if not u.private_key or not u.public_key {
        return None;
    }
    return {
        "object": "privateKeys",
        "publicKeyEncryptionKeyPair": {
            "object": "publicKeyEncryptionKeyPair",
            "publicKey": u.public_key,
            "signedPublicKey": None,
            "wrappedPrivateKey": u.private_key,
        },
        "securityState": None,
        "signatureKeyPair": None,
    };
}
