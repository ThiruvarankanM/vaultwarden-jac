import json;

glob domain: str = "http://localhost";

impl alive -> Reply {
    return ok(fmt_date(now_us()));
}

impl config -> Reply {
    return ok({
        "version": "2026.6.0",
        "gitHash": None,
        "server": {"name": "Vaultwarden", "url": "https://github.com/dani-garcia/vaultwarden"},
        "settings": {"disableUserRegistration": False, "suppressOnboardingInterstitials": False},
        "environment": {
            "vault": domain,
            "api": domain + "/api",
            "identity": domain + "/identity",
            "notifications": domain + "/notifications",
            "sso": "",
            "cloudRegion": None,
            "fillAssistRules": "https://fillassist.bitwarden.com",
        },
        "push": {"pushTechnology": 0, "vapidPublicKey": None},
        "featureStates": {"pm-19148-innovation-archive": True},
        "communication": None,
        "object": "config",
    });
}

impl profile_json(u: User) -> dict[str, any] {
    return {
        "_status": 0,
        "accountKeys": account_keys(u),
        "avatarColor": opt(u.avatar_color),
        "creationDate": fmt_date(u.created_us),
        "culture": "en-US",
        "email": u.email,
        "emailVerified": True,
        "forcePasswordReset": False,
        "id": u.uuid,
        "key": u.akey,
        "name": u.name,
        "object": "profile",
        "organizations": [],
        "organizationsNew": [],
        "premium": True,
        "premiumFromOrganization": False,
        "privateKey": opt(u.private_key),
        "providerOrganizations": [],
        "providers": [],
        "securityStamp": u.security_stamp,
        "twoFactorEnabled": False,
        "usesKeyConnector": False,
    };
}

impl sync(query: str, bearer: str) -> Reply {
    u = account(bearer);
    if u is None {
        return err("Invalid user");
    }
    q = json.loads(query);
    exclude = str(q.get("excludeDomains", "false")).lower() == "true";
    unlock: dict[str, any] = {
        "containedKeyId": opt(u.key_id),
        "kdf": {
            "iterations": u.kdf_iter,
            "kdfType": u.kdf_type,
            "memory": u.kdf_memory,
            "parallelism": u.kdf_parallelism,
        },
        "masterKeyEncryptedUserKey": u.akey,
        "masterKeyWrappedUserKey": u.akey,
        "salt": u.email.strip().lower(),
    };
    decryption: dict[str, any] = {"masterPasswordUnlock": unlock};
    if u.key_id {
        decryption["userKeyId"] = u.key_id;
    }
    return ok({
        "ciphers": [cipher_json(c) for c in [root --> [?:Cipher]]],
        "collections": [],
        "domains": None if exclude else domains_json(),
        "folders": [folder_json(f) for f in [root --> [?:Folder]]],
        "object": "sync",
        "policies": [],
        "policiesNew": [],
        "profile": profile_json(u),
        "sends": [],
        "userDecryption": decryption,
    });
}

def domains_json -> dict[str, any] {
    return {"equivalentDomains": [], "globalEquivalentDomains": [], "object": "domains"};
}

impl profile(bearer: str) -> Reply {
    u = account(bearer);
    if u is None {
        return err("Invalid user");
    }
    return ok(profile_json(u));
}

impl revision_date(bearer: str) -> Reply {
    u = account(bearer);
    if u is None {
        return err("Invalid user");
    }
    return ok(u.updated_us // 1000);
}

impl set_user_key_id(body: str, bearer: str) -> Reply {
    u = account(bearer);
    if u is None {
        return err("Invalid user");
    }
    data = json.loads(body);
    if not fits(data, {"userKeyId": "hex32"}) {
        return unprocessable();
    }
    if u.key_id {
        return err("User key id is already set.");
    }
    u.key_id = data["userKeyId"];
    touch(u);
    return empty();
}
