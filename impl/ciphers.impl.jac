import json;
import re;
import datetime;
import from stdjac.graph { remove }

glob cipher_spec: dict[str, any] = {
    "id": "str?",
    "folderId": "str?",
    "organizationId|organizationID": "str?",
    "key": "str?",
    "encryptedFor": "str?",
    "encryptedByKeyId": "hex32?",
    "type": "int",
    "name": "str?",
    "notes": "str?",
    "fields": "any",
    "login": "any",
    "secureNote": "any",
    "card": "any",
    "identity": "any",
    "sshKey": "any",
    "bankAccount": "any",
    "driversLicense": "any",
    "passport": "any",
    "data": "str?",
    "favorite": "bool?",
    "reprompt": "int?",
    "passwordHistory": "any",
    "attachments": "any",
    "attachments2": "dict?",
    "lastKnownRevisionDate": "str?",
    "archivedDate": "str?"
};

glob share_spec: dict[str, any] = {"cipher|Cipher": cipher_spec, "collectionIds|CollectionIds": "list"};

glob epoch: str = "1970-01-01T00:00:00.000000Z";

def as_u8(s: str) -> int | None {
    d = s[1:] if s.startswith("+") else s;
    if not d or not d.isascii() or not d.isdigit() or int(d) > 255 {
        return None;
    }
    return int(d);
}

def is_number(v: any) -> bool {
    return isinstance(v, (int, float)) and not isinstance(v, bool);
}

def rfc3339(s: str) -> str {
    m = re.fullmatch(r"(\d{4}-\d\d-\d\d)[Tt ](\d\d:\d\d:\d\d)(\.\d+)?([Zz]|[+-]\d\d:\d\d)", s);
    if m is None {
        return epoch;
    }
    try {
        datetime.datetime.fromisoformat(m.group(1) + "T" + m.group(2));
    } except ValueError {
        return epoch;
    }
    off = m.group(4);
    if off not in ("Z", "z") and (int(off[1:3]) > 23 or int(off[4:6]) > 59) {
        return epoch;
    }
    frac = ((m.group(3) or ".")[1:] + "000000")[:6];
    zone = "Z" if off in ("Z", "z", "+00:00", "-00:00") else off;
    return m.group(1) + "T" + m.group(2) + "." + frac + zone;
}

glob type_keys: dict[int, str] = {1: "login", 2: "secureNote", 3: "card", 4: "identity", 5: "sshKey", 6: "bankAccount", 7: "driversLicense", 8: "passport"};

def lcase_first(v: any) -> any {
    if isinstance(v, dict) {
        return {(k[:1].lower() + k[1:] if isinstance(k, str) else k): lcase_first(x) for (k, x) in v.items()};
    }
    if isinstance(v, list) {
        return [lcase_first(x) for x in v];
    }
    return v;
}

def strip_response(v: any) -> any {
    if isinstance(v, list) {
        return [{k: x for (k, x) in i.items() if k != "response"} if isinstance(i, dict) else i for i in v];
    }
    return v;
}

def type_data(c: Cipher) -> any {
    try {
        d = json.loads(c.data);
    } except ValueError {
        d = None;
    }
    d = lcase_first(d) if isinstance(d, dict) else {};
    if c.atype == 1 {
        d["uri"] = None;
        d.setdefault("uris", None);
        uris = d["uris"];
        if isinstance(uris, list) and uris {
            for u in uris {
                if isinstance(u, dict) and isinstance(u.get("match"), str) {
                    u["match"] = as_u8(u["match"]);
                }
            }
            d["uri"] = uris[0].get("uri") if isinstance(uris[0], dict) else None;
        }
        if isinstance(d.get("passwordRevisionDate"), str) {
            d["passwordRevisionDate"] = rfc3339(d["passwordRevisionDate"]);
        }
    }
    if c.atype == 2 and not is_number(d.get("type")) {
        d = {"type": 0};
    }
    if c.atype == 5 and not all(isinstance(d.get(k), str) and d[k] for k in ("keyFingerprint", "privateKey", "publicKey")) {
        return None;
    }
    return d;
}

def fields_json(c: Cipher) -> list[any] | None {
    if c.fields is None {
        return None;
    }
    try {
        items = json.loads(c.fields);
    } except ValueError {
        return [];
    }
    out: list[any] = [];
    for f in (items if isinstance(items, list) else []) {
        f = lcase_first(f);
        t = f.get("type");
        if isinstance(t, str) {
            n = as_u8(t);
            f["type"] = n if n is not None else 1;
        } elif not is_number(t) {
            f["type"] = 1;
        }
        out.append(f);
    }
    return out;
}

def history_json(c: Cipher) -> list[any] | None {
    if c.password_history is None {
        return None;
    }
    try {
        items = json.loads(c.password_history);
    } except ValueError {
        return [];
    }
    out: list[any] = [];
    for h in (items if isinstance(items, list) else []) {
        h = lcase_first(h);
        if not isinstance(h.get("password"), str) {
            continue;
        }
        lud = h.get("lastUsedDate");
        h["lastUsedDate"] = rfc3339(lud) if isinstance(lud, str) else epoch;
        out.append(h);
    }
    return out;
}

impl cipher_json(c: Cipher) -> dict[str, any] {
    f = folder_of(c);
    out: dict[str, any] = {
        "object": "cipherDetails",
        "id": c.uuid,
        "type": c.atype,
        "creationDate": fmt_date(c.created_us),
        "revisionDate": fmt_date(c.updated_us),
        "deletedDate": fmt_date(c.deleted_us),
        "reprompt": c.reprompt if c.reprompt in (0, 1) else 0,
        "organizationId": None,
        "key": c.key,
        "attachments": None,
        "organizationUseTotp": True,
        "collectionIds": [],
        "name": c.name,
        "notes": c.notes,
        "fields": fields_json(c),
        "passwordHistory": history_json(c),
        "login": None,
        "secureNote": None,
        "card": None,
        "identity": None,
        "sshKey": None,
        "bankAccount": None,
        "driversLicense": None,
        "passport": None,
        "folderId": f.uuid if f is not None else None,
        "favorite": c.favorite,
        "archivedDate": fmt_date(c.archived_us),
        "edit": True,
        "viewPassword": True,
        "permissions": {"delete": True, "restore": True}
    };
    out[type_keys[c.atype]] = type_data(c);
    return out;
}

def save_data(c: Cipher, u: User, data: dict[str, any], check_date: bool) -> Reply | None {
    if data.get("encryptedFor") is not None and data.get("encryptedFor") != u.uuid {
        return err("Cipher was not encrypted for the current user. Please try again.");
    }
    if data.get("encryptedByKeyId") is not None and u.key_id is not None and data.get("encryptedByKeyId") != u.key_id {
        return err("Cipher was not encrypted with the current user key. Please try again.");
    }
    if data.get("organizationId") or data.get("organizationID") {
        return err("You don't have permission to add item to organization");
    }
    atype = data.get("type");
    if atype not in type_keys {
        return err("Invalid type");
    }
    name = data.get("name");
    if not isinstance(name, str) or not name.strip() {
        return err("The Name field is required.");
    }
    tdata = data.get(type_keys[atype]);
    if tdata is None {
        return err("Data missing");
    }
    if check_date and isinstance(data.get("lastKnownRevisionDate"), str) {
        known = parse_date(data["lastKnownRevisionDate"]);
        if known is not None and (c.updated_us - known) // 1000000 > 1 {
            return err("The client copy of this cipher is out of date. Resync the client and try again.");
        }
    }
    notes = data.get("notes");
    if isinstance(notes, str) and len(notes) > 10000 {
        return err("The field Notes exceeds the maximum encrypted value length of 10000 characters.");
    }
    folder: Folder | None = None;
    fid = data.get("folderId");
    if fid {
        folder = find_folder(str(fid));
        if folder is None {
            return err("Invalid folder");
        }
    }
    if isinstance(tdata, dict) {
        tdata = {k: v for (k, v) in tdata.items() if k != "response"};
        if isinstance(tdata.get("uris"), list) {
            tdata["uris"] = strip_response(tdata["uris"]);
        }
    }
    c.atype = atype;
    c.name = name;
    c.notes = notes;
    c.fields = json.dumps(strip_response(data["fields"]), separators=(",", ":")) if data.get("fields") is not None else None;
    c.password_history = json.dumps(data["passwordHistory"], separators=(",", ":")) if data.get("passwordHistory") is not None else None;
    c.data = json.dumps(tdata, separators=(",", ":"));
    c.key = data.get("key");
    c.reprompt = data.get("reprompt");
    c.favorite = bool(data.get("favorite", False));
    archived = data.get("archivedDate");
    c.archived_us = parse_date(archived) if isinstance(archived, str) else None;
    c.updated_us = now_us();
    old = folder_of(c);
    if old is not None and (folder is None or old.uuid != folder.uuid) {
        old del ->:Holds:-> c;
    }
    if folder is not None and (old is None or old.uuid != folder.uuid) {
        folder +>:Holds:+> c;
    }
    touch(u);
    return None;
}

def create(body: str, bearer: str, shared: bool) -> Reply {
    u = account(bearer);
    if u is None {
        return err("Invalid user");
    }
    data = json.loads(body);
    if not fits(data, share_spec if shared else cipher_spec) {
        return unprocessable();
    }
    if shared {
        data = data.get("cipher", data.get("Cipher"));
    }
    now = now_us();
    c = Cipher(uuid=new_uuid(), atype=int(data.get("type", 0) or 0), name="", created_us=now, updated_us=now);
    bad = save_data(c, u, data, False);
    if bad is not None {
        return bad;
    }
    root ++> c;
    return ok(cipher_json(c));
}

impl list_ciphers(bearer: str) -> Reply {
    return ok({"data": [cipher_json(c) for c in [root --> [?:Cipher]]], "object": "list", "continuationToken": None});
}

impl read_cipher(id: str, bearer: str) -> Reply {
    c = find_cipher(id);
    if c is None {
        return err("Cipher doesn't exist");
    }
    if not owned(c) {
        return err("Cipher is not owned by user");
    }
    return ok(cipher_json(c));
}

impl add_cipher(body: str, bearer: str) -> Reply {
    return create(body, bearer, False);
}

impl add_shared_cipher(body: str, bearer: str) -> Reply {
    return create(body, bearer, True);
}

impl edit_cipher(id: str, body: str, bearer: str) -> Reply {
    data = json.loads(body);
    if not fits(data, cipher_spec) {
        return unprocessable();
    }
    u = account(bearer);
    c = find_cipher(id);
    if u is None or c is None {
        return err("Cipher doesn't exist");
    }
    if not owned(c) {
        return err("Cipher is not write accessible");
    }
    if data.get("organizationId") or data.get("organizationID") {
        return err("Organization mismatch. Please resync the client before updating the cipher");
    }
    bad = save_data(c, u, data, True);
    if bad is not None {
        return bad;
    }
    return ok(cipher_json(c));
}

impl trash_cipher(id: str, bearer: str) -> Reply {
    u = account(bearer);
    c = find_cipher(id);
    if u is None or c is None {
        return err("Cipher doesn't exist");
    }
    if not owned(c) {
        return err("Cipher can't be deleted by user");
    }
    now = now_us();
    c.deleted_us = now;
    c.updated_us = now;
    touch(u);
    return empty();
}

impl drop_cipher(id: str, bearer: str) -> Reply {
    u = account(bearer);
    c = find_cipher(id);
    if u is None or c is None {
        return err("Cipher doesn't exist");
    }
    if not owned(c) {
        return err("Cipher can't be deleted by user");
    }
    remove(c);
    touch(u);
    return empty();
}

impl restore_cipher(id: str, bearer: str) -> Reply {
    u = account(bearer);
    c = find_cipher(id);
    if u is None or c is None {
        return err("Cipher doesn't exist");
    }
    if not owned(c) {
        return err("Cipher can't be restored by user");
    }
    c.deleted_us = None;
    c.updated_us = now_us();
    touch(u);
    return ok(cipher_json(c));
}
