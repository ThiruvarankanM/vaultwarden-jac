# usage: probe.py <server-url> <tag>   (tag makes the probe's emails unique per run)
import base64, hashlib, json, re, sys, urllib.request, urllib.parse, urllib.error
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from register import register
B = sys.argv[1]; T = sys.argv[2]
def call(m, p, body=None, tok=None, form=False):
    h = {"Bitwarden-Client-Version": "2025.1.0"}
    if tok: h["Authorization"] = "Bearer " + tok
    data = None
    if body is not None:
        if form: data = urllib.parse.urlencode(body).encode(); h["Content-Type"] = "application/x-www-form-urlencoded"
        else: data = json.dumps(body).encode(); h["Content-Type"] = "application/json"
    try:
        with urllib.request.urlopen(urllib.request.Request(B + p, data=data, method=m, headers=h)) as r: return r.status, r.read().decode()
    except urllib.error.HTTPError as e: return e.code, e.read().decode()
def login(email, pw):
    master = hashlib.pbkdf2_hmac("sha256", pw.encode(), email.encode(), 600000, 32)
    h = base64.b64encode(hashlib.pbkdf2_hmac("sha256", master, pw.encode(), 1, 32)).decode()
    s, b = call("POST", "/identity/connect/token", {"grant_type": "password", "username": email, "password": h, "scope": "api offline_access", "client_id": "cli", "deviceType": 8, "deviceIdentifier": "probe-" + email, "deviceName": "linux"}, form=True)
    return json.loads(b)["access_token"]
BOB, EVE = "bob%s@x.com" % T, "eve%s@x.com" % T
for e in (BOB, EVE): register(B, e, "pw")
bob, eve = login(BOB, "pw"), login(EVE, "pw")
def show(label, r):
    s, b = r
    try: b = json.loads(b); b = b.get("message", b) if isinstance(b, dict) and "message" in b else b
    except Exception: pass
    if isinstance(b, dict): b = {k: v for k, v in b.items() if k in ("type","name","login","secureNote","card","identity","sshKey","fields","passwordHistory","folderId","deletedDate","object","notes","reprompt","favorite")}
    t = json.dumps(b, sort_keys=True) if not isinstance(b, str) else b
    t = re.sub(r"(?s)<!DOCTYPE.*<title>(.*?)</title>.*", r"<html \1>", t)
    t = re.sub(r"[0-9a-f]{8}-[0-9a-f-]{27}", "<id>", t); t = re.sub(r"\d{4}-\d\d-\d\dT[\d:.]+Z", "<date>", t)
    print(label, s, t[:600])
c = lambda **kw: {"type": 1, "name": "2.n", "login": {"username": "2.u"}, **kw}
s, f = call("POST", "/api/folders", {"name": "2.f"}, bob); fid = json.loads(f)["id"]
s, x = call("POST", "/api/ciphers", c(folderId=fid), bob); cid = json.loads(x)["id"]
show("badfolder", call("POST", "/api/ciphers", c(folderId="00000000-0000-0000-0000-000000000000"), bob))
show("eve-folder", call("POST", "/api/ciphers", c(folderId=fid), eve))
show("badtype", call("POST", "/api/ciphers", c(type=9), bob))
show("noname", call("POST", "/api/ciphers", c(name=""), bob))
show("nodata", call("POST", "/api/ciphers", {"type": 1, "name": "2.n"}, bob))
show("longnotes", call("POST", "/api/ciphers", c(notes="x" * 10001), bob))
show("encfor", call("POST", "/api/ciphers", c(encryptedFor="someone"), bob))
show("stale", call("PUT", "/api/ciphers/" + cid, c(lastKnownRevisionDate="2000-01-01T00:00:00Z"), bob))
show("note", call("POST", "/api/ciphers", {"type": 2, "name": "2.n", "secureNote": {"Type": "x"}}, bob))
show("ssh", call("POST", "/api/ciphers", {"type": 5, "name": "2.n", "sshKey": {"PrivateKey": "2.p"}}, bob))
show("fields", call("POST", "/api/ciphers", c(fields=[{"name": "2.a", "value": "2.b", "type": "0"}, {"name": "2.c"}], passwordHistory=[{"password": "2.p", "lastUsedDate": "2024-05-01T10:00:00Z"}, {"password": 5}]), bob))
show("matchstr", call("POST", "/api/ciphers", c(login={"uris": [{"uri": "2.x", "match": "3"}, {"uri": "2.y", "match": "zz"}]}), bob))
show("caps", call("POST", "/api/ciphers", {"Type": 1, "Name": "2.n", "Login": {"Username": "2.u", "Uris": [{"Uri": "2.z"}]}}, bob))
show("eve-read", call("GET", "/api/ciphers/" + cid, None, eve))
show("eve-del", call("DELETE", "/api/ciphers/" + cid, None, eve))
show("eve-edit", call("PUT", "/api/ciphers/" + cid, c(), eve))
show("eve-folderget", call("GET", "/api/folders/" + fid, None, eve))
show("eve-folderdel", call("DELETE", "/api/folders/" + fid, None, eve))
show("missing-cipher", call("GET", "/api/ciphers/00000000-0000-0000-0000-000000000000", None, bob))
show("missing-folder", call("GET", "/api/folders/00000000-0000-0000-0000-000000000000", None, bob))
show("restore-live", call("PUT", "/api/ciphers/" + cid + "/restore", None, bob))
show("trash", call("PUT", "/api/ciphers/" + cid + "/delete", None, bob))
show("read-trashed", call("GET", "/api/ciphers/" + cid, None, bob))
show("folder-del", call("DELETE", "/api/folders/" + fid, None, bob))
show("cipher-after-folder-del", call("GET", "/api/ciphers/" + cid, None, bob))
show("keyid-again", call("POST", "/api/accounts/key-management/user-key-id", {"userKeyId": "a"}, bob))
show("keyid-again2", call("POST", "/api/accounts/key-management/user-key-id", {"userKeyId": "b"}, bob))
show("create-shared", call("POST", "/api/ciphers/create", {"cipher": c(), "collectionIds": []}, bob))
show("list", (lambda r: (r[0], str(len(json.loads(r[1])["data"]))))(call("GET", "/api/ciphers", None, bob)))
show("profile-keys", (lambda r: (r[0], json.dumps(sorted(json.loads(r[1]).keys()))))(call("GET", "/api/accounts/profile", None, bob)))

show("keyid-ok", call("POST", "/api/accounts/key-management/user-key-id", {"userKeyId": "0123456789abcdef0123456789abcdef"}, eve))
show("keyid-upper", call("POST", "/api/accounts/key-management/user-key-id", {"userKeyId": "0123456789ABCDEF0123456789abcdef"}, bob))
show("cipher-badkid", call("POST", "/api/ciphers", c(encryptedByKeyId="nothex"), bob))
show("cipher-wrongkid", call("POST", "/api/ciphers", c(encryptedByKeyId="ffffffffffffffffffffffffffffffff"), eve))
show("cipher-notype", call("POST", "/api/ciphers", {"name": "2.n"}, bob))
show("cipher-strtype", call("POST", "/api/ciphers", c(type="1"), bob))
show("cipher-favstr", call("POST", "/api/ciphers", c(favorite="yes"), bob))
show("cipher-list", call("POST", "/api/ciphers", [1], bob))
show("share-nocoll", call("POST", "/api/ciphers/create", {"cipher": c()}, bob))
show("share-caps", call("POST", "/api/ciphers/create", {"Cipher": c(), "CollectionIds": []}, bob))
show("folder-noname", call("POST", "/api/folders", {}, bob))
show("folder-intname", call("POST", "/api/folders", {"name": 5}, bob))
show("prelogin-empty", call("POST", "/identity/accounts/prelogin", {}))
show("prelogin-caps", call("POST", "/identity/accounts/prelogin", {"Email": "a@b.c"}))
show("sendver-noemail", call("POST", "/identity/accounts/register/send-verification-email", {"name": "x"}))
show("register-empty", call("POST", "/identity/accounts/register/finish", {"email": "z@x.com"}))
show("ftypes", call("POST", "/api/ciphers", c(fields=[{"type": "300"}, {"type": "+3"}, {"type": " 3"}, {"type": 2.5}, {"type": True}]), bob))
show("matches", call("POST", "/api/ciphers", c(login={"uris": [{"uri": "2.a", "match": " 3"}, {"uri": "2.b", "match": "+4"}, {"uri": "2.c", "match": "256"}]}), bob))
def raw(label, r):
    st, b = r; d = json.loads(b); print(label, st, json.dumps({"ph": d.get("passwordHistory"), "login": d.get("login")}, sort_keys=True))
raw("dates", call("POST", "/api/ciphers", c(login={"username": "2.u", "passwordRevisionDate": "2024-05-01T10:00:00.123456789+02:00"}, passwordHistory=[{"password": "2.a", "lastUsedDate": "2024-05-01T10:00:00+02:00"}, {"password": "2.b", "lastUsedDate": "2024-05-01 10:00:00z"}, {"password": "2.c", "lastUsedDate": "2024-05-01T10:00:00"}, {"password": "2.d", "lastUsedDate": "2024-02-30T10:00:00Z"}, {"password": "2.e", "lastUsedDate": "2024-05-01T10:00:00-00:00"}]), bob))
show("ssh-int", call("POST", "/api/ciphers", {"type": 5, "name": "2.n", "sshKey": {"keyFingerprint": 1, "privateKey": "2.p", "publicKey": "2.q"}}, bob))
show("ssh-ok", call("POST", "/api/ciphers", {"type": 5, "name": "2.n", "sshKey": {"keyFingerprint": "f", "privateKey": "2.p", "publicKey": "2.q"}}, bob))
show("note-float", call("POST", "/api/ciphers", {"type": 2, "name": "2.n", "secureNote": {"type": 0.0}}, bob))
show("note-bool", call("POST", "/api/ciphers", {"type": 2, "name": "2.n", "secureNote": {"type": True}}, bob))
