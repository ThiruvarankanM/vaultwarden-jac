import base64, hashlib, hmac, json, os, sys, urllib.request

from cryptography.hazmat.primitives import padding, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

ITER = 600000


def b64(b):
    return base64.b64encode(b).decode()


def hkdf_expand(prk, info, n=32):
    out, t, i = b"", b"", 1
    while len(out) < n:
        t = hmac.new(prk, t + info + bytes([i]), hashlib.sha256).digest()
        out += t
        i += 1
    return out[:n]


def enc_string(data, enc_key, mac_key):
    iv = os.urandom(16)
    p = padding.PKCS7(128).padder()
    ct = Cipher(algorithms.AES(enc_key), modes.CBC(iv)).encryptor()
    body = ct.update(p.update(data) + p.finalize()) + ct.finalize()
    mac = hmac.new(mac_key, iv + body, hashlib.sha256).digest()
    return f"2.{b64(iv)}|{b64(body)}|{b64(mac)}"


def post(base, path, body, accept="application/json"):
    req = urllib.request.Request(base + path, data=json.dumps(body).encode(), method="POST",
                                 headers={"Content-Type": "application/json", "Accept": accept})
    with urllib.request.urlopen(req) as r:
        return r.status, r.read().decode()


def register(base, email, password, name="Test User"):
    email = email.lower()
    master = hashlib.pbkdf2_hmac("sha256", password.encode(), email.encode(), ITER, 32)
    mp_hash = b64(hashlib.pbkdf2_hmac("sha256", master, password.encode(), 1, 32))
    s_enc, s_mac = hkdf_expand(master, b"enc"), hkdf_expand(master, b"mac")
    user_key = os.urandom(64)
    priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pub_der = priv.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    priv_der = priv.private_bytes(serialization.Encoding.DER, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
    _, token = post(base, "/identity/accounts/register/send-verification-email", {"email": email, "name": name})
    token = json.loads(token) if token.startswith('"') else token
    return post(base, "/identity/accounts/register/finish", {
        "email": email,
        "emailVerificationToken": token,
        "masterPasswordHash": mp_hash,
        "masterPasswordHint": None,
        "userSymmetricKey": enc_string(user_key, s_enc, s_mac),
        "userAsymmetricKeys": {"publicKey": b64(pub_der), "encryptedPrivateKey": enc_string(priv_der, user_key[:32], user_key[32:])},
        "kdf": 0,
        "kdfIterations": ITER,
    })


if __name__ == "__main__":
    print(*register(sys.argv[1], sys.argv[2], sys.argv[3]))
