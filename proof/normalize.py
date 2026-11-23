# usage: normalize.py <proxy-log.jsonl>: masks ids, dates, tokens and ciphertext
import json, re, sys
UUID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")
DATE = re.compile(r"^\d{4}-\d\d-\d\dT[\d:.]+Z?$")
SECRET = {"access_token","refresh_token","key","privatekey","publickey","name","notes","username","password","uri","securitystamp","masterpasswordhash","userkey","encryptedprivatekey","wrappedprivatekey","signedpublickey","resetpasswordkey","deviceidentifier","device_identifier","emailverificationtoken","stamp","value","totp","folderid","id","masterkeyencrypteduserkey","usersymmetrickey","lastknownrevisiondate","encryptedfor"}
def n(v, k=""):
    if isinstance(v, dict): return {a: n(b, a.lower()) for a, b in sorted(v.items())}
    if isinstance(v, list): return [n(x) for x in v]
    if isinstance(v, str):
        if DATE.match(v): return "<date>"
        if k in SECRET or v.startswith("2.") or v.startswith("eyJ"): return "<s>"
        return UUID.sub("<id>", v)
    if isinstance(v, int) and k in ("expires_in",) : return v
    if isinstance(v, int) and v > 10**11: return "<ms>"
    return v
for line in open(sys.argv[1]):
    r = json.loads(line)
    print(r["method"], UUID.sub("<id>", r["path"].split("?")[0]), r["status"])
    print("  req ", re.sub(r"[0-9a-f]{32}", "<kid>", json.dumps(n(r["request"]), sort_keys=True)))
    print("  resp", re.sub(r"[0-9a-f]{32}", "<kid>", json.dumps(n(r["response"]), sort_keys=True)))
