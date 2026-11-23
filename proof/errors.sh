# usage: errors.sh <server-url>
B=$1
OUT=$(mktemp)
c(){ echo "== $1"; shift; curl -s -o $OUT -w '%{http_code} %{content_type}\n' "$@"; head -c 400 $OUT | sed -E 's/[0-9]{4}-[0-9-]+T[0-9:.]+Z/<date>/g'; echo; }
F='grant_type=password&username=amy@example.com&password=x&scope=api%20offline_access&client_id=cli&deviceType=8&deviceIdentifier=d1&deviceName=linux'
c nover -X POST $B/identity/connect/token -d "$F"
c badpass -X POST $B/identity/connect/token -H 'Bitwarden-Client-Version: 2025.1.0' -d "$F"
c blank -X POST $B/identity/connect/token -d 'grant_type=password&username=amy@example.com'
c nouser -X POST $B/identity/connect/token -H 'Bitwarden-Client-Version: 2025.1.0' -d "${F/amy/zed}"
c badgrant -X POST $B/identity/connect/token -d 'grant_type=foo'
c sso -X POST $B/identity/connect/token -d 'grant_type=authorization_code'
c badrefresh -X POST $B/identity/connect/token -d 'grant_type=refresh_token&refresh_token=abc'
c 404 $B/api/nope
c 401 $B/api/sync
c 401bad $B/api/sync -H 'Authorization: Bearer junk'
k(){ curl -s -X POST $B/identity/accounts/prelogin -H 'Content-Type: application/json' -d "{\"email\":\"$1\"}"; }
echo "== prelogin (unknown email: the settings depend on the install's key, so check what holds on every install)"
curl -s -o /dev/null -w '%{http_code} %{content_type}\n' -X POST $B/identity/accounts/prelogin -H 'Content-Type: application/json' -d '{"email":"nobody@x.com"}'
python3 - "$(k nobody@x.com)" "$(k nobody@x.com)" "$(k ' NOBODY@x.com ')" <<'P'
import json, sys
a, b, c = (json.loads(x) for x in sys.argv[1:])
fake = [(0, 600000, None, None), (0, 100000, None, None), (0, 5000, None, None), (1, 3, 64, 4), (1, 6, 32, 4)]
t = (a["kdf"], a["kdfIterations"], a["kdfMemory"], a["kdfParallelism"])
s = {"iterations": t[1], "kdfType": t[0], "memory": t[2], "parallelism": t[3]}
print("one of upstream's fake settings, salt null:", t in fake and a["kdfSettings"] == s and a["salt"] is None)
print("the same on every call:", a == b)
print("the same for ' NOBODY@x.com ':", a == c)
P
c badjson -X POST $B/identity/accounts/prelogin -H 'Content-Type: application/json' -d '{oops'
c alive $B/alive
