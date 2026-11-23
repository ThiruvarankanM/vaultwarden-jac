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
c prelogin -X POST $B/identity/accounts/prelogin -H 'Content-Type: application/json' -d '{"email":"nobody@x.com"}'
c badjson -X POST $B/identity/accounts/prelogin -H 'Content-Type: application/json' -d '{oops'
c alive $B/alive
