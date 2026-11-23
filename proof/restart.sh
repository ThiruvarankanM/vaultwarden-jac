#!/bin/bash
# usage: restart.sh <server-url> <bw-data-dir> seed|check
set -e
BW="${BW_BIN:?set BW_BIN to the bw executable}"
export BITWARDENCLI_APPDATA_DIR="$2"
export NODE_EXTRA_CA_CERTS="$(dirname "$0")/cert.pem"
rm -rf "$2" && mkdir -p "$2"
EMAIL=rex@example.com
PASS='tall ship quiet harbor'

if [ "$3" = seed ]; then SSL_CERT_FILE="$NODE_EXTRA_CA_CERTS" python3 "$(dirname "$0")/register.py" "$1" "$EMAIL" "$PASS" > /dev/null; fi
"$BW" config server "$1" > /dev/null
export BW_SESSION=$("$BW" login "$EMAIL" "$PASS" --raw)
"$BW" sync > /dev/null
if [ "$3" = seed ]; then
  F=$("$BW" get template folder | jq '.name="Home"' | "$BW" encode | "$BW" create folder | jq -r .id)
  "$BW" get template item | jq --arg f "$F" '.name="Bank" | .folderId=$f | .notes="pin 4321" | .login={"username":"rex","password":"vault-pass","uris":[{"uri":"https://bank.example.com"}]}' | "$BW" encode | "$BW" create item > /dev/null
  "$BW" get template item | jq '.name="Wifi" | .login={"username":"guest","password":"wifi-pass"}' | "$BW" encode | "$BW" create item > /dev/null
  "$BW" sync > /dev/null
fi
"$BW" list folders | jq -c '[.[] | .name]'
"$BW" list items | jq -c '[.[] | {name, notes, folder: (.folderId != null), username: .login.username, password: .login.password, uri: .login.uris[0].uri}] | sort_by(.name)'
"$BW" logout > /dev/null
