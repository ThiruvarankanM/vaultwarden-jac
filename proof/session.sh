#!/bin/bash
# usage: session.sh <server-url> <bw-data-dir>
set -e
BW="${BW_BIN:?set BW_BIN to the bw executable}"
export BITWARDENCLI_APPDATA_DIR="$2"
export NODE_EXTRA_CA_CERTS="$(dirname "$0")/cert.pem"
rm -rf "$2" && mkdir -p "$2"
EMAIL=amy@example.com
PASS='correct horse battery staple'

SSL_CERT_FILE="$NODE_EXTRA_CA_CERTS" python3 "$(dirname "$0")/register.py" "$1" "$EMAIL" "$PASS"
"$BW" config server "$1"
export BW_SESSION=$("$BW" login "$EMAIL" "$PASS" --raw)
"$BW" sync
FOLDER=$("$BW" get template folder | jq '.name="Work"' | "$BW" encode | "$BW" create folder | jq -r .id)
ITEM=$("$BW" get template item | jq --arg f "$FOLDER" '.name="Mail" | .folderId=$f | .login={"username":"amy","password":"s3cret","uris":[{"uri":"https://mail.example.com"}]}' | "$BW" encode | "$BW" create item | jq -r .id)
"$BW" get item "$ITEM" | jq -c '{name, login: {username: .login.username, password: .login.password}}'
"$BW" get item "$ITEM" | jq '.notes="edited"' | "$BW" encode | "$BW" edit item "$ITEM" | jq -c '{name, notes}'
"$BW" list items | jq -c '[.[] | .name]'
"$BW" list folders | jq -c '[.[] | .name]'
"$BW" delete item "$ITEM"
"$BW" list items --trash | jq -c '[.[] | .name]'
"$BW" restore item "$ITEM"
"$BW" delete item "$ITEM" --permanent
"$BW" delete folder "$FOLDER"
"$BW" list items | jq -c '[.[] | .name]'
"$BW" lock
export BW_SESSION=$("$BW" unlock "$PASS" --raw)
"$BW" sync
"$BW" status | jq -c '{status, userEmail}'
"$BW" logout
