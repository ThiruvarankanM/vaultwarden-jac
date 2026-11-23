# vaultwarden in Jac

A Jac (neojac 0.4.0) port of the core of [vaultwarden](https://github.com/dani-garcia/vaultwarden), the Bitwarden-compatible server: accounts, login and refresh, sync, folders and ciphers. The official `bw` CLI works against it unchanged. What neojac could not do is in [FINDINGS.md](FINDINGS.md).

## Run

```sh
neojac check
JAC_VAULTWARDEN_LISTEN=127.0.0.1:8500 neojac run vaultwarden --fresh
```

## Layout

| Module | Holds |
|---|---|
| `wire` | `Reply` (status, body, content type), vaultwarden's error JSON, dates, HS256 JWTs, `fits` (request shape checks) |
| `model` | Nodes `User`, `Device`, `Folder`, `Cipher`; edges `Uses` (user to device) and `Holds` (folder to cipher); lookups |
| `identity` | prelogin, register (send-verification-email, finish), `/identity/connect/token` (password and refresh grants) |
| `core` | alive, config, sync, profile, revision-date, user-key-id |
| `folders` / `ciphers` | The folder and cipher routes, `Cipher::to_json`'s rules |
| `plugins/rest_transport` | Maps vaultwarden's HTTP routes (methods, path parameters, form and JSON bodies, query, headers) onto the endpoints, and a `Reply` onto the HTTP response |
| `plugins/bw_auth` | Reads `Authorization: Bearer <jwt>` so `root` is the caller's |

`archwire.jac` wires the modules; the routes are in `jac.toml` under `[transport.rest_transport]`.

### Where the data lives

- Users and their devices are on `root.shared`, since login and refresh run before there is a caller.
- Each user's folders and ciphers are on that user's own `root`.
- A cipher in a folder also has a `Holds` edge from the folder. Deleting the folder removes the edge, and the cipher stays.
- A cipher is looked up across `allroots()` and then checked against the caller's `root`. This gives the same two errors as the original: "Cipher doesn't exist" vs "Cipher is not owned by user".
- Optional text fields (a cipher's `notes`, `key`, a user's keys and hint) are kept as `""` and sent as JSON `null`, because a kept `str | None` holding `None` makes the data unreadable after a restart ([FINDINGS #14](FINDINGS.md#14-a-str--none-field-holding-none-locks-every-user-out-after-a-restart)).

### Request shapes

Rocket decodes each JSON body into a serde struct before the route runs. A body that fails gives `422`, and one that is not JSON gives `400`, both as Rocket's HTML pages. Each endpoint starts with `fits(data, spec)`. The spec mirrors the route's struct:

- a key is the field's name;
- `a|b` names a field and its alias;
- a trailing `?` marks an `Option`;
- `any` stands for a `serde_json::Value`;
- a nested dict is a nested struct.

## Proof

Both servers run behind `proof/proxy.py`, a TLS proxy that logs every request and reply. The `bw` CLI talks only to the proxy.

| Check | Command | Baseline from the original |
|---|---|---|
| `bw` session: register, login, sync, folder and item create/edit/list/trash/restore/delete, lock, unlock, logout | `BW_BIN=... proof/session.sh https://127.0.0.1:8501 <dir>` | `proof/expected.out` |
| Every request and reply of that session (23), with ids, dates, tokens and ciphertext masked | `proof/normalize.py <proxy log>` | `proof/expected.wire` |
| Error replies: login failures, bad grant, bad refresh, 401, 404, malformed body | `proof/errors.sh <url>` | `proof/expected.errors` |
| 57 edge cases: validation messages, another user's items, 422 shapes, `to_json` normalisation (uris, match, field types, dates, ssh keys, secure notes) | `proof/probe.py <url> <tag>` | `proof/expected.probe` |

All four are identical against the original (vaultwarden built from source) and the Jac version.

The error check's unknown-email `prelogin` reply depends on each install's own key (upstream picks one of 6 fake KDF settings from an HMAC of the email). So that check prints what holds on every install: the reply is one of upstream's settings, with `salt` null, the same on every call and for `" NOBODY@x.com "`.

To check a restart, seed a second user with `proof/restart.sh <proxy-url> <dir> seed`, restart the server without `--fresh`, and run `proof/restart.sh <proxy-url> <dir> check`. It logs in again with `bw` and lists the folders and items, passwords and notes decrypted. The two outputs must be the same, and they are the same as the original's.

| Check | Port | Original |
|---|---|---|
| All 4 checks above | identical | identical |
| Restart: log in again, decrypt folders and items | same as before the restart | same as before the restart |
| `errors.sh` + `probe.py`, once, on a fresh server | 2.25 s | 0.93 s |
| `probe.py`'s 61 requests | 1.84 s | 0.22 s |
| Of those, the 5 that hash a password (PBKDF2, 600,000 rounds) | 1.80 s | 0.18 s |
| Server memory (RSS) after the checks | about 14 MB | about 26 MB |

The port is as fast as the original on everything except password hashing, which is about 10 times slower inside a built neojac app ([FINDINGS #15](FINDINGS.md#15-password-hashing-is-about-10-times-slower-inside-a-built-app)).

## Not ported, or different

- **Signing:** JWTs are HS256 with a key in the app's data directory, not RS256. Clients read the claims but never check the signature.
- **Not ported:**
  - organizations, collections, sends, attachments
  - two-factor, emergency access, SSO
  - push notifications and websockets, email
  - icons, the admin panel, the web vault
  - user `enabled` flags
  - the login rate limit ("Too many login requests")
- **Domains:** `domains` returns empty lists, without the global equivalent-domains table.
- **Ciphers and registration:** v2 "blob" ciphers (`data` with `format_version`) and the current registration format (`masterPasswordAuthentication` / `masterPasswordUnlock`) are not ported. `bw` uses the older formats.
- **Login form:** the token endpoint's form fields are not type-checked the way Rocket's `FromForm` does it.
