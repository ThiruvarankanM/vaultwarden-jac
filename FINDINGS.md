# neojac findings: porting vaultwarden to Jac

**Original:** [dani-garcia/vaultwarden](https://github.com/dani-garcia/vaultwarden), a Bitwarden-compatible password-manager server in Rust (Rocket + Diesel, 64 files, 40.6k lines).
**Port:** this repo, on neojac 0.3.3: 1,292 lines of app code and 411 lines in 2 plugins.
**Scope:** accounts, login and refresh, sync, folders and ciphers. See the [README](README.md) for what isn't ported.
**Status:** done.

## The short version

- **Works with the real client:** the official Bitwarden `bw` CLI runs against the Jac port unchanged.
- **Same replies:** all 4 comparison checks match the original exactly:
  - the full `bw` session;
  - 23/23 requests and replies;
  - 13/13 error cases;
  - 57/57 edge cases.
- **13 findings:** 3 blockers, 4 major and 6 minor.
- **The built-in server can't describe a real HTTP API:** it has no PUT/DELETE, no path parameters and no status codes. So the port has its own transport plugin.
- **Hand-written:** `neojac port` translated **0 of the 64** Rust files.

## Ground rules

We met neojac cold, the way a new user would:

- Only the latest neojac release was used.
- Everything about Jac was learned from what neojac ships: `neojac docs`, `neojac skills`, `neojac help` and its error messages.
- neojac's own source was never read. Each bug is reported by its symptom and a small repro, and any guess at a cause is labelled as a guess.
- The original app's source could be read freely.
- Every gap was logged when it was hit. Nothing was quietly worked around.

## What we did

| Step | Result |
|---|---|
| 1. Machine-translate (`neojac port`) | 0 of 64 files. A binary crate is refused, and two inputs crashed the tool with a Python traceback. |
| 2. Write it by hand, in idiomatic Jac | Done. Users and devices are on `root.shared`, each user's folders and ciphers are on their own `root`, and the modules are wired in `archwire.jac`. |
| 3. Plugins for what the server can't do | `rest_transport` maps vaultwarden's routes, methods, bodies and statuses. `bw_auth` reads the bearer JWT. |
| 4. Prove it behaves the same | All 4 checks below are identical. |

## How "the same" is checked

Both servers run behind `proof/proxy.py`, a TLS proxy that logs every request and reply. Ids, dates, tokens and ciphertext are masked. Any other difference counts as a failure, including a status code, a field, the order of keys or an error message.

| Check | Baseline from the original | Result |
|---|---|---|
| Real `bw` session: register, log in, sync, create, edit, trash, restore and delete folders and items, lock, unlock, log out | `proof/expected.out` | identical |
| Every request and reply of that session | `proof/expected.wire` | 23 / 23 |
| Error replies: bad logins, bad grants, bad refresh, 401, 404, malformed bodies | `proof/expected.errors` | 13 / 13 |
| Edge cases: validation messages, another user's items, 422 shapes, cipher JSON normalisation | `proof/expected.probe` | 57 / 57 |

## Findings at a glance

| Severity | Count | Meaning |
|---|---|---|
| Blocker | 3 | Stops the port as neojac stands |
| Major | 4 | Needs a real workaround, such as a custom plugin |
| Minor | 6 | Friction, wrong docs, or an unclear error |

Click a number to jump to its full repro.

### The built-in server

| # | Severity | What happens |
|---|---|---|
| [#4](#4-restspec-cannot-serve-an-existing-http-api) | Blocker | `@restspec` has GET and POST only, with no path parameters, headers, body or status. An existing HTTP API can't be served. |
| [#7](#7-an-endpoint-cannot-learn-who-is-calling) | Major | An endpoint can't tell who is calling. The auth plugin knows, but the endpoint only gets `root`, so the JWT is checked twice. |
| [#8](#8-no-json-value-type-for-an-endpoint) | Major | There is no JSON value type for endpoints, so an open-shaped body (a Bitwarden cipher) can't be a parameter. |
| [#10](#10-an-endpoints-reply-has-no-status-content-type-or-headers) | Major | Replies have no status, content type or headers. A 400 with JSON, a 401 with HTML and an empty 200 all need a plugin. |

### Porting tools

| # | Severity | What happens |
|---|---|---|
| [#2](#2-neojac-port-refuses-a-binary-crate) | Blocker | `port` refuses a binary crate (no `src/lib.rs`), and every Rust server is one. |
| [#3](#3-rust-port-refuses-nearly-every-construct-real-code-uses) | Blocker | The Rust port refuses `String`, enums, `match`, traits, generics, closures, modules and `use`. |
| [#1](#1-neojac-port-crashes-on-a-binary-crates-src-or-mainrs) | Major | `port` on a crate's `src/` or `main.rs` crashes with a Python traceback. |

### Language

| # | Severity | What happens |
|---|---|---|
| [#11](#11-a-class-cannot-derive-from-an-obj) | Minor | A `class` can't derive from an `obj`, so a transport's claim that holds a Python server must be an `obj`. |

### Error messages

| # | Severity | What happens |
|---|---|---|
| [#6](#6-restspec-diagnostics-wrong-wording-and-a-location-inside-neojac) | Minor | `HTTPMethod.PUT` gets an unrelated error, and a restspec error points into neojac's runtime file. |
| [#9](#9-a-union-endpoint-is-reported-inside-neojacs-runtime) | Minor | A union-typed endpoint is reported inside neojac's codec, and only after other errors are fixed. |
| [#13](#13-lint-rules-print-as-errors-that-do-not-stop-a-build) | Minor | Lints print as `error[...]` and fail `check`, but `build` succeeds. |

### Documentation

| # | Severity | What happens |
|---|---|---|
| [#5](#5-writing-a-plugin-points-at-examples-that-are-not-shipped) | Minor | The `writing-a-plugin` skill points at examples that don't ship. |
| [#12](#12-data_dir-is-missing-from-the-stdjacplan-table) | Minor | `data_dir()` is used in the guides but missing from the `stdjac.plan` reference table. |

Other ports from the same run: [marked-jac](https://github.com/ThiruvarankanM/marked-jac).

---

## Setup details

Compiler: neojac 0.3.3 (macos-aarch64, 98a4abf03de2)
Target: vaultwarden, a Bitwarden-compatible password manager server (Rust, 64 files, 40.6k lines; Rocket + Diesel)
Proof: the same HTTP requests (as the Bitwarden clients send them) and the real `bw` CLI, against the original and the Jac version.

| # | Area | Severity | Gap |
|---|---|---|---|
| 1 | port | major | `neojac port` on a binary crate's `src/` or `main.rs` crashes with a Python traceback |
| 2 | port | blocker | `neojac port` refuses a binary crate (no `src/lib.rs`): every Rust server is one |
| 3 | port | blocker | Rust port refuses `String`, enums, `match`, traits, generics, closures, modules, `use` and every other crate: 0 of vaultwarden's 64 files can port |
| 4 | server | blocker | `@restspec` has GET/POST only, no parameters, no path parameters, no request headers or body, no status code: an existing HTTP API cannot be served |
| 5 | docs | minor | `writing-a-plugin` skill points at worked examples in neojac's repository (`tests/plugins/...`), which ship nowhere in the docs |
| 6 | diagnostics | minor | `HTTPMethod.PUT` is E0108 "evaluates only enum members and methods" (not "no member PUT"); E0109 for a restspec with parameters points into neojac's `rt/stdjac/server.jac`, not at the user's function |
| 7 | server | major | An endpoint cannot learn who is calling: `Auth.caller()` computes the account id, but server code only gets `root`; `signed_in_as()` exists for pages only |
| 8 | crossings | major | No JSON value type for an endpoint: `any` is E1308 and a union of two types is refused, so an open-shaped body (Bitwarden's cipher) cannot be a parameter |
| 9 | diagnostics | minor | A union endpoint is E1229 "serve_def() cannot be specialized" plus two E0109s inside neojac's `rt/stdjac/codec.jac`; and it is not reported at all while the same file has an E1308 |
| 10 | server | major | An endpoint's reply has no status, content type or headers: a 400 with JSON, a 401 with HTML, a bare JSON string and an empty 200 all need a transport plugin that unwraps a `Reply` object |
| 11 | language | minor | E5090: a `class` cannot derive from an `obj` (`stdjac.remote.Claim`) "yet", so a transport's claim holding a Python server must be an `obj` |
| 12 | docs | minor | `stdjac.plan`'s `data_dir()` is used by `apps/plugins` and the `writing-a-plugin` skill but is missing from the `stdjac.plan` table, which lists only `plan().data_dir` |
| 13 | diagnostics | minor | Lint rules print as `error[W3055]` and make `neojac check` exit 1, while `neojac build` of the same file succeeds |

---

## 1. `neojac port` crashes on a binary crate's `src/` or `main.rs`

Repro:

```sh
mkdir -p rbin/src
printf '[package]\nname = "rbin"\nversion = "0.1.0"\nedition = "2021"\n' > rbin/Cargo.toml
printf 'fn main() { let x = 1; }\n' > rbin/src/main.rs
neojac port --check rbin            # clean E4001 (finding 2)
neojac port --check rbin/src        # traceback
neojac port --check rbin/src/main.rs  # traceback
```

Result:

```text
Traceback (most recent call last):
  File "compiler/main.jac", line 194, in <module>
  ...
  File "compiler/ecosystems/impl/rmod.impl.jac", line 257, in <lambda>
ValueError: error: no library targets found in package `rbin`
```

Expected: the same `E4001 ... crate with no library` the crate root gets, as a diagnostic (also in `--diagnostics json`).

Other languages: `cargo` itself answers a target-less command with one `error:` line; `c2rust` / `pyo3` tooling report unsupported crate kinds as diagnostics, not crashes.

Suggested support: catch the cargo-metadata failure and report it as E4001 at the `Cargo.toml`.

## 2. `neojac port` refuses a binary crate

Repro: as in 1, `neojac port --check rbin`:

```text
rbin/Cargo.toml: error[E4001]: port does not translate a Rust crate with no library (src/lib.rs) yet
```

`neojac docs interop/port-rust`: "A crate is ported from its root file, `src/lib.rs`." vaultwarden, like every Rust server and CLI, is a binary crate (`src/main.rs`).

Other languages: `c2rust` translates any C translation unit, `main` included; Python's `2to3` translates scripts as modules.

Suggested support: port `src/main.rs` as a Jac module with `with entry` calling the ported `main`.

## 3. Rust port refuses nearly every construct real code uses

Repro (`rlib/src/lib.rs`):

```rust
pub enum Kind { Login, Note }
pub fn code(k: Kind) -> i32 { match k { Kind::Login => 1, Kind::Note => 2 } }
pub fn name() -> String { String::from("hi") }
```

`neojac port --check rlib`:

```text
error[E4001]: port does not translate a Rust `std::string::String` yet
error[E4001]: port does not translate a call of 'std::convert::From::from', which is another crate's, a trait's or generic yet
    = help: Jac does not import Rust's own items yet (#208): keep this in Rust.
```

`neojac docs interop/port-rust` lists as refused: references other than `self`, enums and `match`, traits, generics, closures, tuples, arrays, slices, strings, modules, `use`, macros expanding to these (`println!`), and every other crate's function, std's too. vaultwarden uses all of them in every file, so 0 of 64 files port; the port is a hand rewrite.

Other languages: Jac itself has enums, `match`, interfaces, generics, lambdas, tuples and `str`, so each refused construct has a target (`neojac docs language/enums`, `pattern-matching`, `interfaces`, `generics`).

Suggested support, in order of what unblocks most code: `String`/`&str` to `str`, `use` and modules, enums + `match` to Jac enums + `match`, `Vec`/`HashMap` to `list`/`dict`, closures to lambdas, `impl Trait for T` to interfaces.

## 4. `@restspec` cannot serve an existing HTTP API

`neojac docs apps/server` ("A path of its own: @restspec") and `neojac docs stdjac.server`:

- `HTTPMethod` is `GET` or `POST`; "A request with another method is 404".
- "The function takes no parameters."; a function with parameters is E0109.
- No path parameters (`/api/ciphers/{id}`), no query string, no request headers, no body.
- No status code: an enveloped reply is `{"ok": ..., "data": ...}`, an unenveloped one must be a `str`.

The Bitwarden clients call, among others, `POST /identity/connect/token` (form-encoded), `PUT /api/ciphers/<id>`, `DELETE /api/folders/<id>`, and expect `400` with `{"error": "invalid_grant", ...}` for a wrong password. None of that can be written.

Repro:

```jac
import from stdjac.server { HTTPMethod, restspec }

@restspec(method=HTTPMethod.GET, path="/api/ciphers/{id}")
def:pub cipher(id: str) -> str {
    return id;
}
```

Result (`neojac check api`): E0109 `comptime assertion failed: a function served at a path of its own takes no parameters`; `HTTPMethod.PUT` is E0108 (finding 6).

Other languages: Express `app.put("/api/ciphers/:id", (req, res) => res.status(400).json(...))`, FastAPI `@app.put("/api/ciphers/{id}")` with typed path/query/body/header parameters and `status_code`, Django URL patterns, Rocket `#[put("/ciphers/<id>", data = "<body>")]`.

Suggested support: `HTTPMethod` with PUT/PATCH/DELETE; path templates bound to parameters by name; query and body (JSON or form) decoded into the remaining parameters by type, as `/__jac/call/` already does; a `Reply(status, body, headers)` result type; selected request headers as parameters.

What this port does instead: the `transport` abstraction's `Request`/`Response` carry method, path, query, headers, body and status, so a transport plugin maps the routes onto endpoints (see the design notes).

## 5. `writing-a-plugin` points at examples that are not shipped

`neojac skills writing-a-plugin`, the table "A worked example in neojac's repository": `tests/plugins/jsonstore`, `tests/plugins/ticket_auth`, `tests/plugins/line_transport`, ... Nothing under `neojac docs --path` holds their source: `neojac docs search line_transport` finds the skill and one table row of `apps/plugins` ("A wire of its own, a line of JSON each way over TCP"). A transport plugin's whole `listen`/`claim`/`send` contract has to be learned from the `apps/stdjac` table alone.

Suggested support: ship each example as a docs page (as `apps/stdjac` does for `stdjac.graph`), or as `neojac skills` assets.

## 6. restspec diagnostics: wrong wording, and a location inside neojac

Repro: the `api.jac` of finding 4 plus

```jac
@restspec(method=HTTPMethod.PUT, path="/x")
def:pub put_x -> str {
    return "x";
}
```

`neojac check api`:

```text
api.jac:8:18: error[E0108]: cannot evaluate at compile time: neojac evaluates only enum members and methods as attributes
/Users/thiru-07/.neojac/0.3.3/rt/stdjac/server.jac:346:5: error[E0109]: comptime assertion failed: a function served at a path of its own takes no parameters
 346 |     comptime assert len(params(f))
```

Expected: `HTTPMethod has no member PUT (it has GET, POST)`, and E0109 at `api.jac:3` (the decorated function), with the library line as a note. As written, the second error sends the user into neojac's runtime source.

Other languages: rustc reports a failed `const` assertion / trait bound at the user's call site with "required by this bound in ..." as a note; TypeScript names the missing enum member.

Suggested support: E0108 for a missing member of a known enum says so; a `comptime assert` failing for a decorator's argument is reported at the decorated declaration.

## 7. An endpoint cannot learn who is calling

`neojac docs apps/server` ("Who is calling"): "Inside an endpoint, `root` is the caller's own root." `neojac docs stdjac.server`: the `Auth` plugin's `caller(headers) -> str | None` says "who a request's caller is". Nothing gives that string to the endpoint. `neojac docs search signed_in_as` finds it only in `apps/pages` (`@jac/runtime`, the browser).

vaultwarden keeps accounts in one table and needs the caller's account id in every protected route (to load the user record, its key id, its revision date). With only `root`, the port keeps users on `root.shared` and passes the bearer token to every `:protect` endpoint as an argument, so the JWT is verified twice: once by the auth plugin (to choose `root`) and again in the app (to find the `User`). The verifying code is duplicated in `plugins/bw_auth/auth.jac` and `wire.jac`, since a plugin and the app share no module.

Repro: there is no function to call; `neojac docs search "caller's id"` and `neojac docs search "who is calling"` return only the pages above.

Other languages: FastAPI `Depends(get_current_user)`, Express `req.user`, Rocket request guards (`headers: Headers` in vaultwarden itself), Django `request.user`.

Suggested support: `stdjac.server.caller() -> str | None` inside an endpoint, returning what `Auth.caller` returned for the request.

## 8. No JSON value type for an endpoint

Repro (`svc.jac` in an app with one native space):

```jac
def:pub echo(body: dict[str, any]) -> dict[str, any];
```

```text
svc.jac:1:1: error[E1308]: 'body: dict[str, any]' is not sendable across a concurrency boundary
svc.jac:1:1: error[E1308]: 'echo() -> dict[str, any]' is not sendable across a concurrency boundary
```

`neojac docs apps/crossings` ("What crosses"): "Not sendable: a function value, an `any`, ... A union of several types besides `None` is refused too, since a JSON value cannot say which it is." Only a walker's reports may be "JSON's own values", and only untyped.

A Bitwarden cipher body is open-shaped: `login`, `card`, `identity`, `sshKey`, ... with client-defined keys and `fields` whose `type` may be an int or a string; vaultwarden stores each as raw JSON (`serde_json::Value`). Typing it as objects would reject what the clients send. The port sends every body as JSON text (`body: str`) and parses it in the endpoint, which also loses strict decoding.

Other languages: `serde_json::Value`, TypeScript `unknown`/`JsonValue`, Pydantic `dict[str, Any]` / `Json`, Go `json.RawMessage`.

Suggested support: a sendable `json` type (null, bool, number, str, list of json, dict of str to json) that crosses as-is.

## 9. A union endpoint is reported inside neojac's runtime

Repro:

```jac
def:pub either(v: int | str) -> int | str;
```

```text
svc.jac:1:1: error[E1229]: serve_def() cannot be specialized for f=either
/Users/thiru-07/.neojac/0.3.3/rt/stdjac/codec.jac:96:9: error[E0109]: comptime assertion failed: the codec takes a union of one type and None
    in encode_sent[int | str], asked for at .../rt/stdjac/codec.jac:68:16
/Users/thiru-07/.neojac/0.3.3/rt/stdjac/codec.jac:188:9: error[E0109]: comptime assertion failed: the codec takes a union of one type and None
```

With `echo` of finding 8 in the same file, `neojac check` reports the two E1308s and nothing for `either`; it shows up only after they are fixed.

Expected: one E1308 at `svc.jac:1` (`'v: int | str' is not sendable`), as the crossings page says, reported together with the others.

## 10. An endpoint's reply has no status, content type or headers

`neojac docs apps/server`: "Every reply but a stream's is JSON: `{"ok": true, "data": ...}` or `{"ok": false, "kind": ..., "detail": ...}`", with the status chosen by `kind` (its status table). `@restspec(..., produces="text/plain", envelope=False)` drops the envelope, for GET/POST with no parameters only (finding 4). vaultwarden's clients depend on:

- `400` with `{"message": ..., "validationErrors": ..., "errorModel": ..., "object": "error"}` (in that key order) for every validation error;
- `401` with Rocket's HTML page for a missing or bad token;
- `400` with `{"error": "invalid_grant"}` for a bad refresh token;
- `200` with an empty body (`DELETE /api/folders/<id>`), and `200` with a bare JSON string (`/alive`, `send-verification-email`);
- `text/plain` or JSON for the same route, chosen by `Accept`.

The port returns `Reply(status, body, ctype)` from every endpoint, and the `rest_transport` plugin turns that object into the HTTP response. It also maps vaultwarden's routes, path parameters, form bodies, query strings and selected headers onto `/__jac/call/` itself (about 250 lines on `http.server`). This is finding 4's cost.

Suggested support: a `stdjac.server.Reply(status, body, headers)` an endpoint may return, honoured by the built-in transport.

## 11. A `class` cannot derive from an `obj`

Repro:

```jac
import from stdjac.remote { Claim }

class HttpClaim(Claim) {
    has srv: int = 0;
}
```

```text
cls.jac:3:1: error[E5090]: neojac does not support a `class` deriving from Claim, which is not a `class` yet
```

A transport mixes Python classes (`http.server.BaseHTTPRequestHandler`, a `class`) with the plugin interfaces (`obj`). The port makes the claim an `obj` holding the server as `any`.

## 12. `data_dir()` is missing from the `stdjac.plan` table

`neojac docs apps/plugins` ("Writing a plugin") calls `data_dir()`, and the `writing-a-plugin` skill says "`stdjac.plan`'s `data_dir()` is where a program keeps its data". The `stdjac.plan` table in `neojac docs apps/stdjac` lists `plan()`, `keep_arrangement`, `remote_url` and `env_name`; `data_dir` appears only as a field of `plan()`'s `AppPlan`. The function works (the port keeps its JWT key there), but its signature and what it returns outside an app are undocumented.

Suggested support: a `data_dir() -> str` row in the table.

## 13. Lint rules print as errors that do not stop a build

Repro (`main.jac` in a project with an empty `jac.toml`):

```jac
def f -> None {
    print("x");
}

with entry {
    f();
}
```

`neojac check main.jac` exits 1 with `error[W3055]` and `error[W3037]`; `neojac build main.jac -o m` exits 0 and builds `m`. `neojac docs lint`: the rules are "reported by `check` only", and the group `"clean"` is on by default. The behaviour is documented, but a `W` code labelled `error` is read as a failure; `warning[W3055]` (or `lint[...]`) would match what `build` does.

