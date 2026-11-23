obj Reply {
    has status: int = 200,
        body: str = "",
        ctype: str = "application/json";
}

def dumps(v: any) -> str;

def ok(v: any) -> Reply;

def empty -> Reply;

def err(msg: str) -> Reply;

glob rocket_422: str = "<!DOCTYPE html>\n<html lang=\"en\">\n<head>\n    <meta charset=\"utf-8\">\n    <meta name=\"color-scheme\" content=\"light dark\">\n    <title>422 Unprocessable Entity</title>\n</head>\n<body align=\"center\">\n    <div role=\"main\" align=\"center\">\n        <h1>422: Unprocessable Entity</h1>\n        <p>The request was well-formed but was unable to be followed due to semantic errors.</p>\n        <hr />\n    </div>\n    <div role=\"contentinfo\" align=\"center\">\n        <small>Rocket</small>\n    </div>\n</body>\n</html>";

def unprocessable -> Reply;

def fits(v: any, spec: dict[str, any]) -> bool;

def now_us -> int;

def fmt_date(us: int | None) -> str | None;

def parse_date(s: str) -> int | None;

def b64url(b: bytes) -> str;

def unb64url(s: str) -> bytes;

def sign(claims: dict[str, any]) -> str;

def verify(token: str, iss: str) -> dict[str, any] | None;

def new_uuid -> str;
