import json;
import threading;
import time;
import http.server;
import http.client;
import urllib.parse;
import from transport.contract { Transport, Request, Response, Claim, Tick, CannotListen }
import from common.contract { Host }

obj Route {
    has method: str,
        parts: list[str],
        target: str,
        args: list[str];
}

obj HttpClaim(Claim) {
    has srv: any = None;
}

glob served: dict[str, any] = {};

class Handler(http.server.BaseHTTPRequestHandler) {
    def do_GET;

    def do_POST;

    def do_PUT;

    def do_DELETE;

    def log_message(format: str, *args: any);
}

obj RestTransport(Transport) {
    has routes: list[str] = [];

    def open(host: dyn Host);

    def send(address: str, r: Request, seconds: float) -> Response;

    def claim(address: str) -> Claim;

    def listen(
        claim: Claim,
        handle: Callable[[Request], Response],
        ticks: list[Tick],
        listening: Callable[[int], None] | None,
    );

    def on_loop(work: Callable[[], None]);

    def serving -> bool;

    def serves_paths -> bool;
}

def parse_route(spec: str) -> Route;

def route_args(r: Route, method: str, parts: list[str]) -> dict[str, str] | None;

def body_of(ctype: str, raw: bytes) -> any;

glob unauthorized: str = "<!DOCTYPE html>\n<html lang=\"en\">\n<head>\n    <meta charset=\"utf-8\">\n    <meta name=\"color-scheme\" content=\"light dark\">\n    <title>401 Unauthorized</title>\n</head>\n<body align=\"center\">\n    <div role=\"main\" align=\"center\">\n        <h1>401: Unauthorized</h1>\n        <p>The request requires user authentication.</p>\n        <hr />\n    </div>\n    <div role=\"contentinfo\" align=\"center\">\n        <small>Rocket</small>\n    </div>\n</body>\n</html>";

glob bad_request: str = "<!DOCTYPE html>\n<html lang=\"en\">\n<head>\n    <meta charset=\"utf-8\">\n    <meta name=\"color-scheme\" content=\"light dark\">\n    <title>400 Bad Request</title>\n</head>\n<body align=\"center\">\n    <div role=\"main\" align=\"center\">\n        <h1>400: Bad Request</h1>\n        <p>The request could not be understood by the server due to malformed syntax.</p>\n        <hr />\n    </div>\n    <div role=\"contentinfo\" align=\"center\">\n        <small>Rocket</small>\n    </div>\n</body>\n</html>";

glob not_found: str = "{\"error\":{\"code\":404,\"description\":\"The requested resource could not be found.\",\"reason\":\"Not Found\"}}";

def arg_value(spec: str, vals: dict[str, str], headers: dict[str, str]) -> tuple[str, str];

def answer(h: any);

def unwrap(resp: Response) -> Response;

def write(h: any, resp: Response);
