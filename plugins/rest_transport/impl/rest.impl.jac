impl Handler.do_GET {
    answer(self);
}

impl Handler.do_POST {
    answer(self);
}

impl Handler.do_PUT {
    answer(self);
}

impl Handler.do_DELETE {
    answer(self);
}

impl Handler.log_message(format: str, *args: any) {
    return;
}

impl RestTransport.send(address: str, r: Request, seconds: float) -> Response {
    u = urllib.parse.urlsplit(address);
    conn = http.client.HTTPConnection(u.hostname, u.port, timeout=seconds);
    conn.request(r.method, r.path, body=r.body, headers=r.headers);
    resp = conn.getresponse();
    return Response(
        status=resp.status,
        ctype=resp.getheader("Content-Type", ""),
        body=resp.read(),
        headers={},
        events=None,
    );
}

impl RestTransport.claim(address: str) -> Claim {
    host = address.rsplit(":", 1);
    try {
        srv = http.server.ThreadingHTTPServer((host[0], int(host[1])), Handler);
    } except OSError as e {
        raise CannotListen(reason=str(e.strerror));
    }
    return HttpClaim(srv=srv);
}

impl RestTransport.listen(
    claim: Claim,
    handle: Callable[[Request], Response],
    ticks: list[Tick],
    listening: Callable[[int], None] | None,
) {
    if not isinstance(claim, HttpClaim) {
        return;
    }
    srv = claim.srv;
    served["handle"] = handle;
    served["routes"] = [parse_route(r) for r in self.routes];
    served["work"] = [];
    threading.Thread(target=srv.serve_forever, args=(0.05,), daemon=True).start();
    if listening is not None {
        listening(srv.server_port);
    }
    due = {t.name: time.time() for t in ticks};
    while True {
        for t in ticks {
            if time.time() >= due[t.name] {
                t.run();
                due[t.name] = time.time() + t.every;
            }
        }
        while served["work"] {
            served["work"].pop(0)();
        }
        time.sleep(0.05);
    }
}

impl RestTransport.on_loop(work: Callable[[], None]) {
    served["work"].append(work);
}

impl RestTransport.serving -> bool {
    return "handle" in served;
}

impl RestTransport.serves_paths -> bool {
    return True;
}

impl parse_route(spec: str) -> Route {
    left = spec.split("=", 1)[0].strip().split(" ");
    right = spec.split("=", 1)[1].strip();
    target = right.split("(")[0].strip();
    args = [a.strip() for a in right.split("(")[1].rstrip(")").split(",") if a.strip()]
        if "(" in right
        else [];
    return Route(method=left[0], parts=left[1].strip("/").split("/"), target=target, args=args);
}

impl route_args(r: Route, method: str, parts: list[str]) -> dict[str, str] | None {
    if r.method != method or len(r.parts) != len(parts) {
        return None;
    }
    got: dict[str, str] = {};
    for (want, have) in zip(r.parts, parts) {
        if want.startswith("{") {
            got[want[1:-1]] = urllib.parse.unquote(have);
        } elif want.lower() != have.lower() {
            return None;
        }
    }
    return got;
}

impl body_of(ctype: str, raw: bytes) -> any {
    if not raw {
        return {};
    }
    if "application/x-www-form-urlencoded" in ctype {
        return {
            k: v[0]
            for (k, v) in urllib.parse.parse_qs(raw.decode(), keep_blank_values=True).items()
        };
    }
    return json.loads(raw.decode());
}

impl arg_value(spec: str, vals: dict[str, str], headers: dict[str, str]) -> tuple[str, str] {
    if "=" not in spec {
        return (spec, vals.get(spec, ""));
    }
    (name, src) = spec.split("=", 1);
    src = src.strip();
    if src.startswith("h.") {
        return (name.strip(), headers.get(src[2:].lower(), ""));
    }
    return (name.strip(), vals.get(src, ""));
}

impl answer(h: any) {
    u = urllib.parse.urlsplit(h.path);
    n = int(h.headers.get("Content-Length", "0") or "0");
    raw = h.rfile.read(n) if n else b"";
    headers: dict[str, str] = {str(k).lower(): str(v) for (k, v) in h.headers.items()};
    parts = u.path.strip("/").split("/");
    handle = served["handle"];
    for r in served["routes"] {
        got = route_args(r, h.command, parts);
        if got is None {
            continue;
        }
        vals: dict[str, str] = dict(got);
        try {
            vals["body"] = json.dumps(body_of(headers.get("content-type", ""), raw));
        } except ValueError {
            write(
                h,
                Response(status=400, ctype="text/html; charset=utf-8", body=bad_request.encode(), headers={}, events=None),
            );
            return;
        }
        vals["query"] = json.dumps({k: v[0] for (k, v) in urllib.parse.parse_qs(u.query).items()});
        auth = headers.get("authorization", "");
        vals["bearer"] = auth[7:].strip() if auth.lower().startswith("bearer ") else "";
        args = dict([arg_value(a, vals, headers) for a in r.args]);
        fwd: dict[str, str] = dict(headers);
        fwd["content-type"] = "application/json";
        target = r.target.split(".");
        req = Request(
            method="POST",
            path="/__jac/call/" + "/".join(target),
            query="",
            headers=fwd,
            body=json.dumps({"args": args}).encode(),
            client=h.client_address[0],
        );
        write(h, unwrap(handle(req)));
        return;
    }
    if not u.path.startswith("/__jac") {
        write(
            h,
            Response(
                status=404,
                ctype="application/json",
                body=not_found.encode(),
                headers={},
                events=None,
            ),
        );
        return;
    }
    req = Request(
        method=h.command,
        path=u.path,
        query=u.query,
        headers=headers,
        body=raw,
        client=h.client_address[0],
    );
    write(h, handle(req));
}

impl unwrap(resp: Response) -> Response {
    try {
        env = json.loads(resp.body.decode()) if resp.body else {};
    } except ValueError {
        return resp;
    }
    if env.get("ok") {
        data = env.get("data");
        if isinstance(data, dict) and set(data.keys()) == {"status", "body", "ctype"} {
            return Response(
                status=data["status"],
                ctype=data["ctype"],
                body=data["body"].encode(),
                headers={},
                events=None,
            );
        }
        return Response(
            status=200,
            ctype="application/json",
            body=json.dumps(data).encode(),
            headers={},
            events=None,
        );
    }
    if env.get("kind") == "rejected" {
        return Response(
            status=401,
            ctype="text/html; charset=utf-8",
            body=unauthorized.encode(),
            headers={},
            events=None,
        );
    }
    return Response(
        status=resp.status if resp.status >= 400 else 500,
        ctype="application/json",
        body=resp.body,
        headers={},
        events=None,
    );
}

impl write(h: any, resp: Response) {
    h.send_response(resp.status);
    if resp.body {
        h.send_header("Content-Type", resp.ctype or "application/json");
    }
    for (k, v) in (resp.headers or {}).items() {
        h.send_header(k, v);
    }
    h.send_header("Content-Length", str(len(resp.body)));
    h.end_headers();
    h.wfile.write(resp.body);
}
