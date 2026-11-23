import http.client, http.server, json, os, ssl, sys, threading

TARGET_HOST, TARGET_PORT = sys.argv[2].split(":")
LOG = open(sys.argv[3], "a")
LOCK = threading.Lock()


def text(b):
    try:
        return json.loads(b) if b else None
    except ValueError:
        return b.decode(errors="replace")


class Proxy(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def relay(self):
        n = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(n) if n else b""
        hdrs = {k: v for k, v in self.headers.items() if k.lower() not in ("host", "accept-encoding")}
        c = http.client.HTTPConnection(TARGET_HOST, int(TARGET_PORT), timeout=60)
        c.request(self.command, self.path, body=body or None, headers=hdrs)
        r = c.getresponse()
        data = r.read()
        self.send_response(r.status)
        for k, v in r.getheaders():
            if k.lower() not in ("transfer-encoding", "content-length", "connection"):
                self.send_header(k, v)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)
        ctype = self.headers.get("Content-Type", "")
        req = dict(x.split("=", 1) for x in body.decode().split("&")) if "urlencoded" in ctype and body else text(body)
        with LOCK:
            LOG.write(json.dumps({"method": self.command, "path": self.path, "status": r.status,
                                  "request": req, "response": text(data)}) + "\n")
            LOG.flush()

    do_GET = do_POST = do_PUT = do_DELETE = do_PATCH = relay

    def log_message(self, *a):
        pass


srv = http.server.ThreadingHTTPServer(("127.0.0.1", int(sys.argv[1])), Proxy)
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
here = os.path.dirname(os.path.abspath(__file__))
ctx.load_cert_chain(os.path.join(here, "cert.pem"), os.path.join(here, "key.pem"))
srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
srv.serve_forever()
