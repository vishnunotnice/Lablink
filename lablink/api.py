"""TLS-only enrollment API; no remote administrative endpoints."""
import json
import ssl
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse
from urllib.request import Request, urlopen


def request(url, body, ca=None):
    if urlparse(url).scheme != 'https':
        raise ValueError("Registration requires HTTPS")
    ctx=ssl.create_default_context(cafile=ca)
    req=Request(url,data=json.dumps(body).encode(),headers={'Content-Type':'application/json'})
    with urlopen(req,context=ctx,timeout=15) as response:
        return json.load(response)


def serve(store, bind, port):
    cfg=store.config()
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass  # Request paths and credentials never enter access logs.
        def do_POST(self):
            try:
                length=int(self.headers.get('Content-Length','0'))
                if length <= 0 or length > 16384:
                    raise ValueError("Body must be 1–16384 bytes")
                self.connection.settimeout(10)
                body=json.loads(self.rfile.read(length))
                if self.path == '/register':
                    result=store.register(body['name'],body['public_key'],body['token'])
                elif self.path == '/poll':
                    result=store.poll(body['request_id'],body['poll_token'])
                else:
                    self.send_error(404); return
                code=200
            except (ValueError,KeyError,TypeError):
                result={'error':'Invalid or unauthorized request'}; code=400
            except Exception:
                result={'error':'Internal server error'}; code=500
            data=json.dumps(result).encode()
            self.send_response(code); self.send_header('Content-Type','application/json')
            self.send_header('Content-Length',str(len(data))); self.end_headers(); self.wfile.write(data)
    server=HTTPServer((bind,port),Handler)
    ctx=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version=ssl.TLSVersion.TLSv1_2
    ctx.load_cert_chain(cfg['tls_cert'],cfg['tls_key'])
    server.socket=ctx.wrap_socket(server.socket,server_side=True)
    print(f"Enrollment API listening on {bind}:{port}")
    try:
        server.serve_forever()
    finally:
        server.server_close()
