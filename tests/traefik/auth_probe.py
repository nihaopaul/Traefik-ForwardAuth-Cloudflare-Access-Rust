from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


EXPECTED_AUDIENCE = "dashboard-aud"


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/auth":
            audiences = self.headers.get_all("X-Auth-Audience", failobj=[])
            self.send_response(204 if audiences == [EXPECTED_AUDIENCE] else 403)
        else:
            self.send_response(200)
        self.end_headers()

    def log_message(self, format, *args):
        return


ThreadingHTTPServer(("0.0.0.0", 9001), Handler).serve_forever()
