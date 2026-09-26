"""
ARC Frontend Static HTTP Server
Serves the Stitch frontend at http://localhost:3000
Run: python server.py
"""
import http.server
import socketserver
import os

PORT = 3000
DIRECTORY = os.path.join(os.path.dirname(__file__), "frontend")

class Handler(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=DIRECTORY, **kwargs)

    def do_GET(self):
        if self.path == "/" or self.path == "":
            self.path = "/stitch_arc_universal_log_pre_processor/arc_01_dashboard/code.html"
        elif self.path.startswith("/arc_"):
            self.path = "/stitch_arc_universal_log_pre_processor" + self.path
        return super().do_GET()

    def log_message(self, format, *args):
        print(f"[{self.date_time_string()}] {format % args}")

    def end_headers(self):
        # Allow CORS so backend calls work
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Cache-Control", "no-cache, no-store, must-revalidate")
        super().end_headers()

class ThreadedHTTPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    daemon_threads = True
    allow_reuse_address = True

if __name__ == "__main__":
    with ThreadedHTTPServer(("", PORT), Handler) as httpd:
        print(f"ARC Frontend running at: http://localhost:{PORT}")
        print(f"Serving from: {DIRECTORY}")
        print(f"Open: http://localhost:{PORT}/stitch_arc_universal_log_pre_processor/arc_01_dashboard/code.html")
        print("Press Ctrl+C to stop.")
        httpd.serve_forever()