#!/usr/bin/env python3
"""Serve blocklist files for testing SafeRoom's download path.

    tools/list-server.py DIR [--port 8765] [--token TOKEN]

Serves the files in DIR on 127.0.0.1. With --token, every request needs
`Authorization: Bearer TOKEN`. Each response carries an ETag (the file's
SHA-256), and a matching If-None-Match gets 304, so the conditional-request
path can be tested. Each request is logged to stdout.

SafeRoom accepts plain http:// only for loopback hosts, which is what this
binds to.
"""
import argparse
import hashlib
import http.server
import os
import sys


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("dir")
    parser.add_argument("--port", type=int, default=8765)
    parser.add_argument("--token")
    args = parser.parse_args()
    root = os.path.realpath(args.dir)

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            if args.token and self.headers.get("Authorization") != f"Bearer {args.token}":
                return self.reply(401, b"unauthorized\n")
            path = os.path.realpath(os.path.join(root, self.path.lstrip("/").split("?")[0]))
            if not path.startswith(root + os.sep) or not os.path.isfile(path):
                return self.reply(404, b"not found\n")
            with open(path, "rb") as f:
                body = f.read()
            etag = '"' + hashlib.sha256(body).hexdigest() + '"'
            if self.headers.get("If-None-Match") == etag:
                return self.reply(304, b"", etag)
            self.reply(200, body, etag)

        def reply(self, status, body, etag=None):
            self.send_response(status)
            if etag:
                self.send_header("ETag", etag)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, fmt, *a):
            sys.stdout.write("%s %s\n" % (self.log_date_time_string(), fmt % a))
            sys.stdout.flush()

    server = http.server.ThreadingHTTPServer(("127.0.0.1", args.port), Handler)
    print(f"serving {root} on http://127.0.0.1:{args.port}/", flush=True)
    server.serve_forever()


if __name__ == "__main__":
    main()
