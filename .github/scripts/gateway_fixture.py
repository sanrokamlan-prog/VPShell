#!/usr/bin/env python3
import argparse
import hashlib
import json
import ssl
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, unquote, urlparse

PROTOCOL_VERSION = 1
SESSION_TOKEN = "vpshell-ci-gateway-session"
API_PREFIX = "/api/v1/"
MAX_BODY = 24 * 1024 * 1024


class GatewayHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    objects = {}

    def log_message(self, _format, *_args):
        pass

    def send_bytes(self, status, body=b"", content_type="application/octet-stream"):
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()
        if body:
            self.wfile.write(body)

    def send_json(self, status, value):
        self.send_bytes(
            status,
            json.dumps(value, separators=(",", ":")).encode("utf-8"),
            "application/json",
        )

    def authorized(self):
        return (
            self.headers.get("Authorization") == f"Bearer {SESSION_TOKEN}"
            and self.headers.get("x-vpshell-protocol") == str(PROTOCOL_VERSION)
        )

    def read_body(self):
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            return None
        if length < 0 or length > MAX_BODY:
            return None
        return self.rfile.read(length)

    def do_POST(self):
        if self.path != f"{API_PREFIX}session":
            self.send_bytes(404)
            return
        body = self.read_body()
        try:
            request = json.loads(body)
            canonical_vault = str(uuid.UUID(request["vaultId"])) == request["vaultId"]
            canonical_device = str(uuid.UUID(request["deviceId"])) == request["deviceId"]
        except (TypeError, ValueError, KeyError, json.JSONDecodeError):
            self.send_bytes(400)
            return
        if set(request) != {
            "protocolVersion",
            "vaultId",
            "deviceId",
            "username",
            "password",
            "totp",
        } or not canonical_vault or not canonical_device:
            self.send_bytes(400)
            return
        if request != {
            "protocolVersion": PROTOCOL_VERSION,
            "vaultId": "11111111-1111-4111-8111-111111111111",
            "deviceId": "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
            "username": "fixture-user",
            "password": "fixture-password",
            "totp": "123456",
        }:
            self.send_bytes(401)
            return
        self.send_json(
            200,
            {
                "protocolVersion": PROTOCOL_VERSION,
                "sessionToken": SESSION_TOKEN,
                "expiresInSeconds": 300,
            },
        )

    def do_GET(self):
        parsed = urlparse(self.path)
        if parsed.path == f"{API_PREFIX}health":
            self.send_bytes(200, b"ok", "text/plain")
            return
        if not self.authorized():
            self.send_bytes(401)
            return
        if parsed.path == f"{API_PREFIX}objects":
            query = parse_qs(parsed.query, keep_blank_values=True)
            try:
                prefix = query["prefix"][0]
                limit = int(query["limit"][0])
                after = query.get("after", [None])[0]
            except (KeyError, ValueError):
                self.send_bytes(400)
                return
            if not 1 <= limit <= 1001:
                self.send_bytes(400)
                return
            keys = [
                key
                for key in sorted(self.objects)
                if key.startswith(prefix) and (after is None or key > after)
            ][:limit]
            self.send_json(
                200,
                {
                    "protocolVersion": PROTOCOL_VERSION,
                    "objects": [
                        {
                            "key": key,
                            "size": len(self.objects[key]),
                            "etag": hashlib.sha256(self.objects[key]).hexdigest(),
                        }
                        for key in keys
                    ],
                },
            )
            return
        key = self.object_key(parsed.path)
        if key is None or key not in self.objects:
            self.send_bytes(404)
            return
        self.send_bytes(200, self.objects[key])

    def do_PUT(self):
        parsed = urlparse(self.path)
        if not self.authorized():
            self.send_bytes(401)
            return
        key = self.object_key(parsed.path)
        if key is None or self.headers.get("If-None-Match") != "*":
            self.send_bytes(400)
            return
        body = self.read_body()
        if body is None or not body:
            self.send_bytes(413)
            return
        if key in self.objects:
            self.send_bytes(412)
            return
        self.objects[key] = body
        self.send_bytes(201)

    @staticmethod
    def object_key(path):
        prefix = f"{API_PREFIX}objects/"
        if not path.startswith(prefix):
            return None
        key = unquote(path[len(prefix):])
        if not key or ".." in key.split("/"):
            return None
        return key


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--cert", required=True)
    parser.add_argument("--key", required=True)
    parser.add_argument("--port", required=True, type=int)
    args = parser.parse_args()
    server = ThreadingHTTPServer(("127.0.0.1", args.port), GatewayHandler)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(args.cert, args.key)
    server.socket = context.wrap_socket(server.socket, server_side=True)
    server.serve_forever()


if __name__ == "__main__":
    main()
