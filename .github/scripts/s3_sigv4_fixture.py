#!/usr/bin/env python3
import argparse
import hashlib
import hmac
import os
import ssl
import threading
import urllib.parse
import xml.etree.ElementTree as ET
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


OBJECTS = {}
LOCK = threading.Lock()
REGION = "us-east-1"
BUCKET = "vpshell-ci"


def signing_key(secret, date, region):
    date_key = hmac.new(("AWS4" + secret).encode(), date.encode(), hashlib.sha256).digest()
    region_key = hmac.new(date_key, region.encode(), hashlib.sha256).digest()
    service_key = hmac.new(region_key, b"s3", hashlib.sha256).digest()
    return hmac.new(service_key, b"aws4_request", hashlib.sha256).digest()


def encoded(value):
    return urllib.parse.quote(value, safe="-_.~")


class S3FixtureHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, _format, *_args):
        return

    def fail(self, status):
        self.send_response(status)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def authenticate(self, body=b""):
        access_key = os.environ["VPSHELL_S3_FIXTURE_ACCESS_KEY_ID"]
        secret_key = os.environ["VPSHELL_S3_FIXTURE_SECRET_ACCESS_KEY"]
        authorization = self.headers.get("Authorization", "")
        amz_date = self.headers.get("x-amz-date", "")
        payload_hash = self.headers.get("x-amz-content-sha256", "")
        if payload_hash != hashlib.sha256(body).hexdigest() or len(amz_date) != 16:
            return False
        prefix = "AWS4-HMAC-SHA256 Credential="
        if not authorization.startswith(prefix):
            return False
        try:
            credential_part, signed_part, signature_part = authorization[len(prefix):].split(", ")
            credential = credential_part.split("/", 1)
            scope = credential[1]
            signed_headers = signed_part.removeprefix("SignedHeaders=")
            supplied_signature = signature_part.removeprefix("Signature=")
            date, region, service, terminal = scope.split("/")
        except (ValueError, IndexError):
            return False
        if credential[0] != access_key or region != REGION or service != "s3" or terminal != "aws4_request":
            return False
        if date != amz_date[:8]:
            return False
        parsed = urllib.parse.urlsplit(self.path)
        query = urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)
        canonical_query = "&".join(
            f"{encoded(key)}={encoded(value)}" for key, value in sorted(query)
        )
        canonical_headers = []
        for name in signed_headers.split(";"):
            value = self.headers.get(name)
            if value is None:
                return False
            canonical_headers.append(f"{name}:{' '.join(value.strip().split())}\n")
        canonical_request = (
            f"{self.command}\n{parsed.path}\n{canonical_query}\n"
            f"{''.join(canonical_headers)}\n{signed_headers}\n{payload_hash}"
        )
        string_to_sign = (
            f"AWS4-HMAC-SHA256\n{amz_date}\n{scope}\n"
            f"{hashlib.sha256(canonical_request.encode()).hexdigest()}"
        )
        expected = hmac.new(
            signing_key(secret_key, date, region),
            string_to_sign.encode(),
            hashlib.sha256,
        ).hexdigest()
        return hmac.compare_digest(expected, supplied_signature)

    def key_from_path(self):
        path = urllib.parse.unquote(urllib.parse.urlsplit(self.path).path)
        root = f"/{BUCKET}/"
        if not path.startswith(root):
            return None
        key = path[len(root):]
        return key or None

    def do_GET(self):
        if not self.authenticate():
            self.fail(403)
            return
        parsed = urllib.parse.urlsplit(self.path)
        query = dict(urllib.parse.parse_qsl(parsed.query, keep_blank_values=True))
        if parsed.path.rstrip("/") == f"/{BUCKET}" and query.get("list-type") == "2":
            self.list_objects(query)
            return
        key = self.key_from_path()
        if key is None:
            self.fail(404)
            return
        with LOCK:
            body = OBJECTS.get(key)
        if body is None:
            self.fail(404)
            return
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("ETag", f'"{hashlib.md5(body, usedforsecurity=False).hexdigest()}"')
        self.end_headers()
        self.wfile.write(body)

    def do_PUT(self):
        length = int(self.headers.get("Content-Length", "-1"))
        if length < 1 or length > 24 * 1024 * 1024:
            self.fail(400)
            return
        body = self.rfile.read(length)
        if not self.authenticate(body) or self.headers.get("If-None-Match") != "*":
            self.fail(403)
            return
        key = self.key_from_path()
        if key is None:
            self.fail(404)
            return
        with LOCK:
            if key in OBJECTS:
                self.fail(412)
                return
            OBJECTS[key] = body
        self.send_response(200)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def list_objects(self, query):
        prefix = query.get("prefix", "")
        token = query.get("continuation-token")
        after = token if token is not None else query.get("start-after", "")
        with LOCK:
            keys = sorted(
                key for key in OBJECTS if key.startswith(prefix) and (not after or key > after)
            )
            page_keys = keys[:1]
            truncated = len(page_keys) < len(keys)
            root = ET.Element("ListBucketResult", xmlns="http://s3.amazonaws.com/doc/2006-03-01/")
            ET.SubElement(root, "IsTruncated").text = "true" if truncated else "false"
            for key in page_keys:
                item = ET.SubElement(root, "Contents")
                ET.SubElement(item, "Key").text = key
                ET.SubElement(item, "ETag").text = hashlib.md5(
                    OBJECTS[key], usedforsecurity=False
                ).hexdigest()
                ET.SubElement(item, "Size").text = str(len(OBJECTS[key]))
            if truncated:
                ET.SubElement(root, "NextContinuationToken").text = page_keys[-1]
            body = ET.tostring(root, encoding="utf-8", xml_declaration=True)
        self.send_response(200)
        self.send_header("Content-Type", "application/xml")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--cert", required=True)
    parser.add_argument("--key", required=True)
    parser.add_argument("--port", type=int, default=24444)
    args = parser.parse_args()
    server = ThreadingHTTPServer(("127.0.0.1", args.port), S3FixtureHandler)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(args.cert, args.key)
    server.socket = context.wrap_socket(server.socket, server_side=True)
    server.serve_forever()


if __name__ == "__main__":
    main()
