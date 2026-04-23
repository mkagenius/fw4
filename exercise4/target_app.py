#!/usr/bin/env python3
"""
Sample web application to fuzz.

Run with:
    python target_app.py

The app listens on http://localhost:80 (or PORT env var).
It intentionally contains several rough edges that a fuzzer can discover.
"""

import json
import os
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse, parse_qs


PORT = int(os.environ.get("PORT", 80))

# In-memory store: id -> item dict
_items: dict[int, dict] = {}
_next_id = 1


class Handler(BaseHTTPRequestHandler):
    """Minimal REST-ish HTTP handler."""

    # ------------------------------------------------------------------ #
    #  Routing helpers
    # ------------------------------------------------------------------ #

    def _send(self, status: int, body: str, content_type: str = "application/json") -> None:
        encoded = body.encode()
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)

    def _read_body(self) -> bytes:
        length = int(self.headers.get("Content-Length", 0))
        return self.rfile.read(length) if length > 0 else b""

    # ------------------------------------------------------------------ #
    #  Route handlers
    # ------------------------------------------------------------------ #

    def _handle_health(self) -> None:
        self._send(200, json.dumps({"status": "ok"}))

    def _handle_echo(self) -> None:
        """Echo query params and headers back as JSON."""
        parsed = urlparse(self.path)
        params = parse_qs(parsed.query)
        headers = dict(self.headers)
        self._send(200, json.dumps({"params": params, "headers": headers}))

    def _handle_items_list(self) -> None:
        self._send(200, json.dumps(list(_items.values())))

    def _handle_items_create(self) -> None:
        global _next_id
        raw = self._read_body()
        try:
            data = json.loads(raw)
        except json.JSONDecodeError as exc:
            self._send(400, json.dumps({"error": f"Invalid JSON: {exc}"}))
            return

        if not isinstance(data, dict):
            self._send(400, json.dumps({"error": "Expected a JSON object"}))
            return

        name = data.get("name", "")
        # Intentional issue: no length cap — fuzzer can find very large names
        if not name:
            self._send(422, json.dumps({"error": "name is required"}))
            return

        item = {"id": _next_id, "name": name, "tags": data.get("tags", [])}
        _items[_next_id] = item
        _next_id += 1
        self._send(201, json.dumps(item))

    def _handle_item_get(self, item_id: str) -> None:
        try:
            iid = int(item_id)
        except ValueError:
            self._send(400, json.dumps({"error": "id must be an integer"}))
            return
        item = _items.get(iid)
        if item is None:
            self._send(404, json.dumps({"error": "not found"}))
        else:
            self._send(200, json.dumps(item))

    def _handle_item_delete(self, item_id: str) -> None:
        try:
            iid = int(item_id)
        except ValueError:
            self._send(400, json.dumps({"error": "id must be an integer"}))
            return
        if iid not in _items:
            self._send(404, json.dumps({"error": "not found"}))
        else:
            del _items[iid]
            self._send(200, json.dumps({"deleted": iid}))

    def _handle_search(self) -> None:
        """Naive substring search — can be slow for deeply nested tags."""
        parsed = urlparse(self.path)
        params = parse_qs(parsed.query)
        query = params.get("q", [""])[0]
        results = [
            it for it in _items.values()
            if query.lower() in it["name"].lower()
            or any(
                query.lower() in t.lower()
                for t in it.get("tags", [])
                if isinstance(t, str)
            )
        ]
        self._send(200, json.dumps(results))

    def _handle_compute(self) -> None:
        """Accepts JSON {expr: "..."} and evaluates a simple math expression.

        WARNING: uses eval() — intentionally unsafe for fuzzing demonstration.
        """
        raw = self._read_body()
        try:
            data = json.loads(raw)
        except json.JSONDecodeError as exc:
            self._send(400, json.dumps({"error": f"Invalid JSON: {exc}"}))
            return

        expr = str(data.get("expr", ""))
        # Intentionally unsafe eval — used here as a fuzzing target.
        # Note: even with __builtins__={}, Python's object model can still
        # be exploited (e.g. ().__class__.__bases__[0].__subclasses__()).
        # This endpoint exists precisely so the fuzzer can discover that.
        try:
            result = eval(expr, {"__builtins__": {}})  # noqa: S307
            self._send(200, json.dumps({"result": result}))
        except Exception as exc:
            self._send(400, json.dumps({"error": str(exc)}))

    # ------------------------------------------------------------------ #
    #  HTTP method dispatchers
    # ------------------------------------------------------------------ #

    def _dispatch(self, method: str) -> None:
        parsed = urlparse(self.path)
        path = parsed.path.rstrip("/") or "/"

        routes = {
            ("GET",    "/health"):    self._handle_health,
            ("GET",    "/echo"):      self._handle_echo,
            ("GET",    "/items"):     self._handle_items_list,
            ("POST",   "/items"):     self._handle_items_create,
            ("GET",    "/search"):    self._handle_search,
            ("POST",   "/compute"):   self._handle_compute,
        }

        # Static routes
        handler = routes.get((method, path))
        if handler:
            handler()
            return

        # Dynamic: /items/<id>
        parts = path.split("/")
        if len(parts) == 3 and parts[1] == "items":
            item_id = parts[2]
            if method == "GET":
                self._handle_item_get(item_id)
            elif method == "DELETE":
                self._handle_item_delete(item_id)
            else:
                self._send(405, json.dumps({"error": "Method Not Allowed"}))
            return

        self._send(404, json.dumps({"error": "Not Found", "path": path}))

    def do_GET(self) -> None:    self._dispatch("GET")
    def do_POST(self) -> None:   self._dispatch("POST")
    def do_PUT(self) -> None:    self._dispatch("PUT")
    def do_DELETE(self) -> None: self._dispatch("DELETE")
    def do_PATCH(self) -> None:  self._dispatch("PATCH")

    def log_message(self, fmt: str, *args) -> None:  # silence default logging
        pass


def main() -> None:
    server = HTTPServer(("0.0.0.0", PORT), Handler)
    print(f"Target app listening on http://0.0.0.0:{PORT}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
