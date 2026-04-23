#!/usr/bin/env python3
"""
HTTP Fuzzer — exercise 4

Uses Atheris (coverage-guided fuzzing) to generate fuzz inputs that are
shaped into HTTP requests and sent to http://localhost (default port 80).

The fuzzer drives:
  - HTTP method selection
  - URL path construction (including path traversal attempts)
  - Query-string parameter names and values
  - Arbitrary request headers
  - Request body (JSON or raw bytes)

Interesting findings (server errors, unexpected status codes, exceptions)
are printed to stderr so Atheris can record the crashing input.

Usage
-----
    # 1. Start the target in a separate terminal:
    #       python target_app.py          (default port 80)
    #       PORT=8080 python target_app.py
    #
    # 2. Run the fuzzer (no corpus needed for a first run):
    #       python fuzz_http.py           (against localhost:80)
    #       TARGET_PORT=8080 python fuzz_http.py
    #
    #    With an initial corpus directory:
    #       python fuzz_http.py corpus/
    #
    #    Atheris CLI flags can be appended after '--':
    #       python fuzz_http.py corpus/ -- -max_total_time=60

Dependencies
------------
    pip install atheris requests
"""

import json
import os
import sys

import atheris
import requests

# ------------------------------------------------------------------ #
#  Configuration
# ------------------------------------------------------------------ #

TARGET_HOST = os.environ.get("TARGET_HOST", "http://localhost")
TARGET_PORT = os.environ.get("TARGET_PORT", "80")
BASE_URL = f"{TARGET_HOST}:{TARGET_PORT}"

# HTTP methods to exercise
_METHODS = ["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"]

# Known path segments — the fuzzer will mix these with fuzz-generated tokens
_KNOWN_PATHS = [
    "/",
    "/health",
    "/echo",
    "/items",
    "/search",
    "/compute",
]

# Session is reused so the TCP connection pool is shared across iterations
_session = requests.Session()
_session.max_redirects = 3


# ------------------------------------------------------------------ #
#  Helpers
# ------------------------------------------------------------------ #

def _pick(provider: atheris.FuzzedDataProvider, items: list):
    """Pick one element from *items* using fuzz data."""
    idx = provider.ConsumeIntInRange(0, len(items) - 1)
    return items[idx]


def _fuzz_path(provider: atheris.FuzzedDataProvider) -> str:
    """Build a URL path from fuzz data.

    Strategy: sometimes use a known path, sometimes generate a random one,
    sometimes inject path-traversal sequences.
    """
    choice = provider.ConsumeIntInRange(0, 2)
    if choice == 0:
        # Known endpoint path, optionally with a fuzz-generated suffix
        base = _pick(provider, _KNOWN_PATHS)
        suffix = provider.ConsumeString(provider.ConsumeIntInRange(0, 32))
        return base + suffix
    if choice == 1:
        # Fully random path tokens
        depth = provider.ConsumeIntInRange(1, 5)
        segments = [provider.ConsumeString(provider.ConsumeIntInRange(1, 20))
                    for _ in range(depth)]
        return "/" + "/".join(segments)
    # Path-traversal attempt
    return "/" + "../" * provider.ConsumeIntInRange(1, 6) + "etc/passwd"


def _fuzz_query(provider: atheris.FuzzedDataProvider) -> dict:
    """Build a query-string dict from fuzz data."""
    count = provider.ConsumeIntInRange(0, 4)
    params: dict[str, str] = {}
    for _ in range(count):
        key = provider.ConsumeString(provider.ConsumeIntInRange(1, 16))
        val = provider.ConsumeString(provider.ConsumeIntInRange(0, 64))
        params[key] = val
    return params


def _fuzz_headers(provider: atheris.FuzzedDataProvider) -> dict:
    """Build extra HTTP headers from fuzz data."""
    headers: dict[str, str] = {}
    count = provider.ConsumeIntInRange(0, 3)
    for _ in range(count):
        name = provider.ConsumeString(provider.ConsumeIntInRange(1, 24))
        value = provider.ConsumeString(provider.ConsumeIntInRange(0, 64))
        # Skip headers that would break the requests library
        if "\n" in name or "\r" in name or ":" in name:
            continue
        headers[name] = value
    return headers


def _fuzz_body(provider: atheris.FuzzedDataProvider) -> tuple[bytes, str]:
    """Return (body_bytes, content_type) from fuzz data."""
    kind = provider.ConsumeIntInRange(0, 3)
    if kind == 0:
        # No body
        return b"", ""
    if kind == 1:
        # Raw bytes
        body = provider.ConsumeBytes(provider.ConsumeIntInRange(0, 256))
        return body, "application/octet-stream"
    if kind == 2:
        # Valid-ish JSON object built from fuzz data
        obj: dict = {}
        key_count = provider.ConsumeIntInRange(0, 4)
        for _ in range(key_count):
            k = provider.ConsumeString(provider.ConsumeIntInRange(1, 16))
            v = provider.ConsumeString(provider.ConsumeIntInRange(0, 64))
            obj[k] = v
        try:
            body = json.dumps(obj).encode()
        except Exception:
            body = b"{}"
        return body, "application/json"
    # Raw fuzz string as body
    body = provider.ConsumeString(provider.ConsumeIntInRange(0, 256)).encode(errors="replace")
    return body, "text/plain"


# ------------------------------------------------------------------ #
#  Interesting-response detection
# ------------------------------------------------------------------ #

# Status codes that should never appear from a well-behaved server
_CRASH_CODES = {500, 502, 503, 504}

def _is_interesting(resp: requests.Response) -> bool:
    """Return True when the response is worth flagging."""
    return resp.status_code in _CRASH_CODES


# ------------------------------------------------------------------ #
#  Fuzz target
# ------------------------------------------------------------------ #

def TestOneInput(data: bytes) -> None:
    """Atheris calls this with every generated/mutated input."""
    if len(data) < 4:
        return

    provider = atheris.FuzzedDataProvider(data)

    method = _pick(provider, _METHODS)
    path = _fuzz_path(provider)
    params = _fuzz_query(provider)
    extra_headers = _fuzz_headers(provider)
    body, content_type = _fuzz_body(provider)

    url = BASE_URL + path

    headers: dict[str, str] = {}
    if content_type:
        headers["Content-Type"] = content_type
    headers.update(extra_headers)

    try:
        resp = _session.request(
            method=method,
            url=url,
            params=params,
            headers=headers,
            data=body if body else None,
            timeout=5,
            allow_redirects=False,
        )
    except requests.exceptions.ConnectionError:
        # Target is down — not a fuzzer-worthy finding
        return
    except requests.exceptions.Timeout:
        # A timeout can indicate a DoS / slowpath — flag it
        print(
            f"[TIMEOUT] {method} {url}  params={params}",
            file=sys.stderr,
        )
        return
    except Exception as exc:
        # Unexpected exception in the HTTP stack itself
        print(f"[HTTP-EXC] {exc}", file=sys.stderr)
        return

    if _is_interesting(resp):
        print(
            f"[FINDING] HTTP {resp.status_code}  {method} {url}\n"
            f"  params  : {params}\n"
            f"  headers : {extra_headers}\n"
            f"  body    : {body!r}\n"
            f"  response: {resp.text[:200]}",
            file=sys.stderr,
        )
        # Raise to let Atheris record this input as a crash/finding
        raise RuntimeError(
            f"Server returned {resp.status_code} for {method} {url}"
        )


# ------------------------------------------------------------------ #
#  Entry point
# ------------------------------------------------------------------ #

def main() -> None:
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
