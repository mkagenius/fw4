# Exercise 4 — HTTP Fuzzer

A coverage-guided HTTP fuzzer written in Python using
[Atheris](https://github.com/google/atheris) and
[requests](https://requests.readthedocs.io/).

The fuzzer generates structurally varied HTTP requests (method, path, query
params, headers, body) and sends them to a target application running at
`http://localhost`.  It flags responses with 5xx status codes and request
timeouts as interesting findings.

---

## Files

| File | Purpose |
|---|---|
| `fuzz_http.py` | The Atheris fuzz target — this is what you run |
| `target_app.py` | A small sample web app to fuzz against |

---

## Quick Start

### 1. Install dependencies

```bash
pip install atheris requests
```

> **Note:** Atheris requires a Clang-instrumented build of Python on Linux.
> The easiest way is to use the pre-built wheel:
> ```bash
> pip install atheris
> ```
> On macOS you may need to install from source; see the
> [Atheris README](https://github.com/google/atheris#installation).

### 2. Start the target application

In **one terminal**:

```bash
python target_app.py          # listens on http://localhost:80
# or
PORT=8080 python target_app.py
```

### 3. Run the fuzzer

In **another terminal**:

```bash
# Against default localhost:80
python fuzz_http.py

# Against a custom port
TARGET_PORT=8080 python fuzz_http.py

# With an initial seed corpus directory
python fuzz_http.py corpus/

# Limit to 60 seconds of fuzzing (Atheris/libFuzzer flag)
python fuzz_http.py corpus/ -- -max_total_time=60
```

### 4. Inspect findings

When the fuzzer finds an interesting response (HTTP 5xx or timeout) it prints
a `[FINDING]` block to stderr and raises an exception so that Atheris saves
the triggering input to disk (in the current directory as `crash-<hash>`).

---

## What the fuzzer mutates

| Dimension | Strategy |
|---|---|
| **HTTP method** | Random selection from GET, POST, PUT, DELETE, PATCH, OPTIONS, HEAD |
| **URL path** | Known endpoints, fully random segments, or path-traversal sequences |
| **Query params** | 0–4 fuzz-generated key/value pairs |
| **Headers** | 0–3 extra fuzz-generated headers |
| **Body** | No body, raw bytes, JSON object, or raw UTF-8 string |

---

## Target app endpoints

The sample `target_app.py` exposes:

| Method | Path | Description |
|---|---|---|
| GET | `/health` | Health check |
| GET | `/echo` | Echoes query params and headers |
| GET | `/items` | List all items |
| POST | `/items` | Create an item `{"name": "...", "tags": [...]}` |
| GET | `/items/<id>` | Get item by id |
| DELETE | `/items/<id>` | Delete item by id |
| GET | `/search?q=...` | Search items by name/tag |
| POST | `/compute` | Evaluate a math expression `{"expr": "..."}` |

The `/compute` endpoint intentionally uses `eval()` to give the fuzzer
something to find — can you trigger an error?

---

## Extending the fuzzer

* **Add seed corpus**: Drop representative JSON request bodies into a
  `corpus/` directory.  Atheris will mutate them to explore new code paths.
* **Fuzz a different host**: Set `TARGET_HOST` and `TARGET_PORT` environment
  variables.
* **Assertion checks**: Add application-level invariants inside
  `TestOneInput` (e.g., check that a `200` response always contains valid
  JSON) and raise on violation to record it as a finding.
