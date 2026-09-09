"""Admin surface: a small web app to manage the PII layer of local-llm-mcp.

Serves a single-page app plus a JSON API over one stdlib HTTP server, no extra
dependencies. It manages the pieces the caller never sees:

* **private terms** — the operator's own names, addresses, numbers; add, remove,
  harvest candidates from pasted text with the local model;
* **sessions** — every conversation's memory: placeholder vault (values shown to
  the operator on request), summary, recent turns, artifacts; purge what a live
  server is not using;
* **scrub tester** — paste text, see exactly what each mode would replace;
* **rules** and **config** — read-only views of what the server runs with.

Everything here shows private values to whoever reaches the port, so it binds to
loopback unless told otherwise, and a bearer token gates every API call when
``LOCAL_LLM_MCP_ADMIN_TOKEN`` (or ``_TOKEN_FILE``) is set. Run it beside the MCP
server; both read the same dotenv, state dir and terms file (hot-reloaded).
"""
from __future__ import annotations

import argparse
import asyncio
import json
import logging
import os
import re
import secrets
import shutil
import sys
import tempfile
import time
from datetime import datetime
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse

from . import prompts
from .config import ENV_PREFIX, Config, ConfigError, load_env_file
from .llm import LLMError, LocalLLM
from .scrub import KINDS, PLACEHOLDER_RE, Scrubber, Vault

log = logging.getLogger("local_llm_mcp.admin")
INDEX = Path(__file__).parent / "admin" / "index.html"
_KEY_RE = re.compile(r"^[A-Za-z0-9._-]{1,128}$")
_TERM_KINDS = ("PERSON", "ADDRESS", "PHONE", "EMAIL", "ACCOUNT", "PII")


def _now() -> str:
    return datetime.now().astimezone().isoformat(timespec="seconds")


def _dir_size(p: Path) -> int:
    total = 0
    for f in p.rglob("*"):
        try:
            if f.is_file():
                total += f.stat().st_size
        except OSError:
            pass
    return total


class AdminState:
    def __init__(self, cfg: Config, token: str = ""):
        self.cfg = cfg
        self.token = token
        self.scrubber = Scrubber(cfg.rules_path, cfg.private_terms_path, strict=cfg.strict_pii)

    # ---- terms -------------------------------------------------------------------

    def terms_doc(self) -> dict:
        p = self.cfg.private_terms_path
        doc: dict = {"terms": []}
        if p.is_file():
            try:
                doc = json.loads(p.read_text(encoding="utf-8"))
            except Exception as exc:
                log.warning("terms file unreadable: %s", exc)
        groups = {str(g.get("kind", "PII")).upper(): g for g in doc.get("terms", []) if isinstance(g, dict)}
        for k in _TERM_KINDS:
            groups.setdefault(k, {"kind": k, "values": []})
            groups[k]["values"] = [str(v) for v in groups[k].get("values", [])]
        doc["terms"] = [groups[k] for k in _TERM_KINDS]
        doc.setdefault("_comment", "Literal terms local-llm-mcp always replaces with placeholders. Managed by the admin app; 0600.")
        return doc

    def save_terms(self, doc: dict) -> None:
        p = self.cfg.private_terms_path
        p.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp = tempfile.mkstemp(prefix=".terms-", dir=str(p.parent))
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(doc, fh, indent=2, ensure_ascii=False)
        os.chmod(tmp, 0o600)
        os.replace(tmp, p)
        self.scrubber.terms.reload()

    def add_terms(self, items: list[dict]) -> int:
        doc = self.terms_doc()
        groups = {g["kind"]: g for g in doc["terms"]}
        added = 0
        for it in items:
            kind = str(it.get("kind", "PII")).upper()
            kind = kind if kind in _TERM_KINDS else "PII"
            value = " ".join(str(it.get("value", "")).split())
            if len(value) < 2 or value.lower() in (v.lower() for v in groups[kind]["values"]):
                continue
            groups[kind]["values"].append(value)
            added += 1
        if added:
            self.save_terms(doc)
        return added

    def remove_term(self, kind: str, value: str) -> bool:
        doc = self.terms_doc()
        for g in doc["terms"]:
            if g["kind"] == kind.upper() and value in g["values"]:
                g["values"].remove(value)
                self.save_terms(doc)
                return True
        return False

    # ---- sessions ----------------------------------------------------------------

    def _sessions_dir(self) -> Path:
        return self.cfg.state_dir / "sessions"

    def _session_dir(self, key: str) -> Path | None:
        if not _KEY_RE.match(key):
            return None
        d = (self._sessions_dir() / key)
        try:
            d.resolve().relative_to(self._sessions_dir().resolve())
        except ValueError:
            return None
        return d if d.is_dir() else None

    def _is_live(self, meta: dict) -> bool:
        pid = meta.get("claude_pid")
        if not pid:
            return False
        sock = self.cfg.sock_dir / f"{pid}.sock"
        return sock.exists() and Path(f"/proc/{pid}").exists()

    def sessions(self) -> list[dict]:
        out = []
        root = self._sessions_dir()
        if not root.is_dir():
            return out
        for d in sorted(root.iterdir(), key=lambda p: p.stat().st_mtime, reverse=True):
            if not d.is_dir():
                continue
            meta = {}
            try:
                meta = json.loads((d / "meta.json").read_text(encoding="utf-8"))
            except Exception:
                pass
            vault = Vault(d / "placeholders.json")
            out.append({
                "key": d.name, "mode": meta.get("mode"), "created": meta.get("created"), "last_seen": meta.get("last_seen"),
                "turns": meta.get("turns", 0), "compactions": meta.get("compactions", 0),
                "last_compaction": meta.get("last_compaction"), "claude_session_id": meta.get("claude_session_id", ""),
                "claude_pid": meta.get("claude_pid"), "live": self._is_live(meta),
                "placeholders": vault.counts(), "placeholder_total": len(vault.by_placeholder),
                "artifacts": len(list((d / "artifacts").glob("a_*.txt"))) if (d / "artifacts").is_dir() else 0,
                "bytes": _dir_size(d), "summary_chars": (d / "summary.md").stat().st_size if (d / "summary.md").is_file() else 0,
            })
        return out

    def session_detail(self, key: str, turns_limit: int = 60) -> dict | None:
        d = self._session_dir(key)
        if d is None:
            return None
        meta = {}
        try:
            meta = json.loads((d / "meta.json").read_text(encoding="utf-8"))
        except Exception:
            pass
        vault = Vault(d / "placeholders.json")
        placeholders = [{"placeholder": ph, "kind": rec["kind"], "value": rec["value"]}
                        for ph, rec in vault.by_placeholder.items()]
        turns: list[dict] = []
        cp = d / "context.jsonl"
        if cp.is_file():
            lines = cp.read_text(encoding="utf-8", errors="replace").splitlines()
            for line in lines[-turns_limit:]:
                try:
                    turns.append(json.loads(line))
                except Exception:
                    continue
        artifacts = []
        ad = d / "artifacts"
        if ad.is_dir():
            for f in sorted(ad.glob("a_*.txt"), key=lambda p: p.stat().st_mtime, reverse=True):
                m = {}
                mf = ad / (f.stem + ".json")
                if mf.is_file():
                    try:
                        m = json.loads(mf.read_text(encoding="utf-8"))
                    except Exception:
                        pass
                artifacts.append({"ref": f.stem, "bytes": f.stat().st_size, **{k: m.get(k) for k in ("kind", "source", "ts", "rc")}})
        summary = (d / "summary.md").read_text(encoding="utf-8", errors="replace") if (d / "summary.md").is_file() else ""
        return {"key": key, "meta": meta, "live": self._is_live(meta), "placeholders": placeholders,
                "summary": summary, "turns": turns, "artifacts": artifacts, "bytes": _dir_size(d)}

    def purge_session(self, key: str) -> tuple[bool, str]:
        d = self._session_dir(key)
        if d is None:
            return False, "no such session"
        det = self.session_detail(key, 0)
        if det and det["live"]:
            return False, "session is live (its server holds the vault in memory); stop that conversation first"
        shutil.rmtree(d)
        return True, "deleted"

    def purge_placeholders(self, key: str) -> tuple[bool, str]:
        d = self._session_dir(key)
        if d is None:
            return False, "no such session"
        det = self.session_detail(key, 0)
        if det and det["live"]:
            return False, "session is live; its server would keep using the in-memory map"
        p = d / "placeholders.json"
        if p.exists():
            p.unlink()
        return True, "placeholders removed"

    def delete_artifacts(self, key: str) -> tuple[int, str]:
        d = self._session_dir(key)
        if d is None:
            return 0, "no such session"
        n = 0
        ad = d / "artifacts"
        if ad.is_dir():
            for f in ad.iterdir():
                if f.is_file():
                    f.unlink()
                    n += 1
        return n, "artifacts deleted"

    # ---- scrub tester / harvest ----------------------------------------------------

    def scrub_test(self, text: str, mode: str) -> dict:
        vault = Vault(Path(tempfile.mkdtemp(prefix="admin-scrub-")) / "v.json")
        secrets_only = mode != "pii"
        spans = [{"start": s, "end": e, "kind": k, "value": v} for s, e, k, v in
                 sorted(self.scrubber.find_spans(text, secrets_only=secrets_only), key=lambda t: t[0])]
        result = self.scrubber.scrub(text, vault, secrets_only=secrets_only)
        return {"mode": mode, "scrubbed": result.text, "replaced": result.replaced, "kinds": result.kinds, "spans": spans,
                "placeholders": [{"placeholder": ph, "kind": rec["kind"], "value": rec["value"]}
                                 for ph, rec in vault.by_placeholder.items()]}

    async def harvest(self, text: str) -> list[dict]:
        llm = LocalLLM(self.cfg)
        try:
            material = text[: self.cfg.chunk_chars * 2]
            out, _ = await llm.chat(prompts.ENTITY_SYSTEM, prompts.ENTITY_USER.format(material=material),
                                    max_tokens=2048, temperature=0.0)
        finally:
            await llm.aclose()
        seen: set[str] = set()
        found = []
        for ent in prompts.parse_entities(out):
            kind = str(ent.get("kind", "")).upper()
            value = " ".join(str(ent.get("value", "")).split())
            if kind not in _TERM_KINDS or len(value) < 2 or value not in text or value in seen:
                continue
            seen.add(value)
            found.append({"kind": kind, "value": value})
        return found

    # ---- read-only views -----------------------------------------------------------

    def rules(self) -> dict:
        self.scrubber.rules.reload()
        return {"source": self.scrubber.rules.source,
                "rules": [{"id": rid, "pattern": pat.pattern, "luhn": luhn} for rid, pat, luhn in self.scrubber.rules.regex]}

    def overview(self) -> dict:
        sessions = self.sessions()
        terms = self.terms_doc()
        ph_total: dict[str, int] = {}
        for s in sessions:
            for k, n in s["placeholders"].items():
                ph_total[k] = ph_total.get(k, 0) + n
        return {
            "now": _now(), "mode_default": self.cfg.mode, "model": self.cfg.model, "endpoint": self.cfg.base_url,
            "terms": {g["kind"]: len(g["values"]) for g in terms["terms"]}, "terms_path": str(self.cfg.private_terms_path),
            "rules_source": self.rules()["source"], "rules_count": len(self.scrubber.rules.regex),
            "sessions": len(sessions), "live": sum(1 for s in sessions if s["live"]),
            "placeholders": ph_total, "artifacts": sum(s["artifacts"] for s in sessions),
            "state_dir": str(self.cfg.state_dir), "state_bytes": sum(s["bytes"] for s in sessions),
            "entity_pass": self.cfg.entity_pass, "strict_pii": self.cfg.strict_pii, "observer": self.cfg.observer or "none",
        }


# ---------------------------------------------------------------------------- HTTP


def make_handler(state: AdminState):
    class Handler(BaseHTTPRequestHandler):
        server_version = "local-llm-mcp-admin"

        def log_message(self, fmt, *args):  # quiet by default; errors still go through log
            log.debug("%s " + fmt, self.address_string(), *args)

        # -- helpers
        def _json(self, code: int, body) -> None:
            data = json.dumps(body, ensure_ascii=False).encode("utf-8")
            self.send_response(code)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(data)

        def _body(self) -> dict:
            n = int(self.headers.get("Content-Length") or 0)
            if n > 4_000_000:
                raise ValueError("body too large")
            raw = self.rfile.read(n) if n else b""
            return json.loads(raw.decode("utf-8")) if raw else {}

        def _authed(self) -> bool:
            if not state.token:
                return True
            h = self.headers.get("Authorization", "")
            return h.startswith("Bearer ") and secrets.compare_digest(h[7:].strip(), state.token)

        def _route(self, method: str) -> None:
            url = urlparse(self.path)
            path = url.path
            if method == "GET" and path in ("/", "/index.html"):
                html = INDEX.read_bytes()
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Content-Length", str(len(html)))
                self.send_header("Cache-Control", "no-store")
                self.send_header("Content-Security-Policy",
                                 "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:")
                self.end_headers()
                self.wfile.write(html)
                return
            if method == "GET" and path == "/api/ping":
                return self._json(200, {"ok": True, "auth_required": bool(state.token), "authed": self._authed()})
            if not path.startswith("/api/"):
                return self._json(404, {"error": "not found"})
            if not self._authed():
                return self._json(401, {"error": "token required"})
            try:
                return self._api(method, path)
            except ValueError as exc:
                return self._json(400, {"error": str(exc)})
            except LLMError as exc:
                return self._json(502, {"error": f"local model: {exc}"})
            except Exception as exc:  # never leak a traceback to the page; log it
                log.exception("admin api error")
                return self._json(500, {"error": f"{type(exc).__name__}"})

        def _api(self, method: str, path: str) -> None:
            parts = path.split("/")[2:]  # after /api/
            head = parts[0] if parts else ""
            if method == "GET" and head == "overview":
                return self._json(200, state.overview())
            if method == "GET" and head == "config":
                return self._json(200, state.cfg.public())
            if method == "GET" and head == "rules":
                return self._json(200, state.rules())
            if head == "terms":
                if method == "GET":
                    return self._json(200, state.terms_doc())
                if method == "POST":
                    body = self._body()
                    items = body.get("items") or ([{"kind": body.get("kind"), "value": body.get("value")}] if body.get("value") else [])
                    return self._json(200, {"added": state.add_terms(items), "terms": state.terms_doc()})
                if method == "DELETE":
                    body = self._body()
                    ok = state.remove_term(str(body.get("kind", "")), str(body.get("value", "")))
                    return self._json(200 if ok else 404, {"removed": ok, "terms": state.terms_doc()})
            if method == "POST" and head == "scrub-test":
                body = self._body()
                text = str(body.get("text", ""))
                if len(text) > 200_000:
                    raise ValueError("text too long (200000 chars max)")
                return self._json(200, state.scrub_test(text, str(body.get("mode", "pii")).lower()))
            if method == "POST" and head == "harvest":
                body = self._body()
                text = str(body.get("text", ""))
                if not text.strip():
                    raise ValueError("no text")
                found = asyncio.run(state.harvest(text))
                return self._json(200, {"candidates": found, "model": state.cfg.model})
            if head == "sessions":
                if len(parts) == 1 and method == "GET":
                    return self._json(200, {"sessions": state.sessions()})
                key = parts[1] if len(parts) > 1 else ""
                if not _KEY_RE.match(key):
                    raise ValueError("bad session key")
                sub = parts[2] if len(parts) > 2 else ""
                if method == "GET" and not sub:
                    det = state.session_detail(key)
                    return self._json(200, det) if det else self._json(404, {"error": "no such session"})
                if method == "DELETE" and not sub:
                    ok, msg = state.purge_session(key)
                    return self._json(200 if ok else 409, {"ok": ok, "message": msg})
                if method == "DELETE" and sub == "placeholders":
                    ok, msg = state.purge_placeholders(key)
                    return self._json(200 if ok else 409, {"ok": ok, "message": msg})
                if method == "DELETE" and sub == "artifacts":
                    n, msg = state.delete_artifacts(key)
                    return self._json(200, {"ok": True, "deleted": n, "message": msg})
            return self._json(404, {"error": "no such endpoint"})

        def do_GET(self):  # noqa: N802
            self._route("GET")

        def do_POST(self):  # noqa: N802
            self._route("POST")

        def do_DELETE(self):  # noqa: N802
            self._route("DELETE")

    return Handler


def make_server(bind: str, port: int, cfg: Config, token: str) -> ThreadingHTTPServer:
    state = AdminState(cfg, token)
    srv = ThreadingHTTPServer((bind, port), make_handler(state))
    srv.daemon_threads = True
    return srv


def _load_token() -> str:
    tok = (os.environ.get(ENV_PREFIX + "ADMIN_TOKEN") or "").strip()
    if tok:
        return tok
    f = os.environ.get(ENV_PREFIX + "ADMIN_TOKEN_FILE")
    if f:
        p = Path(f).expanduser()
        if p.is_file():
            return p.read_text(encoding="utf-8").strip()
        raise ConfigError(f"{ENV_PREFIX}ADMIN_TOKEN_FILE={p} does not exist")
    return ""


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="local-llm-mcp-admin", description="web admin for local-llm-mcp's PII layer")
    ap.add_argument("--bind", default=None, help=f"address to bind ({ENV_PREFIX}ADMIN_BIND, default 127.0.0.1)")
    ap.add_argument("--port", type=int, default=None, help=f"port ({ENV_PREFIX}ADMIN_PORT, default 8631)")
    args = ap.parse_args(argv)
    load_env_file()
    try:
        cfg = Config.from_env()
        token = _load_token()
    except ConfigError as exc:
        print(f"local-llm-mcp-admin: {exc}", file=sys.stderr)
        return 2
    logging.basicConfig(stream=sys.stderr, level=getattr(logging, cfg.log_level, logging.INFO),
                        format="%(asctime)s local-llm-mcp-admin %(levelname)s %(name)s: %(message)s")
    bind = args.bind or os.environ.get(ENV_PREFIX + "ADMIN_BIND") or "127.0.0.1"
    port = args.port or int(os.environ.get(ENV_PREFIX + "ADMIN_PORT") or 8631)
    if bind not in ("127.0.0.1", "localhost", "::1") and not token:
        log.warning("binding %s with NO token: everyone who can reach this port can read private values. "
                    "Set %sADMIN_TOKEN or %sADMIN_TOKEN_FILE.", bind, ENV_PREFIX, ENV_PREFIX)
    srv = make_server(bind, port, cfg, token)
    log.info("admin on http://%s:%d/ (state %s, terms %s, token %s)", bind, port, cfg.state_dir, cfg.private_terms_path,
             "required" if token else "none")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
    return 0


if __name__ == "__main__":
    sys.exit(main())
