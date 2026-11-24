#!/usr/bin/env python3
"""ShipReady MCP Server (zero-dependency Python 3 stdio JSON-RPC 2.0).

Exposes ShipReady static pre-launch security checks inside Cursor, Claude Code,
and Windsurf so AI coding agents can check repos for Supabase RLS, exposed
secrets, and unsigned Stripe webhooks locally.
"""

from __future__ import annotations

import importlib.util
import json
import os
import re
import sys
from pathlib import Path
from typing import Any

SERVER_INFO = {"name": "shipready-mcp", "version": "0.1.0"}
PROTOCOL_VERSION = "2024-11-05"
RULES_BASE = "https://shipmate.agency/rules/"
LOCKDOWN_NOTE = (
    "Automated static checks cannot verify business-logic IDOR, multi-tenant edge cases, "
    "or payment flows. Want a person to test your app and ship fixes in one PR? "
    "https://shipmate.agency/lockdown"
)

FALLBACK_RULES = [
    {"id": "SR-SUPA-001", "slug": "supabase-missing-rls", "severity": "medium", "title": "SQL table created without Row Level Security"},
    {"id": "SR-SUPA-002", "slug": "supabase-policy-using-true", "severity": "medium", "title": "Write policy allows everyone with USING (true)"},
    {"id": "SR-SUPA-003", "slug": "supabase-service-role-key-exposed", "severity": "high", "title": "Supabase service_role key in source code"},
    {"id": "SR-SUPA-004", "slug": "supabase-public-schema-exposed", "severity": "medium", "title": "Tables listed to the anon key in the public schema"},
    {"id": "SR-SEC-001", "slug": "secret-in-public-env-var", "severity": "high", "title": "Server secret in a client-exposed env var"},
    {"id": "SR-SEC-002", "slug": "hardcoded-api-key", "severity": "high", "title": "API key or private key hardcoded in source"},
    {"id": "SR-SEC-003", "slug": "env-file-not-gitignored", "severity": "medium", "title": "Env file present and not in .gitignore"},
    {"id": "SR-PAY-001", "slug": "stripe-webhook-no-signature-check", "severity": "medium", "title": "Stripe webhook handler without signature check"},
    {"id": "SR-WEB-001", "slug": "missing-csp", "severity": "medium", "title": "Content-Security-Policy header missing"},
    {"id": "SR-WEB-002", "slug": "missing-hsts", "severity": "medium", "title": "Strict-Transport-Security header missing"},
    {"id": "SR-WEB-003", "slug": "missing-x-frame-options", "severity": "low", "title": "Clickjacking protection missing"},
    {"id": "SR-WEB-004", "slug": "missing-nosniff", "severity": "low", "title": "X-Content-Type-Options: nosniff missing"},
    {"id": "SR-WEB-005", "slug": "missing-referrer-policy", "severity": "low", "title": "Referrer-Policy header missing"},
    {"id": "SR-WEB-007", "slug": "exposed-dotfile", "severity": "high", "title": "Env or git file served publicly"},
]
RULE_BY_ID = {r["id"]: r for r in FALLBACK_RULES}

SKIP_DIRS = {".git", "node_modules", ".next", "dist", "build", ".venv", "venv", "__pycache__"}
PUBLIC_SECRET_RE = re.compile(
    r"\b(?:NEXT_PUBLIC_|VITE_|PUBLIC_)[A-Z0-9_]*(?:SECRET|SERVICE_ROLE|PRIVATE|API_KEY|TOKEN)\b\s*=",
    re.IGNORECASE,
)
HARDCODED_KEY_RE = re.compile(r"\b(?:sk_live_[A-Za-z0-9]{16,}|sk-(?:proj-)?[A-Za-z0-9_-]{24,}|ghp_[A-Za-z0-9]{30,})\b")
CREATE_TABLE_RE = re.compile(r"create\s+table\s+(?:if\s+not\s+exists\s+)?([a-zA-Z0-9_.\"]+)", re.IGNORECASE)
USING_TRUE_RE = re.compile(r"create\s+policy[\s\S]{0,220}?\bfor\s+(?:all|insert|update|delete)\b[\s\S]{0,220}?using\s*\(\s*true\s*\)", re.IGNORECASE)


def _load_shipready_module() -> Any | None:
    candidates = []
    env_path = os.environ.get("SHIPREADY_CHECK_PY")
    if env_path:
        candidates.append(Path(env_path))
    here = Path(__file__).resolve()
    candidates.extend([
        here.parent / "check.py",
        here.parents[4] / "vibe-code-security-checklist" / "check.py",
    ])
    for cand in candidates:
        if cand.is_file():
            spec = importlib.util.spec_from_file_location("shipready_check", cand)
            if spec and spec.loader:
                mod = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(mod)
                return mod
    return None


def _line_no(text: str, pos: int) -> int:
    return text.count("\n", 0, pos) + 1


def _fallback_scan(root: Path) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []

    def add(rule_id: str, rel: str, line: int, detail: str) -> None:
        r = RULE_BY_ID[rule_id]
        findings.append({
            "rule_id": rule_id,
            "severity": r["severity"],
            "title": r["title"],
            "file": rel,
            "line": line,
            "detail": detail,
            "fix_url": f"{RULES_BASE}{r['slug']}/",
        })

    gitignore = (root / ".gitignore").read_text(encoding="utf-8", errors="ignore") if (root / ".gitignore").is_file() else ""
    if (root / ".env").is_file() and ".env" not in gitignore:
        add("SR-SEC-003", ".env", 1, ".env file exists and is not listed in .gitignore")

    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for fname in filenames:
            fpath = Path(dirpath) / fname
            if fpath.is_symlink():
                continue
            try:
                if fpath.stat().st_size > 512_000:
                    continue
                text = fpath.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                continue
            rel = str(fpath.relative_to(root))

            if fname.endswith(".sql"):
                lower = text.lower()
                for m in CREATE_TABLE_RE.finditer(text):
                    tbl = m.group(1).strip('"')
                    short = tbl.split(".")[-1].lower()
                    if f"enable row level security" not in lower or short not in lower[lower.find("enable row level security"):]:
                        add("SR-SUPA-001", rel, _line_no(text, m.start()), f"Table {tbl} created without ENABLE ROW LEVEL SECURITY")
                for m in USING_TRUE_RE.finditer(text):
                    add("SR-SUPA-002", rel, _line_no(text, m.start()), "Write policy uses USING (true)")

            for m in PUBLIC_SECRET_RE.finditer(text):
                add("SR-SEC-001", rel, _line_no(text, m.start()), f"Client-exposed secret env var: {m.group(0).split('=')[0].strip()}")

            for m in HARDCODED_KEY_RE.finditer(text):
                add("SR-SEC-002", rel, _line_no(text, m.start()), "Hardcoded live API key detected")

            if "service_role" in text and ("createClient" in text or "eyJ" in text):
                idx = text.find("service_role")
                add("SR-SUPA-003", rel, _line_no(text, idx), "Potential Supabase service_role key reference in source")

            if ("webhook" in rel.lower() and "stripe" in text.lower()) and "constructEvent" not in text:
                add("SR-PAY-001", rel, 1, "Stripe webhook handler does not call stripe.webhooks.constructEvent")

    return findings


def scan_repo(path_str: str) -> dict[str, Any]:
    target = Path(path_str).expanduser().resolve()
    if not target.exists() or not target.is_dir():
        raise ValueError(f"Directory does not exist: {path_str}")

    mod = _load_shipready_module()
    if mod is not None and hasattr(mod, "check_repo"):
        raw = mod.check_repo(target)
        findings = []
        for f in raw:
            if getattr(f, "status", "") == "PASS":
                continue
            rid = getattr(f, "rule", "") or ""
            if not rid:
                continue
            r = RULE_BY_ID.get(rid, {"severity": "medium", "title": rid, "slug": ""})
            findings.append({
                "rule_id": rid,
                "severity": r["severity"],
                "title": str(getattr(f, "title", r["title"])),
                "file": str(getattr(f, "location", "")),
                "line": int(getattr(f, "line", 1) or 1),
                "detail": str(getattr(f, "detail", r["title"])),
                "fix_url": f"{RULES_BASE}{r['slug']}/" if r["slug"] else RULES_BASE,
            })
        engine = "shipready-check.py"
    else:
        findings = _fallback_scan(target)
        engine = "shipready-mcp-standalone"

    return {
        "engine": engine,
        "scanned_path": str(target),
        "finding_count": len(findings),
        "findings": findings,
        "next_step": LOCKDOWN_NOTE,
    }


def list_rules() -> dict[str, Any]:
    return {
        "count": len(FALLBACK_RULES),
        "rules": [{**r, "url": f"{RULES_BASE}{r['slug']}/"} for r in FALLBACK_RULES],
    }


TOOLS = [
    {
        "name": "shipready_scan_repo",
        "description": "Scan a local app repository for common vibe-coded / Next.js / Supabase / Stripe security issues (missing RLS, USING true, exposed secrets, unsigned Stripe webhooks) and return exact rule fix URLs.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "path": {"type": "string", "description": "Absolute or relative path to the local repository directory."}
            },
            "required": ["path"],
        },
    },
    {
        "name": "shipready_list_rules",
        "description": "List all 14 ShipReady security rules with severity and documentation URLs on shipmate.agency/rules/.",
        "inputSchema": {"type": "object", "properties": {}},
    },
]


def handle_request(msg: dict[str, Any]) -> dict[str, Any] | None:
    method = msg.get("method")
    req_id = msg.get("id")

    if method == "notifications/initialized" or req_id is None:
        return None
    if method == "initialize":
        return {
            "jsonrpc": "2.0",
            "id": req_id,
            "result": {
                "protocolVersion": PROTOCOL_VERSION,
                "capabilities": {"tools": {}},
                "serverInfo": SERVER_INFO,
            },
        }
    if method == "tools/list":
        return {"jsonrpc": "2.0", "id": req_id, "result": {"tools": TOOLS}}
    if method == "tools/call":
        params = msg.get("params") or {}
        name = params.get("name")
        args = params.get("arguments") or {}
        try:
            if name == "shipready_list_rules":
                data = list_rules()
            elif name == "shipready_scan_repo":
                if not isinstance(args.get("path"), str) or not args["path"].strip():
                    raise ValueError("Missing required string argument: path")
                data = scan_repo(args["path"])
            else:
                return {"jsonrpc": "2.0", "id": req_id, "error": {"code": -32601, "message": f"Unknown tool: {name}"}}
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {"content": [{"type": "text", "text": json.dumps(data, indent=2)}]},
            }
        except Exception as exc:
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {"isError": True, "content": [{"type": "text", "text": str(exc)}]},
            }
    return {"jsonrpc": "2.0", "id": req_id, "error": {"code": -32601, "message": f"Method not found: {method}"}}


def read_message(stream: Any) -> tuple[dict[str, Any] | None, bool]:
    """Read either Content-Length framed or newline-delimited JSON-RPC from stdin."""
    while True:
        line = stream.readline()
        if not line:
            return None, False
        stripped = line.strip()
        if not stripped:
            continue
        if stripped.lower().startswith(b"content-length:"):
            length = int(stripped.split(b":", 1)[1].strip())
            while True:
                hdr = stream.readline()
                if not hdr or hdr in (b"\r\n", b"\n"):
                    break
            body = stream.read(length)
            return json.loads(body.decode("utf-8")), True
        return json.loads(stripped.decode("utf-8")), False


def write_message(stream: Any, payload: dict[str, Any], framed: bool) -> None:
    raw = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    if framed:
        stream.write(f"Content-Length: {len(raw)}\r\n\r\n".encode("ascii") + raw)
    else:
        stream.write(raw + b"\n")
    stream.flush()


def main() -> int:
    stdin = sys.stdin.buffer
    stdout = sys.stdout.buffer
    while True:
        msg, framed = read_message(stdin)
        if msg is None:
            break
        resp = handle_request(msg)
        if resp is not None:
            write_message(stdout, resp, framed)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
