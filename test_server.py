#!/usr/bin/env python3
"""End-to-end stdio JSON-RPC tests for shipready-mcp/server.py."""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

SERVER = Path(__file__).resolve().parent / "server.py"
sys.path.insert(0, str(SERVER.parent))
import server  # noqa: E402


def scan_ids(files: dict[str, str]) -> list[tuple[str, str]]:
    """Write files into a temp repo and return (rule_id, file) for each standalone finding."""
    with tempfile.TemporaryDirectory() as td:
        for rel, text in files.items():
            p = Path(td) / rel
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(text, encoding="utf-8")
        return [(f["rule_id"], f["file"]) for f in server._fallback_scan(Path(td))]


class TestDetection(unittest.TestCase):
    def test_public_env_secret_with_suffix(self) -> None:
        ids = scan_ids({".env.example": "NEXT_PUBLIC_STRIPE_SECRET_KEY=\nVITE_SUPABASE_SERVICE_ROLE_KEY=\nNEXT_PUBLIC_SUPABASE_ANON_KEY=\n"})
        self.assertEqual(ids.count(("SR-SEC-001", ".env.example")), 2)

    def test_gitignore_is_parsed_per_line(self) -> None:
        key = "sk" + "_live_" + "1234567890abcdef1234"
        # ".env.example" in .gitignore does not ignore .env
        self.assertIn(("SR-SEC-003", ".env"), scan_ids({".env": "A=1\n", ".gitignore": ".env.example\n"}))
        ignored = scan_ids({".env": f"STRIPE_SECRET_KEY={key}\n", ".env.local": f"STRIPE_SECRET_KEY={key}\n",
                            ".gitignore": "/.env\n.env*.local\n"})
        self.assertEqual(ignored, [])
        committed = scan_ids({".env.production": f"STRIPE_SECRET_KEY={key}\n", ".gitignore": ".env\n"})
        self.assertEqual(committed, [("SR-SEC-002", ".env.production")])

    def test_rls_matched_per_table_across_migrations(self) -> None:
        ids = scan_ids({
            "m/001.sql": "create table public.profiles (id uuid);\nalter table public.profiles enable row level security;\n"
                         "create table public.posts (id uuid);\ncreate table \"public\".\"orders\" (id uuid);\n",
            "m/002.sql": "alter table if exists \"public\".\"orders\" enable row level security;\n",
        })
        self.assertEqual(ids, [("SR-SUPA-001", "m/001.sql")])  # only posts

    def test_write_policy_allow_all_per_statement(self) -> None:
        sql = (
            "create table t (id uuid);\nalter table t enable row level security;\n"
            'create policy "own update" on t for update using (auth.uid() = id);\n'  # line 3: fine
            'create policy "public read" on t for select using (true);\n'           # line 4: fine (read)
            'create policy "implicit all" on t using (true);\n'                     # line 5: FOR ALL by default
            'create policy "open insert" on t for insert with check (true);\n'     # line 6
        )
        with tempfile.TemporaryDirectory() as td:
            (Path(td) / "a.sql").write_text(sql, encoding="utf-8")
            lines = [f["line"] for f in server._fallback_scan(Path(td)) if f["rule_id"] == "SR-SUPA-002"]
        self.assertEqual(lines, [5, 6])

    def test_hardcoded_key_formats(self) -> None:
        keys = [
            "rk" + "_live_" + "51Habcdefghijklmnopqrstuvwx",
            "github" + "_pat_" + "11ABCDEFG0123456789_" + "abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRS",
            "sk" + "-ant-api03-" + "abcdefghijklmnopqrstuvwxyz0123456789",
        ]
        src = "".join(f"const k{i} = '{k}';\n" for i, k in enumerate(keys))
        self.assertEqual(scan_ids({"lib/keys.ts": src}).count(("SR-SEC-002", "lib/keys.ts")), 3)
        self.assertEqual(scan_ids({"lib/keys.ts": "const pk = 'pk_live_51Habcdefghijklmnopqrstuvwx';\n"}), [])

    def test_unsigned_webhook_without_stripe_import(self) -> None:
        body = 'export async function POST(req) { const e = await req.json(); if (e.type === "checkout.session.completed") upgrade(); }\n'
        self.assertIn(("SR-PAY-001", "app/api/webhooks/route.ts"), scan_ids({"app/api/webhooks/route.ts": body}))
        signed = "const e = stripe.webhooks.constructEvent(await req.text(), sig, secret)\n"
        self.assertEqual(scan_ids({"app/api/stripe/webhook/route.ts": signed}), [])


class TestShipReadyMCP(unittest.TestCase):
    def _rpc(self, proc: subprocess.Popen[bytes], payload: dict) -> dict:
        assert proc.stdin and proc.stdout
        proc.stdin.write((json.dumps(payload) + "\n").encode("utf-8"))
        proc.stdin.flush()
        line = proc.stdout.readline()
        self.assertTrue(line, "Expected response line from MCP server")
        return json.loads(line.decode("utf-8"))

    def test_stdio_initialize_list_and_scan(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "schema.sql").write_text("CREATE TABLE public.invoices (id uuid, user_id uuid);\n", encoding="utf-8")
            (root / ".env").write_text("NEXT_PUBLIC_STRIPE_SECRET_KEY=sk_live_1234567890abcdef1234\n", encoding="utf-8")
            (root / "stripe-webhook.ts").write_text(
                'export async function POST(req) { const e = await req.json(); if (e.type === "checkout.session.completed") upgrade(); }\n',
                encoding="utf-8",
            )

            proc = subprocess.Popen(
                [sys.executable, str(SERVER)],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            try:
                init = self._rpc(proc, {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}})
                self.assertEqual(init["result"]["serverInfo"]["name"], "shipready-mcp")

                tools = self._rpc(proc, {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}})
                names = {t["name"] for t in tools["result"]["tools"]}
                self.assertEqual(names, {"shipready_scan_repo", "shipready_list_rules"})

                rules_res = self._rpc(proc, {
                    "jsonrpc": "2.0", "id": 3, "method": "tools/call",
                    "params": {"name": "shipready_list_rules", "arguments": {}},
                })
                rules_data = json.loads(rules_res["result"]["content"][0]["text"])
                self.assertEqual(rules_data["count"], 14)

                scan_res = self._rpc(proc, {
                    "jsonrpc": "2.0", "id": 4, "method": "tools/call",
                    "params": {"name": "shipready_scan_repo", "arguments": {"path": str(root)}},
                })
                scan_data = json.loads(scan_res["result"]["content"][0]["text"])
                ids = {f["rule_id"] for f in scan_data["findings"]}
                self.assertNotIn("", ids)
                self.assertIn("SR-SUPA-001", ids)
                self.assertIn("SR-SEC-001", ids)
                self.assertIn("SR-PAY-001", ids)
                self.assertIn("shipmate.agency/lockdown", scan_data["next_step"])
            finally:
                for stream in (proc.stdin, proc.stdout, proc.stderr):
                    if stream:
                        stream.close()
                proc.terminate()
                proc.wait(timeout=5)

    def test_scan_works_from_shallow_install_path(self) -> None:
        # Server used to index Path(__file__).parents[4] and raise IndexError near /.
        with tempfile.TemporaryDirectory(dir="/tmp") as inst, tempfile.TemporaryDirectory() as repo:
            server = Path(inst) / "server.py"
            server.write_bytes(SERVER.read_bytes())
            req = {"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                   "params": {"name": "shipready_scan_repo", "arguments": {"path": repo}}}
            out = subprocess.run([sys.executable, str(server)], input=json.dumps(req) + "\n",
                                 capture_output=True, text=True, timeout=10)
            result = json.loads(out.stdout)["result"]
            self.assertNotIn("isError", result)

    def test_protocol_version_negotiation(self) -> None:
        def negotiated(version: str | None) -> str:
            params = {} if version is None else {"protocolVersion": version}
            out = subprocess.run(
                [sys.executable, str(SERVER)],
                input=json.dumps({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": params}) + "\n",
                capture_output=True, text=True, timeout=10,
            )
            return json.loads(out.stdout)["result"]["protocolVersion"]

        self.assertEqual(negotiated("2024-11-05"), "2024-11-05")
        self.assertEqual(negotiated("2025-06-18"), "2025-06-18")
        self.assertEqual(negotiated("2025-11-25"), "2025-11-25")
        self.assertEqual(negotiated("1999-01-01"), "2025-11-25")
        self.assertEqual(negotiated(None), "2025-11-25")

    def test_protocol_errors_keep_server_alive(self) -> None:
        lines = [
            "{not json",
            "[1, 2]",
            json.dumps({"jsonrpc": "2.0", "id": 1, "method": "ping"}),
            json.dumps({"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {"name": "nope", "arguments": {}}}),
            json.dumps({"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": {"name": "shipready_scan_repo", "arguments": "x"}}),
            json.dumps({"jsonrpc": "2.0", "id": 4, "method": "foo/bar"}),
            json.dumps({"jsonrpc": "2.0", "id": 6, "method": "tools/call", "params": [1]}),
            json.dumps({"jsonrpc": "2.0", "id": 5, "method": "tools/list"}),
        ]
        out = subprocess.run(
            [sys.executable, str(SERVER)], input="\n".join(lines) + "\n",
            capture_output=True, text=True, timeout=10,
        )
        resp = [json.loads(l) for l in out.stdout.splitlines()]
        self.assertEqual([r.get("error", {}).get("code") for r in resp], [-32700, -32600, None, -32602, None, -32601, -32603, None])
        self.assertEqual(resp[2]["result"], {})
        self.assertTrue(resp[4]["result"]["isError"])
        self.assertIn("tools", resp[7]["result"])
        self.assertEqual(out.stderr, "")


if __name__ == "__main__":
    unittest.main()
