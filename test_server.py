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
