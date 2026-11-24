# ShipReady MCP Server

Run [Shipmate's](https://shipmate.agency) pre-launch security checks directly inside **Cursor**, **Claude Code**, or **Windsurf**.

Checks local repositories for the bugs most commonly shipped in AI-built Next.js, Supabase, and Stripe apps:
- SQL tables created without Row Level Security (`SR-SUPA-001`)
- Write policies using `USING (true)` (`SR-SUPA-002`)
- Exposed `service_role` keys (`SR-SUPA-003`)
- Server secrets placed in `NEXT_PUBLIC_` / `VITE_` env vars (`SR-SEC-001`)
- Hardcoded live API keys (`SR-SEC-002`) and ungitignored `.env` files (`SR-SEC-003`)
- Stripe webhook handlers missing `stripe.webhooks.constructEvent` (`SR-PAY-001`)

Zero dependencies — Python 3 stdlib only. Runs 100% locally; no source code leaves your machine.

## Install in Cursor (`.cursor/mcp.json`)

```json
{
  "mcpServers": {
    "shipready": {
      "command": "python3",
      "args": ["/path/to/shipready-mcp/server.py"]
    }
  }
}
```

## Install in Claude Code

```bash
claude mcp add shipready -- python3 /path/to/shipready-mcp/server.py
```

## Bonus IDE Rule Packs
- Copy [`cursorrules.txt`](./cursorrules.txt) into your repo's `.cursorrules` (or submit to Cursor Directory).
- Copy [`CLAUDE.security.md`](./CLAUDE.security.md) into your repo's `CLAUDE.md`.

## Automated scan vs human review
Static checks catch known patterns, not business-logic IDOR, multi-tenant edge cases, or payment abuse.
- Free passive check of your live site: https://shipmate.agency/check
- Human review + fixes in 1 PR ($950) or Pentest + attestation letter ($2,950): https://shipmate.agency
