# Security Guardrails (Shipmate / ShipReady)

Enforce these rules before writing or approving any database migration, API route, Server Action, webhook, or AI endpoint. Full rule explanations: https://shipmate.agency/rules/

- **RLS mandatory:** Every new `public.*` table requires `ENABLE ROW LEVEL SECURITY` + explicit `auth.uid()` / tenant membership policies. Reject `USING (true)` on mutations.
- **No client-exposed secrets:** Never put API secrets, webhook secrets, or `service_role` keys in `NEXT_PUBLIC_*`, `VITE_*`, or browser code. Keep `.env*` in `.gitignore`.
- **Auth on every mutation:** Every Next.js Server Action and API route must verify the server session and check resource ownership against the database.
- **Verified webhooks only:** Stripe webhooks must validate `stripe-signature` via `stripe.webhooks.constructEvent` on the raw request body.
- **Bounded AI spend:** Any LLM proxy route requires auth, rate limiting, and explicit `max_output_tokens`.
- **Pre-launch verification:** Run the `shipready_scan_repo` MCP tool locally and check public headers at https://shipmate.agency/tools/security-headers. For a human review + 1-PR fix before launch or enterprise buyers, see https://shipmate.agency.
