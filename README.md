# MEOK CRA Article 14 Reporter MCP

> ## 🧱 Part of the MEOK Governance Substrate (£499/mo)
> See [meok.ai/governance](https://meok.ai/governance).

# EU Cyber Resilience Act Article 14 — actively-exploited-vulnerability reporter

<!-- mcp-name: io.github.CSOAI-ORG/meok-cra-art14-reporter-mcp -->

[![PyPI](https://img.shields.io/pypi/v/meok-cra-art14-reporter-mcp)](https://pypi.org/project/meok-cra-art14-reporter-mcp/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

## What this does

EU Cyber Resilience Act (Regulation 2024/2847) Article 14 requires manufacturers of products with digital elements to notify **ENISA + national CSIRT** when an actively-exploited vulnerability is discovered.

**Effective: 11 September 2026.**

The clock is brutal:
- **24 hours** — early warning to ENISA + national CSIRT (Article 14(2)(a))
- **72 hours** — incident notification with mitigation (Article 14(2)(b))
- **14 days** — final report after the vulnerability is resolved (Article 14(2)(c))

This MCP:
- Classifies vulnerabilities against the "actively exploited" test
- Generates ENISA + national-CSIRT payloads
- Tracks the three clocks per case
- Maps the right national CSIRT (DE: BSI, FR: ANSSI, NL: NCSC-NL, etc.)
- HMAC-signs the chain for audit

## Tools

| Tool | Purpose |
|---|---|
| `classify_vulnerability(description, cvss_v3?, exploited_in_wild?)` | Does this trigger Article 14? |
| `open_vulnerability_case(cve_id, product, description, cvss, ...)` | Start the 3-clock tracker |
| `generate_enisa_payload(case_id, mitigation_steps?)` | ENISA + national-CSIRT submission |
| `check_clock_status(case_id)` | Hours remaining per clock |
| `list_national_csirts()` | EU national CSIRT contact map (10+ countries) |
| `check_cra_status()` | Days until 11 Sept 2026 |
| `sign_chain(case_id)` | HMAC-seal the full case for audit |

## Sister MCPs

Part of the MEOK **Governance** substrate:

- `cra-compliance-mcp` — full CRA Annex I classifier + SBOM + conformity
- `agent-incident-relay-mcp` — broadcasts Article 14 to AI Act + DORA + NIS2 simultaneously
- `sbom-cyclonedx-mcp` — SBOM for the affected product
- `mitre-attack-mcp` — exploit-technique mapping

Full catalogue: [meok.ai/anthropic-registry](https://meok.ai/anthropic-registry)

## Pricing

| Option | Price |
|---|---|
| Self-host MIT | £0 |
| Universal PAYG | £29/mo + £0.0002/call |
| Governance Substrate | £499/mo |
| A2A Substrate | £999/mo |
| Defence | £4,990/mo |

Buy: https://meok.ai/governance

## Wire it up — full stack

This MCP composes with the broader MEOK chain. See [meok.ai/mcp-stack](https://meok.ai/mcp-stack) for the 6-MCP chain that turns one incident into one auditor-defensible event.

## Licence

MIT. By [MEOK AI Labs](https://meok.ai) (CSOAI LTD, UK Companies House 16939677).

<!-- BUY-LADDER:START -->

## 💸 Try MEOK in 30 seconds — instant buy ladder

| Tier | Price | What you get | Stripe |
|---|---|---|---|
| Smoke test | **£1** | Signed sample MCP-Hardening report + Article 50 PDF | <https://buy.stripe.com/dRmcN75ScdQS7oh1Uc8k90U> |
| Quick Kit | **£9** | EU AI Act Article 50 implementation guide (C2PA + EU-Icon) | <https://buy.stripe.com/cNi00la8s1460ZT0Q88k90V> |
| Founder Call | **£29** | 30-min 1-on-1 with the founder | <https://buy.stripe.com/8x228ta8s6oqbExaqI8k90W> |

> Refundable. UK Stripe — VAT-clean. Builds on the 81-MCP MEOK fleet.
> Verify any signed report at <https://meok.ai/verify>.

<!-- BUY-LADDER:END -->

