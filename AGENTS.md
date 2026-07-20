# PonoLens agent guide

This file is the working contract for coding agents modifying this repository.

## Product truth comes first

PonoLens is a privacy visibility and enforcement prototype. Never claim visibility or blocking that the integration cannot prove.

The competition preview is installed with `install.sh` and runs as a local service with a browser dashboard. Do not describe it as a packaged or native macOS application. A PonoLens Personal Mac application is a post-competition roadmap item. Do not claim additional operating-system support until detection, credential storage, filesystem permissions, hook generation, background service, installer, and integration behavior have been implemented and tested there.

- Green means no configured sensitive information or unusual movement was detected.
- Orange means sensitive information was detected and needs review, including information observed after submission.
- Red means a supported pre-submit/pre-action adapter actually returned and enforced a block.
- Codex side-chat prompts are observation-only and must direct users to Safe Prompt.
- Cursor and Claude Code CLI can block supported prompt hooks when configured and running.
- Windsurf can block native Cascade pre-hooks by receiving exit status 2 from the PonoLens adapter.
- Redact mode at supported prompt hooks stops the original and returns a sanitized copy. Do not claim that a third-party composer replaced or submitted that copy unless its documented hook contract proves it.
- Report Only is the stable default. Redact and Block are experimental features whose reliability depends on supported harness hooks. Keep those labels visible wherever the modes are presented.
- Claude Desktop is unsupported and must not be auto-detected as Claude Code.
- MCP coverage includes only calls routed through the PonoLens gateway.
- Experimental command monitoring is off by default and report-only. Record ordinary command events only when `policy.commandMonitoring` is true. Existing network/repository-risk behavior remains separate.

Do not describe deletion after transmission as undoing disclosure or establishing compliance.

## Privacy invariants

- Run deterministic detection and Safe Prompt's initial scan locally.
- Never send the Safe Prompt token map or original protected values to an LLM provider.
- Redact the complete stored event object—including content, commands, file lists, and auxiliary string fields—before it is written to SQLite.
- Never store command output. Sensitive command receipts must be marked for review and their command, serialized tool input, paths, and auxiliary strings must all pass through whole-event redaction.
- Never log raw hook payloads, secrets, API keys, protected values, or token mappings.
- Store API credentials in an operating-system credential facility, not browser local storage, SQLite audit records, or repository files.
- Keep audit data local unless a future feature obtains explicit consent and visibly logs the outbound transfer.
- Treat organization-defined exact values as sensitive local policy data.

## Detector architecture

`public/detectors.js` is the shared detector catalog for both the browser-local Safe Prompt scan and `src/risk-engine.mjs`. Add or change built-in detectors there, then add parity tests. Assign each definition to secrets, contact, healthcare, legal, financial, or custom. Exact values, organization dictionaries, and safe custom regex rules are converted into catalog definitions by `policyDefinitions()`.

Validation-sensitive formats must be validated before they count, redact, or tokenize. Current examples include Luhn payment-card validation, ABA routing checksums, IBAN mod-97, valid IPv4 octets, and contextual entropy checks. Prefer contextual patterns for names, addresses, identity documents, account numbers, and generic identifiers to reduce false positives.

Custom regex rules are limited in length and reject invalid expressions, lookbehind, backreferences, and common nested-quantifier patterns. Preserve those checks in both policy normalization and the browser catalog. Treat regex rules as a constrained MVP feature, not a complete ReDoS sandbox.

## Safe Prompt behavior

The wizard is a round trip:

1. Locally scan the original.
2. Let the user review/edit a readable safe draft.
3. Re-scan edits and generate the canonical tokenized prompt.
4. Copy it or send only that tokenized prompt to the selected provider.
5. Accept/retrieve the response and restore local values.

Sensitive subject matter may be retained with a warning when identifiers have been removed and deleting the topic would destroy the task's meaning. Never label tokenization alone as HIPAA de-identification or legal/compliance certification.

## Integration boundaries

- `public/product-config.js` is the shared source for product defaults, protection-category metadata, LLM/web providers, harness labels, detection paths, coverage, and interception capability. Update the catalog instead of duplicating those values in the server, dashboard, policy layer, or integration adapters.
- Concrete values in README/INSTALL examples may document a current default, but executable code must import the catalog. When a documented default changes, update its user-facing examples in the same change.
- `src/integrations.mjs` owns detection and configuration for Codex, Claude Code CLI, Cursor, and Windsurf.
- `src/adapters/hook.mjs` must return the exact response shape expected by each harness.
- `src/adapters/codex-session-observer.mjs` observes Codex session records; it is not a pre-submit blocker.
- `src/adapters/mcp-proxy.mjs` covers only explicitly proxied MCP JSON-RPC calls.
- `src/ollama-gateway.mjs` retains the disabled Ollama Gateway prototype. Keep `FEATURE_FLAGS.ollamaGateway` false until native-client coverage and deployment behavior are deliberately revisited. Never imply direct port `11434` prompt coverage.
- Hooks should fail visibly without printing raw input. A failed hook must not fabricate a successful block receipt.

When capability behavior changes, update the dashboard language, README, INSTALL guide, and tests in the same change.

## Persistence and settings

- Default database: `~/.ponolens/ponolens.db`
- Test override: `PONOLENS_DATA_DIR=/tmp/ponolens-test`
- Default event retention comes from `PRODUCT_DEFAULTS.retentionDays`
- Pono Guard settings auto-save after each change
- Appearance preferences may use browser local storage because they are not sensitive

Avoid destructive database migrations. Preserve user data and add migration tests for schema changes.

Full-history counts, filters, summaries, and exports must query SQLite before pagination. Do not derive database-wide review panels from the 20-event home preview or the currently loaded 100-event Data Trail page. Harness accordion state is user interface state and must survive live polling re-renders.

## Development workflow

Requirements: Node.js 22.5 or newer.

```bash
npm test
node --check public/app.js
git diff --check
```

`install.sh` is the competition distribution path. It installs the committed project under `~/.ponolens/application`, starts the local service, and opens the browser dashboard. Native application packaging is intentionally deferred until the post-competition PonoLens Personal edition.

Use fictitious data in tests. Include positive and negative/lookalike tests for new detectors. Verify that a validated detector is honored consistently by findings, redaction, tokenization, enforcement decisions, and the Safe Prompt browser path.

Before handing off UI changes, test light/dark themes, small/regular/large text, keyboard focus, reduced motion, and phone/tablet layouts. Maintain semantic controls, visible focus, readable detail text, and WCAG-appropriate contrast.

## Documentation language

Use plain language aimed at nontechnical users. Distinguish:

- **Observed:** PonoLens recorded evidence after or during an action.
- **Sent:** the integration indicates data left the device.
- **Blocked:** the supported adapter stopped the action before completion.
- **Stayed local:** there was no external destination for that event—not a general claim about the harness or model.

Avoid unsupported legal guarantees. Use: “supports privacy and compliance workflows but does not itself establish compliance.”
