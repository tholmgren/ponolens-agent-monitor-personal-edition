# PonoLens Agent Monitor — Personal Edition (Beta)

**Platform: macOS (Unix-based) only. A Windows release is planned for August 2026. Linux and other Unix platforms are not supported by this beta.**

**See what your AI agents send, understand the risk, and stop supported unsafe prompts before they leave your computer.**

PonoLens is a local-first privacy monitor and Safe Prompt workspace for AI coding agents. It turns agent activity into plain-language receipts, detects sensitive information locally, and applies Pono Guard policies at supported interception points.

> **Beta software:** Review the documented harness coverage and limitations before relying on PonoLens. Report Only is stable; Block, Redact, and Agent Command Monitoring are experimental. PonoLens supports privacy workflows but is not a compliance certification or a substitute for organizational controls.

The competition preview supports Codex, Claude Code CLI, Cursor, and Windsurf through a local browser dashboard. Coverage differs by harness and is always described honestly in the dashboard. The current release is built and tested for the Unix environment provided by macOS; it is not a general Linux/Unix or Windows release.

## Quick start

Development requirements: Node.js 22.5 or newer. PonoLens currently has no third-party runtime packages.

```bash
git clone https://github.com/tholmgren/ponolens-agent-monitor-personal-edition.git
cd ponolens-agent-monitor-personal-edition
npm test
npm start
```

Open [http://127.0.0.1:4317](http://127.0.0.1:4317), then use **Scan agents** and **Enable system-wide** for the harnesses installed on your computer. Fully restart a harness after changing its hooks.

The dashboard port is configurable with `PORT`. Set `PONOLENS_COLLECTOR_URL` when generated harness bridges must use an explicit collector address, and reconnect those harnesses after changing it. See the installation guide for examples.

See [INSTALL.md](INSTALL.md) for harness-specific setup, verification, troubleshooting, Ollama, API-provider, and data-location instructions. Open the dashboard's **FAQ** tab for common product and usage questions.

## Competition-preview installation

The beta uses one script-installed local service and browser dashboard. Install the current public release with:

```bash
curl -fsSL https://raw.githubusercontent.com/tholmgren/ponolens-agent-monitor-personal-edition/main/install.sh | sh
```

The installer downloads the public GitHub repository, requires Node.js 22.5+ and Git, installs the application under `~/.ponolens/application`, starts the loopback-only service, and opens the dashboard. It also creates `~/Applications/PonoLens.app`; opening that launcher restarts the service when necessary and opens the dashboard. You can alternatively clone the repository and run `./install.sh` from the checkout. The launcher is locally generated and is not yet a signed native distribution.

## Safe sample data and demo run

No seed database or external dataset is required. PonoLens creates its local SQLite database on first run. Test only with fictitious information—never real patient, client, financial, identity, or authentication data.

1. Start PonoLens and open [http://127.0.0.1:4317](http://127.0.0.1:4317).
2. Open **Agent status**, scan agents, enable one supported integration, and fully restart that harness.
3. Submit a harmless prompt such as `Explain what this demo project does.` A normal observed event should produce a green receipt.
4. With Pono Guard set to its stable **Report Only** mode, submit this deliberately fictional prompt:

   ```text
   Draft a follow-up for demo patient Alex Example, patient ID DEMO-001,
   email alex@example.invalid, with high blood pressure. This is synthetic test data.
   ```

   A supported observed submission should create an orange **Needs Review** receipt with protected categories and redacted stored details.
5. Open **Safe Prompt**, paste the same fictional prompt, continue through the wizard, and confirm that identifiers become local tokens before copying or sending the protected version.
6. Open **Data Trail** to filter the receipts and export a redacted incident report. Select any event on Live Lens or Data Trail to open its human-readable privacy receipt; receipts are event details, not a separate navigation screen.

Experimental Block and Redact should be tested only with fictional data and only after reviewing the harness capability and limitation shown in **Agent status**. A red receipt means the compatible pre-submit adapter actually stopped the action; PonoLens does not label post-submission observation as blocked.

For a deterministic judge preview, expand any configured harness under **Installed harnesses**, then use the **Test Harness** controls. **Test connection** checks the configured adapter without promising a Pono Trail receipt. **Test event** adds one orange, clearly labeled synthetic receipt through the normal detector, redaction, SQLite, Needs Review, and detail-view pipeline. It uses only fictional data and does not contact the harness or a model provider.

## How GPT-5.6 and Codex accelerated the build

GPT-5.6 through Codex was the primary development collaborator for this competition build. It was used to inspect and modify the repository, run the application and test suite, investigate live harness behavior, interpret screenshots and user feedback, harden local storage and HTTP boundaries, update documentation, and prepare the release. GPT-5.6/Codex is part of the development workflow; PonoLens does not secretly send audit logs or protected values to GPT-5.6 at runtime.

Codex materially accelerated work in these areas:

- **Cross-harness implementation:** compared real Codex, Cursor, Claude Code CLI, and Windsurf/Devin event shapes, then built normalization and adapter tests around their different hook contracts.
- **Fast feedback loops:** reproduced stale collector, live-update, filtering, modal, settings-persistence, and responsive-layout problems; changed the code and reran focused checks after each iteration.
- **Privacy engineering:** centralized the detector catalog used by Pono Guard and Safe Prompt, added redaction-before-SQLite guarantees, and wrote tests proving raw protected values do not enter audit records or exports.
- **Security hardening:** helped add loopback request protections, body limits, security headers, static-file containment, database permissions and integrity checks, bounded token storage, constrained custom patterns, and fail-closed supported bridges.
- **Release quality:** maintained the installer, macOS launcher, Apache 2.0 release documentation, honest capability language, and the automated regression suite.

### Key decisions made during the build

The product direction was decided iteratively with GPT-5.6/Codex evaluating implementation options and tradeoffs while the project owner made the final calls:

1. **Local-first by default:** store redacted receipts and policy in owner-only SQLite rather than creating a cloud audit service for the beta.
2. **Honest coverage over a universal-protection claim:** show Installed, Hook configured, Currently reachable, Prompt coverage, capabilities, limitations, and last event separately for every harness.
3. **Report Only as the stable default:** label Block, Redact, and Agent Command Monitoring Experimental because third-party hook coverage differs and can change.
4. **Never confuse observation with prevention:** use red only when a supported pre-submit hook confirms a block; sensitive information detected after transmission remains orange.
5. **Safe Prompt as the dependable controlled path:** identify and tokenize protected identifiers locally, send only the protected draft, and restore values locally in the reply.
6. **One detector definition source:** Pono Guard, command receipts, server analysis, and the browser-local Safe Prompt scanner share the same catalog to reduce inconsistent results.
7. **No raw prompt archive:** retain redacted metadata needed for an understandable trail without turning PonoLens into another sensitive-data repository.
8. **macOS-first beta:** validate the experience deeply in the Unix-based macOS environment before the planned Windows release in August 2026; Linux and other Unix platforms remain future work.

The detailed judging narrative and three-minute demonstration sequence are also available in [COMPETITION.md](COMPETITION.md).

## What PonoLens does

- Maintains a live, user-readable trail of observed prompts and agent actions
- Shows the source, harness, destination, project folder, decision, and detected categories
- Uses green for normal activity, orange for sensitive information that needs review, and red for actions PonoLens actually blocked
- Redacts sensitive values before saving audit previews
- Stores audit events, policies, and organization-defined protected values in local SQLite
- Supports configurable audit retention, with 180 days as the default
- Provides combined harness/risk/date/search filters, daily and repeated-risk summaries, and database-backed pagination
- Exports redacted CSV/PDF incident reports without prompt content or detector samples
- Shows separate installed, configured, reachable, coverage, capability, limitation, and last-event status in compact harness accordions that remain open during live refreshes
- Provides visible, separate **Test connection** and **Test event** controls for configured harnesses so judges can distinguish adapter health from a synthetic trail preview
- Loads **Risks explained** and **Unsafe actions stopped** review lists from the complete retained database, not only the home-page preview
- Provides a local Safe Prompt wizard that tokenizes identifiers before a prompt is copied or sent
- Restores protected values locally after the user pastes an AI response back into the wizard
- Supports a switchable default provider: Ollama, a configured API provider, or a web app copy/paste workflow
- Provides Advanced Guard controls for trusted destinations, risk thresholds, category actions, organization dictionaries, and constrained custom regex rules
- Offers opt-in **Agent command monitoring · Experimental** for commands exposed by supported harness hooks; sensitive command receipts are redacted, marked for review, and never include command output

## Harness coverage

| Harness | Prompt visibility | Experimental command reporting | Important limitation |
|---|---|---|---|
| Cursor | `beforeSubmitPrompt` hook | Commands exposed through configured `preToolUse`/`postToolUse` payloads | Command detail varies by Cursor version and tool; commands that omit a command field cannot be reconstructed |
| Claude Code CLI | `UserPromptSubmit` hook | Shell/command tools exposed through `PreToolUse` | Claude Desktop is a different application and is unsupported |
| Windsurf / Devin Desktop | Native Cascade `pre_user_prompt` hook | Native `pre_run_command` and compatible `PreToolUse` events | Activity that bypasses Cascade hooks is invisible |
| Codex | Local session observation and covered task hooks | Covered command tool calls found in task hooks or observable local sessions | Codex side chats cannot be blocked, and unrelated Terminal commands are invisible |
| Claude Desktop | Not supported | No | Claude Desktop does not use Claude Code hooks |

The experimental Ollama Gateway is disabled in the current build. Ollama remains available as a local Safe Prompt provider, but native Ollama macOS chats are not monitored merely because port `11434` is detected.

PonoLens cannot inspect arbitrary encrypted traffic or activity that bypasses its hooks, observer, MCP gateway, or API. An installed application is not the same as an active monitored integration.

### Experimental command monitoring

Agent command monitoring is off by default and report-only. When enabled, PonoLens records commands such as shell, Git, package-manager, and network commands only when an existing harness exposes the command through a configured hook or observable local session record. Sensitive commands are orange and included by the database-wide **Needs Review** filter.

Before writing SQLite, PonoLens recursively redacts detected secrets, credentials, personal information, regulated identifiers, custom protected values, filenames, serialized tool input, and the command preview itself. It does not store command output. Aliases, shell expansion, nested scripts, subprocesses, encrypted traffic, and unhooked commands can obscure the final operation or destination. PonoLens does not monitor commands manually run in an unrelated Terminal window.

For Codex side chats, use **Safe Prompt** before submitting sensitive text. PonoLens may observe the completed submission afterward, but that receipt cannot undo a transmission.

## Sensitive-data categories

Pono Guard and the browser-local Safe Prompt scanner share the same category model:

- **Secrets and access keys:** passwords, private keys, common API-key formats, cloud/service credentials, and contextual high-entropy secrets
- **Personal and contact information:** emails, phone numbers, contextual names and postal addresses, dates of birth, passports, driver licenses, IP addresses, device identifiers, and contextual international personal identifiers
- **Healthcare information:** patient and insurance identifiers, medical record numbers, health-plan beneficiary numbers, provider identifiers, medical-device identifiers, diagnoses, medications, treatments, and health conditions
- **Legal information:** matter, case, claim, and docket identifiers plus privilege and work-product markers
- **Financial information:** Social Security numbers, bank accounts, validated ABA routing numbers, Luhn-validated payment cards, and validated IBANs
- **Organization-defined values:** exact local dictionary entries such as client names, matter numbers, patient IDs, codenames, and internal classifications

Checksum validation reduces false positives but no deterministic detector is perfect. Built-in detection, hook enforcement, redaction, and Safe Prompt use one shared catalog. Advanced Guard adds local dictionaries and a deliberately restricted, group-free regular-expression subset. Custom expressions cannot use groups, alternation, backreferences, or unbounded quantifiers; bounded ranges may not exceed 1,000 repetitions. Use dictionaries when they can express the same rule more simply.

## Advanced Pono Guard

Open **Advanced Guard** to configure one action per category. **Report Only** is the stable default and records without interruption. **Redact** and **Block** are experimental: they operate only when a compatible pre-submit hook runs and must not be treated as universal prevention. Safe Prompt can replace matching identifiers directly because it controls its own composer; third-party hook APIs generally cannot rewrite an in-flight prompt.

The main **Pono Guard** screen orders its modes as **Report Only · Stable**, **Block · Experimental**, and **Redact · Experimental**. A fourth **Custom · Advanced** state appears when per-category actions use a mixed configuration from Advanced Guard. Selecting a standard mode applies that action across categories; selecting Custom returns to Advanced Guard. The separate opt-in **Agent command monitoring · Experimental** switch creates report-only receipts and does not block or rewrite commands.

Trusted hostnames reduce destination-risk scoring but never bypass sensitive-data rules. Transfer and severity thresholds, dictionaries, and regex rules apply to new events and save automatically in the local policy database.

## Safe Prompt workflow

1. Create the original prompt. The initial scan runs locally in the browser.
2. Review and edit the safe draft. Identifiers are replaced with local tokens; sensitive subject matter may remain with a warning when removing it would destroy the prompt's purpose.
3. Copy the tokenized prompt or send it to the selected default provider.
4. Paste or retrieve the model reply.
5. Restore tokenized values locally for the user-visible result.

The token map and original sensitive values are not sent to the model provider by this workflow. The user must still review the remaining narrative and use an organization-approved provider. Tokenization supports privacy and compliance work, but does not itself establish HIPAA compliance, legal privilege, SEC compliance, or any certification.

## Local data and privacy

By default, PonoLens stores data at:

```text
~/.ponolens/ponolens.db
```

The SQLite database uses write-ahead logging. Stored event previews are redacted; policy settings and exact protected values remain local. PonoLens does not enable cloud synchronization.

Override the data directory for testing:

```bash
PONOLENS_DATA_DIR=/tmp/ponolens-check npm start
```

Appearance preferences are stored in browser local storage. Provider API keys configured through PonoLens are stored using the operating-system credential facility where the current implementation supports it, not in audit events or browser local storage.

Settings also provides a safe policy-template export that excludes user-authored labels, exact protected values, dictionary entries, and custom patterns, plus a confirmed **Delete all local data** control. Database startup applies schema migrations, verifies owner-only file permissions, and supports an integrity check. Generated pre-submit bridges fail closed when the collector is unavailable so an unreviewed prompt is not silently sent.

## FAQ

Open the **FAQ** tab in the dashboard for categorized, expandable answers about stable Report Only behavior, Experimental Block/Redact limitations, supported agents, Safe Prompt, local storage, retention, compliance limitations, MCP coverage, testing, and troubleshooting.

The home page (**Live Lens**) shows only the newest activity preview. Its **Risks explained** and **Unsafe actions stopped** counts and review panels query all retained events. **Data Trail** is the full-history workspace: filters run against SQLite before pagination, and combined filters, summaries, search, and exports therefore apply beyond the currently visible 100 rows. A privacy receipt is the plain-language detail view opened from an event in either workspace; it is not a separate top-level destination.

In **Settings → Default AI model**, provider, model, and web-app changes save automatically. OpenAI model text uses a short typing delay before saving. API-key storage remains a separate explicit Keychain action so a partially entered credential is never saved accidentally.

## Development

```bash
npm test
```

The test suite covers event normalization, hook decisions, opt-in command reporting across existing harness payloads, sensitive-command review classification, raw-value exclusion from command receipts, local storage, database migrations and integrity, static-file containment, fail-closed bridges, redacted exports, redaction/tokenization, harness configuration, checksum validation, expanded sensitive-data detection, and common false-positive cases.

Read [AGENTS.md](AGENTS.md) before changing the risk engine, hook output, privacy claims, or persistence model.

### Shared product configuration

Runtime defaults and product catalogs live in [`public/product-config.js`](public/product-config.js). It is the canonical source for:

- Server host and default port
- Audit retention, activity pagination, and dashboard polling defaults
- Risk and repository-transfer threshold defaults and validation bounds
- Trusted-destination defaults
- Protection-category labels, descriptions, and default enabled state
- LLM modes, web-app providers, endpoints, and model defaults
- Harness names, detection/configuration paths, destination labels, filters, coverage, and prompt-interception events

The browser, server, risk engine, and integration generator import this catalog. Add or change a provider, harness, capability, or default there rather than maintaining another application-level list. User-facing installation examples may state concrete defaults such as port `4317`; those examples document the catalog value and are not runtime configuration sources.

## Event API

Adapters submit normalized events to `POST /api/events`. PonoLens returns a structured decision and saves a redacted receipt.

```json
{
  "harness": "cursor",
  "action": "prompt",
  "hookEvent": "beforeSubmitPrompt",
  "source": "Your prompt",
  "destination": "Cursor model provider",
  "destinationTrust": "unknown",
  "content": "Prompt content inspected locally"
}
```

The API decision does not prove an action was blocked. The harness adapter must receive the event before submission and honor the returned block response.

## Roadmap

1. PII-leak and prompt-injection/threat detection improvements
2. Token and cost metadata by model, harness, project, and organization, without retaining prompt content
3. Broader MCP and Windsurf post-action receipt coverage
4. OpenClaw and Hermes research/integrations
5. Signed native PonoLens Personal Mac application and a Windows release targeted for August 2026; Linux and other Unix packaging remains future work
6. PonoLens Pro production-grade prevention, updates, and professional workflows
7. PonoLens Enterprise policy, fleet, reporting, and optional redacted metadata synchronization

## License

PonoLens Personal Edition is open source under the [Apache License 2.0](LICENSE). The license permits use, modification, and distribution subject to its terms and does not grant rights to the PonoLens name or trademarks.
