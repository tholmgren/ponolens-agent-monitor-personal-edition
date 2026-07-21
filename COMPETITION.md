# PonoLens Agent Monitor — Personal Edition (Beta): competition story

**Current platform: macOS (Unix-based) only. A Windows release is planned for August 2026. Linux and other Unix platforms are not supported by this beta.**

## One-line pitch

PonoLens is a local-first privacy monitor that shows ordinary users what AI coding agents are sending, detects sensitive data locally, and explains every report or experimental prevention action in plain language.

## The problem

AI agents can read repositories, run tools, and send prompts or context to model providers. Existing logs are usually technical, fragmented, or available only after transmission. An installed security integration can also be mistaken for complete protection even when its hook is inactive or the harness does not expose a blocking point.

## The solution

PonoLens combines three experiences:

1. **Agent status:** compact, live-safe accordions separate installed, hook configured, currently reachable, prompt coverage, Report/Redact/Block capability, known limitations, and last event received.
2. **Pono Guard:** detects healthcare, legal, financial, identity, contact, secret, and organization-defined data locally. Report Only is the stable default. Redact and Block are clearly labeled Experimental and run only where supported pre-submit hooks expose compatible control.
3. **Safe Prompt:** creates a de-identified prompt locally, sends only the tokenized version to the chosen model, and restores identifiers locally in the response.

An opt-in **Agent command monitoring · Experimental** control adds report-only receipts for commands exposed by supported hooks. Sensitive commands are redacted before storage, displayed as caution events, and included in Needs Review without retaining command output.

The Data Trail stores redacted receipts in owner-only local SQLite, supports combined database-wide filters, groups repeated risks, and exports redacted incident reports. Home-page risk and blocked-action review counts also open database-backed results rather than filtering only the newest preview.

## Why it is different

- **Human-readable:** “Sensitive information detected and sent” instead of packet traces.
- **Honest coverage:** installed never means fully protected; each harness shows its actual reachability and interception limits.
- **Local-first:** detection, policy, redaction, token mapping, and audit storage stay on the device.
- **Actionable:** users can move from a warning to Safe Prompt instead of merely reading an alert.
- **Cross-harness:** one consistent privacy layer for Codex, Cursor, Claude Code CLI, and Windsurf/Devin.
- **Professional workflows:** shared healthcare, legal, financial, identity, credential, dictionary, and constrained-pattern protections.

## Three-minute demo

1. Open **Agent status** and show that every harness distinguishes installed, configured, reachable, supported actions, limitations, and last event.
2. Submit a harmless prompt in a supported harness; show the green receipt and its real destination/project context.
3. Explain that Report Only is stable, then submit fictitious sensitive data through Cursor, Claude Code CLI, or Windsurf/Devin with Experimental Block enabled; show a red receipt only if the pre-submit adapter actually stops it.
4. Show an observational Codex event as orange—not falsely blocked—and open its explanation recommending Safe Prompt.
5. Use **Safe Prompt** to tokenize a fake patient/client identifier, send only the protected draft, and restore the reply locally.
6. Open **Data Trail**, combine harness + protected-data + date/search filters, show repeated-risk summaries, and export a redacted incident report.
7. Enable Experimental command monitoring, run a harmless command and a fictitious sensitive command, then show the redacted orange receipt under Needs Review.
8. End on Settings: local retention, safe policy export, and confirmed local-data deletion.

## Trust and security proof points

- Loopback-only service with Host/origin/fetch-metadata protections and a required dashboard request header.
- Owner-only local database and sidecar permissions.
- Bounded JSON bodies, request timeouts, bounded token vault, strict security headers, and path-aware static-file containment.
- Parameterized database filters, schema versioning, integrity checks, and migration tests.
- Generated blocking bridges fail closed when the local collector is unavailable.
- Tests prove stored events and CSV/PDF exports exclude raw protected values and prompt previews.
- A safe policy-template export excludes user-authored labels, organization-specific protected values, dictionary entries, and custom patterns.

## Honest limitations

- PonoLens sees only events exposed by supported hooks, local session records, or configured gateways; it is not a universal packet interceptor.
- Codex side chats cannot be reliably blocked before submission, so sensitive events are reported after transmission and users are directed to Safe Prompt.
- Claude Desktop is not Claude Code CLI and is not covered.
- Redact and Block are experimental. Harness APIs may change, miss activity, or interrupt workflows; they are not universal prevention guarantees.
- Experimental redaction in third-party harnesses attempts to stop the original and returns a sanitized copy for review; it does not silently rewrite every third-party composer.
- Tokenization and audit controls support compliance programs but do not alone establish HIPAA, legal-privilege, SEC, or other regulatory compliance.
- Cost/token metadata is intentionally deferred until it can be collected without retaining prompt content.
- Command reporting covers only commands exposed by supported hooks or observable session records. It cannot guarantee visibility into aliases, nested scripts, subprocesses, final shell expansion, command output, or unrelated Terminal activity.
- The competition preview is installed with `install.sh`, runs as a local service with a browser dashboard, and creates a local macOS launcher; it is not yet a signed native distribution.
- The beta is built and tested only for the Unix environment provided by macOS. A Windows release is planned for August 2026; Linux and other Unix platforms are not supported in this release.
- A signed PonoLens Personal Mac application is planned after the competition.

## Business direction

- **Competition preview:** local dashboard, core harness monitoring, stable Report Only, Experimental Redact/Block, Safe Prompt, and redacted history.
- **Personal roadmap:** a polished signed Mac application built from the validated competition experience and a Windows release planned for August 2026.
- **Pro roadmap:** production-grade prevention, signed updates, professional workflows, and support.
- **Enterprise:** multi-agent and multi-user governance, centrally managed redacted policies, organization reporting, SSO/RBAC, and optional redacted metadata synchronization.

PonoLens Personal Edition is open source under the Apache License 2.0. The license permits use, modification, and distribution subject to its terms and does not grant trademark rights.

The enterprise direction preserves the product promise: raw protected values remain local unless an organization deliberately deploys an approved architecture that says otherwise.
