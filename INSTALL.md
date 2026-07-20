# Installing the PonoLens competition preview

The current competition edition is a script-installed local service with a browser dashboard. It is not a packaged native Mac application. A polished PonoLens Personal Mac edition is planned after the competition.

## Recommended installation

From a committed checkout, run:

```bash
./install.sh
```

The installer copies the committed source to `~/.ponolens/application`, starts the loopback-only service, and opens the dashboard. It does not silently install agent hooks; enable each integration from the dashboard.

After the repository and download endpoint are public, the intended marketing command is:

```bash
curl -fsSL https://get.ponolens.com/install.sh | sh
```

While the GitHub repository is private, clone it with an authorized account and run the script from the checkout. The installer defaults to `https://github.com/tholmgren/ponolens-agent-monitor-personal-edition.git`; `PONOLENS_REPOSITORY_URL` can override that source. The script requires Git and Node.js; it does not download or mount a DMG.

## Requirements

- Node.js 22.5 or newer
- Git
- A supported harness: Cursor, Claude Code CLI, Codex, or Windsurf
- A local browser for the dashboard
- Optional: Ollama for local Safe Prompt generation

Confirm Node.js:

```bash
node --version
```

## Start PonoLens

From the repository directory:

```bash
npm start
```

No `npm install` step is currently required because the MVP has no third-party runtime dependencies.

Open [http://127.0.0.1:4317](http://127.0.0.1:4317). Keep this process running while using monitored harnesses. PonoLens writes its local database to `~/.ponolens/ponolens.db` unless `PONOLENS_DATA_DIR` is set.

### Runtime configuration

PonoLens supports these environment variables:

| Variable | Purpose | Default |
|---|---|---|
| `PORT` | Dashboard and collector listening port | `4317` |
| `PONOLENS_COLLECTOR_URL` | Explicit base URL embedded into newly generated Cursor/Windsurf bridges | Address derived from the active host and `PORT` |
| `PONOLENS_DATA_DIR` | SQLite database and generated bridge directory | `~/.ponolens` |
| `PONOLENS_OLLAMA_URL` | Ollama upstream used by Safe Prompt | `http://127.0.0.1:11434` |
| `OPENAI_API_KEY` | Optional OpenAI API credential; the environment takes priority over the macOS credential entry | Not set |

Runtime defaults, provider definitions, and harness metadata are maintained centrally in `public/product-config.js`. Existing generated bridges retain the collector address they were installed with, so reconnect an integration after changing `PORT` or `PONOLENS_COLLECTOR_URL`.

Use **Pono Guard** for the common category switches. **Report Only** is the stable default. **Redact** and **Block** are Experimental: they operate only when supported Cursor, Claude Code CLI, or Windsurf/Devin pre-submit hooks run, and they are not universal prevention guarantees. Redact attempts to stop a sensitive original and provides a sanitized prompt for review and resubmission. Use **Advanced Guard** to set the same actions per category, trusted destinations, thresholds, dictionaries, and constrained regular-expression rules. Settings save automatically.

**Agent command monitoring · Experimental** is a separate Pono Guard switch and is off by default. When enabled, it creates report-only receipts for commands exposed by supported hooks. Sensitive command previews are redacted before SQLite storage, shown in orange, and included in **Needs Review**. PonoLens does not capture command output or commands from unrelated Terminal windows.

## Connect an agent from the dashboard

1. Open **Agent status** and select **Scan agents**.
2. Confirm the expected CLI/application is detected.
3. Select **Enable system-wide** for the agent you want to monitor.
4. Fully quit and reopen that agent so it reloads its hook configuration.
5. Return to PonoLens and select **Test**.
6. Submit a harmless test prompt and confirm a new event appears under **What your agents are doing**.

Each harness appears as a collapsed status accordion. Its header shows the current monitoring state, setup scope, and latest event time. Expand it to review installation, hook configuration, current reachability, prompt coverage, stable Report capability, Experimental Redact/Block capability, known limitations, and testing controls. The selected accordion remains open during live dashboard refreshes.

Command coverage differs by harness:

- **Codex:** covered task hooks and observable local-session tool calls; no unrelated Terminal visibility.
- **Claude Code CLI:** command tools exposed through `PreToolUse`; Claude Desktop remains unsupported.
- **Cursor:** command payloads exposed through configured tool hooks; payload detail depends on Cursor and the tool involved.
- **Windsurf/Devin:** native pre-command and compatible pre-tool events; bypassed hooks remain invisible.

Shell aliases, expansion, nested scripts, subprocesses, and command arguments assembled after the hook may prevent PonoLens from identifying the final command or destination.

System-wide setup writes the harness's user configuration. Project-local integration files can also be used when appropriate. Review generated hook files before enabling them in sensitive environments. Newly generated Cursor and Windsurf/Devin pre-submit bridges fail closed when the PonoLens collector cannot be reached; reconnect an existing integration to regenerate its bridge after upgrading.

## Cursor

PonoLens installs Cursor prompt hooks and a PonoLens MCP entry. A compatible `beforeSubmitPrompt` event can be blocked before submission when Pono Guard is in blocking mode and the detected category is enabled.

After installation:

1. Fully quit Cursor—not just close its window.
2. Reopen Cursor and start a new chat.
3. Submit a harmless prompt, then a test prompt containing a fake identifier.
4. Verify the receipts are labeled Cursor and that an enabled protected category produces the expected warning/block decision.

Only MCP activity explicitly routed through the PonoLens gateway is covered by the MCP path. PonoLens does not claim visibility into every Cursor network request.

## Claude Code CLI

PonoLens supports Claude Code CLI hooks, including `UserPromptSubmit` for prompt blocking and `PreToolUse` for covered actions. Claude Desktop is a different product and is not supported by these hooks.

Install Claude Code using Anthropic's current official instructions, then confirm its command is available on `PATH`. In PonoLens, scan agents and enable Claude Code system-wide. Fully restart the CLI session afterward.

If PonoLens reports **Configured only**, the hook configuration exists but the Claude Code executable is not visible to the PonoLens process. Restart the terminal/app that launched PonoLens and verify the executable is on that environment's `PATH`.

## Windsurf

PonoLens uses Windsurf's native Cascade hooks. It installs `pre_user_prompt`, `pre_read_code`, `pre_write_code`, `pre_run_command`, and `pre_mcp_tool_use` entries. Windsurf can block these pre-hooks when PonoLens exits with status `2`.

The hook command uses a small bridge at `~/.ponolens/hooks/ponolens-windsurf-hook.mjs`. The bridge talks only to the configured local PonoLens collector; this avoids macOS privacy failures that can prevent Devin from reading PonoLens source files inside `Documents`.

The current official Windsurf editor documentation and installer use the **Devin Desktop** name. Depending on installer version, its macOS bundle may be `Devin.app` or `Devin Desktop.app`. PonoLens recognizes those names plus the older Windsurf application/CLI names; all use the Windsurf Cascade hook configuration described below.

User-level hooks are stored at `~/.codeium/windsurf/hooks.json`; project-level hooks are stored at `.windsurf/hooks.json`. Enable Windsurf from the PonoLens dashboard, fully quit and reopen Windsurf, then start a new Cascade chat.

PonoLens intentionally does not enable `post_cascade_response_with_transcript`: full transcript files can duplicate conversation history, source content, tool output, and other sensitive data that PonoLens does not need for prompt protection.

## Codex

PonoLens observes supported local Codex task/session records and covered task hooks. Codex side-chat prompts are not currently exposed early enough for PonoLens to block them before they reach the provider.

Enable the Codex integration in PonoLens, review/trust the hook configuration where Codex requests it, and restart the task. Use **Safe Prompt** before submitting sensitive Codex side-chat content.

An orange Codex receipt means sensitive information was detected after submission. It must not be represented as a successful block.

## Safe Prompt providers

Safe Prompt can work without an API: choose a web app, copy the tokenized prompt, paste it into the provider, then paste the reply back into PonoLens for local restoration.

### Ollama

1. Install Ollama from [ollama.com/download](https://ollama.com/download).
2. Start Ollama and install at least one model.
3. Open **Settings**, select **Ollama**, refresh installed models, and choose the default.
4. In Safe Prompt, review the tokenized version and select **Send to default LLM**.

Ollama uses its local HTTP API; no paid API key is required. Whether a model and its processing remain fully local depends on the Ollama installation and model source selected by the user.

The experimental Ollama Gateway is disabled in the current build. The native Ollama macOS chat connects directly to its local service and is not monitored by PonoLens. Detecting port `11434` proves that Ollama is running; it does not reveal, redact, or block prompt contents.

### API providers

In **Settings**, choose the provider/API option and enter your own key. PonoLens should never place API keys in prompts, audit previews, browser local storage, or source-controlled configuration. Provider terms, data retention, and regulated-data eligibility remain the user's responsibility.

## Verify the installation

```bash
npm test
```

Then verify these behaviors in the dashboard:

- A normal prompt creates a green receipt.
- A fake sensitive prompt creates an orange receipt when merely observed.
- Cursor, Claude Code CLI, or Windsurf creates a red receipt only when Experimental Block was selected and the supported pre-hook actually blocked it.
- Codex side-chat sensitive prompts are orange and recommend Safe Prompt.
- Safe Prompt replaces identifiers with tokens and restores them only after the response returns.
- Agent status distinguishes installation, hook configuration, current reachability, prompt coverage, supported Report/Redact/Block actions, limitations, and the last received event.
- Data Trail supports combined filters and exports only redacted CSV/PDF incident metadata.
- With command monitoring enabled, a normal covered command creates a report-only command receipt; a fictitious command containing an email or credential creates an orange Needs Review receipt whose stored preview is redacted.
- The **Risks explained** and **Unsafe actions stopped** home-page review panels load their matching events from the retained database rather than only the newest home-page preview.
- Settings can export a policy template without user-authored labels or raw protected values and can permanently delete local PonoLens events and settings after typed confirmation.

Use fictitious test data. Never test with real patient, client, financial, authentication, or identity information.

For product behavior and usage questions, open the dashboard's **FAQ** tab.

## Troubleshooting

### Dashboard does not update

- Confirm `npm start` is still running.
- Reload the dashboard and confirm the live collector indicator reconnects.
- Fully restart the harness after hook changes.
- Run **Scan agents** and **Test** again.

### Agent is detected but has no events

Detection only proves the executable/application exists. Confirm the integration is configured, the harness supports the relevant hook, and the current session was started after configuration.

Expand the harness accordion and check all status fields. **Installed** identifies the application or CLI. **Hook configured** confirms PonoLens configuration exists. **Currently reachable** means PonoLens is actively receiving supported activity. The capability badges describe what the integration supports when its hook runs; they do not override the listed limitations.

### A harness accordion closes during live updates

Current builds preserve the selected accordion through the two-second dashboard refresh. Reload the page to clear stale browser assets if an older build still collapses it.

### Port 4317 is already in use

Stop the existing PonoLens process or run on another port:

```bash
PORT=4318 npm start
```

Newly generated hooks use the address of the running PonoLens server. To install hooks for an explicit collector address, start PonoLens with both `PORT` and `PONOLENS_COLLECTOR_URL`, then enable the integration again. Existing generated hooks retain the address they were installed with.

```bash
PORT=4318 PONOLENS_COLLECTOR_URL=http://127.0.0.1:4318 npm start
```

### Reset test data

Prefer a separate test directory instead of deleting your normal audit database:

```bash
PONOLENS_DATA_DIR=/tmp/ponolens-test npm start
```

## Uninstalling integrations

The current dashboard focuses on installation and testing. To remove an integration, inspect the harness's user/project hook configuration and remove only PonoLens entries referencing `ponolens-hook.mjs`, `src/adapters/hook.mjs`, or the `ponolens` MCP server. Back up the configuration first and preserve unrelated hooks.

## Uninstalling the application

Run `./uninstall.sh`. It stops the competition-preview service and removes `~/.ponolens/application`. It intentionally leaves the local database and harness configurations in place. Use **Delete all local data** before uninstalling if you want the local database and policies removed, and remove harness integrations separately.

## License

PonoLens Personal Edition is available under the [Apache License 2.0](LICENSE). The license permits use, modification, and distribution subject to its terms and does not grant trademark rights.
