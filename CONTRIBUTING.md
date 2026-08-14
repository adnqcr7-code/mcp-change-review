# Contributing to MCP Change Review

Thank you for helping improve a small tool with a narrow promise: **review MCP configuration changes without running servers, making network requests, or exposing secret values**.

## Good contribution areas

Useful contributions improve configuration-shape support, add well-scoped detection rules, clarify a reviewer-facing report, or make the command easier to use in a pull-request workflow. Please keep each pull request focused on one problem.

| Change type | Expected evidence |
| --- | --- |
| New or modified detection rule | A regression test showing the rule triggers at the right severity. |
| Output or reporting change | A test that preserves redaction and the intended exit-code behavior. |
| Configuration-shape support | A fixture that demonstrates the supported before-and-after form. |
| Documentation change | A command that users can run as written, without a hidden prerequisite. |

## Development

Node.js 20 or newer is required. The project has no runtime dependencies.

```bash
npm run check
```

This runs syntax checks and the Node.js test suite. The public CLI supports normal text, `--json`, and pull-request-ready `--markdown` output.

## Safety boundaries

Do not add behavior that executes a configured command, contacts a configured endpoint, prints environment-variable values, or treats a report as a guarantee of safety. The tool is a deterministic change-review aid; a human still needs to inspect source provenance, expected privileges, and data-access boundaries.

When filing or reviewing an issue, avoid pasting real credentials. Use placeholders such as `${API_KEY}` or `REDACTED` instead.

## Pull requests

Explain the configuration change being reviewed, the expected report behavior, and the tests that cover it. Small, reviewable pull requests are preferred.
