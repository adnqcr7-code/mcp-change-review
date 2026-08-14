# MCP Change Review

> A **local-first, zero-dependency CLI** for reviewing proposed changes to Model Context Protocol (MCP) configuration files before those changes are applied.

`mcp-change-review` compares a known baseline with a proposed configuration and reports security-relevant differences without printing secret values. It is designed for one concrete moment: **before an MCP configuration update becomes a command, connection, or permission your agent can use**. A new server, changed command, private-network endpoint, or broader permission declaration should receive deliberate human attention before it becomes part of an agent workflow.

## Why change review matters

MCP servers can expose tools that a model discovers and invokes, while local servers may execute with the client’s privileges. The MCP specification recommends confirmation for sensitive actions and audit logging, and its security guidance calls for explicit consent before launching a new local server command. [1] [2]

This tool does not run any server, make network requests, or print environment-variable values. It produces a deterministic report that can be used locally or in a pull-request check.

## What it detects

| Change | Example | Severity |
| --- | --- | --- |
| New server | A new `mcpServers` entry | High |
| Executable change | `node server.js` becomes another command | High |
| Shell evaluation | `bash -c`, `cmd /c`, or PowerShell command evaluation | High |
| Permission bypass | Flags that disable sandboxes or broadly expand access | High |
| Endpoint downgrade | `https://` changes to `http://` | Critical |
| Private-network endpoint | A public endpoint changes to `localhost`, `127.0.0.1`, or RFC1918 IPv4 space | High |
| Secret-like setting | API key, token, password, or credential variable changes | High, values redacted |
| Permission declaration | `permissions`, `alwaysAllow`, `capabilities`, or `allowedPaths` changes | High |
| Ordinary environment change | A non-secret environment setting changes | Medium, values redacted |

> A report without critical or high findings is a useful review signal, **not a guarantee of safety**. Still inspect server source, maintainer provenance, and expected data access.

## Quick start

Node.js 20 or newer is required. There are no runtime dependencies.

```bash
git clone https://github.com/adnqcr7-code/mcp-change-review.git
cd mcp-change-review
npm test
node bin/mcp-change-review.js baseline.json proposed.json
```

For a machine-readable report:

```bash
node bin/mcp-change-review.js baseline.json proposed.json --json
```

For a pull-request-ready report that can be pasted directly into a code review or CI comment:

```bash
node bin/mcp-change-review.js baseline.json proposed.json --markdown
```

The command exits with `0` when it detects no critical or high-risk changes, `1` when review is required, and `2` for invalid input or invocation errors.

## See the problem in one command

Imagine a configuration update that changes a local server from a direct Node.js command to `bash -c`, adds a permission-bypass flag, introduces an API key, and points a new server at `127.0.0.1`. Rather than running that update, review it first:

```bash
node bin/mcp-change-review.js \
  test/fixtures/baseline.json \
  test/fixtures/proposed-risky.json \
  --markdown
```

The resulting report identifies the changed server, categorizes the findings, and recommends the review action. It deliberately redacts the API-key value. This is the intended workflow: **review the diff before an agent can act on it**.

## Supported configuration shapes

The utility accepts either a top-level `mcpServers` object or a top-level `servers` object. It compares each server’s `command`, `args`, `env`, `url`, and common permission-declaration fields.

```json
{
  "mcpServers": {
    "local-notes": {
      "command": "node",
      "args": ["server.js"],
      "env": {
        "DATA_ROOT": "${DATA_ROOT}"
      }
    }
  }
}
```

## Development

```bash
npm run check
```

The tests use Node’s built-in test runner. Every detection rule should include a focused regression test, including a check that any secret-like value remains absent from formatted output.

## License

MIT. See [LICENSE](LICENSE).

## References

[1]: https://modelcontextprotocol.io/specification/2026-07-28/server/tools "Model Context Protocol: Server tools"
[2]: https://modelcontextprotocol.io/specification/draft/basic/security_best_practices "Model Context Protocol: Security best practices"
