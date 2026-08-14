import test from 'node:test';
import assert from 'node:assert/strict';
import { formatReview, reviewConfigChange } from '../lib/review.js';

const byRule = (report, ruleId) => report.findings.find((item) => item.ruleId === ruleId);

test('accepts an unchanged configuration', () => {
  const config = {
    mcpServers: {
      notes: { command: 'node', args: ['server.js'], env: { DATA_ROOT: '${DATA_ROOT}' } }
    }
  };
  const report = reviewConfigChange(config, config);

  assert.equal(report.changes.length, 0);
  assert.equal(report.findings.length, 0);
  assert.equal(report.approved, true);
});

test('flags an added server for explicit review', () => {
  const report = reviewConfigChange({ mcpServers: {} }, {
    mcpServers: { files: { command: 'node', args: ['server.js'] } }
  });

  assert.equal(byRule(report, 'server-added')?.severity, 'high');
  assert.equal(report.approved, false);
});

test('does not expose secret values when a secret setting changes', () => {
  const report = reviewConfigChange({
    mcpServers: { remote: { command: 'node', env: { API_KEY: 'old-secret' } } }
  }, {
    mcpServers: { remote: { command: 'node', env: { API_KEY: 'new-secret' } } }
  });

  assert.equal(byRule(report, 'secret-setting-changed')?.severity, 'high');
  assert.doesNotMatch(formatReview(report), /old-secret|new-secret/);
});

test('flags a HTTPS to HTTP transport downgrade as critical', () => {
  const report = reviewConfigChange({
    mcpServers: { remote: { url: 'https://api.example.test/mcp' } }
  }, {
    mcpServers: { remote: { url: 'http://api.example.test/mcp' } }
  });

  assert.equal(byRule(report, 'url-transport-downgrade')?.severity, 'critical');
});

test('flags a public endpoint changed to a private-network target', () => {
  const report = reviewConfigChange({
    mcpServers: { remote: { url: 'https://api.example.test/mcp' } }
  }, {
    mcpServers: { remote: { url: 'https://127.0.0.1:3000/mcp' } }
  });

  assert.equal(byRule(report, 'url-private-network-target')?.severity, 'high');
  assert.equal(byRule(report, 'url-origin-changed')?.severity, 'high');
});

test('flags newly introduced shell evaluation and permission bypasses', () => {
  const report = reviewConfigChange({
    mcpServers: { local: { command: 'node', args: ['server.js'] } }
  }, {
    mcpServers: { local: { command: 'bash', args: ['-c', 'server --dangerously-skip-permissions'] } }
  });

  assert.equal(byRule(report, 'command-changed')?.severity, 'high');
  assert.equal(byRule(report, 'shell-evaluation-introduced')?.severity, 'high');
  assert.equal(byRule(report, 'permission-bypass-introduced')?.severity, 'high');
});

test('flags changed permission declarations', () => {
  const report = reviewConfigChange({
    mcpServers: { local: { command: 'node', permissions: ['read'] } }
  }, {
    mcpServers: { local: { command: 'node', permissions: ['read', 'write'] } }
  });

  assert.equal(byRule(report, 'permission-scope-changed')?.severity, 'high');
});
