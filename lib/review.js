const SECRET_NAME = /(api[_-]?key|token|secret|password|credential|private[_-]?key)/i;
const HIGH_RISK_ENV = /^(?:NODE_OPTIONS|PYTHONINSPECT|BASH_ENV|ENV)$/i;
const SHELL_COMMAND = /^(?:sh|bash|zsh|fish|cmd(?:\.exe)?|powershell(?:\.exe)?|pwsh(?:\.exe)?)$/i;
const DANGEROUS_ARGUMENT = /(?:--dangerously-skip-permissions|--no-sandbox|--disable-web-security|--allow-all|--allow-net|--allow-write|--allow-fs-write)/i;

function finding({ severity, ruleId, server, message, recommendation }) {
  return { severity, ruleId, server, message, recommendation };
}

function stable(value) {
  if (Array.isArray(value)) return `[${value.map(stable).join(',')}]`;
  if (value && typeof value === 'object') {
    return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${stable(value[key])}`).join(',')}}`;
  }
  return JSON.stringify(value);
}

function equal(left, right) {
  return stable(left) === stable(right);
}

function extractServers(config) {
  if (!config || typeof config !== 'object' || Array.isArray(config)) return {};
  const servers = config.mcpServers ?? config.servers;
  return servers && typeof servers === 'object' && !Array.isArray(servers) ? servers : {};
}

function isPrivateOrLoopbackHostname(hostname) {
  const host = hostname.toLowerCase().replace(/^\[|\]$/g, '');
  if (host === 'localhost' || host === '::1' || host.endsWith('.local')) return true;
  if (/^127\./.test(host) || /^10\./.test(host) || /^192\.168\./.test(host)) return true;
  const match = host.match(/^172\.(\d+)\./);
  return Boolean(match && Number(match[1]) >= 16 && Number(match[1]) <= 31);
}

function parseUrl(value) {
  if (typeof value !== 'string' || value.trim() === '') return null;
  try {
    return new URL(value);
  } catch {
    return null;
  }
}

function includesShellEvaluation(config) {
  const command = String(config.command ?? '');
  const args = Array.isArray(config.args) ? config.args.map(String) : [];
  return SHELL_COMMAND.test(command) && args.some((arg) => /^(-c|\/c|-command|-encodedcommand)$/i.test(arg));
}

function includesDangerousArgument(config) {
  return [config.command, ...(Array.isArray(config.args) ? config.args : [])].filter(Boolean).map(String).join(' ').match(DANGEROUS_ARGUMENT);
}

function summarizeChange(before, after) {
  if (before === undefined) return 'added';
  if (after === undefined) return 'removed';
  return 'modified';
}

function reviewEnv(server, before = {}, after = {}) {
  const findings = [];
  const beforeEnv = before && typeof before === 'object' && !Array.isArray(before) ? before : {};
  const afterEnv = after && typeof after === 'object' && !Array.isArray(after) ? after : {};
  const keys = new Set([...Object.keys(beforeEnv), ...Object.keys(afterEnv)]);

  for (const key of [...keys].sort()) {
    if (equal(beforeEnv[key], afterEnv[key])) continue;
    const change = summarizeChange(beforeEnv[key], afterEnv[key]);
    if (HIGH_RISK_ENV.test(key)) {
      findings.push(finding({
        severity: 'high',
        ruleId: 'env-loader-hook-changed',
        server,
        message: `${key} was ${change}; it can inject code into a child process.`,
        recommendation: 'Require an explicit, independent review of this environment variable before enabling the server.'
      }));
    } else if (SECRET_NAME.test(key)) {
      findings.push(finding({
        severity: 'high',
        ruleId: 'secret-setting-changed',
        server,
        message: `${key} was ${change}. Its value is intentionally redacted.`,
        recommendation: 'Verify the credential source and scope; rotate it if an unintended value may have been committed or shared.'
      }));
    } else {
      findings.push(finding({
        severity: 'medium',
        ruleId: 'environment-changed',
        server,
        message: `${key} was ${change}. Values are not displayed by this tool.`,
        recommendation: 'Confirm that the new environment setting is required and does not expand the server’s access unexpectedly.'
      }));
    }
  }
  return findings;
}

function reviewUrl(server, beforeValue, afterValue) {
  const findings = [];
  if (equal(beforeValue, afterValue)) return findings;
  const before = parseUrl(beforeValue);
  const after = parseUrl(afterValue);

  if (afterValue !== undefined && !after) {
    findings.push(finding({
      severity: 'medium',
      ruleId: 'url-invalid',
      server,
      message: 'The URL was added or changed but could not be parsed as an absolute URL.',
      recommendation: 'Use a complete URL and verify the target before enabling the server.'
    }));
    return findings;
  }

  if (before && after && before.protocol === 'https:' && after.protocol === 'http:') {
    findings.push(finding({
      severity: 'critical',
      ruleId: 'url-transport-downgrade',
      server,
      message: `The endpoint changed from HTTPS to HTTP (${before.host} → ${after.host}).`,
      recommendation: 'Keep HTTPS unless there is a documented, narrowly scoped development exception.'
    }));
  }

  if (after && isPrivateOrLoopbackHostname(after.hostname) && (!before || !isPrivateOrLoopbackHostname(before.hostname))) {
    findings.push(finding({
      severity: 'high',
      ruleId: 'url-private-network-target',
      server,
      message: `The endpoint now targets a loopback or private-network host (${after.host}).`,
      recommendation: 'Confirm the target is intentional, restrict network access, and do not follow unreviewed redirects.'
    }));
  }

  if ((before?.origin ?? '') !== (after?.origin ?? '')) {
    findings.push(finding({
      severity: 'high',
      ruleId: 'url-origin-changed',
      server,
      message: `The remote server origin changed from ${before?.origin ?? 'none'} to ${after?.origin ?? 'none'}.`,
      recommendation: 'Review the new host, transport, authorization expectations, and data-access scope before enabling it.'
    }));
  }

  return findings;
}

function reviewCommand(server, before = {}, after = {}) {
  const findings = [];
  const commandChanged = !equal(before.command, after.command);
  const argsChanged = !equal(before.args, after.args);

  if (commandChanged && after.command !== undefined) {
    findings.push(finding({
      severity: 'high',
      ruleId: 'command-changed',
      server,
      message: 'The executable command changed.',
      recommendation: 'Inspect the exact executable, installation source, and expected local privileges before enabling it.'
    }));
  }

  if (argsChanged && after.args !== undefined) {
    findings.push(finding({
      severity: 'medium',
      ruleId: 'arguments-changed',
      server,
      message: 'The command arguments changed.',
      recommendation: 'Review the complete argument list for changes to file-system, network, or permission scope.'
    }));
  }

  if (!includesShellEvaluation(before) && includesShellEvaluation(after)) {
    findings.push(finding({
      severity: 'high',
      ruleId: 'shell-evaluation-introduced',
      server,
      message: 'The updated configuration introduces shell evaluation.',
      recommendation: 'Call the intended executable directly rather than evaluating a dynamic shell command.'
    }));
  }

  if (!includesDangerousArgument(before) && includesDangerousArgument(after)) {
    findings.push(finding({
      severity: 'high',
      ruleId: 'permission-bypass-introduced',
      server,
      message: 'The updated configuration introduces a flag associated with bypassing security controls or broadening permissions.',
      recommendation: 'Remove the bypass flag and grant only the minimum capabilities required.'
    }));
  }

  return findings;
}

function reviewPermissionFields(server, before = {}, after = {}) {
  const findings = [];
  for (const field of ['permissions', 'alwaysAllow', 'capabilities', 'allowedPaths']) {
    if (!equal(before[field], after[field]) && after[field] !== undefined) {
      findings.push(finding({
        severity: 'high',
        ruleId: 'permission-scope-changed',
        server,
        message: `The ${field} setting changed.`,
        recommendation: 'Confirm each newly granted permission or path is necessary for the server’s intended use.'
      }));
    }
  }
  return findings;
}

function reviewServer(name, before, after) {
  const findings = [];
  if (before === undefined && after !== undefined) {
    findings.push(finding({
      severity: 'high',
      ruleId: 'server-added',
      server: name,
      message: 'A new MCP server entry was added.',
      recommendation: 'Review its source, command or endpoint, permissions, and data-access boundaries before enabling it.'
    }));
  }
  if (before !== undefined && after === undefined) {
    findings.push(finding({
      severity: 'low',
      ruleId: 'server-removed',
      server: name,
      message: 'An MCP server entry was removed.',
      recommendation: 'Confirm this does not disrupt a required workflow or remove an expected security control.'
    }));
    return findings;
  }

  const prior = before ?? {};
  const next = after ?? {};
  if (!next || typeof next !== 'object' || Array.isArray(next)) {
    findings.push(finding({
      severity: 'medium',
      ruleId: 'server-invalid-shape',
      server: name,
      message: 'The new server definition is not a JSON object.',
      recommendation: 'Use a reviewed object with an explicit command or URL transport.'
    }));
    return findings;
  }

  findings.push(...reviewCommand(name, prior, next));
  findings.push(...reviewUrl(name, prior.url, next.url));
  findings.push(...reviewEnv(name, prior.env, next.env));
  findings.push(...reviewPermissionFields(name, prior, next));
  return findings;
}

export function reviewConfigChange(beforeConfig, afterConfig) {
  const before = extractServers(beforeConfig);
  const after = extractServers(afterConfig);
  const names = new Set([...Object.keys(before), ...Object.keys(after)]);
  const findings = [];
  const changes = [];

  for (const name of [...names].sort()) {
    if (equal(before[name], after[name])) continue;
    const kind = summarizeChange(before[name], after[name]);
    changes.push({ server: name, kind });
    findings.push(...reviewServer(name, before[name], after[name]));
  }

  const severityCounts = { critical: 0, high: 0, medium: 0, low: 0 };
  for (const item of findings) severityCounts[item.severity] += 1;

  return {
    beforeServerCount: Object.keys(before).length,
    afterServerCount: Object.keys(after).length,
    changes,
    findings,
    severityCounts,
    approved: severityCounts.critical === 0 && severityCounts.high === 0
  };
}

export function formatReview(report) {
  const lines = [
    `Compared ${report.beforeServerCount} baseline server${report.beforeServerCount === 1 ? '' : 's'} with ${report.afterServerCount} proposed server${report.afterServerCount === 1 ? '' : 's'}.`,
    `Changes: ${report.changes.length}. Findings: ${report.severityCounts.critical} critical, ${report.severityCounts.high} high, ${report.severityCounts.medium} medium, ${report.severityCounts.low} low.`
  ];

  for (const change of report.changes) lines.push(`- ${change.server}: ${change.kind}`);
  for (const item of report.findings) {
    lines.push(`\n[${item.severity.toUpperCase()}] ${item.ruleId} — ${item.server}`);
    lines.push(`  ${item.message}`);
    lines.push(`  Recommendation: ${item.recommendation}`);
  }

  lines.push(`\nResult: ${report.approved ? 'NO CRITICAL OR HIGH-RISK CHANGES DETECTED' : 'REVIEW REQUIRED BEFORE APPLYING THE CHANGE'}`);
  return lines.join('\n');
}
