#!/usr/bin/env node

import { readFile } from 'node:fs/promises';
import path from 'node:path';
import process from 'node:process';
import { formatReview, formatReviewMarkdown, reviewConfigChange } from '../lib/review.js';

const usage = `mcp-change-review <baseline.json> <proposed.json> [--json | --markdown]\n\nCompare two MCP configuration files and highlight security-relevant changes.\nSecret values are never printed.\n\nOptions:\n  --json       Print the full machine-readable report.\n  --markdown   Print a pull-request-ready GitHub Markdown report.\n  --help       Show this help text.\n\nExit codes:\n  0            No critical or high-risk changes detected.\n  1            Critical or high-risk changes require review.\n  2            Invalid invocation or unreadable JSON input.\n`;

function fail(message) {
  process.stderr.write(`Error: ${message}\n\n${usage}`);
  process.exitCode = 2;
}

const args = process.argv.slice(2);
if (args.includes('--help') || args.includes('-h')) {
  process.stdout.write(usage);
} else {
  const jsonOutput = args.includes('--json');
  const markdownOutput = args.includes('--markdown');
  const positional = args.filter((arg) => arg !== '--json' && arg !== '--markdown');

  if (jsonOutput && markdownOutput) {
    fail('Use either --json or --markdown, not both.');
  } else if (positional.length !== 2) {
    fail('Provide a baseline configuration and a proposed configuration.');
  } else {
    try {
      const [baselineText, proposedText] = await Promise.all(
        positional.map((input) => readFile(path.resolve(input), 'utf8'))
      );
      const report = reviewConfigChange(JSON.parse(baselineText), JSON.parse(proposedText));
      const output = jsonOutput
        ? JSON.stringify(report, null, 2)
        : markdownOutput
          ? formatReviewMarkdown(report)
          : formatReview(report);
      process.stdout.write(`${output}\n`);
      process.exitCode = report.approved ? 0 : 1;
    } catch (error) {
      if (error instanceof SyntaxError) {
        fail(`A configuration file is not valid JSON: ${error.message}`);
      } else {
        fail(`Could not read a configuration file: ${error.message}`);
      }
    }
  }
}
