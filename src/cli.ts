import { parseArgs } from 'node:util';

const VERSION = '0.0.1';

function printVersion(): void {
  console.log(`mcp-audit ${VERSION}`);
}

function printHelp(): void {
  console.log(`
Usage: mcp-audit [command] [options]

Commands
  scan [paths...]     Scan MCP configs (default command). No paths = auto-discover.
  rules               List all rules (id, severity, title).
  explain <ruleId>    Print rule documentation.
  init                Create a starter .mcp-audit.json in cwd.

Global options
  -h, --help          Show help
  -v, --version       Show version
`);
}

function main(): void {
  const { values, positionals } = parseArgs({
    args: process.argv.slice(2),
    options: {
      help: { type: 'boolean', short: 'h' },
      version: { type: 'boolean', short: 'v' },
    },
    allowPositionals: true,
  });

  if (values.help) {
    printHelp();
    process.exit(0);
  }

  if (values.version) {
    printVersion();
    process.exit(0);
  }

  const command = positionals[0] ?? 'scan';

  switch (command) {
    case 'scan': {
      console.error('scan command not yet implemented');
      process.exit(2);
    }
    case 'rules': {
      console.error('rules command not yet implemented');
      process.exit(2);
    }
    case 'explain': {
      console.error('explain command not yet implemented');
      process.exit(2);
    }
    case 'init': {
      console.error('init command not yet implemented');
      process.exit(2);
    }
    default: {
      console.error(`Unknown command: ${command}`);
      printHelp();
      process.exit(2);
    }
  }
}

main();
