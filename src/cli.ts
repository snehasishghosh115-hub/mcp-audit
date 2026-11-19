import { parseArgs } from 'node:util';
import { scan } from './index.js';
import { printTextReport } from './reporters/text.js';
import { printJsonReport } from './reporters/json.js';
import { printSarifReport } from './reporters/sarif.js';
import { createDefaultConfig } from './config/index.js';
import { writeFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { VERSION } from './version.js';

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

scan options
  -f, --format <fmt>        text | json | sarif           (default: text)
  -o, --output <file>       Write report to file instead of stdout
      --fail-on <sev>       critical|high|medium|low|info|none   (default: high)
      --min-severity <sev>  Hide findings below this level       (default: info)
      --client <id,...>     Limit discovery: claude-desktop,claude-code,cursor,vscode,windsurf
      --no-user             Skip user-level configs (CI friendly)
      --no-project          Skip project-level configs
      --config <file>       Path to .mcp-audit.json
      --rule <id,...>       Only run these rules
      --skip-rule <id,...>  Skip these rules
      --tools <file>        Audit a saved tools/list JSON file
      --introspect          Start/connect to servers to fetch live tool definitions (RUNS CODE)
  -y, --yes                 Skip --introspect confirmation
      --strict              Treat parse/read errors as failures (exit 1)
`);
}

async function main(): Promise<void> {
  const { values, positionals } = parseArgs({
    args: process.argv.slice(2),
    options: {
      help: { type: 'boolean', short: 'h' },
      version: { type: 'boolean', short: 'v' },
      format: { type: 'string', short: 'f', default: 'text' },
      output: { type: 'string', short: 'o' },
      'fail-on': { type: 'string', default: 'high' },
      'min-severity': { type: 'string', default: 'info' },
      client: { type: 'string' },
      'no-user': { type: 'boolean' },
      'no-project': { type: 'boolean' },
      config: { type: 'string' },
      rule: { type: 'string' },
      'skip-rule': { type: 'string' },
      tools: { type: 'string' },
      introspect: { type: 'boolean' },
      yes: { type: 'boolean', short: 'y' },
      strict: { type: 'boolean' },
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
      const clientIds = values.client ? values.client.split(',') : undefined;
      const ruleIds = values.rule ? values.rule.split(',') : undefined;
      const skipRuleIds = values['skip-rule'] ? values['skip-rule'].split(',') : undefined;

      // Handle introspection confirmation
      if (values.introspect && !values.yes) {
        console.error(
          'WARNING: --introspect will START the configured MCP servers to fetch live tool definitions.'
        );
        console.error('This executes code from your configuration. Only use on configs you trust.');
        console.error('Continue? [y/N] ');

        const stdin = process.stdin;
        stdin.setRawMode(true);
        stdin.resume();
        stdin.setEncoding('utf-8');

        await new Promise<void>(resolve => {
          const onData = (data: string) => {
            stdin.removeListener('data', onData);
            stdin.setRawMode(false);
            stdin.pause();
            if (data.toLowerCase().trim() === 'y') {
              resolve();
            } else {
              console.error('Aborted.');
              process.exit(0);
            }
          };
          stdin.on('data', onData);
        });
      }

      const result = await scan({
        paths: positionals.slice(1).length > 0 ? positionals.slice(1) : undefined,
        failOn: values['fail-on'],
        minSeverity: values['min-severity'],
        clientIds,
        noUser: values['no-user'],
        noProject: values['no-project'],
        configPath: values.config,
        ruleIds,
        skipRuleIds,
        strict: values.strict,
        toolsPath: values.tools,
        introspect: values.introspect,
      });

      let output: string;
      switch (values.format) {
        case 'json':
          output = printJsonReport(result);
          break;
        case 'sarif':
          output = printSarifReport(result);
          break;
        case 'text':
        default:
          output = printTextReport(result);
          break;
      }

      if (values.output) {
        writeFileSync(resolve(values.output), output, 'utf-8');
      } else {
        process.stdout.write(output);
      }

      const severityOrder = { critical: 0, high: 1, medium: 2, low: 3, info: 4, none: 5 };
      const failOnLevel = severityOrder[values['fail-on'] as keyof typeof severityOrder] ?? 1;
      const hasFailFindings = result.findings.some(f => severityOrder[f.severity] <= failOnLevel);

      process.exit(hasFailFindings ? 1 : 0);
    }

    case 'rules': {
      const { ALL_RULES } = await import('./rules/index.js');
      for (const rule of ALL_RULES) {
        console.log(`${rule.id}  ${rule.severity.toUpperCase()}  ${rule.title}`);
      }
      process.exit(0);
    }

    case 'explain': {
      const ruleId = positionals[1];
      if (!ruleId) {
        console.error('Rule ID required');
        process.exit(2);
      }
      const { ALL_RULES } = await import('./rules/index.js');
      const rule = ALL_RULES.find(r => r.id === ruleId);
      if (!rule) {
        console.error(`Rule not found: ${ruleId}`);
        process.exit(2);
      }
      console.log(rule.docs);
      process.exit(0);
    }

    case 'init': {
      const configPath = resolve(values.config ?? '.mcp-audit.json');
      const content = createDefaultConfig();
      writeFileSync(configPath, content, 'utf-8');
      console.log(`Created ${configPath}`);
      process.exit(0);
    }

    default: {
      console.error(`Unknown command: ${command}`);
      printHelp();
      process.exit(2);
    }
  }
}

main().catch(e => {
  console.error(`Fatal error: ${e instanceof Error ? e.message : String(e)}`);
  process.exit(2);
});
