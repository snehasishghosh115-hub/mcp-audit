export const KNOWN_MCP_PACKAGES = [
  '@modelcontextprotocol/server-filesystem',
  '@modelcontextprotocol/server-github',
  '@modelcontextprotocol/server-git',
  '@modelcontextprotocol/server-memory',
  '@modelcontextprotocol/server-fetch',
  '@modelcontextprotocol/server-brave-search',
  '@modelcontextprotocol/server-postgres',
  '@modelcontextprotocol/server-sqlite',
  '@modelcontextprotocol/server-google-maps',
  '@modelcontextprotocol/server-slack',
  '@modelcontextprotocol/server-aws',
  '@modelcontextprotocol/server-azure',
  '@modelcontextprotocol/server-kubernetes',
  '@modelcontextprotocol/server-docker',
  '@modelcontextprotocol/server-terraform',
  '@modelcontextprotocol/server-gcp',
  '@modelcontextprotocol/server-jira',
  '@modelcontextprotocol/server-notion',
  '@modelcontextprotocol/server-linear',
  '@modelcontextprotocol/server-graphql',
  '@modelcontextprotocol/server-rest',
  '@modelcontextprotocol/server-grpc',
  '@modelcontextprotocol/server-kafka',
  '@modelcontextprotocol/server-redis',
  '@modelcontextprotocol/server-mongodb',
  '@modelcontextprotocol/server-elasticsearch',
  '@modelcontextprotocol/server-prometheus',
  '@modelcontextprotocol/server-grafana',
  '@modelcontextprotocol/server-datadog',
  '@modelcontextprotocol/server-newrelic',
  '@modelcontextprotocol/server-sentry',
  '@modelcontextprotocol/server-pagerduty',
  '@modelcontextprotocol/server-opsgenie',
  '@modelcontextprotocol/server-victorops',
  '@modelcontextprotocol/server-xmatters',
  'mcp-server-filesystem',
  'mcp-server-github',
  'mcp-server-git',
  'mcp-server-memory',
  'mcp-server-fetch',
  'mcp-server-brave-search',
  'mcp-server-postgres',
  'mcp-server-sqlite',
  'mcp-server-google-maps',
  'mcp-server-slack',
  'mcp-server-aws',
  'mcp-server-azure',
  'mcp-server-kubernetes',
  'mcp-server-docker',
  'mcp-server-terraform',
  'mcp-server-gcp',
  'mcp-server-jira',
  'mcp-server-notion',
  'mcp-server-linear',
  'mcp-server-graphql',
  'mcp-server-rest',
  'mcp-server-grpc',
  'mcp-server-kafka',
  'mcp-server-redis',
  'mcp-server-mongodb',
  'mcp-server-elasticsearch',
  'mcp-server-prometheus',
  'mcp-server-grafana',
  'mcp-server-datadog',
  'mcp-server-newrelic',
  'mcp-server-sentry',
  'mcp-server-pagerduty',
  'mcp-server-opsgenie',
  'mcp-server-victorops',
  'mcp-server-xmatters',
];

export function isKnownPackage(name: string): boolean {
  const normalized = name.toLowerCase().replace(/^@[^/]+\//, '');
  return KNOWN_MCP_PACKAGES.some(p => p.toLowerCase().replace(/^@[^/]+\//, '') === normalized);
}

function levenshtein(a: string, b: string): number {
  const rows = b.length + 1;
  const cols = a.length + 1;
  // Use a flat array for better TypeScript support
  const matrix = new Array(rows * cols).fill(0);
  const idx = (r: number, c: number) => r * cols + c;

  for (let i = 0; i < rows; i++) {
    matrix[idx(i, 0)] = i;
  }
  for (let j = 0; j < cols; j++) {
    matrix[idx(0, j)] = j;
  }
  for (let i = 1; i < rows; i++) {
    for (let j = 1; j < cols; j++) {
      if (b.charAt(i - 1) === a.charAt(j - 1)) {
        matrix[idx(i, j)] = matrix[idx(i - 1, j - 1)];
      } else {
        matrix[idx(i, j)] = Math.min(
          matrix[idx(i - 1, j - 1)] + 1,
          matrix[idx(i, j - 1)] + 1,
          matrix[idx(i - 1, j)] + 1
        );
      }
    }
  }
  return matrix[idx(b.length, a.length)];
}

export function findTyposquat(name: string, trustedPackages: string[]): string | null {
  const normalized = name.toLowerCase().replace(/^@[^/]+\//, '');

  // Check if it's already a known package
  if (isKnownPackage(name)) return null;

  // Check if it's trusted
  if (trustedPackages.some(tp => name.startsWith(tp))) return null;

  // Check Levenshtein distance 1-2 against known packages
  for (const known of KNOWN_MCP_PACKAGES) {
    const knownNormalized = known.toLowerCase().replace(/^@[^/]+\//, '');
    const dist = levenshtein(normalized, knownNormalized);
    if (dist >= 1 && dist <= 2) {
      return known;
    }
  }

  return null;
}
