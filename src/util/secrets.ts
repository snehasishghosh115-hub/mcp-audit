const SECRET_PATTERNS: Array<{ name: string; regex: RegExp }> = [
  { name: 'AWS Access Key', regex: /AKIA[0-9A-Z]{16}/ },
  { name: 'GitHub Token', regex: /gh[pousr]_[A-Za-z0-9]{36,}/ },
  { name: 'GitHub PAT', regex: /github_pat_[A-Za-z0-9_]{82}/ },
  { name: 'Slack Token', regex: /xox[baprs]-[A-Za-z0-9-]+/ },
  { name: 'Anthropic Key', regex: /sk-ant-[A-Za-z0-9_-]{20,}/ },
  { name: 'OpenAI Key', regex: /sk-[A-Za-z0-9_-]{20,}/ },
  { name: 'Stripe Key', regex: /sk_live_[A-Za-z0-9]{24,}/ },
  { name: 'Google API Key', regex: /AIza[0-9A-Za-z_-]{35}/ },
  { name: 'PEM Private Key', regex: /-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----/ },
  { name: 'JWT', regex: /eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+/ },
  { name: 'Bearer Token', regex: /Bearer\s+[A-Za-z0-9_-]{20,}/ },
];

const ENV_REF_PATTERNS = [
  /\$\{[A-Z_][A-Z0-9_]*\}/, // ${VAR}
  /\$[A-Z_][A-Z0-9_]*/, // $VAR
  /\$\{env:[A-Z_][A-Z0-9_]*\}/, // ${env:VAR}
  /\$\{input:[a-zA-Z0-9_-]+\}/, // ${input:id}
  /%[A-Z_][A-Z0-9_]*%/, // %VAR%
];

const PLACEHOLDER_PATTERNS = [
  /^your-/i,
  /^<.*>$/,
  /^xxx+$/i,
  /^changeme$/i,
  /^example$/i,
  /^test$/i,
  /^dummy$/i,
  /^placeholder$/i,
];

const KEY_NAME_PATTERN = /(secret|token|password|passwd|api[_-]?key|auth|credential)/i;

export function isEnvReference(value: string): boolean {
  return ENV_REF_PATTERNS.some(re => re.test(value));
}

export function isPlaceholder(value: string): boolean {
  return PLACEHOLDER_PATTERNS.some(re => re.test(value));
}

export function shannonEntropy(str: string): number {
  const freq = new Map<string, number>();
  for (const char of str) {
    freq.set(char, (freq.get(char) ?? 0) + 1);
  }
  let entropy = 0;
  const len = str.length;
  for (const count of freq.values()) {
    const p = count / len;
    entropy -= p * Math.log2(p);
  }
  return entropy;
}

export function detectSecret(key: string, value: string): { name: string; match: string } | null {
  if (isEnvReference(value)) return null;
  if (value.length < 8) return null;

  for (const { name, regex } of SECRET_PATTERNS) {
    const match = value.match(regex);
    if (match) {
      return { name, match: match[0] };
    }
  }

  if (KEY_NAME_PATTERN.test(key) && value.length >= 12) {
    const entropy = shannonEntropy(value);
    if (entropy >= 3.0 && !isPlaceholder(value)) {
      return { name: 'High-entropy key', match: value };
    }
  }

  return null;
}

export function redactSecret(value: string): string {
  if (value.length <= 4) {
    return '[REDACTED]';
  }
  return `${value.slice(0, 4)}…[REDACTED len=${value.length}]`;
}

export function scanForSecrets(
  obj: Record<string, unknown>,
  pathPrefix: string = ''
): Array<{ key: string; value: string; path: string; name: string }> {
  const findings: Array<{ key: string; value: string; path: string; name: string }> = [];

  for (const [key, value] of Object.entries(obj)) {
    const currentPath = pathPrefix ? `${pathPrefix}.${key}` : key;
    if (typeof value === 'string') {
      const detected = detectSecret(key, value);
      if (detected) {
        findings.push({ key, value, path: currentPath, name: detected.name });
      }
    } else if (Array.isArray(value)) {
      for (let i = 0; i < value.length; i++) {
        const item = value[i];
        if (typeof item === 'string') {
          const detected = detectSecret(`${key}[${i}]`, item);
          if (detected) {
            findings.push({
              key: `${key}[${i}]`,
              value: item,
              path: `${currentPath}[${i}]`,
              name: detected.name,
            });
          }
        }
      }
    } else if (value && typeof value === 'object') {
      findings.push(...scanForSecrets(value as Record<string, unknown>, currentPath));
    }
  }

  return findings;
}
