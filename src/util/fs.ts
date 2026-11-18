import { readFileSync, existsSync, statSync } from 'node:fs';
import { join, resolve } from 'node:path';

export function readFileSafe(path: string): string | null {
  try {
    return readFileSync(path, 'utf-8');
  } catch {
    return null;
  }
}

export function fileExists(path: string): boolean {
  try {
    return existsSync(path);
  } catch {
    return false;
  }
}

export function getFileMode(path: string): number | null {
  try {
    return statSync(path).mode;
  } catch {
    return null;
  }
}

export function isWorldOrGroupReadable(path: string): boolean {
  const mode = getFileMode(path);
  if (mode === null) return false;
  return (mode & 0o044) !== 0;
}

export function findUp(names: string[], from: string): string | null {
  let current = resolve(from);
  while (true) {
    for (const name of names) {
      const candidate = join(current, name);
      if (existsSync(candidate)) {
        return candidate;
      }
    }
    const parent = join(current, '..');
    if (parent === current) break;
    current = parent;
  }
  return null;
}
