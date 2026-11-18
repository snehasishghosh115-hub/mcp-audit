import type { ParseError } from '../types.js';

export interface JsoncNode {
  type: 'object' | 'array' | 'string' | 'number' | 'boolean' | 'null';
  value: unknown;
  offset: number;
  length: number;
  children?: Map<string, JsoncNode> | JsoncNode[];
}

interface Token {
  type: string;
  value: string;
  offset: number;
  line: number;
  column: number;
}

const KEYWORDS = new Set(['true', 'false', 'null']);

function createParseError(message: string, offset: number, source: string): ParseError {
  let line = 1;
  let column = 1;
  for (let i = 0; i < offset; i++) {
    if (source[i] === '\n') {
      line++;
      column = 1;
    } else {
      column++;
    }
  }
  const error = new Error(message) as ParseError;
  error.line = line;
  error.column = column;
  return error;
}

function charAt(source: string, index: number): string {
  return index < source.length ? (source[index] as string) : '';
}

function tokenize(source: string): Token[] {
  const tokens: Token[] = [];
  let offset = 0;
  let line = 1;
  let column = 1;

  const advance = (n: number = 1) => {
    for (let i = 0; i < n; i++) {
      if (offset < source.length && source[offset] === '\n') {
        line++;
        column = 1;
      } else {
        column++;
      }
      offset++;
    }
  };

  const peek = (n: number = 0): string => charAt(source, offset + n);

  while (offset < source.length) {
    const char = charAt(source, offset);
    const startOffset = offset;
    const startLine = line;
    const startColumn = column;

    if (char === ' ' || char === '\t' || char === '\r' || char === '\n') {
      advance();
      continue;
    }

    if (char === '/' && peek(1) === '/') {
      advance(2);
      while (offset < source.length && charAt(source, offset) !== '\n') {
        advance();
      }
      continue;
    }

    if (char === '/' && peek(1) === '*') {
      advance(2);
      while (offset < source.length) {
        if (charAt(source, offset) === '*' && peek(1) === '/') {
          advance(2);
          break;
        }
        advance();
      }
      continue;
    }

    if (
      char === '{' ||
      char === '}' ||
      char === '[' ||
      char === ']' ||
      char === ':' ||
      char === ','
    ) {
      tokens.push({
        type: char,
        value: char,
        offset: startOffset,
        line: startLine,
        column: startColumn,
      });
      advance();
      continue;
    }

    if (char === '"') {
      advance();
      let value = '';
      while (offset < source.length) {
        const c = charAt(source, offset);
        if (c === '"') {
          advance();
          break;
        }
        if (c === '\\') {
          advance();
          if (offset >= source.length) {
            throw createParseError('Unterminated escape sequence', offset, source);
          }
          const next = charAt(source, offset);
          const escapes: Record<string, string> = {
            '"': '"',
            '\\': '\\',
            '/': '/',
            b: '\b',
            f: '\f',
            n: '\n',
            r: '\r',
            t: '\t',
          };
          if (escapes[next]) {
            value += escapes[next];
            advance();
          } else if (next === 'u') {
            advance();
            if (offset + 4 > source.length) {
              throw createParseError('Invalid unicode escape', offset, source);
            }
            const hex = source.slice(offset, offset + 4);
            if (!/^[0-9a-fA-F]{4}$/.test(hex)) {
              throw createParseError(`Invalid unicode escape: \\u${hex}`, offset, source);
            }
            value += String.fromCharCode(parseInt(hex, 16));
            advance(4);
          } else {
            throw createParseError(`Invalid escape sequence: \\${next}`, offset, source);
          }
        } else if (c === '\n') {
          throw createParseError('Unterminated string', offset, source);
        } else {
          value += c;
          advance();
        }
      }
      tokens.push({
        type: 'string',
        value,
        offset: startOffset,
        line: startLine,
        column: startColumn,
      });
      continue;
    }

    if (/[0-9-]/.test(char)) {
      let value = '';
      const isNegative = char === '-';
      if (isNegative) {
        value += '-';
        advance();
      }
      if (offset < source.length && charAt(source, offset) === '0') {
        value += '0';
        advance();
      } else if (offset < source.length && /[1-9]/.test(charAt(source, offset))) {
        while (offset < source.length && /[0-9]/.test(charAt(source, offset))) {
          value += charAt(source, offset);
          advance();
        }
      } else {
        throw createParseError('Invalid number', offset, source);
      }
      if (offset < source.length && charAt(source, offset) === '.') {
        value += '.';
        advance();
        if (offset >= source.length || !/[0-9]/.test(charAt(source, offset))) {
          throw createParseError('Invalid number', offset, source);
        }
        while (offset < source.length && /[0-9]/.test(charAt(source, offset))) {
          value += charAt(source, offset);
          advance();
        }
      }
      if (offset < source.length && /[eE]/.test(charAt(source, offset))) {
        value += charAt(source, offset);
        advance();
        if (
          offset < source.length &&
          (charAt(source, offset) === '+' || charAt(source, offset) === '-')
        ) {
          value += charAt(source, offset);
          advance();
        }
        if (offset >= source.length || !/[0-9]/.test(charAt(source, offset))) {
          throw createParseError('Invalid number', offset, source);
        }
        while (offset < source.length && /[0-9]/.test(charAt(source, offset))) {
          value += charAt(source, offset);
          advance();
        }
      }
      tokens.push({
        type: 'number',
        value,
        offset: startOffset,
        line: startLine,
        column: startColumn,
      });
      continue;
    }

    if (/[a-zA-Z_]/.test(char)) {
      let value = '';
      while (offset < source.length && /[a-zA-Z0-9_]/.test(charAt(source, offset))) {
        value += charAt(source, offset);
        advance();
      }
      const type = KEYWORDS.has(value) ? value : 'identifier';
      tokens.push({ type, value, offset: startOffset, line: startLine, column: startColumn });
      continue;
    }

    throw createParseError(`Unexpected character: ${char}`, offset, source);
  }

  tokens.push({ type: 'eof', value: '', offset, line, column });
  return tokens;
}

class Parser {
  private tokens: Token[];
  private index = 0;
  private source: string;

  constructor(tokens: Token[], source: string) {
    this.tokens = tokens;
    this.source = source;
  }

  private current(): Token {
    return this.tokens[this.index] ?? { type: 'eof', value: '', offset: 0, line: 1, column: 1 };
  }

  private eat(type: string, value?: string): Token {
    const token = this.current();
    if (token.type !== type || (value !== undefined && token.value !== value)) {
      throw createParseError(
        `Expected ${type}${value ? ` "${value}"` : ''}, got ${token.type}`,
        token.offset,
        this.source
      );
    }
    this.index++;
    return token;
  }

  parse(): JsoncNode {
    const node = this.parseValue();
    this.eat('eof');
    return node;
  }

  private parseValue(): JsoncNode {
    const token = this.current();
    switch (token.type) {
      case '{':
        return this.parseObject();
      case '[':
        return this.parseArray();
      case 'string':
        return this.parseString();
      case 'number':
        return this.parseNumber();
      case 'true':
      case 'false':
        return this.parseBoolean();
      case 'null':
        return this.parseNull();
      default:
        throw createParseError(`Unexpected token: ${token.type}`, token.offset, this.source);
    }
  }

  private parseObject(): JsoncNode {
    const startToken = this.eat('{');
    const children = new Map<string, JsoncNode>();

    while (this.current().type !== '}') {
      if (this.current().type === 'string') {
        const keyToken = this.current();
        const key = keyToken.value;
        this.index++;
        this.eat(':');
        const value = this.parseValue();
        children.set(key, value);
      } else {
        throw createParseError(
          `Expected string key, got ${this.current().type}`,
          this.current().offset,
          this.source
        );
      }

      if (this.current().type === ',') {
        this.index++;
        if (this.current().type === '}') {
          break;
        }
      } else {
        break;
      }
    }

    this.eat('}');
    const endOffset = this.current().offset;
    return {
      type: 'object',
      value: Object.fromEntries(children),
      offset: startToken.offset,
      length: endOffset - startToken.offset + 1,
      children,
    };
  }

  private parseArray(): JsoncNode {
    const startToken = this.eat('[');
    const children: JsoncNode[] = [];

    while (this.current().type !== ']') {
      children.push(this.parseValue());
      if (this.current().type === ',') {
        this.index++;
        if (this.current().type === ']') {
          break;
        }
      } else {
        break;
      }
    }

    this.eat(']');
    const endOffset = this.current().offset;
    return {
      type: 'array',
      value: children.map(c => c.value),
      offset: startToken.offset,
      length: endOffset - startToken.offset + 1,
      children,
    };
  }

  private parseString(): JsoncNode {
    const token = this.eat('string');
    return {
      type: 'string',
      value: token.value,
      offset: token.offset,
      length: token.value.length + 2,
    };
  }

  private parseNumber(): JsoncNode {
    const token = this.eat('number');
    return {
      type: 'number',
      value: Number(token.value),
      offset: token.offset,
      length: token.value.length,
    };
  }

  private parseBoolean(): JsoncNode {
    const token = this.current();
    this.index++;
    return {
      type: 'boolean',
      value: token.value === 'true',
      offset: token.offset,
      length: token.value.length,
    };
  }

  private parseNull(): JsoncNode {
    const token = this.eat('null');
    return {
      type: 'null',
      value: null,
      offset: token.offset,
      length: 4,
    };
  }
}

export function parseJsonc(source: string): JsoncNode {
  const tokens = tokenize(source);
  const parser = new Parser(tokens, source);
  return parser.parse();
}

export function getLoc(
  node: JsoncNode,
  path: (string | number)[],
  source: string
): { line: number; column: number } | undefined {
  let current: JsoncNode | undefined = node;
  for (const key of path) {
    if (!current) return undefined;
    if (current.type === 'object' && current.children instanceof Map) {
      current = current.children.get(String(key));
    } else if (current.type === 'array' && Array.isArray(current.children)) {
      const idx = key as number;
      if (idx >= 0 && idx < current.children.length) {
        current = current.children[idx];
      } else {
        return undefined;
      }
    } else {
      return undefined;
    }
  }
  if (!current) return undefined;
  let line = 1;
  let column = 1;
  for (let i = 0; i < current.offset; i++) {
    if (source[i] === '\n') {
      line++;
      column = 1;
    } else {
      column++;
    }
  }
  return { line, column };
}

function extractValue(node: JsoncNode): unknown {
  if (node.type === 'object' && node.children instanceof Map) {
    const result: Record<string, unknown> = {};
    for (const [key, child] of node.children) {
      result[key] = extractValue(child);
    }
    return result;
  }
  if (node.type === 'array' && Array.isArray(node.children)) {
    return node.children.map(extractValue);
  }
  return node.value;
}

export function getValueAtPath(node: JsoncNode, path: (string | number)[]): unknown {
  let current: JsoncNode | undefined = node;
  for (const key of path) {
    if (!current) return undefined;
    if (current.type === 'object' && current.children instanceof Map) {
      current = current.children.get(String(key));
    } else if (current.type === 'array' && Array.isArray(current.children)) {
      const idx = key as number;
      if (idx >= 0 && idx < current.children.length) {
        current = current.children[idx];
      } else {
        return undefined;
      }
    } else {
      return undefined;
    }
  }
  if (!current) return undefined;
  return extractValue(current);
}
