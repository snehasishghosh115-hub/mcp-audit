import type { Rule } from '../types.js';
import sec001 from './sec-001-hardcoded-secret.js';
import sec002 from './sec-002-secret-in-url.js';
import sec003 from './sec-003-plaintext-http.js';
import sec004 from './sec-004-unpinned-package.js';
import sec005 from './sec-005-floating-version.js';
import sec006 from './sec-006-shell-wrapper.js';
import sec007 from './sec-007-download-execute.js';
import sec008 from './sec-008-broad-filesystem.js';
import sec009 from './sec-009-docker-flags.js';
import sec014 from './sec-014-auto-approve.js';
import sec015 from './sec-015-file-permissions.js';

export const ALL_RULES: Rule[] = [
  sec001,
  sec002,
  sec003,
  sec004,
  sec005,
  sec006,
  sec007,
  sec008,
  sec009,
  sec014,
  sec015,
];
