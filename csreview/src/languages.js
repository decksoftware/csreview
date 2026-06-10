// @ts-check

/**
 * Single source of truth for file-extension metadata.
 *
 * Extension→language (detector rule scoping, report metadata) and
 * extension→tech-stack-label (project overview) used to live in three
 * divergent maps across index.js, detector.js, and scanner.js — the detector
 * copy was stale enough that `.pyw` files never received the Python-specific
 * rules. Both maps live here so adding an extension updates every consumer.
 */

/** Bare extension (no dot) → canonical language id. */
export const LANG_MAP = {
  js: 'javascript',
  mjs: 'javascript',
  cjs: 'javascript',
  ts: 'typescript',
  tsx: 'typescript',
  jsx: 'javascript',
  py: 'python',
  pyw: 'python',
  java: 'java',
  kt: 'kotlin',
  kts: 'kotlin',
  go: 'go',
  rs: 'rust',
  php: 'php',
  phtml: 'php',
  rb: 'ruby',
  erb: 'ruby',
  cs: 'csharp',
  swift: 'swift',
  c: 'c',
  h: 'c',
  cpp: 'cpp',
  cc: 'cpp',
  cxx: 'cpp',
  hpp: 'cpp',
  pas: 'delphi',
  dpr: 'delphi',
  dpk: 'delphi',
  lpr: 'delphi',
  pp: 'delphi',
  vue: 'vue',
  svelte: 'svelte',
  sh: 'bash',
  bash: 'bash',
  sql: 'sql',
  graphql: 'graphql',
  gql: 'graphql',
  html: 'html',
  htm: 'html',
  xml: 'xml',
  json: 'json',
  yaml: 'yaml',
  yml: 'yaml',
  toml: 'toml',
  env: 'env',
  tf: 'terraform',
  tfvars: 'terraform',
  lua: 'lua',
  r: 'r',
  scala: 'scala',
  groovy: 'groovy',
  ex: 'elixir',
  exs: 'elixir',
  erl: 'erlang',
  hs: 'haskell',
  dart: 'dart',
  zig: 'zig',
  nim: 'nim',
  v: 'v',
  sol: 'solidity',
};

/** Bare extension (no dot) → human-readable tech-stack label. */
export const EXTENSION_TO_TECH = {
  js: 'JavaScript/TypeScript',
  mjs: 'JavaScript/TypeScript',
  cjs: 'JavaScript/TypeScript',
  ts: 'JavaScript/TypeScript',
  tsx: 'JavaScript/TypeScript',
  jsx: 'JavaScript/TypeScript',
  py: 'Python',
  pyw: 'Python',
  java: 'Java',
  kt: 'Kotlin',
  kts: 'Kotlin',
  go: 'Go',
  rs: 'Rust',
  php: 'PHP',
  phtml: 'PHP',
  rb: 'Ruby',
  erb: 'Ruby',
  cs: 'C#',
  cshtml: 'C#',
  razor: 'C#',
  c: 'C/C++',
  cpp: 'C/C++',
  cc: 'C/C++',
  cxx: 'C/C++',
  h: 'C/C++',
  hpp: 'C/C++',
  swift: 'Swift',
  dart: 'Dart',
  pas: 'Delphi',
  pp: 'Delphi',
  dpr: 'Delphi',
  lpr: 'Delphi',
  lfm: 'Delphi',
  dfm: 'Delphi',
  lua: 'Lua',
  scala: 'Scala',
  sc: 'Scala',
  ex: 'Elixir',
  exs: 'Elixir',
  clj: 'Clojure',
  cljs: 'Clojure',
  vue: 'Vue',
  svelte: 'Svelte',
  html: 'HTML',
  htm: 'HTML',
  ejs: 'HTML Templates',
  hbs: 'HTML Templates',
  twig: 'HTML Templates',
  pug: 'HTML Templates',
  jade: 'HTML Templates',
  sh: 'Shell',
  bash: 'Shell',
  zsh: 'Shell',
  ps1: 'Shell',
  bat: 'Shell',
  cmd: 'Shell',
  sql: 'SQL',
  graphql: 'GraphQL',
  gql: 'GraphQL',
};

/**
 * Resolve a file path to its canonical language id ('unknown' when unmapped).
 *
 * @param {string} filePath
 * @returns {string}
 */
export function getLanguage(filePath) {
  const name = String(filePath || '');
  const ext = name.includes('.') ? name.split('.').pop().toLowerCase() : '';
  return LANG_MAP[ext] || 'unknown';
}
