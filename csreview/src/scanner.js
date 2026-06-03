// @ts-check
import fs from 'fs';
import path from 'path';
import { glob } from 'glob';
import { safeResolveInside } from './pathSafety.js';

const SOURCE_EXTENSIONS = [
  'js',
  'mjs',
  'cjs',
  'ts',
  'tsx',
  'jsx',
  'py',
  'pyw',
  'java',
  'kt',
  'kts',
  'go',
  'rs',
  'php',
  'phtml',
  'rb',
  'erb',
  'cs',
  'cshtml',
  'razor',
  'c',
  'cpp',
  'cc',
  'cxx',
  'h',
  'hpp',
  'swift',
  'dart',
  'pas',
  'pp',
  'dpr',
  'lpr',
  'lfm',
  'dfm',
  'lua',
  'scala',
  'sc',
  'ex',
  'exs',
  'clj',
  'cljs',
  'vue',
  'svelte',
  'html',
  'htm',
  'ejs',
  'hbs',
  'twig',
  'pug',
  'jade',
  'sh',
  'bash',
  'zsh',
  'ps1',
  'bat',
  'cmd',
  'sql',
  'graphql',
  'gql',
];

const IGNORE_PATTERNS = [
  '**/node_modules/**',
  '**/.git/**',
  '**/dist/**',
  '**/build/**',
  '**/.next/**',
  '**/.nuxt/**',
  '**/coverage/**',
  '**/__pycache__/**',
  '**/.venv/**',
  '**/venv/**',
  '**/.tox/**',
  '**/.mypy_cache/**',
  '**/vendor/**',
  '**/target/**',
  '**/bin/**',
  '**/obj/**',
  '**/*.min.js',
  '**/*.min.css',
  '**/.trae/**',
  '**/.vscode/**',
  '**/.idea/**',
  '**/security-report.html',
  '**/security-findings.md',
  '**/csreview-report.html',
  '**/csreview-report.md',
  '**/*_security-report.html',
  '**/*_security-findings.md',
  '**/csreview-reports/**',
  '**/.csreview/**',
];

const EXTENSION_TO_TECH = {
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

function buildSourceGlobPattern() {
  return `**/*.{${SOURCE_EXTENSIONS.join(',')}}`;
}

function readFileJson(filePath) {
  try {
    const raw = fs.readFileSync(filePath, 'utf8');
    return JSON.parse(raw);
  } catch {
    return null;
  }
}

function readFileLines(filePath) {
  try {
    const raw = fs.readFileSync(filePath, 'utf8');
    return raw.split('\n');
  } catch {
    return [];
  }
}

function readFileContent(filePath) {
  try {
    return fs.readFileSync(filePath, 'utf8');
  } catch {
    return '';
  }
}

function readProjectJson(rootDir, relativePath) {
  const filePath = safeResolveInside(rootDir, relativePath);
  return filePath ? readFileJson(filePath) : null;
}

function readProjectLines(rootDir, relativePath) {
  const filePath = safeResolveInside(rootDir, relativePath);
  return filePath ? readFileLines(filePath) : [];
}

function readProjectContent(rootDir, relativePath) {
  const filePath = safeResolveInside(rootDir, relativePath);
  return filePath ? readFileContent(filePath) : '';
}

function detectTechStack(files) {
  const techSet = new Set();

  for (const file of files) {
    const ext = path.extname(file).replace('.', '');
    if (ext && EXTENSION_TO_TECH[ext]) {
      techSet.add(EXTENSION_TO_TECH[ext]);
    }
  }

  return Array.from(techSet);
}

function detectFrameworksFromPackageJson(rootDir, depFiles) {
  const frameworks = [];
  const pkgPath = depFiles.find((f) => path.basename(f) === 'package.json');

  if (!pkgPath) return frameworks;

  const pkg = readProjectJson(rootDir, pkgPath);
  if (!pkg) return frameworks;

  const allDeps = {
    ...pkg.dependencies,
    ...pkg.devDependencies,
    ...pkg.peerDependencies,
  };

  if (allDeps['react']) frameworks.push('React');
  if (allDeps['vue']) frameworks.push('Vue');
  if (allDeps['@angular/core']) frameworks.push('Angular');
  if (allDeps['svelte']) frameworks.push('Svelte');
  if (allDeps['next']) frameworks.push('Next.js');
  if (allDeps['nuxt']) frameworks.push('Nuxt');
  if (allDeps['express']) frameworks.push('Express');
  if (allDeps['fastify']) frameworks.push('Fastify');
  if (allDeps['@nestjs/core']) frameworks.push('NestJS');
  if (allDeps['react-native']) frameworks.push('React Native');
  if (allDeps['expo']) frameworks.push('Expo');
  if (allDeps['electron']) frameworks.push('Electron');
  if (allDeps['@tauri-apps/api']) frameworks.push('Tauri');

  return frameworks;
}

function detectFrameworksFromRequirements(rootDir, depFiles) {
  const frameworks = [];
  const reqPath = depFiles.find((f) => path.basename(f) === 'requirements.txt');

  if (!reqPath) return frameworks;

  const lines = readProjectLines(rootDir, reqPath);
  const content = lines.join('\n').toLowerCase();

  if (content.includes('django')) frameworks.push('Django');
  if (content.includes('flask')) frameworks.push('Flask');
  if (content.includes('fastapi')) frameworks.push('FastAPI');

  return frameworks;
}

function detectFrameworksFromPyproject(rootDir, depFiles) {
  const frameworks = [];
  const pyprojectPath = depFiles.find((f) => path.basename(f) === 'pyproject.toml');

  if (!pyprojectPath) return frameworks;

  const content = readProjectContent(rootDir, pyprojectPath).toLowerCase();

  if (content.includes('django')) frameworks.push('Django');
  if (content.includes('flask')) frameworks.push('Flask');
  if (content.includes('fastapi')) frameworks.push('FastAPI');

  return frameworks;
}

function detectFrameworksFromComposer(rootDir, depFiles) {
  const frameworks = [];
  const composerPath = depFiles.find((f) => path.basename(f) === 'composer.json');

  if (!composerPath) return frameworks;

  const composer = readProjectJson(rootDir, composerPath);
  if (!composer) return frameworks;

  const allDeps = {
    ...composer.require,
    ...composer['require-dev'],
  };

  if (allDeps && allDeps['laravel/framework']) frameworks.push('Laravel');

  return frameworks;
}

function detectFrameworksFromGemfile(rootDir, depFiles) {
  const frameworks = [];
  const gemfilePath = depFiles.find((f) => path.basename(f) === 'Gemfile');

  if (!gemfilePath) return frameworks;

  const lines = readProjectLines(rootDir, gemfilePath);
  const content = lines.join('\n').toLowerCase();

  if (content.includes("'rails'") || content.includes('"rails"')) frameworks.push('Rails');

  return frameworks;
}

function detectFrameworksFromPomXml(rootDir, depFiles) {
  const frameworks = [];
  const pomPath = depFiles.find((f) => path.basename(f) === 'pom.xml');

  if (!pomPath) return frameworks;

  const content = readProjectContent(rootDir, pomPath).toLowerCase();

  if (content.includes('spring-boot') || content.includes('springframework')) frameworks.push('Spring');

  return frameworks;
}

function detectFrameworksFromGradle(rootDir, depFiles) {
  const frameworks = [];
  const gradlePath = depFiles.find((f) => {
    const base = path.basename(f);
    return base === 'build.gradle' || base === 'build.gradle.kts';
  });

  if (!gradlePath) return frameworks;

  const content = readProjectContent(rootDir, gradlePath).toLowerCase();

  if (content.includes('spring-boot') || content.includes('org.springframework')) frameworks.push('Spring');

  return frameworks;
}

function detectFrameworksFromGoMod(rootDir, depFiles) {
  const frameworks = [];
  const goModPath = depFiles.find((f) => path.basename(f) === 'go.mod');

  if (!goModPath) return frameworks;

  const content = readProjectContent(rootDir, goModPath);

  if (content.includes('gin-gonic/gin')) frameworks.push('Gin');
  if (content.includes('labstack/echo')) frameworks.push('Echo');
  if (content.includes('gofiber/fiber')) frameworks.push('Fiber');

  return frameworks;
}

function detectFrameworksFromCsproj(rootDir, depFiles) {
  const frameworks = [];
  const csprojPath = depFiles.find((f) => path.extname(f) === '.csproj');

  if (!csprojPath) return frameworks;

  const content = readProjectContent(rootDir, csprojPath);

  if (content.includes('Microsoft.AspNetCore')) frameworks.push('ASP.NET');

  return frameworks;
}

function detectFrameworksFromPubspec(rootDir, depFiles) {
  const frameworks = [];
  const pubspecPath = depFiles.find((f) => path.basename(f) === 'pubspec.yaml');

  if (!pubspecPath) return frameworks;

  const content = readProjectContent(rootDir, pubspecPath).toLowerCase();

  if (content.includes('flutter')) frameworks.push('Flutter');

  return frameworks;
}

function detectFrameworksFromConfigFiles(rootDir, configFiles, files) {
  const frameworks = [];

  const hasAngularJson = configFiles.some((f) => path.basename(f) === 'angular.json');
  if (hasAngularJson) frameworks.push('Angular');

  const hasVueConfig = configFiles.some((f) => path.basename(f).startsWith('vue.config.'));
  if (hasVueConfig) frameworks.push('Vue');

  const hasSvelteConfig = configFiles.some((f) => path.basename(f).startsWith('svelte.config.'));
  if (hasSvelteConfig) frameworks.push('Svelte');

  const hasNextConfig = configFiles.some((f) => path.basename(f).startsWith('next.config.'));
  if (hasNextConfig) frameworks.push('Next.js');

  const hasNuxtConfig = configFiles.some((f) => path.basename(f).startsWith('nuxt.config.'));
  if (hasNuxtConfig) frameworks.push('Nuxt');

  const hasGatsbyConfig = configFiles.some((f) => path.basename(f).startsWith('gatsby-config.'));
  if (hasGatsbyConfig) frameworks.push('Gatsby');

  const hasManagePy = files.some((f) => path.basename(f) === 'manage.py');
  if (hasManagePy) frameworks.push('Django');

  return frameworks;
}

function detectFrameworks(rootDir, depFiles, configFiles, files) {
  const allFrameworks = new Set();

  const detectors = [
    detectFrameworksFromPackageJson(rootDir, depFiles),
    detectFrameworksFromRequirements(rootDir, depFiles),
    detectFrameworksFromPyproject(rootDir, depFiles),
    detectFrameworksFromComposer(rootDir, depFiles),
    detectFrameworksFromGemfile(rootDir, depFiles),
    detectFrameworksFromPomXml(rootDir, depFiles),
    detectFrameworksFromGradle(rootDir, depFiles),
    detectFrameworksFromGoMod(rootDir, depFiles),
    detectFrameworksFromCsproj(rootDir, depFiles),
    detectFrameworksFromPubspec(rootDir, depFiles),
    detectFrameworksFromConfigFiles(rootDir, configFiles, files),
  ];

  for (const result of detectors) {
    for (const fw of result) {
      allFrameworks.add(fw);
    }
  }

  return Array.from(allFrameworks);
}

function detectProjectType(frameworks, depFiles, rootDir) {
  const backendFrameworks = [
    'Express',
    'Fastify',
    'NestJS',
    'Django',
    'Flask',
    'FastAPI',
    'Laravel',
    'Rails',
    'Spring',
    'Gin',
    'Echo',
    'Fiber',
    'ASP.NET',
  ];

  const frontendFrameworks = ['React', 'Vue', 'Angular', 'Svelte', 'Next.js', 'Nuxt', 'Gatsby'];

  const mobileFrameworks = ['React Native', 'Flutter', 'Expo'];
  const desktopFrameworks = ['Electron', 'Tauri'];

  const hasBackend = frameworks.some((fw) => backendFrameworks.includes(fw));
  const hasFrontend = frameworks.some((fw) => frontendFrameworks.includes(fw));
  const hasMobile = frameworks.some((fw) => mobileFrameworks.includes(fw));
  const hasDesktop = frameworks.some((fw) => desktopFrameworks.includes(fw));

  if (hasMobile) return 'mobile';
  if (hasDesktop) return 'desktop';
  if (hasBackend && !hasFrontend) return 'api';
  if (hasFrontend) return 'web';

  const pkgPath = depFiles.find((f) => path.basename(f) === 'package.json');
  if (pkgPath) {
    const pkg = readProjectJson(rootDir, pkgPath);
    if (pkg) {
      const hasMainOrExports = !!(pkg.main || pkg.exports);
      const scripts = pkg.scripts || {};
      const hasStartOrDev = !!(scripts.start || scripts.dev || scripts.serve);

      if (hasMainOrExports && !hasStartOrDev) return 'library';
    }
  }

  return 'unknown';
}

function getBaasFilePatterns() {
  return [
    'supabase/config.toml',
    'supabase/migrations/*.sql',
    'supabase/seed.sql',
    'firebase.json',
    'firestore.rules',
    'storage.rules',
    '.firebaserc',
    'database.rules.json',
    'appwrite.json',
    'appwrite.*.json',
    'serverless.yml',
    'samconfig.toml',
    'template.yaml',
    'template.json',
    'cdk.json',
    'pb_migrations/*.js',
    'convex/*.ts',
    'drizzle.config.*',
    'prisma/schema.prisma',
  ];
}

export function readFileSafe(filePath) {
  try {
    const stat = fs.statSync(filePath);
    if (stat.size === 0) {
      return { content: '', isBinary: false, isMinified: false };
    }

    const buffer = Buffer.alloc(Math.min(8192, stat.size));
    const fd = fs.openSync(filePath, 'r');
    fs.readSync(fd, buffer, 0, buffer.length, 0);
    fs.closeSync(fd);

    for (let i = 0; i < buffer.length; i++) {
      if (buffer[i] === 0) {
        return { content: null, isBinary: true, isMinified: false };
      }
    }

    const content = fs.readFileSync(filePath, 'utf8');

    const lines = content.split('\n');
    const isMinified =
      lines.length > 0 && (content.length / lines.length > 500 || lines.some((line) => line.length > 10000));

    return { content, isBinary: false, isMinified };
  } catch {
    return { content: null, isBinary: true, isMinified: false };
  }
}

export async function scanProject(rootDir) {
  console.log('Scanning project structure...');

  const sourceGlob = buildSourceGlobPattern();

  const sourceFiles = await glob(sourceGlob, {
    cwd: rootDir,
    nodir: true,
    dot: true,
    ignore: IGNORE_PATTERNS,
  });

  const configPatterns = [
    '.env',
    '.env.local',
    '.env.development',
    '.env.production',
    '.env.staging',
    '.env.test',
    'docker-compose.yml',
    'docker-compose.yaml',
    'Dockerfile',
    '.dockerignore',
    'nginx.conf',
    'apache2.conf',
    '.htaccess',
    '.github/workflows/*.yml',
    '.github/workflows/*.yaml',
    '.gitlab-ci.yml',
    'Jenkinsfile',
    '.circleci/config.yml',
    'bitbucket-pipelines.yml',
    '*.tf',
    '*.tfvars',
    '.eslintrc',
    '.eslintrc.*',
    'security.txt',
    'package.json',
    'tsconfig.json',
    'webpack.config.*',
    'vite.config.*',
    'next.config.*',
    'nuxt.config.*',
    'angular.json',
    'vue.config.*',
    'svelte.config.*',
    'gatsby-config.*',
    '*.pem',
    '*.crt',
    '*.key',
    'terraform/*.tf',
    'terraform/*.tfvars',
  ];

  const configFiles = [];
  for (const pattern of configPatterns) {
    try {
      const matches = await glob(pattern, {
        cwd: rootDir,
        nodir: true,
        dot: true,
        ignore: IGNORE_PATTERNS,
      });
      for (const match of matches) {
        if (!configFiles.includes(match)) {
          configFiles.push(match);
        }
      }
    } catch {
      // skip invalid patterns
    }
  }

  const depPatterns = [
    'package.json',
    'package-lock.json',
    'yarn.lock',
    'pnpm-lock.yaml',
    'requirements.txt',
    'pyproject.toml',
    'setup.py',
    'setup.cfg',
    'Pipfile',
    'Pipfile.lock',
    'poetry.lock',
    'go.mod',
    'go.sum',
    'Cargo.toml',
    'Cargo.lock',
    'pom.xml',
    'build.gradle',
    'build.gradle.kts',
    'Gemfile',
    'Gemfile.lock',
    '*.gemspec',
    'composer.json',
    'composer.lock',
    '*.csproj',
    '*.sln',
    'packages.config',
    'nuget.config',
    'pubspec.yaml',
    'pubspec.lock',
    'Package.swift',
    '*.lpi',
    '*.dproj',
  ];

  const depFiles = [];
  for (const pattern of depPatterns) {
    try {
      const matches = await glob(pattern, {
        cwd: rootDir,
        nodir: true,
        dot: true,
        ignore: IGNORE_PATTERNS,
      });
      for (const match of matches) {
        if (!depFiles.includes(match)) {
          depFiles.push(match);
        }
      }
    } catch {
      // skip invalid patterns
    }
  }

  const baasPatterns = getBaasFilePatterns();
  const baasFiles = [];
  for (const pattern of baasPatterns) {
    try {
      const matches = await glob(pattern, {
        cwd: rootDir,
        nodir: true,
        dot: true,
        ignore: IGNORE_PATTERNS,
      });
      for (const match of matches) {
        if (!baasFiles.includes(match)) {
          baasFiles.push(match);
        }
      }
    } catch {
      // skip invalid patterns
    }
  }

  const techStack = detectTechStack(sourceFiles);

  const hasNodeJs = depFiles.some((f) => path.basename(f) === 'package.json');
  const hasPython = depFiles.some((f) =>
    ['requirements.txt', 'pyproject.toml', 'setup.py', 'Pipfile'].includes(path.basename(f)),
  );
  const hasGo = depFiles.some((f) => path.basename(f) === 'go.mod');
  const hasRust = depFiles.some((f) => path.basename(f) === 'Cargo.toml');
  const hasDotNet = depFiles.some((f) => path.extname(f) === '.csproj' || path.extname(f) === '.sln');
  const hasDart = depFiles.some((f) => path.basename(f) === 'pubspec.yaml');
  const hasSwift = depFiles.some((f) => path.basename(f) === 'Package.swift');
  const hasDelphi = depFiles.some((f) => {
    const ext = path.extname(f);
    return ext === '.lpi' || ext === '.dproj';
  });

  if (hasNodeJs && !techStack.includes('Node.js')) techStack.push('Node.js');
  if (hasPython && !techStack.includes('Python')) techStack.push('Python');
  if (hasGo && !techStack.includes('Go')) techStack.push('Go');
  if (hasRust && !techStack.includes('Rust')) techStack.push('Rust');
  if (hasDotNet && !techStack.includes('C#')) techStack.push('C#');
  if (hasDart && !techStack.includes('Dart')) techStack.push('Dart');
  if (hasSwift && !techStack.includes('Swift')) techStack.push('Swift');
  if (hasDelphi && !techStack.includes('Delphi')) techStack.push('Delphi');

  const frameworks = detectFrameworks(rootDir, depFiles, configFiles, sourceFiles);
  const projectType = detectProjectType(frameworks, depFiles, rootDir);

  console.log(`Found ${sourceFiles.length} source files`);
  console.log(`Found ${configFiles.length} config files`);
  console.log(`Found ${depFiles.length} dependency files`);
  console.log(`Found ${baasFiles.length} BaaS config files`);
  console.log(`Detected tech stack: ${techStack.join(', ') || 'none'}`);
  console.log(`Detected frameworks: ${frameworks.join(', ') || 'none'}`);
  console.log(`Project type: ${projectType}`);

  const projectInfo = {
    root: rootDir,
    name: path.basename(rootDir),
    files: sourceFiles,
    configFiles,
    depFiles,
    baasFiles,
    techStack,
    frameworks,
    projectType,
  };

  return projectInfo;
}
