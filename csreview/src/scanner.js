// @ts-check
import fs from 'fs';
import path from 'path';
import { glob } from 'glob';
import { safeResolveInside } from './pathSafety.js';
import { buildScannerIgnoreGlobs } from './ignore.js';
import { EXTENSION_TO_TECH } from './languages.js';

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

// File-discovery exclusions derived at module init from the single source of
// truth in ignore.js (shared with the report-level default suppression that
// scopes the external security tools). Adding a generated cache there updates
// both paths. Keep ignore.js side-effect-free so this top-level call is safe.
const IGNORE_PATTERNS = buildScannerIgnoreGlobs();

function buildSourceGlobPattern() {
  return `**/*.{${SOURCE_EXTENSIONS.join(',')}}`;
}

// Discovery patterns match at ANY depth (`**/` prefix): monorepos keep configs,
// manifests, and BaaS rules inside nested workspaces (apps/*, services/*,
// packages/*), and IGNORE_PATTERNS already fences off node_modules and the
// generated caches, so recursion does not reintroduce vendored noise.
function recursivePatterns(patterns) {
  return patterns.map((pattern) => `**/${pattern}`);
}

function pathDepth(filePath) {
  return filePath.split('/').length;
}

// One glob walk per category (the glob library accepts a pattern array — far
// cheaper than one walk per pattern), with /-normalized output so reports and
// dedup keys are identical across platforms, and root-first ordering so
// "find the project manifest" reads keep resolving to the root file.
async function globUnique(patterns, rootDir) {
  const matches = await glob(patterns, {
    cwd: rootDir,
    nodir: true,
    dot: true,
    ignore: IGNORE_PATTERNS,
  });
  const unique = [...new Set(matches.map((match) => match.replace(/\\/g, '/')))];
  return unique.sort((a, b) => pathDepth(a) - pathDepth(b) || a.localeCompare(b));
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

// In a monorepo every workspace manifest contributes frameworks, so the
// detectors below read ALL matching dep files, not just the first one found.
function eachDepFile(depFiles, matcher) {
  return depFiles.filter((f) => matcher(path.basename(f), f));
}

function detectFrameworksFromPackageJson(rootDir, depFiles) {
  const frameworks = new Set();
  for (const pkgPath of eachDepFile(depFiles, (base) => base === 'package.json')) {
    const pkg = readProjectJson(rootDir, pkgPath);
    if (!pkg) continue;

    const allDeps = {
      ...pkg.dependencies,
      ...pkg.devDependencies,
      ...pkg.peerDependencies,
    };

    if (allDeps['react']) frameworks.add('React');
    if (allDeps['vue']) frameworks.add('Vue');
    if (allDeps['@angular/core']) frameworks.add('Angular');
    if (allDeps['svelte']) frameworks.add('Svelte');
    if (allDeps['next']) frameworks.add('Next.js');
    if (allDeps['nuxt']) frameworks.add('Nuxt');
    if (allDeps['express']) frameworks.add('Express');
    if (allDeps['fastify']) frameworks.add('Fastify');
    if (allDeps['@nestjs/core']) frameworks.add('NestJS');
    if (allDeps['react-native']) frameworks.add('React Native');
    if (allDeps['expo']) frameworks.add('Expo');
    if (allDeps['electron']) frameworks.add('Electron');
    if (allDeps['@tauri-apps/api']) frameworks.add('Tauri');
  }
  return [...frameworks];
}

function detectFrameworksFromRequirements(rootDir, depFiles) {
  const frameworks = new Set();
  for (const reqPath of eachDepFile(depFiles, (base) => base === 'requirements.txt')) {
    const content = readProjectLines(rootDir, reqPath).join('\n').toLowerCase();
    if (content.includes('django')) frameworks.add('Django');
    if (content.includes('flask')) frameworks.add('Flask');
    if (content.includes('fastapi')) frameworks.add('FastAPI');
  }
  return [...frameworks];
}

function detectFrameworksFromPyproject(rootDir, depFiles) {
  const frameworks = new Set();
  for (const pyprojectPath of eachDepFile(depFiles, (base) => base === 'pyproject.toml')) {
    const content = readProjectContent(rootDir, pyprojectPath).toLowerCase();
    if (content.includes('django')) frameworks.add('Django');
    if (content.includes('flask')) frameworks.add('Flask');
    if (content.includes('fastapi')) frameworks.add('FastAPI');
  }
  return [...frameworks];
}

function detectFrameworksFromComposer(rootDir, depFiles) {
  const frameworks = new Set();
  for (const composerPath of eachDepFile(depFiles, (base) => base === 'composer.json')) {
    const composer = readProjectJson(rootDir, composerPath);
    if (!composer) continue;
    const allDeps = {
      ...composer.require,
      ...composer['require-dev'],
    };
    if (allDeps && allDeps['laravel/framework']) frameworks.add('Laravel');
  }
  return [...frameworks];
}

function detectFrameworksFromGemfile(rootDir, depFiles) {
  const frameworks = new Set();
  for (const gemfilePath of eachDepFile(depFiles, (base) => base === 'Gemfile')) {
    const content = readProjectLines(rootDir, gemfilePath).join('\n').toLowerCase();
    if (content.includes("'rails'") || content.includes('"rails"')) frameworks.add('Rails');
  }
  return [...frameworks];
}

function detectFrameworksFromPomXml(rootDir, depFiles) {
  const frameworks = new Set();
  for (const pomPath of eachDepFile(depFiles, (base) => base === 'pom.xml')) {
    const content = readProjectContent(rootDir, pomPath).toLowerCase();
    if (content.includes('spring-boot') || content.includes('springframework')) frameworks.add('Spring');
  }
  return [...frameworks];
}

function detectFrameworksFromGradle(rootDir, depFiles) {
  const frameworks = new Set();
  for (const gradlePath of eachDepFile(depFiles, (base) => base === 'build.gradle' || base === 'build.gradle.kts')) {
    const content = readProjectContent(rootDir, gradlePath).toLowerCase();
    if (content.includes('spring-boot') || content.includes('org.springframework')) frameworks.add('Spring');
  }
  return [...frameworks];
}

function detectFrameworksFromGoMod(rootDir, depFiles) {
  const frameworks = new Set();
  for (const goModPath of eachDepFile(depFiles, (base) => base === 'go.mod')) {
    const content = readProjectContent(rootDir, goModPath);
    if (content.includes('gin-gonic/gin')) frameworks.add('Gin');
    if (content.includes('labstack/echo')) frameworks.add('Echo');
    if (content.includes('gofiber/fiber')) frameworks.add('Fiber');
  }
  return [...frameworks];
}

function detectFrameworksFromCsproj(rootDir, depFiles) {
  const frameworks = new Set();
  for (const csprojPath of eachDepFile(depFiles, (base, full) => path.extname(full) === '.csproj')) {
    const content = readProjectContent(rootDir, csprojPath);
    if (content.includes('Microsoft.AspNetCore')) frameworks.add('ASP.NET');
  }
  return [...frameworks];
}

function detectFrameworksFromPubspec(rootDir, depFiles) {
  const frameworks = new Set();
  for (const pubspecPath of eachDepFile(depFiles, (base) => base === 'pubspec.yaml')) {
    const content = readProjectContent(rootDir, pubspecPath).toLowerCase();
    if (content.includes('flutter')) frameworks.add('Flutter');
  }
  return [...frameworks];
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

const CONFIG_FILE_PATTERNS = [
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
];

const DEP_FILE_PATTERNS = [
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

export async function scanProject(rootDir) {
  console.log('Scanning project structure...');

  const [sourceFiles, configFiles, depFiles, baasFiles] = await Promise.all([
    globUnique([buildSourceGlobPattern()], rootDir),
    globUnique(recursivePatterns(CONFIG_FILE_PATTERNS), rootDir),
    globUnique(recursivePatterns(DEP_FILE_PATTERNS), rootDir),
    globUnique(recursivePatterns(getBaasFilePatterns()), rootDir),
  ]);

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
