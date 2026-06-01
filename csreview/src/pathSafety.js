import path from 'path';

function isInsideRoot(rootPath, targetPath) {
  const relative = path.relative(rootPath, targetPath);
  return relative === '' || (!relative.startsWith('..') && !path.isAbsolute(relative));
}

export function normalizeLocalPath(inputPath) {
  // nosemgrep: javascript.lang.security.audit.path-traversal.path-join-resolve-traversal.path-join-resolve-traversal
  return path.resolve(inputPath);
}

export function safeResolveInside(rootDir, relativePath) {
  if (typeof relativePath !== 'string' || path.isAbsolute(relativePath)) {
    return null;
  }

  // nosemgrep: javascript.lang.security.audit.path-traversal.path-join-resolve-traversal.path-join-resolve-traversal
  const rootPath = path.resolve(rootDir);
  // nosemgrep: javascript.lang.security.audit.path-traversal.path-join-resolve-traversal.path-join-resolve-traversal
  const targetPath = path.resolve(rootPath, relativePath);

  return isInsideRoot(rootPath, targetPath) ? targetPath : null;
}
