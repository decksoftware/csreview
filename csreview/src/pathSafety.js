// @ts-check
import path from 'path';

function assertPathString(inputPath, name) {
  if (typeof inputPath !== 'string' || inputPath.trim() === '') {
    throw new Error(`${name} must be a non-empty string`);
  }
}

function isInsideRoot(rootPath, targetPath) {
  const relative = path.relative(rootPath, targetPath);
  return relative === '' || (!relative.startsWith('..') && !path.isAbsolute(relative));
}

export function normalizeLocalPath(inputPath) {
  assertPathString(inputPath, 'inputPath');

  const normalizedPath = path.normalize(inputPath);
  if (path.isAbsolute(normalizedPath)) {
    return normalizedPath;
  }

  return path.normalize(`${process.cwd()}${path.sep}${normalizedPath}`);
}

export function safeResolveInside(rootDir, relativePath) {
  assertPathString(rootDir, 'rootDir');

  if (
    typeof relativePath !== 'string' ||
    relativePath.trim() === '' ||
    path.isAbsolute(relativePath) ||
    path.win32.isAbsolute(relativePath) ||
    /^[A-Za-z]:/.test(relativePath)
  ) {
    return null;
  }

  const rootPath = normalizeLocalPath(rootDir);
  const normalizedRelativePath = path.normalize(relativePath);
  const targetPath = path.normalize(`${rootPath}${path.sep}${normalizedRelativePath}`);

  return isInsideRoot(rootPath, targetPath) ? targetPath : null;
}
