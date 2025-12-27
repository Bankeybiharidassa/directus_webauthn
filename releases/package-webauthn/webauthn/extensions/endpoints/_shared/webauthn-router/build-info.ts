import { createHash } from 'node:crypto';
import { readFileSync, readdirSync, statSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { execSync } from 'node:child_process';

export type BuildInfo = {
  git_sha: string;
  branch: string;
  build_time: string;
  package_version: string;
  bundle_hash?: string;
  source?: 'git' | 'bundle' | 'unknown';
};

const DEFAULT_BUILD_INFO: BuildInfo = {
  git_sha: 'unknown',
  branch: 'unknown',
  build_time: 'unknown',
  package_version: '0.0.0',
  source: 'unknown',
};

function safeReadJson(path: string): Record<string, any> | null {
  try {
    const raw = readFileSync(path, 'utf8');
    return JSON.parse(raw);
  } catch (error) {
    return null;
  }
}

function readPackageVersion(baseDir: string): string | null {
  const packagePath = join(baseDir, '..', 'package.json');
  const fallbackPath = join(baseDir, 'package.json');
  const json = safeReadJson(packagePath) ?? safeReadJson(fallbackPath);
  const version = (json as any)?.version;
  return typeof version === 'string' && version.trim() ? version.trim() : null;
}

function resolveGitSha(baseDir: string): string | null {
  try {
    const output = execSync('git rev-parse --short=12 HEAD', {
      cwd: baseDir,
      stdio: ['ignore', 'pipe', 'ignore'],
    })
      .toString()
      .trim();
    return output || null;
  } catch (error) {
    return null;
  }
}

function computeBundleHash(baseDir: string): string | null {
  const distDir = join(baseDir, '..', 'dist');
  const hasher = createHash('sha256');

  try {
    const entries = readdirSync(distDir, { withFileTypes: true })
      .filter((entry) => entry.isFile())
      .map((entry) => entry.name)
      .sort();

    let included = 0;

    for (const name of entries) {
      const path = join(distDir, name);
      const stats = statSync(path);
      if (!stats.isFile()) continue;
      const contents = readFileSync(path);
      hasher.update(contents);
      included += 1;
    }

    if (included === 0) return null;

    return hasher.digest('hex').slice(0, 12);
  } catch (error) {
    return null;
  }
}

export function loadBuildInfo(): BuildInfo {
  const dir = dirname(fileURLToPath(import.meta.url));
  const buildInfo = safeReadJson(join(dir, 'build_info.json')) ?? {};
  const packageVersion = readPackageVersion(dir) ?? buildInfo.package_version ?? DEFAULT_BUILD_INFO.package_version;
  const bundleHash = computeBundleHash(dir) ?? buildInfo.bundle_hash ?? null;
  const gitShaFromRepo = resolveGitSha(dir);

  const gitSha = gitShaFromRepo ?? (buildInfo.git_sha as string) ?? 'unknown';
  const normalizedGitSha = typeof gitSha === 'string' && gitSha.trim() ? gitSha.trim() : 'unknown';
  const resolvedSha = normalizedGitSha === 'unknown' ? bundleHash ?? 'unknown' : normalizedGitSha;

  return {
    ...DEFAULT_BUILD_INFO,
    ...buildInfo,
    package_version: packageVersion,
    git_sha: resolvedSha,
    bundle_hash: bundleHash ?? undefined,
    source: normalizedGitSha === 'unknown' ? (bundleHash ? 'bundle' : 'unknown') : 'git',
  };
}
