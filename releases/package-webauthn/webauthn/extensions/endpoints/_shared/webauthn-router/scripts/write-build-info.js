#!/usr/bin/env node
import { execSync } from 'node:child_process';
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

function safe(cmd) {
  try {
    return execSync(cmd, { stdio: ['ignore', 'pipe', 'ignore'] }).toString().trim();
  } catch (error) {
    return 'unknown';
  }
}

const git_sha = safe('git rev-parse HEAD');
const branch = safe('git rev-parse --abbrev-ref HEAD');
const build_time = new Date().toISOString();
const pkgPath = join(dirname(fileURLToPath(import.meta.url)), '..', 'package.json');
const pkgJson = JSON.parse(readFileSync(pkgPath, 'utf8'));
const package_version = pkgJson.version ?? '0.0.0';

const info = { git_sha, branch, build_time, package_version };
const outDir = dirname(fileURLToPath(import.meta.url));
const distDir = join(outDir, '..', 'dist');
const outPath = join(distDir, 'build_info.json');

mkdirSync(distDir, { recursive: true });

writeFileSync(outPath, JSON.stringify(info, null, 2));
console.log(`[webauthn-router] wrote build info to ${outPath}`);
