import fs from 'node:fs';
import path from 'node:path';

const rootDir = process.cwd();
const staticDir = path.resolve(rootDir, 'static');
const distDir = path.resolve(rootDir, 'dist');

fs.mkdirSync(distDir, { recursive: true });
fs.cpSync(staticDir, distDir, { recursive: true });
console.log(`Built static site in ${path.relative(rootDir, distDir)}`);
