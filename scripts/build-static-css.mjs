import fs from 'node:fs';
import path from 'node:path';
import { compile } from '@tailwindcss/node';
import { Scanner } from '@tailwindcss/oxide';

const rootDir = process.cwd();
const inputPath = path.resolve(rootDir, 'src/static-input.css');
const outPath = path.resolve(rootDir, 'static/styles.css');

const cssSource = fs.readFileSync(inputPath, 'utf8');
const compiler = await compile(cssSource, {
  base: path.dirname(inputPath),
  onDependency() {},
});

const scanner = new Scanner({
  sources: [
    {
      base: path.resolve(rootDir, 'static'),
      pattern: '**/*',
      negated: false,
    },
  ],
});

const candidates = scanner.scan();
const outputCss = compiler.build(candidates);

fs.mkdirSync(path.dirname(outPath), { recursive: true });
fs.writeFileSync(outPath, outputCss, 'utf8');
console.log(`Built ${path.relative(rootDir, outPath)} (${candidates.length} candidates)`);
