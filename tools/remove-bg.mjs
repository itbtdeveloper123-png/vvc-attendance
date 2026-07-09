import { mkdir, readFile, writeFile } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';
import { removeBackground } from '@imgly/background-removal-node';

const [, , inputPath, outputPath] = process.argv;

if (!inputPath || !outputPath) {
  console.error('Usage: node tools/remove-bg.mjs <input-image> <output-png>');
  process.exit(64);
}

try {
  const input = await readFile(inputPath);
  await mkdir(dirname(resolve(outputPath)), { recursive: true });

  const blob = await removeBackground(input, {
    model: process.env.IMGLY_BG_MODEL || 'medium',
    output: {
      format: 'image/png',
      type: 'foreground',
    },
  });

  const output = Buffer.from(await blob.arrayBuffer());
  await writeFile(outputPath, output);
} catch (error) {
  console.error(error instanceof Error ? error.stack || error.message : error);
  process.exit(1);
}
