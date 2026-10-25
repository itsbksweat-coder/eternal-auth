#!/usr/bin/env node
// Obfuscate a Luau script locally with the ShadowVM port, then upload the
// output through the dashboard (the Worker stores uploads as-is). Runs on your
// machine, so there is no Cloudflare CPU limit — nuclear defaults are fine here.
//
// Usage:
//   node scripts/obfuscate.mjs input.lua [output.lua] [--settings '{"vm_strength":25,"layers":3}']
//   node scripts/obfuscate.mjs input.lua > output.lua
import { readFileSync, writeFileSync } from "node:fs";
import { obfuscateLuau } from "../src/obfuscator.js";

const args = process.argv.slice(2);
let settings = {};
const positional = [];
for (let i = 0; i < args.length; i++) {
  if (args[i] === "--settings") { settings = JSON.parse(args[++i] || "{}"); }
  else positional.push(args[i]);
}
const [inPath, outPath] = positional;
if (!inPath) {
  console.error("usage: node scripts/obfuscate.mjs <input.lua> [output.lua] [--settings '{...}']");
  process.exit(1);
}

const src = readFileSync(inPath, "utf8");
const { code, stats } = obfuscateLuau(src, settings);
if (outPath) writeFileSync(outPath, code);
else process.stdout.write(code);

const strength = settings.vm_strength ?? 25;
const layers = stats.vm_layers;
console.error(`[obfuscate] ${stats.original_size}B -> ${code.length}B (ratio ${stats.ratio}, strength ${strength}, layers ${layers})${outPath ? ` written to ${outPath}` : ""}`);
