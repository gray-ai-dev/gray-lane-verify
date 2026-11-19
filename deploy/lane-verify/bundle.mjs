// Bundles gray-lane-verify (workers/packages/lane-verify/src/node/cli.ts) and everything it imports into one ES module
// that runs on Node 22 or later with no install step, with esbuild (the version workers/package-lock.json pins).
// deploy/lane-verify/release.sh runs it for a release and the published source's rebuild.sh runs it the same way: the
// same commit and lockfile give the same bytes.
//
// Licenses. gray-lane-verify is Apache-2.0 (deploy/lane-verify/LICENSE and NOTICE): the file's first lines after the
// entry's hashbang say so, with NOTICE's copyright line. Every npm package the bundle takes code from must carry a license in THIRD_PARTY_LICENSES
// below (permissive, redistributable inside an Apache-2.0 work); another fails the bundle. Their legal comments stay
// in the code (esbuild's `legalComments: "eof"`), and THIRD_PARTY_NOTICES lists each package with its license and
// notice files as it ships them, or, for a package that ships none, its README's license section, or failing that the
// license its package.json declares. The same text is appended to the file as comments.
//
//   node deploy/lane-verify/bundle.mjs <workers directory> <output directory> --commit <40 hex>
//
// Writes <output>/gray-lane-verify-<version>.mjs and <output>/THIRD_PARTY_NOTICES (mode 0644), the version being
// workers/packages/lane-verify/VERSION, and prints the notices' sha256 and then the bundle's path and sha256 last. --commit is the source commit `gray-lane-verify --version` prints; it changes
// no file the bundle reads. Paths in the bundle's comments are relative to the directory above <workers>, so a tree
// with the repository's layout gives the same file wherever it is.
import { chmodSync, existsSync, mkdirSync, readdirSync, readFileSync, writeFileSync } from "node:fs";
import { createHash } from "node:crypto";
import { createRequire } from "node:module";
import { dirname, join, resolve, sep } from "node:path";

const args = process.argv.slice(2);
const commitAt = args.indexOf("--commit");
const commit = commitAt >= 0 ? args[commitAt + 1] : undefined;
const [workersArg, outArg] = args.filter((_, index) => index !== commitAt && index !== commitAt + 1);
if (workersArg === undefined || outArg === undefined || commit === undefined) {
  console.error("usage: node bundle.mjs <workers directory> <output directory> --commit <40 hex>");
  process.exit(2);
}
if (!/^[0-9a-f]{40}$/.test(commit)) {
  console.error("bundle.mjs: --commit is 40 lower-case hex digits");
  process.exit(2);
}
const workers = resolve(workersArg);
const root = dirname(workers);
const out = resolve(outArg);
// Loaded with require(), not import: public-source.mjs records the files a bundle reads through a require hook
// (scripts/ops/public-source/esbuild-metafile.cjs).
const require = createRequire(join(workers, "package.json"));
const esbuild = require("esbuild");

const version = readFileSync(join(workers, "packages/lane-verify/VERSION"), "utf8").trim();
if (!/^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-[0-9A-Za-z.-]+)?$/.test(version)) {
  console.error("bundle.mjs: workers/packages/lane-verify/VERSION holds no semantic version");
  process.exit(2);
}
const name = `gray-lane-verify-${version}.mjs`;
// The licenses a bundled package may carry: permissive ones whose terms an Apache-2.0 work's binary meets by shipping
// the package's notices (THIRD_PARTY_NOTICES). Anything else is a decision, not a default.
const THIRD_PARTY_LICENSES = new Set(["MIT", "ISC", "BSD-2-Clause", "BSD-3-Clause", "0BSD", "Apache-2.0"]);
const notice = readFileSync(join(root, "deploy/lane-verify/NOTICE"), "utf8");
const copyright = notice.split("\n").find((line) => /^Copyright [0-9]{4} \S/.test(line));
if (copyright === undefined) {
  console.error("bundle.mjs: deploy/lane-verify/NOTICE has no `Copyright <year> <holder>` line");
  process.exit(2);
}
const header = [
  `// gray-lane-verify ${version}, built from Gray's source commit ${commit}.`,
  `// ${copyright}. SPDX-License-Identifier: Apache-2.0`,
  "// Licensed under the Apache License, Version 2.0 (https://www.apache.org/licenses/LICENSE-2.0); LICENSE and NOTICE are",
  "// published beside this file and in its source. Third-party code in this file keeps its own license: each package's",
  "// license and notice texts are at the end of this file and in THIRD_PARTY_NOTICES.",
].join("\n");

const result = await esbuild.build({
  entryPoints: [join(workers, "packages/lane-verify/src/node/cli.ts")],
  absWorkingDir: root,
  bundle: true,
  write: false,
  platform: "node",
  format: "esm",
  target: "node22",
  define: {
    __GRAY_LANE_VERIFY_VERSION__: JSON.stringify(version),
    __GRAY_LANE_VERIFY_COMMIT__: JSON.stringify(commit),
    // ws loads two optional native helpers when it finds them; the bundle never looks for them.
    "process.env.WS_NO_BUFFER_UTIL": JSON.stringify("1"),
    "process.env.WS_NO_UTF_8_VALIDATE": JSON.stringify("1"),
  },
  // CommonJS dependencies call require() for Node's built-ins, which an ES module has no binding for.
  banner: { js: `${header}\nimport { createRequire as __grayCreateRequire } from "node:module"; const require = __grayCreateRequire(import.meta.url);` },
  // jsonc-parser's `main` is a UMD build whose require() calls esbuild cannot follow (the file would look for
  // ./impl/format beside itself at run time); its ES build (its `module`) is the same code.
  plugins: [
    {
      name: "jsonc-parser-esm",
      setup(build) {
        const path = require.resolve("jsonc-parser/lib/esm/main.js");
        build.onResolve({ filter: /^jsonc-parser$/ }, () => ({ path }));
      },
    },
  ],
  // The bundled packages' own license comments (/*! ... */, @license, @preserve), collected at the end of the file.
  legalComments: "eof",
  metafile: true,
  logLevel: "warning",
  outfile: join(out, name),
});
const [file] = result.outputFiles;
if (file === undefined) throw new Error("esbuild wrote no bundle");

// The npm packages the bundle took code from, by name; the workspace's own packages are Gray's.
const packages = new Map();
for (const input of Object.keys(result.metafile.inputs)) {
  const path = resolve(root, input);
  const marker = `${sep}node_modules${sep}`;
  const at = path.lastIndexOf(marker);
  if (at < 0) continue;
  const rest = path.slice(at + marker.length).split(sep);
  const packageName = rest[0].startsWith("@") ? `${rest[0]}/${rest[1]}` : rest[0];
  packages.set(packageName, join(path.slice(0, at + marker.length), packageName));
}
const byName = ([a], [b]) => (a < b ? -1 : a > b ? 1 : 0);
const plain = (text) => text.replace(/\r\n?/g, "\n").trimEnd();

/** A README's license section: from its `License` heading to the next heading of the same or a higher level. */
function readmeLicense(dir) {
  const readme = readdirSync(dir).filter((entry) => /^readme(\.(md|markdown|txt))?$/i.test(entry)).sort()[0];
  if (readme === undefined) return null;
  const lines = plain(readFileSync(join(dir, readme), "utf8")).split("\n");
  const start = lines.findIndex((line) => /^#{1,6}\s*licen[cs]e\b/i.test(line));
  if (start < 0) return null;
  const level = lines[start].match(/^#+/)[0].length;
  let end = lines.length;
  for (let index = start + 1; index < lines.length; index += 1) {
    const heading = lines[index].match(/^(#{1,6})\s/);
    if (heading !== null && heading[1].length <= level) {
      end = index;
      break;
    }
  }
  return { file: readme, text: lines.slice(start, end).join("\n").trim() };
}

const RULE = "=".repeat(100);
const blocks = [];
const refused = [];
for (const [packageName, packageRoot] of [...packages].sort(byName)) {
  const manifest = JSON.parse(readFileSync(join(packageRoot, "package.json"), "utf8"));
  const license = typeof manifest.license === "string" ? manifest.license : null;
  if (license === null || !THIRD_PARTY_LICENSES.has(license)) refused.push(`${packageName}@${manifest.version} (${license ?? JSON.stringify(manifest.license ?? manifest.licenses ?? null)})`);
  const repository = typeof manifest.repository === "string" ? manifest.repository : manifest.repository?.url ?? manifest.homepage ?? null;
  const files = readdirSync(packageRoot).filter((entry) => /^(licen[cs]e|copying|notice)/i.test(entry)).sort();
  const parts = [`${packageName} ${manifest.version}`, `License: ${license}`, ...(repository === null ? [] : [`Repository: ${repository}`]), "-".repeat(100)];
  if (files.length > 0) {
    for (const entry of files) parts.push(`${entry}:`, "", plain(readFileSync(join(packageRoot, entry), "utf8")), "");
  } else {
    const section = readmeLicense(packageRoot);
    const author = typeof manifest.author === "string" ? manifest.author : manifest.author?.name ?? null;
    parts.push(section === null
      ? `The package ships no license text. Its package.json declares ${license}${author === null ? "" : ` and names its author, ${author}`}.`
      : `The package ships no license file. The license section of its ${section.file}:`, "");
    if (section !== null) parts.push(section.text, "");
    if (license === "Apache-2.0") parts.push("The Apache License, Version 2.0, is gray-lane-verify's LICENSE, published beside this file.", "");
  }
  blocks.push(`${RULE}\n${parts.join("\n").trimEnd()}`);
  console.log(`bundle.mjs: bundled ${packageName}@${manifest.version} (${license ?? "no license field"}${files.length === 0 ? ", no license file" : ""})`);
}
if (refused.length > 0) {
  console.error(`bundle.mjs: these packages carry no license in THIRD_PARTY_LICENSES (${[...THIRD_PARTY_LICENSES].join(", ")}); decide before bundling them: ${refused.join(", ")}`);
  process.exit(1);
}
const notices = [
  `gray-lane-verify ${version}: third-party notices`,
  "",
  `The file ${name} and the container image of the same version contain code from the npm packages below,`,
  "bundled by deploy/lane-verify/bundle.mjs from the lockfile workers/package-lock.json. Each keeps its own license.",
  "For each package its license and notice files follow as it ships them; for a package that ships none, the license",
  "section of its README, or the license its package.json declares. gray-lane-verify itself is licensed under the",
  "Apache License, Version 2.0 (LICENSE, NOTICE).",
  "",
  ...blocks,
  "",
].join("\n");
const comment = (text) => text.trimEnd().split("\n").map((line) => (line === "" ? "//" : `// ${line}`)).join("\n");
const bytes = Buffer.concat([Buffer.from(file.contents), Buffer.from(`\n${comment(notices)}\n`, "utf8")]);

mkdirSync(out, { recursive: true });
const target = join(out, name);
writeFileSync(target, bytes);
chmodSync(target, 0o644);
const noticesTarget = join(out, "THIRD_PARTY_NOTICES");
writeFileSync(noticesTarget, notices);
chmodSync(noticesTarget, 0o644);
if (!existsSync(target)) throw new Error(`no ${target}`);
const sha256 = (data) => createHash("sha256").update(data).digest("hex");
console.log(`bundle.mjs: ${noticesTarget} (${packages.size} packages) sha256:${sha256(Buffer.from(notices, "utf8"))}`);
console.log(`bundle.mjs: ${target} (gray-lane-verify ${version}, source commit ${commit}, ${bytes.length} bytes)`);
console.log(`sha256:${sha256(bytes)}`);
