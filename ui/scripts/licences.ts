// SPDX-License-Identifier: GPL-3.0-or-later
// The `ui-licences` gate. Every npm package in the browser bundle (listed by `vite build`, see
// tools/shipped-packages.ts) must carry a licence from the allowlist, and its licence text goes
// into THIRD-PARTY-NOTICES.txt. `--check` fails when that file is out of date. Run `vite build`
// first. Build tools and test libraries never ship, so they are not listed here (axe-core is
// MPL-2.0 and dev only).
import { existsSync, readdirSync, readFileSync, writeFileSync } from "node:fs";
import { join, resolve } from "node:path";

const root = resolve(import.meta.dirname, "..");
const SHIPPED = join(root, ".svelte-kit", "shipped-packages.json");
const NOTICES = join(root, "THIRD-PARTY-NOTICES.txt");
const OVERRIDES = join(root, "licence-overrides.json");

/** SPDX ids accepted for shipped code (fonts add OFL-1.1 when they are bundled). */
export const ALLOWED = new Set([
  "MIT",
  "ISC",
  "Apache-2.0",
  "BSD-2-Clause",
  "BSD-3-Clause",
  "0BSD",
  "OFL-1.1",
]);

/** Whether an SPDX expression is covered: every AND needs at least one allowed OR alternative. */
export function allowed(expression: string): boolean {
  const terms = expression.replace(/[()]/g, " ").split(/\s+AND\s+/);
  return terms.every((term) =>
    term.split(/\s+OR\s+/).some((id) => ALLOWED.has(id.trim())),
  );
}

interface Manifest {
  name: string;
  version: string;
  license?: string | { type?: string };
  licenses?: Array<{ type?: string } | string>;
  repository?: { url?: string };
  homepage?: string;
}

export interface Entry {
  name: string;
  version: string;
  licence: string | undefined;
  text: string | undefined;
  repository: string;
}

function licenceOf(pkg: Manifest): string | undefined {
  if (typeof pkg.license === "string") return pkg.license;
  if (typeof pkg.license === "object" && typeof pkg.license.type === "string") {
    return pkg.license.type;
  }
  if (Array.isArray(pkg.licenses)) {
    return pkg.licenses
      .map((l) => (typeof l === "string" ? l : (l.type ?? "")))
      .join(" OR ");
  }
  return undefined;
}

function licenceText(dir: string): string | undefined {
  const name = readdirSync(dir).find((f) =>
    /^(licen[sc]e|copying)(\.|$)/i.test(f),
  );
  return name
    ? readFileSync(join(dir, name), "utf8").replaceAll("\r\n", "\n").trim()
    : undefined;
}

export function collect(
  shipped: string[],
  overrides: Record<string, { licence?: string }> = {},
): { entries: Entry[]; problems: string[] } {
  const problems: string[] = [];
  const entries: Entry[] = [];
  for (const dir of shipped) {
    const manifest = join(dir, "package.json");
    if (!existsSync(manifest)) {
      problems.push(`${dir}: no package.json`);
      continue;
    }
    const pkg = JSON.parse(readFileSync(manifest, "utf8")) as Manifest;
    const label = `${pkg.name}@${pkg.version}`;
    const licence = licenceOf(pkg) ?? overrides[label]?.licence;
    if (!licence) problems.push(`${label}: no licence declared`);
    else if (!allowed(licence))
      problems.push(`${label}: licence ${licence} is not on the allowlist`);
    const text = licenceText(dir);
    if (!text)
      problems.push(`${label}: no licence file to include in the notices`);
    entries.push({
      name: pkg.name,
      version: pkg.version,
      licence,
      text,
      repository: pkg.repository?.url ?? pkg.homepage ?? "",
    });
  }
  entries.sort(
    (a, b) =>
      a.name.localeCompare(b.name) || a.version.localeCompare(b.version),
  );
  return { entries, problems };
}

export function render(entries: Entry[]): string {
  const lines = [
    "Third-party software shipped in puddle's user interface.",
    "",
  ];
  for (const e of entries) {
    lines.push("=".repeat(72), `${e.name} ${e.version} (${e.licence})`);
    if (e.repository) lines.push(e.repository.replace(/^git\+/, ""));
    lines.push("", e.text ?? "", "");
  }
  return `${lines.join("\n").trimEnd()}\n`;
}

function main(argv: string[]): number {
  if (!existsSync(SHIPPED)) {
    console.error(
      "ui-licences: run `npm run build` first (it lists the packages in the bundle)",
    );
    return 1;
  }
  const overrides = (
    JSON.parse(readFileSync(OVERRIDES, "utf8")) as {
      overrides: Record<string, { licence?: string }>;
    }
  ).overrides;
  const { entries, problems } = collect(
    JSON.parse(readFileSync(SHIPPED, "utf8")),
    overrides,
  );
  if (problems.length > 0) {
    console.error(
      `ui-licences: ${problems.length} problem(s)\n  ${problems.join("\n  ")}`,
    );
    return 1;
  }
  const text = render(entries);
  if (argv.includes("--check")) {
    const current = existsSync(NOTICES)
      ? readFileSync(NOTICES, "utf8").replaceAll("\r\n", "\n")
      : "";
    if (current !== text) {
      console.error(
        "ui-licences: THIRD-PARTY-NOTICES.txt is stale; run `npm run licences` and commit it",
      );
      return 1;
    }
    console.log(
      `ui-licences ok: ${entries.length} shipped packages, notices current`,
    );
    return 0;
  }
  writeFileSync(NOTICES, text);
  console.log(
    `ui-licences: wrote THIRD-PARTY-NOTICES.txt (${entries.length} packages)`,
  );
  return 0;
}

if (process.argv[1] && resolve(process.argv[1]) === import.meta.filename) {
  process.exitCode = main(process.argv.slice(2));
}
