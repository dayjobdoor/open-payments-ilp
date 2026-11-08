// Every type assertion (`x as T`) in `src/` carries a `SAFETY:` comment within the six lines above it, or on its own
// line, that says why the assertion holds. `as const` and import/export renames need none. Generated files are skipped.
//
// A line scan, not a parser: TypeScript 7 has no JS parser API to build on. It strips strings and comments first, and
// skips the member lists of `import` / `export` statements, which is where the other `as` lives.
import { readdirSync, readFileSync } from "node:fs";
import { join, relative } from "node:path";

const root = new URL("../src", import.meta.url).pathname;
const WINDOW = 6;
const missing = [];

const files = (dir) =>
  readdirSync(dir, { withFileTypes: true }).flatMap((entry) => {
    const path = join(dir, entry.name);

    if (entry.isDirectory()) return entry.name === "generated" ? [] : files(path);

    return path.endsWith(".ts") ? [path] : [];
  });

/** `line` without string literals, template text and trailing `//` comments. */
/** An `import` statement, or an `export` that re-exports (`export { a as b }`, `export * as ns`). */
const isModuleStatement = (line) => /^(import\b|export\s+(type\s+)?[{*])/.test(line);

const code = (line) =>
  line.replace(/"(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*'|`(?:[^`\\]|\\.)*`/g, '""').replace(/\/\/.*$/, "");

for (const path of files(root)) {
  const lines = readFileSync(path, "utf8").split("\n");
  let inBlockComment = false;
  let inModuleList = false;

  lines.forEach((raw, index) => {
    const trimmed = raw.trim();

    if (inBlockComment) {
      if (trimmed.includes("*/")) inBlockComment = false;

      return;
    }

    if (trimmed.startsWith("/*")) {
      inBlockComment = !trimmed.includes("*/");

      return;
    }

    if (trimmed.startsWith("//")) return;

    if (isModuleStatement(trimmed) && /\{[^}]*$/.test(trimmed)) inModuleList = true;

    if (inModuleList) {
      if (/\}\s*from\b/.test(trimmed) || trimmed.startsWith("}")) inModuleList = false;

      return;
    }

    if (isModuleStatement(trimmed)) return;

    const text = code(raw);

    if (/\bas\s+(?!const\b)[A-Za-z_{[(<"']/.test(text)) {
      const near = lines.slice(Math.max(0, index - WINDOW), index + 1).join("\n");

      if (!near.includes("SAFETY")) missing.push(`${relative(root, path)}:${index + 1}: ${trimmed.slice(0, 100)}`);
    }
  });
}

if (missing.length > 0) {
  console.error(`type assertions without a SAFETY: comment (${WINDOW} lines above):\n${missing.join("\n")}`);
  process.exit(1);
}

console.log("check-casts: every type assertion in src/ has a SAFETY: comment");
