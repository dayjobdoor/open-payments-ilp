// Every type assertion (`x as T`) in `src/` carries a `SAFETY:` comment, on the same line or within the six lines above
// it, that says why the assertion holds. `as const` and import/export renames need none. Generated files are skipped.
// `node scripts/check-casts.mjs [dir]` scans another directory.
//
// A token scan, not a parser: TypeScript 7 has no JS parser API to build on. It blanks strings, template text, regular
// expressions and comments first, so only code is searched for `as`, and keeps the comment text to look for `SAFETY:`.
// Angle-bracket assertions (`<T>x`) are banned by the lint rule `typescript/consistent-type-assertions` in
// vite.config.ts, so `as` is the only form. The `as` clause of a mapped type (`[K in keyof T as U]`) is reported too,
// although it asserts nothing: give it a `SAFETY:` comment or write the type another way.
import { readdirSync, readFileSync } from "node:fs";
import { join, relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const root = process.argv[2] ? resolve(process.argv[2]) : fileURLToPath(new URL("../src", import.meta.url));
const WINDOW = 6;
const missing = [];

const files = (dir) =>
  readdirSync(dir, { withFileTypes: true }).flatMap((entry) => {
    const path = join(dir, entry.name);

    if (entry.isDirectory()) return entry.name === "generated" ? [] : files(path);

    return path.endsWith(".ts") ? [path] : [];
  });

/** A `/` after one of these characters or keywords starts a regular expression; after anything else it divides. */
const startsRegex = (code) => {
  let end = code.length;

  while (end > 0 && /\s/.test(code[end - 1])) end -= 1;

  const before = code.slice(Math.max(0, end - 10), end);

  return (
    before === "" ||
    "(,=:[!&|?{};+-*%<>~^".includes(before.at(-1)) ||
    /(?:^|[^\w$.])(?:return|typeof|case|do|else|in|of|void|delete|throw|new|yield|await)$/.test(before)
  );
};

/**
 * Splits source text into `code` and the comment text of each line. In `code` comments, string and template text and
 * regular expressions are blanked to spaces (quotes stay, line breaks stay), so offsets and line numbers still match.
 */
const scan = (text) => {
  let code = "";
  const comments = [""];
  const interpolations = []; // the brace depth inside each open `${ ... }`
  let at = 0;

  const emit = (end, { comment = false, keepFirst = false, keepLast = false } = {}) => {
    const slice = text.slice(at, end);

    for (let k = 0; k < slice.length; k += 1) {
      const ch = slice[k];

      if (ch === "\n") {
        code += ch;
        comments.push("");
      } else {
        code += (keepFirst && k === 0) || (keepLast && k === slice.length - 1) ? ch : " ";

        if (comment) comments[comments.length - 1] += ch;
      }
    }

    at = end;
  };

  /** Where the template text that starts at `from` ends, and whether a `${` (not a closing backtick) ends it. */
  const templateText = (from) => {
    for (let k = from; k < text.length; k += text[k] === "\\" ? 2 : 1) {
      if (text[k] === "`") return { end: k + 1, open: false };

      if (text[k] === "$" && text[k + 1] === "{") return { end: k + 2, open: true };
    }

    return { end: text.length, open: false };
  };

  const code1 = (ch) => {
    code += ch;
    at += 1;

    if (ch === "\n") comments.push("");
  };

  while (at < text.length) {
    const ch = text[at];
    const next = text[at + 1];

    if (ch === "/" && next === "/") {
      const end = text.indexOf("\n", at);

      emit(end === -1 ? text.length : end, { comment: true });
    } else if (ch === "/" && next === "*") {
      const close = text.indexOf("*/", at + 2);

      emit(close === -1 ? text.length : close + 2, { comment: true });
    } else if (ch === '"' || ch === "'") {
      let end = at + 1;

      while (end < text.length && text[end] !== ch && text[end] !== "\n") end += text[end] === "\\" ? 2 : 1;

      emit(Math.min(end + 1, text.length), { keepFirst: true, keepLast: text[end] === ch });
    } else if (ch === "`") {
      const { end, open } = templateText(at + 1);

      if (open) interpolations.push(0);

      emit(end, { keepFirst: true, keepLast: !open });
    } else if (ch === "{" && interpolations.length > 0) {
      interpolations[interpolations.length - 1] += 1;
      code1(ch);
    } else if (ch === "}" && interpolations.length > 0) {
      if (interpolations[interpolations.length - 1] > 0) {
        interpolations[interpolations.length - 1] -= 1;
        code1(ch);
      } else {
        interpolations.pop();

        const { end, open } = templateText(at + 1);

        if (open) interpolations.push(0);

        emit(end, { keepLast: !open });
      }
    } else if (ch === "/" && startsRegex(code)) {
      let end = at + 1;
      let inClass = false;

      while (end < text.length && text[end] !== "\n" && (inClass || text[end] !== "/")) {
        if (text[end] === "\\") end += 1;
        else if (text[end] === "[") inClass = true;
        else if (text[end] === "]") inClass = false;

        end += 1;
      }

      end += 1;

      while (end < text.length && /[a-z]/.test(text[end])) end += 1;

      emit(Math.min(end, text.length));
    } else {
      code1(ch);
    }
  }

  return { code, comments };
};

/** `import ...;` and `export { ... }` / `export * as ns from ...`: the other place `as` appears. */
const MODULE_STATEMENT =
  /^[ \t]*(?:import\b(?!\s*[(.])|export\s+(?:type\s+)?[{*])[^;]*?(?:\bfrom\s*["'][^"'\n]*["']|;)/gm;
const ASSERTION = /\bas\s+(?!const\b)[^\s=,;:)}\]]/g;

for (const path of files(root)) {
  const source = readFileSync(path, "utf8");
  const { code, comments } = scan(source);
  const lines = source.split("\n");
  const bare = code.replace(MODULE_STATEMENT, (statement) => statement.replace(/[^\n]/g, " "));
  const reported = new Set();

  for (const match of bare.matchAll(ASSERTION)) {
    const index = bare.slice(0, match.index).split("\n").length - 1;
    const documented = comments.slice(Math.max(0, index - WINDOW), index + 1).some((text) => text.includes("SAFETY:"));

    if (!documented && !reported.has(index)) {
      reported.add(index);
      missing.push(`${relative(root, path)}:${index + 1}: ${lines[index].trim().slice(0, 100)}`);
    }
  }
}

if (missing.length > 0) {
  console.error(`type assertions without a SAFETY: comment (${WINDOW} lines above):\n${missing.join("\n")}`);
  process.exit(1);
}

console.log(`check-casts: every type assertion in ${relative(process.cwd(), root) || "."} has a SAFETY: comment`);
