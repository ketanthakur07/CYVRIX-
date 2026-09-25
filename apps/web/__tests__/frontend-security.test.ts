/**
 * V3.9 static frontend security scan (Phase 59 / 70 / 76).
 *
 * This is a source-level guardrail, not a substitute for runtime tests.
 * It fails the build if the client source introduces patterns that would
 * break the "browser is not an authority" model:
 * - raw HTML injection
 * - dynamic code execution
 * - browser storage of auth material
 * - credential/token material in the client bundle
 * - hardcoded security state
 * - unexplained TODO/FIXME
 */
import * as fs from "fs";
import * as path from "path";

const ROOT = path.join(__dirname, "..");
const SCAN_DIRS = ["app", "components", "lib"];
const SOURCE_EXT = /\.(ts|tsx)$/;

function walk(dir: string, out: string[] = []): string[] {
  const abs = path.join(ROOT, dir);
  if (!fs.existsSync(abs)) return out;
  for (const entry of fs.readdirSync(abs, { withFileTypes: true })) {
    const rel = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      if (entry.name === "node_modules" || entry.name.startsWith(".")) continue;
      walk(rel, out);
    } else if (SOURCE_EXT.test(entry.name)) {
      out.push(rel);
    }
  }
  return out;
}

const FILES = SCAN_DIRS.flatMap((d) => walk(d));

function readAll(): Array<{ file: string; content: string }> {
  return FILES.map((file) => ({
    file,
    content: fs.readFileSync(path.join(ROOT, file), "utf8"),
  }));
}

interface Forbidden {
  name: string;
  pattern: RegExp;
}

const FORBIDDEN: Forbidden[] = [
  { name: "dangerouslySetInnerHTML", pattern: /dangerouslySetInnerHTML/ },
  { name: "eval", pattern: /\beval\s*\(/ },
  { name: "new Function", pattern: /\bnew\s+Function\s*\(/ },
  { name: "localStorage", pattern: /\blocalStorage\b/ },
  { name: "sessionStorage", pattern: /\bsessionStorage\b/ },
  { name: "document.cookie", pattern: /document\.cookie/ },
  { name: "@ts-ignore", pattern: /@ts-ignore/ },
  { name: "TODO/FIXME", pattern: /\b(TODO|FIXME)\b/ },
  {
    name: "credential material",
    pattern: /\b(GITHUB_TOKEN|EXECUTOR_SERVICE_TOKEN|PRIVATE_KEY|client_secret)\b/,
  },
  {
    name: "Authorization bearer header",
    pattern: /["'`]Bearer\s/,
  },
  {
    name: "hardcoded security authority",
    pattern:
      /(?:const|let|var)\s+\w*(?:approved|authorized|verified|admin|canRollback|isOperator)\w*\s*=\s*true/i,
  },
];

describe("frontend source security scan", () => {
  it("discovers source files to scan", () => {
    expect(FILES.length).toBeGreaterThan(10);
  });

  for (const rule of FORBIDDEN) {
    it(`does not contain ${rule.name}`, () => {
      const offenders = readAll()
        .filter((f) => rule.pattern.test(f.content))
        .map((f) => f.file);
      expect(offenders).toEqual([]);
    });
  }
});

describe("authority is never derived on the client", () => {
  it("does not whitelist authority field names in request builders", () => {
    const apiSource = fs.readFileSync(path.join(ROOT, "lib", "api.ts"), "utf8");
    // Request bodies must not include server-authority keys.
    for (const key of [
      "authorized:",
      "approved:",
      "verified:",
      "policy_decision:",
      "rollback_sha:",
      "tenant_id:",
    ]) {
      expect(apiSource).not.toContain(key);
    }
  });
});
