// What the Action exports, read from its "secrets" input (design §32.21).
// Pure functions, tested without GitHub.

/** One line of the input. */
export interface Spec {
  /** The secret: its name, or "id:<uuid>". */
  secret: string;
  /** The one field to export; undefined exports every field. */
  field?: string;
  /** The variable name, or the prefix of every field's variable. */
  name: string;
  /** Write a 0600 file and export its path instead of the value. */
  file: boolean;
}

const envName = /^[A-Z_][A-Z0-9_]{0,99}$/;
const fieldName = /^[a-z0-9_]{1,64}$/;
const secretRef = /^(id:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}|[A-Za-z0-9._/-]{1,128})$/;

/** The variable name for a secret's name: upper case, other characters _. */
export function variableOf(secret: string): string {
  const base = secret.replace(/^id:/, "").toUpperCase().replace(/[^A-Z0-9_]/g, "_");
  return /^[0-9]/.test(base) ? "_" + base : base;
}

/** The variable of one field under a prefix. */
export function fieldVariable(prefix: string, field: string): string {
  return prefix + "_" + field.toUpperCase();
}

/** Reads the input; a line that does not read throws, naming its number only. */
export function parseSpecs(input: string): Spec[] {
  const out: Spec[] = [];
  input.split(/\r?\n/).forEach((raw, i) => {
    let line = raw.trim();
    if (line === "" || line.startsWith("#")) {
      return;
    }
    const bad = () => new Error(`codewarden-secrets: line ${i + 1} of "secrets" does not read; write NAME=secret#field, NAME=secret or secret`);
    let file = false;
    if (line.startsWith("file:")) {
      file = true;
      line = line.slice(5).trim();
    }
    let name: string | undefined;
    const eq = line.indexOf("=");
    if (eq >= 0) {
      name = line.slice(0, eq).trim();
      line = line.slice(eq + 1).trim();
    }
    const hash = line.indexOf("#");
    const secret = hash >= 0 ? line.slice(0, hash) : line;
    const field = hash >= 0 ? line.slice(hash + 1) : undefined;
    if (!secretRef.test(secret) || (field !== undefined && !fieldName.test(field))) {
      throw bad();
    }
    name ??= field === undefined ? variableOf(secret) : fieldVariable(variableOf(secret), field);
    if (!envName.test(name) || name.startsWith("GITHUB_") || name.startsWith("RUNNER_") || name === "CODEWARDEN_TOKEN") {
      throw bad();
    }
    out.push(field === undefined ? { secret, name, file } : { secret, field, name, file });
  });
  if (out.length === 0) {
    throw new Error('codewarden-secrets: "secrets" names no secret');
  }
  return out;
}

/**
 * The strings to mask for a value: the whole value and each of its lines,
 * since GitHub masks line by line; blank lines and very short pieces are
 * left out, as masking them would hide unrelated log text.
 */
export function maskPieces(value: string): string[] {
  const pieces = new Set<string>();
  if (value.trim() !== "") {
    pieces.add(value);
  }
  for (const line of value.split(/\r?\n/)) {
    const t = line.trim();
    if (t.length >= 4) {
      pieces.add(line);
      pieces.add(t);
    }
  }
  return [...pieces];
}

/**
 * The strings to mask for a binary value: its base64 (how it is exported
 * as a variable) and, when the bytes are UTF-8 text such as a PEM .p8 or
 * an XML plist stored as binary, that text's pieces too, since a step may
 * print the file it was written to.
 */
export function binaryMaskPieces(bytes: Uint8Array): string[] {
  const pieces = new Set<string>(maskPieces(Buffer.from(bytes).toString("base64")));
  try {
    const text = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
    for (const p of maskPieces(text)) {
      pieces.add(p);
    }
  } catch {
    // Not text: only the base64 can reach a log.
  }
  return [...pieces];
}
