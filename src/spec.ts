// What the Action exports, read from its "secrets" input (design §32.22).
// Pure functions, tested without GitHub.

/** One line of the input. */
export interface Spec {
  /** The secret's ID (a UUID): secrets are named by ID only, never by name. */
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
const secretID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;

/** The most secrets one exchange may name. */
export const maxSecrets = 20;

/** The variable of one field under a prefix. */
export function fieldVariable(prefix: string, field: string): string {
  return prefix + "_" + field.toUpperCase();
}

/**
 * Reads the input; a line that does not read throws, naming its number only.
 * Secrets are named by ID (review of #243): a name could be another team's
 * secret of the same name, so it is never looked up.
 */
export function parseSpecs(input: string): Spec[] {
  const out: Spec[] = [];
  input.split(/\r?\n/).forEach((raw, i) => {
    let line = raw.trim();
    if (line === "" || line.startsWith("#")) {
      return;
    }
    const where = `codewarden-secrets: line ${i + 1} of "secrets"`;
    const bad = () => new Error(`${where} does not read; write NAME=<secret id>#field or NAME=<secret id>`);
    let file = false;
    if (line.startsWith("file:")) {
      file = true;
      line = line.slice(5).trim();
    }
    const eq = line.indexOf("=");
    if (eq < 0) {
      throw new Error(`${where} names no variable; write NAME=<secret id>#field or NAME=<secret id>`);
    }
    const name = line.slice(0, eq).trim();
    line = line.slice(eq + 1).trim();
    const hash = line.indexOf("#");
    const secret = (hash >= 0 ? line.slice(0, hash) : line).toLowerCase();
    const field = hash >= 0 ? line.slice(hash + 1) : undefined;
    if (!secretID.test(secret)) {
      throw new Error(
        `${where}: secrets are named by ID, not by name; find the ID with the MCP operation secrets.search or on the secret's page`,
      );
    }
    if (field !== undefined && !fieldName.test(field)) {
      throw bad();
    }
    if (!envName.test(name) || name.startsWith("GITHUB_") || name.startsWith("RUNNER_") || name === "CODEWARDEN_TOKEN") {
      throw bad();
    }
    out.push(field === undefined ? { secret, name, file } : { secret, field, name, file });
  });
  if (out.length === 0) {
    throw new Error('codewarden-secrets: "secrets" names no secret');
  }
  if (secretIDs(out).length > maxSecrets) {
    throw new Error(`codewarden-secrets: "secrets" names more than ${maxSecrets} secrets`);
  }
  return out;
}

/** The distinct secret IDs of specs, in first-seen order: the exchange's secret_ids. */
export function secretIDs(specs: Spec[]): string[] {
  return [...new Set(specs.map((s) => s.secret))];
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
